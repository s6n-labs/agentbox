#!/usr/bin/env bash
# End-to-end test on Linux: a real daemon and real bubblewrap sandboxes, with
# tests/fake-nix standing in for Nix. Needs bwrap, python3, curl and network access.
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
# cargo's target dir may be redirected by the user's config, so ask cargo.
BIN=${AGENTBOX_BIN:-$(cd "$ROOT" && cargo build --quiet && cargo metadata --format-version 1 --no-deps | python3 -c 'import json, sys; print(json.load(sys.stdin)["target_directory"])')/debug/agentbox}
T=$(mktemp -d)
trap 'kill $DPID 2>/dev/null || true; rm -rf "$T"' EXIT

export AGENTBOX_SOCKET=$T/d.sock AGENTBOX_STATE_DIR=$T/state AGENTBOX_CONFIG=$T/config.toml FAKE_STORE=$T/store
cat >"$AGENTBOX_CONFIG" <<EOF
nix_bin = "$ROOT/tests/fake-nix"
approval_timeout_secs = 3
[network]
allow = ["*.com", "*.org", "blocked-by-host.example:443"]
[fs]
readonly = ["/usr", "/lib", "/lib64", "/bin", "/etc/ssl"]
EOF

W=$T/work
mkdir -p "$W" && cd "$W"
# spec <drv> <allow-json> <writable-json> <env-json> [extra-json-members]
spec() {
  echo "{\"drv\":\"/nix/store/$1.drv\",\"policy\":{\"version\":1,\"network\":{\"allow\":$2},\"fs\":{\"writable\":$3,\"workdirWritable\":true},\"capabilities\":[],\"env\":$4}${5:-}}" >sandbox.json
  echo "# $1" >flake.nix
}
cat >mcp-call.sh <<'EOF'
#!/bin/bash
# mcp-call.sh <tool> <json-arguments>: one MCP tool call over `agentbox mcp`.
coproc M { agentbox mcp; }
printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"e2e","version":"0"}}}' >&"${M[1]}"
printf '%s\n' '{"jsonrpc":"2.0","method":"notifications/initialized"}' >&"${M[1]}"
printf '%s\n' "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"$1\",\"arguments\":$2}}" >&"${M[1]}"
while read -r line <&"${M[0]}"; do case $line in *'"id":2'*) echo "$line"; break ;; esac; done
kill "$M_PID" 2>/dev/null
EOF
chmod +x mcp-call.sh

n=0
ok() { n=$((n + 1)); echo "ok $n - $1"; }
fail() { echo "FAIL: $1"; echo "--- output"; echo "${2:-}"; echo "--- daemon log"; cat "$T/daemon.log"; exit 1; }
expect() { [[ $2 == *"$3"* ]] || fail "$1: expected to find '$3'" "$2"; ok "$1"; }
refute() { [[ $2 != *"$3"* ]] || fail "$1: did not expect '$3'" "$2"; ok "$1"; }
run() { "$BIN" run "$@" </dev/null 2>&1; }
# Waits for a pending request, then runs the given decision.
decide_when_pending() {
  for _ in $(seq 100); do
    if "$BIN" review --json | grep -q '"reason"'; then "$BIN" "$@"; return; fi
    sleep 0.1
  done
  fail "no pending request appeared"
}

"$BIN" daemon 2>"$T/daemon.log" &
DPID=$!
for _ in $(seq 50); do [[ -S $AGENTBOX_SOCKET ]] && break; sleep 0.1; done

# --- isolation
spec env1 '["example.com"]' '[]' '{"FOO":"1","W":"$WORKDIR/x"}'
out=$(run -- sh -c 'echo "home=$HOME foo=$FOO w=$W"; ls /home 2>&1; ls "$AGENTBOX_SOCK"; touch made-inside; exit 7') && code=0 || code=$?
expect "HOME is recreated under the workdir" "$out" "home=$W/.agentbox/home"
expect "policy env is set and \$WORKDIR expanded" "$out" "foo=1 w=$W/x"
expect "the real home is not visible" "$out" "/home': No such file"
expect "the agent socket is visible" "$out" "/run/agentbox/agent.sock"
[[ $code == 7 ]] || fail "exit code is forwarded (got $code)" "$out"; ok "exit code is forwarded"
[[ -e made-inside ]] || fail "workdir is writable"; ok "workdir is writable"
out=$(run -- sh -c "ls $AGENTBOX_SOCKET $T/state 2>&1; echo x > /run/agentbox/env.sh" || true)
refute "the daemon socket is not visible" "$out" "$AGENTBOX_SOCKET"$'\n'
expect "the run directory is read-only" "$out" "Read-only file system"

# --- network
out=$(run -- sh -c 'curl -sS -o /dev/null -w "https=%{http_code}\n" https://example.com; curl -sS -o /dev/null -w "http=%{http_code}\n" http://example.com; curl -sS -o /dev/null -w "plain-denied=%{http_code}\n" http://example.org; curl -sS -m 10 https://example.org 2>&1; curl -sS -m 5 --noproxy "*" https://example.com 2>&1' || true)
expect "allowed domain is reachable through the proxy" "$out" "https=200"
expect "plain HTTP is forwarded" "$out" "http=200"
expect "plain HTTP to other domains is refused" "$out" "plain-denied=403"
expect "other domains are refused by the proxy" "$out" "403"
expect "bypassing the proxy fails" "$out" "Could not resolve host"
expect "denials are recorded" "$("$BIN" denials)" "example.org:443"
expect "explain names the rule" "$("$BIN" explain example.com)" "allowed by repo network.allow[0]"
expect "explain covers paths" "$("$BIN" explain /home)" "denied"

# --- agent request, approved: hot reload
cat >agent.sh <<'EOF'
#!/bin/bash
sed -i 's/"FOO":"1"/"FOO":"1","BAR":"2"/; s/\["example.com"\]/["example.com","example.org","blocked-by-host.example"]/; s/env1/env2/' sandbox.json
echo "# env2" >flake.nix
echo "RESULT=$(./mcp-call.sh reload_env '{"reason":"need BAR"}')"
bash -c 'echo "bar=$BAR"'
curl -sS -o /dev/null -w "org=%{http_code}\n" https://example.org
echo "AGAIN=$(./mcp-call.sh reload_env '{}')"
echo "POLICY=$(./mcp-call.sh current_policy '{}')"
EOF
chmod +x agent.sh
run -- ./agent.sh >"$T/agent.out" &
pid=$!
out=$("$BIN" review --json; decide_when_pending review --json)
expect "review shows the reason" "$out" '"reason": "need BAR"'
expect "review shows the policy patch" "$out" '"path": "/env/BAR"'
expect "review shows the text diff" "$out" "+# env2"
expect "accept applies without a restart" "$("$BIN" accept)" "applied"
wait $pid || true
out=$(cat "$T/agent.out")
expect "reload_env returns applied" "$out" 'New commands already use it; restart long-running processes (LSP, MCP servers, watchers) started earlier.\",\"result\":\"applied\"'
expect "new env reaches new commands" "$out" "bar=2"
expect "new network rule is live" "$out" "org=200"
expect "same files again are unchanged" "$out" 'nothing to approve.\",\"result\":\"unchanged\"'
refute "host layer caps the repo policy" "$out" 'blocked-by-host.example\"'
expect "policy --effective applies the host layer" "$("$BIN" policy --effective | tr -d ' \n')" '"allow":["example.com","example.org"]'

# --- agent request, rejected; unapproved edits stay in the workdir
cat >agent.sh <<'EOF'
#!/bin/bash
sed -i 's/env2/env3/' sandbox.json
echo "RESULT=$(./mcp-call.sh reload_env '{"reason":"sneaky"}')"
EOF
run -- ./agent.sh >"$T/agent.out" &
pid=$!
expect "reject" "$(decide_when_pending reject -m 'not needed')" "rejected"
wait $pid || true
expect "reload_env returns the rejection reason" "$(cat "$T/agent.out")" 'Rejected by the human: not needed'
out=$(run -- true) && fail "run must not pick up unapproved edits" "$out"
expect "run asks before applying unapproved edits" "$out" "pass --yes"
out=$("$BIN" reload </dev/null 2>&1) && fail "reload must not pick up unapproved edits" "$out"
expect "reload asks too" "$out" "derivation changed"
expect "run --yes accepts them" "$(run --yes -- echo fine)" "fine"
expect "afterwards run needs no confirmation" "$(run -- echo again)" "again"

# --- evaluation errors, timeouts, build errors
cat >agent.sh <<'EOF'
#!/bin/bash
cp sandbox.json good.json
echo '{"error":"undefined variable"}' >sandbox.json
echo "EVAL=$(./mcp-call.sh reload_env '{}')"
sed 's/env3/env4/' good.json >sandbox.json
echo "WAIT=$(./mcp-call.sh reload_env '{}')"
sed 's/env3/env5/; s/}$/,"buildError":"boom"}/' good.json >sandbox.json
echo "BUILD=$(./mcp-call.sh reload_env '{}')"
cp good.json sandbox.json
EOF
run -- ./agent.sh >"$T/agent.out" &
pid=$!
sleep 5 # let the env4 request time out (approval_timeout_secs = 3)
out=$(decide_when_pending accept 2>&1 || true)
expect "accept reports the build failure" "$out" "boom"
wait $pid || true
out=$(cat "$T/agent.out")
expect "eval errors return immediately" "$out" 'error: undefined variable\",\"result\":\"eval_error\"'
expect "unanswered requests time out as still_pending" "$out" '\"result\":\"still_pending\"'
expect "build errors reach the agent" "$out" '\"result\":\"build_error\"'

# --- kernel-enforced change: the agent is restarted at the end of its turn and resumed
cat >claude <<'EOF'
#!/bin/bash
# Fake agent: only the name matters to the adapter.
if [[ " $* " == *" --continue "* ]]; then echo "RESUMED: ${*: -1}"; ls -d out; exit 0; fi
agentbox hook busy
sed -i 's/"writable":\[\]/"writable":["out"]/' sandbox.json
echo "RESULT=$(./mcp-call.sh reload_env '{"reason":"need out/"}')"
agentbox hook idle
sleep 30
echo "NOT RESTARTED"
EOF
chmod +x claude
run --yes -- ./claude >"$T/agent.out" &
pid=$!
expect "accept schedules a restart" "$(decide_when_pending accept)" "restart_scheduled"
wait $pid || true
out=$(cat "$T/agent.out")
expect "reload_env returns restart_scheduled" "$out" '\"result\":\"restart_scheduled\"'
expect "the agent is resumed in a new sandbox" "$out" "RESUMED: agentbox: the sandbox was recreated"
refute "the old process was stopped" "$out" "NOT RESTARTED"

# --- the agent cannot redirect a writable bind with a symlink
rmdir out && ln -s "$HOME" out
out=$(run --yes -- ls out) && fail "symlinked fs.writable must be refused" "$out"
ok "symlinked fs.writable is refused"
rm out

echo "all $n checks passed"

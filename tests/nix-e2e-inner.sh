#!/bin/sh
# Runs inside the container started by nix-e2e.sh.
set -eu

export NIX_CONFIG="experimental-features = nix-command flakes"

n=0
ok() { n=$((n + 1)); echo "ok $n - $1"; }
fail() { echo "FAIL: $1"; echo "--- output"; echo "${2:-}"; echo "--- daemon log"; cat /tmp/daemon.log 2>/dev/null; exit 1; }
expect() { case $2 in *"$3"*) ok "$1" ;; *) fail "$1: expected to find '$3'" "$2" ;; esac; }

# --- the flake itself
cd /src
[ -e flake.lock ] || { nix flake lock path:/src; chown "$HOST_OWNER" flake.lock; }
nix build path:/src -o /agentbox
nix build --inputs-from path:/src nixpkgs#bubblewrap -o /bwrap
export PATH="/agentbox/bin:/bwrap/bin:$PATH"
ok "the flake package builds"

# --- a repository using the library
mkdir -p /work && cd /work
write_flake() {
  cat >flake.nix <<NIX
{
  inputs.agentbox.url = "path:/src";
  inputs.nixpkgs.follows = "agentbox/nixpkgs";

  outputs = { self, nixpkgs, agentbox }: {
    devShells.x86_64-linux.default =
      let pkgs = nixpkgs.legacyPackages.x86_64-linux; in
      pkgs.mkShell {
        packages = [ pkgs.curl pkgs.cacert pkgs.hello $1 ];
        FOO = "from-shell";
        shellHook = "export HOOKED=1";
      };

    agentSandboxes = agentbox.lib.eachSystem (pkgs: {
      default = {
        version = 1;
        shell = self.devShells.\${pkgs.stdenv.hostPlatform.system}.default;
        network.allow = [ "example.com" $2 ];
        fs.writable = [ ".cache" ];
        env.BAR = "\$WORKDIR/x";
      };
    });
  };
}
NIX
}
write_flake "" ""

cat >mcp-call.sh <<'SH'
#!/usr/bin/env bash
coproc M { agentbox mcp; }
printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"e2e","version":"0"}}}' >&"${M[1]}"
printf '%s\n' '{"jsonrpc":"2.0","method":"notifications/initialized"}' >&"${M[1]}"
printf '%s\n' "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"$1\",\"arguments\":$2}}" >&"${M[1]}"
while read -r line <&"${M[0]}"; do case $line in *'"id":2'*) echo "$line"; break ;; esac; done
kill "$M_PID" 2>/dev/null
SH
chmod +x mcp-call.sh

start_daemon() {
  agentbox daemon 2>/tmp/daemon.log &
  DPID=$!
  for _ in $(seq 50); do [ -S /run/agentbox/daemon.sock ] && break; sleep 0.1; done
}
# Failures are judged by the output checks, not by the exit code.
run() { agentbox run "$@" </dev/null 2>&1 || echo "[exit $?]"; }

start_daemon

out=$(agentbox policy)
expect "the module evaluates to a policy" "$out" '"example.com"'
expect "module defaults are filled in" "$out" '"workdirWritable": true'

out=$(run -- sh -c 'hello; echo "foo=$FOO bar=$BAR"; bash -c "echo hooked=\$HOOKED"; curl -sS -o /dev/null -w "https=%{http_code}\n" https://example.com; curl -sS -m 10 https://example.org 2>&1; ls /root /nix/var 2>&1; touch .cache/x && echo cache-writable')
expect "packages of the dev shell are on PATH" "$out" "Hello, world!"
expect "dev shell and policy variables are set" "$out" "foo=from-shell bar=/work/x"
expect "shellHook runs for bash commands" "$out" "hooked=1"
expect "allowed domain is reachable" "$out" "https=200"
expect "other domains are refused" "$out" "403"
expect "the nix database is not visible" "$out" "/nix/var': No such file"
expect "fs.writable is created" "$out" "cache-writable"
ls /nix/var/nix/gcroots/agentbox/ >/tmp/roots
[ ! -s /tmp/roots ] || fail "GC roots are removed when the run ends" "$(cat /tmp/roots)"
ok "GC roots are removed when the run ends"

# --- agent adds a package and a domain; a human approves; hot reload
cat >agent.sh <<'SH'
#!/usr/bin/env bash
sed -i 's/pkgs.hello /pkgs.hello pkgs.jq /; s/"example.com" /"example.com" "example.org" /' flake.nix
echo "RESULT=$(./mcp-call.sh reload_env '{"reason":"need jq"}')"
bash -c 'jq --version'
curl -sS -o /dev/null -w "org=%{http_code}\n" https://example.org
SH
chmod +x agent.sh
run -- ./agent.sh >/tmp/agent.out &
pid=$!
for _ in $(seq 600); do agentbox review --json | grep -q '"reason"' && break; sleep 0.2; done
out=$(agentbox review --json)
expect "review shows the reason" "$out" '"reason": "need jq"'
expect "review shows the policy patch" "$out" '"path": "/network/allow/1"'
expect "review shows the nix diff" "$out" "pkgs.jq"
expect "accept builds and applies" "$(agentbox accept)" "applied"
wait $pid || true
out=$(cat /tmp/agent.out)
expect "reload_env returns applied" "$out" 'applied'
expect "the new package is usable without a restart" "$out" "jq-"
expect "the new domain is reachable" "$out" "org=200"

# --- closure diff works on derivations, i.e. before anything is built
old=$(nix eval --raw path:/work#agentSandboxes.x86_64-linux.default.env.drvPath)
write_flake "" ""
new=$(nix eval --raw path:/work#agentSandboxes.x86_64-linux.default.env.drvPath)
out=$(nix store diff-closures "$old" "$new" 2>&1 || true)
expect "diff-closures compares derivation closures" "$out" "jq"

# --- invalid policies are evaluation errors
sed -i 's|fs.writable = \[ ".cache" \]|fs.writable = [ "/etc" ]|' flake.nix
out=$(run --yes -- true)
expect "absolute paths are rejected by the module" "$out" "fs.writable"
write_flake "" ""

# --- dedicated agent user
kill $DPID; wait $DPID 2>/dev/null || true
echo 'agent:x:4242:4242::/var/empty:/bin/sh' >>/etc/passwd
echo 'agent:x:4242:' >>/etc/group
mkdir -p /etc/agentbox && echo 'agent_user = "agent"' >/etc/agentbox/config.toml
chmod -R a+rwX /work
start_daemon
out=$(run --yes -- sh -c 'echo "uid=$(id -u)"; touch as-agent && echo wrote')
expect "the sandbox runs as the agent user" "$out" "uid=4242"
expect "the agent user can write the workdir" "$out" "wrote"

echo "all $n checks passed"

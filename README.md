# agentbox

A sandbox for LLM agents whose environment is a Nix flake in your repository.

The agent runs inside the dev shell you define, sees only what the sandbox policy
allows, and reaches the network only through an allow-listing proxy. It may edit the
nix files to ask for more (a package, a domain, a writable directory), but nothing
changes until a human approves the request. Evaluation and builds always happen on the
host; the agent never talks to the Nix daemon.

> **Status:** early. Linux (bubblewrap) is tested end to end, including against real
> Nix. The macOS backend (Seatbelt) compiles and generates a profile, but has not been
> run on a Mac yet. "agentbox" is a working name.

## How it works

```
 human ──CLI──▶ agentbox daemon ──▶ nix (evaluate, build)
                  │        ▲
      env.sh, proxy│        │reload_env (MCP)
                  ▼        │
               sandbox: agent + dev shell      /nix/store read-only
```

- **The daemon** owns everything that matters: evaluation, builds, approval state, GC
  roots and the outbound proxy. Its socket is not visible inside a sandbox, so a request
  on it is a human's decision by construction.
- **The sandbox** gets the workdir, a private `HOME` and `TMPDIR` under
  `<workdir>/.agentbox/`, the Nix store read-only, and nothing else of the host.
- **The agent** gets three MCP tools: `reload_env`, `list_denials` and `current_policy`.
  There is no tool to approve anything.

## Requirements

- Nix with flakes
- Linux: [bubblewrap](https://github.com/containers/bubblewrap) (`bwrap`) on the
  daemon's `PATH`. On distributions that restrict unprivileged user namespaces with
  AppArmor (Ubuntu), use the distribution's `bwrap`; one from the Nix store cannot
  create network namespaces as a normal user.
- macOS: nothing extra (`sandbox-exec` ships with the system)

## Install

```sh
nix build            # ./result/bin/agentbox, wrapped so bwrap is found
# or
cargo build --release
```

## Quick start

### 1. Describe the sandbox in your flake

```nix
{
  inputs.agentbox.url = "<this repository>";
  inputs.nixpkgs.follows = "agentbox/nixpkgs";

  outputs = { self, nixpkgs, agentbox }: {
    devShells.x86_64-linux.default =
      let pkgs = nixpkgs.legacyPackages.x86_64-linux; in
      pkgs.mkShell {
        # Put the agent's own package here as well: the sandbox only sees the Nix store.
        packages = [ pkgs.cargo pkgs.cacert ];
      };

    agentSandboxes = agentbox.lib.eachSystem (pkgs: {
      default = {
        version = 1;
        shell = self.devShells.${pkgs.stdenv.hostPlatform.system}.default;
        network.allow = [ "crates.io" "static.crates.io" "github.com:443" ];
        fs.writable = [ ".cache" "target" ];
        env.CARGO_HOME = "$WORKDIR/.cache/cargo";
      };
    });
  };
}
```

### 2. Start the daemon

```sh
agentbox daemon
```

As a normal user it serves only you. As root it serves every user of the machine and
can run sandboxes as a dedicated user (see [Host configuration](#host-configuration)).

### 3. Run something in the sandbox

```sh
cd my-repo
agentbox run -- claude          # an agent
agentbox run -- zsh             # a shell for yourself, in a sandbox of its own
```

One `run` is one sandbox, and it lives exactly as long as the command. For `claude`,
agentbox adds its MCP server and turn hooks to the command line by itself.

## Changing the environment

Who asks decides what happens:

| Who | How | Approval |
| --- | --- | --- |
| You | edit the nix files, then `agentbox reload` | none: asking is the decision |
| The agent | edits the nix files, then calls `reload_env` with a reason | required |

When the agent asks, the daemon copies the flake source to the store and evaluates that
copy. If the result differs from what is applied, the request waits for you:

```sh
agentbox review                 # TUI: a accept, r reject, d closure diff
agentbox accept                 # or without the TUI
agentbox reject -m "use curl"   # the reason goes back to the agent
```

What you approve is the copy taken at request time, so later edits cannot slip in.
`reload_env` blocks until you decide and returns one of:

| Result | Meaning |
| --- | --- |
| `unchanged` | evaluates to what is already applied; no approval involved |
| `eval_error` | evaluation failed; returned at once, you are not bothered |
| `applied` | approved and hot-reloaded; new commands use the new environment |
| `restart_scheduled` | approved; the sandbox is recreated when the agent's turn ends |
| `build_error` | approved, but the build failed |
| `rejected` | with your reason |
| `still_pending` | nobody answered in time; calling again resumes waiting |

Most changes apply without a restart, because every command re-sources an `env.sh` that
the daemon swaps atomically, and network rules are enforced in the proxy. Only what the
sandbox itself enforces needs a new one:

| Change | Applied by |
| --- | --- |
| dev shell (packages, variables), `env` | hot reload |
| `network.allow` | hot reload |
| `fs.*`, `capabilities` | restart |
| the agent's own package | restart |

After a rejection the agent's edits are still in your workdir. So that they are never
picked up by accident, `agentbox run` and `agentbox reload` show the diff and ask for
confirmation whenever the files differ from the last approved state and something has
run in the workdir since (`--yes` skips the question).

## Commands

```
agentbox run [-s NAME] [--yes] -- CMD…   run a command in a new sandbox
agentbox reload [--yes]                  re-evaluate and apply to all runs of this directory
agentbox review [--json]                 review the agent's pending request
agentbox accept | reject -m REASON       decide without the TUI
agentbox policy [--effective]            policy of the current files (∩ host layer)
agentbox denials                         accesses that were denied
agentbox explain PATH|HOST[:PORT]        which rule allows or denies it, in which layer
agentbox daemon                          run the host daemon
```

All of them act on the current directory; `-s` picks a sandbox other than `default`.

## Policy reference

Set per sandbox under `agentSandboxes.<system>.<name>`:

| Option | Default | |
| --- | --- | --- |
| `version` | | schema version, must be `1` |
| `shell` | | the dev shell derivation |
| `network.allow` | `[]` | `host`, `*.host` or `*`, optionally `:port` (no port = any port) |
| `fs.writable` | `[]` | workdir-relative paths that are created and stay writable |
| `fs.workdirWritable` | `true` | if `false`, only `fs.writable` is writable in the workdir |
| `capabilities` | `[]` | named platform permissions; currently `"xcode"` (macOS) |
| `env` | `{}` | extra variables; `$WORKDIR` is expanded |

A repository can only name things relative to its workdir. Absolute host paths and raw
sandbox rules are reserved for the host layer.

## Host configuration

The host layer sets the upper bound for every repository; what is enforced is the
intersection. It lives where the agent cannot reach it:
`~/.config/agentbox/config.toml`, or `/etc/agentbox/config.toml` for a root daemon.
Everything is optional:

```toml
nix_bin = "nix"
approval_timeout_secs = 600        # how long reload_env waits before still_pending
agent_user = "agentbox"            # root daemon only: run sandboxes as this user

[network]
allow = ["*"]                      # e.g. ["*.example.com", "github.com:443"]

[capabilities]
allow = ["*"]

[fs]                               # absolute host paths shown to every sandbox
readonly = []
writable = []

[seatbelt]
extra = ""                         # raw SBPL appended to the macOS profile
```

With `agent_user`, that user needs access to the workdirs (for example through ACLs);
agentbox does not set that up.

## Development

```sh
cargo test                            # unit tests
cargo test --test e2e -- --ignored    # real daemon + real bubblewrap, fake nix
tests/nix-e2e.sh                      # real Nix, in a privileged nixos/nix container
cargo insta review                    # after changing the review TUI
```

The end-to-end tests need bubblewrap, python3, bash and curl on the host, which is why
they are ignored by default.

Layout:

- `src/lib.rs` is the core: `daemon/` (approval and run state), `sandbox/` (bubblewrap,
  Seatbelt, `env.sh`), `policy/`, `proxy.rs`, `mcp.rs`, `nixcmd.rs`.
- `src/cli/` is the command-line client and the review TUI; it only uses the library's
  public API.
- `proto/agentbox/v1/daemon.proto` defines the daemon's Connect RPC API; code is
  generated at build time.
- `nix/sandbox.nix` is the module behind `agentbox.lib.eachSystem`.

## Known limitations

- **macOS is unverified.** The Seatbelt profile is a starting point; the system paths
  and Mach services it needs still have to be worked out on a real machine.
- **On Linux the Nix store can be listed.** bubblewrap cannot make a directory
  traversable but not listable, so every store path name is visible (contents of
  unrelated paths are readable too, as with any shared store).
- **`denials` only knows about the network.** Filesystem denials are not collected.
- **Only Claude Code is wired up as an agent** (MCP server, turn hooks, resume). Other
  commands run fine but get no restart-and-resume.
- **A hot reload you trigger does not tell the agent** to restart its long-running
  processes; the agent only reads that in the result of its own `reload_env`.
- No systemd or launchd units yet.

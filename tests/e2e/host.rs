//! The host side of an end-to-end test: a private daemon, a workdir, and helpers to
//! drive the CLI the way a human would.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use assert_cmd::cargo::cargo_bin_cmd;
use serde_json::{Value, json};
use tempfile::TempDir;

const AGENTBOX: &str = env!("CARGO_BIN_EXE_agentbox");
const MANIFEST_DIR: &str = env!("CARGO_MANIFEST_DIR");

/// How long anything asynchronous may take before the test fails.
const PATIENCE: Duration = Duration::from_secs(20);

/// Host directories a sandbox needs to run ordinary system binaries (sh, curl, …).
/// There is no Nix store in these tests, so the host layer shows them instead.
const SYSTEM_DIRS: &[&str] = &["/usr", "/lib", "/lib64", "/bin"];

/// Scripts that run inside the sandbox. Shown to it read-only by the host layer.
pub fn fixtures() -> PathBuf {
    Path::new(MANIFEST_DIR).join("tests/fixtures/sandbox")
}

/// Shell snippet calling an MCP tool from inside the sandbox.
pub fn mcp_call(tool: &str, arguments: &str) -> String {
    format!("{}/mcp-call.sh {tool} '{arguments}'", fixtures().display())
}

/// Shell snippet an "agent" runs to edit the nix files: switches to the staged spec.
pub const SWITCH_TO_STAGED: &str = "cp next.json sandbox.json; cp next.nix flake.nix";

/// What the fake nix evaluates the workdir to (see `tests/fake-nix`).
#[derive(Clone)]
pub struct Spec {
    drv: String,
    allow: Vec<String>,
    writable: Vec<String>,
    env: BTreeMap<String, String>,
    eval_error: Option<String>,
    build_error: Option<String>,
}

impl Spec {
    pub fn new(drv: &str) -> Self {
        Self {
            drv: drv.to_owned(),
            allow: Vec::new(),
            writable: Vec::new(),
            env: BTreeMap::new(),
            eval_error: None,
            build_error: None,
        }
    }

    /// Same policy, different environment derivation.
    pub fn drv(mut self, drv: &str) -> Self {
        drv.clone_into(&mut self.drv);
        self
    }

    pub fn allow(mut self, destination: impl Into<String>) -> Self {
        self.allow.push(destination.into());
        self
    }

    pub fn writable(mut self, path: &str) -> Self {
        self.writable.push(path.to_owned());
        self
    }

    pub fn env(mut self, name: &str, value: &str) -> Self {
        self.env.insert(name.to_owned(), value.to_owned());
        self
    }

    pub fn eval_error(mut self, message: &str) -> Self {
        self.eval_error = Some(message.to_owned());
        self
    }

    pub fn build_error(mut self, message: &str) -> Self {
        self.build_error = Some(message.to_owned());
        self
    }

    fn json(&self) -> Value {
        if let Some(message) = &self.eval_error {
            return json!({ "error": message });
        }

        let mut spec = json!({
            "drv": format!("/nix/store/{}.drv", self.drv),
            "policy": {
                "version": 1,
                "network": { "allow": self.allow },
                "fs": { "writable": self.writable, "workdirWritable": true },
                "capabilities": [],
                "env": self.env,
            },
        });
        if let Some(message) = &self.build_error {
            spec["buildError"] = json!(message);
        }

        spec
    }

    /// Writes the spec as `<name>.json`, plus a nix file whose text differs per drv.
    fn write(&self, workdir: &Path, json_name: &str, nix_name: &str) {
        std::fs::write(workdir.join(json_name), self.json().to_string()).unwrap();
        std::fs::write(workdir.join(nix_name), format!("# {}\n", self.drv)).unwrap();
    }
}

/// An HTTP server on the host, standing in for a site on the internet.
pub struct Origin {
    pub port: u16,
}

impl Origin {
    pub fn start() -> Self {
        let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
        let port = server.server_addr().to_ip().unwrap().port();

        thread::spawn(move || {
            for request in server.incoming_requests() {
                let _ = request.respond(tiny_http::Response::from_string("hello from origin"));
            }
        });

        Self { port }
    }

    /// As written in `network.allow`.
    pub fn destination(&self) -> String {
        format!("127.0.0.1:{}", self.port)
    }

    pub fn url(&self) -> String {
        format!("http://127.0.0.1:{}/", self.port)
    }
}

/// The result of an MCP tool call made with [`mcp_call`] and printed as `NAME=<response>`.
pub struct ToolResult {
    /// For `reload_env`: `applied`, `rejected`, …
    pub kind: String,
    pub message: String,
    /// The tool's text output, unparsed.
    pub text: String,
}

/// Finds `NAME=<json-rpc response>` in a sandbox's output and unpacks the tool result.
pub fn tool_result(output: &str, name: &str) -> ToolResult {
    let prefix = format!("{name}=");
    let line = output
        .lines()
        .find_map(|line| line.strip_prefix(&prefix))
        .unwrap_or_else(|| panic!("no {name}= line in:\n{output}"));

    let response: Value = serde_json::from_str(line).expect("a JSON-RPC response");
    let text = response["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or_else(|| panic!("no tool result in: {line}"))
        .to_owned();

    // `reload_env` answers with a small JSON document; other tools with plain text.
    let body: Value = serde_json::from_str(&text).unwrap_or_default();

    ToolResult {
        kind: body["result"].as_str().unwrap_or_default().to_owned(),
        message: body["message"].as_str().unwrap_or_default().to_owned(),
        text,
    }
}

pub struct Host {
    root: TempDir,
    daemon: Child,
}

/// Host-layer settings of one test.
pub struct HostConfig {
    /// `network.allow` of the host layer.
    pub network_allow: Vec<String>,
    pub approval_timeout_secs: u64,
}

impl Default for HostConfig {
    fn default() -> Self {
        Self {
            network_allow: vec!["*".into()],
            approval_timeout_secs: 30,
        }
    }
}

impl Host {
    /// Starts a daemon of its own for this test.
    pub fn start() -> Self {
        Self::start_with(HostConfig::default())
    }

    pub fn start_with(config: HostConfig) -> Self {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir(root.path().join("work")).unwrap();

        let mut readonly: Vec<String> = SYSTEM_DIRS
            .iter()
            .filter(|dir| Path::new(dir).exists())
            .map(ToString::to_string)
            .collect();
        readonly.push(fixtures().to_string_lossy().into_owned());

        let toml = format!(
            "nix_bin = {nix:?}\n\
             approval_timeout_secs = {timeout}\n\
             [network]\n\
             allow = {allow:?}\n\
             [fs]\n\
             readonly = {readonly:?}\n",
            nix = format!("{MANIFEST_DIR}/tests/fake-nix"),
            timeout = config.approval_timeout_secs,
            allow = config.network_allow,
        );
        std::fs::write(root.path().join("config.toml"), toml).unwrap();

        let mut command = Command::new(AGENTBOX);
        command.arg("daemon").stderr(Stdio::null());
        for (name, value) in environment(root.path()) {
            command.env(name, value);
        }
        let daemon = command.spawn().expect("starting the daemon");

        let host = Self { root, daemon };
        Self::wait_until("the daemon is listening", || {
            host.socket().exists().then_some(())
        });
        host
    }

    pub fn workdir(&self) -> PathBuf {
        self.root.path().join("work")
    }

    pub fn socket(&self) -> PathBuf {
        self.root.path().join("daemon.sock")
    }

    pub fn state_dir(&self) -> PathBuf {
        self.root.path().join("state")
    }

    /// Polls `check` until it yields something, failing the test after [`PATIENCE`].
    fn wait_until<T>(what: &str, check: impl Fn() -> Option<T>) -> T {
        let deadline = Instant::now() + PATIENCE;

        loop {
            if let Some(value) = check() {
                return value;
            }

            assert!(Instant::now() < deadline, "timed out waiting until {what}");
            thread::sleep(Duration::from_millis(50));
        }
    }

    /// The human edits the nix files.
    pub fn write_spec(&self, spec: &Spec) {
        spec.write(&self.workdir(), "sandbox.json", "flake.nix");
    }

    /// Prepares an edit for an agent to make with [`SWITCH_TO_STAGED`].
    pub fn stage_spec(&self, spec: &Spec) {
        spec.write(&self.workdir(), "next.json", "next.nix");
    }

    /// `agentbox <args…>` in the workdir, as a human without a terminal.
    pub fn agentbox(&self) -> assert_cmd::Command {
        let mut command = cargo_bin_cmd!("agentbox");
        command.current_dir(self.workdir());
        for (name, value) in environment(self.root.path()) {
            command.env(name, value);
        }

        command
    }

    /// `agentbox run -- sh -c <script>`
    pub fn run_sh(&self, script: &str) -> assert_cmd::assert::Assert {
        self.agentbox()
            .args(["run", "--", "sh", "-c", script])
            .assert()
    }

    /// `agentbox run -- bash -c <script>`
    pub fn run_bash(&self, script: &str) -> assert_cmd::assert::Assert {
        self.agentbox()
            .args(["run", "--", "bash", "-c", script])
            .assert()
    }

    /// Starts `agentbox run -- <argv…>` and returns while it is still running,
    /// so the test can play the human in the meantime.
    pub fn spawn_run(&self, argv: &[&str]) -> BackgroundRun {
        let mut command = Command::new(AGENTBOX);
        command
            .args(["run", "--yes", "--"])
            .args(argv)
            .current_dir(self.workdir())
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        for (name, value) in environment(self.root.path()) {
            command.env(name, value);
        }

        BackgroundRun {
            child: command.spawn().expect("starting agentbox run"),
        }
    }

    /// Like [`Host::spawn_run`], with a bash script playing the agent.
    pub fn spawn_agent(&self, script: &str) -> BackgroundRun {
        self.spawn_run(&["bash", "-c", script])
    }

    /// `agentbox review --json`
    pub fn review(&self) -> Value {
        let output = self.agentbox().args(["review", "--json"]).unwrap();

        serde_json::from_slice(&output.stdout).expect("review --json prints JSON")
    }

    /// Waits for an agent's request to show up and returns it as `review --json` shows it.
    pub fn wait_for_request(&self) -> Value {
        Self::wait_until("an agent's request is pending", || {
            let pending = self.review()["pending"].take();
            (!pending.is_null()).then_some(pending)
        })
    }
}

impl Drop for Host {
    fn drop(&mut self) {
        // Sandboxes die with the daemon (bwrap --die-with-parent).
        let _ = self.daemon.kill();
        let _ = self.daemon.wait();
    }
}

/// Points the daemon and the CLI at this test's private directories.
fn environment(root: &Path) -> Vec<(&'static str, PathBuf)> {
    vec![
        ("AGENTBOX_SOCKET", root.join("daemon.sock")),
        ("AGENTBOX_STATE_DIR", root.join("state")),
        ("AGENTBOX_CONFIG", root.join("config.toml")),
        ("FAKE_STORE", root.join("store")),
    ]
}

/// An `agentbox run` started with [`Host::spawn_run`].
pub struct BackgroundRun {
    child: Child,
}

impl BackgroundRun {
    /// Waits for the command to end and returns what it printed (stdout, then stderr).
    pub fn output(self) -> String {
        let output = self.child.wait_with_output().unwrap();

        format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    }
}

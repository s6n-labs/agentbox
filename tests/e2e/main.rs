//! End-to-end tests: the real CLI, a real daemon and real bubblewrap sandboxes.
//!
//! Only Nix is faked (`tests/fake-nix` evaluates a `sandbox.json` in the workdir), and
//! "the internet" is an HTTP server started by the test. Each test has its own daemon.
//!
//! They need bubblewrap, python3, bash and curl on the host, so they are ignored by
//! default:
//!
//! ```sh
//! cargo test --test e2e -- --ignored
//! ```
//!
//! `tests/nix-e2e.sh` covers the same ground against real Nix, in a container.
#![cfg(target_os = "linux")]

mod host;

use predicates::prelude::*;
use predicates::str::contains;
use serde_json::json;

use host::{Host, HostConfig, Origin, SWITCH_TO_STAGED, Spec, fixtures, mcp_call, tool_result};

/// An agent's turn: edit the nix files, then ask for the new environment.
fn switch_and_request(reason: &str) -> String {
    let arguments = json!({ "reason": reason }).to_string();
    let request = mcp_call("reload_env", &arguments);

    format!("{SWITCH_TO_STAGED}; echo \"RESULT=$({request})\"")
}

// ---- isolation

#[test]
#[ignore = "needs bubblewrap, python3, bash and curl"]
fn the_command_sees_only_its_sandbox() {
    let host = Host::start();
    let workdir = host.workdir();
    let spec = Spec::new("env1")
        .env("FOO", "1")
        .env("CACHE", "$WORKDIR/cache");
    host.write_spec(&spec);

    // A file that certainly exists on the host, right next to a directory the host
    // layer does show (the fixtures): showing a path must not show its surroundings.
    let host_file = concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml");

    let script = format!(
        r#"
        echo "home=$HOME foo=$FOO cache=$CACHE"
        test -e {host_file} && echo HOST-FILE-VISIBLE
        test -e /etc/hostname && echo HOST-ETC-VISIBLE
        cat /etc/passwd
        ls "$AGENTBOX_SOCK"
        touch made-inside
        exit 7
        "#
    );
    host.run_sh(&script)
        .code(7)
        .stdout(contains(format!(
            "home={}/.agentbox/home",
            workdir.display()
        )))
        .stdout(contains(format!("foo=1 cache={}/cache", workdir.display())))
        .stdout(contains("VISIBLE").not())
        .stdout(contains("agent:x:"))
        .stdout(contains("/run/agentbox/agent.sock"));

    assert!(
        workdir.join("made-inside").exists(),
        "the workdir is writable"
    );
    assert!(workdir.join(".agentbox/.gitignore").exists());
}

#[test]
#[ignore = "needs bubblewrap, python3, bash and curl"]
fn the_host_side_is_out_of_reach() {
    let host = Host::start();
    host.write_spec(&Spec::new("env1"));

    let script = format!(
        "test -e {socket} && echo DAEMON-SOCKET-VISIBLE
         test -e {state} && echo STATE-VISIBLE
         echo tampered > /run/agentbox/env.sh",
        socket = host.socket().display(),
        state = host.state_dir().display(),
    );

    host.run_sh(&script)
        .failure()
        .stdout(contains("VISIBLE").not())
        .stderr(contains("Read-only file system"));
}

#[test]
#[ignore = "needs bubblewrap, python3, bash and curl"]
fn a_symlinked_writable_directory_is_refused() {
    let host = Host::start();
    host.write_spec(&Spec::new("env1").writable("out"));

    // What an agent could do to get something else mounted read-write next time.
    let outside = tempfile::tempdir().unwrap();
    std::os::unix::fs::symlink(outside.path(), host.workdir().join("out")).unwrap();

    host.run_sh("touch out/escaped")
        .code(127)
        .stderr(contains("symlinks are not allowed"));

    assert!(!outside.path().join("escaped").exists());
}

// ---- network

#[test]
#[ignore = "needs bubblewrap, python3, bash and curl"]
fn the_network_is_reachable_only_through_the_proxy() {
    let host = Host::start();
    let allowed = Origin::start();
    let denied = Origin::start();
    host.write_spec(&Spec::new("env1").allow(allowed.destination()));

    let script = format!(
        r#"
        code() {{ curl -sS -o /dev/null -w "$1=%{{http_code}}\n" "${{@:2}}"; }}
        code plain {allowed}
        code tunnel --proxytunnel {allowed}
        code denied {denied}
        curl -sS -m 5 --noproxy '*' {allowed} >/dev/null 2>&1; echo "direct=$?"
        "#,
        allowed = allowed.url(),
        denied = denied.url(),
    );

    host.run_bash(&script)
        .success()
        .stdout(contains("plain=200"))
        .stdout(contains("tunnel=200"))
        .stdout(contains("denied=403"))
        // curl's "could not connect": the sandbox has no route to the host at all.
        .stdout(contains("direct=7"));

    host.agentbox()
        .arg("denials")
        .assert()
        .success()
        .stdout(contains(denied.destination()))
        .stdout(contains(allowed.destination()).not());

    host.agentbox()
        .args(["explain", &allowed.destination()])
        .assert()
        .stdout(contains("allowed by repo network.allow[0]"));
    host.agentbox()
        .args(["explain", "/home"])
        .assert()
        .stdout(contains("denied"));
}

// ---- the approval flow

#[test]
#[ignore = "needs bubblewrap, python3, bash and curl"]
fn an_approved_request_is_applied_without_a_restart() {
    let first = Origin::start();
    let second = Origin::start();
    let host = Host::start_with(HostConfig {
        // The host layer permits local destinations only.
        network_allow: vec!["127.0.0.1".into()],
        ..Default::default()
    });

    let before = Spec::new("env1").allow(first.destination()).env("FOO", "1");
    let after = before
        .clone()
        .drv("env2")
        .allow(second.destination())
        .allow("blocked-by-host.example")
        .env("BAR", "2");
    host.write_spec(&before);
    host.stage_spec(&after);

    let agent = host.spawn_agent(&format!(
        r#"
        {request}
        bash -c 'echo "bar=$BAR"'
        curl -sS -o /dev/null -w "second=%{{http_code}}\n" {second}
        echo "AGAIN=$({again})"
        echo "POLICY=$({policy})"
        "#,
        request = switch_and_request("need BAR"),
        second = second.url(),
        again = mcp_call("reload_env", "{}"),
        policy = mcp_call("current_policy", "{}"),
    ));

    // The human reviews what the agent asked for…
    let request = host.wait_for_request();
    assert_eq!(request["reason"], "need BAR");
    assert!(request["textDiff"].as_str().unwrap().contains("+# env2"));
    let paths: Vec<&str> = request["policyPatch"]
        .as_array()
        .unwrap()
        .iter()
        .map(|operation| operation["path"].as_str().unwrap())
        .collect();
    assert!(paths.contains(&"/env/BAR"), "{paths:?}");

    // …and accepts it.
    host.agentbox()
        .arg("accept")
        .assert()
        .success()
        .stdout(contains("applied"));

    let output = agent.output();
    assert_eq!(tool_result(&output, "RESULT").kind, "applied");
    assert!(
        output.contains("bar=2"),
        "new commands see the new env:\n{output}"
    );
    assert!(
        output.contains("second=200"),
        "the new rule is live:\n{output}"
    );
    assert_eq!(tool_result(&output, "AGAIN").kind, "unchanged");
    assert!(
        !tool_result(&output, "POLICY")
            .text
            .contains("blocked-by-host")
    );

    let effective = host.agentbox().args(["policy", "--effective"]).unwrap();
    let effective: serde_json::Value = serde_json::from_slice(&effective.stdout).unwrap();
    assert_eq!(
        effective["network"]["allow"],
        json!([first.destination(), second.destination()])
    );
}

#[test]
#[ignore = "needs bubblewrap, python3, bash and curl"]
fn a_rejected_request_leaves_edits_that_need_confirmation() {
    let host = Host::start();
    host.write_spec(&Spec::new("env1"));
    host.stage_spec(&Spec::new("env2"));

    let agent = host.spawn_agent(&switch_and_request("sneaky"));
    host.wait_for_request();
    host.agentbox()
        .args(["reject", "-m", "not needed"])
        .assert()
        .success()
        .stdout(contains("rejected"));

    let result = tool_result(&agent.output(), "RESULT");
    assert_eq!(result.kind, "rejected");
    assert!(result.message.contains("not needed"), "{}", result.message);

    // The agent's edit is still in the workdir. Neither a new run nor a reload may
    // pick it up silently.
    host.agentbox()
        .args(["run", "--", "true"])
        .assert()
        .failure()
        .stderr(contains("pass --yes"));
    host.agentbox()
        .arg("reload")
        .assert()
        .failure()
        .stderr(contains("derivation changed"));

    // Once the human says yes, it is approved and nobody asks again.
    host.agentbox()
        .args(["run", "--yes", "--", "echo", "fine"])
        .assert()
        .success()
        .stdout(contains("fine"));
    host.agentbox()
        .args(["run", "--", "echo", "again"])
        .assert()
        .success()
        .stdout(contains("again"));
}

#[test]
#[ignore = "needs bubblewrap, python3, bash and curl"]
fn evaluation_errors_go_back_to_the_agent_at_once() {
    let host = Host::start();
    host.write_spec(&Spec::new("env1"));
    host.stage_spec(&Spec::new("env2").eval_error("undefined variable 'pkgs'"));

    let output = host.spawn_agent(&switch_and_request("oops")).output();

    let result = tool_result(&output, "RESULT");
    assert_eq!(result.kind, "eval_error");
    assert!(
        result.message.contains("undefined variable"),
        "{}",
        result.message
    );
    assert!(host.review()["pending"].is_null(), "no human is bothered");
}

#[test]
#[ignore = "needs bubblewrap, python3, bash and curl"]
fn an_unanswered_request_times_out_as_still_pending() {
    let host = Host::start_with(HostConfig {
        approval_timeout_secs: 1,
        ..Default::default()
    });
    host.write_spec(&Spec::new("env1"));
    host.stage_spec(&Spec::new("env2"));

    let output = host
        .spawn_agent(&switch_and_request("anyone there?"))
        .output();

    assert_eq!(tool_result(&output, "RESULT").kind, "still_pending");
    assert_eq!(host.review()["pending"]["reason"], "anyone there?");
}

#[test]
#[ignore = "needs bubblewrap, python3, bash and curl"]
fn build_errors_reach_both_the_human_and_the_agent() {
    let host = Host::start();
    host.write_spec(&Spec::new("env1"));
    host.stage_spec(&Spec::new("env2").build_error("boom"));

    let agent = host.spawn_agent(&switch_and_request("please build"));
    host.wait_for_request();
    host.agentbox()
        .arg("accept")
        .assert()
        .failure()
        .stderr(contains("boom"));

    let result = tool_result(&agent.output(), "RESULT");
    assert_eq!(result.kind, "build_error");
    assert!(result.message.contains("boom"), "{}", result.message);
}

// ---- restart

#[test]
#[ignore = "needs bubblewrap, python3, bash and curl"]
fn an_agent_is_restarted_after_its_turn_and_resumed() {
    let host = Host::start();
    host.write_spec(&Spec::new("env1"));
    // Filesystem rules are enforced by the sandbox itself: this needs a new one.
    host.stage_spec(&Spec::new("env1").writable("out"));

    // See tests/fixtures/sandbox/claude for the agent's side of this.
    let claude = fixtures().join("claude");
    let agent = host.spawn_run(&[claude.to_str().unwrap()]);
    host.wait_for_request();
    host.agentbox()
        .arg("accept")
        .assert()
        .success()
        .stdout(contains("restart_scheduled"));

    let output = agent.output();
    assert_eq!(tool_result(&output, "RESULT").kind, "restart_scheduled");
    assert!(
        output.contains("RESUMED: agentbox: the sandbox was recreated"),
        "{output}"
    );
    assert!(
        output.contains("\nout\n"),
        "the new directory exists:\n{output}"
    );
    assert!(!output.contains("NOT RESTARTED"), "{output}");
}

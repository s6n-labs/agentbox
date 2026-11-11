//! Adapter layer: what differs between agents is absorbed here.
//!
//! Environment-based wiring (BASH_ENV, CLAUDE_ENV_FILE, …) applies to every command and
//! lives in `env.rs`; this file only handles what needs command-line arguments.

use std::path::Path;

use serde_json::json;

/// Is this a command we know how to wire up (MCP server, turn hooks, resume)?
pub fn is_agent(argv: &[String]) -> bool {
    let name = Path::new(&argv[0]).file_name();

    name.is_some_and(|name| name == "claude")
}

/// Adds the MCP server and turn hooks to an agent's command line.
///
/// `resume` is set when the sandbox was recreated: the agent continues its previous
/// session and is told what happened.
pub fn adapt_argv(argv: &[String], exe_inside: &Path, resume: Option<&str>) -> Vec<String> {
    let mut adapted = argv.to_vec();
    if !is_agent(argv) {
        return adapted;
    }

    let exe = exe_inside.to_string_lossy();

    let mcp_config = json!({
        "mcpServers": {
            "agentbox": { "command": exe, "args": ["mcp"] },
        },
    });

    // Hook commands are run by a shell, so the path must survive word splitting.
    let quoted_exe = shlex::try_quote(&exe).unwrap_or_default();

    // The hooks tell the daemon when a turn starts and ends, so a restart can wait
    // for the end of the turn.
    let hook = |state: &str| {
        json!([{
            "hooks": [{ "type": "command", "command": format!("{quoted_exe} hook {state}") }],
        }])
    };
    let settings = json!({
        "hooks": {
            "UserPromptSubmit": hook("busy"),
            "Stop": hook("idle"),
        },
    });

    adapted.extend([
        "--mcp-config".to_owned(),
        mcp_config.to_string(),
        "--settings".to_owned(),
        settings.to_string(),
    ]);

    if let Some(message) = resume {
        adapted.extend(["--continue".to_owned(), message.to_owned()]);
    }

    adapted
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn claude_gets_mcp_hooks_and_resume() {
        let exe = Path::new("/bin/agentbox");

        let claude = vec!["claude".to_string()];
        let adapted = adapt_argv(&claude, exe, Some("env updated"));

        assert!(adapted.contains(&"--mcp-config".to_string()));
        assert!(adapted.contains(&"--settings".to_string()));
        assert_eq!(&adapted[adapted.len() - 2..], ["--continue", "env updated"]);
    }

    #[test]
    fn other_commands_are_untouched() {
        let zsh = vec!["zsh".to_string()];

        assert_eq!(adapt_argv(&zsh, Path::new("/bin/agentbox"), None), zsh);
    }

    #[test]
    fn agents_are_recognised_by_file_name() {
        let is = |program: &str| is_agent(&[program.to_string()]);

        assert!(is("claude"));
        assert!(is("./claude"));
        assert!(is("/nix/store/abc-claude-code/bin/claude"));

        assert!(!is("claude-wrapper"));
        assert!(!is("zsh"));
    }

    #[test]
    fn the_wiring_is_valid_json_pointing_at_our_binary() {
        let claude = vec!["claude".to_string(), "--verbose".to_string()];
        let adapted = adapt_argv(&claude, Path::new("/opt/agent box/agentbox"), None);
        let value_of = |flag: &str| {
            let index = adapted.iter().position(|arg| arg == flag).unwrap();
            serde_json::from_str::<serde_json::Value>(&adapted[index + 1]).unwrap()
        };

        // The original arguments come first, untouched.
        assert_eq!(&adapted[..2], ["claude", "--verbose"]);
        assert!(!adapted.contains(&"--continue".to_string()));

        let mcp = value_of("--mcp-config");
        assert_eq!(
            mcp["mcpServers"]["agentbox"]["command"],
            "/opt/agent box/agentbox"
        );
        assert_eq!(mcp["mcpServers"]["agentbox"]["args"], json!(["mcp"]));

        let hooks = &value_of("--settings")["hooks"];
        assert_eq!(
            hooks["UserPromptSubmit"][0]["hooks"][0]["command"],
            "'/opt/agent box/agentbox' hook busy"
        );
        assert_eq!(
            hooks["Stop"][0]["hooks"][0]["command"],
            "'/opt/agent box/agentbox' hook idle"
        );
    }
}

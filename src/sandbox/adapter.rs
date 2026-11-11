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

    // The hooks tell the daemon when a turn starts and ends, so a restart can wait
    // for the end of the turn.
    let hook = |state: &str| {
        json!([{
            "hooks": [{ "type": "command", "command": format!("{exe} hook {state}") }],
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
}

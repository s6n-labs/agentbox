//! What a human sees before approving: a structural diff, no bespoke rendering.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use serde_json::Value;

use crate::nixcmd::Eval;
use crate::proto::{Diff, PatchOperation};

/// Directories that never hold flake sources worth diffing.
const SKIPPED_DIRS: &[&str] = &["target", "node_modules"];

/// Collects nix files and the lock file of a source tree, keyed by relative path.
fn collect_nix_files(root: &Path, rel: &Path, files: &mut BTreeMap<String, String>) {
    let Ok(entries) = std::fs::read_dir(root.join(rel)) else {
        return;
    };

    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        let path = rel.join(&name);
        let Ok(file_type) = entry.file_type() else {
            continue;
        };

        if file_type.is_dir() {
            if !name.starts_with('.') && !SKIPPED_DIRS.contains(&name.as_str()) {
                collect_nix_files(root, &path, files);
            }
            continue;
        }

        let has_nix_extension = path.extension().is_some_and(|extension| extension == "nix");
        let is_nix_file = has_nix_extension || name == "flake.lock";
        if !is_nix_file {
            continue;
        }

        if let Ok(content) = std::fs::read_to_string(entry.path()) {
            files.insert(path.to_string_lossy().into_owned(), content);
        }
    }
}

fn nix_files(pinned: Option<&str>) -> BTreeMap<String, String> {
    let mut files = BTreeMap::new();

    if let Some(pinned) = pinned {
        collect_nix_files(Path::new(pinned), Path::new(""), &mut files);
    }

    files
}

/// Unified diff of the nix files between two pinned source trees.
fn text_diff(old_pinned: Option<&str>, new_pinned: &str) -> String {
    let old = nix_files(old_pinned);
    let new = nix_files(Some(new_pinned));
    let names: BTreeSet<&String> = old.keys().chain(new.keys()).collect();

    let mut out = String::new();
    for name in names {
        let before = old.get(name).map_or("", String::as_str);
        let after = new.get(name).map_or("", String::as_str);
        if before == after {
            continue;
        }

        let diff = similar::TextDiff::from_lines(before, after);
        let unified = diff
            .unified_diff()
            .header(&format!("a/{name}"), &format!("b/{name}"))
            .to_string();
        out += &unified;
    }

    out
}

/// Converts an RFC 6902 patch into its protobuf form.
fn patch_operations(patch: &json_patch::Patch) -> Vec<PatchOperation> {
    let json = serde_json::to_value(patch).unwrap_or_default();
    let operations = json.as_array().map(Vec::as_slice).unwrap_or_default();

    operations
        .iter()
        .map(|operation| PatchOperation {
            op: operation["op"].as_str().unwrap_or_default().to_owned(),
            path: operation["path"].as_str().unwrap_or_default().to_owned(),
            value: operation.get("value").map(Value::to_string),
            ..Default::default()
        })
        .collect()
}

/// Describes how `new` differs from the approved state `old`.
pub fn make_diff(old: Option<&Eval>, new: &Eval, reason: Option<String>) -> Diff {
    let old_policy = old.map_or(Value::Null, |eval| eval.policy.clone());
    let patch = json_patch::diff(&old_policy, &new.policy);

    Diff {
        reason,
        policy_patch: patch_operations(&patch),
        text_diff: text_diff(old.map(|eval| eval.pinned.as_str()), &new.pinned),
        derivation_changed: old.is_none_or(|eval| eval.drv != new.drv),
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    /// A pinned source tree with the given files.
    fn source(files: &[(&str, &str)]) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();

        for (name, content) in files {
            let path = dir.path().join(name);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, content).unwrap();
        }

        dir
    }

    fn eval(source: &tempfile::TempDir, drv: &str, allow: &[&str]) -> Eval {
        Eval {
            pinned: source.path().to_string_lossy().into_owned(),
            drv: drv.to_owned(),
            policy: json!({ "network": { "allow": allow } }),
        }
    }

    #[test]
    fn policy_changes_become_patch_operations() {
        let dir = source(&[]);
        let old = eval(&dir, "a.drv", &["crates.io"]);
        let new = eval(&dir, "a.drv", &["crates.io", "github.com:443"]);

        let diff = make_diff(Some(&old), &new, Some("need github".into()));

        assert_eq!(diff.reason.as_deref(), Some("need github"));
        assert_eq!(diff.policy_patch.len(), 1);
        assert_eq!(diff.policy_patch[0].op, "add");
        assert_eq!(diff.policy_patch[0].path, "/network/allow/1");
        assert_eq!(
            diff.policy_patch[0].value.as_deref(),
            Some("\"github.com:443\"")
        );
        assert!(!diff.derivation_changed);
        assert!(diff.text_diff.is_empty());
    }

    #[test]
    fn removals_carry_no_value() {
        let dir = source(&[]);
        let old = eval(&dir, "a.drv", &["crates.io", "github.com"]);
        let new = eval(&dir, "a.drv", &["crates.io"]);

        let diff = make_diff(Some(&old), &new, None);

        assert_eq!(diff.policy_patch.len(), 1);
        assert_eq!(diff.policy_patch[0].op, "remove");
        assert_eq!(diff.policy_patch[0].value, None);
    }

    #[test]
    fn nix_files_are_diffed_as_text() {
        let before = source(&[
            ("flake.nix", "{ a = 1; }\n"),
            ("nix/shell.nix", "old\n"),
            ("flake.lock", "{}\n"),
        ]);
        let after = source(&[
            ("flake.nix", "{ a = 2; }\n"),
            ("nix/shell.nix", "old\n"),
            ("flake.lock", "{}\n"),
            ("nix/extra.nix", "new\n"),
        ]);

        let diff = make_diff(
            Some(&eval(&before, "a.drv", &[])),
            &eval(&after, "b.drv", &[]),
            None,
        );

        assert!(diff.derivation_changed);
        assert!(diff.text_diff.contains("--- a/flake.nix"));
        assert!(diff.text_diff.contains("-{ a = 1; }"));
        assert!(diff.text_diff.contains("+{ a = 2; }"));
        assert!(diff.text_diff.contains("+++ b/nix/extra.nix"));

        // Unchanged files do not show up.
        assert!(!diff.text_diff.contains("shell.nix"));
        assert!(!diff.text_diff.contains("flake.lock"));
    }

    #[test]
    fn only_nix_sources_are_diffed() {
        let before = source(&[("flake.nix", "same\n")]);
        let after = source(&[
            ("flake.nix", "same\n"),
            ("src/main.rs", "fn main() {}\n"),
            ("README.md", "hello\n"),
            (".direnv/cache.nix", "hidden\n"),
            ("target/out.nix", "build output\n"),
            ("node_modules/pkg/default.nix", "vendored\n"),
        ]);

        let diff = make_diff(
            Some(&eval(&before, "a.drv", &[])),
            &eval(&after, "a.drv", &[]),
            None,
        );

        assert_eq!(diff.text_diff, "");
    }

    #[test]
    fn the_first_evaluation_is_all_additions() {
        let dir = source(&[("flake.nix", "{ }\n")]);

        let diff = make_diff(None, &eval(&dir, "a.drv", &["crates.io"]), None);

        assert!(diff.derivation_changed);
        assert!(diff.text_diff.contains("+{ }"));
        assert_eq!(diff.policy_patch[0].op, "replace");
        assert_eq!(diff.policy_patch[0].path, "");
    }
}

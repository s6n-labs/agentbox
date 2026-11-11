# Evaluates one sandbox definition into { env, policy }.
# `policy` is plain JSON-able data read by the host with `nix eval --json`;
# `env` is the devShell derivation, built separately after approval.
{ lib, cfg }:
let
  inherit (lib) mkOption types;
  # Relative to the workdir, no absolute paths, no `..` components.
  relPath = types.strMatching "([^/.][^/]*|\\.[^/.][^/]*|\\.)(/([^/.][^/]*|\\.[^/.][^/]*))*";
  module = {
    options = {
      version = mkOption {
        type = types.enum [ 1 ];
        description = "Policy schema version.";
      };
      shell = mkOption {
        type = types.package;
        description = "devShell the agent runs in.";
      };
      network.allow = mkOption {
        type = types.listOf types.str;
        default = [ ];
        description = "Outbound destinations: host, *.host, optionally :port.";
      };
      fs.writable = mkOption {
        type = types.listOf relPath;
        default = [ ];
        description = "Workdir-relative paths that are created and kept writable.";
      };
      fs.workdirWritable = mkOption {
        type = types.bool;
        default = true;
        description = "If false, only fs.writable is writable inside the workdir.";
      };
      capabilities = mkOption {
        type = types.listOf (types.enum [ "xcode" ]);
        default = [ ];
        description = "Named platform-specific permissions, expanded by the host.";
      };
      env = mkOption {
        type = types.attrsOf types.str;
        default = { };
        description = "Extra environment variables; $WORKDIR is expanded by the host.";
      };
    };
  };
  c = (lib.evalModules { modules = [ module cfg ]; }).config;
in
{
  env = c.shell;
  policy = {
    inherit (c)
      version
      network
      fs
      capabilities
      env
      ;
  };
}

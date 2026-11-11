{
  description = "agentbox: Nix-based sandbox for LLM agents";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";

  outputs =
    { self, nixpkgs }:
    let
      inherit (nixpkgs) lib;
      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "aarch64-darwin"
        "x86_64-darwin"
      ];
    in
    {
      # agentSandboxes = agentbox.lib.eachSystem (pkgs: { default = { ... }; });
      lib.eachSystem =
        f:
        lib.genAttrs systems (
          system:
          lib.mapAttrs (_: cfg: import ./nix/sandbox.nix { inherit lib cfg; }) (
            f nixpkgs.legacyPackages.${system}
          )
        );

      packages = lib.genAttrs systems (system: {
        default = nixpkgs.legacyPackages.${system}.rustPlatform.buildRustPackage {
          pname = "agentbox";
          version = "0.1.0";
          src = lib.fileset.toSource {
            root = ./.;
            fileset = lib.fileset.unions [
              ./Cargo.toml
              ./Cargo.lock
              ./build.rs
              ./proto
              ./src
            ];
          };
          cargoLock.lockFile = ./Cargo.lock;

          # build.rs generates the Connect RPC code from proto/ with this protoc.
          PROTOC = "${nixpkgs.legacyPackages.${system}.protobuf}/bin/protoc";
        };
      });
    };
}

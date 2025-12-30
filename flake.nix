/*
Some utility commands:
- `nix flake update --commit-lock-file`
- `nix flake lock update-input <input>`
- `nix build .#pathguard` or `nix build .`
- `nix run .#pathguard` or `nix run .`
*/

{
  description = "A customizable password protection system for HTTP services and file servers.";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    rust-overlay.url = "github:oxalica/rust-overlay";
  };

  outputs = { self, nixpkgs, rust-overlay }:
    let
      overlays = [ (import rust-overlay) ];
      system = "x86_64-linux";
      pkgs = import nixpkgs {
        inherit system overlays;
      };
      rustSettings = with pkgs; {
        src = ./.;
        #nativeBuildInputs = [ pkg-config ];
        #buildInputs = [ openssl ];
        cargoHash = "sha256-TjCWQtS0xh0STfi+kYhNMPRegwAtguD0wj7+TZCQPuM=";
      };
      meta = with nixpkgs.lib; {
        homepage = "https://github.com/ElnuDev/pathguard";
        license = [ licenses.gpl3 ];
        platforms = [ system ];
        maintainers = with maintainers; [ elnudev ];
      };
      nightly = pkgs.rust-bin.nightly.latest.default.override {
        extensions = [ "rust-src" ];
      };
      platform = pkgs.makeRustPlatform {
        cargo = nightly;
        rustc = nightly;
      };
    in {
      devShells.${system}.default = with pkgs; mkShell {
        packages = [
          nightly
          cargo-edit
          cargo-shear
          bacon
          diesel-cli
        ];
        inputsFrom = with self.packages.${system}; [ pathguard ];
      };
      packages.${system} = {
        default = self.packages.${system}.pathguard;
        pathguard = platform.buildRustPackage (rustSettings // {
          pname = "pathguard";
          version = "0.1.0";
          buildAndTestSubdir = "pathguard";
          meta = meta // {
            description = "A customizable password protection system for HTTP services and file servers.";
          };
        });
      };
      nixosModules.default = { config, ... }: let
        lib = nixpkgs.lib;
      in {
        options.services.pathguard = {
          enable = lib.mkEnableOption (lib.mdDoc "pathguard service");
          package = lib.mkOption {
            type = lib.types.package;
            default = self.packages.${system}.pathguard;
            defaultText = "pkgs.pathguard";
            description = lib.mdDoc ''
              The pathguard package that should be used.
            '';
          };
          mode = lib.mkOption {
            type = lib.types.submodule {
              options = {
                kind = lib.mkOption {
                  type = lib.types.enum [ "proxy" "files" ];
                };
                port = lib.mkOption {
                  type = lib.types.port;
                };
                root = lib.mkOption {
                  type = lib.types.path;
                };
              };
            };
          };
          port = lib.mkOption {
            type = lib.types.port;
            default = 8000;
          };
          dashboard = lib.mkOption {
            type = lib.types.str;
            default = "/pathguard";
          };
          minPasswordStrength = lib.mkOption {
            type = lib.types.int;
            default = 60;
          };
        };
        config.systemd.services.pathguard = let
          cfg = config.services.pathguard;
          pkg = self.packages.${system}.pathguard;
        in lib.mkIf cfg.enable {
          description = pkg.meta.description;
          after = [ "network.target" ];
          wantedBy = [ "network.target" ];
          serviceConfig = {
            StateDirectory = "pathguard";
            ExecStart = let
              params =
                "--db /var/lib/pathguard/database.db " +
                "--key /var/lib/pathguard/session.key " +
                "--port ${builtins.toString cfg.port} " +
                "--dashboard ${cfg.dashboard} " +
                "--min-password-strength ${builtins.toString cfg.minPasswordStrength}";
              mode =
                if cfg.mode.kind == "proxy" then
                  "proxy ${builtins.toString cfg.mode.port}"
                else
                  "files ${cfg.mode.root}";
            in
              "${cfg.package}/bin/pathguard ${params} ${mode}";
            Restart = "always";
            DynamicUser = true;
          };
        };
      };
    };
}

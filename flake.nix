/*
TODO
4. (optional) uncomment `nativeBuildInputs` and `buildInputs`
5. (optional) set your project homepage
6. (optional) uncomment the NixOS module and update it for your needs
7. Delete this comment block
*/

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
        cargoHash = nixpkgs.lib.fakeHash;
      };
      meta = with nixpkgs.lib; {
        #homepage = "https://example.com";
        license = [ licenses.gpl3 ];
        platforms = [ system ];
        maintainers = with maintainers; [ elnudev ];
      };
    in {
      devShells.${system}.default = with pkgs; mkShell {
        packages = [
          (pkgs.rust-bin.nightly.latest.default.override {
            extensions = [ "rust-src" ];
          })
          cargo-edit
          cargo-shear
          bacon
          diesel-cli
        ];
        inputsFrom = with self.packages.${system}; [ pathguard ];
      };
      packages.${system} = {
        default = self.packages.${system}.pathguard;
        pathguard = pkgs.rustPlatform.buildRustPackage (rustSettings // {
          pname = "pathguard";
          version = "0.1.0";
          buildAndTestSubdir = "pathguard";
          cargoHash = "sha256-+TaGIiKf+Pz2bTABeG8aCZz0/ZTCKl5398+qbas4Nvo=";
          meta = meta // {
            description = "A customizable password protection system for HTTP services and file servers.";
          };
        });
      };
      /*
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
          port = lib.mkOption {
            type = lib.types.port;
            default = 8000;
            description = lib.mdDoc ''
              The port at which to run.
            '';
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
            ExecStart = ''
              ${cfg.package}/bin/pathguard --port ${builtins.toString cfg.port}
            '';
            Restart = "always";
            DynamicUser = true;
          };
        };
      };
      */
    };
}

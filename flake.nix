/*
TODO
1. Find and replace "helloworld" with your package name for **ALL FILES IN REPOSITORY**
2. Add a flake description that describes the workspace on line 27
3. Add a package description on line 70
4. (optional) uncomment `nativeBuildInputs` and `buildInputs` on lines 43 and 44 if you need openssl
5. (optional) set your project homepage, license, and maintainers list on lines 48-51
6. (optional) uncomment the NixOS module and update it for your needs
7. Delete this comment block
*/

/*
Some utility commands:
- `nix flake update --commit-lock-file`
- `nix flake lock update-input <input>`
- `nix build .#helloworld` or `nix build .`
- `nix run .#helloworld` or `nix run .`
*/

{
  description = "";

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
        #license = [ licenses.gpl3 ];
        platforms = [ system ];
        #maintainers = with maintainers; [ ];
      };
    in {
      devShells.${system}.default = with pkgs; mkShell {
        packages = [
          (pkgs.rust-bin.stable.latest.default.override {
            extensions = [ "rust-src" ];
          })
          cargo-edit
          bacon
        ];
        inputsFrom = with self.packages.${system}; [ helloworld ];
      };
      packages.${system} = {
        default = self.packages.${system}.helloworld;
        helloworld = pkgs.rustPlatform.buildRustPackage (rustSettings // {
          pname = "helloworld";
          version = "0.1.0";
          buildAndTestSubdir = "helloworld";
          cargoHash = "sha256-+TaGIiKf+Pz2bTABeG8aCZz0/ZTCKl5398+qbas4Nvo=";
          meta = meta // {
            description = "";
          };
        });
      };
      /*
      nixosModules.default = { config, ... }: let
        lib = nixpkgs.lib;
      in {
        options.services.helloworld = {
          enable = lib.mkEnableOption (lib.mdDoc "helloworld service");
          package = lib.mkOption {
            type = lib.types.package;
            default = self.packages.${system}.helloworld;
            defaultText = "pkgs.helloworld";
            description = lib.mdDoc ''
              The helloworld package that should be used.
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
        config.systemd.services.helloworld = let
          cfg = config.services.helloworld;
          pkg = self.packages.${system}.helloworld;
        in lib.mkIf cfg.enable {
          description = pkg.meta.description;
          after = [ "network.target" ];
          wantedBy = [ "network.target" ];
          serviceConfig = {
            ExecStart = ''
              ${cfg.package}/bin/helloworld --port ${builtins.toString cfg.port}
            '';
            Restart = "always";
            DynamicUser = true;
          };
        };
      };
      */
    };
}

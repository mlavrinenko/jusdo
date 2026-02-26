{
  inputs = {
    flake-utils.url = "github:numtide/flake-utils";
    naersk = {
      url = "github:nix-community/naersk";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
  };

  outputs =
    {
      self,
      flake-utils,
      naersk,
      nixpkgs,
      ...
    }:
    {
      overlays.default = final: _prev: {
        jusdo = self.packages.${final.system}.default;
      };

      nixosModules.default =
        { pkgs, ... }:
        {
          nixpkgs.overlays = [ self.overlays.default ];
          imports = [ ./nix/module.nix ];
        };
    }
    // flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = (import nixpkgs) {
          inherit system;
        };

        naersk' = pkgs.callPackage naersk { };

      in
      {
        # For `nix build` & `nix run`:
        packages.default = naersk'.buildPackage {
          src = ./.;
          meta = with pkgs.lib; {
            description = "Allow sudo just for picked Justfiles";
            license = licenses.mit;
            mainProgram = "jusdo";
          };
        };

        # For `nix develop`:
        devShells.default = pkgs.mkShell {
          nativeBuildInputs = with pkgs; [
            rustc
            cargo
            cargo-tarpaulin
            clippy
            rustfmt
            just
            nixd
            rust-analyzer
            tokei
          ];
        };
      }
    );
}

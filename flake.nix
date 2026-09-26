{
  description = "Rust package using webrtc crate";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable"; # or unstable if you prefer
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay.url = "github:oxalica/rust-overlay";
  };

  outputs = { self, nixpkgs, flake-utils, rust-overlay }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [ rust-overlay.overlays.default ];
          config.allowUnfree = true;

        };

        rust = pkgs.rust-bin.stable.latest.default.override {
          targets = [
           
          ];
        };

      in
      {
        packages.default = rust.buildRustPackage rec {
          pname = "rocket_oidc";
          version = "0.1.0";

          src = ./.;

          cargoLock = {
            lockFile = ./Cargo.lock;
          };

          
        };
        devShells.default = pkgs.mkShell {
          buildInputs = with pkgs; [
            cargo
            rust
            mdbook
    
          ];

        };
      });
}
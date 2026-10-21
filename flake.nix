{
  description = "wolf-crypto: safe Rust bindings over wolfCrypt";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = { self, nixpkgs }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin" ];
      forAll = f: nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});
    in
    {
      # `nix develop` gives wolf-crypto-sys's build script what bindgen needs:
      # libclang (LIBCLANG_PATH) and the C include paths of the nix toolchain
      # (BINDGEN_EXTRA_CLANG_ARGS), both set by rustPlatform.bindgenHook, plus
      # a C compiler for the vendored wolfCrypt sources. The Rust toolchain is
      # not provided: cargo and rustc come from the caller's environment
      # (rustup), so `cargo build`, `cargo test` and `cargo publish` run with
      # the toolchain already in use.
      devShells = forAll (pkgs: {
        default = pkgs.mkShell {
          nativeBuildInputs = [ pkgs.rustPlatform.bindgenHook ];
          packages = [ pkgs.clang ];
        };
      });
    };
}

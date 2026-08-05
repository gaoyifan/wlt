{
  description = "Nftables-based network outlet manager";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = {
    self,
    nixpkgs,
    ...
  }: let
    systems = [
      "aarch64-linux"
      "x86_64-linux"
    ];
    forAllSystems = nixpkgs.lib.genAttrs systems;
  in {
    packages = forAllSystems (system: let
      pkgs = nixpkgs.legacyPackages.${system};
    in {
      default = pkgs.rustPlatform.buildRustPackage {
        pname = "wlt";
        version = "2.0.0";
        src = ./.;

        cargoHash = "sha256-NI4Mv60Qn0lW2+EleSuPtVErcDKSzQq8FPoL6NA6q0Y=";

        nativeBuildInputs = [pkgs.makeWrapper];
        postInstall = ''
          wrapProgram $out/bin/wlt \
            --prefix PATH : ${pkgs.lib.makeBinPath [pkgs.nftables]}
        '';

        meta = {
          description = "Nftables-based network outlet manager";
          homepage = "https://github.com/gaoyifan/wlt";
          license = pkgs.lib.licenses.mit;
          mainProgram = "wlt";
        };
      };
    });

    apps = forAllSystems (system: {
      default = {
        type = "app";
        program = "${nixpkgs.lib.getExe self.packages.${system}.default}";
      };
    });

    devShells = forAllSystems (system: {
      default = nixpkgs.legacyPackages.${system}.mkShell {
        packages = with nixpkgs.legacyPackages.${system}; [
          cargo
          rustc
          rustfmt
        ];
      };
    });

    formatter = forAllSystems (system: nixpkgs.legacyPackages.${system}.alejandra);
  };
}

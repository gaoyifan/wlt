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

        cargoHash = "sha256-9BxeBuAYIF+KEzfNduIPrd2WV2EEDT5BwK4rdlCZeu4=";
        cargoBuildFlags = ["--bins"];
        cargoCheckFlags = ["--all-targets"];

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
          clippy
          rustc
          rustfmt
        ];
      };
    });

    formatter = forAllSystems (system: nixpkgs.legacyPackages.${system}.alejandra);

    nixosModules.default = import ./nixos-module.nix {inherit self;};

    checks = forAllSystems (system: let
      pkgs = nixpkgs.legacyPackages.${system};
      configFile = pkgs.writeText "wlt-dns.toml" "";
      evaluated = nixpkgs.lib.nixosSystem {
        inherit system;
        modules = [
          self.nixosModules.default
          {
            system.stateVersion = "26.05";
            services.wltDns = {
              enable = true;
              inherit configFile;
              configDirectory = "/etc/wlt/config.d";
              uid = 398;
            };
          }
        ];
      };
      service = evaluated.config.systemd.services.wlt-dns;
    in {
      nixos-module = assert !evaluated.config.services.wlt.enable;
      assert evaluated.config.users.users.wlt-dns.uid == 398;
      assert evaluated.config.users.groups.wlt-dns.gid == 398;
      assert nixpkgs.lib.hasInfix "/bin/wlt-dns" service.serviceConfig.ExecStart;
      assert nixpkgs.lib.hasInfix "wlt-dns.toml" service.serviceConfig.ExecStart;
      assert nixpkgs.lib.hasInfix "--config-dir" service.serviceConfig.ExecStart;
      assert nixpkgs.lib.elem "CAP_NET_ADMIN" service.serviceConfig.AmbientCapabilities;
        pkgs.runCommand "wlt-nixos-module-check" {} "touch $out";
    });
  };
}

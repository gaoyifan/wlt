{self}: {
  config,
  lib,
  pkgs,
  utils,
  ...
}: let
  cfg = config.services.wlt;
in {
  options.services.wlt = {
    enable = lib.mkEnableOption "WLT outlet selector";

    package = lib.mkOption {
      type = lib.types.package;
      default = self.packages.${pkgs.stdenv.hostPlatform.system}.default;
      description = "WLT package to run.";
    };

    configFile = lib.mkOption {
      type = lib.types.path;
      description = "Path to the main WLT configuration file.";
    };

    configDirectory = lib.mkOption {
      type = lib.types.nullOr lib.types.externalPath;
      default = null;
      description = "Path to the WLT configuration fragment directory.";
    };
  };

  config = lib.mkIf cfg.enable {
    systemd.services.wlt = {
      description = "WLT outlet selector";
      wantedBy = ["multi-user.target"];
      wants = ["network-online.target"];
      after = [
        "network-online.target"
        "nftables.service"
      ];
      serviceConfig = {
        ExecStart = utils.escapeSystemdExecArgs (
          [
            (lib.getExe cfg.package)
            "--config"
            cfg.configFile
          ]
          ++ lib.optionals (cfg.configDirectory != null) [
            "--config-dir"
            cfg.configDirectory
          ]
        );
        Restart = "always";
      };
    };
  };
}

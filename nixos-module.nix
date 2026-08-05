{self}: {
  config,
  lib,
  pkgs,
  ...
}: let
  cfg = config.services.wlt;
in {
  options.services.wlt = {
    enable = lib.mkEnableOption "WLT outlet selector";

    package = lib.mkOption {
      type = lib.types.package;
      default = self.packages.${pkgs.stdenv.hostPlatform.system}.default;
      defaultText = lib.literalExpression "inputs.wlt.packages.${pkgs.stdenv.hostPlatform.system}.default";
      description = "WLT package to run.";
    };

    configFile = lib.mkOption {
      type = lib.types.str;
      description = "Path to the main WLT configuration file.";
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
        ExecStart = "${lib.getExe cfg.package} --config ${cfg.configFile}";
        Restart = "always";
      };
    };
  };
}

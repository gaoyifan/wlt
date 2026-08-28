{self}: {
  config,
  lib,
  pkgs,
  utils,
  ...
}: let
  cfg = config.services.wlt;
  dnsCfg = config.services.wltDns;
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
      type = lib.types.nullOr lib.types.path;
      default = null;
      description = "Path to the WLT configuration fragment directory.";
    };
  };

  options.services.wltDns = {
    enable = lib.mkEnableOption "WLT split-forwarding DNS proxy";

    package = lib.mkOption {
      type = lib.types.package;
      default = self.packages.${pkgs.stdenv.hostPlatform.system}.default;
      description = "WLT package containing the wlt-dns executable.";
    };

    configFile = lib.mkOption {
      type = lib.types.path;
      description = "Path to the wlt-dns configuration file.";
    };

    configDirectory = lib.mkOption {
      type = lib.types.nullOr lib.types.path;
      default = null;
      description = "Path to WLT outlet-group configuration fragments.";
    };

    uid = lib.mkOption {
      type = lib.types.nullOr lib.types.ints.positive;
      default = null;
      description = "Fixed UID for policy rules that select wlt-dns traffic.";
    };
  };

  config = lib.mkMerge [
    (lib.mkIf cfg.enable {
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
    })

    (lib.mkIf dnsCfg.enable {
      users.groups.wlt-dns = lib.optionalAttrs (dnsCfg.uid != null) {
        gid = dnsCfg.uid;
      };
      users.users.wlt-dns =
        {
          isSystemUser = true;
          group = "wlt-dns";
        }
        // lib.optionalAttrs (dnsCfg.uid != null) {
          uid = dnsCfg.uid;
        };

      systemd.services.wlt-dns = {
        description = "WLT DNS data plane";
        wantedBy = ["multi-user.target"];
        wants = ["network-online.target"];
        after = [
          "network-online.target"
          "nftables.service"
        ];
        restartTriggers = [dnsCfg.configFile];
        serviceConfig = {
          User = "wlt-dns";
          Group = "wlt-dns";
          ExecStart = utils.escapeSystemdExecArgs (
            [
              (lib.getExe' dnsCfg.package "wlt-dns")
              "--config"
              dnsCfg.configFile
            ]
            ++ lib.optionals (dnsCfg.configDirectory != null) [
              "--config-dir"
              dnsCfg.configDirectory
            ]
          );
          Restart = "on-failure";
          RestartSec = "2s";
          AmbientCapabilities = [
            "CAP_NET_ADMIN"
            "CAP_NET_BIND_SERVICE"
          ];
          CapabilityBoundingSet = [
            "CAP_NET_ADMIN"
            "CAP_NET_BIND_SERVICE"
          ];
          NoNewPrivileges = true;
          PrivateTmp = true;
          ProtectHome = true;
          ProtectSystem = "strict";
          RestrictAddressFamilies = [
            "AF_INET"
            "AF_INET6"
            "AF_NETLINK"
          ];
        };
      };
    })
  ];
}

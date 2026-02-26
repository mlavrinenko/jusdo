{
  config,
  lib,
  pkgs,
  ...
}:
let
  cfg = config.services.jusdo;

  configFile = pkgs.writeText "jusdo-config.toml" (''
    socket_dir = "${cfg.socketDir}"
    default_duration_mins = ${toString cfg.defaultDurationMins}
    expiry_warn_secs = ${toString cfg.expiryWarnSecs}
  '' + lib.optionalString (cfg.auditLogPath != null) ''
    audit_log_path = "${cfg.auditLogPath}"
  '');
in
{
  options.services.jusdo = {
    enable = lib.mkEnableOption "jusdo — scoped, time-limited sudo just delegation";

    package = lib.mkPackageOption pkgs "jusdo" {
      description = "The jusdo package to use.";
    };

    socketDir = lib.mkOption {
      type = lib.types.str;
      default = "/run/jusdo";
      description = "Directory for the daemon Unix socket.";
    };

    defaultDurationMins = lib.mkOption {
      type = lib.types.ints.positive;
      default = 60;
      description = "Default grant duration in minutes.";
    };

    expiryWarnSecs = lib.mkOption {
      type = lib.types.ints.positive;
      default = 300;
      description = "Seconds before expiry to log warnings.";
    };

    auditLogPath = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      description = "Path for the append-only audit log (null = disabled).";
    };
  };

  config = lib.mkIf cfg.enable {
    environment.etc."jusdo/config.toml".source = configFile;

    systemd.services.jusdo = {
      description = "jusdo — scoped, time-limited sudo just delegation";
      wantedBy = [ "multi-user.target" ];
      after = [ "network.target" ];

      serviceConfig = {
        Type = "simple";
        ExecStart = "${lib.getExe cfg.package} serve";
        Restart = "on-failure";
        RuntimeDirectory = "jusdo";
        RuntimeDirectoryMode = "0755";

        # Hardening
        ProtectSystem = "strict";
        ProtectHome = "read-only";
        PrivateTmp = true;
        # NoNewPrivileges must be false because the daemon spawns `just`
        # which executes arbitrary recipes as root. Enabling this would
        # prevent child processes from gaining capabilities they need.
        NoNewPrivileges = false;
      };
    };
  };
}

# Copyright 2025 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
# Licensed under the Apache License, Version 2.0

{ config, lib, pkgs, ... }:

with lib;

let
  cfg = config.services.peernix;
  
  configFile = pkgs.writeText "peernix.conf" (
    lib.concatStringsSep "\n" (
      lib.mapAttrsToList (name: value:
        "${name} = ${toString value}"
      ) cfg.settings
    )
  );
in
{
  options.services.peernix = {
    enable = mkEnableOption "peernix P2P Nix store sharing";

    package = mkOption {
      type = types.package;
      default = pkgs.peernix;
      description = "The peernix package to use.";
    };

    user = mkOption {
      type = types.str;
      default = "_peernix";
      description = "User account under which peernix runs.";
    };

    uid = mkOption {
      type = types.nullOr types.int;
      default = null;
      description = "Optional UID for the peernix user. If null, no uid is forced.";
    };

    gid = mkOption {
      type = types.int;
      default = 20; # macOS 'staff'
      description = "Primary GID for the peernix user. We do not create this group; it must already exist (e.g. gid 20 = staff).";
    };

    dataDir = mkOption {
      type = types.path;
      default = "/var/lib/peernix";
      description = "Directory where peernix stores its data.";
    };

    settings = mkOption {
      type = types.attrsOf (types.oneOf [ types.str types.int types.bool ]);
      default = {};
      example = {
        "udp-port" = 9999;
        "http-port" = 9999;
        "signing-enabled" = true;
        "compression-enabled" = true;
        "discovery-interval" = "5m";
        "peer-ttl" = "10m";
      };
      description = ''
        Configuration options for peernix in nix.conf format.
        See peernix.conf.example for available options.
      '';
    };
  };

  config = mkIf cfg.enable {
    # Create user
    users.users.${cfg.user} = lib.mkMerge [
      (lib.optionalAttrs (cfg.uid != null) { uid = cfg.uid; })
      {
        description = "peernix service user";
        gid = cfg.gid;
        home = cfg.dataDir;
        createHome = true;
        shell = "/bin/sh";
      }
    ];

    # Ensure data directory exists with correct permissions
    system.activationScripts.peernix = ''
      mkdir -p ${cfg.dataDir}
      chown ${cfg.user}:${toString cfg.gid} ${cfg.dataDir}
      chmod 755 ${cfg.dataDir}
    '';

    # Configure launchd service
    launchd.daemons.peernix = {
      program = "${cfg.package}/bin/peernix";
      serviceConfig = {
        WorkingDirectory = cfg.dataDir;
        StandardOutPath = "/var/log/peernix.log";
        StandardErrorPath = "/var/log/peernix.log";
        KeepAlive = true;
        RunAtLoad = true;
        EnvironmentVariables = {
          PATH = "${pkgs.nix}/bin:${pkgs.coreutils}/bin:/usr/bin:/bin";
        };
        
        # Network service dependencies
        WatchPaths = [ cfg.dataDir ];
        
        # Resource limits
        SoftResourceLimits = {
          NumberOfFiles = 1024;
          NumberOfProcesses = 256;
        };
      };
    };

    system.activationScripts.peernix-config = ''
      if [ ${builtins.toString (builtins.length (builtins.attrNames cfg.settings))} -gt 0 ]; then
        cp ${configFile} ${cfg.dataDir}/peernix.conf
        chown ${cfg.user}:${toString cfg.gid} ${cfg.dataDir}/peernix.conf
        chmod 644 ${cfg.dataDir}/peernix.conf
      fi
    '';

    # Open firewall ports if enabled
    # Note: macOS doesn't have declarative firewall config like NixOS
    # Users need to manually configure Application Firewall or pfctl
    
    # Add helpful environment setup
    environment.systemPackages = [ cfg.package ];
    
    # Add to nix configuration automatically
    nix.settings = mkIf (cfg.settings ? "http-port") {
      extra-trusted-substituters = [ "http://localhost:${toString cfg.settings."http-port"}/nix-cache/" ];
    };
  };
}
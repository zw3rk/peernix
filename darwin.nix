# Copyright 2025 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
# Licensed under the Apache License, Version 2.0

{ config, lib, pkgs, ... }:

with lib;

let
  cfg = config.services.peernix;
  peernix = pkgs.callPackage ./. {};
  
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
      default = peernix;
      description = "The peernix package to use.";
    };

    user = mkOption {
      type = types.str;
      default = "_peernix";
      description = "User account under which peernix runs.";
    };

    group = mkOption {
      type = types.str;
      default = "_peernix";
      description = "Group under which peernix runs.";
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
    # Create user and group
    users.users.${cfg.user} = {
      description = "peernix service user";
      group = cfg.group;
      home = cfg.dataDir;
      createHome = true;
      shell = "/bin/sh";
    };

    users.groups.${cfg.group} = {};

    # Ensure data directory exists with correct permissions
    system.activationScripts.peernix = ''
      mkdir -p ${cfg.dataDir}
      chown ${cfg.user}:${cfg.group} ${cfg.dataDir}
      chmod 755 ${cfg.dataDir}
    '';

    # Configure launchd service
    launchd.agents.peernix = {
      enable = true;
      config = {
        ProgramArguments = [ "${cfg.package}/bin/peernix" ];
        WorkingDirectory = cfg.dataDir;
        StandardOutPath = "${cfg.dataDir}/peernix.log";
        StandardErrorPath = "${cfg.dataDir}/peernix.log";
        KeepAlive = true;
        RunAtLoad = true;
        
        # Set environment variables
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

    # Install configuration file
    system.activationScripts.peernix-config = ''
      if [ ${builtins.toString (builtins.length (builtins.attrNames cfg.settings))} -gt 0 ]; then
        cp ${configFile} ${cfg.dataDir}/peernix.conf
        chown ${cfg.user}:${cfg.group} ${cfg.dataDir}/peernix.conf
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
      extra-substituters = [ "http://localhost:${toString cfg.settings."http-port"}/nix-cache/" ];
      extra-trusted-substituters = [ "http://localhost:${toString cfg.settings."http-port"}/nix-cache/" ];
    };
  };
}
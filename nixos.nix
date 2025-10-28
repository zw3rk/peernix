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
      default = "peernix";
      description = "User account under which peernix runs.";
    };

    group = mkOption {
      type = types.str;
      default = "peernix";
      description = "Group under which peernix runs.";
    };

    dataDir = mkOption {
      type = types.path;
      default = "/var/lib/peernix";
      description = "Directory where peernix stores its data.";
    };

    openFirewall = mkOption {
      type = types.bool;
      default = true;
      description = "Whether to open the firewall for peernix ports.";
    };

    settings = mkOption {
      type = types.attrsOf (types.oneOf [ types.str types.int types.bool ]);
      default = {
        "udp-port" = 9999;
        "http-port" = 9999;
        "signing-enabled" = true;
        "compression-enabled" = true;
        "discovery-interval" = "5m";
        "peer-ttl" = "10m";
        "max-connections" = 10;
        "request-timeout" = "5m";
      };
      example = {
        "udp-port" = 9999;
        "http-port" = 9999;
        "signing-enabled" = true;
        "compression-enabled" = true;
        "discovery-interval" = "5m";
        "peer-ttl" = "10m";
        "max-connections" = 20;
        "request-timeout" = "10m";
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
      homeMode = "0755";
      isSystemUser = true;
    };

    users.groups.${cfg.group} = {};

    # Systemd service
    systemd.services.peernix = {
      description = "peernix P2P Nix store sharing";
      after = [ "network.target" "nix-daemon.service" ];
      wants = [ "network.target" ];
      wantedBy = [ "multi-user.target" ];
      
      serviceConfig = {
        Type = "simple";
        User = cfg.user;
        Group = cfg.group;
        WorkingDirectory = cfg.dataDir;
        ExecStart = "${cfg.package}/bin/peernix";
        Restart = "always";
        RestartSec = "5s";
        
        # Security settings
        NoNewPrivileges = true;
        PrivateTmp = true;
        ProtectSystem = "strict";
        ProtectHome = true;
        ReadWritePaths = [ cfg.dataDir "/nix/store" ];
        
        # Network restrictions
        IPAddressDeny = "any";
        IPAddressAllow = [ "localhost" "10.0.0.0/8" "172.16.0.0/12" "192.168.0.0/16" "fe80::/10" ];
        RestrictAddressFamilies = [ "AF_INET" "AF_INET6" "AF_UNIX" ];
        
        # Resource limits
        LimitNOFILE = 1024;
        LimitNPROC = 256;
        
        # Environment
        Environment = [
          "PATH=${pkgs.nix}/bin:${pkgs.coreutils}/bin"
        ];
      };
      
      preStart = ''
        # Ensure data directory exists
        mkdir -p ${cfg.dataDir}
        chown ${cfg.user}:${cfg.group} ${cfg.dataDir}
        chmod 755 ${cfg.dataDir}
        
        # Install configuration file
        if [ -f ${configFile} ]; then
          cp ${configFile} ${cfg.dataDir}/peernix.conf
          chown ${cfg.user}:${cfg.group} ${cfg.dataDir}/peernix.conf
          chmod 644 ${cfg.dataDir}/peernix.conf
        fi
      '';
    };

    # Open firewall ports
    networking.firewall = mkIf cfg.openFirewall {
      allowedTCPPorts = [ cfg.settings."http-port" ];
      allowedUDPPorts = [ cfg.settings."udp-port" ];
    };
    
    # Add to nix configuration automatically
    nix.settings = {
      extra-substituters = [ "http://localhost:${toString cfg.settings."http-port"}/nix-cache/" ];
      extra-trusted-substituters = [ "http://localhost:${toString cfg.settings."http-port"}/nix-cache/" ];
    };
  };
}
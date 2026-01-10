{
    description = "Mitsubishi Outlander PHEV MQTT proxy on your NixOS system";
    inputs = {
        nixpkgs.url = "github:NixOS/nixpkgs";
        flake-utils.url = "github:numtide/flake-utils";
    };

    outputs = { self, flake-utils, ... }@inputs: rec {
        overlay = final: prev: rec {
            phev2mqtt = with final.lib; final.buildGoModule {
                pname = "phev2mqtt";
                version = if self ? shortRev then self.shortRev else "dirty";
                src = cleanSourceWith {
                    src = ./.;
                    filter = p: t: cleanSourceFilter p t || p == "flake.nix" || p == "flake.lock";
                };
                vendorHash = "sha256-cESihpbkM1vkzBRhEx4sJlWPwvqdj89qEHgILhgx6Zw=";
                buildInputs = [ final.libpcap ];
                meta = {
                    license = licenses.gpl3;
                };
            };
        };

        nixosModules.default = { config, lib, pkgs, utils, ... }: with lib; {
            options.services.phev2mqtt = {
                enable = mkEnableOption "Enable the Mitsubishi Outlander PHEV MQTT proxy service.";
                package = mkOption {
                    description = "The `phev2mqtt` package to use";
                    type = types.package;
                    default = pkgs.phev2mqtt;
                };
                wirelessInterface = mkOption {
                    description = "The wireless interface to use for connection to the PHEV";
                    type = types.str;
                };
                phevAddress = mkOption {
                    description = "The IP address that the PHEV uses (is static & doesn't change)";
                    type = types.str;
                    default = "192.168.8.46";
                };
                mqttBroker = mkOption {
                    description = "Address of the MQTT broker";
                    type = types.str;
                };
                flags = mkOption {
                    description = "Additional flags to pass to the service";
                    type = types.listOf types.str;
                    default = [];
                };
            };

            config = let
                cfg = config.services.phev2mqtt;
                flags = [
                    "--address" "${cfg.phevAddress}:8080"
                    "--mqtt_server" cfg.mqttBroker
                ] ++ cfg.flags;
            in mkIf cfg.enable {
                nixpkgs.overlays = [ overlay ];
                networking.wireless.interfaces = [ cfg.wirelessInterface ];

                systemd.services."wpa_supplicant-${cfg.wirelessInterface}" = {
                    requires = lib.mkForce [];
                    wantedBy = lib.mkForce [];
                    bindsTo = [ "sys-subsystem-net-devices-${cfg.wirelessInterface}.device" ];
                    upheldBy = [ "sys-subsystem-net-devices-${cfg.wirelessInterface}.device" ];
                    serviceConfig.BindPaths = [ "/etc/wpa_supplicant_${cfg.wirelessInterface}.conf:/etc/wpa_supplicant.conf" ];
                };

                systemd.services.phev2mqtt = {
                    description = "Mitsubishi Outlander PHEV MQTT proxy";
                    wantedBy = [ "multi-user.target" ];
                    unitConfig.StartLimitIntervalSec = "0s";
                    serviceConfig = {
                        Type = "exec";
                        ExecStart = utils.escapeSystemdExecArgs (
                            [ "${pkgs.phev2mqtt}/bin/phev2mqtt"  "client" "mqtt" "--interface" cfg.wirelessInterface ] ++ flags
                        );
                        WatchdogSec = 1200;
                        Restart = "always";
                        RestartSec = 5;
                        DynamicUser = 1;
                        Environment = "GOMAXPROCS=1";
                        LimitMEMLOCK = "0";
                        LockPersonality = "true";
                        PrivateDevices = "true";
                        ProtectClock = "true";
                        ProtectControlGroups = "true";
                        ProtectHome = "true";
                        ProtectHostname = "true";
                        ProtectKernelLogs = "true";
                        ProtectKernelModules = "true";
                        ProtectKernelTunables = "true";
                        ProtectProc = "invisible";
                        RestrictAddressFamilies = "AF_INET AF_UNIX AF_NETLINK";
                        RestrictNamespaces = "yes";
                        RestrictRealtime = "true";
                        SystemCallArchitectures = "native";
                        CapabilityBoundingSet = "CAP_NET_RAW";
                        AmbientCapabilities = "CAP_NET_RAW";
                        SystemCallFilter = [ "@system-service" "@network-io" ];
                        UMask = 0077;
                    };
                };
            };
        };
    } // flake-utils.lib.eachDefaultSystem (system: {
        packages = with import inputs.nixpkgs { inherit system; overlays = [ self.overlay ]; }; {
            inherit phev2mqtt;
        };
        apps.default = {
            type = "app";
            program = "${self.packages.${system}.phev2mqtt}/bin/phev2mqtt";
        };
    });
}

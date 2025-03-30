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
                vendorHash = "sha256-1Ci2ULhcAQzmXA6Ms1+l20rXRUa0lNxRW51hGfBPKKk=";
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
                    "--wifi_restart_command" "''"
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
                    partOf = [ "ping-${cfg.wirelessInterface}.service" ];
                    serviceConfig.BindPaths = [ "/etc/wpa_supplicant_${cfg.wirelessInterface}.conf:/etc/wpa_supplicant.conf" ];
                };

                systemd.services."ping-${cfg.wirelessInterface}" = {
                    # This service covers in particular a number of failure modes I've seen in
                    # PHEV connection: first is that frequently DHCP server will not respond
                    # after association, and second is that at some point the association gets
                    # in a state where communication is no longer possible. PHEV appears to be
                    # setting up a firewall or something based on the DHCP leases it gave out –
                    # statically assigning IP addresses does *not* work.
                    bindsTo = [ "wpa_supplicant-${cfg.wirelessInterface}.service" ];
                    wantedBy = [ "wpa_supplicant-${cfg.wirelessInterface}.service" ];
                    after = [ "wpa_supplicant-${cfg.wirelessInterface}.service" ];
                    script = ''
                        set -e
                        ${pkgs.coreutils}/bin/sleep 30
                        while true; do
                            # This will exit with a failure code if there isn't a successful
                            # response in `-w 60` seconds. It will send an ICMP ping every `-i
                            # 5` second on the `wirelessInterface`.
                            ${pkgs.iputils}/bin/ping ${cfg.phevAddress} -w 30 -c 1 -i 5 -I ${cfg.wirelessInterface} -q > /dev/null
                            ${pkgs.coreutils}/bin/sleep 60
                        done
                    '';
                    serviceConfig = {
                        Restart = "always";
                        RestartSec = 5;
                    };
                };

                systemd.services.phev2mqtt = {
                    description = "Mitsubishi Outlander PHEV MQTT proxy";
                    wantedBy = [ "multi-user.target" ];
                    unitConfig.StartLimitIntervalSec = "0s";
                    serviceConfig = {
                        Type = "exec";
                        ExecStart = utils.escapeSystemdExecArgs (
                            [ "${pkgs.phev2mqtt}/bin/phev2mqtt"  "client" "mqtt" ] ++ flags
                        );
                        WatchdogSec = 1200;
                        Restart = "always";
                        RestartSec = 5;
                        DynamicUser = 1;
                        Environment = "GOMAXPROCS=1";
                        LimitMEMLOCK = "0";
                        LockPersonality = "true";
                        PrivateDevices = "true";
                        PrivateUsers = "yes";
                        ProtectClock = "true";
                        ProtectControlGroups = "true";
                        ProtectHome = "true";
                        ProtectHostname = "true";
                        ProtectKernelLogs = "true";
                        ProtectKernelModules = "true";
                        ProtectKernelTunables = "true";
                        ProtectProc = "noaccess";
                        RestrictAddressFamilies = "AF_INET AF_INET6 AF_UNIX";
                        RestrictNamespaces = "yes";
                        RestrictRealtime = "true";
                        SystemCallArchitectures = "native";
                        SystemCallFilter = ["@system-service" "~@privileged"];
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

# phev2mqtt - Mitsubishi Outlander PHEV to MQTT gateway

Utility to interact with a Mitsubishi Outlander PHEV via the Wifi remote
control protocol.

Inspired by https://github.com/phev-remote/ but written entirely in Go.

For further hacking, read the [protocol documentation](protocol/README.md).

Tested against a MY18 vehicle.

## Supported functionality

 * MQTT proxy to Phev, as a [Homie 5](https://homieiot.github.io/) device
 * Register client to car
 * Fetch battery, charge, door, light status
 * Set lights and charge enable
 * Near-instant response to commands
 * *Only tested on a MY18 Phev*

Also includes some debugging utilities, and a vehicle emulator.

## Requirements

 * Go compiler

## Licence, etc

Licenced under the GPLv2.

Copyright 2021 Ben Buxton <bbuxton@gmail.com>

Contributions and PRs are welcome.

## Getting started.

### Compiling

#### Install Go

 * Download and install the latest [Go compiler](https://golang.org/dl/)
   * Your distro packager may have a version thats too old
   * For raspbian choose the ARMv6 release

#### Install PCAP dev libraries

 * Optionally, you may want to have libpcap-dev package installed (if building with `-tags pcap`.)

#### Download, extract, and compile phev2mqtt

 * Download the phev2mqtt archive
 * Extract it
 * Go into its the top level directory and run `go build`
 * Verify it runs with `./phev2mqtt -h`

### Connecting to the vehicle.

#### Configure Wifi client on system running mqtt2phev

On your computer running the phev2mqtt tools, configure a new Wifi connection to the
car's SSID,

#### Register the client to the car

Follow the [Mitsubishi instructions](https://www.mitsubishi-motors.com/en/products/outlander_phev/app/remote/)
to find the Wifi credentials provided with the car.

Verify that your Wifi connection to the car is established - your local IP address
should be 192.168.8.47.

Follow the [Mitsubishi instructions](https://www.mitsubishi-motors.com/en/products/outlander_phev/app/remote/)
and put the car into registration mode ("Setup Your Vehicle"). You may need to
re-establish the Wifi connection.

Register by running `phev2mqtt client register` and you should shortly see a message
indicating successful registration.

#### Testing the tool

Once connected to the car, you can sniff for messages by running *phev2mqtt client watch*.
The phone client needs to be disconnected for this to work.
You'll see a bunch of data go by - some of those will be decoded into readable
messages such as charge and AC status.

### MQTT Gateway

The primary feature of this code is to run as a proxy between the car and
MQTT. The car is published as the [Homie 5](https://homieiot.github.io/specification/) device
`homie/5/phev`, and its settable properties control certain aspects of the vehicle.

Start the MQTT gateway with:

`./phev2mqtt client mqtt --mqtt_server tcp://<your_mqtt_address:1883/ [--mqtt_username <mqtt_username>] [--mqtt_password <mqtt_password>]`

The device's `$state` is *ready* while the car is connected, *disconnected* otherwise, and *lost*
when phev2mqtt is gone. Its properties are below, relative to `homie/5/phev/`. Booleans are
*true* or *false*. Set a settable property by publishing to its topic followed by `/set`. Sets are
ignored, and logged, while the car isn't connected.

| Property | Type | Settable | Description |
|---|---|---|---|
| battery/level | integer, % | | Current drive battery level |
| charge/charging | boolean | | Whether the battery is charging |
| charge/remaining | integer, min | | Minutes left, if charging |
| charge/plug | boolean | | Whether the charging plug is connected |
| charge/cancel-timer | enum *cancel* | yes, not retained | Cancel the charge timer |
| doors/locked | boolean | | Whether the car is locked |
| doors/driver | boolean | | Whether the door is open |
| doors/front-passenger | boolean | | Whether the door is open |
| doors/rear-left | boolean | | Whether the door is open |
| doors/rear-right | boolean | | Whether the door is open |
| doors/bonnet | boolean | | Whether the bonnet is open |
| doors/boot | boolean | | Whether the boot is open |
| lights/head | boolean | yes | Head lights |
| lights/parking | boolean | yes | Parking lights |
| lights/interior | boolean | | Interior lights |
| lights/hazard | boolean | | Hazard lights |
| climate/state | enum *off*, *heat*, *cool*, *windscreen*, *terminated* | | AC/climate state |
| climate/command | JSON | yes, not retained | Turn the climate on or off, e.g. `{"mode":"heat","duration":20}`. `mode` is *off*, *heat*, *cool* or *windscreen*; `duration` is 10, 20 or 30 minutes, 10 by default. *off* while terminated clears the termination |
| car/vin | string | | VIN of the car |
| car/ecu-version | string | | ECU version |
| car/registrations | integer | | Number of wifi clients registered to the car |
| connection/state | enum *offline*, *waiting-for-ip*, *connecting*, *online* | | Wifi connection status to the car |
| connection/command | enum *off*, *on*, *restart* | yes, not retained | Change the car connection state |

Raw register values are logged at the debug level, with the register and the data as fields.

Under systemd, the logs go to the journal natively, with their priorities and with their fields as
`F_<FIELD>` journal fields. Plain `journalctl -u phev2mqtt` shows only the messages; use `-o verbose`
or `-o json` for the fields.

#### Raspbian setup with auto-start

It's useful to have the tool auto-start when running on e.g a Raspberry Pi. The following
describes how to set this up.

- Edit or add to `/etc/systemd/network/00-default.link` with the following:

```
[Match]
# This should be the 'real' (default) mac address of the Pi's wireless interface.
MACAddress=b8:27:eb:50:c0:52

[Link]
# This should be the MAC address to use to connect to the car, per above.
MACAddress=ee:4d:ec:de:7a:91
NamePolicy=kernel database onboard slot path

```

- Add the car's Wifi info to `/etc/wpa_supplicant/wpa_supplicant.conf`:

```
ctrl_interface=DIR=/var/run/wpa_supplicant GROUP=netdev
update_config=1
country=AU

network={
	ssid="REMOTE45bhds"
	scan_ssid=1
	psk="blahblahbla12314"
}

```

- Copy `phev2mqtt.service.example` to `/etc/systemd/system/phev2mqtt.service`, updating the MQTT
address to suit your setup.

- Copy the `phev2mqtt` binary to /usr/local/bin and make sure it's executable.

- Start the service with `sudo systemctl start phev2mqtt.service`

- Enable the service to run at boot, with `sudo systemctl enable phev2mqtt.service`.

- Restart the Pi and verify that it can connect to the car. Also run `ifconfig` and check
that the `wlan0` interface has the correct mac address. You should also see this interface
have the IP address `192.168.8.47`.

- Verify that the phev2mqtt service is communicating with the car, by checking
the logs: `sudo journalctl -f -u phev2mqtt -o cat`

### Sniffing the official client

Further development of this library can be done with a packet dump of the official
Mistubishi app.

A number of sniffer apps for phones are available for this. Two that the author have
used are *Packet Capture* and *PCAP Remote*. These do not require root access, yet
can successfully sniff the traffic into PCAP files for further analysis.

*Packet Capture* can save the PCAP files to your local phone storage which you can
then extract off the phone.

*PCAP Remote* is a little more involved, but allows for live sniffing of the traffic.

Once you have downloaded the PCAP file(s) from the phone, you can analyse them with
the command *phev2mqtt decode pcap <filename>*. First build a `phev2mqtt` with pcap features:
`go build -tags pcap`; you will need libpcap for this. Adjust the verbosity level (`-v`) between
`info`, `debug` and `trace` for more details.

Additionally, the flag `--latency` will use the PCAP packet timestamps to decode
the packets with original timings which can help pinpoint app events.

You can also specify *tcp:<host>:<port>* which will connect to that host/port
over TCP and decode that traffic - useful when live sniffing to a TCP service.

### Vehicle emulator

There is an emulator built in which can be used to test functionality without needing
a real car (and also reduces risk of putting your car into weird states).

Start it with `phev2mqtt emulator` and then you can point a client at it.

The official app will always try to connect to IP `192.168.8.46`, so you'll need
to ensure you run `phev2mqtt` on a machine with this IP and which you can
reach via WIFI. The author uses a Raspberry Pi setup as an AP (using hostapd)
and runs `phev2mqtt` on it, though you could also tunnel the TCP connection to
a dev machine.

The app should successfully be able to register with the emulator (it might take
a couple of goes).

Any settings sent by the app won't actually change state for now, but it can
be useful for sniffing the app.

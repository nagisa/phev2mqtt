/*
Copyright © 2021 Ben Buxton <bbuxton@gmail.com>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program. If not, see <http://www.gnu.org/licenses/>.
*/
package cmd

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"github.com/buxtronix/phev2mqtt/client"
	"github.com/buxtronix/phev2mqtt/protocol"
	"github.com/spf13/cobra"
	"os/exec"
	"strings"
	"time"
	"context"
	"net"
	"syscall"
	"os"

	mqtt "github.com/eclipse/paho.mqtt.golang"
	netlink "github.com/vishvananda/netlink"
	log "github.com/sirupsen/logrus"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

const defaultWifiRestartCmd = "sudo ip link set wlan0 down && sleep 3 && sudo ip link set wlan0 up"

// mqttCmd represents the mqtt command
var mqttCmd = &cobra.Command{
	Use:   "mqtt",
	Short: "Start an MQTT bridge.",
	Long: `Maintains a connected to the Phev (retry as needed) and also to an MQTT server.

Status data from the car is passed to the MQTT topics, and also some commands from MQTT
are sent to control certain aspects of the car. See the phev2mqtt Github page for
more details on the topics.
`,
	RunE: func(cmd *cobra.Command, args []string) error {
		mc := &mqttClient{climate: new(climate)}
		return mc.Run(cmd, args)
	},
}

// Tracks complete climate state as on and mode are separately
// sent by the car.
type climate struct {
	state *protocol.PreACState
	mode  *string
}

func (c *climate) setMode(m string) {
	c.mode = &m
}
func (c *climate) setState(state protocol.PreACState) {
	c.state = &state
}

func (c *climate) mqttStates() map[string]string {
	m := map[string]string{
		"/climate/state":      "off",
		"/climate/cool":       "off",
		"/climate/heat":       "off",
		"/climate/windscreen": "off",
	}
	if c.mode == nil || c.state == nil {
		return m
	}
	switch *c.state {
	case protocol.PreACOn: m["/climate/state"] = *c.mode
	case protocol.PreACOff: {
		m["/climate/state"] = "off"
		return m
	}
	case protocol.PreACTerminated: {
		m["/climate/state"] = "terminated"
		return m
	}
	default: {
		m["/climate/state"] = "unknown"
		return m
	}
	}
	m["/climate/state"] = *c.mode
	switch *c.mode {
	case "cool":
		m["/climate/cool"] = "on"
	case "heat":
		m["/climate/heat"] = "on"
	case "windscreen":
		m["/climate/windscreen"] = "on"
	}
	return m
}

var lastWifiRestart time.Time

func restartWifi(cmd *cobra.Command) error {
	restartRetryTime, err := cmd.Flags().GetDuration("wifi_restart_retry_time")
	if err != nil {
		return err
	}
	if time.Now().Sub(lastWifiRestart) < restartRetryTime {
		return nil
	}
	defer func() {
		lastWifiRestart = time.Now()
	}()

	restartCommand, _ := cmd.Flags().GetString("wifi_restart_command")
	if restartCommand == "" {
		log.Debugf("wifi restart disabled")
		return nil
	}

	log.Infof("Attempting to restart wifi")

	restartCmd := exec.Command("sh", "-c", restartCommand)

	stdoutStderr, err := restartCmd.CombinedOutput()
	log.Infof("Output from wifi restart: %s", stdoutStderr)
	return err
}

type mqttClient struct {
	client         mqtt.Client
	options        *mqtt.ClientOptions
	mqttData       map[string]string

	interfaceName  string
	pingInterval   time.Duration

	phev           *client.Client
	updateInterval time.Duration
	everPublishedBatteryLevel bool

	prefix string

	haDiscovery       bool
	haDiscoveryPrefix string

	climate *climate
	enabled bool
}

func (m *mqttClient) topic(topic string) string {
	return fmt.Sprintf("%s%s", m.prefix, topic)
}

func (m *mqttClient) Run(cmd *cobra.Command, args []string) error {
	var err error

	m.enabled = true // Default.
	mqttServer, _ := cmd.Flags().GetString("mqtt_server")
	mqttUsername, _ := cmd.Flags().GetString("mqtt_username")
	mqttPassword, _ := cmd.Flags().GetString("mqtt_password")
	m.prefix, _ = cmd.Flags().GetString("mqtt_topic_prefix")
	m.haDiscovery, _ = cmd.Flags().GetBool("ha_discovery")
	m.haDiscoveryPrefix, _ = cmd.Flags().GetString("ha_discovery_prefix")
	m.updateInterval, err = cmd.Flags().GetDuration("update_interval")
	m.pingInterval, err = cmd.Flags().GetDuration("ping_interval")
	if err != nil {
		return err
	}
	watchdogInterval, _ := client.SdWatchdogInterval(600 * time.Second)
	if m.pingInterval > watchdogInterval {
		m.pingInterval = watchdogInterval
	}

	m.interfaceName, err = cmd.Flags().GetString("interface")
	if err != nil {
		return err
	}

	m.options = mqtt.NewClientOptions().
		AddBroker(mqttServer).
		SetClientID("phev2mqtt").
		SetUsername(mqttUsername).
		SetPassword(mqttPassword).
		SetAutoReconnect(true).
		SetDefaultPublishHandler(m.handleIncomingMqtt).
		SetWill(m.topic("/available"), "offline", 2, true)

	m.client = mqtt.NewClient(m.options)
	if token := m.client.Connect(); token.Wait() && token.Error() != nil {
		return token.Error()
	}

	if token := m.client.Subscribe(m.topic("/set/#"), 0, nil); token.Wait() && token.Error() != nil {
		return token.Error()
	}
	if token := m.client.Subscribe(m.topic("/connection"), 0, nil); token.Wait() && token.Error() != nil {
		return token.Error()
	}
	if token := m.client.Subscribe(m.topic("/settings/#"), 0, nil); token.Wait() && token.Error() != nil {
		return token.Error()
	}

	m.mqttData = map[string]string{}

	for {
		if m.enabled {
			if err := m.handlePhev(cmd); err != nil {
				log.Error(err)
			}
			time.Sleep(time.Second)
		}
	}
}

func (m *mqttClient) publish(topic, payload string) {
	if cache := m.mqttData[topic]; cache != payload {
		m.client.Publish(m.topic(topic), 2, true, payload)
		m.mqttData[topic] = payload
	}
}

func (m *mqttClient) handleIncomingMqtt(mqtt_client mqtt.Client, msg mqtt.Message) {
	log.Infof("Topic: [%s] Payload: [%s]", msg.Topic(), msg.Payload())

	topicParts := strings.Split(msg.Topic(), "/")
	context := context.Background()
	if strings.HasPrefix(msg.Topic(), m.topic("/set/register/")) {
		if len(topicParts) != 4 {
			log.Infof("Bad topic format [%s]", msg.Topic())
			return
		}
		register, err := hex.DecodeString(topicParts[3])
		if err != nil {
			log.Infof("Bad register in topic [%s]: %v", msg.Topic(), err)
			return
		}
		data, err := hex.DecodeString(string(msg.Payload()))
		if err != nil {
			log.Infof("Bad payload [%s]: %v", msg.Payload(), err)
			return
		}
		if err := m.phev.SetRegister(context, register[0], data); err != nil {
			log.Infof("Error setting register %02x: %v", register[0], err)
			return
		}
	} else if msg.Topic() == m.topic("/connection") {
		payload := strings.ToLower(string(msg.Payload()))
		switch payload {
		case "off":
			m.enabled = false
			m.phev.Close()
			m.client.Publish(m.topic("/available"), 2, true, "offline")
		case "on":
			m.enabled = true
		case "restart":
			m.enabled = true
			m.client.Publish(m.topic("/available"), 2, true, "offline")
			m.phev.Close()
		}
	} else if msg.Topic() == m.topic("/set/parkinglights") {
		values := map[string]byte{"on": 0x1, "off": 0x2}
		if v, ok := values[strings.ToLower(string(msg.Payload()))]; ok {
			if err := m.phev.SetRegister(context, 0xb, []byte{v}); err != nil {
				log.Infof("Error setting register 0xb: %v", err)
				return
			}
		}
	} else if msg.Topic() == m.topic("/set/headlights") {
		values := map[string]byte{"on": 0x1, "off": 0x2}
		if v, ok := values[strings.ToLower(string(msg.Payload()))]; ok {
			if err := m.phev.SetRegister(context, 0xa, []byte{v}); err != nil {
				log.Infof("Error setting register 0xb: %v", err)
				return
			}
		}
	} else if msg.Topic() == m.topic("/set/cancelchargetimer") {
		if err := m.phev.SetRegister(context, 0x17, []byte{0x1}); err != nil {
			log.Infof("Error setting register 0x17: %v", err)
			return
		}
		if err := m.phev.SetRegister(context, 0x17, []byte{0x11}); err != nil {
			log.Infof("Error setting register 0x17: %v", err)
			return
		}
	} else if strings.HasPrefix(msg.Topic(), m.topic("/set/climate/state")) {
		payload := strings.ToLower(string(msg.Payload()))
		if payload == "reset" {
			if err := m.phev.SetRegister(context, protocol.SetAckPreACTermRegister, []byte{0x1}); err != nil {
				log.Infof("Error acknowledging Pre-AC termination: %v", err)
				return
			}
		}
	} else if strings.HasPrefix(msg.Topic(), m.topic("/set/climate/")) {
		topic := msg.Topic()
		payload := strings.ToLower(string(msg.Payload()))

		modeMap := map[string]byte{"off": 0x0, "OFF": 0x0, "cool": 0x1, "heat": 0x2, "windscreen": 0x3, "mode": 0x4}
		durMap := map[string]byte{"10": 0x0, "20": 0x1, "30": 0x2, "on": 0x0, "off": 0x0}
		parts := strings.Split(topic, "/")
		mode, ok := modeMap[parts[len(parts)-1]]
		if !ok {
			log.Errorf("Unknown climate mode: %s", parts[len(parts)-1])
			return
		}
		if mode == 0x4 { // set/climate/mode -> "heat"
			mode = modeMap[payload]
			payload = "on"
		}
		if payload == "off" {
			mode = 0x0
		}
		duration, ok := durMap[payload]
		if mode != 0x0 && !ok {
			log.Errorf("Unknown climate duration: %s", payload)
			return
		}

		if m.phev.ModelYear == client.ModelYear14 {
			// Set the AC mode first
			registerPayload := bytes.Repeat([]byte{0xff}, 15)
			registerPayload[0] = 0x0
			registerPayload[1] = 0x0
			registerPayload[6] = mode | duration
			if err := m.phev.SetRegister(context, protocol.SetACModeRegisterMY14, registerPayload); err != nil {
				log.Infof("Error setting AC mode: %v", err)
				return
			}

			// Then, enable/disable the AC
			acEnabled := byte(0x02)
			if mode == 0x0 {
				acEnabled = 0x01
			}
			if err := m.phev.SetRegister(context, protocol.SetACEnabledRegisterMY14, []byte{acEnabled}); err != nil {
				log.Infof("Error setting AC enabled state: %v", err)
				return
			}
		} else if m.phev.ModelYear == client.ModelYear18 {
			state := byte(0x02)
			if mode == 0x0 {
				state = 0x1
			}
			if err := m.phev.SetRegister(context, protocol.SetACModeRegisterMY18, []byte{state, mode, duration, 0x0}); err != nil {
				log.Infof("Error setting AC mode: %v", err)
				return
			}
		}
	} else if msg.Topic() == m.topic("/settings/dump") {
		log.Infof("CURRENT_SETTINGS:")
		log.Infof("\n%s", m.phev.Settings.Dump())
		m.phev.Settings.Clear()
	} else {
		log.Errorf("Unknown topic from mqtt: %s", msg.Topic())
	}
}

// Determine if the WiFi link is in a good enough state to start connecting to PHEV.
//
// A common situation where this matters is the vehicle driving away out of the WiFi range.
// At which point, why bother spinning our wheels? Kernel will notify us via netlink as
// soon as the link state changes again (i.e. vehicle enters the driveway.)
func (m *mqttClient) evaluateLinkState() bool {
	link, err := netlink.LinkByName(m.interfaceName)
	// WiFi interface is not present altogether.
	if err != nil {
		log.Errorf("interface `%s` is not available: %v", m.interfaceName, err);
		m.client.Publish(m.topic("/available"), 2, true, "offline")
		return false
	}
	// WiFi is not associated. E.g. vehicle not in the driveway.
	if link.Attrs().OperState != netlink.OperUp {
		log.Debugf("interface `%s` is not up", m.interfaceName);
		m.client.Publish(m.topic("/available"), 2, true, "offline")
		return false
	}

	addrs, _ := netlink.AddrList(link, netlink.FAMILY_V4)
	log.Debugf("interface `%s` is up and has following addresses: %v", m.interfaceName, addrs);
	var validIP net.IP = nil
	for _, addr := range addrs {
		ip := addr.IP
		if ip.IsLoopback() {
			continue
		}
		if ip.IsLinkLocalUnicast() {
			continue
		}
		validIP = ip
		break
	}

	if validIP == nil {
		m.client.Publish(m.topic("/available"), 2, true, "waiting-for-ip")
		return false
	} else {
		return true
	}
}

// Send out an ICMP message to the PHEV.
//
// We don't really care if PHEV responds, the only reason is to keep the connection
// alive and try to prevent PHEV from going to some sort of weird sleep state where
// it entirely stops communicating with us.
//
// If you care to see the full comms, use tcpdump on your wireless interface.
func (m *mqttClient) pingTarget(ctx context.Context, address string) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		host = address
	}
	resolver := net.DefaultResolver
	ips, err := resolver.LookupIP(ctx, "ip4", host)
	if err != nil || len(ips) == 0 {
		return fmt.Errorf("could not resolve %s: %v", host, err)
	}
	dstIP := ips[0]
	lc := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) {
				syscall.BindToDevice(int(fd), m.interfaceName)
			})
		},
	}
	conn, err := lc.ListenPacket(ctx, "ip4:icmp", "0.0.0.0")
	if err != nil {
		return err
	}
	defer conn.Close()

	msg := icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Code: 0,
		Body: &icmp.Echo{
			ID: os.Getpid() & 0xffff, Seq: 1,
			Data: []byte("phev2mqtt"),
		},
	}
	wb, err := msg.Marshal(nil)
	if err != nil {
		return err
	}
	_, err = conn.WriteTo(wb, &net.IPAddr{IP: dstIP})
	return err
}

func (m *mqttClient) handlePhev(cmd *cobra.Command) error {
	var err error

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	pingTicker := time.NewTicker(m.pingInterval)
	defer pingTicker.Stop()
	updateTicker := time.NewTicker(m.updateInterval)
	defer updateTicker.Stop()

	address, _ := cmd.Flags().GetString("address")
	m.phev, err = client.New(client.AddressOption(address))
	if err != nil {
		return err
	}

	// Wait for the interface to become available.
	linkChanges := make(chan netlink.LinkUpdate)
	netlinkOk := false
	if err := netlink.LinkSubscribe(linkChanges, ctx.Done()); err != nil {
		log.Errorf("could not subscribe to netlink link changes: %v", err)
		netlinkOk = false
	}
	addrChanges := make(chan netlink.AddrUpdate)
    if err := netlink.AddrSubscribe(addrChanges, ctx.Done()); err != nil {
		log.Errorf("could not subscribe to netlink address changes: %v", err)
		netlinkOk = false
    }
	if !m.evaluateLinkState() && netlinkOk {
		loop: for {
			select {
			case <-pingTicker.C:
				if _, err := client.SdNotify(false, client.SdNotifyWatchdog); err != nil {
					log.Warnf("could not reset systemd watchdog: %v", err)
				}
			case <-linkChanges:
				if m.evaluateLinkState() {
					break loop
				}
			case <-addrChanges:
				if m.evaluateLinkState() {
					break loop
				}
			}
		}
	}

	m.client.Publish(m.topic("/available"), 2, true, "connecting")
	m.everPublishedBatteryLevel = false
	var encodingErrorCount = 0
	var lastEncodingError time.Time

	connectResult := make(chan error)
	go func() {
		if err := m.phev.Connect(ctx); err != nil {
			connectResult <- err
			return
		}
		if err := m.phev.Start(ctx); err != nil {
			connectResult <- err
			return
		}
		connectResult <- nil
	}()

	for {
		select {
		case err := <- connectResult:
			if err == nil {
				m.client.Publish(m.topic("/available"), 2, true, "online")
			} else {
				return err
			}
		case <-linkChanges:
		 	if !m.evaluateLinkState() {
				return fmt.Errorf("interface disconnected")
			}
		case <-addrChanges:
		 	if !m.evaluateLinkState() {
				return fmt.Errorf("interface disconnected")
			}
		case <-updateTicker.C:
			go func(m *mqttClient, ctx context.Context) {
				if err := m.phev.SetRegister(ctx, 0x6, []byte{0x3}); err != nil {
					log.Warnf("no response to update request: ", err)
				}
			}(m, ctx)
		case <-pingTicker.C:
			go func(m *mqttClient, ctx context.Context) {
				if err := m.pingTarget(ctx, address); err != nil {
					log.Warnf("can't ping at ipv4 level: ", err)
				}
			}(m, ctx)
		case msg, ok := <-m.phev.Recv:
			if !ok {
				pingTicker.Stop()
				return fmt.Errorf("connection closed")
			}
			switch msg.Type {
			case protocol.CmdInBadEncoding:
				if time.Now().Sub(lastEncodingError) > 30*time.Second {
					encodingErrorCount = 0
				}
				if encodingErrorCount > 5 {
					m.phev.Close()
					return fmt.Errorf("disconnecting due to too many errors")
				}
				encodingErrorCount += 1
				lastEncodingError = time.Now()
			case protocol.CmdInResp:
				if msg.Ack != protocol.Request {
					break
				}
				m.publishRegister(msg)
				m.phev.Send <- &protocol.PhevMessage{
					Type:     protocol.CmdOutSend,
					Register: msg.Register,
					Ack:      protocol.Ack,
					Xor:      msg.Xor,
					Data:     []byte{0x0},
				}
			}
		}
	}
}

var boolOnOff = map[bool]string{
	false: "off",
	true:  "on",
}
var boolOpen = map[bool]string{
	false: "closed",
	true:  "open",
}

func (m *mqttClient) publishRegister(msg *protocol.PhevMessage) {
	dataStr := hex.EncodeToString(msg.Data)
	m.publish(fmt.Sprintf("/register/%02x", msg.Register), dataStr)
	switch reg := msg.Reg.(type) {
	case *protocol.RegisterVIN:
		m.publish("/vin", reg.VIN)
		m.publishHomeAssistantDiscovery(reg.VIN, m.prefix, "Phev")
		m.publish("/registrations", fmt.Sprintf("%d", reg.Registrations))
	case *protocol.RegisterECUVersion:
		m.publish("/ecuversion", reg.Version)
	case *protocol.RegisterACMode:
		m.climate.setMode(reg.Mode)
		for t, p := range m.climate.mqttStates() {
			m.publish(t, p)
		}
	case *protocol.RegisterPreACState:
		m.climate.setState(reg.State)
		for t, p := range m.climate.mqttStates() {
			m.publish(t, p)
		}
	case *protocol.RegisterChargeStatus:
		m.publish("/charge/charging", boolOnOff[reg.Charging])
		m.publish("/charge/remaining", fmt.Sprintf("%d", reg.Remaining))
	case *protocol.RegisterDoorStatus:
		m.publish("/door/locked", boolOpen[!reg.Locked])
		m.publish("/door/rear_left", boolOpen[reg.RearLeft])
		m.publish("/door/rear_right", boolOpen[reg.RearRight])
		m.publish("/door/front_right", boolOpen[reg.Driver])
		m.publish("/door/driver", boolOpen[reg.Driver])
		m.publish("/door/front_left", boolOpen[reg.FrontPassenger])
		m.publish("/door/front_passenger", boolOpen[reg.FrontPassenger])
		m.publish("/door/bonnet", boolOpen[reg.Bonnet])
		m.publish("/door/boot", boolOpen[reg.Boot])
		m.publish("/lights/head", boolOnOff[reg.Headlights])
	case *protocol.RegisterBatteryLevel:
		if !m.everPublishedBatteryLevel || reg.Level > 5 {
			m.everPublishedBatteryLevel = true
			m.publish("/battery/level", fmt.Sprintf("%d", reg.Level))
		} else {
			log.Debugf("Ignoring battery level reading: %v", reg.Level)
		}
		m.publish("/lights/parking", boolOnOff[reg.ParkingLights])
	case *protocol.RegisterLightStatus:
		m.publish("/lights/interior", boolOnOff[reg.Interior])
		m.publish("/lights/hazard", boolOnOff[reg.Hazard])
	case *protocol.RegisterChargePlug:
		if reg.Connected {
			m.publish("/charge/plug", "connected")
		} else {
			m.publish("/charge/plug", "unplugged")
		}
	}
}

// Publish home assistant discovery message.
// Uses the vehicle VIN, so sent after VIN discovery.
var publishedDiscovery = false

func (m *mqttClient) publishHomeAssistantDiscovery(vin, topic, name string) {

	if publishedDiscovery || !m.haDiscovery {
		return
	}
	publishedDiscovery = true
	discoveryData := map[string]string{
		// Doors.
		"%s/binary_sensor/%s_door_locked/config": `{
		"device_class": "lock",
		"name": "__NAME__ Locked",
		"state_topic": "~/door/locked",
		"payload_off": "closed",
		"payload_on": "open",
		"avty_t": "~/available",
		"unique_id": "__VIN___door_locked",
		"device": {
			"name": "PHEV __VIN__",
			"identifiers": ["phev-__VIN__"],
			"manufacturer": "Mitsubishi",
			"model": "Outlander PHEV"},
		"~": "__TOPIC__"}`,
		"%s/binary_sensor/%s_door_bonnet/config": `{
		"device_class": "door",
		"name": "__NAME__ Bonnet",
		"state_topic": "~/door/bonnet",
		"payload_off": "closed",
		"payload_on": "open",
		"avty_t": "~/available",
		"unique_id": "__VIN___door_bonnet",
		"device": {
			"name": "PHEV __VIN__",
			"identifiers": ["phev-__VIN__"],
			"manufacturer": "Mitsubishi",
			"model": "Outlander PHEV"},
		"~": "__TOPIC__"}`,
		"%s/binary_sensor/%s_door_boot/config": `{
		"device_class": "door",
		"name": "__NAME__ Boot",
		"state_topic": "~/door/boot",
		"payload_off": "closed",
		"payload_on": "open",
		"avty_t": "~/available",
		"unique_id": "__VIN___door_boot",
		"dev": {
			"name": "PHEV __VIN__",
			"identifiers": ["phev-__VIN__"],
			"manufacturer": "Mitsubishi",
			"model": "Outlander PHEV"
		},
		"~": "__TOPIC__"}`,
		"%s/binary_sensor/%s_door_front_passenger/config": `{
		"device_class": "door",
		"name": "__NAME__ Front Passenger Door",
		"state_topic": "~/door/front_passenger",
		"payload_off": "closed",
		"payload_on": "open",
		"avty_t": "~/available",
		"unique_id": "__VIN___door_front_passenger",
		"dev": {
			"name": "PHEV __VIN__",
			"identifiers": ["phev-__VIN__"],
			"manufacturer": "Mitsubishi",
			"model": "Outlander PHEV"
		},
		"~": "__TOPIC__"}`,
		"%s/binary_sensor/%s_door_driver/config": `{
		"device_class": "door",
		"name": "__NAME__ Driver Door",
		"state_topic": "~/door/driver",
		"payload_off": "closed",
		"payload_on": "open",
		"avty_t": "~/available",
		"unique_id": "__VIN___door_driver",
		"dev": {
			"name": "PHEV __VIN__",
			"identifiers": ["phev-__VIN__"],
			"manufacturer": "Mitsubishi",
			"model": "Outlander PHEV"
		},
		"~": "__TOPIC__"}`,
		"%s/binary_sensor/%s_door_rear_left/config": `{
		"device_class": "door",
		"name": "__NAME__ Rear Left Door",
		"state_topic": "~/door/rear_left",
		"payload_off": "closed",
		"payload_on": "open",
		"avty_t": "~/available",
		"unique_id": "__VIN___door_rear_left",
		"dev": {
			"name": "PHEV __VIN__",
			"identifiers": ["phev-__VIN__"],
			"manufacturer": "Mitsubishi",
			"model": "Outlander PHEV"
		},
		"~": "__TOPIC__"}`,
		"%s/binary_sensor/%s_door_rear_right/config": `{
		"device_class": "door",
		"name": "__NAME__ Rear Right Door",
		"state_topic": "~/door/rear_right",
		"payload_off": "closed",
		"payload_on": "open",
		"avty_t": "~/available",
		"unique_id": "__VIN___door_rear_right",
		"dev": {
			"name": "PHEV __VIN__",
			"identifiers": ["phev-__VIN__"],
			"manufacturer": "Mitsubishi",
			"model": "Outlander PHEV"
		},
		"~": "__TOPIC__"}`,

		// Battery and charging
		"%s/sensor/%s_battery_level/config": `{
		"device_class": "battery",
		"name": "__NAME__ Battery",
		"state_topic": "~/battery/level",
		"state_class": "measurement",
		"unit_of_measurement": "%",
		"avty_t": "~/available",
		"unique_id": "__VIN___battery_level",
		"dev": {
			"name": "PHEV __VIN__",
			"identifiers": ["phev-__VIN__"],
			"manufacturer": "Mitsubishi",
			"model": "Outlander PHEV"
		},
		"~": "__TOPIC__"}`,
		"%s/sensor/%s_battery_charge_remaining/config": `{
		"name": "__NAME__ Charge Remaining",
		"state_topic": "~/charge/remaining",
		"unit_of_measurement": "min",
		"avty_t": "~/available",
		"unique_id": "__VIN___battery_charge_remaining",
		"dev": {
			"name": "PHEV __VIN__",
			"identifiers": ["phev-__VIN__"],
			"manufacturer": "Mitsubishi",
			"model": "Outlander PHEV"
		},
		"~": "__TOPIC__"}`,
		"%s/binary_sensor/%s_charger_connected/config": `{
		"device_class": "plug",
		"name": "__NAME__ Charger Connected",
		"state_topic": "~/charge/plug",
		"payload_on": "connected",
		"payload_off": "unplugged",
		"avty_t": "~/available",
		"unique_id": "__VIN___charger_connected",
		"dev": {
			"name": "PHEV __VIN__",
			"identifiers": ["phev-__VIN__"],
			"manufacturer": "Mitsubishi",
			"model": "Outlander PHEV"
		},
		"~": "__TOPIC__"}`,
		"%s/binary_sensor/%s_battery_charging/config": `{
		"device_class": "battery_charging",
		"name": "__NAME__ Charging",
		"state_topic": "~/charge/charging",
		"payload_on": "on",
		"payload_off": "off",
		"avty_t": "~/available",
		"unique_id": "__VIN___battery_charging",
		"dev": {
			"name": "PHEV __VIN__",
			"identifiers": ["phev-__VIN__"],
			"manufacturer": "Mitsubishi",
			"model": "Outlander PHEV"
		},
		"~": "__TOPIC__"}`,
		"%s/switch/%s_cancel_charge_timer/config": `{
		"name": "__NAME__ Disable Charge Timer",
		"icon": "mdi:timer-off",
		"state_topic": "~/battery/charging",
		"command_topic": "~/set/cancelchargetimer",
		"avty_t": "~/available",
		"unique_id": "__VIN___cancel_charge_timer",
		"dev": {
			"name": "PHEV __VIN__",
			"identifiers": ["phev-__VIN__"],
			"manufacturer": "Mitsubishi",
			"model": "Outlander PHEV"
		},
		"~": "__TOPIC__"}`,
		// Climate
		"%s/switch/%s_climate_heat/config": `{
		"name": "__NAME__ Heat",
		"icon": "mdi:weather-sunny",
		"state_topic": "~/climate/heat",
		"command_topic": "~/set/climate/heat",
		"payload_off": "off",
		"payload_on": "on",
		"avty_t": "~/available",
		"unique_id": "__VIN___climate_heat",
		"dev": {
			"name": "PHEV __VIN__",
			"identifiers": ["phev-__VIN__"],
			"manufacturer": "Mitsubishi",
			"model": "Outlander PHEV"
		},
		"~": "__TOPIC__"}`,
		"%s/switch/%s_climate_cool/config": `{
		"name": "__NAME__ cool",
		"icon": "mdi:air-conditioner",
		"state_topic": "~/climate/cool",
		"command_topic": "~/set/climate/cool",
		"payload_off": "off",
		"payload_on": "on",
		"avty_t": "~/available",
		"unique_id": "__VIN___climate_cool",
		"dev": {
			"name": "PHEV __VIN__",
			"identifiers": ["phev-__VIN__"],
			"manufacturer": "Mitsubishi",
			"model": "Outlander PHEV"
		},
		"~": "__TOPIC__"}`,
		"%s/switch/%s_climate_windscreen/config": `{
		"name": "__NAME__ windscreen",
		"state_topic": "~/climate/windscreen",
		"command_topic": "~/set/climate/windscreen",
		"payload_off": "off",
		"payload_on": "on",
		"avty_t": "~/available",
		"unique_id": "__VIN___climate_windscreen",
		"dev": {
			"name": "PHEV __VIN__",
			"identifiers": ["phev-__VIN__"],
			"manufacturer": "Mitsubishi",
			"model": "Outlander PHEV"
		},
		"icon": "mdi:car-defrost-front",
		"~": "__TOPIC__"}`,
		"%s/select/%s_climate_on/config": `{
				"name": "__NAME__ climate state",
				"state_topic": "~/climate/mode",
				"command_topic": "~/set/climate/mode",
				"options": [ "off", "heat", "cool", "windscreen"],
				"avty_t": "~/available",
				"unique_id": "__VIN___climate_on",
		"dev": {
			"name": "PHEV __VIN__",
			"identifiers": ["phev-__VIN__"],
			"manufacturer": "Mitsubishi",
			"model": "Outlander PHEV"
		},
				"icon": "mdi:car-seat-heater",
				"~": "__TOPIC__"}`,
		// Lights.
		"%s/light/%s_parkinglights/config": `{
		"name": "__NAME__ Park Lights",
		"icon": "mdi:car-parking-lights",
		"state_topic": "~/lights/parking",
		"command_topic": "~/set/parkinglights",
		"payload_off": "off",
		"payload_on": "on",
		"avty_t": "~/available",
		"unique_id": "__VIN___parkinglights",
		"dev": {
			"name": "PHEV __VIN__",
			"identifiers": ["phev-__VIN__"],
			"manufacturer": "Mitsubishi",
			"model": "Outlander PHEV"
		},
		"~": "__TOPIC__"}`,
		"%s/light/%s_headlights/config": `{
		"name": "__NAME__ Head Lights",
		"icon": "mdi:car-light-high",
		"state_topic": "~/lights/head",
		"command_topic": "~/set/headlights",
		"payload_off": "off",
		"payload_on": "on",
		"avty_t": "~/available",
		"unique_id": "__VIN___headlights",
		"dev": {
			"name": "PHEV __VIN__",
			"identifiers": ["phev-__VIN__"],
			"manufacturer": "Mitsubishi",
			"model": "Outlander PHEV"
		},
		"~": "__TOPIC__"}`,
		// General topics.
		"%s/button/%s_reconnect_wifi/config": `{
		"name": "__NAME__ Restart Wifi connetion",
		"icon": "mdi:timer-off",
		"command_topic": "~/connection",
		"payload_press": "restart",
		"avty_t": "~/available",
		"unique_id": "__VIN___restart_wifi",
		"dev": {
			"name": "PHEV __VIN__",
			"identifiers": ["phev-__VIN__"],
			"manufacturer": "Mitsubishi",
			"model": "Outlander PHEV"
		},
		"~": "__TOPIC__"}`,
	}
	mappings := map[string]string{
		"__NAME__":  name,
		"__VIN__":   vin,
		"__TOPIC__": topic,
	}
	for topic, d := range discoveryData {
		topic = fmt.Sprintf(topic, m.haDiscoveryPrefix, vin)
		for in, out := range mappings {
			d = strings.Replace(d, in, out, -1)
		}
		m.client.Publish(topic, 2, true, d)
	}
}

func init() {
	clientCmd.AddCommand(mqttCmd)
	mqttCmd.Flags().String("mqtt_server", "tcp://127.0.0.1:1883", "Address of MQTT server")
	mqttCmd.Flags().String("mqtt_username", "", "Username to login to MQTT server")
	mqttCmd.Flags().String("mqtt_password", "", "Password to login to MQTT server")
	mqttCmd.Flags().String("mqtt_topic_prefix", "phev", "Prefix for MQTT topics")
	mqttCmd.Flags().Bool("ha_discovery", true, "Enable Home Assistant MQTT discovery")
	mqttCmd.Flags().String("ha_discovery_prefix", "homeassistant", "Prefix for Home Assistant MQTT discovery")
	mqttCmd.Flags().Duration("update_interval", 5*time.Minute, "how often to request for updated PHEV state")
	mqttCmd.Flags().Duration("ping_interval", 60*time.Second, "how often to ping the PHEV")
	mqttCmd.Flags().String("interface", "", "The WiFi interface over which to connect")
}

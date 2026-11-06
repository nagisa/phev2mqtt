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
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/buxtronix/phev2mqtt/client"
	"github.com/buxtronix/phev2mqtt/protocol"
	"github.com/spf13/cobra"

	mqtt "github.com/eclipse/paho.mqtt.golang"
	log "github.com/sirupsen/logrus"
	netlink "github.com/vishvananda/netlink"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

const defaultWifiRestartCmd = "sudo ip link set wlan0 down && sleep 3 && sudo ip link set wlan0 up"

// homieBase is the Homie 5 topic of the device. It is a root device with the ID `phev`.
const homieBase = "homie/5/phev"

// mqttCmd represents the mqtt command
var mqttCmd = &cobra.Command{
	Use:   "mqtt",
	Short: "Start an MQTT bridge.",
	Long: `Maintains a connected to the Phev (retry as needed) and also to an MQTT server.

Status data from the car is published as the Homie 5 device ` + homieBase + `, and its settable
properties control certain aspects of the car. See the phev2mqtt Github page for more details
on the properties.
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

// value is the `climate/state` property value, if known.
func (c *climate) value() (string, bool) {
	if c.state == nil {
		return "", false
	}
	switch *c.state {
	case protocol.PreACOff:
		return "off", true
	case protocol.PreACTerminated:
		return "terminated", true
	case protocol.PreACOn:
		if c.mode == nil {
			return "", false
		}
		switch *c.mode {
		case "cool", "heat", "windscreen":
			return *c.mode, true
		}
	}
	return "", false
}

// restartWifi takes the wifi interface down and up again. Needs CAP_NET_ADMIN.
func (m *mqttClient) restartWifi() error {
	link, err := netlink.LinkByName(m.interfaceName)
	if err != nil {
		return fmt.Errorf("looking up the interface: %w", err)
	}
	if err := netlink.LinkSetDown(link); err != nil {
		return fmt.Errorf("setting the interface down: %w", err)
	}
	// Give the driver a moment to tear the association down.
	time.Sleep(time.Second)
	if err := netlink.LinkSetUp(link); err != nil {
		return fmt.Errorf("setting the interface up: %w", err)
	}
	return nil
}

// Homie 5 device description. Retained defaults to true and settable to false.
type homieDescription struct {
	Homie   string               `json:"homie"`
	Version uint32               `json:"version"`
	Name    string               `json:"name"`
	Nodes   map[string]homieNode `json:"nodes"`
}

type homieNode struct {
	Name       string                   `json:"name"`
	Properties map[string]homieProperty `json:"properties"`
}

type homieProperty struct {
	Name     string `json:"name"`
	Datatype string `json:"datatype"`
	Format   string `json:"format,omitempty"`
	Settable bool   `json:"settable,omitempty"`
	Retained *bool  `json:"retained,omitempty"`
	Unit     string `json:"unit,omitempty"`
}

var notRetained = new(bool)

var description = homieDescription{
	Homie: "5.0",
	Name:  "Mitsubishi Outlander PHEV",
	Nodes: map[string]homieNode{
		"battery": {Name: "Battery", Properties: map[string]homieProperty{
			"level": {Name: "Level", Datatype: "integer", Format: "0:100", Unit: "%"},
		}},
		"charge": {Name: "Charging", Properties: map[string]homieProperty{
			"charging":     {Name: "Charging", Datatype: "boolean"},
			"remaining":    {Name: "Time remaining", Datatype: "integer", Unit: "min"},
			"plug":         {Name: "Plug", Datatype: "boolean", Format: "unplugged,connected"},
			"cancel-timer": {Name: "Cancel charge timer", Datatype: "enum", Format: "cancel", Settable: true, Retained: notRetained},
		}},
		"doors": {Name: "Doors", Properties: map[string]homieProperty{
			"locked":          {Name: "Locked", Datatype: "boolean", Format: "unlocked,locked"},
			"driver":          {Name: "Driver's door", Datatype: "boolean", Format: "closed,open"},
			"front-passenger": {Name: "Front passenger's door", Datatype: "boolean", Format: "closed,open"},
			"rear-left":       {Name: "Rear left door", Datatype: "boolean", Format: "closed,open"},
			"rear-right":      {Name: "Rear right door", Datatype: "boolean", Format: "closed,open"},
			"bonnet":          {Name: "Bonnet", Datatype: "boolean", Format: "closed,open"},
			"boot":            {Name: "Boot", Datatype: "boolean", Format: "closed,open"},
		}},
		"lights": {Name: "Lights", Properties: map[string]homieProperty{
			"head":     {Name: "Headlights", Datatype: "boolean", Format: "off,on", Settable: true},
			"parking":  {Name: "Parking lights", Datatype: "boolean", Format: "off,on", Settable: true},
			"interior": {Name: "Interior lights", Datatype: "boolean", Format: "off,on"},
			"hazard":   {Name: "Hazard lights", Datatype: "boolean", Format: "off,on"},
		}},
		"climate": {Name: "Climate", Properties: map[string]homieProperty{
			"state":   {Name: "State", Datatype: "enum", Format: "off,heat,cool,windscreen,terminated"},
			"command": {Name: "Command", Datatype: "json", Format: climateCommandSchema, Settable: true, Retained: notRetained},
		}},
		"car": {Name: "Car", Properties: map[string]homieProperty{
			"vin":           {Name: "VIN", Datatype: "string"},
			"ecu-version":   {Name: "ECU version", Datatype: "string"},
			"registrations": {Name: "Registered clients", Datatype: "integer"},
		}},
		"connection": {Name: "Connection", Properties: map[string]homieProperty{
			"state":   {Name: "State", Datatype: "enum", Format: "offline,waiting-for-ip,connecting,online"},
			"command": {Name: "Command", Datatype: "enum", Format: "off,on,restart", Settable: true, Retained: notRetained},
		}},
	},
}

// climateCommandSchema is the format of `climate/command`. Duration is in minutes, 10 by default.
const climateCommandSchema = `{"type":"object","properties":{` +
	`"mode":{"enum":["off","heat","cool","windscreen"]},` +
	`"duration":{"enum":[10,20,30]}` +
	`},"required":["mode"],"additionalProperties":false}`

// climateCommand is a `climate/command` value.
type climateCommand struct {
	Mode     string `json:"mode"`
	Duration *int   `json:"duration"`
}

// descriptionJSON is the `$description` payload. Its version is a hash of the rest, so it changes
// whenever the description does.
func descriptionJSON() ([]byte, error) {
	d := description
	d.Version = 0
	unversioned, err := json.Marshal(d)
	if err != nil {
		return nil, err
	}
	h := fnv.New32a()
	h.Write(unversioned)
	d.Version = h.Sum32()
	return json.Marshal(d)
}

type mqttClient struct {
	client  mqtt.Client
	options *mqtt.ClientOptions

	interfaceName string
	pingInterval  time.Duration

	updateInterval            time.Duration
	everPublishedBatteryLevel bool

	// mu guards the fields below. MQTT handlers run on paho's goroutines.
	mu sync.Mutex
	// The device's `$state`, and the last value published for each property.
	state  string
	values map[string]string
	// The car connection, if any. connected is whether it is up.
	phev      *client.Client
	connected bool
	// Cancels the car connection.
	cancel  context.CancelFunc
	climate *climate
	enabled bool
	// Wakes up Run when the connection gets enabled.
	wake chan struct{}
	// What evaluateLinkState last found wrong with the link, to log changes only.
	linkProblem string
}

var errInterfaceDisconnected = errors.New("interface disconnected")

func (m *mqttClient) Run(cmd *cobra.Command, args []string) error {
	var err error

	m.enabled = true // Default.
	m.wake = make(chan struct{}, 1)
	m.state = "disconnected"
	m.values = map[string]string{}
	mqttServer, _ := cmd.Flags().GetString("mqtt-server")
	mqttUsername, _ := cmd.Flags().GetString("mqtt-username")
	mqttPassword, _ := cmd.Flags().GetString("mqtt-password")
	m.updateInterval, err = cmd.Flags().GetDuration("update-interval")
	m.pingInterval, err = cmd.Flags().GetDuration("ping-interval")
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
	wifiRestartThreshold, err := cmd.Flags().GetInt("wifi-restart-threshold")
	if err != nil {
		return err
	}

	m.options = mqtt.NewClientOptions().
		AddBroker(mqttServer).
		SetClientID("phev2mqtt").
		SetUsername(mqttUsername).
		SetPassword(mqttPassword).
		SetAutoReconnect(true).
		SetOnConnectHandler(m.onConnect).
		SetWill(homieBase+"/$state", "lost", 2, true)

	m.client = mqtt.NewClient(m.options)
	if token := m.client.Connect(); token.Wait() && token.Error() != nil {
		return token.Error()
	}

	// Failed attempts since the car was last connected, or wifi was restarted.
	failedAttempts := 0
	for {
		m.mu.Lock()
		enabled := m.enabled
		m.mu.Unlock()
		if !enabled {
			m.publish("connection/state", "offline")
			<-m.wake
			continue
		}
		started := time.Now()
		established, err := m.handlePhev(cmd)
		logger := log.WithField("duration", time.Since(started).Round(time.Millisecond))
		switch {
		case established && errors.Is(err, context.Canceled):
			logger.Info("car connection closed by command")
			failedAttempts = 0
		case established:
			logger.WithError(err).Error("car connection lost")
			failedAttempts = 0
		case errors.Is(err, context.Canceled):
			logger.Info("connecting to the car cancelled by command")
		case errors.Is(err, errInterfaceDisconnected):
			// The car is out of range, which is not the same as not answering.
			logger.WithError(err).Debug("could not connect to the car")
			failedAttempts = 0
		default:
			failedAttempts++
			logger = logger.WithError(err).WithField("failed_attempts", failedAttempts)
			if failedAttempts == 1 {
				logger.Warn("could not connect to the car")
			} else {
				logger.Debug("could not connect to the car")
			}
			if wifiRestartThreshold > 0 && failedAttempts >= wifiRestartThreshold && m.evaluateLinkState() {
				restartStart := time.Now()
				err := m.restartWifi()
				logger = log.WithFields(log.Fields{
					"interface":       m.interfaceName,
					"failed_attempts": failedAttempts,
					"duration":        time.Since(restartStart).Round(time.Millisecond),
				})
				if err != nil {
					logger.WithError(err).Error("restarted wifi")
				} else {
					logger.Info("restarted wifi")
				}
				failedAttempts = 0
			}
		}
		time.Sleep(time.Second)
	}
}

// onConnect publishes the device, as the broker might have lost it, and subscribes to the settable
// properties. It runs on every connection to the broker.
func (m *mqttClient) onConnect(c mqtt.Client) {
	desc, err := descriptionJSON()
	if err != nil {
		log.WithError(err).Error("could not encode the device description")
		return
	}
	// Under the lock, so that a newer value isn't overwritten by the one here.
	m.mu.Lock()
	c.Publish(homieBase+"/$state", 2, true, "init")
	c.Publish(homieBase+"/$description", 2, true, desc)
	for property, value := range m.values {
		c.Publish(homieBase+"/"+property, 2, true, value)
	}
	c.Publish(homieBase+"/$state", 2, true, m.state)
	m.mu.Unlock()
	topic := homieBase + "/+/+/set"
	if token := c.Subscribe(topic, 2, m.handleSet); token.Wait() && token.Error() != nil {
		log.WithError(token.Error()).WithField("topic", topic).Error("could not subscribe")
	}
}

// publish publishes a property value, if it changed.
func (m *mqttClient) publish(property, value string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if cache, ok := m.values[property]; ok && cache == value {
		return
	}
	m.values[property] = value
	m.client.Publish(homieBase+"/"+property, 2, true, value)
}

// setConnected records whether the car is connected, as the device's `$state`.
func (m *mqttClient) setConnected(connected bool) {
	state := "disconnected"
	if connected {
		state = "ready"
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.connected = connected
	if m.state == state {
		return
	}
	m.state = state
	m.client.Publish(homieBase+"/$state", 2, true, m.state)
}

func (m *mqttClient) handleSet(_ mqtt.Client, msg mqtt.Message) {
	property := strings.TrimSuffix(strings.TrimPrefix(msg.Topic(), homieBase+"/"), "/set")
	value := string(msg.Payload())
	logger := log.WithFields(log.Fields{"property": property, "value": value})
	if msg.Retained() {
		// It would be applied again on every connection to the broker.
		logger.Warn("ignoring a retained set")
		return
	}
	logger.Info("setting a property")
	if err := m.set(property, value); err != nil {
		logger.WithError(err).Warn("could not set the property")
	}
}

var errInvalidValue = errors.New("invalid value")

func (m *mqttClient) set(property, value string) error {
	switch property {
	case "connection/command":
		m.mu.Lock()
		defer m.mu.Unlock()
		switch value {
		case "off":
			m.enabled = false
		case "on":
			m.enabled = true
		case "restart":
			m.enabled = true
		default:
			return errInvalidValue
		}
		if value != "on" && m.cancel != nil {
			m.cancel()
		}
		if m.enabled {
			select {
			case m.wake <- struct{}{}:
			default:
			}
		}
		return nil
	}

	m.mu.Lock()
	phev, connected := m.phev, m.connected
	m.mu.Unlock()
	if !connected {
		return errors.New("the car is not connected")
	}
	ctx := context.Background()
	lights := map[string]byte{"true": 0x1, "false": 0x2}
	switch property {
	case "lights/head":
		v, ok := lights[value]
		if !ok {
			return errInvalidValue
		}
		return phev.SetRegister(ctx, 0xa, []byte{v})
	case "lights/parking":
		v, ok := lights[value]
		if !ok {
			return errInvalidValue
		}
		return phev.SetRegister(ctx, 0xb, []byte{v})
	case "charge/cancel-timer":
		if value != "cancel" {
			return errInvalidValue
		}
		if err := phev.SetRegister(ctx, 0x17, []byte{0x1}); err != nil {
			return err
		}
		return phev.SetRegister(ctx, 0x17, []byte{0x11})
	case "climate/command":
		return m.setClimate(ctx, phev, value)
	}
	return errors.New("unknown property")
}

func (m *mqttClient) setClimate(ctx context.Context, phev *client.Client, value string) error {
	var command climateCommand
	decoder := json.NewDecoder(strings.NewReader(value))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&command); err != nil {
		return fmt.Errorf("%w: %w", errInvalidValue, err)
	}
	if decoder.More() {
		return fmt.Errorf("%w: trailing data", errInvalidValue)
	}
	modes := map[string]byte{"off": 0x0, "cool": 0x1, "heat": 0x2, "windscreen": 0x3}
	durations := map[int]byte{10: 0x0, 20: 0x1, 30: 0x2}
	mode, ok := modes[command.Mode]
	if !ok {
		return fmt.Errorf("%w: unknown mode %q", errInvalidValue, command.Mode)
	}
	duration := durations[10]
	if command.Duration != nil {
		if duration, ok = durations[*command.Duration]; !ok {
			return fmt.Errorf("%w: unsupported duration %d", errInvalidValue, *command.Duration)
		}
	}
	m.mu.Lock()
	current, _ := m.climate.value()
	m.mu.Unlock()
	if mode == 0x0 {
		duration = 0x0
		if current == "terminated" {
			return phev.SetRegister(ctx, protocol.SetAckPreACTermRegister, []byte{0x1})
		}
	}

	switch phev.ModelYear {
	case client.ModelYear14:
		// Set the AC mode first
		registerPayload := bytes.Repeat([]byte{0xff}, 15)
		registerPayload[0] = 0x0
		registerPayload[1] = 0x0
		registerPayload[6] = mode | duration
		if err := phev.SetRegister(ctx, protocol.SetACModeRegisterMY14, registerPayload); err != nil {
			return fmt.Errorf("setting the AC mode: %w", err)
		}

		// Then, enable/disable the AC
		acEnabled := byte(0x02)
		if mode == 0x0 {
			acEnabled = 0x01
		}
		if err := phev.SetRegister(ctx, protocol.SetACEnabledRegisterMY14, []byte{acEnabled}); err != nil {
			return fmt.Errorf("setting the AC enabled state: %w", err)
		}
		return nil
	case client.ModelYear18:
		state := byte(0x02)
		if mode == 0x0 {
			state = 0x1
		}
		return phev.SetRegister(ctx, protocol.SetACModeRegisterMY18, []byte{state, mode, duration, 0x0})
	}
	return errors.New("unknown model year")
}

// Determine if the WiFi link is in a good enough state to start connecting to PHEV.
//
// A common situation where this matters is the vehicle driving away out of the WiFi range.
// At which point, why bother spinning our wheels? Kernel will notify us via netlink as
// soon as the link state changes again (i.e. vehicle enters the driveway.)
func (m *mqttClient) evaluateLinkState() bool {
	logger := log.WithField("interface", m.interfaceName)
	// This is polled, so only the first report of a problem is worth more than debug.
	reportProblem := func(problem string) *log.Entry {
		m.mu.Lock()
		defer m.mu.Unlock()
		changed := m.linkProblem != problem
		m.linkProblem = problem
		if changed {
			return logger.WithField("problem", problem)
		}
		return nil
	}
	link, err := netlink.LinkByName(m.interfaceName)
	// WiFi interface is not present altogether.
	if err != nil {
		if l := reportProblem("unavailable"); l != nil {
			l.WithError(err).Error("interface is not available")
		} else {
			logger.WithError(err).Trace("interface is not available")
		}
		m.publish("connection/state", "offline")
		return false
	}
	// WiFi is not associated. E.g. vehicle not in the driveway.
	if link.Attrs().OperState != netlink.OperUp {
		if l := reportProblem("down"); l != nil {
			l.Info("interface is not up")
		} else {
			logger.Trace("interface is not up")
		}
		m.publish("connection/state", "offline")
		return false
	}
	reportProblem("")

	addrs, _ := netlink.AddrList(link, netlink.FAMILY_V4)
	logger.WithField("addresses", addrs).Debug("interface is up")
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
		m.publish("connection/state", "waiting-for-ip")
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

// handlePhev maintains a connection to the car until it fails. established is whether the car
// got connected and started before that.
func (m *mqttClient) handlePhev(cmd *cobra.Command) (established bool, _ error) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	pingTicker := time.NewTicker(m.pingInterval)
	defer pingTicker.Stop()
	updateTicker := time.NewTicker(m.updateInterval)
	defer updateTicker.Stop()

	address, _ := cmd.Flags().GetString("address")
	phev, err := client.New(client.AddressOption(address))
	if err != nil {
		return established, err
	}
	m.mu.Lock()
	m.phev = phev
	m.cancel = func() {
		cancel()
		phev.Close()
	}
	m.mu.Unlock()
	defer m.setConnected(false)

	// Wait for the interface to become available.
	linkChanges := make(chan netlink.LinkUpdate, 1)
	if err := netlink.LinkSubscribe(linkChanges, ctx.Done()); err != nil {
		log.WithError(err).Error("could not subscribe to netlink link changes")
		linkChanges = nil
	}
	addrChanges := make(chan netlink.AddrUpdate, 1)
	if err := netlink.AddrSubscribe(addrChanges, ctx.Done()); err != nil {
		log.WithError(err).Error("could not subscribe to netlink address changes")
		addrChanges = nil
	}
	if !m.evaluateLinkState() {
		// Netlink notifications are the fast path. Keep polling as a fallback so
		// a failed subscription cannot leave us either dialing without a link or
		// waiting forever for an event that will never arrive.
		linkPollTicker := time.NewTicker(5 * time.Second)
		defer linkPollTicker.Stop()
	loop:
		for {
			select {
			case <-ctx.Done():
				return established, ctx.Err()
			case <-pingTicker.C:
				if _, err := client.SdNotify(false, client.SdNotifyWatchdog); err != nil {
					log.WithError(err).Warn("could not reset systemd watchdog")
				}
			case <-linkPollTicker.C:
				if m.evaluateLinkState() {
					break loop
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

	m.publish("connection/state", "connecting")
	m.everPublishedBatteryLevel = false
	var encodingErrorCount = 0
	var lastEncodingError time.Time

	connectStart := time.Now()
	connectResult := make(chan error, 1)
	go func() {
		if err := phev.Connect(ctx); err != nil {
			connectResult <- err
			return
		}
		if err := phev.Start(ctx); err != nil {
			connectResult <- err
			return
		}
		connectResult <- nil
	}()

	for {
		select {
		case <-ctx.Done():
			return established, ctx.Err()
		case err := <-connectResult:
			if err != nil {
				return established, err
			}
			established = true
			m.publish("connection/state", "online")
			m.setConnected(true)
			log.WithFields(log.Fields{
				"address":    address,
				"model_year": phev.ModelYear,
				"duration":   time.Since(connectStart).Round(time.Millisecond),
			}).Info("connected to the car")
		case <-linkChanges:
			if !m.evaluateLinkState() {
				return established, errInterfaceDisconnected
			}
		case <-addrChanges:
			if !m.evaluateLinkState() {
				return established, errInterfaceDisconnected
			}
		case <-updateTicker.C:
			go func() {
				if err := phev.SetRegister(ctx, 0x6, []byte{0x3}); err != nil {
					log.WithError(err).Warn("no response to update request")
				}
			}()
		case <-pingTicker.C:
			go func() {
				if err := m.pingTarget(ctx, address); err != nil {
					log.WithError(err).Warn("can't ping at ipv4 level")
				}
			}()
		case msg, ok := <-phev.Recv:
			if !ok {
				return established, fmt.Errorf("connection closed")
			}
			switch msg.Type {
			case protocol.CmdInBadEncoding:
				if time.Now().Sub(lastEncodingError) > 30*time.Second {
					encodingErrorCount = 0
				}
				if encodingErrorCount > 5 {
					phev.Close()
					return established, fmt.Errorf("disconnecting due to too many errors")
				}
				encodingErrorCount += 1
				lastEncodingError = time.Now()
			case protocol.CmdInResp:
				if msg.Ack != protocol.Request {
					break
				}
				m.publishRegister(msg)
				if err := phev.SendMessage(ctx, &protocol.PhevMessage{
					Type:     protocol.CmdOutSend,
					Register: msg.Register,
					Ack:      protocol.Ack,
					Xor:      msg.Xor,
					Data:     []byte{0x0},
				}); err != nil {
					return established, fmt.Errorf("acknowledging register %02x: %w", msg.Register, err)
				}
			}
		}
	}
}

func (m *mqttClient) publishBool(property string, value bool) {
	m.publish(property, strconv.FormatBool(value))
}

func (m *mqttClient) publishClimate() {
	m.mu.Lock()
	value, ok := m.climate.value()
	m.mu.Unlock()
	if ok {
		m.publish("climate/state", value)
	}
}

func (m *mqttClient) publishRegister(msg *protocol.PhevMessage) {
	log.WithFields(log.Fields{
		"register": fmt.Sprintf("%02x", msg.Register),
		"data":     hex.EncodeToString(msg.Data),
	}).Debug("register update")
	switch reg := msg.Reg.(type) {
	case *protocol.RegisterVIN:
		m.publish("car/vin", reg.VIN)
		m.publish("car/registrations", strconv.Itoa(reg.Registrations))
	case *protocol.RegisterECUVersion:
		m.publish("car/ecu-version", reg.Version)
	case *protocol.RegisterACMode:
		m.mu.Lock()
		m.climate.setMode(reg.Mode)
		m.mu.Unlock()
		m.publishClimate()
	case *protocol.RegisterPreACState:
		m.mu.Lock()
		m.climate.setState(reg.State)
		m.mu.Unlock()
		m.publishClimate()
	case *protocol.RegisterChargeStatus:
		m.publishBool("charge/charging", reg.Charging)
		m.publish("charge/remaining", strconv.Itoa(reg.Remaining))
	case *protocol.RegisterDoorStatus:
		m.publishBool("doors/locked", reg.Locked)
		m.publishBool("doors/driver", reg.Driver)
		m.publishBool("doors/front-passenger", reg.FrontPassenger)
		m.publishBool("doors/rear-left", reg.RearLeft)
		m.publishBool("doors/rear-right", reg.RearRight)
		m.publishBool("doors/bonnet", reg.Bonnet)
		m.publishBool("doors/boot", reg.Boot)
		m.publishBool("lights/head", reg.Headlights)
	case *protocol.RegisterBatteryLevel:
		if !m.everPublishedBatteryLevel || reg.Level > 5 {
			m.everPublishedBatteryLevel = true
			m.publish("battery/level", strconv.Itoa(reg.Level))
		} else {
			log.WithField("level", reg.Level).Debug("ignoring battery level reading")
		}
		m.publishBool("lights/parking", reg.ParkingLights)
	case *protocol.RegisterLightStatus:
		m.publishBool("lights/interior", reg.Interior)
		m.publishBool("lights/hazard", reg.Hazard)
	case *protocol.RegisterChargePlug:
		m.publishBool("charge/plug", reg.Connected)
	}
}

func init() {
	clientCmd.AddCommand(mqttCmd)
	mqttCmd.Flags().String("mqtt-server", "tcp://127.0.0.1:1883", "Address of MQTT server")
	mqttCmd.Flags().String("mqtt-username", "", "Username to login to MQTT server")
	mqttCmd.Flags().String("mqtt-password", "", "Password to login to MQTT server")
	mqttCmd.Flags().Duration("update-interval", 5*time.Minute, "how often to request for updated PHEV state")
	mqttCmd.Flags().Duration("ping-interval", 60*time.Second, "how often to ping the PHEV")
	mqttCmd.Flags().String("interface", "", "The WiFi interface over which to connect")
	mqttCmd.Flags().Int("wifi-restart-threshold", 5, "Restart the WiFi interface (needs CAP_NET_ADMIN) once this many attempts in a row to connect to the car have failed, 0 to never")
}

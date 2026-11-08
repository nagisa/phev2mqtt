package protocol

import (
	"encoding/binary"
	"fmt"
	"strings"
	//        log "github.com/sirupsen/logrus"
)

// Vehicle settings are sent to the client in register 0x16.
// The client sends updated settings to the vehicle via register 0x0f.
type Settings struct {
	settings []uint64
}

// SettingUnsupported is the value of a setting the car does not have.
const SettingUnsupported = 7

// Setting is a single vehicle setting carried in the 0x16 register.
type Setting struct {
	ID byte
	// Value is the index of the selected option.
	Value byte
	// Allowed is a bitmask of the options the car accepts, bit n being option n.
	Allowed byte
}

func (s Setting) String() string {
	name, ok := settingNames[s.ID]
	if !ok {
		name = "unknown"
	}
	if s.Value == SettingUnsupported {
		return fmt.Sprintf("0x%02x (%s)=unsupported", s.ID, name)
	}
	return fmt.Sprintf("0x%02x (%s)=%d allowed=%07b", s.ID, name, s.Value, s.Allowed)
}

// DecodeSettings decodes the up to three settings in a 0x16 register.
func DecodeSettings(reg []byte) ([]Setting, error) {
	if err := checkSettingsRegister(reg); err != nil {
		return nil, err
	}
	var ret []Setting
	for i := 1; i < 7; i += 2 {
		a, b := reg[i], reg[i+1]
		if a&0x3f == 0 {
			continue
		}
		ret = append(ret, Setting{
			ID:      a & 0x3f,
			Value:   a>>6 | (b&1)<<2,
			Allowed: b >> 1,
		})
	}
	return ret, nil
}

func checkSettingsRegister(reg []byte) error {
	switch {
	case len(reg) != 8:
		return fmt.Errorf("register wrong length got=%d want=8", len(reg))
	case reg[0] != 0x0 && reg[0] != 0x2:
		return fmt.Errorf("register must start with 0x0 or 0x2, is 0x%x", reg[0])
	case reg[7] != 0x0:
		return fmt.Errorf("register must end with 0x0, is 0x%x", reg[7])
	}
	return nil
}

// settingNames are the names the official app gives to setting IDs.
var settingNames = map[byte]string{
	0x01: "operation in key position",
	0x02: "lane-change signals",
	0x03: "turn signal lights answerback",
	0x04: "windshield wipers intermittent operation",
	0x05: "wipers linked to washer",
	0x06: "rear wiper intermittent interval",
	0x07: "charging lid light auto cut-out",
	0x08: "auto fold mirrors",
	0x09: "auto light sensitivity",
	0x0a: "auto light linked to wiper",
	0x0b: "dome light duration after door closed",
	0x0c: "headlight auto-cutout",
	0x0d: "interior light auto-cutout time",
	0x0e: "lane-change signals activation time",
	0x0f: "comfort washer",
	0x10: "automatic unlock",
	0x11: "unlock operation",
	0x13: "lock button pushes for dead lock",
	0x14: "horn answerback at keyless entry lock",
	0x15: "keyless operation answerback beeps",
	0x16: "automatic relock after remote unlock",
	0x18: "timer function after ignition off",
	0x1a: "multi mode keyless entry",
	0x1c: "horn answerback duration",
	0x1d: "rear wiper in reverse",
	0x20: "remote unlock inactivation after locking",
	0x21: "horn answerback at remote engine start",
	0x22: "open operation after ignition off",
	0x23: "power window lock-switch prohibition",
	0x24: "ACC power auto cut",
	0x2a: "headlights on when exiting vehicle",
	0x2b: "exterior lights on with remote unlock",
	0x32: "recirculation control",
	0x33: "A/C switch control",
	0x35: "eco mode",
	0x36: "foot/defroster airflow ratio",
	0x37: "face/foot airflow ratio",
	0x38: "automatic rear defrost at start",
	0x39: "start A/C or heater at door unlock",
	0x3a: "slight defroster airflow in foot mode",
	0x3c: "fast idle for heater when stopped",
}

// FromRegister records the raw 0x16 register so that it can be replayed.
func (s *Settings) FromRegister(reg []byte) error {
	if err := checkSettingsRegister(reg); err != nil {
		return err
	}
	value := binary.LittleEndian.Uint64(reg)
	for _, v := range s.settings {
		if value == v {
			return nil
		}
	}
	s.settings = append(s.settings, value)
	return nil
}

func (s *Settings) Clear() {
	s.settings = []uint64{}
}

func (s *Settings) NewSender() *SettingsSender {
	return &SettingsSender{settings: s.settings}
}

func (s *Settings) Dump() string {
	ret := []string{}
	for _, v := range s.settings {
		ret = append(ret, fmt.Sprintf("%016x", v))
	}
	return strings.Join(ret, "\n")
}

type SettingsSender struct {
	C        chan *PhevMessage
	settings []uint64
}

func (s *SettingsSender) Start() {
	s.C = make(chan *PhevMessage)
	go func() {
		for i := 0; i < len(s.settings); i++ {
			buf := make([]byte, 8)
			binary.LittleEndian.PutUint64(buf, s.settings[i])
			s.C <- NewMessage(CmdInResp, 0x16, false, buf)
		}
		close(s.C)
	}()
}

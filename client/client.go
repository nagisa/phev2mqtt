// Package client implements a client for communicating with a Mitsubishi
// Outlander Phev.
package client

import (
	"context"
	"encoding/hex"
	"fmt"
	log "github.com/sirupsen/logrus"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/buxtronix/phev2mqtt/protocol"
)

const DefaultAddress = "192.168.8.46:8080"

// A Listener is for communicating messages from the vehicle to
// interested clients.
type Listener struct {
	// C has received messages.
	C    chan *protocol.PhevMessage
	stop bool
}

func (l *Listener) Start() {
	l.C = make(chan *protocol.PhevMessage, 5)
}

func (l *Listener) Stop() {
	close(l.C)
}

func (l *Listener) Send(m *protocol.PhevMessage) {
	select {
	case l.C <- m:
	default:
		log.WithFields(m.LogFields()).Warn("listener is full, dropping a message")
	}
}

type ModelYear int64

const (
	ModelYearUnknown ModelYear = iota
	ModelYear14
	ModelYear18
)

// A Client is a TCP client to a Phev.
type Client struct {
	// Recv is a channel where incoming messages from the Phev are sent.
	Recv chan *protocol.PhevMessage
	// Send is a channel to send messages to the Phev.
	Send chan *protocol.PhevMessage

	// Settings are settings for the car.
	Settings *protocol.Settings

	listeners []*Listener
	lMu       sync.Mutex
	registers chan struct{}

	address string
	conn    net.Conn
	connMu  sync.Mutex
	lastRx  time.Time
	// When the TCP connection was established, and what happened on it since.
	connectedAt time.Time
	rxMessages  atomic.Int64
	txMessages  atomic.Int64
	// The first error that ended the connection, if it was not us who closed it.
	cause    error
	causeMu  sync.Mutex
	started  chan struct{}
	done     chan struct{}
	close    sync.Once
	closeErr error

	key *protocol.SecurityKey

	// Keep track of the model year so we can use the correct registers
	ModelYear ModelYear
}

// An Option configures the client.
type Option func(c *Client)

// AddressOption configures the address to the Phev.
func AddressOption(address string) func(*Client) {
	return func(c *Client) {
		c.address = address
	}
}

// New returns a new client, not yet connected.
func New(opts ...Option) (*Client, error) {
	cl := &Client{
		Recv:      make(chan *protocol.PhevMessage, 5),
		Send:      make(chan *protocol.PhevMessage, 5),
		Settings:  &protocol.Settings{},
		started:   make(chan struct{}, 2),
		done:      make(chan struct{}),
		registers: make(chan struct{}, 1),
		listeners: []*Listener{},
		address:   DefaultAddress,
		key:       &protocol.SecurityKey{},
		ModelYear: ModelYearUnknown,
	}
	for _, o := range opts {
		o(cl)
	}
	return cl, nil
}

// Create and return a new Listener.
func (c *Client) AddListener() *Listener {
	c.lMu.Lock()
	defer c.lMu.Unlock()
	l := &Listener{}
	l.Start()
	c.listeners = append(c.listeners, l)
	return l
}

func (c *Client) RemoveListener(l *Listener) {
	newL := []*Listener{}
	c.lMu.Lock()
	defer c.lMu.Unlock()
	for _, lis := range c.listeners {
		if lis != l {
			newL = append(newL, lis)
		}
	}
	c.listeners = newL
}

// Close closes the client.
func (c *Client) Close() error {
	c.shutdown()
	return c.closeErr
}

// shutdown marks the client closed and interrupts any goroutines waiting on
// the connection. The Send channel stays open so concurrent senders cannot
// panic while the connection is being torn down.
func (c *Client) shutdown() {
	c.close.Do(func() {
		close(c.done)
		c.connMu.Lock()
		conn := c.conn
		if conn != nil {
			c.closeErr = conn.Close()
		}
		c.connMu.Unlock()
		if conn == nil {
			return
		}
		c.causeMu.Lock()
		cause := c.cause
		c.causeMu.Unlock()
		logger := log.WithFields(log.Fields{
			"address":     c.address,
			"duration":    time.Since(c.connectedAt).Round(time.Millisecond),
			"rx_messages": c.rxMessages.Load(),
			"tx_messages": c.txMessages.Load(),
		})
		if cause != nil {
			logger = logger.WithError(cause)
		}
		logger.Debug("tcp connection closed")
	})
}

// fail records why the connection ended, unless it was closed deliberately.
func (c *Client) fail(err error) {
	select {
	case <-c.done:
		return
	default:
	}
	c.causeMu.Lock()
	defer c.causeMu.Unlock()
	if c.cause == nil {
		c.cause = err
	}
}

// SendMessage queues a message unless the connection or context has ended.
func (c *Client) SendMessage(ctx context.Context, msg *protocol.PhevMessage) error {
	select {
	case <-c.done:
		return fmt.Errorf("connection is closed")
	default:
	}
	select {
	case c.Send <- msg:
		return nil
	case <-c.done:
		return fmt.Errorf("connection is closed")
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Connect connects to the Phev.
func (c *Client) Connect(ctx context.Context) error {
	SdNotify(false, SdNotifyWatchdog)
	interval, _ := SdWatchdogInterval(5000 * time.Millisecond)
	dialctx, _ := context.WithTimeout(ctx, interval)
	dialer := &net.Dialer{}
	dialStart := time.Now()
	conn, err := dialer.DialContext(dialctx, "tcp", c.address)
	if err != nil {
		return err
	}
	log.WithFields(log.Fields{
		"address": c.address,
		"elapsed": time.Since(dialStart).Round(time.Millisecond),
	}).Debug("tcp connected")
	c.connMu.Lock()
	select {
	case <-c.done:
		c.connMu.Unlock()
		conn.Close()
		return fmt.Errorf("connection was closed while dialing")
	default:
	}
	c.conn = conn
	c.connectedAt = time.Now()
	c.connMu.Unlock()
	go func() {
		select {
		case <-ctx.Done():
			c.Close()
		case <-c.done:
		}
	}()
	// Listen before reading, so manage sees the start request even if the car sends it at once.
	ml := c.AddListener()
	go c.reader()
	go c.writer()
	go c.manage(ml)
	return nil
}

var startTimeout = 20 * time.Second

// Start waits for the client to start.
func (c *Client) Start(ctx context.Context) error {
	startedAt := time.Now()
	timeoutCtx, _ := context.WithTimeout(ctx, startTimeout)
	for {
		select {
		case _, ok := <-c.started:
			if !ok {
				return fmt.Errorf("receiver closed before getting start request")
			}
			log.WithFields(log.Fields{
				"address":    c.address,
				"elapsed":    time.Since(startedAt).Round(time.Millisecond),
				"model_year": c.ModelYear,
			}).Debug("car started")
		case <-ctx.Done():
			return fmt.Errorf("operation cancelled")
		case <-timeoutCtx.Done():
			return fmt.Errorf("timed out waiting for start")
		}
		return nil
	}
}

// SetRegister sets a register on the car.
func (c *Client) SetRegister(ctx context.Context, register byte, value []byte) error {
	timeoutCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	// Register responses have no transaction ID, so keep only one request in flight.
	select {
	case c.registers <- struct{}{}:
		defer func() { <-c.registers }()
	case <-timeoutCtx.Done():
		if ctx.Err() != nil {
			return fmt.Errorf("cancelled setting of register %02x", register)
		}
		return fmt.Errorf("timed out attempting to set register %02x", register)
	case <-c.done:
		return fmt.Errorf("connection is closed")
	}

	setRegister := func(xor byte) error {
		return c.SendMessage(timeoutCtx, &protocol.PhevMessage{
			Type:     protocol.CmdOutSend,
			Ack:      protocol.Request,
			Register: register,
			Data:     value,
			Xor:      xor,
		})
	}
	xor := byte(0)
	l := c.AddListener()
	defer c.RemoveListener(l)
SETREG:
	if err := setRegister(xor); err != nil {
		return fmt.Errorf("sending register %02x: %w", register, err)
	}
	for {
		select {
		case <-timeoutCtx.Done():
			if ctx.Err() != nil {
				return fmt.Errorf("cancelled setting of register %02x", register)
			}
			return fmt.Errorf("timed out attempting to set register %02x", register)
		case <-c.done:
			return fmt.Errorf("connection is closed")
		case msg, ok := <-l.C:
			if !ok {
				return fmt.Errorf("listener channel closed")
			}
			if msg.Type == protocol.CmdInBadEncoding {
				xor = msg.Data[0]
				goto SETREG
			}
			if msg.Type == protocol.CmdInResp && msg.Ack == protocol.Ack && msg.Register == register {
				return nil
			}
		}
	}
}

func (c *Client) nextRecvMsg(deadline time.Time) (*protocol.PhevMessage, error) {
	timer := time.After(deadline.Sub(time.Now()))
	for {
		select {
		case <-timer:
			return nil, fmt.Errorf("timed out waiting for message")
		case m, ok := <-c.Recv:
			if !ok {
				return nil, fmt.Errorf("error: receive channel closed")
			}
			return m, nil
		}
	}
}

// signalStarted tells Start that the car sent a start request. The car repeats the request,
// and nothing reads this after Start returned, so a full channel must not block manage.
func (c *Client) signalStarted() {
	select {
	case c.started <- struct{}{}:
	default:
	}
}

// manages the connection, handling control messages.
func (c *Client) manage(ml *Listener) {
	// Once this returns nothing drains the listener, so it would only fill up and warn.
	defer c.RemoveListener(ml)
	defer close(c.started)
	for m := range ml.C {
		switch m.Type {
		case protocol.CmdInResp:
			if m.Ack == protocol.Request && m.Register == protocol.SettingsRegister {
				c.Settings.FromRegister(m.Data)
			}
		case protocol.CmdInStartResp:
			if err := c.SendMessage(context.Background(), protocol.NewPingRequestMessage(0xa)); err != nil {
				return
			}
		case protocol.CmdInMy18StartReq:
			if m.Ack != protocol.Request {
				break // The car acknowledging our rekey request.
			}
			c.ModelYear = ModelYear18
			if err := c.SendMessage(context.Background(), &protocol.PhevMessage{
				Type:     protocol.CmdOutMy18StartResp,
				Register: 0x1,
				Ack:      protocol.Ack,
				Xor:      m.Xor,
				Data:     []byte{0x0},
			}); err != nil {
				return
			}
			log.WithFields(m.LogFields()).WithField("model_year", c.ModelYear).Debug("received a start request")
			c.signalStarted()
		case protocol.CmdInMy14StartReq:
			if m.Ack != protocol.Request {
				break // The car acknowledging our rekey request.
			}
			c.ModelYear = ModelYear14
			if err := c.SendMessage(context.Background(), &protocol.PhevMessage{
				Type:     protocol.CmdOutMy14StartResp,
				Register: 0x1,
				Ack:      protocol.Ack,
				Xor:      m.Xor,
				Data:     []byte{0x0},
			}); err != nil {
				return
			}
			log.WithFields(m.LogFields()).WithField("model_year", c.ModelYear).Debug("received a start request")
			c.signalStarted()
		}
	}
}

func (c *Client) reader() {
	for {
		c.conn.(*net.TCPConn).SetReadDeadline(time.Now().Add(30 * time.Second))
		data := make([]byte, 4096)
		n, err := c.conn.Read(data)
		if err != nil {
			c.fail(fmt.Errorf("reading: %w", err))
			break
		}
		c.lastRx = time.Now()
		log.WithFields(log.Fields{"bytes": n, "data": hex.EncodeToString(data[:n])}).Trace("received data")
		if _, err := SdNotify(false, SdNotifyWatchdog); err != nil {
			log.WithError(err).Warn("could not reset systemd watchdog")
		}
		messages := protocol.NewFromBytes(data[:n], c.key)
		for _, m := range messages {
			c.rxMessages.Add(1)
			log.WithFields(m.LogFields()).Debug("received a message")
			c.lMu.Lock()
			for _, l := range c.listeners {
				l.Send(m)
			}
			c.lMu.Unlock()
			c.Recv <- m
		}
	}
	c.shutdown()
	close(c.Recv)
	c.lMu.Lock()
	for _, l := range c.listeners {
		l.Stop()
	}
	c.lMu.Unlock()
	return
}

// The encrypted message types we send in reply to the car: acks to its register notifications and
// pings in reply to its keepalives. The writer rekeys ahead of time when one of these would
// collide, so that the reply is not held back while the car waits for it. Messages we send on our
// own initiative only rekey once they are about to be sent.
var replyTypes = []byte{protocol.CmdOutSend, protocol.CmdOutPingReq}

// How long to wait for the car to answer a rekey request.
var rekeyTimeout = 2 * time.Second

func (c *Client) writer() {
	defer c.shutdown()
	// Messages waiting to be sent. They are held back while the car rekeys.
	var queue []*protocol.PhevMessage
	var rekeyDeadline <-chan time.Time
	// The type of the start responses we sent, telling the car's model year. Kept here rather
	// than read from ModelYear, which manage updates concurrently.
	var startResponse byte
	rekey := func(why string) error {
		log.WithField("reason", why).Debug("asking the car to rekey")
		rekeyDeadline = time.After(rekeyTimeout)
		return c.write(protocol.NewRekeyRequestMessage(startResponse))
	}
	// Set when the car did not answer a rekey request. Until it sends a new start request,
	// collisions are left to be recovered from by resyncing on the CmdInBadEncoding that follows.
	rekeyFailed := false
	for {
		for rekeyDeadline == nil && len(queue) > 0 {
			msg := queue[0]
			if !rekeyFailed && c.collides(msg.Type, startResponse) {
				if err := rekey(fmt.Sprintf("a %02x message would collide", msg.Type)); err != nil {
					c.fail(err)
					return
				}
				break
			}
			if err := c.write(msg); err != nil {
				c.fail(err)
				return
			}
			queue = queue[1:]
		}
		if rekeyDeadline == nil && !rekeyFailed {
			for _, typ := range replyTypes {
				if c.collides(typ, startResponse) {
					if err := rekey(fmt.Sprintf("the next %02x message would collide", typ)); err != nil {
						c.fail(err)
						return
					}
					break
				}
			}
		}
		select {
		case <-c.done:
			return
		case <-rekeyDeadline:
			log.WithField("timeout", rekeyTimeout).Warn("the car did not rekey, not asking again until it restarts")
			rekeyDeadline = nil
			rekeyFailed = true
		case msg, ok := <-c.Send:
			if !ok {
				return
			}
			switch msg.Type {
			case protocol.CmdOutMy18StartResp, protocol.CmdOutMy14StartResp:
				// Not encrypted, and the car waits for it before using the new key.
				if err := c.write(msg); err != nil {
					c.fail(err)
					return
				}
				startResponse = msg.Type
				rekeyDeadline = nil
				rekeyFailed = false
			default:
				queue = append(queue, msg)
			}
		}
	}
}

// collides is whether a message of type typ, encoded with the current send key, would begin
// with startResponse, the type of the unencrypted start response. The car takes such messages
// for one and drops them without advancing its receive key, after which it fails to decode
// everything we send.
func (c *Client) collides(typ, startResponse byte) bool {
	if startResponse == 0 {
		return false // Not started yet.
	}
	return typ != startResponse && typ^c.key.SKey(false) == startResponse
}

func (c *Client) write(msg *protocol.PhevMessage) error {
	msg.Xor = 0
	data := msg.EncodeToBytes(c.key)
	log.WithFields(msg.LogFields()).Debug("sending a message")
	log.WithFields(log.Fields{"bytes": len(data), "data": hex.EncodeToString(data)}).Trace("sending data")
	c.conn.(*net.TCPConn).SetWriteDeadline(time.Now().Add(15 * time.Second))
	if _, err := c.conn.Write(data); err != nil {
		return fmt.Errorf("writing: %w", err)
	}
	c.txMessages.Add(1)
	return nil
}

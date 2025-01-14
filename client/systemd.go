package client

import ("net"; "os"; "strconv"; "time")

const (
	// SdNotifyWatchdog tells the service manager to update the watchdog
	// timestamp for the service.
	SdNotifyWatchdog = "WATCHDOG=1"
)

// SdNotify sends a message to the init daemon. It is common to ignore the error.
// If `unsetEnvironment` is true, the environment variable `NOTIFY_SOCKET`
// will be unconditionally unset.
//
// It returns one of the following:
// (false, nil) - notification not supported (i.e. NOTIFY_SOCKET is unset)
// (false, err) - notification supported, but failure happened (e.g. error connecting to NOTIFY_SOCKET or while sending data)
// (true, nil) - notification supported, data has been sent
func SdNotify(unsetEnvironment bool, state string) (bool, error) {
	socketAddr := &net.UnixAddr{
		Name: os.Getenv("NOTIFY_SOCKET"),
		Net:  "unixgram",
	}

	// NOTIFY_SOCKET not set
	if socketAddr.Name == "" {
		return false, nil
	}

	if unsetEnvironment {
		if err := os.Unsetenv("NOTIFY_SOCKET"); err != nil {
			return false, err
		}
	}

	conn, err := net.DialUnix(socketAddr.Net, nil, socketAddr)
	// Error connecting to NOTIFY_SOCKET
	if err != nil {
		return false, err
	}
	defer conn.Close()

	if _, err = conn.Write([]byte(state)); err != nil {
		return false, err
	}
	return true, nil
}

func SdWatchdogInterval(defaultInterval time.Duration) (time.Duration, error) {
	watchdogUsec, hasValue := os.LookupEnv("WATCHDOG_USEC")
	if !hasValue {
		return defaultInterval, nil
	}
	usec, err := strconv.ParseInt(watchdogUsec, 10, 64)
	if err != nil {
		return defaultInterval, err
	}
	return time.Duration(usec / 2) * time.Microsecond, nil
}

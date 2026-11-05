package cmd

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/coreos/go-systemd/v22/journal"
	log "github.com/sirupsen/logrus"
)

// journalHook sends log entries to journald with their real priorities, and their fields as
// `F_<NAME>` journal fields.
type journalHook struct{}

var journalPriorities = map[log.Level]journal.Priority{
	log.PanicLevel: journal.PriCrit,
	log.FatalLevel: journal.PriCrit,
	log.ErrorLevel: journal.PriErr,
	log.WarnLevel:  journal.PriWarning,
	log.InfoLevel:  journal.PriInfo,
	log.DebugLevel: journal.PriDebug,
	log.TraceLevel: journal.PriDebug,
}

func (journalHook) Levels() []log.Level {
	return log.AllLevels
}

func (journalHook) Fire(e *log.Entry) error {
	vars := make(map[string]string, len(e.Data)+3)
	for k, v := range e.Data {
		vars["F_"+journalFieldName(k)] = fmt.Sprint(v)
	}
	if e.Caller != nil {
		vars["CODE_FILE"] = e.Caller.File
		vars["CODE_LINE"] = strconv.Itoa(e.Caller.Line)
		vars["CODE_FUNC"] = e.Caller.Function
	}
	return journal.Send(e.Message, journalPriorities[e.Level], vars)
}

// journalFieldName makes a logrus field name a valid journal field name: uppercase letters,
// digits and underscores.
func journalFieldName(name string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z':
			return r - 'a' + 'A'
		case r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			return r
		default:
			return '_'
		}
	}, name)
}

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
	"fmt"
	"io"
	"os"

	"github.com/coreos/go-systemd/v22/journal"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var (
	cfgFile  string
	logLevel string
	logTimes bool
	// Whether stderr is the journal stream systemd connected. Children inherit `JOURNAL_STREAM`,
	// so this also checks that it is stderr's device and inode.
	toJournal bool
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "phev2mqtt",
	Short: "A utility for communicating with a Mitsubishi PHEV",
	Long: `See below for subcommands. For further information
	on this tool, see https://github.com/buxtronix/phev2mqtt.`,
	SilenceErrors: true,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		level, err := log.ParseLevel(logLevel)
		if err != nil {
			return err
		}
		// The flags parsed, so any further error is not a usage error.
		cmd.SilenceUsage = true
		log.SetLevel(level)
		if toJournal {
			log.SetReportCaller(true)
			log.SetOutput(io.Discard)
			log.AddHook(journalHook{})
		} else if logTimes {
			log.SetFormatter(&log.TextFormatter{
				FullTimestamp: true,
			})
		}
		return nil
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	toJournal, _ = journal.StderrIsJournalStream()
	if err := rootCmd.Execute(); err != nil {
		if toJournal {
			// journald stores this line at error priority because of the `<3>`.
			fmt.Fprintf(os.Stderr, "<3>error: %v\n", err)
		} else {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
		}
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().StringVarP(&logLevel, "verbosity", "v", "info", "logging level to use")
	rootCmd.PersistentFlags().BoolVarP(&logTimes, "log_timestamps", "t", false, "logging with timestamps")
}

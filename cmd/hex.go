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
	"encoding/hex"
	"github.com/buxtronix/phev2mqtt/protocol"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

// hexCmd represents the hex command
var hexCmd = &cobra.Command{
	Use:   "hex",
	Short: "Decode provided raw hex messages.",
	Long: `Decodes raw messages provided as arguments. Messages
should be in hex format, e;g 'dc2b2f762f7f'.`,
	Args: cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		securityKey = &protocol.SecurityKey{}
		for _, arg := range args {
			data, err := hex.DecodeString(arg)
			if err != nil {
				log.Errorf("Not a valid hex string [%s]: %v", arg, err)
				continue
			}
			for _, msg := range protocol.NewFromBytes(data, securityKey) {
				log.Debug(hex.EncodeToString(msg.Original))
				log.Infof("%s", msg.ShortForm())
			}
		}
	},
}

func init() {
	decodeCmd.AddCommand(hexCmd)
}

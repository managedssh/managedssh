package cmd

import (
	"github.com/mylovelytools/managedssh/internal/tui"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "managedssh",
	Short: "A beautiful SSH connection manager",
	Long: `ManagedSSH - manage, organize, and connect to your SSH hosts from a slick terminal UI.

Interface Controls:
	q           quit
	l           lock vault
	c           change master key
	/           focus search
	esc         clear search or cancel current context
	j / k       move selection (arrow keys also supported)
	a           add host
	e           edit selected host
	y           duplicate selected host
	d           delete selected host (with confirmation)
	h           run health check for all saved hosts
	enter       connect to selected host
	x           export backup
	i           import backup`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		return tui.Start()
	},
}

func Execute() error {
	return rootCmd.Execute()
}

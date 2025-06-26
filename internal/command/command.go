package command

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"

	"github.com/caddyserver/caddy/v2"
	caddycmd "github.com/caddyserver/caddy/v2/cmd"
	"github.com/spf13/cobra"

	"github.com/hslatman/caddy-crowdsec-bouncer/internal/adminapi"
	"github.com/hslatman/caddy-crowdsec-bouncer/internal/version"
)

func Register() {
	caddycmd.RegisterCommand(caddycmd.Command{
		Name:  "crowdsec",
		Usage: ``,
		Short: "Commands related to the CrowdSec integration (experimental)",
		Long: `Commands related to the CrowdSec integration (experimental)

The subcommands can help assessing the status of the CrowdSec integration.

Output of the commands can change, so shouldn't be relied upon (yet).`,
		CobraFunc: func(cmd *cobra.Command) {
			infoCmd := &cobra.Command{
				Use:   "info [--config <path> [--adapter <name>]] [--address <interface>]",
				Short: "Shows CrowdSec runtime information",
				Long:  ``,
				RunE:  caddycmd.WrapCommandFuncForCobra(cmdInfo),
			}
			healthCmd := &cobra.Command{
				Use:   "health [--config <path> [--adapter <name>]] [--address <interface>]",
				Short: "Checks CrowdSec integration health",
				Long:  ``,
				RunE:  caddycmd.WrapCommandFuncForCobra(cmdHealth),
			}
			pingCmd := &cobra.Command{
				Use:   "ping [--config <path> [--adapter <name>]] [--address <interface>]",
				Short: "Pings the CrowdSec LAPI endpoint",
				Long:  ``,
				RunE:  caddycmd.WrapCommandFuncForCobra(cmdPing),
			}
			checkCmd := &cobra.Command{
				Use:   "check <ip> [--config <path> [--adapter <name>]] [--address <interface>]",
				Short: "Checks an IP to be banned or not",
				Long:  ``,
				RunE:  caddycmd.WrapCommandFuncForCobra(cmdCheck),
			}
			checkCmd.Flags().BoolP("live", "", false, `Force the check to use the "live" bouncer to check the IP`)

			// shared flags for all subcommands
			cmd.PersistentFlags().StringP("config", "c", "", "Configuration file to use to parse the admin address, if --address is not used")
			cmd.PersistentFlags().StringP("adapter", "a", "", "Name of config adapter to apply (when --config is used)")
			cmd.PersistentFlags().StringP("address", "", "", "The address to use to reach the admin API endpoint, if not the default")

			// add the subcommands
			cmd.AddCommand(infoCmd)
			cmd.AddCommand(healthCmd)
			cmd.AddCommand(checkCmd)
			cmd.AddCommand(pingCmd)

			// set version for this command to the CrowdSec module version
			cmd.Version = version.Current()
		},
	})
}

const (
	exitCodeError   = caddy.ExitCodeFailedStartup
	exitCodeSuccess = caddy.ExitCodeSuccess
)

func withClientConfigFromFlags(fl caddycmd.Flags) adminapi.ClientConfig {
	return adminapi.ClientConfig{
		Address:    fl.String("address"),
		ConfigFile: fl.String("config"),
		Adapter:    fl.String("adapter"),
	}
}

func cmdInfo(fl caddycmd.Flags) (int, error) {
	c, err := adminapi.NewClient(withClientConfigFromFlags(fl))
	if err != nil {
		return exitCodeError, err
	}

	s, err := c.Info()
	if err != nil {
		return exitCodeError, fmt.Errorf("failed getting CrowdSec runtime info: %w", err)
	}

	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return exitCodeError, fmt.Errorf("failed marshaling CrowdSec runtime info: %w", err)
	}

	fmt.Println(string(b))

	return exitCodeSuccess, nil
}

func cmdHealth(fl caddycmd.Flags) (int, error) {
	c, err := adminapi.NewClient(withClientConfigFromFlags(fl))
	if err != nil {
		return exitCodeError, err
	}

	h, err := c.Health()
	if err != nil {
		return exitCodeError, fmt.Errorf("failed getting CrowdSec runtime health: %w", err)
	}

	if !h.Ok {
		return exitCodeError, nil
	}

	return exitCodeSuccess, nil
}

func cmdPing(fl caddycmd.Flags) (int, error) {
	c, err := adminapi.NewClient(withClientConfigFromFlags(fl))
	if err != nil {
		return exitCodeError, err
	}

	h, err := c.Ping()
	if err != nil {
		return exitCodeError, fmt.Errorf("failed pinging CrowdSec LAPI: %w", err)
	}

	if !h.Ok {
		fmt.Println("failed")
		return exitCodeError, nil
	}

	fmt.Println("success")
	return exitCodeSuccess, nil
}

func cmdCheck(fl caddycmd.Flags) (int, error) {
	c, err := adminapi.NewClient(withClientConfigFromFlags(fl))
	if err != nil {
		return exitCodeError, err
	}

	ipString := fl.Arg(0)
	if ipString == "" {
		return exitCodeError, errors.New("ip required")
	}

	ip, err := netip.ParseAddr(ipString)
	if err != nil {
		return exitCodeError, fmt.Errorf("failed parsing %q as IP address: %w", ipString, err)
	}

	forceLive := fl.Bool("live")
	h, err := c.Check(ip, forceLive)
	if err != nil {
		return exitCodeError, fmt.Errorf("failed checking IP %q: %w", ip, err)
	}

	fmt.Println("blocked:", h.Blocked)

	return exitCodeSuccess, nil
}

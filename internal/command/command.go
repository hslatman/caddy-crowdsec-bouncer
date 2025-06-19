package command

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"

	"github.com/caddyserver/caddy/v2"
	caddycmd "github.com/caddyserver/caddy/v2/cmd"
	"github.com/spf13/cobra"
)

func Register() {
	caddycmd.RegisterCommand(caddycmd.Command{
		Name:  "crowdsec",
		Usage: ``, //Usage: "[--config <path> [--adapter <name>]] [--envfile <path>] [--watch] [--pidfile <file>]",
		Short: "Commands related to the CrowdSec integration",
		Long:  ``,
		CobraFunc: func(cmd *cobra.Command) {
			statusCmd := &cobra.Command{
				Use:   "info [--config <path> [--adapter <name>]] [--address <interface>]",
				Short: "Shows some CrowdSec runtime information",
				Long:  ``,
				RunE:  caddycmd.WrapCommandFuncForCobra(cmdInfo),
			}
			statusCmd.Flags().StringP("config", "c", "", "Configuration file to use to parse the admin address, if --address is not used")
			statusCmd.Flags().StringP("adapter", "a", "", "Name of config adapter to apply (when --config is used)")
			statusCmd.Flags().StringP("address", "", "", "The address to use to reach the admin API endpoint, if not the default")
			cmd.AddCommand(statusCmd)

			healthCmd := &cobra.Command{
				Use:   "health [--config <path> [--adapter <name>]] [--address <interface>]",
				Short: "Checks CrowdSec health",
				Long:  ``,
				RunE:  caddycmd.WrapCommandFuncForCobra(cmdHealth),
			}
			healthCmd.Flags().StringP("config", "c", "", "Configuration file to use to parse the admin address, if --address is not used")
			healthCmd.Flags().StringP("adapter", "a", "", "Name of config adapter to apply (when --config is used)")
			healthCmd.Flags().StringP("address", "", "", "The address to use to reach the admin API endpoint, if not the default")
			cmd.AddCommand(healthCmd)

			checkCmd := &cobra.Command{
				Use:   "check <ip> [--config <path> [--adapter <name>]] [--address <interface>]",
				Short: "Checks an IP",
				Long:  ``,
				RunE:  caddycmd.WrapCommandFuncForCobra(cmdCheck),
			}
			checkCmd.Flags().StringP("config", "c", "", "Configuration file to use to parse the admin address, if --address is not used")
			checkCmd.Flags().StringP("adapter", "a", "", "Name of config adapter to apply (when --config is used)")
			checkCmd.Flags().StringP("address", "", "", "The address to use to reach the admin API endpoint, if not the default")
			checkCmd.Flags().BoolP("live", "", false, `Force the check to use the "live" bouncer to check the IP`)
			cmd.AddCommand(checkCmd)

			pingCmd := &cobra.Command{
				Use:   "ping [--config <path> [--adapter <name>]] [--address <interface>]",
				Short: "Pings the CrowdSec LAPI endpoint",
				Long:  ``,
				RunE:  caddycmd.WrapCommandFuncForCobra(cmdPing),
			}
			pingCmd.Flags().StringP("config", "c", "", "Configuration file to use to parse the admin address, if --address is not used")
			pingCmd.Flags().StringP("adapter", "a", "", "Name of config adapter to apply (when --config is used)")
			pingCmd.Flags().StringP("address", "", "", "The address to use to reach the admin API endpoint, if not the default")
			pingCmd.Flags().BoolP("live", "", false, `Force the check to use the "live" bouncer to check the IP`)
			cmd.AddCommand(pingCmd)
		},
	})
}

const (
	errorCode   = caddy.ExitCodeFailedStartup
	successCode = caddy.ExitCodeSuccess
)

func cmdInfo(fl caddycmd.Flags) (int, error) {
	c, err := newAdminClient(fl.String("address"), fl.String("config"), fl.String("adapter"))
	if err != nil {
		return errorCode, fmt.Errorf("failed creating Caddy admin client: %w", err)
	}

	s, err := c.Info()
	if err != nil {
		return errorCode, fmt.Errorf("failed getting CrowdSec runtime info: %w", err)
	}

	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return errorCode, fmt.Errorf("failed marshaling CrowdSec runtime info: %w", err)
	}

	fmt.Println(string(b))

	return successCode, nil
}

func cmdHealth(fl caddycmd.Flags) (int, error) {
	c, err := newAdminClient(fl.String("address"), fl.String("config"), fl.String("adapter"))
	if err != nil {
		return errorCode, fmt.Errorf("failed creating Caddy admin client: %w", err)
	}

	h, err := c.Health()
	if err != nil {
		return errorCode, fmt.Errorf("failed getting CrowdSec runtime health: %w", err)
	}

	if !h.Ok {
		return errorCode, nil
	}

	return successCode, nil
}

func cmdPing(fl caddycmd.Flags) (int, error) {
	c, err := newAdminClient(fl.String("address"), fl.String("config"), fl.String("adapter"))
	if err != nil {
		return errorCode, fmt.Errorf("failed creating Caddy admin client: %w", err)
	}

	h, err := c.Ping()
	if err != nil {
		return errorCode, fmt.Errorf("failed pinging CrowdSec LAPI: %w", err)
	}

	if !h.Ok {
		fmt.Println("failed")
		return errorCode, nil
	}

	fmt.Println("success")
	return successCode, nil
}

func cmdCheck(fl caddycmd.Flags) (int, error) {
	c, err := newAdminClient(fl.String("address"), fl.String("config"), fl.String("adapter"))
	if err != nil {
		return errorCode, fmt.Errorf("failed creating Caddy admin client: %w", err)
	}

	ipString := fl.Arg(0)
	if ipString == "" {
		return errorCode, errors.New("ip required")
	}

	ip, err := netip.ParseAddr(ipString)
	if err != nil {
		return errorCode, fmt.Errorf("failed parsing %q as IP address: %w", ipString, err)
	}

	forceLive := fl.Bool("live")
	h, err := c.Check(ip, forceLive)
	if err != nil {
		return errorCode, fmt.Errorf("failed checking IP %q: %w", ip, err)
	}

	fmt.Println("blocked:", h.Blocked)

	return successCode, nil
}

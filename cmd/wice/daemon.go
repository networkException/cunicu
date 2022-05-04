package main

import (
	"github.com/spf13/cobra"
	"go.uber.org/zap"
	"go.uber.org/zap/zapio"
	"golang.zx2c4.com/wireguard/wgctrl"
	"riasc.eu/wice/internal/config"
	"riasc.eu/wice/pkg"
	"riasc.eu/wice/pkg/socket"
)

var (
	daemonCmd = &cobra.Command{
		Use:               "daemon [interfaces...]",
		Short:             "Start the daemon",
		Run:               daemon,
		ValidArgsFunction: daemonCompletionArgs,
	}

	cfg *config.Config
)

func init() {
	pf := daemonCmd.PersistentFlags()
	cfg = config.NewConfig(pf)

	rootCmd.AddCommand(daemonCmd)
}

func daemonCompletionArgs(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	// Create Wireguard netlink socket
	client, err := wgctrl.New()
	if err != nil {
		logger.Fatal("Failed to create Wireguard client", zap.Error(err))
	}

	devs, err := client.Devices()
	if err != nil {
		return []string{}, cobra.ShellCompDirectiveError | cobra.ShellCompDirectiveNoFileComp
	}

	var existing = map[string]interface{}{}
	var ifnames = []string{}

	for _, arg := range args {
		existing[arg] = nil
	}

	for _, dev := range devs {
		if _, exists := existing[dev.Name]; !exists {
			ifnames = append(ifnames, dev.Name)
		}
	}

	return ifnames, cobra.ShellCompDirectiveNoFileComp
}

func daemon(cmd *cobra.Command, args []string) {
	if err := cfg.Setup(args); err != nil {
		zap.L().Fatal("Failed to parse configuration", zap.Error(err))
	}

	if logger.Core().Enabled(zap.DebugLevel) {
		logger.Debug("Loaded configuration:")
		cfg.Dump(&zapio.Writer{Log: logger})
	}

	// Create daemon
	daemon, err := pkg.NewDaemon(cfg)
	if err != nil {
		logger.Fatal("Failed to create daemon", zap.Error(err))
	}

	// Create control socket server to manage daemon
	_, err = socket.Listen("unix", cfg.GetString("socket.path"), cfg.GetBool("socket.wait"), daemon)
	if err != nil {
		logger.Fatal("Failed to initialize control socket", zap.Error(err))
	}

	if err := daemon.Run(); err != nil {
		logger.Fatal("Failed run daemon", zap.Error(err))
	}
}

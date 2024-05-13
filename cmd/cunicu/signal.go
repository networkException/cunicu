// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"net"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	osx "cunicu.li/cunicu/pkg/os"
	grpcx "cunicu.li/cunicu/pkg/signaling/grpc"
)

type signalOptions struct {
	listenAddress string
	secure        bool
}

func init() { //nolint:gochecknoinits
	opts := &signalOptions{
		secure: false,
	}
	cmd := &cobra.Command{
		Use:   "signal",
		Short: "Start gRPC signaling server",
		Run: func(cmd *cobra.Command, args []string) {
			signal(cmd, args, opts)
		},
		Args: cobra.NoArgs,
	}

	pf := cmd.PersistentFlags()
	pf.StringVarP(&opts.listenAddress, "listen", "L", ":8080", "listen address")
	pf.BoolVarP(&opts.secure, "secure", "S", false, "listen with TLS")

	rootCmd.AddCommand(cmd)
}

func signal(_ *cobra.Command, _ []string, opts *signalOptions) {
	var protocol string

	if strings.HasPrefix(opts.listenAddress, "/") || strings.HasPrefix(opts.listenAddress, "./") {
		protocol = "unix"
	} else {
		protocol = "tcp"
	}

	l, err := net.Listen(protocol, opts.listenAddress)
	if err != nil {
		logger.Fatal("Failed to listen", zap.Error(err))
	}

	if protocol == "unix" {
		err = os.Chmod(opts.listenAddress, 0222)
		if err != nil {
			logger.Fatal("Failed to set unix socket permissions", zap.Error(err))
		}
	}

	// Disable TLS
	svrOpts := []grpc.ServerOption{}
	if !opts.secure {
		svrOpts = append(svrOpts, grpc.Creds(insecure.NewCredentials()))
	}

	svr := grpcx.NewSignalingServer(svrOpts...)

	go func() {
		for sig := range osx.SetupSignals() {
			logger.Debug("Received signal", zap.Any("signal", sig))

			if err := svr.Close(); err != nil {
				logger.Error("Failed to close server", zap.Error(err))
			}
		}
	}()

	logger.Info("Starting gRPC signaling server", zap.String("address", opts.listenAddress))

	if err := svr.Serve(l); err != nil {
		logger.Fatal("Failed to start gRPC server", zap.Error(err))
	}

	logger.Info("Gracefully stopped gRPC signaling server")
}

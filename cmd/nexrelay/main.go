package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/urfave/cli/v2"

	"github.com/nexodus-io/nexodus/internal/nexodus/nexrelay"
	"go.uber.org/zap"
)

const (
	nexRelayLogEnv = "NEXRELAY_LOGLEVEL"
)

// This variable is set using ldflags at build time. See Makefile for details.
var Version = "dev"

func main() {
	// set the log level
	debug := os.Getenv(nexRelayLogEnv)
	var logger *zap.Logger
	var err error
	if debug != "" {
		logger, err = zap.NewDevelopment()
		logger.Info("Debug logging enabled")
	} else {
		logCfg := zap.NewProductionConfig()
		logCfg.DisableStacktrace = true
		logger, err = logCfg.Build()
	}
	if err != nil {
		logger.Fatal(err.Error())
	}

	// Overwrite usage to capitalize "Show"
	cli.HelpFlag.(*cli.BoolFlag).Usage = "Show help"
	// flags are stored in the global flags variable
	app := &cli.App{
		Name:  "nexrelay",
		Usage: "Nexodus relay agent that configure traffic relay between two nodes in Nexodus network through a relay node.",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:     "public-key",
				Value:    "",
				Usage:    "Public key for the local host - agent generates keys by default",
				EnvVars:  []string{"NEXRELAY_PUB_KEY"},
				Required: false,
			},
			&cli.StringFlag{
				Name:     "private-key",
				Value:    "",
				Usage:    "Private key for the local host (dev purposes only - soon to be removed)",
				EnvVars:  []string{"NEXRELAY_PRIVATE_KEY"},
				Required: false,
			},
			&cli.IntFlag{
				Name:     "listen-port",
				Value:    0,
				Usage:    "Port wireguard is to listen for incoming peers on",
				EnvVars:  []string{"NEXRELAY_LISTEN_PORT"},
				Required: false,
			},
			&cli.StringFlag{
				Name:     "request-ip",
				Value:    "",
				Usage:    "Request a specific IP address from Ipam if available (optional)",
				EnvVars:  []string{"NEXRELAY_REQUESTED_IP"},
				Required: false,
			},
			&cli.StringFlag{
				Name:     "local-endpoint-ip",
				Value:    "",
				Usage:    "Specify the endpoint address of this node instead of being discovered (optional)",
				EnvVars:  []string{"NEXRELAY_LOCAL_ENDPOINT_IP"},
				Required: false,
			},
			&cli.BoolFlag{
				Name:     "stun",
				Usage:    "Discover the public address for this host using STUN",
				Value:    false,
				EnvVars:  []string{"NEXRELAY_STUN"},
				Required: false,
			},
			&cli.StringFlag{
				Name:     "username",
				Value:    "",
				Usage:    "Username for accessing the nexodus service",
				EnvVars:  []string{"NEXRELAY_USERNAME"},
				Required: false,
			},
			&cli.StringFlag{
				Name:     "password",
				Value:    "",
				Usage:    "Password for accessing the nexodus service",
				EnvVars:  []string{"NEXRELAY_PASSWORD"},
				Required: false,
			},
			&cli.BoolFlag{
				Name:     "insecure-skip-tls-verify",
				Value:    false,
				Usage:    "If true, server certificates will not be checked for validity. This will make your HTTPS connections insecure",
				EnvVars:  []string{"APEX_INSECURE_SKIP_TLS_VERIFY"},
				Required: false,
			},
		},
		Before: func(c *cli.Context) error {
			if c.IsSet("clean") {
				log.Print("Cleaning up any existing interfaces")
				// todo: implement a cleanup function
			}
			return nil
		},
		Action: func(cCtx *cli.Context) error {

			controller := cCtx.Args().First()
			if controller == "" {
				logger.Info("<controller-url> required")
				return nil
			}

			ctx, _ := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGQUIT, syscall.SIGINT)

			nexrelay, err := nexrelay.NewNexrelay(
				ctx,
				logger.Sugar(),
				controller,
				cCtx.String("username"),
				cCtx.String("password"),
				cCtx.Int("listen-port"),
				cCtx.String("public-key"),
				cCtx.String("private-key"),
				cCtx.String("request-ip"),
				cCtx.String("local-endpoint-ip"),
				cCtx.Bool("stun"),
				cCtx.Bool("insecure-skip-tls-verify"),
				Version,
			)
			if err != nil {
				logger.Fatal(err.Error())
			}

			wg := &sync.WaitGroup{}
			if err := nexrelay.Start(ctx, wg); err != nil {
				logger.Fatal(err.Error())
			}
			wg.Wait()

			return nil
		},
	}
	if err := app.Run(os.Args); err != nil {
		logger.Fatal(err.Error())
	}
}

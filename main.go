package main // import "alterway/sshportal"

import (
	"context"
	"log"
	"os"
	"path"

	"github.com/urfave/cli/v3"
)

var (
	// GitTag will be overwritten automatically by the build system
	GitTag = "n/a"
	// GitSha will be overwritten automatically by the build system
	GitSha = "n/a"
)

func main() {
	app := &cli.Command{
		Name:    path.Base(os.Args[0]),
		Authors: []any{"Manfred Touron"},
		Version: GitTag + " (" + GitSha + ")",
	}

	app.Commands = []*cli.Command{
		{
			Name:  "server",
			Usage: "Start sshportal server",
			Action: func(c context.Context, cmd *cli.Command) error {
				if err := ensureLogDirectory(cmd.String("logs-location")); err != nil {
					return err
				}
				cfg, err := parseServerConfig(cmd)
				if err != nil {
					return err
				}
				return server(cfg)
			},
			Flags: []cli.Flag{
				&cli.StringFlag{
					Name:    "bind-address, b",
					Sources: cli.EnvVars("SSHPORTAL_BIND"),
					Value:   ":2222",
					Usage:   "SSH server bind address",
				},
				&cli.StringFlag{
					Name:    "db-driver",
					Sources: cli.EnvVars("SSHPORTAL_DB_DRIVER"),
					Value:   "sqlite3",
					Usage:   "GORM driver (sqlite3)",
				},
				&cli.StringFlag{
					Name:    "db-conn",
					Sources: cli.EnvVars("SSHPORTAL_DATABASE_URL"),
					Value:   "./sshportal.db",
					Usage:   "GORM connection string",
				},
				&cli.BoolFlag{
					Name:    "debug, D",
					Sources: cli.EnvVars("SSHPORTAL_DEBUG"),
					Usage:   "Display debug information",
				},
				&cli.StringFlag{
					Name:    "aes-key",
					Sources: cli.EnvVars("SSHPORTAL_AES_KEY"),
					Usage:   "Encrypt sensitive data in database (length: 16, 24 or 32)",
				},
				&cli.StringFlag{
					Name:    "logs-location",
					Sources: cli.EnvVars("SSHPORTAL_LOGS_LOCATION"),
					Value:   "./log",
					Usage:   "Store user session files",
				},
				&cli.DurationFlag{
					Name:  "idle-timeout",
					Value: 0,
					Usage: "Duration before an inactive connection is timed out (0 to disable)",
				},
				&cli.StringFlag{
					Name:    "acl-check-cmd",
					Sources: cli.EnvVars("SSHPORTAL_ACL_CHECK_CMD"),
					Usage:   "Execute external command to check ACL",
				},
			},
		},
		{
			Name: "healthcheck",
			Action: func(c context.Context, cmd *cli.Command) error {
				cfg, err := parseServerConfig(cmd)
				if err != nil {
					return err
				}
				return healthcheck(cfg, cmd.String("addr"), cmd.Bool("wait"), cmd.Bool("quiet"))
			},
			Flags: []cli.Flag{
				&cli.StringFlag{
					Name:  "addr, a",
					Value: "localhost:2222",
					Usage: "sshportal server address",
				},
				&cli.StringFlag{
					Name:    "db-driver",
					Sources: cli.EnvVars("SSHPORTAL_DB_DRIVER"),
					Value:   "sqlite3",
					Usage:   "GORM driver (sqlite3)",
				},
				&cli.StringFlag{
					Name:    "db-conn",
					Sources: cli.EnvVars("SSHPORTAL_DATABASE_URL"),
					Value:   "./sshportal.db",
					Usage:   "GORM connection string",
				},
				&cli.BoolFlag{
					Name:  "wait, w",
					Usage: "Loop indefinitely until sshportal is ready",
				},
				&cli.BoolFlag{
					Name:  "quiet, q",
					Usage: "Do not print errors, if any",
				},
			},
		},
		{
			Name:   "_test_server",
			Hidden: true,
			Action: testServer,
		},
	}

	if err := app.Run(context.Background(), os.Args); err != nil {
		log.Fatalf("error: %v", err)
	}
}

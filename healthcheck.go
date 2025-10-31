package main

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"strings"
	"time"

	"github.com/urfave/cli/v3"
	gossh "golang.org/x/crypto/ssh"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// performs a healthcheck test without requiring an ssh client or an ssh key
// This is used for the Docker HEALTHCHECK
func healthcheck(c *serverConfig, addr string, wait, quiet bool) error {
	var hostKey string

	db, err := dbConnect(c, &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		return fmt.Errorf("healthcheck: can't connect to DB: %v", err)
	}

	if err := db.Table("ssh_keys").Where("name = ?", "host").Select("pub_key").Find(&hostKey).Error; err != nil {
		return fmt.Errorf("healthcheck: %v", err)
	}

	pubKey, _, _, _, err := gossh.ParseAuthorizedKey([]byte(hostKey)) //nolint:dogsled
	if err != nil {
		return fmt.Errorf("healthcheck: %v", err)
	}

	cfg := gossh.ClientConfig{
		User:            "healthcheck",
		HostKeyCallback: gossh.FixedHostKey(pubKey),
		Auth:            []gossh.AuthMethod{gossh.Password("healthcheck")},
	}

	if wait {
		for {
			if err := healthcheckOnce(addr, cfg, quiet); err != nil {
				if !quiet {
					log.Printf("healthcheck: %v", err)
				}
				time.Sleep(time.Second)
				continue
			}
			return nil
		}
	}

	if err := healthcheckOnce(addr, cfg, quiet); err != nil {
		if quiet {
			return cli.Exit("", 1)
		}
		return err
	}
	return nil
}

func healthcheckOnce(addr string, config gossh.ClientConfig, quiet bool) error {
	client, err := gossh.Dial("tcp", addr, &config)
	if err != nil {
		return err
	}

	session, err := client.NewSession()
	if err != nil {
		return err
	}
	defer func() {
		// https://github.com/golang/go/issues/38115
		if err := session.Close(); err != nil {
			if !quiet && err != io.EOF {
				log.Printf("failed to close session: %v", err)
			}
		}
	}()

	var b bytes.Buffer
	session.Stdout = &b
	if err := session.Run(""); err != nil {
		return err
	}
	stdout := strings.TrimSpace(b.String())
	if stdout != "OK" {
		return fmt.Errorf("invalid stdout: %q expected 'OK'", stdout)
	}
	return nil
}

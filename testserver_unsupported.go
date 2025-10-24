//go:build windows
// +build windows

package main

import (
	"fmt"

	"github.com/urfave/cli/v3"
)

// testServer is an hidden handler used for integration tests
func testServer(c *cli.Context) error {
	return fmt.Errorf("not available on windows")
}

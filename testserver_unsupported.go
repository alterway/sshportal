//go:build windows

package main

import (
	"context"
	"fmt"

	"github.com/urfave/cli/v3"
)

// testServer is an hidden handler used for integration tests
func testServer(_ context.Context, _ *cli.Command) error {
	return fmt.Errorf("not available on windows")
}

//go:build !linux

package host

import "os/exec"

func configureGeneratedFlowCommand(cmd *exec.Cmd) {}

func cleanupGeneratedFlowCommand(cmd *exec.Cmd) {}

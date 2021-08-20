package ui

import (
	"fmt"
	"os"

	"golang.org/x/sys/windows"
)

func init() {
	var inMode, outMode uint32
	if err := windows.GetConsoleMode(windows.Stdin, &inMode); err == nil {
		inMode |= windows.ENABLE_VIRTUAL_TERMINAL_INPUT
		if err := windows.SetConsoleMode(windows.Stdin, inMode); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to set console mode: %v", err)
		}
	}
	if err := windows.GetConsoleMode(windows.Stdout, &outMode); err == nil {
		outMode |= windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING
		if err := windows.SetConsoleMode(windows.Stdout, outMode); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to set console mode: %v", err)
		}
	}
}

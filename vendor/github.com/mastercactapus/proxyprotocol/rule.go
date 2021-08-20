package proxyprotocol

import (
	"net"
	"time"
)

// Rule contains configuration for a single subnet.
type Rule struct {
	// Subnet is used to match incomming IP addresses against this rule.
	Subnet *net.IPNet

	// Timeout indicates the max amount of time to receive the PROXY header before
	// terminating the connection.
	Timeout time.Duration
}

package proxyprotocol

// Cmd indicates the PROXY command being used.
type Cmd byte

const (
	// CmdLocal indicates the connection was established on purpose by the proxy without being relayed.
	CmdLocal Cmd = 0x00

	// CmdProxy the connection was established on behalf of another node, and reflects the original connection endpoints.
	CmdProxy Cmd = 0x01
)

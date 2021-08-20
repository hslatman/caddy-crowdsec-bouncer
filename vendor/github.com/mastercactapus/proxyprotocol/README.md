# proxyprotocol

[![GoDoc](https://godoc.org/github.com/mastercactapus/proxyprotocol?status.svg)](https://godoc.org/github.com/mastercactapus/proxyprotocol)
[![Build Status](https://travis-ci.org/mastercactapus/proxyprotocol.svg?branch=master)](https://travis-ci.org/mastercactapus/proxyprotocol)


This package provides PROXY protocol support for versions 1 and 2.

https://www.haproxy.org/download/1.8/doc/proxy-protocol.txt

Features:

- Auto detect both V1 and V2
- Client & Server usage support
- Listener with optional subnet filtering (for TCP/UDP listeners)

## Installation

Installable via `go get`

```bash
go get -u github.com/mastercactapus/proxyprotocol
```

## Usage

```go
// Create any net.Listener
l, err := net.Listen("tcp", ":0")
l, err := net.Listen("udp", ":0")
l, err := net.Listen("unix", "/tmp/example")
l, err := net.Listen("unixgram", "/tmp/example")

// Wrap it to have RemoteAddr() and LocalAddr() resolved for all new connections
l = proxyprotocol.NewListener(l, 0)

c, err : = l.Accept()

c.RemoteAddr() // = The PROXY header source address
c.LocalAddr()  // = The PROXY header destination address
```

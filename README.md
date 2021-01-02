# CrowdSec Bouncer for Caddy

A (WIP) Caddy app and http handler that blocks malicious traffic based on decisions made by [CrowdSec](https://crowdsec.net/).

## Description

__This repository is currently a WIP. Things are likely going to change a bit.__

CrowdSec is a free and open source security automation tool that uses local logs and a set of scenarios to infer malicious intent. 
In addition to operating locally, an optional community integration is also available, through which crowd-sourced IP reputation lists are distributed.

The architecture of CrowdSec is very modular.
Its core is the CrowdSec Agent, which keeps track of all data and related systems.
Bouncers are pieces of software that perform specific actions based on the decisions of the Agent.

This repository contains a custom CrowdSec Bouncer that can be embedded as a Caddy module.
It consists of the follwing two main pieces:

* A Caddy App
* A Caddy HTTP Handler

The App is responsible for communicating with a CrowdSec Agent via the CrowdSec *Local API* and keeping track of the decisions of the Agent.
The HTTP Handler checks client IPs of incoming requests against the decisions stored by the App.
This way, multiple independent HTTP Handlers can use the storage exposed by the App.

## Usage

Get the module

```bash
go get github.com/hslatman/caddy-crowdsec-bouncer/pkg/crowdsec
```

Create a (custom) Caddy server (or use *xcaddy*)

```go
package main

import (
	cmd "github.com/caddyserver/caddy/v2/cmd"

	_ "github.com/caddyserver/caddy/v2/modules/standard"
	_ "github.com/caddyserver/format-encoder"

	_ "github.com/hslatman/caddy-crowdsec-bouncer/pkg/crowdsec"
)

func main() {
	cmd.Main()
}
```

Example config.json:

```json
{   
    "apps": {
      "crowdsec": {
        "api_key": "<insert_crowdsec_local_api_key_here>",
        "api_url": "http://127.0.0.1:8080/",
        "ticker_interval": "10s"
      },
      "http": {
        "http_port": 9080,
        "https_port": 9443,
        "servers": {
          "example": {
            "listen": [
              "127.0.0.1:9443"
            ],
            "routes": [
              {
                "group": "example-group",
                "match": [
                  {
                    "path": [
                      "/*"
                    ]
                  }
                ],
                "handle": [
                  {
                    "handler": "crowdsec"
                  },
                  {
                    "handler": "static_response",
                    "status_code": "200",
                    "body": "Hello World!"
                  },
                  {
                    "handler": "headers",
                    "response": {
                      "set": {
                        "Server": ["caddy-cs-bouncer"]
                      }
                    }
                  }
                ]
              }
            ],
            "logs": {}
          }
        }
      }
    }
  }
```

Run the Caddy server

```bash
go run main.go run -config config.json
```

## TODO

* Add log integration from Caddy to CrowdSec (i.e. using Nginx log format)
* Add tests
* Do testing with IPv6
* Extend the Docker example with a more complete setup
* Add captcha action (currently works the same as a ban)
* Add support for custom actions (defaults to blocking access now)
* Improve logic for IPv4 vs. IPv6 handling (some custom wrapper, perhaps?)
* Test (and improve?) handling of IPv6 parsing/masking logic
* Test/integrate with *project conncept* (Caddy layer 4 app)
* Fix UserAgent (CrowdSec writes: "bad user agent 'caddy-cs-bouncer' from ...)
* ...
# CrowdSec Bouncer for Caddy

A [Caddy](https://caddyserver.com/) module that blocks malicious traffic based on decisions made by [CrowdSec](https://crowdsec.net/).

## Description

__This repository is currently a WIP. Things may change a bit.__

CrowdSec is a free and open source security automation tool that uses local logs and a set of scenarios to infer malicious intent. 
In addition to operating locally, an optional community integration is also available, through which crowd-sourced IP reputation lists are distributed.

The architecture of CrowdSec is very modular.
At its core is the CrowdSec Agent, which keeps track of all data and related systems.
Bouncers are pieces of software that perform specific actions based on the decisions of the Agent.

This repository contains a custom CrowdSec Bouncer that can be embedded as a Caddy module.
It consists of the follwing three main pieces:

* A Caddy App
* A Caddy HTTP Handler
* A Caddy [Layer 4](https://github.com/mholt/caddy-l4) Connection Matcher

The App is responsible for communicating with a CrowdSec Agent via the CrowdSec *Local API* and keeping track of the decisions of the Agent.
The HTTP Handler checks client IPs of incoming requests against the decisions stored by the App.
This way, multiple independent HTTP Handlers or Connection Matchers can use the storage exposed by the App.
The App can be configured to use either the StreamBouncer, which gets decisions via a HTTP polling mechanism, or the LiveBouncer, which sends a request on every incoming HTTP request or Layer 4 connection setup.

## Usage

Get the module

```bash
# get the http handler
go get github.com/hslatman/caddy-crowdsec-bouncer/http

# get the layer4 connection matcher (only required if you need support for TCP/UDP level blocking)
go get github.com/hslatman/caddy-crowdsec-bouncer/layer4
```

Create a (custom) Caddy server (or use *xcaddy*)

```go
package main

import (
  cmd "github.com/caddyserver/caddy/v2/cmd"
  _ "github.com/caddyserver/caddy/v2/modules/standard"
  // import the http handler
  _ "github.com/hslatman/caddy-crowdsec-bouncer/http"
  // import the layer4 matcher (in case you want to block connections to layer4 servers using CrowdSec)
  _ "github.com/hslatman/caddy-crowdsec-bouncer/layer4"
)

func main() {
  cmd.Main()
}
```

Example Caddyfile:

```
{
    debug
    crowdsec {
        api_url http://localhost:8080
        api_key <api_key>
        ticker_interval 15s
        #disable_streaming
        #enable_hard_fails
    }
}

localhost {
    route {
        crowdsec
        respond "Allowed by CrowdSec!"
    }
}
```

Configuration using a Caddyfile is only supported for HTTP handlers.
You'll also need to use a recent version of Caddy (i.e. 2.7.3 and newer) and Go 1.20 (or newer).
In case you want to use the CrowdSec bouncer on TCP or UDP level, you'll need to configure Caddy using the native JSON format.
An example configuration is shown below:

```json
{   
    "apps": {
      "crowdsec": {
        "api_key": "<insert_crowdsec_local_api_key_here>",
        "api_url": "http://127.0.0.1:8080/",
        "ticker_interval": "10s",
        "enable_streaming": true,
        "enable_hard_fails": false,
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
                        "Server": ["caddy-cs-bouncer-example-server"]
                      }
                    }
                  }
                ]
              }
            ],
            "logs": {}
          }
        }
      },
      "layer4": {
        "servers": {
          "https_proxy": {
            "listen": ["localhost:8443"],
            "routes": [
              {
                "match": [
                  {
                    "crowdsec": {},
                    "tls": {}
                  }
                ],
                "handle": [
                  {
                    "handler": "proxy",
                    "upstreams": [
                      {
                        "dial": ["localhost:9443"]
                      }
                    ]
                  }
                ]
              }
            ]
          }
        }
      },
    }
  }
```

Run the Caddy server

```bash
# with a Caddyfile
go run main.go run -config Caddyfile 

# with JSON configuration
go run main.go run -config config.json
```

## Demo

This repository also contains an example using Docker.
Steps to run this demo are as follows:

```bash
# run CrowdSec container
$ docker-compose up -d crowdsec

# add the Caddy bouncer, generating an API key
$ docker-compose exec crowdsec cscli bouncers add caddy-bouncer

# copy and paste the API key in the ./docker/config.json file
# below is the git diff after changing the appropriate line:
$ git diff

- "api_key": "<api_key>",
+ "api_key": "9e4ac94cf9aebaa3625a1d51951230a9",

# run Caddy; at first run a custom build will be created using xcaddy
$ docker-compose up -d caddy

# tail the logs
$ docker-compose logs -tf
```

You can then access https://localhost:9443 and https://localhost:8443.
The latter is an example of using the [Layer 4 App](https://github.com/mholt/caddy-l4) and will simply proxy to port 9443 in this case. 

## Client IP

If your Caddy server with this bouncer is deployed behind a proxy, a CDN or another system fronting the web server, the IP of the client requesting a resource is masked by the system that sits between the client and your server.
Starting with `v0.3.1`, the HTTP handler relies on Caddy to determine the actual client IP of the system performing the HTTP request. 
The new logic was implemented as part of [caddy#5104](https://github.com/caddyserver/caddy/pull/5104), and released with Caddy `v2.7.0`.
The IP that Caddy determines is used to check against the CrowdSec decisions to see if it's allowed in or not.

Caddy determines the actual client IP from the `X-Forwarded-For` header by default, but it is possible to change this using the [client_ip_headers](https://caddyserver.com/docs/json/apps/http/servers/#client_ip_headers) directive in the global settings.
The setting depends on the [trusted_proxies](https://caddyserver.com/docs/json/apps/http/servers/#trusted_proxies) directive to be set, so that the IP reported in the `X-Forwarded-For` (or one of the headers you configure as override) can be trusted.

For older versions of this Caddy module, and for older versions of Caddy (up to `v2.4.6`), the [realip](https://github.com/kirsch33/realip) module can be used instead.

## Things That Can Be Done

* Add integration tests for the HTTP and L4 handlers
* Tests with IPv6
* Test with *project conncept* (Caddy layer 4 app; TCP seems to work; UDP to be tested)
* Add captcha action (currently works the same as a ban)?
* Add support for custom actions (defaults to blocking access now)?
* Add Caddy metrics integration?
* Add Caddy profiling integration?
* Caching the LiveBouncer (for the duration of the decision)?
* ...

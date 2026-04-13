# CrowdSec Bouncer for Caddy

[![Go Report Card](https://goreportcard.com/badge/github.com/hslatman/caddy-crowdsec-bouncer)](https://goreportcard.com/report/github.com/hslatman/caddy-crowdsec-bouncer)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

> A [Caddy](https://caddyserver.com/) module that blocks malicious traffic based on decisions made by [CrowdSec](https://crowdsec.net/).

## Table of Contents
- [CrowdSec Bouncer for Caddy](#crowdsec-bouncer-for-caddy)
  - [Table of Contents](#table-of-contents)
  - [Description](#description)
    - [What is CrowdSec?](#what-is-crowdsec)
  - [Usage](#usage)
    - [Option 1: Docker Build](#option-1-docker-build)
    - [Option 2: Custom Go Build (xcaddy)](#option-2-custom-go-build-xcaddy)
    - [Configuration](#configuration)
  - [Demo](#demo)
  - [Utilities](#utilities)
    - [Usage](#usage-1)
  - [Client IP](#client-ip)
  - [Roadmap](#roadmap)
    - [Contributing](#contributing)

## Description

The Caddy CrowdSec Bouncer consists of five main components:

- **Caddy App**: Responsible for communicating with a CrowdSec Agent via the CrowdSec *Local API* and keeping track of the agent's decisions. It supports both *StreamBouncer* (HTTP polling) and *LiveBouncer* (a request is made to the agent on every incoming connection).
- **Bouncer HTTP Handler**: Checks client IPs of incoming HTTP requests against the decisions stored by the App. Multiple independent HTTP Handlers and Connection Matchers can share the storage exposed by the App.
- **Layer 4 Connection Matcher**: Matches TCP and UDP IP addresses against the CrowdSec *Local API*. Uses the [Caddy Layer 4 app](https://github.com/mholt/caddy-l4).
- **AppSec HTTP Handler**: Communicates with an AppSec component configured on your CrowdSec deployment, seamlessly checking incoming HTTP requests against configured rulesets.
- **`caddy crowdsec` Command**: Offers useful Caddy CLI commands for your CrowdSec integration.

### What is CrowdSec?

CrowdSec is a free and open source security automation tool that uses local logs and a set of scenarios to infer malicious intent. 
In addition to operating locally, an optional community integration is also available, through which crowd-sourced IP reputation lists are distributed.

The architecture of CrowdSec is very modular.
At its core is the CrowdSec Agent, which keeps track of all data and related systems.
Bouncers are pieces of software that perform specific actions based on the decisions of the Agent.

## Usage

You can use the bouncer by either building a custom Caddy image with Docker or by fetching the required Go modules directly into your own build.

> **Note:** You will need a recent version of **Caddy (v2.7.3+)** and **Go (1.20+)**.

### Option 1: Docker Build

The easiest way to include the bouncer is to build a custom Caddy Docker image using `xcaddy`. Create a `Dockerfile`:

```dockerfile
ARG CADDY_VERSION=2.11

FROM caddy:${CADDY_VERSION}-builder AS builder

RUN xcaddy build \
    --with github.com/mholt/caddy-l4 \
    --with github.com/caddyserver/transform-encoder \
    --with github.com/hslatman/caddy-crowdsec-bouncer/http@main \
    --with github.com/hslatman/caddy-crowdsec-bouncer/appsec@main \
    --with github.com/hslatman/caddy-crowdsec-bouncer/layer4@main

FROM caddy:${CADDY_VERSION} AS caddy

COPY --from=builder /usr/bin/caddy /usr/bin/caddy
```

### Option 2: Custom Go Build (xcaddy)

If you are compiling outside of Docker, you can fetch the modules using `go get`:

```bash
# Get the CrowdSec Bouncer HTTP handler
go get github.com/hslatman/caddy-crowdsec-bouncer/http

# Get the CrowdSec layer4 connection matcher (only required for TCP/UDP level blocking)
go get github.com/hslatman/caddy-crowdsec-bouncer/layer4

# Get the AppSec HTTP handler (only required for CrowdSec AppSec support)
go get github.com/hslatman/caddy-crowdsec-bouncer/appsec
```

### Configuration

Configuration using a Caddyfile is supported for HTTP handlers and Layer 4 matchers.

Example Caddyfile:

A comprehensive example of a Caddyfile using the module is provided in [examples/Caddyfile](examples/Caddyfile).

Run the Caddy server

```bash
# with a Caddyfile
caddy run --config Caddyfile 
```

## Demo

This repository also contains an example using Docker.
Steps to run this demo are as follows:

```bash
# run CrowdSec container
docker compose up -d crowdsec

# add the Caddy bouncer, generating an API key
docker compose exec crowdsec cscli bouncers add caddy-bouncer

# Copy and paste the API key in the ./docker/config.json file

# run Caddy; at first run a custom build will be created using xcaddy
docker compose up -d caddy

# tail the logs
docker compose logs -tf
```

You can then access https://localhost:9443 and https://localhost:8443.
The latter is an example of using the [Layer 4 App](https://github.com/mholt/caddy-l4) and will simply proxy to port 9443 in this case. 

## Utilities

When Caddy is built with this module enabled, a new `caddy crowdsec` command will be enabled.
Its subcommands allow you to interact with your CrowdSec integration at runtime using [Caddy's Admin API](https://caddyserver.com/docs/api).
This is useful to verify the status of your integration, and check if it's configured and working properly.
The command requires the Admin API to be reachable from the system it is run from.

Support for the command is currently experimental, and will be improved and extended in future releases.
Output of the commands should not be relied upon in automated processes (yet).

### Usage

```console
$ caddy crowdsec

Commands related to the CrowdSec integration (experimental)

Usage:
  caddy crowdsec [command]

Available Commands:
  check       Checks an IP to be banned or not
  health      Checks CrowdSec integration health
  info        Shows CrowdSec runtime information
  ping        Pings the CrowdSec LAPI endpoint

Flags:
  -a, --adapter string   Name of config adapter to apply (when --config is used)
      --address string   The address to use to reach the admin API endpoint, if not the default
  -c, --config string    Configuration file to use to parse the admin address, if --address is not used
  -h, --help             help for crowdsec
  -v, --version          version for crowdsec

Use "caddy crowdsec [command] --help" for more information about a command.

Full documentation is available at:
https://caddyserver.com/docs/command-line
```

## Client IP

When your Caddy server is deployed behind a proxy (like a CDN or load balancer), the actual client IP is masked. Starting with `v0.3.1`, this module relies on Caddy's native logic (introduced in Caddy `v2.7.0` via [caddy#5104](https://github.com/caddyserver/caddy/pull/5104)) to determine the correct client IP before checking it against CrowdSec decisions.

> **Important:** Caddy uses the `X-Forwarded-For` header by default. To trust this header, you **must** configure the [`trusted_proxies`](https://caddyserver.com/docs/json/apps/http/servers/#trusted_proxies) global directive in your Caddyfile.

You can override the default header using the [`client_ip_headers`](https://caddyserver.com/docs/json/apps/http/servers/#client_ip_headers) directive.

*Note: For Caddy versions up to `v2.4.6` and older versions of this module, the [realip](https://github.com/kirsch33/realip) module is required.*

## Roadmap

- [ ] Add integration tests for the HTTP and L4 handlers
- [ ] Implement tests for IPv6 support
- [ ] Validate *project conncept* (Caddy layer 4 app: TCP working, UDP needs testing)
- [ ] Add support for captcha actions
- [ ] Implement support for custom actions (currently defaults to block)
- [ ] Integrate with Caddy metrics
- [ ] Integrate with Caddy profiling
- [ ] Implement caching for the LiveBouncer

...and more things to come!

### Contributing

We are always open to contributions! Whether it's fixing bugs, improving documentation, or adding new features from the Roadmap above, your help is welcome. Feel free to open an issue or submit a pull request.

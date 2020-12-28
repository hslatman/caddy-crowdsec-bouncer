# CrowdSec Bouncer for Caddy

A Caddy app and http handler that blocks malicious traffic based on decisions made by [CrowdSec](https://crowdsec.net/).

## Description

## Usage

## TODO

* Add log integration from Caddy to CrowdSec (i.e. using Nginx log format)
* Add tests
* Do testing with IPv6
* Extend the Docker example with a more complete setup
* Add captcha action (currently works the same as a ban)
* Add support for custom actions (defaults to blocking access now)
* Improve logic for IPv4 vs. IPv6 handling (some custom wrapper, perhaps?)
* Test (and improve?) handling of IPv6 parsing/masking logic
* ...
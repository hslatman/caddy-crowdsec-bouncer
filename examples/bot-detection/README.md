# Bot detection example

Runs Caddy with the AppSec handler in front of a CrowdSec v1.8 AppSec component with [bot detection](https://docs.crowdsec.net/docs/next/appsec/bot_detection/intro/) enabled.
Caddy is built from the checked out source.

## Usage

```bash
docker compose up -d --build
```

Wait until CrowdSec is ready (`docker compose logs -f crowdsec`, look for `Appsec Runner ready to process event`), then:

- open http://localhost:8080 in a browser: the challenge page is solved automatically and you end up at the upstream response
- `curl -i http://localhost:8080` returns the challenge page
- `curl -i http://localhost:8080/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php` is blocked by virtual patching with a 403
- `docker compose exec crowdsec cscli metrics show bot-detection` shows the challenge funnel

The API key is fixed for the example only; generate one with `cscli bouncers add` for any real deployment.

ARG CADDY_VERSION=2

FROM caddy:${CADDY_VERSION}-builder-alpine AS builder

# build from the checked out source, so the example runs the code under development
COPY . /src
RUN xcaddy build \
  --with github.com/hslatman/caddy-crowdsec-bouncer=/src

FROM caddy:${CADDY_VERSION}

COPY --from=builder /usr/bin/caddy /usr/bin/caddy

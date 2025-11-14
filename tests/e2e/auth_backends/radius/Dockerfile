FROM alpine:3.19

LABEL org.opencontainers.image.title="freeradius-e2e" \
      org.opencontainers.image.description="Minimal FreeRADIUS for tacacs e2e tests with bootstrap users" \
      org.opencontainers.image.licenses="MIT"

RUN apk add --no-cache freeradius freeradius-utils bash

# Copy bootstrap and entrypoint
COPY bootstrap /bootstrap
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 1812/udp 1813/udp
CMD ["/entrypoint.sh"]


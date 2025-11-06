FROM alpine:latest

RUN apk add --no-cache haproxy socat bash ca-certificates

COPY haproxy.cfg /etc/haproxy/haproxy.cfg
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 5049 1812/udp

ENTRYPOINT ["/entrypoint.sh"]


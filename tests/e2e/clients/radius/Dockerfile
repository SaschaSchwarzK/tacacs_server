FROM alpine:latest

RUN apk add --no-cache freeradius-client bash ca-certificates

WORKDIR /app
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]


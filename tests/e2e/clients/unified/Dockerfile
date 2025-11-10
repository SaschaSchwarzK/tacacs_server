FROM python:3.13-alpine

RUN apk add --no-cache freeradius-client bash ca-certificates

WORKDIR /app
COPY tacacs_client.py /app/tacacs_client.py
COPY client.py /app/client.py
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]


FROM alpine:latest

LABEL org.opencontainers.image.title="tiny-openldap" \
      org.opencontainers.image.description="Minimal OpenLDAP for tacacs e2e tests with bootstrap support" \
      org.opencontainers.image.source="https://example.local/repo" \
      org.opencontainers.image.licenses="MIT"

# Install OpenLDAP server & tools + openssl for TLS certs
RUN apk add --no-cache openldap openldap-back-mdb openldap-clients openssl

# Create dirs
RUN mkdir -p /etc/openldap/slapd.d /var/lib/openldap/openldap-data /docker-entrypoint-initldif.d \
 && chown -R ldap:ldap /etc/openldap/slapd.d /var/lib/openldap

# Environment defaults (overridable at runtime)
ENV LDAP_DOMAIN=example.org \
    LDAP_ORGANIZATION="Example Inc." \
    LDAP_ADMIN_PASSWORD=admin \
    LDAP_BASE_DN= \
    LDAP_TLS_ENABLE=true

# Generate a built-in self-signed TLS cert (CN=localhost)
# Users may still mount their own at /tls to override.
RUN mkdir -p /tls \
 && openssl req -x509 -newkey rsa:2048 -nodes \
      -keyout /tls/key.pem -out /tls/cert.pem \
      -days 3650 -subj "/CN=localhost" \
 && cp /tls/cert.pem /tls/ca.pem \
 && chown -R ldap:ldap /tls \
 && chmod 600 /tls/key.pem && chmod 644 /tls/cert.pem /tls/ca.pem

# Entry script: builds cn=config + DB if empty, then runs slapd
ADD entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 389 636
USER ldap
CMD ["/entrypoint.sh"]

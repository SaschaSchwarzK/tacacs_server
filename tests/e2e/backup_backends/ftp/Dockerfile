FROM alpine:latest

LABEL org.opencontainers.image.title="tiny-ftp-sftp" \
      org.opencontainers.image.description="Minimal FTP + SFTP for e2e tests with user and key bootstrap" \
      org.opencontainers.image.licenses="MIT"

# Install vsftpd and openssh
RUN apk add --no-cache vsftpd openssh openssh-keygen bash

# Create runtime dirs
RUN mkdir -p /etc/vsftpd /var/run/vsftpd /data/ftp /export /tmp/uploads \
    && addgroup -S ftpusers || true

# Defaults (overridable)
ENV FTP_USER=testuser \
    FTP_PASS=password \
    FTP_PASV_ENABLE=YES \
    FTP_PASV_MIN_PORT=30000 \
    FTP_PASV_MAX_PORT=30009 \
    FTP_PASV_ADDRESS= \
    SFTP_USER=testuser \
    SFTP_PASS=password \
    SFTP_KEY_BITS=2048 \
    EXPORT_DIR=/export \
    FTP_WATCHDOG=1

# SSH server basic setup (robust edits that won't fail if keys are missing)
RUN set -eux; \
  sed -i -E 's|^#?PasswordAuthentication .*|PasswordAuthentication yes|' /etc/ssh/sshd_config || true; \
  sed -i -E 's|^#?ChallengeResponseAuthentication .*|ChallengeResponseAuthentication no|' /etc/ssh/sshd_config || true; \
  sed -i -E '/^#?UsePAM/d' /etc/ssh/sshd_config || true; \
  if grep -Eq '^#?Subsystem[[:space:]]+sftp' /etc/ssh/sshd_config; then \
    sed -i -E 's|^#?Subsystem[[:space:]]+sftp.*|Subsystem sftp /usr/lib/ssh/sftp-server|' /etc/ssh/sshd_config; \
  else \
    echo 'Subsystem sftp /usr/lib/ssh/sftp-server' >> /etc/ssh/sshd_config; \
  fi; \
  if grep -Eq '^#?PubkeyAuthentication ' /etc/ssh/sshd_config; then \
    sed -i -E 's|^#?PubkeyAuthentication .*|PubkeyAuthentication yes|' /etc/ssh/sshd_config; \
  else \
    echo 'PubkeyAuthentication yes' >> /etc/ssh/sshd_config; \
  fi; \
  # Remove any existing AuthorizedKeysFile directives and set exactly one
  sed -i -E '/^#?AuthorizedKeysFile /d' /etc/ssh/sshd_config || true; \
  echo 'AuthorizedKeysFile %h/.ssh/authorized_keys' >> /etc/ssh/sshd_config; \
  if grep -Eq '^#?StrictModes ' /etc/ssh/sshd_config; then \
    sed -i -E 's|^#?StrictModes .*|StrictModes yes|' /etc/ssh/sshd_config; \
  else \
    echo 'StrictModes yes' >> /etc/ssh/sshd_config; \
  fi; \
  if grep -Eq '^#?KbdInteractiveAuthentication ' /etc/ssh/sshd_config; then \
    sed -i -E 's|^#?KbdInteractiveAuthentication .*|KbdInteractiveAuthentication no|' /etc/ssh/sshd_config; \
  else \
    echo 'KbdInteractiveAuthentication no' >> /etc/ssh/sshd_config; \
  fi; \
  # Highest verbosity to understand pubkey decisions
  sed -i -E '/^#?LogLevel /d' /etc/ssh/sshd_config || true; \
  echo 'LogLevel DEBUG3' >> /etc/ssh/sshd_config; \
  # Ensure ed25519 is allowed explicitly (paranoid environments)
  grep -q '^PubkeyAcceptedAlgorithms' /etc/ssh/sshd_config || echo 'PubkeyAcceptedAlgorithms +ssh-ed25519' >> /etc/ssh/sshd_config; \
  grep -q '^HostKeyAlgorithms' /etc/ssh/sshd_config || echo 'HostKeyAlgorithms +ssh-ed25519' >> /etc/ssh/sshd_config; \
  mkdir -p /var/run/sshd

# Accept RSA test keys for pubkey auth (compat with ssh-rsa test keys)
RUN echo 'PubkeyAcceptedAlgorithms +ssh-rsa' >> /etc/ssh/sshd_config \
 && echo 'PubkeyAcceptedKeyTypes +ssh-rsa' >> /etc/ssh/sshd_config \
 && echo 'HostKeyAlgorithms +ssh-rsa' >> /etc/ssh/sshd_config

# Add entrypoint
ADD entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 21 22 30000-30009
CMD ["/entrypoint.sh"]

#!/usr/bin/env bash
set -euo pipefail
umask 022

EXPORT_DIR=${EXPORT_DIR:-/export}
FTP_USER=${FTP_USER:-testuser}
FTP_PASS=${FTP_PASS:-password}
SFTP_USER=${SFTP_USER:-$FTP_USER}
SFTP_PASS=${SFTP_PASS:-$FTP_PASS}
# Key settings: use ed25519 by default; legacy RSA still works if pre-existing
SFTP_KEY_TYPE=${SFTP_KEY_TYPE:-ed25519}
SFTP_KEY_BITS=${SFTP_KEY_BITS:-2048}

FTP_HOME_BASE=/data/ftp
FTP_USER_HOME="$FTP_HOME_BASE/$FTP_USER"
SFTP_USER_HOME="/home/$SFTP_USER"

mkdir -p "$EXPORT_DIR" "$FTP_HOME_BASE" "$FTP_USER_HOME" "$SFTP_USER_HOME/.ssh" /var/run/vsftpd /var/run/sshd /tmp/uploads /var/log
chmod 700 "$SFTP_USER_HOME/.ssh"

# Create or update users
if ! id -u "$FTP_USER" >/dev/null 2>&1; then
  adduser -D -h "$FTP_USER_HOME" -G ftpusers "$FTP_USER"
fi
echo "$FTP_USER:$FTP_PASS" | chpasswd
chown -R "$FTP_USER":ftpusers "$FTP_USER_HOME"

# Ensure dedicated group for SFTP user exists
if ! getent group "$SFTP_USER" >/dev/null 2>&1; then
  addgroup -S "$SFTP_USER" || true
fi
if ! id -u "$SFTP_USER" >/dev/null 2>&1; then
  adduser -D -h "$SFTP_USER_HOME" -G "$SFTP_USER" "$SFTP_USER"
fi
echo "$SFTP_USER:$SFTP_PASS" | chpasswd
chown -R "$SFTP_USER":"$SFTP_USER" "$SFTP_USER_HOME"
chmod 700 "$SFTP_USER_HOME"

# Ensure parent home directory ownership/perms are secure and predictable for sshd checks
chown root:root /home || true
chmod 755 /home || true

# Generate user SSH keypair for SFTP login and export it for tests
# Prefer ed25519; also support legacy RSA. Install all available pubkeys into authorized_keys.
USER_KEY_ED25519="$EXPORT_DIR/${SFTP_USER}_id_ed25519"
USER_KEY_RSA="$EXPORT_DIR/${SFTP_USER}_id_rsa"
AUTH_KEYS_DIR="/var/lib/ssh-authorized/$SFTP_USER"
AUTH_KEYS_ALT="$AUTH_KEYS_DIR/authorized_keys"

if [[ "$SFTP_KEY_TYPE" == "ed25519" ]]; then
  [[ -f "$USER_KEY_ED25519" && -f "$USER_KEY_ED25519.pub" ]] || \
    ssh-keygen -t ed25519 -N '' -f "$USER_KEY_ED25519" -C "$SFTP_USER@test"
else
  [[ -f "$USER_KEY_RSA" && -f "$USER_KEY_RSA.pub" ]] || \
    ssh-keygen -t rsa -b "$SFTP_KEY_BITS" -N '' -f "$USER_KEY_RSA" -C "$SFTP_USER@test"
fi

# Build authorized_keys using a single selected pubkey (ed25519 preferred), to avoid mismatches
AUTH_KEYS="$SFTP_USER_HOME/.ssh/authorized_keys"
# Prepare a container-local authorized_keys location to avoid host bind-mount permission quirks
mkdir -p "$AUTH_KEYS_DIR"
chown "$SFTP_USER":"$SFTP_USER" "$AUTH_KEYS_DIR"
chmod 700 "$AUTH_KEYS_DIR"
SELECTED_PUB=""
if [[ -f "$USER_KEY_ED25519.pub" ]]; then
  SELECTED_PUB="$USER_KEY_ED25519.pub"
elif [[ -f "$USER_KEY_RSA.pub" ]]; then
  SELECTED_PUB="$USER_KEY_RSA.pub"
fi

if [[ -n "$SELECTED_PUB" ]]; then
  cat "$SELECTED_PUB" > "$AUTH_KEYS"
  chmod 600 "$AUTH_KEYS"
  chown "$SFTP_USER":"$SFTP_USER" "$AUTH_KEYS"
  # Also install a copy into container-local path to bypass potential bind-mount semantics
  cat "$SELECTED_PUB" > "$AUTH_KEYS_ALT"
  chmod 600 "$AUTH_KEYS_ALT"
  chown "$SFTP_USER":"$SFTP_USER" "$AUTH_KEYS_ALT"
  echo "[sshd] Installed authorized_keys from: $SELECTED_PUB" >&2
  ssh-keygen -lf "$SELECTED_PUB" >&2 || true
fi
chmod 600 "$SFTP_USER_HOME/.ssh/authorized_keys"
chown -R "$SFTP_USER":"$SFTP_USER" "$SFTP_USER_HOME/.ssh"

# Flush metadata/content to disk before starting sshd (avoid races)
sync || true

# Log effective permissions to help diagnose pubkey issues
echo "[sshd] Home perms:" >&2
ls -ld "$SFTP_USER_HOME" >&2 || true
echo "[sshd] .ssh perms:" >&2
ls -ld "$SFTP_USER_HOME/.ssh" >&2 || true
echo "[sshd] authorized_keys perms:" >&2
ls -l "$SFTP_USER_HOME/.ssh/authorized_keys" >&2 || true

# Ensure server host keys exist (explicitly generate RSA/ed25519 so tests
# can read them from /etc/ssh).
ssh-keygen -A
if [[ ! -f /etc/ssh/ssh_host_rsa_key ]]; then
  ssh-keygen -t rsa -b "${SFTP_KEY_BITS:-2048}" -N '' -f /etc/ssh/ssh_host_rsa_key
fi
if [[ ! -f /etc/ssh/ssh_host_ed25519_key ]]; then
  ssh-keygen -t ed25519 -N '' -f /etc/ssh/ssh_host_ed25519_key
fi

# Configure vsftpd
PASV_ENABLE=${FTP_PASV_ENABLE:-YES}
PASV_MIN=${FTP_PASV_MIN_PORT:-30000}
PASV_MAX=${FTP_PASV_MAX_PORT:-30009}
PASV_ADDRESS=${FTP_PASV_ADDRESS:-}

# Ensure log file exists and writable by vsftpd (runs as root by default)
touch /var/log/vsftpd.log
chmod 644 /var/log/vsftpd.log

cat > /etc/vsftpd/vsftpd.conf <<EOF
listen=YES
listen_ipv6=NO
anonymous_enable=NO
local_enable=YES
write_enable=YES
chroot_local_user=YES
allow_writeable_chroot=YES
local_umask=022
dirmessage_enable=YES
use_localtime=YES
xferlog_enable=YES
log_ftp_protocol=YES
# Send transfer logs to docker stdout for visibility
xferlog_file=/dev/stdout
xferlog_std_format=NO
dual_log_enable=NO
seccomp_sandbox=NO
connect_from_port_20=YES

# Passive mode
pasv_enable=$PASV_ENABLE
pasv_min_port=$PASV_MIN
pasv_max_port=$PASV_MAX
EOF

if [[ -n "$PASV_ADDRESS" ]]; then
  echo "pasv_address=$PASV_ADDRESS" >> /etc/vsftpd/vsftpd.conf
fi

# Point user to a writeable upload area inside home
mkdir -p "$FTP_USER_HOME/upload"
chown "$FTP_USER":ftpusers "$FTP_USER_HOME/upload"

# Validate sshd config and start it in background, sending logs to stderr (Docker logs)
/usr/sbin/sshd -t || { echo "sshd config test failed" >&2; cat /etc/ssh/sshd_config >&2; exit 1; }
# Normalize key-related sshd settings to avoid earlier conflicting lines
sed -i -E '/^[#[:space:]]*AuthorizedKeysFile[[:space:]]/d' /etc/ssh/sshd_config || true
echo 'AuthorizedKeysFile %h/.ssh/authorized_keys /var/lib/ssh-authorized/%u/authorized_keys' >> /etc/ssh/sshd_config
sed -i -E '/^[#[:space:]]*PubkeyAuthentication[[:space:]]/d' /etc/ssh/sshd_config || true
echo 'PubkeyAuthentication yes' >> /etc/ssh/sshd_config
sed -i -E '/^[#[:space:]]*StrictModes[[:space:]]/d' /etc/ssh/sshd_config || true
echo 'StrictModes no' >> /etc/ssh/sshd_config
# Ensure modern and legacy pubkey algorithms are accepted for tests
sed -i -E '/^[#[:space:]]*PubkeyAcceptedAlgorithms[[:space:]]/d' /etc/ssh/sshd_config || true
echo 'PubkeyAcceptedAlgorithms +rsa-sha2-512,rsa-sha2-256,ssh-ed25519,ssh-rsa' >> /etc/ssh/sshd_config
# Widen server host key algorithms to avoid negotiation issues in CI
sed -i -E '/^[#[:space:]]*HostKeyAlgorithms[[:space:]]/d' /etc/ssh/sshd_config || true
echo 'HostKeyAlgorithms +ssh-ed25519,ecdsa-sha2-nistp256,rsa-sha2-512,rsa-sha2-256,ssh-rsa' >> /etc/ssh/sshd_config

echo "[sshd] Effective Key Settings:" >&2
grep -nE 'AuthorizedKeysFile|PubkeyAuthentication|LogLevel|StrictModes|PubkeyAcceptedAlgorithms|HostKeyAlgorithms' /etc/ssh/sshd_config >&2 || true
echo "[sshd] sshd -T (subset):" >&2
sshd -T 2>/dev/null | grep -E 'authorizedkeysfile|pubkeyauthentication|loglevel|strictmodes|hostkeyalgorithms|pubkeyacceptedalgorithms' >&2 || true
# Restart any existing sshd (if any), then start fresh
pkill sshd 2>/dev/null || true
sleep 1
/usr/sbin/sshd -D -E /dev/stderr &

# Optionally keep container alive and restart vsftpd if it exits
WATCHDOG=${FTP_WATCHDOG:-1}
if [[ "$WATCHDOG" == "1" ]]; then
  echo "Starting vsftpd with watchdog (auto-restart on exit)"
  while true; do
    /usr/sbin/vsftpd /etc/vsftpd/vsftpd.conf || true
    echo "vsftpd exited with code $?; restarting in 1s" >&2
    sleep 1
  done
else
  exec /usr/sbin/vsftpd /etc/vsftpd/vsftpd.conf
fi

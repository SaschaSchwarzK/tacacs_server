#!/bin/sh
set -e

CONFIG_DIR=/etc/openldap/slapd.d
DATA_DIR=/var/lib/openldap/openldap-data
INIT_DIR=/docker-entrypoint-initldif.d
BOOTSTRAP_DIR=${LDAP_BOOTSTRAP_DIR:-/bootstrap}

LDAP_DOMAIN="${LDAP_DOMAIN:-example.org}"
LDAP_ORGANIZATION="${LDAP_ORGANIZATION:-Example Inc.}"
LDAP_ADMIN_PASSWORD="${LDAP_ADMIN_PASSWORD:-admin}"

# Derive BASE DN if not provided
if [ -z "$LDAP_BASE_DN" ]; then
  LDAP_BASE_DN="dc=$(echo "$LDAP_DOMAIN" | sed 's/\./,dc=/g')"
fi

# Optional TLS
TLS_ENABLED=0
if [ "$LDAP_TLS_ENABLE" = "true" ]; then
  [ -f /tls/cert.pem ] && [ -f /tls/key.pem ] && TLS_ENABLED=1 || \
    echo "TLS requested but /tls/cert.pem or /tls/key.pem missing; continuing without TLS."
fi

# 1) Initialize cn=config (once)
if [ ! -d "$CONFIG_DIR/cn=config" ]; then
  echo "Initializing cn=config…"

  mkdir -p "$CONFIG_DIR" "$DATA_DIR"
  chown -R ldap:ldap "$CONFIG_DIR" "$DATA_DIR"

  HASHED_PW="$(slappasswd -s "$LDAP_ADMIN_PASSWORD")"

  # Global config
  cat > /tmp/00-config.ldif <<'EOF'
dn: cn=config
objectClass: olcGlobal
cn: config
olcArgsFile: /var/run/openldap/slapd.args
olcPidFile: /var/run/openldap/slapd.pid
olcToolThreads: 1
EOF

  # Load back_mdb module (required for MDB database)
  cat > /tmp/01-modules.ldif <<'EOF'
dn: cn=module{0},cn=config
objectClass: olcModuleList
cn: module{0}
olcModuleLoad: back_mdb
EOF

  # Apply global + module
  slapadd -F "$CONFIG_DIR" -n 0 -l /tmp/00-config.ldif
  slapadd -F "$CONFIG_DIR" -n 0 -l /tmp/01-modules.ldif

  # Load core schemas shipped by Alpine (already in LDIF form)
  slapadd -F "$CONFIG_DIR" -n 0 -l /etc/openldap/schema/core.ldif
  slapadd -F "$CONFIG_DIR" -n 0 -l /etc/openldap/schema/cosine.ldif
  slapadd -F "$CONFIG_DIR" -n 0 -l /etc/openldap/schema/inetorgperson.ldif

  # Database (MDB) definition
  cat > /tmp/10-mdb.ldif <<EOF
dn: olcDatabase=mdb,cn=config
objectClass: olcDatabaseConfig
objectClass: olcMdbConfig
olcDatabase: mdb
olcSuffix: $LDAP_BASE_DN
olcRootDN: cn=admin,$LDAP_BASE_DN
olcRootPW: $HASHED_PW
olcDbDirectory: $DATA_DIR
olcDbIndex: objectClass eq
olcDbIndex: uid,cn,mail,sn,givenName eq,pres,sub
olcAccess: {0}to attrs=userPassword by dn.exact="cn=admin,$LDAP_BASE_DN" write by anonymous auth by self write by * none
olcAccess: {1}to * by dn.exact="cn=admin,$LDAP_BASE_DN" write by * read
EOF
  slapadd -F "$CONFIG_DIR" -n 0 -l /tmp/10-mdb.ldif

  # Optional TLS on cn=config
  if [ "$TLS_ENABLED" -eq 1 ]; then
    cat > /tmp/20-tls.ldif <<'EOF'
dn: cn=config
changetype: modify
add: olcTLSCertificateFile
olcTLSCertificateFile: /tls/cert.pem
-
add: olcTLSCertificateKeyFile
olcTLSCertificateKeyFile: /tls/key.pem
EOF
    [ -f /tls/ca.pem ] && cat >> /tmp/20-tls.ldif <<'EOF'
-
add: olcTLSCACertificateFile
olcTLSCACertificateFile: /tls/ca.pem
EOF
    slapadd -F "$CONFIG_DIR" -n 0 -l /tmp/20-tls.ldif
  fi

  chown -R ldap:ldap "$CONFIG_DIR"
fi

# 2) Seed directory data only if DB is empty
if [ -z "$(ls -A "$DATA_DIR" 2>/dev/null)" ]; then
  echo "Seeding base directory…"

  cat > /tmp/base.ldif <<EOF
dn: $LDAP_BASE_DN
objectClass: top
objectClass: dcObject
objectClass: organization
o: $LDAP_ORGANIZATION
dc: $(echo "$LDAP_DOMAIN" | cut -d. -f1)

dn: cn=admin,$LDAP_BASE_DN
objectClass: simpleSecurityObject
objectClass: organizationalRole
cn: admin
description: Directory Manager
userPassword: $(slappasswd -s "$LDAP_ADMIN_PASSWORD")

dn: ou=people,$LDAP_BASE_DN
objectClass: organizationalUnit
ou: people

dn: ou=groups,$LDAP_BASE_DN
objectClass: organizationalUnit
ou: groups
EOF

  # Apply any user-provided LDIFs first
  for f in "$INIT_DIR"/*.ldif; do
    [ -f "$f" ] || continue
    echo "Applying $f"
    slapadd -F "$CONFIG_DIR" -b "$LDAP_BASE_DN" -l "$f"
  done

  # Now apply base
  slapadd -F "$CONFIG_DIR" -b "$LDAP_BASE_DN" -l /tmp/base.ldif
  chown -R ldap:ldap "$DATA_DIR"

  # 2b) Optional bootstrap of groups/users from simple CSV files
  # Supported files under $BOOTSTRAP_DIR:
  #  - groups.csv: "cn,description" (description optional)
  #  - users.csv:  "uid,password,cn,sn,groups" where groups is a '|' separated list of group CNs
  # If not present, create a small default dataset for testing.

  GEN_DIR=/tmp/bootstrap
  mkdir -p "$GEN_DIR"

  USERS_CSV="$BOOTSTRAP_DIR/users.csv"
  GROUPS_CSV="$BOOTSTRAP_DIR/groups.csv"

  if [ ! -f "$USERS_CSV" ] && [ ! -f "$GROUPS_CSV" ]; then
    echo "No bootstrap CSV provided; creating default LDAP test data."
    mkdir -p "$BOOTSTRAP_DIR"
    cat > "$GEN_DIR/groups.csv" <<'EOF'
admin-A,Administrators for customer A
operator-A,Operators for customer A
admin-B,Administrators for customer B
operator-B,Operators for customer B
EOF
    cat > "$GEN_DIR/users.csv" <<'EOF'
adminA,password,Admin A,Admin,admin-A
operatorA,password,Operator A,Operator,operator-A
adminB,password,Admin B,Admin,admin-B
operatorB,password,Operator B,Operator,operator-B
EOF
    GROUPS_CSV="$GEN_DIR/groups.csv"
    USERS_CSV="$GEN_DIR/users.csv"
  fi

  # Generate LDIF for users
  if [ -f "$USERS_CSV" ]; then
    echo "Generating users from $USERS_CSV"
    USERS_LDIF="$GEN_DIR/20-users.ldif"
    : > "$USERS_LDIF"
    # Also accumulate group memberships for later group creation
    MEMBERS_TMP="$GEN_DIR/members.map"
    : > "$MEMBERS_TMP"
    while IFS=',' read -r uid upw ucn usn ugroups || [ -n "$uid" ]; do
      # skip empty or commented lines
      [ -z "$uid" ] && continue
      case "$uid" in \#*) continue;; esac
      DN="uid=$uid,ou=people,$LDAP_BASE_DN"
      HASH="$(slappasswd -s "$upw")"
      cat >> "$USERS_LDIF" <<EOF
dn: $DN
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: inetOrgPerson
uid: $uid
cn: ${ucn:-$uid}
sn: ${usn:-$uid}
userPassword: $HASH

EOF
      # Record memberships (groups separated by '|')
      if [ -n "$ugroups" ]; then
        echo "$ugroups" | tr '|' '\n' | while read -r g; do
          [ -z "$g" ] && continue
          echo "$g|$DN" >> "$MEMBERS_TMP"
        done
      fi
    done < "$USERS_CSV"
    slapadd -F "$CONFIG_DIR" -b "$LDAP_BASE_DN" -l "$USERS_LDIF"
  fi

  # Generate LDIF for groups (use provided list, and attach members discovered from users.csv)
  if [ -f "$GROUPS_CSV" ] || [ -f "$MEMBERS_TMP" ]; then
    echo "Generating groups"
    GROUPS_LDIF="$GEN_DIR/30-groups.ldif"
    : > "$GROUPS_LDIF"
    # Build a list of unique group CNs, with optional description
    GROUP_LIST="$GEN_DIR/groups.list"
    : > "$GROUP_LIST"
    if [ -f "$GROUPS_CSV" ]; then
      awk -F',' 'NF>=1 && $1!~/^\s*#/ {print $1","$2}' "$GROUPS_CSV" >> "$GROUP_LIST" 2>/dev/null || true
    fi
    # Add any groups referenced by users.csv but not explicitly listed
    if [ -f "$MEMBERS_TMP" ]; then
      cut -d'|' -f1 "$MEMBERS_TMP" | sort -u | while read -r gc; do
        # only add if not already present exactly
        grep -q "^${gc}," "$GROUP_LIST" 2>/dev/null || echo "$gc," >> "$GROUP_LIST"
      done
    fi

    # For each group, emit LDIF as groupOfUniqueNames with members
    while IFS=',' read -r gcn gdesc || [ -n "$gcn" ]; do
      [ -z "$gcn" ] && continue
      case "$gcn" in \#*) continue;; esac
      GDN="cn=$gcn,ou=groups,$LDAP_BASE_DN"
      echo "dn: $GDN" >> "$GROUPS_LDIF"
      echo "objectClass: top" >> "$GROUPS_LDIF"
      echo "objectClass: groupOfUniqueNames" >> "$GROUPS_LDIF"
      echo "cn: $gcn" >> "$GROUPS_LDIF"
      [ -n "$gdesc" ] && echo "description: $gdesc" >> "$GROUPS_LDIF"
      # add members for this group
      if [ -f "$MEMBERS_TMP" ]; then
        awk -F'|' -v g="$gcn" '$1==g {print $2}' "$MEMBERS_TMP" | sort -u | while read -r mdn; do
          [ -z "$mdn" ] && continue
          echo "uniqueMember: $mdn" >> "$GROUPS_LDIF"
        done
      fi
      echo "" >> "$GROUPS_LDIF"
    done < "$GROUP_LIST"

    slapadd -F "$CONFIG_DIR" -b "$LDAP_BASE_DN" -l "$GROUPS_LDIF"
  fi
fi

# 3) Run slapd
if [ "$TLS_ENABLED" -eq 1 ]; then
  exec /usr/sbin/slapd -d 0 -h "ldap:/// ldaps:///" -F "$CONFIG_DIR"
else
  exec /usr/sbin/slapd -d 0 -h "ldap:///" -F "$CONFIG_DIR"
fi

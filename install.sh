#!/usr/bin/env bash
set -euo pipefail
umask 027

# =========================
# CONFIG (override via env)
# =========================
MYSQL_PWD="${MYSQL_PWD:-ChangeThisMySQLPwd!}"
GUAC_PWD="${GUAC_PWD:-ChangeThisGuacPwd!}"

INSTALLER_URL="https://raw.githubusercontent.com/Infopercept/secure-remote-access/refs/heads/master/secure-remote-install.sh"
WAR_URL="https://github.com/Infopercept/secure-remote-access/raw/refs/heads/master/guacamole-1.6.0.war"
GUAC_VER="1.6.0"

# Paths
GUAC_HOME="/etc/guacamole"
EXT_DIR="${GUAC_HOME}/extensions"
LIB_DIR="${GUAC_HOME}/lib"
GUAC_PROPERTIES="${GUAC_HOME}/guacamole.properties"
GUACD_CONF="${GUAC_HOME}/guacd.conf"
RECORD_DIR="/var/lib/guacamole/recordings"

TOMCAT_SVC="tomcat9"
TOMCAT_SERVER_XML="/etc/tomcat9/server.xml"     # May be a symlink on Debian/Ubuntu
TOMCAT_WEBAPPS="/var/lib/tomcat9/webapps"
WAR_DEST="${TOMCAT_WEBAPPS}/guacamole.war"

NGINX_SSL_DIR="/etc/nginx/ssl"
SITE_NAME="ztna"
SITE_AVAIL="/etc/nginx/sites-available/${SITE_NAME}.conf"
SITE_ENABLED="/etc/nginx/sites-enabled/${SITE_NAME}.conf"
CERT_KEY="${NGINX_SSL_DIR}/ztna.key"
CERT_CRT="${NGINX_SSL_DIR}/ztna.crt"

# Logging (console = brief; details -> file)
LOG="${LOG_FILE:-/var/log/ztna_install_$(date +%F_%H%M%S).log}"
mkdir -p "$(dirname "$LOG")"
touch "$LOG"; chmod 600 "$LOG"

say() { printf '%s\n' "$*"; }                            # brief console line
note() { printf '%s\n' "$*" >>"$LOG"; }                  # log only
run() {                                                  # run <desc> <command...> (fail-fast)
  local desc="$1"; shift
  say "• $desc"
  note ""
  note "== $desc =="
  # shellcheck disable=SC2068
  bash -o errexit -o pipefail -c "$*" >>"$LOG" 2>&1
}

write_file() {  # write_file <path> <content>
  local path="$1"; shift
  local content="$*"
  say "• Write $path"
  printf '%s' "$content" > "$path"
  {
    printf '\n---- %s ----\n' "$path"
    printf '%s\n' "$content"
  } >>"$LOG"
}

finish() {
  say " Done. Full log: $LOG"
}
trap finish EXIT

# =========================
# Preflight
# =========================
[ "$(id -u)" -eq 0 ] || { say "Run as root (sudo)."; exit 1; }
export DEBIAN_FRONTEND=noninteractive

say "== ZTNA install (logged to $LOG) =="

run "Install prerequisites (nginx, tomcat9, acl, tools)" \
  "apt-get update -y && apt-get install -y curl wget tar nginx openssl acl xmlstarlet ${TOMCAT_SVC}"

TMPDIR="$(mktemp -d)"; trap 'rm -rf "${TMPDIR}"; finish' EXIT

# =========================
# 1) Base install via Infopercept script
# =========================
run "Fetch secure-remote installer" \
  "curl -fsSL '${INSTALLER_URL}' -o '${TMPDIR}/secure-remote-install.sh' && chmod +x '${TMPDIR}/secure-remote-install.sh'"

run "Run installer (non-interactive)" \
  "'${TMPDIR}/secure-remote-install.sh' --mysqlpwd '${MYSQL_PWD}' --guacpwd '${GUAC_PWD}' --nomfa --installmysql"

run "Ensure ZTNA_HOME layout" \
  "mkdir -p '${EXT_DIR}' '${LIB_DIR}'"

# =========================
# 2) Rebranded WAR
# =========================
run "Download rebranded WAR" \
  "curl -fL '${WAR_URL}' -o '${TMPDIR}/guacamole.war'"

run "Deploy WAR" \
  "install -m 0644 -o root -g tomcat '${TMPDIR}/guacamole.war' '${WAR_DEST}'"

# =========================
# 3) Nginx HTTPS reverse proxy (serve UI at '/')
# =========================
run "Disable default Nginx site if present" \
  "rm -f /etc/nginx/sites-enabled/default || true"

run "Generate self-signed TLS key/cert (if missing)" \
  "mkdir -p '${NGINX_SSL_DIR}'; \
   [ -f '${CERT_KEY}' ] && [ -f '${CERT_CRT}' ] || \
   openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout '${CERT_KEY}' -out '${CERT_CRT}' -subj '/C=IN/ST=NA/L=NA/O=Infopercept/CN=infopercept.local'; \
   chmod 600 '${CERT_KEY}'"

NGINX_CONF=$(cat <<'EOF'
map $http_connection $connection_upgrade { default upgrade; '' close; }

server {
    listen 443 ssl default_server;
    ssl_certificate     __CERT_CRT__;
    ssl_certificate_key __CERT_KEY__;
    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_ciphers         HIGH:!aNULL:!MD5;

    # Strip /guacamole so UI is at /
    rewrite ^/guacamole(/.*)?$ $1 break;

    location / {
        proxy_pass         http://127.0.0.1:8080/guacamole/;
        proxy_http_version 1.1;
        proxy_set_header   Host              $host;
        proxy_set_header   X-Real-IP         $remote_addr;
        proxy_set_header   X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header   X-Forwarded-Proto $scheme;
        proxy_set_header   Upgrade           $http_upgrade;
        proxy_set_header   Connection        $connection_upgrade;
        proxy_buffer_size       128k;
        proxy_buffers           4 256k;
        proxy_busy_buffers_size 256k;
        proxy_read_timeout      3600s;
        proxy_send_timeout      3600s;
    }
}

server {
    listen 80 default_server;
    return 301 https://$host$request_uri;
}
EOF
)
NGINX_CONF="${NGINX_CONF/__CERT_CRT__/${CERT_CRT}}"
NGINX_CONF="${NGINX_CONF/__CERT_KEY__/${CERT_KEY}}"
write_file "${SITE_AVAIL}" "${NGINX_CONF}"

run "Enable site and reload Nginx" \
  "ln -fs '${SITE_AVAIL}' '${SITE_ENABLED}'; nginx -t; systemctl reload nginx"

# =========================
# 4) Tomcat: 127.0.0.1 bind + RemoteIpValve (symlink-safe)
# =========================
if [ -f "${TOMCAT_SERVER_XML}" ]; then
  # Resolve real path to avoid in-place edits replacing a symlink
  TOMCAT_SERVER_XML_REAL="$(readlink -f "${TOMCAT_SERVER_XML}" || echo "${TOMCAT_SERVER_XML}")"

  run "Backup Tomcat server.xml" \
    "cp -a '${TOMCAT_SERVER_XML_REAL}' '${TOMCAT_SERVER_XML_REAL}.bak_$(date +%F_%T)'"

  run "Bind Tomcat 8080 to 127.0.0.1" \
    "xmlstarlet ed --inplace \
       -u '//Connector[@port=\"8080\"]/@address' -v '127.0.0.1' \
       '${TOMCAT_SERVER_XML_REAL}' || \
     xmlstarlet ed --inplace \
       -i '//Connector[@port=\"8080\"]' -t attr -n address -v '127.0.0.1' \
       '${TOMCAT_SERVER_XML_REAL}'"

  run "Insert RemoteIpValve if missing" \
    "grep -q 'org.apache.catalina.valves.RemoteIpValve' '${TOMCAT_SERVER_XML_REAL}' || \
     xmlstarlet ed --inplace \
       -s '//Host' -t elem -n Valve -v '' \
       -i '//Host/Valve[not(@className)]' -t attr -n className -v 'org.apache.catalina.valves.RemoteIpValve' \
       -i '//Host/Valve[@className=\"org.apache.catalina.valves.RemoteIpValve\"]' -t attr -n internalProxies -v '127.0.0.1|0:0:0:0:0:0:0:1' \
       -i '//Host/Valve[@className=\"org.apache.catalina.valves.RemoteIpValve\"]' -t attr -n remoteIpHeader -v 'x-forwarded-for' \
       -i '//Host/Valve[@className=\"org.apache.catalina.valves.RemoteIpValve\"]' -t attr -n proxiesHeader -v 'x-forwarded-by' \
       -i '//Host/Valve[@className=\"org.apache.catalina.valves.RemoteIpValve\"]' -t attr -n protocolHeader -v 'x-forwarded-proto' \
       '${TOMCAT_SERVER_XML_REAL}'"

  # Keep permissions sane (avoid surprises if real path differs)
  run "Ensure Tomcat conf ownership (best-effort)" \
    "chown -R daemon:tomcat /var/lib/tomcat9/conf || true; \
     chown daemon:tomcat '${TOMCAT_SERVER_XML_REAL}' 2>/dev/null || true"
fi

# =========================
# 5) History recording extension + property
# =========================
run "Install history recording extension ${GUAC_VER}" \
  "curl -fsSL 'https://archive.apache.org/dist/guacamole/${GUAC_VER}/binary/guacamole-history-recording-storage-${GUAC_VER}.tar.gz' -o '${TMPDIR}/history.tar.gz' && \
   tar -xzf '${TMPDIR}/history.tar.gz' -C '${TMPDIR}' && \
   cp -f '${TMPDIR}/guacamole-history-recording-storage-${GUAC_VER}/guacamole-history-recording-storage-${GUAC_VER}.jar' '${EXT_DIR}/'"

run "Set recording-search-path property" \
  "mkdir -p '${GUAC_HOME}'; touch '${GUAC_PROPERTIES}'; \
   cp -a '${GUAC_PROPERTIES}' '${GUAC_PROPERTIES}.bak_$(date +%F_%T)'; \
   if grep -Eq '^[[:space:]]*recording-search-path[[:space:]]*[:=]' '${GUAC_PROPERTIES}'; then \
     sed -i -E 's|^[[:space:]]*recording-search-path[[:space:]]*[:=].*|recording-search-path: ${RECORD_DIR}|' '${GUAC_PROPERTIES}'; \
   else \
     printf '\\nrecording-search-path: %s\\n' '${RECORD_DIR}' >> '${GUAC_PROPERTIES}'; \
   fi"

# =========================
# 5b) OIDC SSO extension
# =========================
run "Download OIDC SSO extension ${GUAC_VER}" \
  "curl -fsSL 'https://downloads.apache.org/guacamole/${GUAC_VER}/binary/guacamole-auth-sso-${GUAC_VER}.tar.gz' -o '${TMPDIR}/oidc.tar.gz' && \
   tar -xzf '${TMPDIR}/oidc.tar.gz' -C '${TMPDIR}'"

run "Install OIDC extension JAR" \
  "cp -f '${TMPDIR}/guacamole-auth-sso-${GUAC_VER}/openid/guacamole-auth-sso-openid-${GUAC_VER}.jar' '${EXT_DIR}/'"


# =========================
# 6) Make world-readable (dirs 755, files 644)
# =========================
run "Apply read-perms for ZTNA_HOME" \
  "chmod 755 '${GUAC_HOME}' '${EXT_DIR}' '${LIB_DIR}'; \
   chmod 644 '${GUAC_PROPERTIES}' '${GUACD_CONF}' 2>/dev/null || true; \
   chmod 644 '${EXT_DIR}'/*.jar 2>/dev/null || true; \
   chmod 644 '${LIB_DIR}'/*.jar 2>/dev/null || true; \
   chown -R root:root '${GUAC_HOME}' || true; \
   chown -R daemon:tomcat /var/lib/tomcat9/conf || true"

# =========================
# 7) Recording path perms (guacd writer + tomcat reader)
# =========================
GUACD_USER="$(systemctl show -p User guacd.service | cut -d= -f2 || true)"
[ -z "$GUACD_USER" ] && GUACD_USER="guacd"
say "• guacd user: $GUACD_USER"

run "Prepare parent dir (traversable)" \
  "mkdir -p /var/lib/guacamole '${RECORD_DIR}'; \
   chown '${GUACD_USER}:tomcat' /var/lib/guacamole; \
   chmod 2755 /var/lib/guacamole"

run "Own recordings dir by ${GUACD_USER}:tomcat; setgid; group-writable" \
  "chown -R '${GUACD_USER}:tomcat' '${RECORD_DIR}'; \
   chmod 2770 '${RECORD_DIR}'; \
   usermod -aG tomcat '${GUACD_USER}' 2>/dev/null || true"

UMASK_OVERRIDE=$(cat <<'EOF'
[Service]
UMask=007
EOF
)
run "Set guacd UMask=007 (systemd drop-in) & reload" \
  "mkdir -p /etc/systemd/system/guacd.service.d; \
   printf '%s' '${UMASK_OVERRIDE}' > /etc/systemd/system/guacd.service.d/override.conf; \
   systemctl daemon-reload"

run "Set default ACLs so children inherit rwx for guacd:tomcat" \
  "setfacl -Rm d:u:'${GUACD_USER}':rwx,d:g:tomcat:rwx,u:'${GUACD_USER}':rwx,g:tomcat:rwx '${RECORD_DIR}'"

run "Configure OIDC " \
  "if grep -q 'openid-issuer' '${GUAC_PROPERTIES}'; then
     note 'OIDC configuration already present — skipping add.'
   else
     printf '\\n## OIDC Configuration\\n' >> '${GUAC_PROPERTIES}'
     printf 'openid-issuer: http://172.17.14.3:8080/realms/any\\n' >> '${GUAC_PROPERTIES}'
     printf 'openid-authorization-endpoint: http://172.17.14.38:8080/realms/any/protocol/openid-connect/auth\\n' >> '${GUAC_PROPERTIES}'
     printf 'openid-jwks-endpoint: http://172.17.14.38:8080/realms/any/protocol/openid-connect/certs\\n' >> '${GUAC_PROPERTIES}'
     printf 'openid-redirect-uri: https://172.17.14.39/\\n' >> '${GUAC_PROPERTIES}'
     printf 'openid-client-id: ot-secure-access\\n' >> '${GUAC_PROPERTIES}'
     printf 'openid-client-secret: dgC8B6ByGkTmhOD2izzU8WvFpONhRo4j\\n' >> '${GUAC_PROPERTIES}'
     printf 'openid-username-claim-type: preferred_username\\n' >> '${GUAC_PROPERTIES}'
     printf 'openid-allow-unverified-users: true\\n' >> '${GUAC_PROPERTIES}'
     printf 'extension-priority: *, openid\\n' >> '${GUAC_PROPERTIES}'
   fi"

# =========================
# 7b) Replace vendor service with ot-secure.service
# =========================
OT_UNIT_PATH="/etc/systemd/system/ot-secure.service"
OT_UNIT_CONTENT=$(cat <<'EOF'

[Unit]
Description=Ztna Server
Documentation=man:guacd(8)
After=network.target

[Service]
User=daemon
# Keep recordings private to daemon:tomcat and inherited children
UMask=007
ExecStart=/usr/local/sbin/guacd -f
Restart=on-abnormal

[Install]
WantedBy=multi-user.target
EOF
)

write_file "${OT_UNIT_PATH}" "${OT_UNIT_CONTENT}"

run "Reload systemd units" \
  "systemctl daemon-reload"

# Stop/disable distro-provided unit if it exists
run "Stop & disable guacd.service (best-effort)" \
  "systemctl stop guacd.service 2>/dev/null || true; systemctl disable guacd.service 2>/dev/null || true"

# Enable/start our custom unit
run "Enable and start ot-secure.service" \
  "systemctl enable ot-secure.service && systemctl start ot-secure.service"


# =========================
# 8) Restart services
# =========================
run "Restart ot-secure (guacd) and Tomcat" \
  "systemctl restart ot-secure '${TOMCAT_SVC}'"

run "Reload Nginx" \
  "nginx -t && systemctl reload nginx"


say "======================================================="
say " ZTNA ready at: https://<server-ip>/"
say " Log file: ${LOG}"
say "======================================================="

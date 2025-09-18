#!/usr/bin/env bash
set -euo pipefail
umask 027

# =========================
# CONFIG - EDIT THESE
# =========================
MYSQL_PWD="ChangeThisMySQLPwd!"
GUAC_PWD="ChangeThisGuacPwd!"

# Sources
INSTALLER_URL="https://raw.githubusercontent.com/Infopercept/secure-remote-access/refs/heads/master/secure-remote-install.sh"
WAR_URL="https://github.com/Infopercept/secure-remote-access/raw/refs/heads/master/guacamole-1.6.0.war"

# Guacamole / Tomcat / Nginx
GUAC_VER="1.6.0"
EXT_DIR="/etc/guacamole/extensions"
GUAC_CONF_DIR="/etc/guacamole"
GUAC_PROPERTIES="${GUAC_CONF_DIR}/guacamole.properties"
RECORD_DIR="/var/lib/guacamole/recordings"

TOMCAT_SVC="tomcat9"
TOMCAT_SERVER_XML="/etc/tomcat9/server.xml"
TOMCAT_WEBAPPS="/var/lib/tomcat9/webapps"
WAR_DEST="${TOMCAT_WEBAPPS}/guacamole.war"

NGINX_SSL_DIR="/etc/nginx/ssl"
SITE_NAME="guacamole"
SITE_AVAIL="/etc/nginx/sites-available/${SITE_NAME}.conf"
SITE_ENABLED="/etc/nginx/sites-enabled/${SITE_NAME}.conf"
CERT_KEY="${NGINX_SSL_DIR}/ztna.key"
CERT_CRT="${NGINX_SSL_DIR}/ztna.crt"

# Ownership for extension JAR and recordings dir
JAR_OWNER_USER="daemon"
JAR_OWNER_GROUP="tomcat"

# =========================
# Preflight
# =========================
if [ "$(id -u)" -ne 0 ]; then
  echo "Please run as root (sudo)."; exit 1
fi

echo "[*] Installing prerequisites..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y curl wget tar nginx openssl ${TOMCAT_SVC}

# =========================
# 1) Run Infopercept installer (non-interactive)
# =========================
echo "[*] Fetching secure-remote installer..."
TMPDIR="$(mktemp -d)"
trap 'rm -rf "${TMPDIR}"' EXIT

curl -fsSL "${INSTALLER_URL}" -o "${TMPDIR}/secure-remote-install.sh"
chmod +x "${TMPDIR}/secure-remote-install.sh"

echo "[*] Running installer (this may take a few minutes)..."
"${TMPDIR}/secure-remote-install.sh" \
  --mysqlpwd "${MYSQL_PWD}" \
  --guacpwd "${GUAC_PWD}" \
  --nomfa \
  --installmysql

# =========================
# 2) Deploy rebranded WAR
# =========================
echo "[*] Downloading rebranded WAR..."
curl -fL "${WAR_URL}" -o "${TMPDIR}/guacamole.war"

echo "[*] Deploying WAR to ${WAR_DEST}..."
install -m 0644 -o root -g tomcat "${TMPDIR}/guacamole.war" "${WAR_DEST}"

echo "[*] Restarting guacd and Tomcat..."
systemctl restart guacd.service "${TOMCAT_SVC}.service"

# =========================
# 3) Nginx HTTPS reverse-proxy (pretty URL '/')
# =========================
echo "[*] Disabling default Nginx site (if present)..."
rm -f /etc/nginx/sites-enabled/default || true

echo "[*] Generating self-signed TLS key/cert (if missing)..."
mkdir -p "${NGINX_SSL_DIR}"
if [ ! -f "${CERT_KEY}" ] || [ ! -f "${CERT_CRT}" ]; then
  openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout "${CERT_KEY}" \
    -out "${CERT_CRT}" \
    -subj "/C=IN/ST=NA/L=NA/O=Infopercept/CN=infopercept.local"
  chmod 600 "${CERT_KEY}"
fi

echo "[*] Writing Nginx site ${SITE_AVAIL}..."
cat > "${SITE_AVAIL}" <<EOF
map \$http_connection \$connection_upgrade {
    default upgrade;
    ''      close;
}

server {
    listen 443 ssl default_server;

    ssl_certificate     ${CERT_CRT};
    ssl_certificate_key ${CERT_KEY};
    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_ciphers         HIGH:!aNULL:!MD5;

    # Optional: strip /guacamole so UI is served at /
    rewrite ^/guacamole(/.*)?\$ \$1 break;

    location / {
        proxy_pass         http://127.0.0.1:8080/guacamole/;
        proxy_http_version 1.1;

        proxy_set_header   Host              \$host;
        proxy_set_header   X-Real-IP         \$remote_addr;
        proxy_set_header   X-Forwarded-For   \$proxy_add_x_forwarded_for;
        proxy_set_header   X-Forwarded-Proto \$scheme;
        proxy_set_header   Upgrade           \$http_upgrade;
        proxy_set_header   Connection        \$connection_upgrade;

        proxy_buffer_size       128k;
        proxy_buffers           4 256k;
        proxy_busy_buffers_size 256k;
        proxy_read_timeout      3600s;
        proxy_send_timeout      3600s;
    }
}

server {
    listen 80 default_server;
    return 301 https://\$host\$request_uri;
}
EOF

echo "[*] Enabling site & reloading Nginx..."
ln -fs "${SITE_AVAIL}" "${SITE_ENABLED}"
nginx -t
systemctl reload nginx

# =========================
# 4) Lock Tomcat to 127.0.0.1 and insert RemoteIpValve
# =========================
if [ -f "${TOMCAT_SERVER_XML}" ]; then
  echo "[*] Locking Tomcat :8080 to 127.0.0.1..."
  cp -a "${TOMCAT_SERVER_XML}" "${TOMCAT_SERVER_XML}.bak_$(date +%F_%T)"
  if grep -q '<Connector port="8080" protocol="HTTP/1.1"' "${TOMCAT_SERVER_XML}" && \
     ! grep -q 'Connector.*port="8080".*address="127.0.0.1"' "${TOMCAT_SERVER_XML}"; then
    sed -i '/<Connector port="8080" protocol="HTTP\/1\.1"/ s#<Connector #<Connector address="127.0.0.1" #' "${TOMCAT_SERVER_XML}"
  fi

  if ! grep -q 'org.apache.catalina.valves.RemoteIpValve' "${TOMCAT_SERVER_XML}"; then
    echo "[*] Inserting RemoteIpValve..."
    cp -a "${TOMCAT_SERVER_XML}" "${TOMCAT_SERVER_XML}.bak_remoteip_$(date +%F_%T)"
    read -r -d '' VALVE_SNIPPET <<'VALVE'
        <!-- Honor X-Forwarded-* from Nginx -->
        <Valve className="org.apache.catalina.valves.RemoteIpValve"
               internalProxies="127\.0\.0\.1|0:0:0:0:0:0:0:1"
               remoteIpHeader="x-forwarded-for"
               remoteIpProxiesHeader="x-forwarded-by"
               protocolHeader="x-forwarded-proto" />
VALVE
    awk -v needle='<Host ' -v snippet="$VALVE_SNIPPET" '
      {
        print
        if ($0 ~ needle && !inserted) {
          inserted=1
          print snippet
        }
      }
    ' "${TOMCAT_SERVER_XML}" > "${TOMCAT_SERVER_XML}.new"
    mv "${TOMCAT_SERVER_XML}.new" "${TOMCAT_SERVER_XML}"
  fi
fi

echo "[*] Restarting Tomcat after connector/valve changes..."
systemctl restart "${TOMCAT_SVC}"

# =========================
# 5) Install history recording extension
# =========================
echo "[*] Installing Guacamole history recording storage extension v${GUAC_VER}..."
HIST_TGZ="${TMPDIR}/history.tar.gz"
curl -fsSL "https://archive.apache.org/dist/guacamole/${GUAC_VER}/binary/guacamole-history-recording-storage-${GUAC_VER}.tar.gz" -o "${HIST_TGZ}"
tar -xzf "${HIST_TGZ}" -C "${TMPDIR}"
mkdir -p "${EXT_DIR}"
cp -f "${TMPDIR}/guacamole-history-recording-storage-${GUAC_VER}/guacamole-history-recording-storage-${GUAC_VER}.jar" "${EXT_DIR}/"
chown "${JAR_OWNER_USER}:${JAR_OWNER_GROUP}" "${EXT_DIR}/"*.jar
chmod 644 "${EXT_DIR}/"*.jar

echo "[*] Ensuring recordings directory ${RECORD_DIR}..."
mkdir -p "${RECORD_DIR}"
chown -R "${JAR_OWNER_USER}:${JAR_OWNER_GROUP}" "${RECORD_DIR}"
chmod 2770 "${RECORD_DIR}"

echo "[*] Adding 'recording-search-path: ${RECORD_DIR}' to ${GUAC_PROPERTIES}..."
mkdir -p "${GUAC_CONF_DIR}"
touch "${GUAC_PROPERTIES}"
cp -a "${GUAC_PROPERTIES}" "${GUAC_PROPERTIES}.bak_$(date +%F_%T)"
if grep -Eq '^[[:space:]]*recording-search-path[[:space:]]*[:=]' "${GUAC_PROPERTIES}"; then
  sed -i -E "s|^[[:space:]]*recording-search-path[[:space:]]*[:=].*|recording-search-path: ${RECORD_DIR}|" "${GUAC_PROPERTIES}"
else
  printf "\nrecording-search-path: %s\n" "${RECORD_DIR}" >> "${GUAC_PROPERTIES}"
fi
chown root:${JAR_OWNER_GROUP} "${GUAC_PROPERTIES}" || true
chmod 640 "${GUAC_PROPERTIES}" || true

# =========================
# 6) Final restarts
# =========================
echo "[*] Restarting services (guacd, tomcat9, nginx)..."
systemctl restart guacd.service "${TOMCAT_SVC}.service"
nginx -t && systemctl reload nginx

echo
echo "======================================================="
echo "✔ Guacamole installed & rebranded, HTTPS reverse proxy on."
echo "  URL: https://<your-server-ip>/"
echo "  Cert: ${CERT_CRT}"
echo "  Tomcat: bound to 127.0.0.1:8080 with RemoteIpValve"
echo "  History JAR: ${EXT_DIR}"
echo "  Recordings:  ${RECORD_DIR}"
echo "  Property:    recording-search-path: ${RECORD_DIR}"
echo "  Backups:     ${TOMCAT_SERVER_XML}.bak_*, ${GUAC_PROPERTIES}.bak_*"
echo "======================================================="

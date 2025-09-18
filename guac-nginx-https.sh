#!/usr/bin/env bash
set -euo pipefail

# === 1. Install prerequisites ===
apt-get update
apt-get install -y nginx openssl

# === 2. Disable default Nginx site ===
if [ -e /etc/nginx/sites-enabled/default ]; then
  rm /etc/nginx/sites-enabled/default
fi

# === 3. Generate self-signed certificate ===
SSL_DIR="/etc/nginx/ssl"
mkdir -p "$SSL_DIR"
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout "$SSL_DIR/ztna.key" \
  -out "$SSL_DIR/ztna.crt" \
  -subj "/C=IN/ST=NA/L=NA/O=Infopercept/CN=infopercept.local"

# === 4. Deploy Nginx HTTPS reverse proxy config for ZTNA ===
cat > /etc/nginx/sites-available/guacamole.conf <<EOF
map \$http_connection \$connection_upgrade {
    default upgrade;
    ''      close;
}

server {
    listen 443 ssl default_server;
    ssl_certificate     $SSL_DIR/guac.crt;
    ssl_certificate_key $SSL_DIR/guac.key;

    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_ciphers         HIGH:!aNULL:!MD5;

    # Strip leading /guacamole
    rewrite ^/guacamole(/.*)?\$ \$1 break;

    location / {
        proxy_pass         http://127.0.0.1:8080/guacamole/;
        proxy_http_version 1.1;
        proxy_set_header   Host              \$host;
        proxy_set_header   X-Real-IP         \$remote_addr;
        proxy_set_header   X-Forwarded-For   \$proxy_add_x_forwarded_for;
        proxy_set_header   X-Forwarded-Proto \$scheme;
        proxy_set_header   Upgrade           \$http_upgrade;

        proxy_buffer_size       128k;
        proxy_buffers           4 256k;
        proxy_busy_buffers_size 256k;
    }
}

server {
    listen 80 default_server;
    return 301 https://\$host\$request_uri;
}
EOF



# === 5. Enable config and reload Nginx ===
ln -fs /etc/nginx/sites-available/ztna.conf /etc/nginx/sites-enabled/
nginx -t
systemctl reload nginx

# === 6. Lock Tomcat to localhost only ===
SERVER_XML=/etc/tomcat9/server.xml
if ! grep -q 'port="8080".*address="127.0.0.1"' "$SERVER_XML"; then
  cp "$SERVER_XML" "${SERVER_XML}.bak_$(date +%F_%T)"
  sed -i '/<Connector port="8080" protocol="HTTP\/1.1"/ s#<Connector #<Connector address="127.0.0.1" #' "$SERVER_XML"
fi

# === 7. Ensure RemoteIpValve is present inside the <Host> section (idempotent)
SERVER_XML=/etc/tomcat9/server.xml

if ! grep -q 'org.apache.catalina.valves.RemoteIpValve' "$SERVER_XML"; then
  cp "$SERVER_XML" "${SERVER_XML}.bak_remoteip_$(date +%F_%T)"

  read -r -d '' VALVE_SNIPPET <<'VALVE'
        <!-- Inserted to honor X-Forwarded-* from Nginx -->
        <Valve className="org.apache.catalina.valves.RemoteIpValve"
               internalProxies="127\.0\.0\.1|0:0:0:0:0:0:0:1"
               remoteIpHeader="x-forwarded-for"
               remoteIpProxiesHeader="x-forwarded-by"
               protocolHeader="x-forwarded-proto" />
VALVE

  awk -v needle='<Host name="localhost"' -v snippet="$VALVE_SNIPPET" '
    {
      print
    }
    $0 ~ needle && !host_seen {
      host_seen=1
      # Insert snippet on the next line after the <Host ...> tag
      print snippet
    }
  ' "$SERVER_XML" > "${SERVER_XML}.new"

  mv "${SERVER_XML}.new" "$SERVER_XML"
fi

# (Optional) Make AccessLogValve log the real remote IP quickly (use %a to avoid reverse DNS)
# Only touch the default AccessLogValve line if pattern looks default
#if grep -q 'className="org.apache.catalina.valves.AccessLogValve"' "$SERVER_XML"; then
#  cp "$SERVER_XML" "${SERVER_XML}.bak_accesslog_$(date +%F_%T)"
#  sed -i 's/pattern="%h %l %u %t &quot;%r&quot; %s %b"/pattern="%a %l %u %t &quot;%r&quot; %s %b"/' "$SERVER_XML"
#fi

# === 8. Restart Tomcat to apply changes ===
systemctl restart tomcat9

# === Done ===
echo
echo " ZTNA reverse-proxy is LIVE over HTTPS!"
echo "   • Access: https://<your-server-IP>/"
echo "   • Note: You'll see a browser warning due to self-signed cert."
echo "   • Tomcat is restricted to 127.0.0.1:8080"

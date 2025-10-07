#!/usr/bin/env bash
set -euo pipefail

# DANGER: This script PURGES packages and DELETES data directories.
# It will remove Guacamole, guacd, Tomcat (9/10), Nginx, MySQL/MariaDB,
# and all related configs/data. Run only if you accept total removal.

require_root() { [ "$(id -u)" -eq 0 ] || { echo "Run as root (sudo)."; exit 1; }; }
quiet_rm() { for p in "$@"; do [ -n "${p:-}" ] && rm -rf -- "$p" 2>/dev/null || true; done; }
quiet_purge() { apt-get purge -y "$@" 2>/dev/null || true; }

require_root
export DEBIAN_FRONTEND=noninteractive

echo "[*] Stopping services (ignore errors if not present)..."
for svc in guacd tomcat9 tomcat10 nginx mysql mariadb; do
  systemctl stop "${svc}.service" 2>/dev/null || true
  systemctl disable "${svc}.service" 2>/dev/null || true
done

echo "[*] Remove custom ot-secure.service (if present)..."
systemctl stop ot-secure.service 2>/dev/null || true
systemctl disable ot-secure.service 2>/dev/null || true
quiet_rm /etc/systemd/system/ot-secure.service \
         /etc/systemd/system/ot-secure.service.d
systemctl daemon-reload || true
systemctl reset-failed 2>/dev/null || true

echo "[*] Remove Nginx sites/config..."
quiet_rm /etc/nginx/sites-enabled/guacamole.conf \
         /etc/nginx/sites-enabled/ztna.conf \
         /etc/nginx/sites-available/guacamole.conf \
         /etc/nginx/sites-available/ztna.conf \
         /etc/nginx/ssl/ztna.key /etc/nginx/ssl/ztna.crt
# Try to reload nginx if still installed
nginx -t >/dev/null 2>&1 && systemctl reload nginx || true

echo "[*] Remove Tomcat webapps (guacamole war/dir)..."
quiet_rm /var/lib/tomcat9/webapps/guacamole.war \
         /var/lib/tomcat9/webapps/guacamole \
         /var/lib/tomcat10/webapps/guacamole.war \
         /var/lib/tomcat10/webapps/guacamole

echo "[*] Remove Ztna configs/libs/recordings..."
quiet_rm /etc/guacamole \
         /var/lib/guacamole/recordings

echo "[*] Remove guacd installed from source (binaries, libs, unit)..."
systemctl disable guacd.service 2>/dev/null || true
quiet_rm /etc/systemd/system/guacd.service
systemctl daemon-reload || true
quiet_rm /usr/local/sbin/guacd \
         /usr/local/lib/guacamole \
         /usr/local/lib/libguac*.so* \
         /usr/local/include/guacamole*.h \
         /usr/local/share/man/man8/guacd.8
ldconfig || true

echo "[*] Purge Ztna-related packages (if any via distro repos)..."
# (Usually guacamole-server was built from source; these are just safety nets)
quiet_purge guacamole guacamole-server guacamole-tomcat guacamole-common || true

echo "[*] Purge Tomcat and Nginx packages..."
quiet_purge tomcat9 tomcat9-common libtomcat9-java tomcat10 tomcat10-common libtomcat10-java
quiet_purge nginx nginx-core nginx-common libnginx-mod-http-geoip2 libnginx-mod-http-image-filter \
            libnginx-mod-http-xslt-filter libnginx-mod-mail libnginx-mod-stream libnginx-mod-stream-geoip2

echo "[*] Purge MySQL/MariaDB server/client packages..."
# Try MariaDB first, then MySQL (or both—purges will noop if absent)
quiet_purge mariadb-server mariadb-client mariadb-common libmariadb3 libmariadb-dev-compat
quiet_purge mysql-server mysql-server-core-8.0 mysql-client mysql-client-core-8.0 \
            mysql-common libmysqlclient* mysql-apt-config

echo "[*] Remove MySQL/MariaDB data/config/logs (irrevocable)..."
quiet_rm /var/lib/mysql /etc/mysql /var/log/mysql /var/run/mysqld

echo "[*] Remove leftover MySQL connectors (JDBC) if any..."
quiet_rm /etc/guacamole/lib/mysql-connector-*.jar /etc/guacamole/lib/mysql-connector-java.jar

echo "[*] Autoremove and clean..."
apt purge tomcat9 -y 2>/dev/null || true
apt purge mysql-* -y 2>/dev/null || true
apt-get autoremove -y 2>/dev/null || true
apt-get autoclean -y 2>/dev/null || true

rm -rf /var/lib/tomcat9

echo
echo "✔ TOTAL UNINSTALL complete."
echo "  - Ztna, guacd, Tomcat (9/10), Nginx removed"
echo "  - MySQL/MariaDB packages & data removed"
echo "  - Configs/WARs/sites wiped"

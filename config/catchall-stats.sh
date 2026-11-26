#!/bin/bash
# Rebuild the private visitor statistics pages from the nginx access logs.
OUT=/var/www/stats
GEO=/var/lib/catchall-stats/country.mmdb
COMMON=(--log-format=COMBINED --no-progress --no-query-string --exclude-ip=209.182.233.34
        --exclude-ip=142.11.231.215 --exclude-ip=127.0.0.1 --html-prefs='{"theme":"bright","perPage":20}'
        --ignore-panel=KEYPHRASES --ignore-panel=REMOTE_USER --ignore-panel=CACHE_STATUS)
[ -f "$GEO" ] && COMMON+=(--geoip-database="$GEO")
logs() { zcat -f /var/log/nginx/access.log* ; }
logs | goaccess - "${COMMON[@]}" --ignore-crawlers --html-report-title="catchall.mx visitors" -o $OUT/index.html.tmp.html 2>/dev/null && mv $OUT/index.html.tmp.html $OUT/index.html
logs | goaccess - "${COMMON[@]}" --crawlers-only --html-report-title="catchall.mx crawlers and bots" -o $OUT/bots.tmp.html 2>/dev/null && mv $OUT/bots.tmp.html $OUT/bots.html
chown -R www-data:www-data $OUT

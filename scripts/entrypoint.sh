#!/bin/bash
set -e

download_custom_schema() {
    if [ ! -z ${GLUU_CUSTOM_SCHEMA_URL} ]; then
        wget -q ${GLUU_CUSTOM_SCHEMA_URL} -O /ldap/custom_schema/custom-schema.tar.gz
        cd /ldap/custom_schema
        tar xf custom-schema.tar.gz
    fi
}

if [ ! -f /touched ]; then
    download_custom_schema
    python /ldap/scripts/entrypoint.py
    touch /touched
fi

# run slapd
exec /opt/symas/lib64/slapd \
    -d 256 \
    -u root \
    -g root \
    -h ldaps://0.0.0.0:1636/ \
    -f /opt/symas/etc/openldap/slapd.conf \
    -F /opt/symas/etc/openldap/slapd.d

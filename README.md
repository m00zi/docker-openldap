# OpenLDAP

A docker image version of OpenLDAP.

## Latest Stable Release

Latest stable release is `gluufederation/openldap:3.1.2_dev`. See `CHANGES.md` for archives.

## Versioning/Tagging

This image uses its own versioning/tagging format.

    <IMAGE-NAME>:<GLUU-SERVER-VERSION>_<INTERNAL-REV-VERSION>

For example, `gluufederation/openldap:3.1.2_dev` consists of:

- glufederation/openldap as `<IMAGE_NAME>`: the actual image name
- 3.1.2 as `GLUU-SERVER-VERSION`: the Gluu Server version as setup reference
- `_dev` as `<BASELINE_DEV>`: used until official production release

## Installation

Pull the image:

```
docker pull gluufederation/openldap:3.1.2_dev
```

## Environment Variables

- `GLUU_KV_HOST`: hostname or IP address of Consul.
- `GLUU_KV_PORT`: port of Consul.
- `GLUU_LDAP_INIT`: whether to import initial LDAP entries (possible value are `true` or `false`).
- `GLUU_LDAP_INIT_HOST`: hostname of LDAP for initial configuration (only usable when `GLUU_LDAP_INIT` set to `true`).
- `GLUU_LDAP_INIT_PORT`: port of LDAP for initial configuration (only usable when `GLUU_LDAP_INIT` set to `true`).
-`GLUU_CUSTOM_SCHEMA_URL`: URL to downloadable custom schema packed using `.tar.gz` format (note this feature is deprecated, instead bind a volume to `/ldap/custom_schema` directly)
- `GLUU_CACHE_TYPE`: supported values are 'IN_MEMORY' and 'REDIS', default is 'IN_MEMORY'.
- `GLUU_REDIS_URL`: URL of redis service, format is `redis_host:redis_port` (optional).
- `GLU_LDAP_ADDR_INTERFACE`: interface name where the IP will be registered, if the value is empty, it will try to guess from `eth1` or `eth0`

## Volumes

1. `/opt/gluu/data/main_db` directory
2. `/opt/gluu/data/site_db` directory

## Running The Container

Here's an example to run the container as ldap master with initial LDAP entries:

```
docker run -d \
    --name openldap-init \
    -e GLUU_KV_HOST=consul.example.com \
    -e GLUU_KV_PORT=8500 \
    -e GLUU_LDAP_INIT=true \
    -e GLUU_LDAP_INIT_HOST=ldap.example.com \
    -e GLUU_LDAP_INIT_PORT=1636 \
    -e GLUU_CACHE_TYPE=REDIS \
    -e GLUU_REDIS_URL='redis.example:6379' \
    -v /path/to/ldap/flag:/flag \
    gluufederation/openldap:3.1.2_dev
```

Note: to avoid data being re-initialized after container restart, volume mapping of `/flag` directory is encouraged. In the future, the process of LDAP initial data will be taken care by another container.

To add other container(s):

```
docker run -d \
    --name openldap \
    -e GLUU_KV_HOST=consul.example.com \
    -e GLUU_KV_PORT=8500 \
    -e GLUU_LDAP_INIT=false \
    gluufederation/openldap:3.1.2_dev
```

Note: all containers must be synchronized using `ntp`.

## Customizing OpenLDAP

If user has a custom LDAP schema then user need to mount a volume from host into container.
Here's an example to run the container as ldap master with initial LDAP entries and custom schema:

```
docker run -d \
    --name openldap-init \
    -e GLUU_KV_HOST=consul.example.com \
    -e GLUU_KV_PORT=8500 \
    -e GLUU_LDAP_INIT=true \
    -e GLUU_LDAP_INIT_HOST=ldap.example.com \
    -e GLUU_LDAP_INIT_PORT=1636 \
    -v /path/to/ldap/flag:/flag \
    -v /path/to/custom/schema:/ldap/custom_schema \
    gluufederation/openldap:3.1.2_dev
```

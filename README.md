# OpenLDAP

A docker image version of OpenLDAP.

## Versioning/Tagging

This image uses its own versioning/tagging format.

    <IMAGE-NAME>:<GLUU-SERVER-VERSION>_<INTERNAL-REV-VERSION>

For example, `gluufederation/openldap:3.0.1_rev1.0.0` consists of:

- glufederation/openldap as `<IMAGE_NAME>`; the actual image name
- 3.0.1 as `GLUU-SERVER-VERSION`; the Gluu Server version as setup reference
- rev1.0.0 as `<INTERNAL-REV-VERSION>`; revision made when developing the image

## Installation

Build the image:

```
docker build --rm --force-rm -t gluufederation/openldap:latest .
```

Or get it from Docker Hub:

```
docker pull gluufederation/openldap:latest
```

## Environment Variables

- `GLUU_KV_HOST`: hostname or IP address of Consul.
- `GLUU_KV_PORT`: port of Consul.
- `GLUU_LDAP_INIT`: whether to import initial LDAP entries (possible value are `true` or `false`).
- `GLUU_LDAP_INIT_HOST`: hostname of LDAP for initial configuration (only usable when `GLUU_LDAP_INIT` set to `true`).
- `GLUU_LDAP_INIT_PORT`: port of LDAP for initial configuration (only usable when `GLUU_LDAP_INIT` set to `true`).
- `GLUU_CACHE_TYPE`: supported values are 'IN_MEMORY' and 'REDIS', default is 'IN_MEMORY'.
- `GLUU_REDIS_URL`: Url of redis service, fornat is redis_host:redis_port (optional).

## Volumes

1. `/opt/gluu/data/main_db` directory
2. `/opt/gluu/data/site_db` directory

## Running The Container

Here's an example to run the container as ldap master with initial LDAP entries:

```
docker run -d \
    --name openldap-init \
    -e GLUU_KV_HOST=my.consul.domain.com \
    -e GLUU_KV_PORT=8500 \
    -e GLUU_LDAP_INIT=true \
    -e GLUU_LDAP_INIT_HOST=my.ldap.hostname \
    -e GLUU_LDAP_INIT_PORT=1389 \
    -e GLUU_CACHE_TYPE=REDIS \
    -e GLUU_REDIS_URL='my.redis.hostname:6379' \
    -v /path/to/ldap/flag:/flag \
    gluufederation/openldap:containership
```

Note: to avoid data being re-initialized after container restart, volume mapping of `/flag` directory is encouraged. In the future, the process of LDAP initial data will be taken care by another container.

To add other container(s):

```
docker run -d \
    --name openldap \
    -e GLUU_KV_HOST=my.consul.domain.com \
    -e GLUU_KV_PORT=8500 \
    -e GLUU_LDAP_INIT=false \
    gluufederation/openldap:containership
```

Note: all containers must be synchronized using `ntp`.

## Customizing OpenLDAP

If user has a custome ldap schema then user need to put the schema file in a tar.gz archive.
This archive will just contain schama file. User need to provide a url for that archive file.
user must pass custom schema to init ldap master to take effect.

Here's an example to run the container as ldap master with initial LDAP entries and custom schema:

```
docker run -d \
    --name openldap-init \
    -e GLUU_KV_HOST=my.consul.domain.com \
    -e GLUU_KV_PORT=8500 \
    -e GLUU_LDAP_INIT=true \
    -e GLUU_LDAP_INIT_HOST=my.ldap.hostname \
    -e GLUU_LDAP_INIT_PORT=1389 \
    -e GLUU_CUSTOM_SCHEMA_URL=https://url/of/custom-schema.tar.gz \
    -v /path/to/ldap/flag:/flag \
    gluufederation/openldap:containership
```

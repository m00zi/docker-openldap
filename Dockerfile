FROM ubuntu:14.04

LABEL maintainer="Gluu Inc. <support@gluu.org>"

RUN apt-get update && apt-get install -y \
    wget \
    curl \
    python-pip \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /ldap

# ========
# OpenLDAP
# ========
ENV OPENLDAP_DEB_URL https://repo.gluu.org/ubuntu/symas-openldap-gluu.amd64_2.4.44-20161020_amd64.deb

RUN wget -q ${OPENLDAP_DEB_URL} -O /tmp/openldap.deb \
    && dpkg --install /tmp/openldap.deb \
    && rm -rf /tmp/openldap.deb

# ===============
# Python packages
# ===============

COPY requirements.txt /tmp/
RUN pip install -U pip
# A workaround to address https://github.com/docker/docker-py/issues/1054
# # and to make sure latest pip is being used, not from OS one
ENV PYTHONPATH="/usr/local/lib/python2.7/dist-packages:/usr/lib/python2.7/dist-packages"
RUN pip install --no-cache-dir -r /tmp/requirements.txt --ignore-installed six

# ====
# Tini
# ====

ENV TINI_VERSION v0.18.0
RUN wget -q https://github.com/krallin/tini/releases/download/${TINI_VERSION}/tini-static -O /usr/bin/tini \
    && chmod +x /usr/bin/tini

# ====
# misc
# ====
RUN mkdir -p /var/symas/run \
    && mkdir -p /opt/symas/etc/openldap \
    && mkdir -p /opt/gluu/schema/openldap \
    && mkdir -p /opt/gluu/data/accesslog \
    && mkdir -p /etc/certs \
    && mkdir -p /opt/symas/etc/openldap/slapd.d \
    && mkdir -p /opt/gluu/data/main_db \
    && mkdir -p /opt/gluu/data/site_db \
    && mkdir -p /flag

COPY schema /opt/gluu/schema/openldap
COPY templates ./templates
COPY scripts ./scripts
RUN cp ./templates/slapd/symas-openldap.conf /opt/symas/etc/openldap/symas-openldap.conf

# Volumes
VOLUME /opt/gluu/data/main_db
VOLUME /opt/gluu/data/site_db

# Custom schema path
RUN mkdir -p /ldap/custom_schema

EXPOSE 1636

ENV GLUU_LDAP_ADDR_INTERFACE ""
ENV GLUU_LDAP_INIT True
ENV GLUU_LDAP_INIT_HOST localhost
ENV GLUU_LDAP_INIT_PORT 1636
ENV GLUU_CACHE_TYPE IN_MEMORY
ENV GLUU_REDIS_URL localhost:6379
ENV GLUU_OXTRUST_CONFIG_GENERATION False
ENV GLUU_REDIS_TYPE STANDALONE

# Entrypoint
ENTRYPOINT ["tini", "--"]
CMD ["/ldap/scripts/wait-for-it", "/ldap/scripts/entrypoint.sh"]

FROM ubuntu:14.04

LABEL maintainer="Gluu Inc. <support@gluu.org>"

RUN apt-get update && apt-get install -y \
    wget \
    curl \
    python \
    python-dev \
    python-pip \
    swig \
    libssl-dev \
    libldap2-dev \
    libsasl2-dev \
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
RUN pip install --no-cache-dir -r /tmp/requirements.txt

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
    && mkdir -p /opt/gluu/data/site_db

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

# Entrypoint
COPY entrypoint.sh /
RUN chmod +x /entrypoint.sh
CMD ["/entrypoint.sh"]

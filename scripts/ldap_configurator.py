import fcntl
import logging
import os
import socket
import struct

import consulate

from ldap_initializer import decrypt_text

GLUU_KV_HOST = os.environ.get('GLUU_KV_HOST', 'localhost')
GLUU_KV_PORT = os.environ.get('GLUU_KV_PORT', 8500)

GLUU_LDAP_ADDR_INTERFACE = os.environ.get("GLUU_LDAP_ADDR_INTERFACE", "")

consul = consulate.Consul(host=GLUU_KV_HOST, port=GLUU_KV_PORT)

logger = logging.getLogger("ldap_configurator")
logger.setLevel(logging.INFO)
ch = logging.FileHandler('/ldap/ldap_configurator.log')
fmt = logging.Formatter('[%(levelname)s] - %(asctime)s - %(message)s')
ch.setFormatter(fmt)
logger.addHandler(ch)

CONFIG_PREFIX = "gluu/config/"


def merge_path(name):
    # example: `hostname` renamed to `gluu/config/hostname`
    return "".join([CONFIG_PREFIX, name])


def unmerge_path(name):
    # example: `gluu/config/hostname` renamed to `hostname`
    return name[len(CONFIG_PREFIX):]


def get_config(name, default=None):
    return consul.kv.get(merge_path(name), default)


def set_config(name, value):
    return consul.kv.set(merge_path(name), value)


def get_ip_addr(ifname):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    addr = socket.inet_ntoa(fcntl.ioctl(
        sock.fileno(),
        0x8915,  # SIOCGIFADDR
        struct.pack('256s', ifname[:15])
    )[20:24])
    return addr


def guess_ip_addr(ifname=GLUU_LDAP_ADDR_INTERFACE):
    addr = ""

    if ifname:
        return get_ip_addr(ifname)

    # priorities
    for ifname in ("eth1", "eth0"):
        try:
            addr = get_ip_addr(ifname)
        except IOError:
            continue
        else:
            break
    return addr


def configure_provider_openldap():
    src = '/ldap/templates/slapd/slapd.conf'
    dest = '/opt/symas/etc/openldap/slapd.conf'

    ctx_data = {
        'openldapSchemaFolder': '/opt/gluu/schema/openldap',
        'encoded_ldap_pw': get_config('encoded_ldap_pw'),
        'replication_dn': get_config('replication_dn'),
    }

    with open(src, 'r') as fp:
        slapd_template = fp.read()

    with open(dest, 'w') as fp:
        fp.write(slapd_template % ctx_data)

    # register master
    host = guess_ip_addr()
    port = get_config("ldaps_port", 1636)
    set_config("ldap_masters/{}:{}".format(host, port), {
        "host": host, "port": port,
    })


def sync_ldap_certs():
    """Gets openldap.crt, openldap.key, and openldap.pem
    """
    ssl_cert = decrypt_text(get_config("ldap_ssl_cert"), get_config("encoded_salt"))
    with open("/etc/certs/openldap.crt", "w") as fw:
        fw.write(ssl_cert)
    ssl_key = decrypt_text(get_config("ldap_ssl_key"), get_config("encoded_salt"))
    with open("/etc/certs/openldap.key", "w") as fw:
        fw.write(ssl_key)
    ssl_cacert = decrypt_text(get_config("ldap_ssl_cacert"), get_config("encoded_salt"))
    with open("/etc/certs/openldap.pem", "w") as fw:
        fw.write(ssl_cacert)


if __name__ == "__main__":
    logger.info('start of basic configuration')
    sync_ldap_certs()
    configure_provider_openldap()

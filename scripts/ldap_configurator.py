import glob
import logging
import os

from ldap_initializer import decrypt_text
from gluu_config import ConfigManager

GLUU_LDAP_ADDR_INTERFACE = os.environ.get("GLUU_LDAP_ADDR_INTERFACE", "")

config_manager = ConfigManager()

logger = logging.getLogger("ldap_configurator")
logger.setLevel(logging.INFO)
ch = logging.StreamHandler()
fmt = logging.Formatter('[%(levelname)s] - %(asctime)s - %(message)s')
ch.setFormatter(fmt)
logger.addHandler(ch)


def get_custom_schema():
    pattern = "/ldap/custom_schema/*.schema"

    custom_schema = "\n".join([
        "include\t {}".format(x) for x in glob.iglob(pattern)
    ])
    return custom_schema


def configure_provider_openldap():
    src = '/ldap/templates/slapd/slapd.conf'
    dest = '/opt/symas/etc/openldap/slapd.conf'

    ctx_data = {
        'openldapSchemaFolder': '/opt/gluu/schema/openldap',
        'encoded_ldap_pw': config_manager.get('encoded_ldap_pw'),
        'replication_dn': config_manager.get('replication_dn'),
        "customSchema": get_custom_schema(),
    }

    with open(src, 'r') as fp:
        slapd_template = fp.read()

    with open(dest, 'w') as fp:
        fp.write(slapd_template % ctx_data)


def sync_ldap_certs():
    """Gets openldap.crt, openldap.key, and openldap.pem
    """
    ssl_cert = decrypt_text(config_manager.get("ldap_ssl_cert"), config_manager.get("encoded_salt"))
    with open("/etc/certs/openldap.crt", "w") as fw:
        fw.write(ssl_cert)
    ssl_key = decrypt_text(config_manager.get("ldap_ssl_key"), config_manager.get("encoded_salt"))
    with open("/etc/certs/openldap.key", "w") as fw:
        fw.write(ssl_key)
    ssl_cacert = decrypt_text(config_manager.get("ldap_ssl_cacert"), config_manager.get("encoded_salt"))
    with open("/etc/certs/openldap.pem", "w") as fw:
        fw.write(ssl_cacert)


if __name__ == "__main__":
    sync_ldap_certs()
    configure_provider_openldap()

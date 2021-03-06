import base64
import glob
import json
import logging
import os
import shlex
import shutil
import subprocess
import tempfile

import pyDes

from gluu_config import ConfigManager

# Whether initial data should be inserted
GLUU_LDAP_INIT = os.environ.get("GLUU_LDAP_INIT", True)
GLUU_LDAP_INIT_HOST = os.environ.get('GLUU_LDAP_INIT_HOST', 'localhost')
GLUU_LDAP_INIT_PORT = os.environ.get("GLUU_LDAP_INIT_PORT", 1636)
GLUU_LDAP_ADDR_INTERFACE = os.environ.get("GLUU_LDAP_ADDR_INTERFACE", "")
GLUU_CACHE_TYPE = os.environ.get("GLUU_CACHE_TYPE", 'IN_MEMORY')
GLUU_REDIS_URL = os.environ.get('GLUU_REDIS_URL', 'localhost:6379')
GLUU_REDIS_TYPE = os.environ.get('GLUU_REDIS_TYPE', 'STANDALONE')
GLUU_MEMCACHED_URL = os.environ.get("GLUU_MEMCACHED_URL", "localhost:11211")
GLUU_OXTRUST_CONFIG_GENERATION = os.environ.get("GLUU_OXTRUST_CONFIG_GENERATION", False)
GLUU_CERT_ALT_NAME = os.environ.get("GLUU_CERT_ALT_NAME", "")

TMPDIR = tempfile.mkdtemp()

logger = logging.getLogger("entrypoint")
logger.setLevel(logging.INFO)
ch = logging.StreamHandler()
fmt = logging.Formatter('[%(levelname)s] - %(asctime)s - %(message)s')
ch.setFormatter(fmt)
logger.addHandler(ch)

config_manager = ConfigManager()


def as_boolean(val, default=False):
    truthy = set(('t', 'T', 'true', 'True', 'TRUE', '1', 1, True))
    falsy = set(('f', 'F', 'false', 'False', 'FALSE', '0', 0, False))

    if val in truthy:
        return True
    if val in falsy:
        return False
    return default


def render_ldif():
    ctx = {
        # o_site.ldif
        # has no variables

        # appliance.ldif
        'cache_provider_type': GLUU_CACHE_TYPE,
        'redis_url': GLUU_REDIS_URL,
        'redis_type': GLUU_REDIS_TYPE,
        'memcached_url': GLUU_MEMCACHED_URL,
        # oxpassport-config.ldif
        'inumAppliance': config_manager.get('inumAppliance'),
        'ldap_hostname': config_manager.get('ldap_init_host'),
        # TODO: currently using std ldaps port 1636 as ldap port.
        # after basic testing we need to do it right, and remove this hack.
        # to do this properly we need to update all templates.
        'ldaps_port': config_manager.get('ldap_init_port'),
        'ldap_binddn': config_manager.get('ldap_binddn'),
        'encoded_ox_ldap_pw': config_manager.get('encoded_ox_ldap_pw'),
        'jetty_base': config_manager.get('jetty_base'),

        # asimba.ldif
        # attributes.ldif
        # groups.ldif
        # oxidp.ldif
        # scopes.ldif
        'inumOrg': r"{}".format(config_manager.get('inumOrg')),  # raw string

        # base.ldif
        'orgName': config_manager.get('orgName'),

        # clients.ldif
        'oxauth_client_id': config_manager.get('oxauth_client_id'),
        'oxauthClient_encoded_pw': config_manager.get('oxauthClient_encoded_pw'),
        'hostname': config_manager.get('hostname'),
        'idp_client_id': config_manager.get('idp_client_id'),
        'idpClient_encoded_pw': config_manager.get('idpClient_encoded_pw'),

        # configuration.ldif
        'oxauth_config_base64': config_manager.get('oxauth_config_base64'),
        'oxauth_static_conf_base64': config_manager.get('oxauth_static_conf_base64'),
        'oxauth_openid_key_base64': config_manager.get('oxauth_openid_key_base64'),
        'oxauth_error_base64': config_manager.get('oxauth_error_base64'),
        'oxtrust_config_base64': config_manager.get('oxtrust_config_base64'),
        'oxtrust_cache_refresh_base64': config_manager.get('oxtrust_cache_refresh_base64'),
        'oxtrust_import_person_base64': config_manager.get('oxtrust_import_person_base64'),
        'oxidp_config_base64': config_manager.get('oxidp_config_base64'),
        # 'oxcas_config_base64': config_manager.get('oxcas_config_base64'),
        'oxasimba_config_base64': config_manager.get('oxasimba_config_base64'),

        # passport.ldif
        'passport_rs_client_id': config_manager.get('passport_rs_client_id'),
        'passport_rs_client_base64_jwks': config_manager.get('passport_rs_client_base64_jwks'),
        'passport_rp_client_id': config_manager.get('passport_rp_client_id'),
        'passport_rp_client_base64_jwks': config_manager.get('passport_rp_client_base64_jwks'),
        "passport_rp_client_jks_fn": config_manager.get("passport_rp_client_jks_fn"),
        "passport_rp_client_jks_pass": config_manager.get("passport_rp_client_jks_pass"),

        # people.ldif
        "encoded_ldap_pw": config_manager.get('encoded_ldap_pw'),

        # scim.ldif
        'scim_rs_client_id': config_manager.get('scim_rs_client_id'),
        'scim_rs_client_base64_jwks': config_manager.get('scim_rs_client_base64_jwks'),
        'scim_rp_client_id': config_manager.get('scim_rp_client_id'),
        'scim_rp_client_base64_jwks': config_manager.get('scim_rp_client_base64_jwks'),

        # scripts.ldif
        "person_authentication_usercertexternalauthenticator": config_manager.get("person_authentication_usercertexternalauthenticator"),
        "person_authentication_passportexternalauthenticator": config_manager.get("person_authentication_passportexternalauthenticator"),
        "dynamic_scope_dynamic_permission": config_manager.get("dynamic_scope_dynamic_permission"),
        "id_generator_samplescript": config_manager.get("id_generator_samplescript"),
        "dynamic_scope_org_name": config_manager.get("dynamic_scope_org_name"),
        "dynamic_scope_work_phone": config_manager.get("dynamic_scope_work_phone"),
        "cache_refresh_samplescript": config_manager.get("cache_refresh_samplescript"),
        "person_authentication_yubicloudexternalauthenticator": config_manager.get("person_authentication_yubicloudexternalauthenticator"),
        "uma_rpt_policy_uma_rpt_policy": config_manager.get("uma_rpt_policy_uma_rpt_policy"),
        "uma_claims_gathering_uma_claims_gathering": config_manager.get("uma_claims_gathering_uma_claims_gathering"),
        "person_authentication_basiclockaccountexternalauthenticator": config_manager.get("person_authentication_basiclockaccountexternalauthenticator"),
        "person_authentication_uafexternalauthenticator": config_manager.get("person_authentication_uafexternalauthenticator"),
        "person_authentication_otpexternalauthenticator": config_manager.get("person_authentication_otpexternalauthenticator"),
        "person_authentication_duoexternalauthenticator": config_manager.get("person_authentication_duoexternalauthenticator"),
        "update_user_samplescript": config_manager.get("update_user_samplescript"),
        "user_registration_samplescript": config_manager.get("user_registration_samplescript"),
        "user_registration_confirmregistrationsamplescript": config_manager.get("user_registration_confirmregistrationsamplescript"),
        "person_authentication_googleplusexternalauthenticator": config_manager.get("person_authentication_googleplusexternalauthenticator"),
        "person_authentication_u2fexternalauthenticator": config_manager.get("person_authentication_u2fexternalauthenticator"),
        "person_authentication_supergluuexternalauthenticator": config_manager.get("person_authentication_supergluuexternalauthenticator"),
        "person_authentication_basicexternalauthenticator": config_manager.get("person_authentication_basicexternalauthenticator"),
        "scim_samplescript": config_manager.get("scim_samplescript"),
        "person_authentication_samlexternalauthenticator": config_manager.get("person_authentication_samlexternalauthenticator"),
        "client_registration_samplescript": config_manager.get("client_registration_samplescript"),
        "person_authentication_twilio2fa": config_manager.get("person_authentication_twilio2fa"),
        "application_session_samplescript": config_manager.get("application_session_samplescript"),
        "uma_rpt_policy_umaclientauthzrptpolicy": config_manager.get("uma_rpt_policy_umaclientauthzrptpolicy"),
        "person_authentication_samlpassportauthenticator": config_manager.get("person_authentication_samlpassportauthenticator"),
        "consent_gathering_consentgatheringsample": config_manager.get("consent_gathering_consentgatheringsample"),
        "person_authentication_thumbsigninexternalauthenticator": config_manager.get("person_authentication_thumbsigninexternalauthenticator"),

        # scripts_casa
        "person_authentication_casa": config_manager.get("person_authentication_casa"),
        "client_registration_casa": config_manager.get("client_registration_casa"),

        # replication.ldif
        'replication_dn': config_manager.get('replication_dn'),
        'replication_cn': config_manager.get('replication_cn'),
        'encoded_replication_pw': config_manager.get('encoded_replication_pw'),
    }

    ldif_template_base = '/ldap/templates/ldif'
    pattern = '/*.ldif'
    for file_path in glob.glob(ldif_template_base + pattern):
        with open(file_path, 'r') as fp:
            template = fp.read()
        # render
        rendered_content = template % ctx
        # write to tmpdir
        with open(os.path.join(TMPDIR, os.path.basename(file_path)), 'w') as fp:
            fp.write(rendered_content)


def import_ldif():
    ldif_import_order = [
        'base.ldif',
        'appliance.ldif',
        'attributes.ldif',
        'scopes.ldif',
        'clients.ldif',
        'people.ldif',
        'groups.ldif',
        'o_site.ldif',
        'scripts.ldif',
        'configuration.ldif',
        'scim.ldif',
        'asimba.ldif',
        'passport.ldif',
        'oxpassport-config.ldif',
        'oxidp.ldif',
        "replication.ldif",
    ]

    slapadd_cmd = '/opt/symas/bin/slapadd'
    config = '/opt/symas/etc/openldap/slapd.conf'

    for ldif_file in ldif_import_order:
        ldif_file_path = os.path.join(TMPDIR, ldif_file)
        if 'site.ldif' in ldif_file_path:
            base_dn = "o=site"
        else:
            base_dn = "o=gluu"
        exec_cmd("{} -b {} -f {} -l {}".format(slapadd_cmd, base_dn, config, ldif_file_path))


def cleanup():
    shutil.rmtree(TMPDIR)


# TODO: Remove oxtrust related code from openldap
def reindent(text, num_spaces=1):
    text = [(num_spaces * " ") + line.lstrip() for line in text.splitlines()]
    text = "\n".join(text)
    return text


def generate_base64_contents(text, num_spaces=1):
    text = text.encode("base64").strip()
    if num_spaces > 0:
        text = reindent(text, num_spaces)
    return text


def oxtrust_config():
    # keeping redundent data in context of ldif ctx_data dict for now.
    # so that we can easily remove it from here
    ctx = {
        'inumOrg': r"{}".format(config_manager.get('inumOrg')),  # raw string
        'admin_email': config_manager.get('admin_email'),
        'inumAppliance': config_manager.get('inumAppliance'),
        'hostname': config_manager.get('hostname'),
        'shibJksFn': config_manager.get('shibJksFn'),
        'shibJksPass': config_manager.get('shibJksPass'),
        'jetty_base': config_manager.get('jetty_base'),
        'oxTrustConfigGeneration': config_manager.get('oxTrustConfigGeneration'),
        'encoded_shib_jks_pw': config_manager.get('encoded_shib_jks_pw'),
        'oxauth_client_id': config_manager.get('oxauth_client_id'),
        'oxauthClient_encoded_pw': config_manager.get('oxauthClient_encoded_pw'),
        'scim_rs_client_id': config_manager.get('scim_rs_client_id'),
        'scim_rs_client_jks_fn': config_manager.get('scim_rs_client_jks_fn'),
        'scim_rs_client_jks_pass_encoded': config_manager.get('scim_rs_client_jks_pass_encoded'),
        'passport_rs_client_id': config_manager.get('passport_rs_client_id'),
        'passport_rs_client_jks_fn': config_manager.get('passport_rs_client_jks_fn'),
        'passport_rs_client_jks_pass_encoded': config_manager.get('passport_rs_client_jks_pass_encoded'),
        'shibboleth_version': config_manager.get('shibboleth_version'),
        'idp3Folder': config_manager.get('idp3Folder'),
        'orgName': config_manager.get('orgName'),
        'ldap_site_binddn': config_manager.get('ldap_site_binddn'),
        'encoded_ox_ldap_pw': config_manager.get('encoded_ox_ldap_pw'),
        'ldap_hostname': config_manager.get('ldap_init_host'),
        'ldaps_port': config_manager.get('ldap_init_port'),
    }

    oxtrust_template_base = '/ldap/templates/oxtrust'

    key_and_jsonfile_map = {
        'oxtrust_cache_refresh_base64': 'oxtrust-cache-refresh.json',
        'oxtrust_config_base64': 'oxtrust-config.json',
        'oxtrust_import_person_base64': 'oxtrust-import-person.json'
    }

    for key, json_file in key_and_jsonfile_map.iteritems():
        json_file_path = os.path.join(oxtrust_template_base, json_file)
        with open(json_file_path, 'r') as fp:
            config_manager.set(key, generate_base64_contents(fp.read() % ctx))


def decrypt_text(encrypted_text, key):
    cipher = pyDes.triple_des(b"{}".format(key), pyDes.ECB,
                              padmode=pyDes.PAD_PKCS5)
    encrypted_text = b"{}".format(base64.b64decode(encrypted_text))
    return cipher.decrypt(encrypted_text)


def get_custom_schema():
    pattern = "/ldap/custom_schema/*.schema"

    custom_schema = "\n".join([
        "include\t {}".format(x) for x in glob.iglob(pattern)
    ])
    return custom_schema


def get_openldap_indexes():
    output = ""
    with open("/ldap/static/index.json") as fr:
        indexes = json.loads(fr.read())
        output = "\n".join([
            "index\t{}\t{}".format(index["attribute"], index["index"])
            for index in indexes["indexes"]
        ])
    return output


def configure_provider_openldap():
    src = '/ldap/templates/slapd/slapd.conf'
    dest = '/opt/symas/etc/openldap/slapd.conf'

    ctx_data = {
        'openldapSchemaFolder': '/opt/gluu/schema/openldap',
        'encoded_ldap_pw': config_manager.get('encoded_ldap_pw'),
        'replication_dn': config_manager.get('replication_dn'),
        "customSchema": get_custom_schema(),
        "openldap_indexes": get_openldap_indexes(),
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


def exec_cmd(cmd):
    """Executes shell command.

    :param cmd: String of shell command.
    :returns: A tuple consists of stdout, stderr, and return code
              returned from shell command execution.
    """
    args = shlex.split(cmd)
    popen = subprocess.Popen(args,
                             stdin=subprocess.PIPE,
                             stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE)
    stdout, stderr = popen.communicate()
    retcode = popen.returncode
    return stdout, stderr, retcode


def sync_ldap_pkcs12():
    pkcs = decrypt_text(config_manager.get("ldap_pkcs12_base64"),
                        config_manager.get("encoded_salt"))

    with open(config_manager.get("ldapTrustStoreFn"), "wb") as fw:
        fw.write(pkcs)


def main():
    logger.info("Syncing OpenLDAP certs.")
    sync_ldap_certs()
    sync_ldap_pkcs12()

    logger.info("Checking certificate's Subject Alt Name (SAN)")
    san = get_certificate_san("/etc/certs/openldap.crt").replace("DNS:", "")

    if GLUU_CERT_ALT_NAME != san:
        logger.info("Re-generating OpenLDAP certs with SAN support.")

        render_san_cnf(GLUU_CERT_ALT_NAME)
        regenerate_ldap_certs()

        salt = config_manager.get("encoded_salt")

        with open("/etc/certs/{}.pem".format("openldap"), "w") as fw:
            with open("/etc/certs/{}.crt".format("openldap")) as fr:
                ldap_ssl_cert = fr.read()

            with open("/etc/certs/{}.key".format("openldap")) as fr:
                ldap_ssl_key = fr.read()

            ldap_ssl_cacert = "".join([ldap_ssl_cert, ldap_ssl_key])
            fw.write(ldap_ssl_cacert)

            # update config
            config_manager.set("ldap_ssl_cert",
                               encrypt_text(ldap_ssl_cert, salt))
            config_manager.set("ldap_ssl_key",
                               encrypt_text(ldap_ssl_key, salt))
            config_manager.set("ldap_ssl_cacert",
                               encrypt_text(ldap_ssl_cacert, salt))

        regenerate_ldap_pkcs12()
        # update config
        with open(config_manager.get("ldapTrustStoreFn"), "rb") as fr:
            config_manager.set("ldap_pkcs12_base64",
                               encrypt_text(fr.read(), salt))

    configure_provider_openldap()

    if as_boolean(GLUU_LDAP_INIT):
        if not os.path.isfile("/flag/ldap_initialized"):
            config_manager.set('ldap_init_host', GLUU_LDAP_INIT_HOST)
            config_manager.set('ldap_init_port', GLUU_LDAP_INIT_PORT)
            config_manager.set("oxTrustConfigGeneration", as_boolean(GLUU_OXTRUST_CONFIG_GENERATION))

            oxtrust_config()
            render_ldif()
            import_ldif()

            exec_cmd("touch /flag/ldap_initialized")
    cleanup()


def get_certificate_san(certpath):
    openssl_proc = subprocess.Popen(
        shlex.split("openssl x509 -text -noout -in {}".format(certpath)),
        stdout=subprocess.PIPE,
    )
    grep_proc = subprocess.Popen(
        shlex.split("grep DNS"),
        stdout=subprocess.PIPE,
        stdin=openssl_proc.stdout,
    )
    san = grep_proc.communicate()[0]
    return san.strip()


def encrypt_text(text, key):
    cipher = pyDes.triple_des(b"{}".format(key), pyDes.ECB,
                              padmode=pyDes.PAD_PKCS5)
    encrypted_text = cipher.encrypt(b"{}".format(text))
    return base64.b64encode(encrypted_text)


def regenerate_ldap_pkcs12():
    suffix = "openldap"
    passwd = config_manager.get("ldap_truststore_pass")
    hostname = config_manager.get("hostname")

    # Convert key to pkcs12
    cmd = " ".join([
        "openssl",
        "pkcs12",
        "-export",
        "-inkey /etc/certs/{}.key".format(suffix),
        "-in /etc/certs/{}.crt".format(suffix),
        "-out /etc/certs/{}.pkcs12".format(suffix),
        "-name {}".format(hostname),
        "-passout pass:{}".format(passwd),
    ])
    _, err, retcode = exec_cmd(cmd)
    assert retcode == 0, "Failed to generate PKCS12 file; reason={}".format(err)


def regenerate_ldap_certs():
    suffix = "openldap"
    passwd = decrypt_text(config_manager.get("encoded_ox_ldap_pw"),
                          config_manager.get("encoded_salt"))
    country_code = config_manager.get("country_code")
    state = config_manager.get("state")
    city = config_manager.get("city")
    org_name = config_manager.get("orgName")
    domain = config_manager.get("hostname")
    email = config_manager.get("admin_email")

    # create key with password
    _, err, retcode = exec_cmd(
        "openssl genrsa -des3 -out /etc/certs/{}.key.orig "
        "-passout pass:'{}' 2048".format(suffix, passwd))
    assert retcode == 0, "Failed to generate SSL key with password; reason={}".format(err)

    # create .key
    _, err, retcode = exec_cmd(
        "openssl rsa -in /etc/certs/{0}.key.orig "
        "-passin pass:'{1}' -out /etc/certs/{0}.key".format(suffix, passwd))
    assert retcode == 0, "Failed to generate SSL key; reason={}".format(err)

    # create .csr
    _, err, retcode = exec_cmd(
        "openssl req -new -key /etc/certs/{0}.key "
        "-out /etc/certs/{0}.csr "
        "-config /etc/ssl/san.cnf "
        "-subj /C='{1}'/ST='{2}'/L='{3}'/O='{4}'/CN='{5}'/emailAddress='{6}'".format(suffix, country_code, state, city, org_name, domain, email))
    assert retcode == 0, "Failed to generate SSL CSR; reason={}".format(err)

    # create .crt
    _, err, retcode = exec_cmd(
        "openssl x509 -req -days 365 -in /etc/certs/{0}.csr "
        "-extensions v3_req -extfile /etc/ssl/san.cnf "
        "-signkey /etc/certs/{0}.key -out /etc/certs/{0}.crt".format(suffix))
    assert retcode == 0, "Failed to generate SSL cert; reason={}".format(err)

    # return the paths
    return "/etc/certs/{}.crt".format(suffix), "/etc/certs/{}.key".format(suffix)


def render_san_cnf(name):
    ctx = {"alt_name": name}

    with open("/ldap/templates/ssl/san.cnf") as fr:
        txt = fr.read() % ctx

        with open("/etc/ssl/san.cnf", "w")as fw:
            fw.write(txt)


if __name__ == "__main__":
    main()

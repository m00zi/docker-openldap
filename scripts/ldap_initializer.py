import base64
import glob
import os
import shutil
import subprocess
import traceback
import tempfile
import logging

import consulate
import pyDes

GLUU_KV_HOST = os.environ.get('GLUU_KV_HOST', 'localhost')
GLUU_KV_PORT = os.environ.get('GLUU_KV_PORT', 8500)
# Whether initial data should be inserted
GLUU_LDAP_INIT = os.environ.get("GLUU_LDAP_INIT", True)
GLUU_LDAP_INIT_HOST = os.environ.get('GLUU_LDAP_INIT_HOST', 'localhost')
GLUU_LDAP_INIT_PORT = os.environ.get("GLUU_LDAP_INIT_PORT", 1389)
GLUU_CACHE_TYPE = os.environ.get("GLUU_CACHE_TYPE", 'IN_MEMORY')
GLUU_REDIS_URL = os.environ.get('GLUU_REDIS_URL', 'localhost:6379')
TMPDIR = tempfile.mkdtemp()
GLUU_OXTRUST_CONFIG_GENERATION = os.environ.get("GLUU_OXTRUST_CONFIG_GENERATION", False)

consul = consulate.Consul(host=GLUU_KV_HOST, port=GLUU_KV_PORT)

logger = logging.getLogger("ldap_initializer")
logger.setLevel(logging.INFO)
ch = logging.StreamHandler()
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


def as_boolean(val, default=False):
    truthy = set(('t', 'T', 'true', 'True', 'TRUE', '1', 1, True))
    falsy = set(('f', 'F', 'false', 'False', 'FALSE', '0', 0, False))

    if val in truthy:
        return True
    if val in falsy:
        return False
    return default


def runcmd(args, cwd=None, env=None, useWait=False):
    try:
        p = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=cwd, env=env)
        if useWait:
            code = p.wait()
            logger.info('Run: %s with result code: %d' % (' '.join(args), code))
        else:
            output, err = p.communicate()
            if output:
                logger.info(output)
            if err:
                logger.warn(err)
    except Exception:
        logger.warn('Error running command : %s' % ' '.join(args))
        logger.warn(traceback.format_exc())


def render_ldif():
    ctx = {
        # o_site.ldif
        # has no variables

        # appliance.ldif
        'cache_provider_type': GLUU_CACHE_TYPE,
        'redis_url': GLUU_REDIS_URL,
        # oxpassport-config.ldif
        'inumAppliance': get_config('inumAppliance'),
        'ldap_hostname': get_config('ldap_init_host'),
        # TODO: currently using std ldaps port 1636 as ldap port.
        # after basic testing we need to do it right, and remove this hack.
        # to do this properly we need to update all templates.
        'ldaps_port': get_config('ldap_init_port'),
        'ldap_binddn': get_config('ldap_binddn'),
        'encoded_ox_ldap_pw': get_config('encoded_ox_ldap_pw'),
        'jetty_base': get_config('jetty_base'),

        # asimba.ldif
        # attributes.ldif
        # groups.ldif
        # oxidp.ldif
        # scopes.ldif
        'inumOrg': r"{}".format(get_config('inumOrg')),  # raw string

        # base.ldif
        'orgName': get_config('orgName'),

        # clients.ldif
        'oxauth_client_id': get_config('oxauth_client_id'),
        'oxauthClient_encoded_pw': get_config('oxauthClient_encoded_pw'),
        'hostname': get_config('hostname'),

        # configuration.ldif
        'oxauth_config_base64': get_config('oxauth_config_base64'),
        'oxauth_static_conf_base64': get_config('oxauth_static_conf_base64'),
        'oxauth_openid_key_base64': get_config('oxauth_openid_key_base64'),
        'oxauth_error_base64': get_config('oxauth_error_base64'),
        'oxtrust_config_base64': get_config('oxtrust_config_base64'),
        'oxtrust_cache_refresh_base64': get_config('oxtrust_cache_refresh_base64'),
        'oxtrust_import_person_base64': get_config('oxtrust_import_person_base64'),
        'oxidp_config_base64': get_config('oxidp_config_base64'),
        # 'oxcas_config_base64': get_config('oxcas_config_base64'),
        'oxasimba_config_base64': get_config('oxasimba_config_base64'),

        # passport.ldif
        'passport_rs_client_id': get_config('passport_rs_client_id'),
        'passport_rs_client_base64_jwks': get_config('passport_rs_client_base64_jwks'),
        'passport_rp_client_id': get_config('passport_rp_client_id'),
        'passport_rp_client_base64_jwks': get_config('passport_rp_client_base64_jwks'),

        # people.ldif
        "encoded_ldap_pw": get_config('encoded_ldap_pw'),

        # scim.ldif
        'scim_rs_client_id': get_config('scim_rs_client_id'),
        'scim_rs_client_base64_jwks': get_config('scim_rs_client_base64_jwks'),
        'scim_rp_client_id': get_config('scim_rp_client_id'),
        'scim_rp_client_base64_jwks': get_config('scim_rp_client_base64_jwks'),

        # scripts.ldif
        "person_authentication_usercertexternalauthenticator": get_config("person_authentication_usercertexternalauthenticator"),
        "person_authentication_passportexternalauthenticator": get_config("person_authentication_passportexternalauthenticator"),
        "dynamic_scope_dynamic_permission": get_config("dynamic_scope_dynamic_permission"),
        "id_generator_samplescript": get_config("id_generator_samplescript"),
        "dynamic_scope_org_name": get_config("dynamic_scope_org_name"),
        "dynamic_scope_work_phone": get_config("dynamic_scope_work_phone"),
        "cache_refresh_samplescript": get_config("cache_refresh_samplescript"),
        "person_authentication_yubicloudexternalauthenticator": get_config("person_authentication_yubicloudexternalauthenticator"),
        "uma_rpt_policy_uma_rpt_policy": get_config("uma_rpt_policy_uma_rpt_policy"),
        "uma_claims_gathering_uma_claims_gathering": get_config("uma_claims_gathering_uma_claims_gathering"),
        "person_authentication_basiclockaccountexternalauthenticator": get_config("person_authentication_basiclockaccountexternalauthenticator"),
        "person_authentication_uafexternalauthenticator": get_config("person_authentication_uafexternalauthenticator"),
        "person_authentication_otpexternalauthenticator": get_config("person_authentication_otpexternalauthenticator"),
        "person_authentication_duoexternalauthenticator": get_config("person_authentication_duoexternalauthenticator"),
        "update_user_samplescript": get_config("update_user_samplescript"),
        "user_registration_samplescript": get_config("user_registration_samplescript"),
        "user_registration_confirmregistrationsamplescript": get_config("user_registration_confirmregistrationsamplescript"),
        "person_authentication_googleplusexternalauthenticator": get_config("person_authentication_googleplusexternalauthenticator"),
        "person_authentication_u2fexternalauthenticator": get_config("person_authentication_u2fexternalauthenticator"),
        "person_authentication_supergluuexternalauthenticator": get_config("person_authentication_supergluuexternalauthenticator"),
        "person_authentication_basicexternalauthenticator": get_config("person_authentication_basicexternalauthenticator"),
        "scim_samplescript": get_config("scim_samplescript"),
        "person_authentication_samlexternalauthenticator": get_config("person_authentication_samlexternalauthenticator"),
        "client_registration_samplescript": get_config("client_registration_samplescript"),
        "person_authentication_twilio2fa": get_config("person_authentication_twilio2fa"),
        "application_session_samplescript": get_config("application_session_samplescript"),
        "uma_rpt_policy_umaclientauthzrptpolicy": get_config("uma_rpt_policy_umaclientauthzrptpolicy"),
        "person_authentication_samlpassportauthenticator": get_config("person_authentication_samlpassportauthenticator"),
        "consent_gathering_consentgatheringsample": get_config("consent_gathering_consentgatheringsample"),

        # scripts_cred_manager
        "person_authentication_credmanager": get_config("person_authentication_credmanager"),
        "client_registration_credmanager": get_config("client_registration_credmanager"),

        # replication.ldif
        'replication_dn': get_config('replication_dn'),
        'replication_cn': get_config('replication_cn'),
        'encoded_replication_pw': get_config('encoded_replication_pw'),
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
            runcmd([slapadd_cmd, '-b', 'o=site', '-f', config, '-l', ldif_file_path])
        else:
            runcmd([slapadd_cmd, '-b', 'o=gluu', '-f', config, '-l', ldif_file_path])


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
        'inumOrg': r"{}".format(get_config('inumOrg')),  # raw string
        'admin_email': get_config('admin_email'),
        'inumAppliance': get_config('inumAppliance'),
        'hostname': get_config('hostname'),
        'shibJksFn': get_config('shibJksFn'),
        'shibJksPass': get_config('shibJksPass'),
        'jetty_base': get_config('jetty_base'),
        'oxTrustConfigGeneration': get_config('oxTrustConfigGeneration'),
        'encoded_shib_jks_pw': get_config('encoded_shib_jks_pw'),
        'oxauth_client_id': get_config('oxauth_client_id'),
        'oxauthClient_encoded_pw': get_config('oxauthClient_encoded_pw'),
        'scim_rs_client_id': get_config('scim_rs_client_id'),
        'scim_rs_client_jks_fn': get_config('scim_rs_client_jks_fn'),
        'scim_rs_client_jks_pass_encoded': get_config('scim_rs_client_jks_pass_encoded'),
        'passport_rs_client_id': get_config('passport_rs_client_id'),
        'passport_rs_client_jks_fn': get_config('passport_rs_client_jks_fn'),
        'passport_rs_client_jks_pass_encoded': get_config('passport_rs_client_jks_pass_encoded'),
        'shibboleth_version': get_config('shibboleth_version'),
        'idp3Folder': get_config('idp3Folder'),
        'orgName': get_config('orgName'),
        'ldap_site_binddn': get_config('ldap_site_binddn'),
        'encoded_ox_ldap_pw': get_config('encoded_ox_ldap_pw'),
        'ldap_hostname': get_config('ldap_init_host'),
        'ldaps_port': get_config('ldap_init_port'),
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
            set_config(key, generate_base64_contents(fp.read() % ctx))


def run():
    if as_boolean(GLUU_LDAP_INIT):
        set_config('ldap_init_host', GLUU_LDAP_INIT_HOST)
        set_config('ldap_init_port', GLUU_LDAP_INIT_PORT)
        set_config("oxTrustConfigGeneration", as_boolean(GLUU_OXTRUST_CONFIG_GENERATION))

        oxtrust_config()
        logger.info('start rendering of ldif files')
        render_ldif()
        logger.info('start importing rendered ldif files')
        import_ldif()
    cleanup()


def decrypt_text(encrypted_text, key):
    cipher = pyDes.triple_des(b"{}".format(key), pyDes.ECB,
                              padmode=pyDes.PAD_PKCS5)
    encrypted_text = b"{}".format(base64.b64decode(encrypted_text))
    return cipher.decrypt(encrypted_text)


if __name__ == '__main__':
    run()

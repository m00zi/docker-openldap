import base64
import glob
import os
import shutil
import subprocess
import traceback
import tempfile
import logging

import pyDes

from gluu_config import ConfigManager

# Whether initial data should be inserted
GLUU_LDAP_INIT = os.environ.get("GLUU_LDAP_INIT", True)
GLUU_LDAP_INIT_HOST = os.environ.get('GLUU_LDAP_INIT_HOST', 'localhost')
GLUU_LDAP_INIT_PORT = os.environ.get("GLUU_LDAP_INIT_PORT", 1389)
GLUU_CACHE_TYPE = os.environ.get("GLUU_CACHE_TYPE", 'IN_MEMORY')
GLUU_REDIS_URL = os.environ.get('GLUU_REDIS_URL', 'localhost:6379')
GLUU_REDIS_TYPE = os.environ.get('GLUU_REDIS_TYPE', 'STANDALONE')
GLUU_OXTRUST_CONFIG_GENERATION = os.environ.get("GLUU_OXTRUST_CONFIG_GENERATION", False)

TMPDIR = tempfile.mkdtemp()

config_manager = ConfigManager()

logger = logging.getLogger("ldap_initializer")
logger.setLevel(logging.INFO)
ch = logging.StreamHandler()
fmt = logging.Formatter('[%(levelname)s] - %(asctime)s - %(message)s')
ch.setFormatter(fmt)
logger.addHandler(ch)


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
        'redis_type': GLUU_REDIS_TYPE,
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

        # scripts_cred_manager
        "person_authentication_credmanager": config_manager.get("person_authentication_credmanager"),
        "client_registration_credmanager": config_manager.get("client_registration_credmanager"),

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


def run():
    if as_boolean(GLUU_LDAP_INIT):
        config_manager.set('ldap_init_host', GLUU_LDAP_INIT_HOST)
        config_manager.set('ldap_init_port', GLUU_LDAP_INIT_PORT)
        config_manager.set("oxTrustConfigGeneration", as_boolean(GLUU_OXTRUST_CONFIG_GENERATION))

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

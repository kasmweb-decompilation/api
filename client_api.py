# Source Generated with Decompyle++
# File: client_api.pyc (Python 3.8)

import tempfile
import typing
from urllib.error import URLError
import uuid
import hashlib
import cherrypy
import traceback
import logging
import logging.config as logging
import time
import datetime
import json
import os
import stripe
import pyotp
import base64
import urllib.request as urllib
import requests
import ssl
import jwt
import random
import webauthn
from urllib.parse import urlparse, urlunparse
from socket import gethostbyname, gaierror
from decimal import Decimal
from provider_manager import ProviderManager
from data.data_access_factory import DataAccessFactory
from data.categories import ALL_CATEGORIES
from data.enums import CONNECTION_PROXY_TYPE, CONNECTION_TYPE, SESSION_OPERATIONAL_STATUS, LANGUAGES, TIMEZONES, IMAGE_TYPE, STORAGE_PROVIDER_TYPES, JWT_AUTHORIZATION, SERVER_OPERATIONAL_STATUS
from data.lookup_tables import LANGUAGE_MAPPING_TO_TERRITORIES
from data.data_utils import generate_password
from utils import passwordComplexityCheck, Authenticated, JwtAuthenticated, CookieAuthenticated, LicenseHelper, check_usage, get_usage, update_hubspot_contact_by_email, generate_hmac, validate_session_token_ex, validate_recaptcha, func_timing, ConnectionError, is_healthy, generate_jwt_token, generate_guac_client_secret, object_storage_variable_substitution, Unauthenticated
from authentication.ldap_auth import LDAPAuthentication
from authentication.saml.saml_auth import SamlAuthentication
from authentication.oidc import OIDCAuthentication
from storage_providers import GoogleDrive, Dropbox, OneDrive, S3, Nextcloud, CustomStorageProvider
from filtering.kasm_web_filter import KasmWebFilter
from cachetools.func import ttl_cache
from pydantic import ValidationError
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.fernet import Fernet
from providers.aws_provider import AwsObjectStorageProvider
from webauthn.helpers.structs import AuthenticatorSelectionCriteria, UserVerificationRequirement, RegistrationCredential, AuthenticationCredential, PublicKeyCredentialDescriptor
from http.cookies import Morsel
Morsel._reserved['samesite'] = 'SameSite'

class ClientApi(object):
    
    def __init__(self, config):
        self.config = config
        self.logger = logging.getLogger('client_api_server')
        self._db = DataAccessFactory.createSession(config['database']['type'], config)
        self.hubspot_api_key = None
        if self._db.config.get('subscription') and self._db.config['subscription'].get('hubspot_api_key'):
            self.hubspot_api_key = self._db.config['subscription']['hubspot_api_key'].value
        self.zone_name = self.config['server']['zone_name']
        self.provider_manager = ProviderManager(config, self._db, self.logger)
        self.installation_id = str(self._db.getInstallation().installation_id)
        if self._db.hasFilterWithCategorization():
            self.init_webfilter()
        else:
            self.kasm_web_filter = None
        self.logger.info('%s initialized' % self.__class__.__name__)

    
    def init_webfilter(self):
        self.kasm_web_filter = KasmWebFilter(self._db.get_config_setting_value('web_filter', 'web_filter_update_url'), self.installation_id, self.logger)

    
    def is_sso_licensed(logger):
        license_helper = LicenseHelper(cherrypy.request.db, logger)
        return license_helper.is_sso_ok()

    is_sso_licensed = staticmethod(ttl_cache(200, 600, **('maxsize', 'ttl'))(is_sso_licensed))
    
    def is_allow_kasm_sharing_licensed(logger):
        license_helper = LicenseHelper(cherrypy.request.db, logger)
        return license_helper.is_allow_kasm_sharing_ok()

    is_allow_kasm_sharing_licensed = staticmethod(ttl_cache(200, 600, **('maxsize', 'ttl'))(is_allow_kasm_sharing_licensed))
    
    def is_usage_limit_licensed(logger):
        license_helper = LicenseHelper(cherrypy.request.db, logger)
        return license_helper.is_usage_limit_ok()

    is_usage_limit_licensed = staticmethod(ttl_cache(200, 600, **('maxsize', 'ttl'))(is_usage_limit_licensed))
    
    def is_session_recording_licensed(logger):
        license_helper = LicenseHelper(cherrypy.request.db, logger)
        return license_helper.is_session_recording_ok()

    is_session_recording_licensed = staticmethod(ttl_cache(200, 600, **('maxsize', 'ttl'))(is_session_recording_licensed))
    
    def healthcheck(self):
        response = {
            'ok': True }
        cherrypy.request.db.getInstallation()
        return response

    healthcheck = cherrypy.expose([
        '__healthcheck'])(cherrypy.tools.json_out()(Unauthenticated()(healthcheck)))
    
    def acs(self, **params):
        if not self.is_sso_licensed(self.logger):
            return 'Access Denied. This feature is not licensed'
        if None in cherrypy.request.params:
            config = cherrypy.request.db.get_saml_config(cherrypy.request.params['id'])
        else:
            return 'Login Failure: No saml ID in request'
        if None:
            saml = SamlAuthentication(cherrypy.request, config, '/api/acs')
            response = saml.acs()
            if 'error' in response or response['error'] or response['auth'] is False:
                return response['error']
            sanitized_username = None['userid'].strip().lower()
            user = cherrypy.request.db.getUser(sanitized_username)
            if not user:
                license_helper = LicenseHelper(cherrypy.request.db, self.logger)
                if license_helper.is_per_named_user_ok(True, **('with_user_added',)):
                    user = cherrypy.request.db.createUser(sanitized_username, 'saml', cherrypy.request.params['id'], **('username', 'realm', 'saml_id'))
                else:
                    msg = 'License limit exceeded. Unable to create user'
                    self.logger.error(msg)
                    return None
                if None.realm == 'saml':
                    if cherrypy.request.db.serializable(user.saml_id) == cherrypy.request.params['id']:
                        self.process_sso_group_membership(user, response['attributes'].get(config.group_attribute, []), 'saml', config.saml_id)
                        attributes = response['attributes'] if 'attributes' in response else { }
                        for sso_attribute_mapping in config.user_attribute_mappings:
                            if sso_attribute_mapping.attribute_name.lower() == 'debug':
                                self.logger.debug(f'''SAML Attributes: {str(attributes)}''')
                            else:
                                value = sso_attribute_mapping.process_attributes(user, attributes)
                                self.logger.debug(f'''New attribute value ({value}) applied to user {sanitized_username} for {sso_attribute_mapping.user_field}''')
                        if len(config.user_attribute_mappings) > 0:
                            cherrypy.request.db.updateUser(user)
                        priv_key = str.encode(self._db.get_config_setting_value_cached('auth', 'api_private_key'))
                        session_lifetime = int(self._db.get_config_setting_value_cached('auth', 'session_lifetime'))
                        session_token = cherrypy.request.db.createSessionToken(user)
                        user_id = cherrypy.request.db.serializable(user.user_id)
                        session_jwt = session_token.generate_jwt(priv_key, session_lifetime)
                        raise cherrypy.HTTPRedirect(response['base_url'] + '/#/sso/' + user_id + '/' + session_jwt, 302, **('status',))
                    return 'Saml login rejected: different Saml ID expected for user'
                return 'Saml login rejected: Non Saml user'
        self.logger.error('No Saml configuration with that ID found in the acs request')
        return 'Error: wrong Saml ID'

    acs = cherrypy.expose(Unauthenticated()(acs))
    
    def process_sso_group_membership(self, user = None, sso_groups = None, sso_type = None, sso_id = {
        'sso_groups': typing.Dict,
        'sso_type': str,
        'sso_id': str }):
        group_mappings = cherrypy.request.db.getGroupMappingBySsoID(sso_type, sso_id, **('sso_type', 'sso_id'))
        sso_groups = (lambda .0: [ x.lower() for x in .0 ])(sso_groups)
        user_group_ids = (lambda .0: [ x.group_id for x in .0 ])(user.groups)
        distinct_groups = set()
        (lambda .0 = None: [ distinct_groups.add(x.group) for x in .0 ])(group_mappings)
        distinct_groups = list(distinct_groups)
        for group in distinct_groups:
            sso_group_mappings = (lambda .0 = None: [ x for x in .0 if x.sso_id == sso_id ])(group.group_mappings)
            self.logger.debug(f'''Processing Group ({group.name}) with ({len(sso_group_mappings)}) sso_mappings for sso type {sso_type}, id: ({sso_id})''')
            do_add = False
            for group_mapping in sso_group_mappings:
                if group_mapping.apply_to_all_users:
                    do_add = True
                    self.logger.debug(f'''User ({user.username}) should be assigned to group ({group.name}) : Apply to All Users''')
                
                if group_mapping.sso_group_attributes.lower() in sso_groups:
                    self.logger.debug(f'''User ({user.username}) should be assigned to group ({group.name}). Matched group attribute ({group_mapping.sso_group_attributes})''')
                    do_add = True
                    continue
                    if do_add:
                        if group.group_id in user_group_ids:
                            self.logger.debug(f'''User ({user.username}) already a member of group ({group.name}). No Action''')
                        else:
                            self.logger.debug(f'''Adding User ({user.username}) to Group ({group.name})''')
                            cherrypy.request.db.addUserGroup(user, group)
                        continue
            if group.group_id in user_group_ids:
                self.logger.debug(f'''Removing User ({user.username}) from Group ({group.name})''')
                cherrypy.request.db.removeUserGroup(user, group)
                continue
            self.logger.debug(f'''User ({user.username}) is not a member of group ({group.name}). No Action''')

    
    def slo(self, **params):
        if 'id' in cherrypy.request.params:
            config = cherrypy.request.db.get_saml_config(cherrypy.request.params['id'])
        else:
            response = 'No saml ID'
            return response
        if None:
            saml = SamlAuthentication(cherrypy.request, config, '/api/slo')
            (url, name_id) = saml.sls()
            if name_id:
                sanitized_username = name_id.strip().lower()
                user = cherrypy.request.db.getUser(sanitized_username)
                cherrypy.request.db.remove_all_session_tokens(user)
            if not url:
                url = cherrypy.request.base.replace('http', 'https')
            raise cherrypy.HTTPRedirect(url, 301, **('status',))
        self.logger.error('Saml Logout Error: No config for this Saml ID')

    slo = cherrypy.expose(Unauthenticated()(slo))
    
    def sso(self, **params):
        response = { }
        event = cherrypy.request.json
        if 'id' in event:
            if 'sso_type' in event and event['sso_type'] == 'saml_id':
                config = cherrypy.request.db.get_saml_config(event['id'])
                saml = SamlAuthentication(cherrypy.request, config, '/api/sso')
                response['url'] = saml.sso()
            elif 'sso_type' in event and event['sso_type'] == 'oidc_id':
                config = cherrypy.request.db.get_oidc_config(event['id'])
                response['url'] = OIDCAuthentication(config).get_login_url()
            else:
                response['error_message'] = 'No SSO ID'
                return response
            return None

    sso = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Unauthenticated()(sso))))
    
    def sso_login(self, **params):
        if 'id' in cherrypy.request.params:
            id = cherrypy.request.params['id']
            config = cherrypy.request.db.get_saml_config(id)
            if config:
                url = SamlAuthentication(cherrypy.request, config, '/api/sso_login').sso()
                raise cherrypy.HTTPRedirect(url, 301, **('status',))
            config = cherrypy.request.db.get_oidc_config(id)
            if config:
                url = OIDCAuthentication(config).get_login_url()
                raise cherrypy.HTTPRedirect(url, 301, **('status',))
            cherrypy.response.status = 403
        else:
            cherrypy.response.status = 403

    sso_login = cherrypy.expose(Unauthenticated()(sso_login))
    
    def metadata(self, **params):
        response = { }
        if 'id' in cherrypy.request.params:
            config = cherrypy.request.db.get_saml_config(cherrypy.request.params['id'])
        else:
            return 'No saml ID'
        if None:
            saml = SamlAuthentication(cherrypy.request, config, '/api/metadata')
            response = saml.metadata()
            cherrypy.response.headers['Content-Type'] = 'text/xml; charset=utf-8'
        else:
            response['error_message'] = 'No saml Configuration'
        if 'error_message' in response:
            return response['error_message']
        return None['metadata']

    metadata = cherrypy.expose(Unauthenticated()(metadata))
    
    def get_available_storage_providers(self):
        response = {
            'storage_providers': [] }
        user = cherrypy.request.authenticated_user
        is_admin = JWT_AUTHORIZATION.is_authorized_action(cherrypy.request.authorizations, JWT_AUTHORIZATION.STORAGE_PROVIDERS_VIEW)
        if (is_admin or user) and user.get_setting_value('allow_user_storage_mapping', False):
            storage_providers = cherrypy.request.db.get_storage_providers(True, **('enabled',))
            for storage_provider in storage_providers:
                if not is_admin:
                    if storage_provider.storage_provider_type != STORAGE_PROVIDER_TYPES.CUSTOM.value:
                        response['storage_providers'].append({
                            'name': storage_provider.name,
                            'storage_provider_id': str(storage_provider.storage_provider_id),
                            'storage_provider_type': storage_provider.storage_provider_type })
                        continue
                        return response

    get_available_storage_providers = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.USER], True, **('requested_actions', 'read_only'))(get_available_storage_providers))))
    
    def get_storage_mappings(self):
        response = {
            'storage_mappings': [] }
        user = cherrypy.request.authenticated_user
        is_admin = JWT_AUTHORIZATION.any_authorized_actions(cherrypy.request.authorizations, [
            JWT_AUTHORIZATION.USERS_VIEW,
            JWT_AUTHORIZATION.GROUPS_VIEW,
            JWT_AUTHORIZATION.GROUPS_VIEW_IFMEMBER,
            JWT_AUTHORIZATION.GROUPS_VIEW_SYSTEM,
            JWT_AUTHORIZATION.IMAGES_VIEW])
        event = cherrypy.request.json
        target_storage_mapping = event.get('target_storage_mapping', { })
        if target_storage_mapping:
            _user_id = target_storage_mapping.get('user_id')
            _group_id = target_storage_mapping.get('group_id')
            _image_id = target_storage_mapping.get('image_id')
            _storage_mapping_id = target_storage_mapping.get('storage_mapping_id')
            _test = (lambda .0: [ x for x in .0 if x is not None ])((_user_id, _group_id, _image_id, _storage_mapping_id))
            if len(_test) == 1:
                if is_admin:
                    storage_mappings = cherrypy.request.db.get_storage_mappings(_storage_mapping_id, _user_id, _group_id, _image_id, **('storage_mapping_id', 'user_id', 'group_id', 'image_id'))
                    response['storage_mappings'] = []
                    for storage_mapping in storage_mappings:
                        is_authorized = False
                        if storage_mapping.user:
                            if not storage_mapping.user.user_id == user.user_id:
                                pass
                            is_authorized = JWT_AUTHORIZATION.is_user_authorized_action(user, cherrypy.request.authorizations, JWT_AUTHORIZATION.USERS_VIEW, storage_mapping.user, **('target_user',))
                        elif storage_mapping.group:
                            is_authorized = JWT_AUTHORIZATION.is_user_authorized_action(user, cherrypy.request.authorizations, JWT_AUTHORIZATION.GROUPS_VIEW, storage_mapping.group, **('target_group',))
                        elif storage_mapping.image:
                            is_authorized = JWT_AUTHORIZATION.is_authorized_action(cherrypy.request.authorizations, JWT_AUTHORIZATION.IMAGES_VIEW)
                        if is_authorized:
                            response['storage_mappings'].append(cherrypy.request.db.serializable(storage_mapping.jsonDict))
                            continue
                        elif _user_id or _user_id != user.user_id.hex:
                            msg = 'Unauthorized attempt to update storage mappings for other user/group/image'
                            self.logger.error(msg)
                            response['error_message'] = 'Access Denied'
                            return response
                storage_mappings = cherrypy.request.db.get_storage_mappings(user.user_id, **('user_id',))
                for vc in storage_mappings:
                    response['storage_mappings'].append({
                        'storage_mapping_id': str(vc.storage_mapping_id),
                        'storage_provider_type': vc.storage_provider.storage_provider_type,
                        'user_id': str(vc.user_id),
                        'name': vc.name,
                        'storage_provider_id': str(vc.storage_provider_id),
                        'enabled': vc.enabled,
                        'read_only': vc.read_only,
                        'target': vc.target,
                        's3_access_key_id': vc.s3_access_key_id,
                        's3_secret_access_key': '**********',
                        's3_bucket': vc.s3_bucket,
                        'webdav_user': vc.webdav_user,
                        'webdav_pass': '**********' })
            else:
                msg = 'Invalid request. Only one of the following parameters may be defined (storage_mapping_id, user_id, group_id, image_id)'
                self.logger.error(msg)
                response['error_message'] = msg
        else:
            msg = 'Invalid request. Missing required parameters'
            self.logger.error(msg)
            response['error_message'] = msg
        return response

    get_storage_mappings = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.USER], True, **('requested_actions', 'read_only'))(get_storage_mappings))))
    
    def delete_storage_mapping(self):
        response = { }
        user = cherrypy.request.authenticated_user
        event = cherrypy.request.json
        target_storage_mapping = event.get('target_storage_mapping')
        is_admin = JWT_AUTHORIZATION.any_authorized_actions(cherrypy.request.authorizations, [
            JWT_AUTHORIZATION.USERS_MODIFY,
            JWT_AUTHORIZATION.USERS_MODIFY_ADMIN,
            JWT_AUTHORIZATION.GROUPS_MODIFY,
            JWT_AUTHORIZATION.IMAGES_MODIFY,
            JWT_AUTHORIZATION.USERS_VIEW,
            JWT_AUTHORIZATION.GROUPS_VIEW,
            JWT_AUTHORIZATION.IMAGES_VIEW])
        is_authorized = False
        if target_storage_mapping:
            storage_mapping_id = target_storage_mapping.get('storage_mapping_id')
            if storage_mapping_id:
                if is_admin:
                    storage_mapping = cherrypy.request.db.get_storage_mapping(storage_mapping_id, **('storage_mapping_id',))
                    if storage_mapping:
                        if storage_mapping.user:
                            if not user or storage_mapping.user.user_id == user.user_id:
                                pass
                            is_authorized = JWT_AUTHORIZATION.is_user_authorized_action(user, cherrypy.request.authorizations, JWT_AUTHORIZATION.USERS_MODIFY, storage_mapping.user, **('target_user',))
                        elif storage_mapping.group:
                            is_authorized = JWT_AUTHORIZATION.is_user_authorized_action(user, cherrypy.request.authorizations, JWT_AUTHORIZATION.GROUPS_MODIFY, storage_mapping.group, **('target_group',))
                        elif storage_mapping.image:
                            is_authorized = JWT_AUTHORIZATION.is_authorized_action(cherrypy.request.authorizations, JWT_AUTHORIZATION.IMAGES_MODIFY)
                        else:
                            storage_mapping = cherrypy.request.db.get_storage_mapping(storage_mapping_id, user.user_id, **('storage_mapping_id', 'user_id'))
                            is_authorized = True
                if storage_mapping:
                    if not (is_authorized or storage_mapping.storage_provider_type == STORAGE_PROVIDER_TYPES.CUSTOM.value) and is_admin:
                        if not is_authorized:
                            self.logger.error(f'''User ({cherrypy.request.kasm_user_id}) unauthorized to delete storage mapping ({storage_mapping_id}).''')
                        else:
                            self.logger.error(f'''User ({cherrypy.request.kasm_user_id}) unauthorized to delete Custom storage mapping ({storage_mapping_id}).''')
                        response['error_message'] = 'Unauthorized Action'
                        cherrypy.response.status = 401
                        return response
                    None.request.db.delete_storage_mapping(storage_mapping)
                    self.logger.info('Successfully deleted storage_mapping_id (%s)' % storage_mapping_id, {
                        'storage_mapping_id': storage_mapping_id }, **('extra',))
                else:
                    msg = 'Storage Mapping ID (%s) Not found' % storage_mapping_id
                    self.logger.error(msg)
                    response['error_message'] = msg
            else:
                msg = 'Invalid request. Missing required parameters'
                self.logger.error(msg)
                response['error_message'] = msg
        else:
            msg = 'Invalid request. Missing required parameters'
            self.logger.error(msg)
            response['error_message'] = msg
        return response

    delete_storage_mapping = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.USER], False, **('requested_actions', 'read_only'))(delete_storage_mapping))))
    
    def create_storage_mapping(self):
        response = { }
        user = cherrypy.request.authenticated_user
        is_admin = JWT_AUTHORIZATION.any_authorized_actions(cherrypy.request.authorizations, [
            JWT_AUTHORIZATION.USERS_MODIFY,
            JWT_AUTHORIZATION.USERS_MODIFY_ADMIN,
            JWT_AUTHORIZATION.GROUPS_MODIFY,
            JWT_AUTHORIZATION.IMAGES_MODIFY,
            JWT_AUTHORIZATION.USERS_VIEW,
            JWT_AUTHORIZATION.GROUPS_VIEW,
            JWT_AUTHORIZATION.IMAGES_VIEW])
        event = cherrypy.request.json
        target_storage_mapping = event.get('target_storage_mapping')
        if is_admin or user.get_setting_value('allow_user_storage_mapping', False):
            if target_storage_mapping:
                _user_id = target_storage_mapping.get('user_id')
                _group_id = target_storage_mapping.get('group_id')
                _image_id = target_storage_mapping.get('image_id')
                _storage_provider_id = target_storage_mapping.get('storage_provider_id')
                target_user = None
                _test = (lambda .0: [ x for x in .0 if x is not None ])((_user_id, _group_id, _image_id))
                if len(_test) == 1:
                    if not is_admin:
                        if target_storage_mapping.get('target') or target_storage_mapping.get('config'):
                            msg = 'Unauthorized attempt to define restricted storage mapping property'
                            self.logger.error(msg)
                            response['error_message'] = 'Access Denied'
                            return response
                        if None or _user_id != user.user_id.hex:
                            msg = 'Unauthorized attempt to create storage mappings for other user/group/image'
                            self.logger.error(msg)
                            response['error_message'] = 'Access Denied'
                            return response
                        if None:
                            target_user = cherrypy.request.db.get_user_by_id(_user_id, **('user_id',))
                            if target_user:
                                max_user_storage_mappings = target_user.get_setting_value('max_user_storage_mappings', 2)
                                if len(target_user.storage_mappings) >= max_user_storage_mappings:
                                    msg = 'Unable to create storage mapping. Limit exceeded'
                                    self.logger.error(msg)
                                    response['error_message'] = msg
                                    return response
                            msg = 'Invalid user_id'
                            self.logger.error(msg)
                            response['error_message'] = msg
                            return response
                        is_authorized = None
                        if target_user and user and target_user.user_id == user.user_id:
                            is_authorized = True
                        elif is_admin:
                            if target_user:
                                is_authorized = JWT_AUTHORIZATION.is_user_authorized_action(user, cherrypy.request.authorizations, JWT_AUTHORIZATION.USERS_MODIFY, target_user, **('target_user',))
                            elif _group_id:
                                target_group = cherrypy.request.db.getGroup(_group_id, **('group_id',))
                                if target_group:
                                    pass
                                is_authorized = JWT_AUTHORIZATION.is_user_authorized_action(user, cherrypy.request.authorizations, JWT_AUTHORIZATION.GROUPS_MODIFY, target_group, **('target_group',))
                            elif _image_id:
                                is_authorized = JWT_AUTHORIZATION.is_authorized_action(cherrypy.request.authorizations, JWT_AUTHORIZATION.IMAGES_MODIFY)
                    if not is_authorized:
                        self.logger.error(f'''User ({cherrypy.request.kasm_user_id}) attempted to create a storage mapping but is not authorized to modify the target group, user, or image.''')
                        response['error_message'] = 'Unauthorized to modify the target user/group/image for the storage mapping.'
                        response['ui_show_error'] = True
                        cherrypy.response.status = 401
                        return response
                    storage_provider_id = None.get('storage_provider_id')
                    if storage_provider_id:
                        storage_provider = cherrypy.request.db.get_storage_provider(storage_provider_id, **('storage_provider_id',))
                        if storage_provider:
                            jwt_priv_key = str.encode(cherrypy.request.db.get_config_setting_value_cached('auth', 'api_private_key'))
                            encoded_jwt = None
                            if storage_provider.storage_provider_type == STORAGE_PROVIDER_TYPES.GOOGLE_DRIVE.value:
                                (url, encoded_jwt) = GoogleDrive(storage_provider).get_login_url(target_storage_mapping, jwt_priv_key)
                                response['url'] = url
                            elif storage_provider.storage_provider_type == STORAGE_PROVIDER_TYPES.DROPBOX.value:
                                (url, encoded_jwt) = Dropbox(storage_provider).get_login_url(target_storage_mapping, jwt_priv_key)
                                response['url'] = url
                            elif storage_provider.storage_provider_type == STORAGE_PROVIDER_TYPES.ONEDRIVE.value:
                                (url, encoded_jwt) = OneDrive(storage_provider).get_login_url(target_storage_mapping, jwt_priv_key)
                                response['url'] = url
                            elif storage_provider.storage_provider_type == STORAGE_PROVIDER_TYPES.S3.value:
                                error_message = S3(storage_provider).validate_storage_mapping(target_storage_mapping)
                                if error_message:
                                    response['error_message'] = error_message
                                else:
                                    storage_mapping = cherrypy.request.db.create_storage_mapping('%s Storage Mapping' % storage_provider.name, target_storage_mapping.get('enabled'), target_storage_mapping.get('read_only'), target_storage_mapping.get('user_id'), target_storage_mapping.get('group_id'), target_storage_mapping.get('image_id'), target_storage_mapping.get('storage_provider_id'), target_storage_mapping.get('s3_access_key_id'), target_storage_mapping.get('s3_secret_access_key'), target_storage_mapping.get('s3_bucket'), **('name', 'enabled', 'read_only', 'user_id', 'group_id', 'image_id', 'storage_provider_id', 's3_access_key_id', 's3_secret_access_key', 's3_bucket'))
                                    response['storage_mapping'] = cherrypy.request.db.serializable(storage_mapping.jsonDict)
                                    self.logger.info('Successfully created storage_mapping_id (%s)' % storage_mapping.storage_mapping_id, {
                                        'storage_mapping_id': storage_mapping.storage_mapping_id }, **('extra',))
                            elif storage_provider.storage_provider_type == STORAGE_PROVIDER_TYPES.NEXTCLOUD.value:
                                error_message = Nextcloud(storage_provider).validate_storage_mapping(target_storage_mapping)
                                if error_message:
                                    response['error_message'] = error_message
                                else:
                                    storage_mapping = cherrypy.request.db.create_storage_mapping('%s Storage Mapping' % storage_provider.name, target_storage_mapping.get('enabled'), target_storage_mapping.get('read_only'), target_storage_mapping.get('user_id'), target_storage_mapping.get('group_id'), target_storage_mapping.get('image_id'), target_storage_mapping.get('storage_provider_id'), target_storage_mapping.get('webdav_user'), target_storage_mapping.get('webdav_pass'), **('name', 'enabled', 'read_only', 'user_id', 'group_id', 'image_id', 'storage_provider_id', 'webdav_user', 'webdav_pass'))
                                    response['storage_mapping'] = cherrypy.request.db.serializable(storage_mapping.jsonDict)
                                    self.logger.info('Successfully created storage_mapping_id (%s)' % storage_mapping.storage_mapping_id, {
                                        'storage_mapping_id': storage_mapping.storage_mapping_id }, **('extra',))
                            elif storage_provider.storage_provider_type == STORAGE_PROVIDER_TYPES.CUSTOM.value and is_admin:
                                error_message = CustomStorageProvider(storage_provider).validate_storage_mapping(target_storage_mapping)
                                if error_message:
                                    response['error_message'] = error_message
                                else:
                                    storage_mapping = cherrypy.request.db.create_storage_mapping('%s Storage Mapping' % storage_provider.name, target_storage_mapping.get('enabled'), target_storage_mapping.get('read_only'), target_storage_mapping.get('user_id'), target_storage_mapping.get('group_id'), target_storage_mapping.get('image_id'), target_storage_mapping.get('storage_provider_id'), target_storage_mapping.get('webdav_user'), target_storage_mapping.get('webdav_pass'), **('name', 'enabled', 'read_only', 'user_id', 'group_id', 'image_id', 'storage_provider_id', 'webdav_user', 'webdav_pass'))
                                    response['storage_mapping'] = cherrypy.request.db.serializable(storage_mapping.jsonDict)
                                    self.logger.info('Successfully created storage_mapping_id (%s)' % storage_mapping.storage_mapping_id, {
                                        'storage_mapping_id': storage_mapping.storage_mapping_id }, **('extra',))
                            else:
                                msg = 'Unknown Storage Provider Type'
                                self.logger.error(msg)
                                response['error_message'] = msg
                            if encoded_jwt:
                                kasm_auth_domain = self._db.get_config_setting_value('auth', 'kasm_auth_domain')
                                if kasm_auth_domain and kasm_auth_domain.lower() == '$request_host$':
                                    kasm_auth_domain = cherrypy.request.headers['HOST']
                                same_site = self._db.get_config_setting_value('auth', 'same_site')
                                cherrypy.response.cookie['storage_token'] = encoded_jwt
                                cherrypy.response.cookie['storage_token']['Path'] = '/'
                                cherrypy.response.cookie['storage_token']['Max-Age'] = 300
                                cherrypy.response.cookie['storage_token']['Domain'] = kasm_auth_domain
                                cherrypy.response.cookie['storage_token']['Secure'] = True
                                cherrypy.response.cookie['storage_token']['httpOnly'] = True
                                cherrypy.response.cookie['storage_token']['SameSite'] = same_site
                            else:
                                msg = 'Invalid Storage Provider ID (%s)' % storage_provider_id
                                self.logger.error(msg)
                                response['error_message'] = msg
                        else:
                            msg = 'Invalid Request. Missing required parameters'
                            self.logger.error(msg)
                            response['error_message'] = msg
                    else:
                        msg = 'Invalid request. Only one attribute group_id, user_id, or image_id may be set'
                        self.logger.error(msg)
                        response['error_message'] = msg
                else:
                    msg = 'Invalid request. Missing required parameters'
                    self.logger.error(msg)
                    response['error_message'] = msg
            else:
                msg = 'Creating a storage mapping is not allowed for this user'
                self.logger.error(msg)
                response['error_message'] = msg
        return response

    create_storage_mapping = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.USER], False, **('requested_actions', 'read_only'))(create_storage_mapping))))
    
    def update_storage_mapping(self):
        response = { }
        user = cherrypy.request.authenticated_user
        is_admin = JWT_AUTHORIZATION.any_authorized_actions(cherrypy.request.authorizations, [
            JWT_AUTHORIZATION.USERS_MODIFY,
            JWT_AUTHORIZATION.USERS_MODIFY_ADMIN,
            JWT_AUTHORIZATION.GROUPS_MODIFY,
            JWT_AUTHORIZATION.IMAGES_MODIFY,
            JWT_AUTHORIZATION.USERS_VIEW,
            JWT_AUTHORIZATION.GROUPS_VIEW,
            JWT_AUTHORIZATION.IMAGES_VIEW])
        event = cherrypy.request.json
        target_storage_mapping = event.get('target_storage_mapping')
        target_user = None
        if is_admin or user.get_setting_value('allow_user_storage_mapping', False):
            if target_storage_mapping:
                _user_id = target_storage_mapping.get('user_id')
                _group_id = target_storage_mapping.get('group_id')
                _image_id = target_storage_mapping.get('image_id')
                storage_mapping_id = target_storage_mapping.get('storage_mapping_id')
                _test = (lambda .0: [ x for x in .0 if x is not None ])((_user_id, _group_id, _image_id))
                if len(_test) == 1:
                    if not is_admin:
                        if target_storage_mapping.get('target') or target_storage_mapping.get('config'):
                            msg = 'Unauthorized attempt to define target or config in storage mapping'
                            self.logger.error(msg)
                            response['error_message'] = 'Access Denied'
                            return response
                        if None or _user_id != user.user_id.hex:
                            msg = 'Unauthorized attempt to create storage mappings for other user/group/image'
                            self.logger.error(msg)
                            response['error_message'] = 'Access Denied'
                            return response
                        if None:
                            target_user = cherrypy.request.db.get_user_by_id(_user_id, **('user_id',))
                            if target_user:
                                max_user_storage_mappings = target_user.get_setting_value('max_user_storage_mappings', 2)
                                if len(target_user.storage_mappings) >= max_user_storage_mappings:
                                    msg = 'Unable to create storage mapping. Limit exceeded'
                                    self.logger.error(msg)
                                    response['error_message'] = msg
                                    return response
                            msg = 'Invalid user_id'
                            self.logger.error(msg)
                            response['error_message'] = msg
                            return response
                        if None:
                            is_authorized = False
                            if target_user and user and target_user.user_id == user.user_id:
                                is_authorized = True
                            elif is_admin:
                                if target_user:
                                    is_authorized = JWT_AUTHORIZATION.is_user_authorized_action(user, cherrypy.request.authorizations, JWT_AUTHORIZATION.USERS_MODIFY, target_user, **('target_user',))
                                elif _group_id:
                                    target_group = cherrypy.request.db.getGroup(_group_id, **('group_id',))
                                    if target_group:
                                        pass
                                    is_authorized = JWT_AUTHORIZATION.is_user_authorized_action(user, cherrypy.request.authorizations, JWT_AUTHORIZATION.GROUPS_MODIFY, target_group, **('target_group',))
                                elif _image_id:
                                    is_authorized = JWT_AUTHORIZATION.is_authorized_action(cherrypy.request.authorizations, JWT_AUTHORIZATION.IMAGES_MODIFY)
                            if not is_authorized:
                                self.logger.error(f'''User ({cherrypy.request.kasm_user_id}) attempted to update a storage mapping but is not authorized to modify the target group, user, or image.''')
                                response['error_message'] = 'Unauthorized to modify the target user/group/image for the storage mapping.'
                                response['ui_show_error'] = True
                                cherrypy.response.status = 401
                                return response
                            storage_mapping = None.request.db.get_storage_mapping(storage_mapping_id, None if is_admin else user.user_id, **('storage_mapping_id', 'user_id'))
                            if storage_mapping:
                                if not storage_mapping.storage_provider_type == STORAGE_PROVIDER_TYPES.CUSTOM.value and is_admin:
                                    msg = 'Unauthorized attempted to modify Custom Storage mapping'
                                    self.logger.error(msg)
                                    response['error_message'] = 'Access Denied'
                                    return response
                                storage_mapping = None.request.db.update_storage_mapping(storage_mapping, target_storage_mapping.get('name'), target_storage_mapping.get('config') if is_admin else None, target_storage_mapping.get('enabled'), target_storage_mapping.get('read_only'), target_storage_mapping.get('user_id'), target_storage_mapping.get('group_id'), target_storage_mapping.get('image_id'), target_storage_mapping.get('target') if is_admin else None, target_storage_mapping.get('webdav_user'), target_storage_mapping.get('webdav_pass'), target_storage_mapping.get('s3_access_key_id'), target_storage_mapping.get('s3_secret_access_key'), target_storage_mapping.get('s3_bucket'), **('name', 'config', 'enabled', 'read_only', 'user_id', 'group_id', 'image_id', 'target', 'webdav_user', 'webdav_pass', 's3_access_key_id', 's3_secret_access_key', 's3_bucket'))
                                response['storage_mapping'] = cherrypy.request.db.serializable(storage_mapping.jsonDict)
                                self.logger.info('Successfully updated storage_mapping_id (%s)' % storage_mapping.storage_mapping_id, {
                                    'storage_mapping_id': storage_mapping.storage_mapping_id }, **('extra',))
                            else:
                                msg = 'Invalid Storage Mapping ID (%s)' % storage_mapping_id
                                self.logger.error(msg)
                                response['error_message'] = msg
                        else:
                            msg = 'Invalid request. Missing required parameters'
                            self.logger.error(msg)
                            response['error_message'] = msg
                    else:
                        msg = 'Invalid request. Only one attribute group_id, user_id, or image_id may be set'
                        self.logger.error(msg)
                        response['error_message'] = msg
                else:
                    msg = 'Invalid request. Missing required parameters'
                    self.logger.error(msg)
                    response['error_message'] = msg
            else:
                msg = 'Updating a storage mapping is not allowed for this user'
                self.logger.error(msg)
                response['error_message'] = msg
        return response

    update_storage_mapping = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.USER], False, **('requested_actions', 'read_only'))(update_storage_mapping))))
    
    def cloud_storage_callback(self, **params):
        response = None
        state = cherrypy.request.params.get('state')
        user = cherrypy.request.authenticated_user
        is_admin = JWT_AUTHORIZATION.any_authorized_actions(cherrypy.request.authorizations, [
            JWT_AUTHORIZATION.USERS_MODIFY,
            JWT_AUTHORIZATION.IMAGES_MODIFY,
            JWT_AUTHORIZATION.GROUPS_MODIFY])
        callback_url = cherrypy.request.base + cherrypy.request.path_info + '?' + cherrypy.request.query_string
        callback_url = callback_url.replace('http', 'https')
        if state:
            storage_token_cookie = cherrypy.request.cookie.get('storage_token')
            if storage_token_cookie:
                decoded_jwt = self.decode_jwt(storage_token_cookie.value)
                if decoded_jwt:
                    if decoded_jwt.get('state_token') == state:
                        storage_provider_id = decoded_jwt.get('storage_provider_id')
                        user_id = decoded_jwt.get('user_id')
                        group_id = decoded_jwt.get('group_id')
                        image_id = decoded_jwt.get('image_id')
                        return_url = decoded_jwt.get('return_url')
                        enabled = decoded_jwt.get('enabled')
                        read_only = decoded_jwt.get('read_only')
                        if not return_url:
                            return_url = cherrypy.request.base.replace('http', 'https')
                            return_url += '/'
                        _test = (lambda .0: [ x for x in .0 if x is not None ])((user_id, group_id, image_id))
                        if len(_test) == 1:
                            if not is_admin:
                                if user_id or user_id != user.user_id.hex:
                                    msg = 'Unauthorized attempt to create storage mappings for other user/group/image'
                                    self.logger.error(msg)
                                    cherrypy.response.status = 401
                                    response = 'Unauthorized'
                                    return response
                                is_permitted = None
                                if is_admin:
                                    if user_id:
                                        target_user = cherrypy.request.db.get_user_by_id(user_id)
                                        is_permitted = JWT_AUTHORIZATION.is_user_authorized_action(user, cherrypy.request.authorizations, JWT_AUTHORIZATION.USERS_MODIFY, target_user, **('target_user',))
                                    elif group_id:
                                        target_group = cherrypy.request.db.getGroup(group_id, **('group_id',))
                                        is_permitted = JWT_AUTHORIZATION.is_user_authorized_action(user, cherrypy.request.authorizations, JWT_AUTHORIZATION.GROUPS_MODIFY, target_group, **('target_group',))
                                    elif image_id:
                                        is_permitted = JWT_AUTHORIZATION.is_user_authorized_action(user, cherrypy.request.authorizations, JWT_AUTHORIZATION.IMAGES_MODIFY)
                                    if not is_permitted:
                                        msg = 'Unauthorized attempt to create storage mappings for other user/group/image'
                                        self.logger.error(msg)
                                        cherrypy.response.status = 401
                                        response = 'Unauthorized'
                                        return response
                                    storage_provider = None.request.db.get_storage_provider(storage_provider_id, **('storage_provider_id',))
                                    if storage_provider:
                                        oauth_token = None
                                        if storage_provider.storage_provider_type == STORAGE_PROVIDER_TYPES.GOOGLE_DRIVE.value:
                                            oauth_token = GoogleDrive(storage_provider).get_oauth_token(callback_url)
                                        elif storage_provider.storage_provider_type == STORAGE_PROVIDER_TYPES.DROPBOX.value:
                                            oauth_token = Dropbox(storage_provider).get_oauth_token(callback_url)
                                        elif storage_provider.storage_provider_type == STORAGE_PROVIDER_TYPES.ONEDRIVE.value:
                                            oauth_token = OneDrive(storage_provider).get_oauth_token(callback_url)
                                        else:
                                            response = 'Unknown Storage Provider Type (%s)' % storage_provider.storage_provider_type
                                            self.logger.error(response)
                                        if oauth_token:
                                            storage_mapping = cherrypy.request.db.create_storage_mapping('%s Storage Mapping' % storage_provider.name, enabled, read_only, user_id, group_id, image_id, storage_provider_id, oauth_token, **('name', 'enabled', 'read_only', 'user_id', 'group_id', 'image_id', 'storage_provider_id', 'oauth_token'))
                                            self.logger.info('Successfully created storage_mapping_id (%s)' % storage_mapping.storage_mapping_id, {
                                                'storage_mapping_id': storage_mapping.storage_mapping_id }, **('extra',))
                                            raise cherrypy.HTTPRedirect(return_url, 302, **('status',))
                                        response = 'Error Processing Oauth callback for (%s)' % storage_provider.name
                                        self.logger.error(response)
                                    else:
                                        response = 'Missing Storage Provider config for (%s)' % storage_provider_id
                                        self.logger.error(response)
                                else:
                                    response = 'Invalid request. Only one attribute group_id, user_id, or image_id may be set'
                                    self.logger.error(response)
                            else:
                                response = 'Access Denied'
                                self.logger.error('Invalid State Token')
                        else:
                            response = 'Access Denied'
                            self.logger.error('Invalid JWT')
                    else:
                        response = 'Invalid Request. Missing required cookie'
                        self.logger.error(response)
                else:
                    response = 'Invalid request. Missing required parameters'
                    self.logger.error(response)
        return response

    cloud_storage_callback = cherrypy.expose(CookieAuthenticated([
        JWT_AUTHORIZATION.USER], **('requested_actions',))(cloud_storage_callback))
    
    def oidc_callback(self, **params):
        oidc_id = cherrypy.request.params['state'][:32]
        oidc_config = cherrypy.request.db.get_oidc_config(oidc_id)
        oidc_auth = OIDCAuthentication(oidc_config)
        _url = cherrypy.request.base + cherrypy.request.path_info + '?' + cherrypy.request.query_string
        _url = _url.replace('http', 'https')
        user_attributes = oidc_auth.process_callback(_url)
        if user_attributes['username'] and oidc_id:
            sanitized_username = user_attributes['username'].strip().lower()
            user = cherrypy.request.db.getUser(sanitized_username)
            if not user:
                license_helper = LicenseHelper(cherrypy.request.db, self.logger)
                if license_helper.is_per_named_user_ok(True, **('with_user_added',)):
                    user = cherrypy.request.db.createUser(sanitized_username, 'oidc', oidc_id, **('username', 'realm', 'oidc_id'))
                else:
                    msg = 'License limit exceeded. Unable to create user'
                    self.logger.error(msg)
                    return None
                if None.realm == 'oidc':
                    if user.oidc_id and user.oidc_id.hex == oidc_id:
                        self.process_sso_group_membership(user, user_attributes.get('groups', []), 'oidc', oidc_config.oidc_id, **('sso_type', 'sso_id'))
                        session_token = cherrypy.request.db.createSessionToken(user)
                        priv_key = str.encode(cherrypy.request.db.get_config_setting_value_cached('auth', 'api_private_key'))
                        session_lifetime = int(cherrypy.request.db.get_config_setting_value_cached('auth', 'session_lifetime'))
                        session_jwt = session_token.generate_jwt(priv_key, session_lifetime)
                        user_id = cherrypy.request.db.serializable(user.user_id)
                        _url = cherrypy.request.base.replace('http', 'https')
                        _url += '/#/sso/' + user_id + '/' + session_jwt
                        for sso_attribute_mapping in oidc_config.user_attribute_mappings:
                            if sso_attribute_mapping.attribute_name.lower() == 'debug':
                                self.logger.debug(f'''OIDC Attributes: {str(user_attributes)}''')
                            else:
                                value = sso_attribute_mapping.process_attributes(user, user_attributes)
                                self.logger.debug(f'''OIDC attribute value ({value}) applied to user {sanitized_username} for {sso_attribute_mapping.user_field}''')
                        if len(oidc_config.user_attribute_mappings) > 0:
                            cherrypy.request.db.updateUser(user)
                        raise cherrypy.HTTPRedirect(_url, 302, **('status',))
                    return 'OIDC login rejected: different OIDC ID expected for user'
                return 'OIDC login rejected: Non OIDC user'
            return None

    oidc_callback = cherrypy.expose(Unauthenticated()(oidc_callback))
    
    def login_settings(self):
        hostname = cherrypy.request.headers['HOST']
        return self.login_settings_cache(hostname, self.logger)

    login_settings = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Unauthenticated()(login_settings))))
    
    def login_settings_cache(hostname, logger):
        response = { }
        saml_configs = cherrypy.request.db.get_saml_configs()
        for x in saml_configs:
            if x.enabled:
                response['sso_enabled'] = x.enabled
                continue
                oidc_configs = cherrypy.request.db.get_oidc_configs()
                for x in oidc_configs:
                    if x.enabled:
                        response['sso_enabled'] = x.enabled
                        continue
                        branding = None
                        license_helper = LicenseHelper(cherrypy.request.db, logger)
                        if license_helper.is_branding_ok():
                            branding = cherrypy.request.db.get_effective_branding_config(hostname)
                            if branding:
                                response['login_logo'] = branding.login_logo_url
                                response['login_splash_background'] = branding.login_splash_url
                                response['login_caption'] = branding.login_caption
                                response['header_logo'] = branding.header_logo_url
                                response['html_title'] = branding.html_title
                                response['favicon_logo'] = branding.favicon_logo_url
                                response['loading_session_text'] = branding.loading_session_text
                                response['joining_session_text'] = branding.joining_session_text
                                response['destroying_session_text'] = branding.destroying_session_text
                                response['launcher_background_url'] = branding.launcher_background_url
        if not branding:
            internal_branding_config = cherrypy.request.db.get_internal_branding_config()
            response['login_logo'] = internal_branding_config['login_logo_url']
            response['login_splash_background'] = internal_branding_config['login_splash_url']
            response['login_caption'] = internal_branding_config['login_caption']
            response['header_logo'] = internal_branding_config['header_logo_url']
            response['html_title'] = internal_branding_config['html_title']
            response['favicon_logo'] = internal_branding_config['favicon_logo_url']
            response['loading_session_text'] = internal_branding_config['loading_session_text']
            response['joining_session_text'] = internal_branding_config['joining_session_text']
            response['destroying_session_text'] = internal_branding_config['destroying_session_text']
            response['launcher_background_url'] = internal_branding_config['launcher_background_url']
        _s = [
            'login_assistance']
        if license_helper.is_login_banner_ok():
            _s += [
                'notice_message',
                'notice_title']
        settings = (lambda .0: [ cherrypy.request.db.serializable(x.jsonDict) for x in .0 ])(cherrypy.request.db.get_config_settings())
        for x in settings:
            if x['name'] in _s:
                response[x['name']] = x['value']
                continue
                if license_helper.is_login_banner_ok():
                    if 'notice_message' not in response:
                        response['notice_message'] = 'Warning: By using this system you agree to all the terms and conditions.'
                    if 'notice_title' not in response:
                        response['notice_title'] = 'Notice'
        _sc = []
        enabled_configs = list(filter((lambda v: v.enabled), saml_configs))
        matching_configs = None(None((lambda v = None: v.hostname == hostname), enabled_configs))
        if not len(matching_configs):
            matching_configs = list(filter((lambda v: v.is_default), enabled_configs))
        for config in matching_configs:
            _sc.append({
                'display_name': config.display_name,
                'hostname': config.hostname,
                'default': config.is_default,
                'enabled': config.enabled,
                'saml_id': cherrypy.request.db.serializable(config.saml_id),
                'auto_login': config.auto_login,
                'logo_url': config.logo_url })
        response['saml'] = {
            'saml_configs': _sc }
        _oc = []
        enabled_oidc_configs = list(filter((lambda v: v.enabled), oidc_configs))
        matching_oidc_configs = None(None((lambda v = None: v.hostname == hostname), enabled_oidc_configs))
        if not len(matching_oidc_configs):
            matching_oidc_configs = list(filter((lambda v: v.is_default), enabled_oidc_configs))
        for config in matching_oidc_configs:
            _oc.append({
                'display_name': config.display_name,
                'hostname': config.hostname,
                'default': config.is_default,
                'enabled': config.enabled,
                'oidc_id': cherrypy.request.db.serializable(config.oidc_id),
                'auto_login': config.auto_login,
                'logo_url': config.logo_url })
        response['oidc'] = {
            'oidc_configs': _oc }
        response['recaptcha'] = {
            'google_recaptcha_site_key': '' }
        google_recaptcha_site_key = cherrypy.request.db.get_config_setting_value('auth', 'google_recaptcha_site_key')
        if google_recaptcha_site_key:
            response['recaptcha']['google_recaptcha_site_key'] = google_recaptcha_site_key
        return response

    login_settings_cache = staticmethod(ttl_cache(200, 30, **('maxsize', 'ttl'))(login_settings_cache))
    
    def login_saml(self):
        response = { }
        event = cherrypy.request.json
        cherrypy.response.status = 403
        if 'user_id' in event and 'session_token' in event:
            
            try:
                user = cherrypy.request.db.get_user_by_id(event['user_id'])
            finally:
                pass
            except Exception:
                self.logger.error('User was sent with invalid user_id')
                response['error_message'] = 'Invalid user ID'
                return None
            else:
                pub_cert = str.encode(self._db.get_config_setting_value_cached('auth', 'api_public_cert'))
                decoded_jwt = jwt.decode(event['session_token'], pub_cert, 'RS256', **('algorithm',))

            return response

    login_saml = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Unauthenticated()(login_saml))))
    
    def authenticate(self):
        response = { }
        cherrypy.response.status = 403
        event = cherrypy.request.json
        return response

    authenticate = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Unauthenticated()(authenticate))))
    
    def encrypt_client_data(self, client_key, data):
        client_key_b64_bytes = base64.urlsafe_b64decode(client_key)
        if len(client_key_b64_bytes) != 32:
            raise Exception(f'''Invalid client key length {len(client_key)}''')
        install_id_bytes = None.installation_id.replace('-', '').encode('ascii')
        key = client_key_b64_bytes[0:16] + install_id_bytes[0:16]
        key_b64 = base64.urlsafe_b64encode(key)
        fernet = Fernet(key_b64)
        return fernet.encrypt(data).decode('utf-8')

    
    def decrypt_client_data(self, client_key, encrypted_data):
        client_key_b64_bytes = base64.urlsafe_b64decode(client_key)
        if len(client_key_b64_bytes) != 32:
            raise Exception('Invalid client key length')
        install_id_bytes = None.installation_id.replace('-', '').encode('ascii')
        key = client_key_b64_bytes[0:16] + install_id_bytes[0:16]
        key_b64 = base64.urlsafe_b64encode(key)
        fernet = Fernet(key_b64)
        return fernet.decrypt(encrypted_data.encode())

    
    def set_secret_authenticated(self):
        response = { }
        event = cherrypy.request.json
        user = cherrypy.request.authenticated_user
        if not user.get_setting_value('allow_2fa_self_enrollment', False):
            self.logger.warning('User (%s) attempted to call set_secret_authenticated, but self_enrollment is disabled.', event['username'])
            response['error_message'] = 'Self Enrollment is not permitted'
            return response
        check_resp = None.check_password()
        if 'error_message' in check_resp:
            self.logger.warning('Invalid password to set_secret_authenticated for user (%s)', event['username'])
            response['error_message'] = check_resp['error_message']
            return response
        set_secret_resp = None._set_secret(event, user)
        if 'error_message' in set_secret_resp:
            self.logger.warning('set_secret for User (%s) failed', event['username'])
            if set_secret_resp['error_message'] == 'Access Denied':
                response['error_message'] = 'Failure Setting secret'
            else:
                response['error_message'] = set_secret_resp['error_message']
            return response

    set_secret_authenticated = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.USER], False, **('requested_actions', 'read_only'))(set_secret_authenticated))))
    
    def set_secret(self):
        response = { }
        event = cherrypy.request.json
        cherrypy.response.status = 403
        if 'username' not in event or 'password' not in event:
            self.logger.warning('Invalid call to set_secret')
            response['error_message'] = 'Access Denied'
            return response
        user = None.request.db.getUser(event['username'].strip().lower())
        auth_resp = self.authenticate()
        if 'error_message' in auth_resp:
            self.logger.warning('Authentication failed on attempt to set 2fa secret for user: (%s)' % event['username'])
            response['error_message'] = auth_resp['error_message']
            return response
        if not None.get('require_2fa'):
            self.logger.warning('User attempted to set two factor token when 2fa is not enabled for the user: (%s)' % event['username'])
            response['error_message'] = 'Access Denied'
            return response
        return None._set_secret(event, user)

    set_secret = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Unauthenticated()(set_secret))))
    
    def _set_secret(self, event, user):
        response = { }
        if not user.get_setting_value('allow_totp_2fa', True):
            self.logger.warning('User (%s) attempted to call set_secret, but totp is not allowed')
            response['error_message'] = 'TOTP is not permitted for user. Access Denied.'
            return response
        if None.set_two_factor and 'target_token' not in event:
            self.logger.warning('User attempted to set secret on 2fa when secret is already set: (%s)' % event['username'])
            response['error_message'] = 'Access Denied'
            return response
        if None in event:
            if 'serial_number' not in event['target_token']:
                self.logger.warning('User attempted to self assign a token but no serial number provided: (%s)' % event['username'])
                response['error_message'] = 'Access Denied'
                return response
            token = None.request.db.get_physical_token(event['target_token']['serial_number'])
            if token and token.user is None:
                token = cherrypy.request.db.assign_physical_token(token, user)
                self.logger.info(f'''User ({event['username']}) self assign token with serial number ({event['target_token']['serial_number']}).''')
            elif token and token.user:
                self.logger.warning(f'''User ({event['username']}) attempted to self assign a token but the token serial number ({event['target_token']['serial_number']}) is already assigned.''')
                token = None
            else:
                self.logger.warning(f'''User ({event['username']}) attempted to self assign a token but the token serial number ({event['target_token']['serial_number']}) was not found.''')
                token = None
        return response

    
    def two_factor_auth_authenticated(self):
        event = cherrypy.request.json
        response = { }
        user = cherrypy.request.authenticated_user
        if 'username' not in event and 'password' not in event or 'code' not in event:
            self.logger.warning('Invalid call to two_factor_auth')
            response['error_message'] = 'Access Denied'
            return response
        check_resp = None.check_password()
        if 'error_message' in check_resp:
            self.logger.warning('Invalid password to set_secret_authenticated for user (%s)', event['username'])
            response['error_message'] = check_resp['error_message']
            return response
        two_factor_resp = None._two_factor_auth(event, user)
        if 'error_message' in two_factor_resp:
            self.logger.warning('Error when user (%s) made call to two_factor_auth_authenticated', event['username'])
            if two_factor_resp['error_message'] == 'Access Denied':
                response['error_message'] = 'Two Factor Auth Failed'
            else:
                response['error_message'] = two_factor_resp['error_message']
            return response

    two_factor_auth_authenticated = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.USER], False, **('requested_actions', 'read_only'))(two_factor_auth_authenticated))))
    
    def two_factor_auth(self):
        event = cherrypy.request.json
        response = { }
        if 'username' not in event and 'password' not in event or 'code' not in event:
            self.logger.warning('Invalid call to two_factor_auth')
            response['error_message'] = 'Access Denied'
            return response
        user = None.request.db.getUser(event['username'].strip().lower())
        if user is None:
            self.logger.warning('Invalid user (%s)' % event['username'])
            response['error_message'] = 'Access Denied'
            return response
        auth_resp = None.authenticate()
        if 'error_message' in auth_resp:
            self.logger.warning('Authentication failed on 2fa attempt for user: (%s)' % event['username'])
            response['error_message'] = auth_resp['error_message']
            return response
        return None._two_factor_auth(event, user)

    two_factor_auth = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Unauthenticated()(two_factor_auth))))
    
    def _two_factor_auth(self, event, user):
        response = { }
        if not user.get_setting_value('allow_totp_2fa', True):
            self.logger.warning('User (%s) attempted to login with totp, but it is disabled')
            response['error_message'] = 'TOTP is not permitted for user. Access Denied.'
            cherrypy.response.status = 401
            return response
        if not None.get_setting_value('require_2fa', False) and user.get_setting_value('allow_2fa_self_enrollment', False):
            self.logger.warning('User attempted to set two factor token when 2fa is not enabled for the user: (%s)' % event['username'])
            response['error_message'] = 'Access Denied'
            return response
        if None.locked:
            self.logger.warning('Two factor auth failed for locked account: (%s)' % event['username'])
            response['error_message'] = 'Access Denied'
            return response
        totp = None.TOTP(user.secret)
        token_drift_max = self._db.get_config_setting_value_cached('auth', 'token_drift_max')
        token_drift_max = int(token_drift_max) if token_drift_max is not None and token_drift_max.isnumeric() else 1
        if token_drift_max > 10:
            self.logger.warning(f'''Invalid token drift of {token_drift_max} configured, applying a maximum of 10.''')
            token_drift_max = 10
        is_token_code_match = False
        for minute_drift in range(0, token_drift_max + 1):
            td1 = minute_drift * 60
            td2 = td1 + 30
            self.logger.debug(f'''Checking 2fa token code for User ({user.username}) with delta between {td1} and {td2} seconds''')
            if not event['code'] == totp.at(datetime.datetime.now() - datetime.timedelta(td1, **('seconds',)), **('for_time',)) and event['code'] == totp.at(datetime.datetime.now() - datetime.timedelta(td2, **('seconds',)), **('for_time',)) and event['code'] == totp.at(datetime.datetime.now() + datetime.timedelta(td1, **('seconds',)), **('for_time',)):
                if event['code'] == totp.at(datetime.datetime.now() + datetime.timedelta(td2, **('seconds',)), **('for_time',)):
                    is_token_code_match = True
                    self.logger.info(f'''Valid 2fa token code for User ({user.username}) with delta between {td1} and {td2} seconds''')
                
                if not is_token_code_match:
                    response['error_message'] = 'Token did not match'
                    self.logger.warning(f'''Token did not match for 2fa attempt for user: {event['username']}''')
                    user.failed_pw_attempts += 1
                    user.locked = user.failed_pw_attempts >= int(self._db.get_config_setting_value('auth', 'max_login_attempts'))
                    if user.locked:
                        response['error_message'] = 'Account Locked'
                    cherrypy.request.db.updateUser(user)
                    return response
                if not None.set_two_factor:
                    user.set_two_factor = True
                    cherrypy.request.db.updateUser(user)
                    self.logger.info('User (%s) successfully registered token.' % user.username)
        response = self._generate_auth_resp(user, event, response)
        user.failed_pw_attempts = 0
        cherrypy.request.db.updateUser(user)
        return response

    
    def set_password(self):
        response = { }
        event = cherrypy.request.json
        user = cherrypy.request.authenticated_user
        if 'current_password' in event and 'new_password' in event:
            if user.realm == 'ldap':
                ldap_configs = cherrypy.request.db.get_ldap_configs()
                for ldap_config in ldap_configs:
                    if ldap_config.enabled:
                        ldap_auth = LDAPAuthentication(ldap_config)
                        if ldap_auth.match_domain(user.username):
                            ldap_response = ldap_auth.set_password(user.username, event['new_password'])
                            if ldap_response.error:
                                response['error_message'] = ldap_response.error
                                self.logger.warning('Password reset attempted failed for user: (%s) because: (%s)' % (user.username, ldap_response.error), {
                                    'metric_name': 'account.password_reset.failed_ldap_error' }, **('extra',))
                                continue
                    self.logger.info(f'''User ({user.username}) ldap password successfully changed.''')
            elif user.realm == 'saml':
                message = 'Error. Changing passwords for SAML users is not supported. Please contact an administrator'
                self.logger.warning(message)
                response['error_message'] = message
            elif user.realm == 'oidc':
                message = 'Error. Changing passwords for OIDC users is not supported. Please contact an administrator'
                self.logger.warning(message)
                response['error_message'] = message
            elif user.locked:
                message = 'Access Denied! User account is locked out. Please contact an administrator'
                self.logger.warning(message)
                response['error_message'] = message
            else:
                hashy = hashlib.sha256(event['current_password'].encode() + user.salt.encode()).hexdigest()
                if hashy == user.pw_hash:
                    pwr = passwordComplexityCheck(event['new_password'])
                    if pwr['status']:
                        user = cherrypy.request.db.getUser(event['username'])
                        user.pw_hash = hashlib.sha256(event['new_password'].encode() + user.salt.encode()).hexdigest()
                        if 'set_two_factor' in event and event['set_two_factor'] is True:
                            user.set_two_factor = False
                            user.secret = ''
                        cherrypy.request.db.updateUser(user)
                        self.logger.info(f'''User ({user.username}) local password successfully changed.''', {
                            'metric_name': 'account.password_reset.successful' }, **('extra',))
                        cherrypy.request.db.remove_all_session_tokens(user)
                    else:
                        response['error_message'] = pwr['message']
                else:
                    message = 'Access Denied! Invalid Current Password.'
                    user.failed_pw_attempts += 1
                    user.locked = user.failed_pw_attempts >= int(self._db.get_config_setting_value('auth', 'max_login_attempts'))
                    if user.locked:
                        message = message + ' User is now locked out.'
                    cherrypy.request.db.updateUser(user)
                    self.logger.warning(message)
                    response['error_message'] = message
        else:
            message = 'Invalid Request. Missing one or more required parameters'
            self.logger.warning(message)
            response['error_message'] = message
        return response

    set_password = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.USER], False, **('requested_actions', 'read_only'))(set_password))))
    
    def reset_password(self):
        response = { }
        event = cherrypy.request.json
        if 'username' not in event and 'current_password' not in event or 'new_password' not in event:
            self.logger.warning('Invalid call to set password')
            response['error_message'] = 'Access Denied'
            return response
        if None['current_password'] == event['new_password']:
            self.logger.info(f'''User ({event['username']}) attempted to reuse old password.''')
            response['error_message'] = 'Cannot set new password to the old password.'
            return response
        sanitized_username = None['username'].strip().lower()
        user = cherrypy.request.db.getUser(sanitized_username)
        event['password'] = event['current_password']
        auth_resp = self.authenticate()
        if ('error_message' not in auth_resp or 'reason' in auth_resp) and auth_resp['reason'] == 'expired_password':
            if user and user.realm == 'saml':
                message = 'Error. Changing passwords for SAML users is not supported. Please contact an administrator'
                self.logger.warning(message)
                response['error_message'] = message
            elif user and user.realm == 'oidc':
                message = 'Error. Changing passwords for OIDC users is not supported. Please contact an administrator'
                self.logger.warning(message)
                response['error_message'] = message
            elif user or user.realm == 'ldap':
                ldap_configs = cherrypy.request.db.get_ldap_configs()
                for ldap_config in ldap_configs:
                    if ldap_config.enabled:
                        ldap_auth = LDAPAuthentication(ldap_config)
                        if ldap_auth.match_domain(sanitized_username):
                            ldap_response = ldap_auth.set_password(sanitized_username, event['new_password'])
                            if ldap_response.error:
                                response['error_message'] = ldap_response.error
                                self.logger.warning('Password reset attempted failed for user: (%s) because: (%s)' % (sanitized_username, ldap_response.error), {
                                    'metric_name': 'account.password_reset.failed_ldap_error' }, **('extra',))
                            else:
                                self.logger.info(f'''User ({sanitized_username}) ldap password successfully changed.''', {
                                    'metric_name': 'account.password_reset.successful' }, **('extra',))
                    return response
                self.logger.warning(f'''Invalid username ({event['username']})''')
            elif user:
                if user.locked:
                    message = 'Access Denied! User account is locked out. Please contact an administrator'
                    self.logger.warning(message)
                    response['error_message'] = message
                else:
                    pwr = passwordComplexityCheck(event['new_password'])
                    if pwr['status']:
                        user.pw_hash = hashlib.sha256(event['new_password'].encode() + user.salt.encode()).hexdigest()
                        user.password_set_date = datetime.datetime.utcnow()
                        if 'set_two_factor' in event and event['set_two_factor'] is True:
                            user.set_two_factor = False
                            user.secret = ''
                        cherrypy.request.db.updateUser(user)
                        self.logger.info(f'''User ({user.username}) local password successfully changed.''', {
                            'metric_name': 'account.password_reset.successful' }, **('extra',))
                        cherrypy.request.db.remove_all_session_tokens(user)
                    else:
                        response['error_message'] = pwr['message']
            else:
                self.logger.warning(f'''User ({event['username']}) attempted to reset password with invalid credentials.''')
                response['error_message'] = auth_resp['error_message']
        return response

    reset_password = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Unauthenticated()(reset_password))))
    
    def new_session_token(self):
        event = cherrypy.request.json
        response = { }
        user = cherrypy.request.db.getUser(event['username'])
        session_token = cherrypy.request.db.updateSessionToken(cherrypy.request.session_token_id)
        if session_token is not None:
            priv_key = str.encode(self._db.get_config_setting_value_cached('auth', 'api_private_key'))
            session_lifetime = int(self._db.get_config_setting_value_cached('auth', 'session_lifetime'))
            session_jwt = session_token.generate_jwt(priv_key, session_lifetime)
            response['token'] = session_jwt
            response['is_admin'] = JWT_AUTHORIZATION.any_admin_action(cherrypy.request.authorizations)
            response['authorized_views'] = JWT_AUTHORIZATION.get_authorized_views(session_token.get_authorizations())
            response['is_anonymous'] = user.anonymous
            response['dashboard_redirect'] = user.get_setting_value('dashboard_redirect', None)
            response['require_subscription'] = user.get_setting_value('require_subscription', None)
            response['has_subscription'] = user.has_subscription
            response['has_plan'] = user.has_plan
            kasm_auth_domain = self._db.get_config_setting_value('auth', 'kasm_auth_domain')
            same_site = self._db.get_config_setting_value('auth', 'same_site')
            if kasm_auth_domain and kasm_auth_domain.lower() == '$request_host$':
                kasm_auth_domain = cherrypy.request.headers['HOST']
            cherrypy.response.cookie['session_token'] = session_jwt
            cherrypy.response.cookie['session_token']['Path'] = '/'
            cherrypy.response.cookie['session_token']['Max-Age'] = session_lifetime
            cherrypy.response.cookie['session_token']['Domain'] = kasm_auth_domain
            cherrypy.response.cookie['session_token']['Secure'] = True
            cherrypy.response.cookie['session_token']['httpOnly'] = True
            cherrypy.response.cookie['session_token']['SameSite'] = same_site
            cherrypy.response.cookie['username'] = user.username
            cherrypy.response.cookie['username']['Path'] = '/'
            cherrypy.response.cookie['username']['Max-Age'] = session_lifetime
            cherrypy.response.cookie['username']['Domain'] = kasm_auth_domain
            cherrypy.response.cookie['username']['Secure'] = True
            cherrypy.response.cookie['username']['httpOnly'] = True
            cherrypy.response.cookie['username']['SameSite'] = same_site
        else:
            response['error_message'] = 'Invalid session token'
            self.logger.info('Invalid session token used to request a new token for user (%s)' % user.username)
        return response

    new_session_token = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.USER], False, **('requested_actions', 'read_only'))(new_session_token))))
    
    def request_kasm(self):
        return self._request_kasm()

    request_kasm = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.USER], False, **('requested_actions', 'read_only'))(func_timing(request_kasm)))))
    
    def _request_kasm(self, cast_config = (None,)):
        event = cherrypy.request.json
        user = cherrypy.request.authenticated_user
        is_admin = JWT_AUTHORIZATION.any_authorized_actions(cherrypy.request.authorizations, [
            JWT_AUTHORIZATION.REPORTS_VIEW])
        response = { }
        license_helper = LicenseHelper(cherrypy.request.db, self.logger)
        kasms = cherrypy.request.db.get_kasms(user)
        if user is None:
            if cherrypy.request.is_api:
                msg = f'''DevAPI Key ({cherrypy.request.api_key_id}) made invalid call to impersonate a user without providing a user_id.'''
            else:
                msg = 'Invalid Request'
            self.logger.error(msg)
            response['error_message'] = msg
            cherrypy.response.status = 400
            return response
        if None.get_setting_value('max_kasms_per_user') is None:
            max_kasms = 2
        else:
            max_kasms = int(user.get_setting_value('max_kasms_per_user'))
        if (max_kasms == 0 or kasms) and len(kasms) >= max_kasms:
            msg = 'Kasm limit exceeded for user: (%s)' % user.username
            self.logger.warning(msg)
            response['error_message'] = msg
        elif check_usage(user) and self.is_usage_limit_licensed(self.logger):
            msg = 'Usage limit exceeded for user: (%s)' % user.username
            self.logger.warning(msg)
            response['error_message'] = msg
        elif not license_helper.is_per_named_user_ok():
            msg = 'Per named user license limit exceeded. Unable to create Kasm'
            self.logger.error(msg)
            response['error_message'] = msg
        elif not license_helper.is_per_concurrent_kasm_ok():
            msg = 'Per concurrent session license limit exceeded. Unable to create session'
            self.logger.error(msg)
            response['error_message'] = msg
    # WARNING: Decompyle incomplete

    
    def kasm_connect_cache(session_token, username, kasm_id):
        ret = {
            'log': {
                'level': None,
                'message': None },
            'port_map': None,
            'kasm_server_hostname': None }
        auth_enabled = cherrypy.request.db.get_config_setting_value('auth', 'enable_kasm_auth')
        if auth_enabled is not None and auth_enabled.lower() == 'true':
            if username and session_token:
                if validate_session_token_ex(session_token, username):
                    user = cherrypy.request.db.getUser(username)
                    if user:
                        cherrypy.request.authenticated_user = user
                        cherrypy.request.kasm_user_id = str(user.user_id)
                        cherrypy.request.kasm_user_name = user.username
                        kasm = cherrypy.request.db.getKasm(kasm_id)
                        if kasm:
                            if (kasm.user_id == user.user_id or kasm.share_id) and kasm.kasm_id in (lambda .0: [ x.kasm_id for x in .0 ])(user.session_permissions):
                                if kasm.image.is_container:
                                    ret['connection_type'] = CONNECTION_TYPE.KASMVNC.value
                                    ret['port_map'] = kasm.get_port_map()
                                    ret['connect_address'] = kasm.server.hostname
                                elif kasm.server.is_rdp and kasm.server.is_vnc or kasm.server.is_ssh:
                                    ret['connection_type'] = kasm.server.connection_type
                                    connection_proxy = None
                                    connection_proxies = cherrypy.request.db.get_connection_proxies(kasm.server.zone_id, CONNECTION_PROXY_TYPE.GUAC.value, **('zone_id', 'connection_proxy_type'))
                                    random.shuffle(connection_proxies)
                                    for x in connection_proxies:
                                        if is_healthy('https://%s:%s/guac/__healthcheck' % (x.server_address, x.server_port), **('url',)):
                                            connection_proxy = x
                                        
                                        if not connection_proxy:
                                            connection_proxy = connection_proxies[0]
                                    ret['connect_address'] = connection_proxy.server_address
                                    ret['connect_port'] = connection_proxy.server_port
                                    ret['port_map'] = kasm.get_port_map()
                                elif kasm.server.is_kasmvnc:
                                    ret['connection_type'] = kasm.server.connection_type
                                    ret['port_map'] = kasm.get_port_map()
                                    ret['connect_address'] = kasm.server.hostname
                                else:
                                    ret['log']['level'] = logging.WARNING
                                    ret['log']['message'] = 'Unauthorized access attempt to kasm_id (%s) by user (%s)' % (kasm.kasm_id, user.username)
                            else:
                                ret['log']['level'] = logging.WARNING
                                ret['log']['message'] = 'Invalid kasm_id (%s)' % kasm_id
                        else:
                            ret['log']['level'] = logging.ERROR
                            ret['log']['message'] = 'Invalid User (%s)' % username
                    elif username == 'kasm_api_user':
                        kasm = cherrypy.request.db.getKasm(kasm_id)
                        if kasm:
                            if kasm.api_token and session_token == kasm.api_token:
                                ret['port_map'] = kasm.get_port_map()
                                ret['connect_address'] = kasm.server.hostname
                            else:
                                ret['log']['level'] = logging.WARNING
                                ret['log']['message'] = 'Unauthorized attempt to use kasm_api_user'
                        else:
                            ret['log']['level'] = logging.WARNING
                            ret['log']['message'] = 'Invalid kasm_id (%s)' % kasm_id
                    else:
                        ret['log']['level'] = logging.WARNING
                        ret['log']['message'] = 'Invalid session token presented for user (%s)' % username
                else:
                    ret['log']['level'] = logging.WARNING
                    ret['log']['message'] = 'Missing username or session token and kasm authorization is enabled'
            else:
                kasm = cherrypy.request.db.getKasm(kasm_id)
                if kasm:
                    ret['port_map'] = kasm.get_port_map()
                    ret['connect_address'] = kasm.server.hostname
                else:
                    ret['log']['level'] = logging.WARNING
                    ret['log']['message'] = 'Invalid kasm_id (%s)' % kasm_id
        return ret

    kasm_connect_cache = staticmethod(ttl_cache(200, 30, **('maxsize', 'ttl'))(kasm_connect_cache))
    
    def kasm_connect(self):
        cherrypy.response.status = 403
        original_uri = cherrypy.request.headers.get('X-Original-URI')
    # WARNING: Decompyle incomplete

    kasm_connect = cherrypy.expose(CookieAuthenticated([
        JWT_AUTHORIZATION.USER], **('requested_actions',))(kasm_connect))
    
    def decode_jwt(self, token):
        
        try:
            pub_cert = str.encode(self._db.get_config_setting_value_cached('auth', 'api_public_cert'))
            decoded_jwt = jwt.decode(token, pub_cert, 'RS256', **('algorithm',))
        finally:
            pass
        except jwt.exceptions.DecodeError:
            return None
        else:
            return decoded_jwt


    
    def guac_get_deleted_kasms(self):
        event = cherrypy.request.json
        response = { }
        connection_proxy_id = cherrypy.request.decoded_jwt.get('connection_proxy_id', None)
        requested_kasms = event.get('kasms')
        if requested_kasms and connection_proxy_id:
            connection_proxy = cherrypy.request.db.get_connection_proxy(connection_proxy_id)
            if connection_proxy:
                kasms = cherrypy.request.db.getKasmsIn(requested_kasms, 'running')
                response['running_kasms'] = (lambda .0: [ x.kasm_id.hex for x in .0 ])(kasms)
                response['deleted_kasms'] = (lambda .0 = None: [ x for x in .0 if x not in response['running_kasms'] ])(requested_kasms)
            else:
                msg = 'Connection Proxy by id (%s) not found' % connection_proxy_id
                self.logger.error(msg)
                response['error_message'] = msg
        else:
            msg = 'Error. Missing required parameters'
            self.logger.error(msg)
            response['error_message'] = msg
        return response

    guac_get_deleted_kasms = cherrypy.expose()(cherrypy.tools.json_in()(cherrypy.tools.json_out()(JwtAuthenticated([
        JWT_AUTHORIZATION.GUAC], **('authorizations',))(guac_get_deleted_kasms))))
    
    def guac_get_managers(self):
        event = cherrypy.request.json
        response = { }
        connection_proxy_id = cherrypy.request.decoded_jwt.get('connection_proxy_id', None)
        connection_proxy = cherrypy.request.db.get_connection_proxy(connection_proxy_id)
        if connection_proxy:
            response = {
                'hostnames': [] }
            managers = cherrypy.request.db.getManagers(connection_proxy.zone.zone_name, **('zone_name',))
            for manager in managers:
                d = cherrypy.request.db.serializable(manager.jsonDict)
                response['hostnames'].append(d['manager_hostname'])
        else:
            msg = 'Connection Proxy by id (%s) not found' % connection_proxy_id
            self.logger.error(msg)
            response['error_message'] = msg
        return cherrypy.request.db.serializable(response)

    guac_get_managers = cherrypy.expose()(cherrypy.tools.json_in()(cherrypy.tools.json_out()(JwtAuthenticated([
        JWT_AUTHORIZATION.GUAC], **('authorizations',))(guac_get_managers))))
    
    def guac_auth(self):
        event = cherrypy.request.json
        user = cherrypy.request.authenticated_user
        response = { }
        kasm_id = event.get('kasm_id')
        service = event.get('service')
        connection_proxy_auth_token = event.get('auth_token')
        
        try:
            pub_cert = str.encode(cherrypy.request.db.get_config_setting_value_cached('auth', 'api_public_cert'))
            decoded_jwt = jwt.decode(connection_proxy_auth_token, pub_cert, 'RS256', **('algorithm',))
            authorized = False
            if 'authorizations' in decoded_jwt:
                for authorization in decoded_jwt['authorizations']:
                    if JWT_AUTHORIZATION.is_authorized(authorization, [
                        JWT_AUTHORIZATION.GUAC]):
                        authorized = True
                except jwt.exceptions.DecodeError:
                    self.logger.error('Error decoding JWT token')
                    response['error_message'] = 'Access Denied.'
                    cherrypy.response.status = 403
                    return None
                    except jwt.exceptions.ExpiredSignatureError:
                        response
                        self.logger.error('Error, expired JWT token')
                        response['error_message'] = 'Access Denied.'
                        cherrypy.response.status = 403
                        return None
                    elif authorized:
                        connection_proxy_id = decoded_jwt.get('connection_proxy_id', None)
                        connection_proxy = cherrypy.request.db.get_connection_proxy(connection_proxy_id)
                        if connection_proxy:
                            kasm = cherrypy.request.db.getKasm(kasm_id)
                            if kasm and kasm.user.username == user.username:
                                if kasm.server.connection_info:
                                    connection_info = kasm.server.connection_info.copy()
                                elif kasm.server.is_rdp:
                                    connection_info = json.loads(self._db.get_config_setting_value('connections', 'default_vm_rdp_connection_settings'))
                                elif kasm.server.is_vnc:
                                    connection_info = json.loads(self._db.get_config_setting_value('connections', 'default_vm_vnc_connection_settings'))
                                elif kasm.server.is_ssh:
                                    connection_info = json.loads(self._db.get_config_setting_value('connections', 'default_vm_ssh_connection_settings'))
                                else:
                                    msg = 'Unknown connection type'
                                    self.logger.error(msg)
                                    response['error_message'] = msg
                                    return response
                                username = None
                                password = ''
                                private_key = ''
                                if kasm.server.max_simultaneous_sessions == 1:
                                    username = kasm.server.connection_username
                                    password = kasm.server.connection_password
                                elif (kasm.server.connection_username or '{sso_username}' in kasm.server.connection_username) and '{sso_create_user}' in kasm.server.connection_username or kasm.server.is_ssh:
                                    username = kasm.server.connection_username
                                if kasm.server.connection_password or '{sso_cred}' in kasm.server.connection_password or kasm.server.is_ssh:
                                    password = kasm.server.connection_password
                                if username is None:
                                    username = ''
                                if password is None:
                                    password = ''
                                if kasm.server.is_ssh:
                                    pass
                                if '{sso_username}' in username:
                                    username = kasm.server.get_connection_username(user)
                                if password.strip() == '{sso_cred}':
                                    kasm_client_key = event.get('kasm_client_key')
                                    if kasm_client_key and user.sso_ep:
                                        password = self.decrypt_client_data(kasm_client_key.encode(), user.sso_ep)
                                        self.logger.debug(f'''SSO credential passthrough completed for {username}.''')
                                    elif user.sso_ep:
                                        password = ''
                                        self.logger.warning(f'''Client {user.username} guac_auth connection set to use SSO but no client key cookie present.''')
                                    else:
                                        password = ''
                                        self.logger.warning(f'''Client {user.username} guac_auth connection set to use SSO but no sso_ep set.''')
                                if username == '{sso_create_user}':
                                    username = kasm.server.get_connection_username(user)
                                    password = kasm.connection_credential
                                if 'guac' not in connection_info:
                                    connection_info['guac'] = { }
                                if 'settings' not in connection_info['guac']:
                                    connection_info['guac']['settings'] = { }
                                connection_info['guac']['settings']['username'] = username
                                connection_info['guac']['settings']['password'] = password
                                if kasm.server.is_ssh:
                                    if private_key:
                                        connection_info['guac']['settings']['private-key'] = private_key
                                    if kasm.server.connection_passphrase:
                                        connection_info['guac']['settings']['passphrase'] = kasm.server.connection_passphrase
                                connection_info['guac']['settings']['hostname'] = kasm.server.hostname
                                connection_info['guac']['settings']['port'] = kasm.server.connection_port
                                if kasm.connection_info and 'guac' in kasm.connection_info and 'settings' in kasm.connection_info['guac']:
                                    if 'remote-app' in kasm.connection_info['guac']['settings'] and '' in kasm.connection_info['guac']['settings']['remote-app']:
                                        connection_info['guac']['settings']['remote-app'] = kasm.connection_info['guac']['settings']['remote-app']
                                    if 'timezone' in kasm.connection_info['guac']['settings'].keys() and 'timezone' not in connection_info['guac']['settings']:
                                        self.logger.debug(f'''Setting user timezone: {kasm.connection_info['guac']['settings']['timezone']}''')
                                        connection_info['guac']['settings']['timezone'] = kasm.connection_info['guac']['settings']['timezone']
                                    if 'locale' in kasm.connection_info['guac']['settings'].keys() and 'locale' not in connection_info['guac']['settings']:
                                        self.logger.debug(f'''Setting user locale: {kasm.connection_info['guac']['settings']['locale']}''')
                                        connection_info['guac']['settings']['locale'] = kasm.connection_info['guac']['settings']['locale']
                                    if 'printer-name' in kasm.connection_info['guac']['settings'].keys() and 'printer-name' not in connection_info['guac']['settings']:
                                        self.logger.debug(f'''Setting printer name: {kasm.connection_info['guac']['settings']['printer-name']}''')
                                        connection_info['guac']['settings']['printer-name'] = kasm.connection_info['guac']['settings']['printer-name']
                                    if not ('remote-app' in kasm.connection_info['guac']['settings'] or '' in kasm.connection_info['guac']['settings']['remote-app']) and 'timezone' in kasm.connection_info['guac']['settings'].keys() and 'locale' in kasm.connection_info['guac']['settings'].keys():
                                        self.logger.warning('A Kasm session utilizing guac has a connection_info defined without specifying any supported connection settings.')
                                response['connection_info'] = connection_info
                                priv_key = str.encode(cherrypy.request.db.get_config_setting_value_cached('auth', 'api_private_key'))
                                response['jwt_token'] = generate_jwt_token({
                                    'system_username': username,
                                    'username': user.username,
                                    'user_id': str(user.user_id) }, [
                                    JWT_AUTHORIZATION.USER], priv_key, 4095, **('expires_days',))
                                response['client_secret'] = generate_guac_client_secret(self.installation_id, str(user.user_id))
                                settings = cherrypy.request.db.get_default_client_settings(user, kasm.cast_config_id)
                                response['client_settings'] = {
                                    'allow_kasm_uploads': settings['allow_kasm_uploads'],
                                    'allow_kasm_downloads': settings['allow_kasm_downloads'],
                                    'allow_kasm_clipboard_up': settings['allow_kasm_clipboard_up'],
                                    'allow_kasm_clipboard_down': settings['allow_kasm_clipboard_down'],
                                    'allow_kasm_clipboard_seamless': settings['allow_kasm_clipboard_seamless'],
                                    'allow_kasm_audio': settings['allow_kasm_audio'],
                                    'allow_kasm_microphone': settings['allow_kasm_microphone'],
                                    'allow_kasm_printing': settings['allow_kasm_printing'] }
                                if user.get_setting_value('record_sessions', False) and self.is_session_recording_licensed(self.logger):
                                    storage_key = cherrypy.request.db.get_config_setting_value('session_recording', 'recording_object_storage_key')
                                    storage_secret = cherrypy.request.db.get_config_setting_value('session_recording', 'recording_object_storage_secret')
                                    storage_location_url = cherrypy.request.db.get_config_setting_value('session_recording', 'session_recording_upload_location')
                                    framerate = cherrypy.request.db.get_config_setting_value('session_recording', 'session_recording_framerate')
                                    width = cherrypy.request.db.get_config_setting_value('session_recording', 'session_recording_res_width')
                                    height = cherrypy.request.db.get_config_setting_value('session_recording', 'session_recording_res_height')
                                    bitrate = cherrypy.request.db.get_config_setting_value('session_recording', 'session_recording_bitrate')
                                    queue_length = cherrypy.request.db.get_config_setting_value('session_recording', 'session_recording_queue_length')
                                    retention_period = cherrypy.request.db.get_config_setting_value('session_recording', 'session_recording_retention_period')
                                    disk_usage_limit = cherrypy.request.db.get_config_setting_value('session_recording', 'session_recording_guac_disk_limit')
                                    if storage_key and storage_secret and storage_location_url and framerate and width and height and bitrate and queue_length and retention_period and disk_usage_limit:
                                        response['record_sessions'] = user.get_setting_value('record_sessions', False)
                                        response['session_recording_framerate'] = framerate
                                        response['session_recording_width'] = width
                                        response['session_recording_height'] = height
                                        response['session_recording_bitrate'] = bitrate
                                        response['session_recording_queue_length'] = queue_length
                                        response['session_recording_retention_period'] = retention_period
                                        response['session_recording_guac_disk_limit'] = disk_usage_limit
                                    else:
                                        msg = 'Session recording is enabled, but not all session recording settings are present. Aborting session'
                                        self.logger.error(msg)
                                        response['error_message'] = msg
                                        return response
                                response['record_sessions'] = False
                                if user.get_setting_value('record_sessions', False):
                                    self.logger.error('Session recording is configured but not licensed. Will not enable.')
                                kasm.connection_proxy_id = connection_proxy_id
                                cherrypy.request.db.updateKasm(kasm)
                            elif not kasm:
                                msg = f'''Kasm not found {kasm_id}'''
                                self.logger.error(msg)
                                response['error_message'] = msg
                            else:
                                msg = 'Invalid User for Kasm'
                                self.logger.error(msg)
                                response['error_message'] = msg
                        else:
                            msg = 'Missing required parameters'
                            self.logger.error(msg)
                            response['error_message'] = msg
                    else:
                        self.logger.error(f'''Invalid JWT token utilized on guac_auth: {decoded_jwt}''')
                        response['error_message'] = 'Access Denied!'
            return response


    guac_auth = cherrypy.expose()(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.USER], True, **('requested_actions', 'read_only'))(guac_auth))))
    
    def internal_auth(self):
        auth_enabled = self._db.get_config_setting_value_cached('auth', 'enable_kasm_auth')
        if auth_enabled is not None and auth_enabled.lower() != 'true':
            cherrypy.response.status = 202
        else:
            cherrypy.response.status = 403
        if 'X-Original-URI' not in cherrypy.request.headers:
            return None
        requested_file = None.request.headers.get('X-Original-URI')
        requested_file_path = requested_file.split('/')
        requested_file_relative = requested_file_path[len(requested_file_path) - 1]
    # WARNING: Decompyle incomplete

    internal_auth = cherrypy.expose(CookieAuthenticated([
        JWT_AUTHORIZATION.USER], **('requested_actions',))(internal_auth))
    
    def join_kasm(self):
        return self._join_kasm()

    join_kasm = cherrypy.expose()(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.USER], True, **('requested_actions', 'read_only'))(join_kasm))))
    
    def _join_kasm(self):
        event = cherrypy.request.json
        response = { }
    # WARNING: Decompyle incomplete

    
    def get_recent_kasms(self):
        event = cherrypy.request.json
        response = {
            'viewed_kasms': [],
            'dead_kasms': [] }
        if 'kasms' in event:
            for share_kasm in event['kasms']:
                _kasm = { }
                kasm = cherrypy.request.db.getSharedKasm(share_kasm)
                if kasm is not None:
                    _kasm['image'] = kasm.image.friendly_name
                    _kasm['image_src'] = kasm.image.image_src
                    _kasm['user'] = kasm.user.username
                    _kasm['share_id'] = kasm.share_id
                    response['viewed_kasms'].append(_kasm)
                    continue
                response['dead_kasms'].append(share_kasm)
            return response

    get_recent_kasms = cherrypy.expose()(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.USER], True, **('requested_actions', 'read_only'))(get_recent_kasms))))
    
    def get_kasm_frame_stats(self):
        event = cherrypy.request.json
        response = { }
        kasm = cherrypy.request.db.getKasm(event['kasm_id'])
        user = cherrypy.request.authenticated_user
        client = event['client'] if 'client' in event else 'auto'
    # WARNING: Decompyle incomplete

    get_kasm_frame_stats = cherrypy.expose()(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.USER], True, **('requested_actions', 'read_only'))(get_kasm_frame_stats))))
    
    def get_kasm_bottleneck_stats(self):
        event = cherrypy.request.json
        response = { }
        kasm = cherrypy.request.db.getKasm(event['kasm_id'])
        user = cherrypy.request.authenticated_user
    # WARNING: Decompyle incomplete

    get_kasm_bottleneck_stats = cherrypy.expose()(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.USER], True, **('requested_actions', 'read_only'))(get_kasm_bottleneck_stats))))
    
    def get_kasm_screenshot(self, kasm_id, width, height = ('', 300, 300)):
        cherrypy.response.status = 404
        kasm = cherrypy.request.db.getKasm(kasm_id)
    # WARNING: Decompyle incomplete

    get_kasm_screenshot = cherrypy.expose([
        'get_kasm_screenshot'])(CookieAuthenticated([
        JWT_AUTHORIZATION.USER], **('requested_actions',))(get_kasm_screenshot))
    
    def get_kasm_status(self):
        event = cherrypy.request.json
        response = { }
        kasm = cherrypy.request.db.getKasm(event['kasm_id'])
        user = cherrypy.request.authenticated_user
        if 'skip_agent_check' not in event:
            event['skip_agent_check'] = False
    # WARNING: Decompyle incomplete

    get_kasm_status = cherrypy.expose([
        'get_user_kasm'])(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.USER], True, **('requested_actions', 'read_only'))(func_timing(get_kasm_status)))))
    
    def exec_kasm(self):
        event = cherrypy.request.json
        response = { }
        if 'target_kasm' in event:
            target_kasm = event['target_kasm']
            if 'kasm_id' in target_kasm and 'kasm_exec' in target_kasm:
                kasm = cherrypy.request.db.getKasm(target_kasm['kasm_id'])
                user = cherrypy.request.authenticated_user
                kasm_exec = target_kasm['kasm_exec']
                kasm_url = target_kasm.get('kasm_url', '')
                response = self._exec_kasm(kasm, user, kasm_exec, kasm_url)
            else:
                msg = 'Missing required parameters'
                self.logger.error(msg)
                response['error_message'] = msg
        else:
            msg = 'Missing required parameters'
            self.logger.error(msg)
            response['error_message'] = msg
        return response

    exec_kasm = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.USER], False, **('requested_actions', 'read_only'))(exec_kasm))))
    
    def _exec_kasm(self, kasm, user, kasm_exec, kasm_url):
        response = { }
    # WARNING: Decompyle incomplete

    
    def logout(self):
        event = cherrypy.request.json
        user = cherrypy.request.authenticated_user
        session_token_id = cherrypy.request.session_token_id
        response = { }
    # WARNING: Decompyle incomplete

    logout = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.USER], False, **('requested_actions', 'read_only'))(logout))))
    
    def get_client_settings(self):
        user = cherrypy.request.authenticated_user
        response = cherrypy.request.db.get_default_client_settings(user)
        return response

    get_client_settings = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.USER], True, **('requested_actions', 'read_only'))(get_client_settings))))
    
    def get_default_images(self):
        return self._get_default_images()

    get_default_images = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.USER], True, **('requested_actions', 'read_only'))(get_default_images))))
    
    def _get_default_images(self):
        response = { }
        user = cherrypy.request.authenticated_user
        user_image = cherrypy.request.db.getUserAttributes(user)
        if user_image is not None:
            response['user_image'] = cherrypy.request.db.serializable(user_image.default_image)
        group_image = user.get_setting_value('default_image')
        if group_image is not None:
            response['group_image'] = group_image
        return response

    
    def get_user_attributes(self):
        response = { }
        response['user_attributes'] = self.get_attributes_for_user(cherrypy.request.authenticated_user)
        return response

    get_user_attributes = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.USER], True, **('requested_actions', 'read_only'))(get_user_attributes))))
    
    def get_attributes_for_user(self, user):
        attr = cherrypy.request.db.getUserAttributes(user)
        res = {
            'user_attributes_id': cherrypy.request.db.serializable(attr.user_attributes_id),
            'default_image': cherrypy.request.db.serializable(attr.default_image),
            'show_tips': cherrypy.request.db.serializable(attr.show_tips),
            'auto_login_kasm': cherrypy.request.db.serializable(attr.user_login_to_kasm),
            'user_id': cherrypy.request.db.serializable(attr.user_id),
            'toggle_control_panel': cherrypy.request.db.serializable(attr.toggle_control_panel),
            'theme': cherrypy.request.db.serializable(attr.theme),
            'chat_sfx': cherrypy.request.db.serializable(attr.chat_sfx),
            'ssh_public_key': cherrypy.request.db.serializable(attr.ssh_public_key),
            'preferred_language': cherrypy.request.db.serializable(attr.preferred_language),
            'preferred_timezone': cherrypy.request.db.serializable(attr.preferred_timezone) }
        return res

    
    def update_user_attribute(self):
        return self._update_user_attribute()

    update_user_attribute = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.USER], False, **('requested_actions', 'read_only'))(update_user_attribute))))
    
    def _update_user_attribute(self, public = (False,)):
        response = { }
        event = cherrypy.request.json
    # WARNING: Decompyle incomplete

    
    def keepalive(self):
        event = cherrypy.request.json
        user = cherrypy.request.authenticated_user
        response = { }
        if 'kasm_id' in event and event.get('kasm_id'):
            kasm = cherrypy.request.db.getKasm(event['kasm_id'])
            if kasm:
                if kasm.user.username == event['username']:
                    return self._keepalive(kasm, user)
                None.logger.error('Invalid user for kasm_id (%s) for keepalive request for user (%s)' % (event['kasm_id'], event['username']))
                response['error_message'] = 'Keepalive Error'
            else:
                self.logger.warning('Invalid kasm_id (%s) for keepalive request for user (%s)' % (event['kasm_id'], event['username']))
                response['error_message'] = 'Keepalive Error'
        else:
            self.logger.error('Missing kasm_id for keepalive request for user (%s)' % event['username'])
            response['error_message'] = 'Keepalive Error'
        return response

    keepalive = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.USER], False, **('requested_actions', 'read_only'))(keepalive))))
    
    def _keepalive(self, kasm, user):
        response = { }
        kasm_status = kasm.get_operational_status()
    # WARNING: Decompyle incomplete

    
    def destroy_kasm(self):
        event = cherrypy.request.json
        user = cherrypy.request.authenticated_user
        response = { }
    # WARNING: Decompyle incomplete

    destroy_kasm = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.USER], False, **('requested_actions', 'read_only'))(func_timing(destroy_kasm)))))
    
    def stop_kasm(self):
        event = cherrypy.request.json
        user = cherrypy.request.authenticated_user
        response = { }
    # WARNING: Decompyle incomplete

    stop_kasm = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.USER], False, **('requested_actions', 'read_only'))(func_timing(stop_kasm)))))
    
    def pause_kasm(self):
        event = cherrypy.request.json
        user = cherrypy.request.authenticated_user
        response = { }
        kasm_id = event.get('kasm_id')
        is_admin = JWT_AUTHORIZATION.is_authorized_action(cherrypy.request.authorizations, JWT_AUTHORIZATION.SESSIONS_MODIFY)
    # WARNING: Decompyle incomplete

    pause_kasm = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.USER], False, **('requested_actions', 'read_only'))(func_timing(pause_kasm)))))
    
    def resume_kasm(self):
        event = cherrypy.request.json
        user = cherrypy.request.authenticated_user
        response = { }
        kasm_id = event.get('kasm_id')
        license_helper = LicenseHelper(cherrypy.request.db, self.logger)
    # WARNING: Decompyle incomplete

    resume_kasm = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.USER], False, **('requested_actions', 'read_only'))(func_timing(resume_kasm)))))
    
    def get_user_images(self):
        event = cherrypy.request.json
        user = cherrypy.request.db.getUser(event['username'])
        result = []
        all_categories = []
        images = self._get_user_images(user)
        for image_id in images.keys():
            images[image_id]['image_id'] = image_id
            result.append(images[image_id])
            all_categories += images[image_id]['categories']
        all_categories = list(set(all_categories))
        all_categories = sorted(all_categories, (lambda x: x.lower()), **('key',))
        return {
            'images': cherrypy.request.db.serializable(result),
            'all_categories': all_categories,
            'disabled_image_message': user.get_setting_value('disabled_image_message', '') }

    get_user_images = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.USER], True, **('requested_actions', 'read_only'))(get_user_images))))
    
    def _get_user_images(self, user):
        data = dict()
        show_disabled_images = user.get_setting_value('show_disabled_images', False)
        images = user.get_images(not show_disabled_images, **('only_enabled',))
        zones = []
        all_network_names = None
        allow_zone_selection = user.get_setting_value('allow_zone_selection', False)
        if allow_zone_selection:
            zones.append({
                'zone_id': '',
                'zone_name': 'Auto' })
            all_zones = cherrypy.request.db.getZones()
            if all_zones:
                for zone in sorted(all_zones, (lambda x: x.zone_name.lower()), **('key',)):
                    zones.append({
                        'zone_id': zone.zone_id,
                        'zone_name': zone.zone_name })
        for image in images:
            _zones = zones
            _image_networks = []
            if allow_zone_selection and image.restrict_to_zone and image.zone_id:
                _zones = [
                    {
                        'zone_id': '',
                        'zone_name': 'Auto' },
                    {
                        'zone_id': str(image.zone_id),
                        'zone_name': image.zone.zone_name }]
            if image.allow_network_selection:
                if image.restrict_to_network:
                    _image_networks = [
                        {
                            'network_id': '',
                            'network_name': 'Auto' }]
                    for n in image.restrict_network_names:
                        _image_networks.append({
                            'network_id': n,
                            'network_name': n })
                elif all_network_names == None:
                    _network_names = self._get_network_names()
                    all_network_names = [
                        {
                            'network_id': '',
                            'network_name': 'Auto' }]
                    for n in _network_names:
                        all_network_names.append({
                            'network_id': n,
                            'network_name': n })
                    _image_networks = all_network_names
                else:
                    _image_networks = all_network_names
            data[cherrypy.request.db.serializable(image.image_id)] = {
                'name': image.name,
                'friendly_name': image.friendly_name,
                'description': image.description,
                'image_src': image.image_src,
                'available': image.available if image.is_container else True,
                'cores': image.cores,
                'memory': image.memory,
                'memory_friendly': '%sMB' % int(int(image.memory) / 1000000),
                'persistent_profile_settings': image.get_persistent_profile_permissions(user),
                'zones': _zones,
                'networks': _image_networks,
                'categories': image.categories,
                'default_category': image.default_category,
                'enabled': image.enabled,
                'hidden': image.hidden,
                'image_type': image.image_type,
                'link_url': image.link_url,
                'launch_config': image.launch_config }
        return data

    
    def get_user_kasms(self):
        user = cherrypy.request.authenticated_user
        response = {
            'kasms': [],
            'current_time': str(datetime.datetime.utcnow()) }
        for kasm in cherrypy.request.db.get_kasms(user):
            response['kasms'].append(self.get_normalized_kasm(kasm))
        return cherrypy.request.db.serializable(response)

    get_user_kasms = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.USER], True, **('requested_actions', 'read_only'))(get_user_kasms))))
    
    def get_normalized_kasm(self, kasm):
        _kasm = cherrypy.request.db.serializable(kasm.__dict__, [
            'user',
            'image',
            'docker_environment'], **('skip_fields',))
        _kasm['is_persistent_profile'] = kasm.is_persistent_profile
        _kasm['persistent_profile_mode'] = kasm.persistent_profile_mode
        _kasm['port_map'] = kasm.get_port_map()
        _kasm['token'] = ''
        _kasm['view_only_token'] = ''
        _kasm.pop('api_token', None)
    # WARNING: Decompyle incomplete

    
    def get_normalized_shared_kasm(self, kasm, user):
        _kasm = { }
        _kasm['port_map'] = kasm.get_port_map()
        _kasm['view_only_token'] = ''
        _kasm['user'] = {
            'username': kasm.user.username }
        if 'uploads' in _kasm['port_map']:
            del _kasm['port_map']['uploads']
        if 'audio_input' in _kasm['port_map']:
            del _kasm['port_map']['audio_input']
        if 'webcam' in _kasm['port_map']:
            del _kasm['port_map']['webcam']
    # WARNING: Decompyle incomplete

    
    def update_user(self):
        return self._update_user()

    update_user = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.USER], False, **('requested_actions', 'read_only'))(update_user))))
    
    def _update_user(self, public = (True,)):
        response = { }
        event = cherrypy.request.json
        remove_tokens = False
        if 'target_user' in event:
            target_user = event['target_user']
            if 'user_id' in target_user:
                user = cherrypy.request.db.get_user_by_id(target_user['user_id'])
                if user:
                    is_admin = JWT_AUTHORIZATION.is_user_authorized_action(cherrypy.request.authenticated_user, cherrypy.request.authorizations, JWT_AUTHORIZATION.USERS_MODIFY, user, **('target_user',))
                    if (is_admin or cherrypy.request.authenticated_user) and cherrypy.request.authenticated_user.user_id == target_user['user_id']:
                        if not target_user.get('username'):
                            response['error_message'] = 'Username is not present'
                        if target_user.get('password'):
                            remove_tokens = True
                            if user.realm not in ('local', 'ldap'):
                                response['error_message'] = 'Passwords can only be set on local and ldap accounts.'
                            pwr = passwordComplexityCheck(target_user['password'])
                            if not pwr['status']:
                                response['error_message'] = pwr['message']
                        if target_user.get('company_id'):
                            if cherrypy.request.db.getCompany(target_user['company_id'], **('company_id',)):
                                user.company_id = target_user['company_id']
                            else:
                                response['error_message'] = 'Company does not exist by id (%s)' % target_user['company_id']
                        group = None
                        if target_user.get('program_id'):
                            group = cherrypy.request.db.getGroup(target_user['program_id'], **('program_id',))
                            if group:
                                user.program_id = target_user.get('program_id')
                            else:
                                msg = 'Unknown program_id (%s)' % target_user.get('program_id')
                                self.logger.error(msg)
                                response['error_message'] = msg
                        status = target_user.get('status')
                        if status:
                            if status == 'active':
                                target_user['locked'] = False
                            elif status == 'inactive':
                                target_user['locked'] = True
                            else:
                                msg = 'Invalid Status (%s)' % status
                                self.logger.error(msg)
                                response['error_message'] = msg
                        if not response.get('error_message'):
                            if target_user.get('username'):
                                user.username = target_user['username'].strip().lower()[:255]
                            if target_user.get('password'):
                                if user.realm == 'local':
                                    user.salt = str(uuid.uuid4())
                                    user.pw_hash = hashlib.sha256((target_user['password'] + user.salt).encode()).hexdigest()
                                    user.locked = False
                                    user.password_set_date = datetime.datetime.utcnow()
                                    self.logger.info(f'''User ({user.username}) local password successfully changed.''', {
                                        'metric_name': 'account.password_reset.successful' }, **('extra',))
                                elif user.realm == 'ldap':
                                    ldap_configs = cherrypy.request.db.get_ldap_configs()
                                    for ldap_config in ldap_configs:
                                        if ldap_config.enabled:
                                            ldap_auth = LDAPAuthentication(ldap_config)
                                            if ldap_auth.match_domain(user.username):
                                                ldap_response = ldap_auth.set_password(user.username, target_user['password'])
                                                if ldap_response.error:
                                                    response['error_message'] = ldap_response.error
                                                    self.logger.warning('Password reset attempted failed for user: (%s) because: (%s)' % (user.username, ldap_response.error), {
                                                        'metric_name': 'account.password_reset.failed_ldap_error' }, **('extra',))
                                                else:
                                                    self.logger.info(f'''User ({user.username}) ldap password successfully changed.''', {
                                                        'metric_name': 'account.password_reset.successful' }, **('extra',))
                            if target_user.get('first_name') != None:
                                user.first_name = target_user['first_name'][:64]
                            if target_user.get('last_name') != None:
                                user.last_name = target_user['last_name'][:64]
                            if target_user.get('phone') != None:
                                user.phone = target_user['phone'][:64]
                            if target_user.get('organization') != None:
                                user.organization = target_user['organization'][:64]
                            if target_user.get('notes') != None:
                                user.notes = target_user['notes']
                            if target_user.get('city') != None:
                                user.city = target_user['city']
                            if target_user.get('state') != None:
                                user.state = target_user['state']
                            if target_user.get('country') != None:
                                user.country = target_user['country']
                            if target_user.get('email') != None:
                                user.email = target_user['email']
                            if target_user.get('custom_attribute_1') != None:
                                user.custom_attribute_1 = target_user['custom_attribute_1']
                            if target_user.get('custom_attribute_2') != None:
                                user.custom_attribute_2 = target_user['custom_attribute_2']
                            if target_user.get('custom_attribute_3') != None:
                                user.custom_attribute_3 = target_user['custom_attribute_3']
                            if is_admin:
                                if target_user.get('realm') != None:
                                    user.realm = target_user['realm']
                                if target_user.get('locked'):
                                    user.locked = True
                                elif target_user.get('locked') == False:
                                    user.locked = False
                                    user.failed_pw_attempts = 0
                                if target_user.get('force_password_reset', False) == True:
                                    user.password_set_date = None
                                if target_user.get('disabled') != None:
                                    user.disabled = target_user['disabled']
                            if target_user.get('set_two_factor') is not None and target_user.get('set_two_factor') is True:
                                user.set_two_factor = False
                                user.secret = ''
                            if target_user.get('reset_webauthn'):
                                user.set_two_factor = False
                                cherrypy.request.db.delete_webauthn_credentials(user.user_id)
                            cherrypy.request.db.updateUser(user)
                            if remove_tokens:
                                cherrypy.request.db.remove_all_session_tokens(user)
                            if group:
                                if group.group_id not in user.get_group_ids():
                                    self.logger.debug('Adding user (%s) to Group: name(%s), ID (%s)' % (user.user_id, group.name, group.group_id))
                                    cherrypy.request.db.addUserGroup(user, group)
                                for user_group in user.groups:
                                    if user_group.group.program_data and user_group.group.program_data.get('program_id') != target_user['program_id']:
                                        self.logger.debug('Removing user (%s) from Group: name(%s), ID (%s)' % (user.user_id, user_group.group.name, user_group.group.group_id))
                                        cherrypy.request.db.removeUserGroup(user, user_group.group)
                                        continue
                                        response['user'] = cherrypy.request.db.serializable({
                                            'user_id': user.user_id,
                                            'username': user.username,
                                            'locked': user.locked,
                                            'disabled': user.disabled,
                                            'last_session': user.last_session,
                                            'groups': user.get_groups(),
                                            'first_name': user.first_name,
                                            'last_name': user.last_name,
                                            'phone': user.phone,
                                            'organization': user.organization,
                                            'notes': user.notes,
                                            'realm': user.realm })
                                        self.logger.debug('Updated User ID (%s)' % target_user['user_id'])
                                    elif public:
                                        cherrypy.response.status = 400
                                    else:
                                        response['error_message'] = 'Unauthorized'
                                        self.logger.warning(f'''User ({cherrypy.request.kasm_user_id}) attempted to make unauthorized update to user ({user.user_id})''')
                                        cherrypy.response.status = 401
                                response['error_message'] = 'Unknown User'
                                if public:
                                    cherrypy.response.status = 400
                                else:
                                    response['error_message'] = 'Invalid Request'
                                    if public:
                                        cherrypy.response.status = 400
                                    else:
                                        response['error_message'] = 'Invalid Request'
                                        if public:
                                            cherrypy.response.status = 400
        return response

    
    def get_user(self):
        return self._get_user(False, **('public',))

    get_user = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.USER], True, **('requested_actions', 'read_only'))(get_user))))
    
    def _get_user(self, public = (False,)):
        response = { }
        event = cherrypy.request.json
        if 'target_user' in event:
            target_user = event['target_user']
            user = None
            if 'user_id' in target_user:
                target_user_id = None
                
                try:
                    target_user_id = uuid.UUID(target_user['user_id'])
                finally:
                    pass
                if target_user_id:
                    user = cherrypy.request.db.get_user_by_id(target_user['user_id'])
                elif 'username' in target_user:
                    user = cherrypy.request.db.getUser(target_user['username'])

            if user:
                is_admin = JWT_AUTHORIZATION.is_user_authorized_action(cherrypy.request.authenticated_user, cherrypy.request.authorizations, JWT_AUTHORIZATION.USERS_VIEW, user, **('target_user',))
                if (is_admin or cherrypy.request.authenticated_user) and cherrypy.request.authenticated_user.user_id == user.user_id:
                    kasms = []
                    if (JWT_AUTHORIZATION.is_authorized_action(cherrypy.request.authorizations, JWT_AUTHORIZATION.SESSIONS_VIEW) or cherrypy.request.authenticated_user) and cherrypy.request.authenticated_user.user_id == user.user_id:
                        for kasm in user.kasms:
                            kasms.append({
                                'kasm_id': kasm.kasm_id,
                                'start_date': kasm.start_date,
                                'keepalive_date': kasm.keepalive_date,
                                'expiration_date': kasm.expiration_date,
                                'server': {
                                    'server_id': kasm.server.server_id if kasm.server else None,
                                    'hostname': kasm.server.hostname if kasm.server else None,
                                    'port': kasm.server.port if kasm.server else None } })
                    two_factor = user.get_setting_value('require_2fa', False)
                    response['user'] = cherrypy.request.db.serializable({
                        'user_id': user.user_id,
                        'username': user.username,
                        'locked': user.locked,
                        'disabled': user.disabled,
                        'last_session': user.last_session,
                        'groups': user.get_groups(),
                        'first_name': user.first_name,
                        'last_name': user.last_name,
                        'phone': user.phone,
                        'organization': user.organization,
                        'notes': user.notes,
                        'kasms': kasms,
                        'realm': user.realm,
                        'two_factor': two_factor,
                        'program_id': user.program_id,
                        'created': user.created,
                        'password_set_date': user.password_set_date,
                        'city': user.city,
                        'state': user.state,
                        'country': user.country,
                        'email': user.email,
                        'custom_attribute_1': user.custom_attribute_1,
                        'custom_attribute_2': user.custom_attribute_2,
                        'custom_attribute_3': user.custom_attribute_3 })
                    self.logger.debug('Fetched User ID (%s)' % user.user_id)
                else:
                    response['error_message'] = 'Unauthorized'
                    cherrypy.response.status = 401
                    self.logger.error(f'''User ({cherrypy.request.kasm_user_name}) is not authorized to view target user ({target_user}).''')
            elif 'error_message' not in response:
                self.logger.warning(f'''Unable to locate target_user ({target_user}).''')
                response['error_message'] = 'Invalid Request'
                if public:
                    cherrypy.response.status = 400
                elif 'error_message' not in response:
                    response['error_message'] = 'Invalid Request'
                    self.logger.warning('Request is missing required target_user.')
                    if public:
                        cherrypy.response.status = 400
        return response

    
    def get_user_permissions(self):
        response = { }
        event = cherrypy.request.json
        if 'target_user' in event and 'user_id' in event['target_user']:
            target_user = event['target_user']
            target_user_id = None
            
            try:
                target_user_id = uuid.UUID(target_user['user_id'])
            finally:
                pass
            if target_user_id:
                user = cherrypy.request.db.get_user_by_id(target_user['user_id'])
                if user:
                    is_admin = JWT_AUTHORIZATION.is_user_authorized_action(cherrypy.request.authenticated_user, cherrypy.request.authorizations, JWT_AUTHORIZATION.USERS_VIEW, user, **('target_user',))
                    if (is_admin or cherrypy.request.authenticated_user) and cherrypy.request.authenticated_user.user_id == target_user_id:
                        response['permissions'] = (lambda .0: [ cherrypy.request.db.serializable(x.jsonDict) for x in .0 if x.permission ])(user.get_group_permissions())
                    else:
                        cherrypy.response.status = 401
                        response['error_message'] = 'Unauthorized'
                else:
                    response['error_message'] = 'Invalid Request'
                    self.logger.warning(f'''Unable to find requested user by id ({target_user_id}).''')
                    if cherrypy.request.is_api:
                        cherrypy.response.status = 400
                    else:
                        response['error_message'] = 'Invalid Request'
                        self.logger.warning('Request is missing required target_user_id or id passed was invalid.')
                        if cherrypy.request.is_api:
                            cherrypy.response.status = 400
                        else:
                            response['error_message'] = 'Invalid Request'
                            self.logger.warning('Request is missing required target_user field.')
                            if cherrypy.request.is_api:
                                cherrypy.response.status = 400

        return response

    get_user_permissions = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.USER,
        JWT_AUTHORIZATION.USERS_VIEW], True, **('requested_actions', 'read_only'))(get_user_permissions))))
    
    def license_status(self):
        response = {
            'license': { } }
        license_helper = LicenseHelper(cherrypy.request.db, self.logger)
        response['license']['status'] = license_helper.effective_license.dump()
        return response

    license_status = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.USER], True, **('requested_actions', 'read_only'))(license_status))))
    
    def create_kasm_share_id(self):
        return self._create_kasm_share_id()

    create_kasm_share_id = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.USER], False, **('requested_actions', 'read_only'))(create_kasm_share_id))))
    
    def _create_kasm_share_id(self):
        event = cherrypy.request.json
        response = { }
        if self.is_allow_kasm_sharing_licensed(self.logger):
            if 'kasm_id' in event:
                kasm = cherrypy.request.db.getKasm(event['kasm_id'])
                user = cherrypy.request.authenticated_user
                if kasm is not None:
                    if kasm.user_id == user.user_id:
                        if not user.get_setting_value('allow_kasm_sharing', False):
                            self.logger.error('Sharing is not allowed for this (%s)' % kasm.user.username)
                            response['error_message'] = 'Sharing is not allowed for this (%s)' % kasm.user.username
                            return response
                        if None.share_id is None:
                            kasm.share_id = uuid.uuid4().hex[:8]
                            cherrypy.request.db.updateKasm(kasm)
                            response['share_id'] = kasm.share_id
                        else:
                            message = 'A share_id already exists for Kasm (%s)' % kasm.share_id
                            self.logger.error(message)
                            response['error_message'] = message
                    else:
                        self.logger.error('User (%s) attempted create_kasm_share_id for Kasm (%s) which is owned by user (%s)' % (user.user_id, kasm.kasm_id, kasm.user_id))
                        response['error_message'] = 'Access Denied'
                else:
                    self.logger.error('create_kasm_share_link could not find kasm by id: %s', event['kasm_id'])
                    response['error_message'] = 'Could not find requested Kasm.'
            else:
                msg = 'Missing required parameters'
                self.logger.error(msg)
                response['error_message'] = msg
        else:
            msg = 'Access Denied. This feature is not licensed'
            self.logger.error(msg)
            response['error_message'] = msg
        return response

    
    def get_kasm_share_id(self):
        event = cherrypy.request.json
        response = { }
        if 'kasm_id' in event:
            kasm = cherrypy.request.db.getKasm(event['kasm_id'])
            user = cherrypy.request.authenticated_user
            if kasm is not None:
                if not kasm.user_id == user.user_id or kasm.share_id:
                    response['share_id'] = kasm.share_id
                else:
                    self.logger.error('User (%s) attempted get_kasm_share_id for Kasm (%s) which is owned by user (%s)' % (user.user_id, kasm.kasm_id, kasm.user_id))
                    response['error_message'] = 'Access Denied'
            else:
                self.logger.error('get_kasm_share_id could not find kasm by id: %s', event['kasm_id'])
                response['error_message'] = 'Could not find requested Kasm.'
        else:
            msg = 'Missing required parameters'
            self.logger.error(msg)
            response['error_message'] = msg
        return response

    get_kasm_share_id = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.USER], True, **('requested_actions', 'read_only'))(get_kasm_share_id))))
    
    def delete_kasm_share_id(self):
        event = cherrypy.request.json
        response = { }
        if 'kasm_id' in event:
            kasm = cherrypy.request.db.getKasm(event['kasm_id'])
            user = cherrypy.request.authenticated_user
            if kasm is not None:
                if kasm.user_id == user.user_id or kasm.share_id is not None:
                    kasm.share_id = None
                    cherrypy.request.db.updateKasm(kasm)
                    response['share_id'] = kasm.share_id
                    session_permissions = cherrypy.request.db.get_session_permissions(kasm.kasm_id, **('kasm_id',))
                    cherrypy.request.db.delete_session_permissions(session_permissions)
                    resp = self._kasmvnc_api('get_users', kasm, True, 'get')
                    if resp.status_code == 200:
                        kasmvnc_users = json.loads(resp.content)
                        self.logger.error(f'''KasmVNC Response: {kasmvnc_users}''')
                        for k_user in kasmvnc_users:
                            if 'user' in k_user and k_user['user'] not in ('kasm_user', 'kasm_viewer'):
                                resp = self._kasmvnc_api(f'''remove_user?name={k_user['user']}''', kasm, True, 'get')
                                if resp.status_code == 200:
                                    self.logger.debug(f'''Successfully removed KasmVNC user ({k_user['user']}) from Kasm session ({kasm.kasm_id})''')
                                    continue
                            self.logger.error(f'''Error removing KasmVNC user ({k_user['user']}) kasm session ({kasm.kasm_id})''')
                    else:
                        self.logger.error(f'''Error removing users from a shared session ({kasm.kasm_id}).''')
                else:
                    self.logger.error('User (%s) attempted get_kasm_share_id for Kasm (%s) which is owned by user (%s)' % (user.user_id, kasm.kasm_id, kasm.user_id))
                    response['error_message'] = 'Access Denied'
            else:
                self.logger.error('get_kasm_share_id could not find kasm by id: %s', event['kasm_id'])
                response['error_message'] = 'Could not find requested Kasm.'
        else:
            msg = 'Missing required parameters'
            self.logger.error(msg)
            response['error_message'] = msg
        return response

    delete_kasm_share_id = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.USER], False, **('requested_actions', 'read_only'))(delete_kasm_share_id))))
    
    def get_usage_details(self):
        response = { }
        user = cherrypy.request.authenticated_user
        if self.is_usage_limit_licensed(self.logger):
            pass
        limit = user.get_setting_value('usage_limit', False)
        response['usage_limit'] = limit
        start_date = (datetime.datetime.utcnow() + datetime.timedelta(-30, **('days',))).strftime('%Y-%m-%d 00:00:00')
        end_date = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        dump = cherrypy.request.db.getuserAccountDump(user.user_id, start_date, end_date)
        response['account_dump'] = (lambda .0: [ cherrypy.request.db.serializable(x.jsonDict) for x in .0 ])(dump)
        response['start_date'] = start_date
        response['end_date'] = end_date
        return response

    get_usage_details = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.USER], True, **('requested_actions', 'read_only'))(get_usage_details))))
    
    def get_usage_summary(self):
        response = { }
        user = cherrypy.request.authenticated_user
        if self.is_usage_limit_licensed(self.logger):
            pass
        limit = user.get_setting_value('usage_limit', False)
        response['usage_limit'] = limit
        if limit:
            usage_type = limit['type']
            interval = limit['interval']
            hours = limit['hours']
            (_used_hours, _dates) = get_usage(user)
            response['usage_limit_remaining'] = hours - _used_hours
            response['usage_limit_type'] = usage_type
            response['usage_limit_interval'] = interval
            response['usage_limit_hours'] = hours
            response['usage_limit_start_date'] = _dates['start_date']
            response['usage_limit_next_start_date'] = _dates['next_start_date']
        group_metadata = user.get_setting_value('metadata', { })
        response['group_metadata'] = group_metadata
        return response

    get_usage_summary = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.USER], True, **('requested_actions', 'read_only'))(get_usage_summary))))
    
    def subscription_info(self):
        response = {
            'billing_info': {
                'stripe_pricing_table_id': '',
                'stripe_publishable_key': '' } }
        stripe_pricing_table_id = self._db.get_config_setting_value('subscription', 'stripe_pricing_table_id')
        stripe_publishable_key = self._db.get_config_setting_value('subscription', 'stripe_publishable_key')
        if stripe_pricing_table_id and stripe_publishable_key:
            response['billing_info']['stripe_pricing_table_id'] = stripe_pricing_table_id
            response['billing_info']['stripe_publishable_key'] = stripe_publishable_key
        user = cherrypy.request.authenticated_user
        if user.subscription_id:
            stripe.api_version = '2022-11-15'
            stripe.api_key = self._db.get_config_setting_value('subscription', 'stripe_private_key')
            
            try:
                sub = stripe.Subscription.retrieve(user.subscription_id)
                session = stripe.billing_portal.Session.create(sub['customer'], cherrypy.request.headers['Referer'].rstrip('/') + '/#/userdashboard', **('customer', 'return_url'))
                response['billing_info']['portal'] = session.url
                period_end_date = cherrypy.request.db.serializable(datetime.datetime.fromtimestamp(sub['current_period_end']))
                plans = []
                for item in sub['items']['data']:
                    product = stripe.Product.retrieve(item['plan']['product'])
                    plans.append({
                        'name': product['name'],
                        'description': product['metadata'].get('description', ''),
                        'amount': item['plan']['amount'],
                        'recurring': item['price']['recurring'].get('interval', ''),
                        'metadata': item['plan']['metadata'],
                        'nickname': item['plan']['nickname'],
                        'id': item['plan']['id'] })
                subscription_info = {
                    'plans': plans,
                    'period_end_date': period_end_date,
                    'start_date': sub['start_date'],
                    'status': sub['status'],
                    'pending_cancel': sub['cancel_at_period_end'] }
                response['subscription_info'] = subscription_info
            finally:
                return None
                except stripe.error.InvalidRequestError:
                    self.logger.error('Invalid Request Sent to Stripe: %s', traceback.format_exc())
                    response['error_message'] = 'Invalid Request made to Stripe'
                    return None
                    except stripe.error.StripeError:
                        response
                        self.logger.error('Stripe encountered an Error: %s', traceback.format_exc())
                        response['error_message'] = 'Stripe Encountered an Error'
                        return None
                    
                except:
                    response['error_message'] = 'No Subscription ID for user %s' % user.username
                    return response
                    return None


    subscription_info = cherrypy.expose()(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.USER], False, **('requested_actions', 'read_only'))(subscription_info))))
    
    def get_url_cache(self):
        start = datetime.datetime.now()
        event = cherrypy.request.json
        response = { }
        if 'kasm_id' in event:
            kasm = cherrypy.request.db.getKasm(event['kasm_id'])
            if kasm:
                cherrypy.request.kasm_id = kasm.kasm_id
                if kasm.user:
                    cherrypy.request.kasm_user_id = kasm.user.user_id
                    cherrypy.request.kasm_user_name = kasm.user.username
                url_filter_policy = None
                if not kasm.image.filter_policy_force_disabled:
                    if kasm.image.filter_policy_id:
                        url_filter_policy = kasm.image.filter_policy
                    elif kasm.user:
                        pass
                    
                    url_filter_policy_id = None
                    if url_filter_policy_id:
                        url_filter_policy = cherrypy.request.db.get_url_filter_policy(url_filter_policy_id)
                    else:
                        msg = 'Url cache requested for non-existent kasm_id (%s)' % event['kasm_id']
                        self.logger.error(msg)
                        response['error_message'] = msg
                        return response
                    if 'filter_id' in event:
                        url_filter_policy = cherrypy.request.db.get_url_filter_policy(event['filter_id'])
                    else:
                        msg = 'Missing kasm_id'
                        self.logger.error(msg)
                        response['error_message'] = msg
                        return response
                    if kasm.user.get_setting_value('web_filter_policy'):
                        if not url_filter_policy.ssl_bypass_domains:
                            pass
                        if not url_filter_policy.ssl_bypass_ips:
                            pass
                        if not url_filter_policy.disable_logging:
                            pass
                        response['config'] = {
                            'deny_by_default': url_filter_policy.deny_by_default,
                            'enable_categorization': url_filter_policy.enable_categorization,
                            'redirect_url': url_filter_policy.redirect_url,
                            'ssl_bypass_domains': [],
                            'ssl_bypass_ips': [],
                            'safe_search_patterns': url_filter_policy.safe_search_patterns if url_filter_policy.enable_safe_search else [],
                            'disable_logging': False }
                        cache = { }
                        whitelist = []
                        blacklist = []
                        if url_filter_policy.domain_whitelist and type(url_filter_policy.domain_whitelist) == list:
                            whitelist = url_filter_policy.domain_whitelist
                        if url_filter_policy.domain_blacklist and type(url_filter_policy.domain_blacklist) == list:
                            blacklist = url_filter_policy.domain_blacklist
                        if url_filter_policy.enable_categorization:
                            domains = cherrypy.request.db.get_domains_ex(10000, **('limit',))
                            default_allow = not (url_filter_policy.deny_by_default)
                            (allow_categories, deny_categories) = url_filter_policy.get_allow_categories(default_allow, **('default_allow',))
                            for k, v in domains.items():
                                _whitelist_found = (lambda .0 = None: [ x for x in .0 if x in k ])(whitelist)
                                _blacklist_found = (lambda .0 = None: [ x for x in .0 if x in k ])(blacklist)
                                if not _blacklist_found and _whitelist_found:
                                    _categories = (lambda .0: [ ALL_CATEGORIES.get(x, { }).get('label', x) for x in .0 ])(list(set(v)))
                                    allow = not deny_categories.intersection(v)
                                    cache[k] = {
                                        'allow': allow,
                                        'category': ', '.join(_categories) }
                                    continue
                                    if whitelist:
                                        for x in url_filter_policy.domain_whitelist:
                                            cache[x] = {
                                                'allow': True,
                                                'category': 'whitelist' }
                        if blacklist:
                            for x in url_filter_policy.domain_blacklist:
                                cache[x] = {
                                    'allow': False,
                                    'category': 'blacklist' }
                        response['cache'] = cache
                    else:
                        msg = 'URL cache request but no policy is assigned'
                        self.logger.warning(msg)
                        response['error_message'] = msg
        return response

    get_url_cache = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated(True, True, **('kasm', 'read_only'))(get_url_cache))))
    
    def filter_checkin(self):
        response = {
            'kasm_user_name': cherrypy.request.kasm_user_name if hasattr(cherrypy.request, 'kasm_user_name') else '',
            'kasm_user_id': cherrypy.request.kasm_user_id if hasattr(cherrypy.request, 'kasm_user_id') else '' }
        return response

    filter_checkin = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated(True, True, **('kasm', 'read_only'))(filter_checkin))))
    
    def url_check(self):
        start = datetime.datetime.now()
        event = cherrypy.request.json
        response = { }
        if 'url' in event:
            url = event['url']
            domain = urlparse(url).netloc.split(':')[0]
            domain_split = domain.split('.')
            username = ''
        return response

    url_check = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated(True, True, **('kasm', 'read_only'))(url_check))))
    
    def ui_log(self):
        response = { }
        event = cherrypy.request.json
        for log in event.get('logs'):
            extra = log
            extra['application'] = 'kasm_ui'
            message = extra.pop('message', '')
            level = extra.pop('level', 'warning')
            level = logging._nameToLevel.get(level.upper(), 'INFO')
            self.logger.log(level, message, extra, **('extra',))
        return response

    ui_log = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.USER], False, **('requested_actions', 'read_only'))(ui_log))))
    
    def cast_validity_test(self, cast_config, event, client_ip):
        res = {
            'ok': True,
            'error_message': '' }
        if cast_config.require_recaptcha and cast_config.allow_anonymous:
            recaptcha_value = event.get('recaptcha_value')
            if recaptcha_value:
                recaptcha_respones = validate_recaptcha(recaptcha_value, self._db.get_config_setting_value('auth', 'google_recaptcha_api_url'), self._db.get_config_setting_value('auth', 'google_recaptcha_priv_key'))
                if recaptcha_respones.get('status'):
                    self.logger.debug('Request passed reCAPTCHA request')
                else:
                    res['ok'] = False
                    res['error_message'] = 'reCAPTCHA Failed'
                    self.logger.warning('Request did not pass reCAPTCHA request', {
                        'metric_name': 'provision.cast.validate',
                        'validation_failure_reason': 'recaptcha.failed' }, **('extra',))
                    return res
            res['ok'] = False
            res['error_message'] = 'recaptcha_needed'
            res['google_recaptcha_site_key'] = self._db.get_config_setting_value('auth', 'google_recaptcha_site_key')
            self.logger.info('Request needs reCAPTCHA')
        else:
            self.logger.debug('No reCAPTCHA validation needed')
        if cast_config.limit_sessions:
            if cast_config.session_remaining > 0:
                self.logger.debug('Cast Config has sessions_remaining validation passed with (%s) sessions remaining' % cast_config.session_remaining)
            else:
                res['ok'] = False
                res['error_message'] = 'Session limit exceeded.'
                self.logger.warning('Cast Config has no sessions remaining', {
                    'metric_name': 'provision.cast.validate',
                    'validation_failure_reason': 'no_sessions_remaining' }, **('extra',))
                return res
        self.logger.debug('Cast Config not configured to limit sessions')
        referrer = event.get('referrer', '')
        if cast_config.allowed_referrers:
            if referrer:
                domain = urlparse(referrer).netloc.split(':')[0]
                if domain.lower().strip() in cast_config.allowed_referrers:
                    self.logger.debug('Request domain (%s) in allowed referrer (%s)' % (domain, cast_config.allowed_referrers))
                else:
                    res['ok'] = False
                    res['error_message'] = 'Requests are not allowed from this domain.'
                    self.logger.warning('Request domain (%s) not in allowed referrer (%s)' % (domain, cast_config.allowed_referrers), {
                        'metric_name': 'provision.cast.validate',
                        'validation_failure_reason': 'bad_referrer' }, **('extra',))
                    return res
            self.logger.debug('Request has no referrer')
        if cast_config.limit_ips and cast_config.ip_request_limit and cast_config.ip_request_seconds:
            after = datetime.datetime.utcnow() - datetime.timedelta(cast_config.ip_request_seconds, **('seconds',))
            accountings = cherrypy.request.db.getAccountings(cast_config.cast_config_id, client_ip, after, **('cast_config_id', 'user_ip', 'after'))
            if len(accountings) >= cast_config.ip_request_limit:
                self.logger.warning('IP Limit (%s) within (%s) seconds reached' % (cast_config.ip_request_limit, cast_config.ip_request_seconds), {
                    'metric_name': 'provision.cast.validate',
                    'validation_failure_reason': 'ip_limit' }, **('extra',))
                res['ok'] = False
                res['error_message'] = 'Request limit reached. Please try again later.'
                return res
            None.logger.debug('Passed IP Limit restriction. Current sessions (%s) within limit' % len(accountings))
        else:
            self.logger.debug('No IP Limit restrictions configured')
        if cast_config.valid_until and cast_config.valid_until < datetime.datetime.utcnow():
            self.logger.warning('Casting config valid_until (%s) has expired' % cast_config.valid_until, {
                'metric_name': 'provision.cast.validate',
                'validation_failure_reason': 'expired' }, **('extra',))
            res['ok'] = False
            res['error_message'] = 'This link has expired'
            return res

    
    def check_form(self, image):
        event = cherrypy.request.json
        launch_selections = event.get('launch_selections')
        if not launch_selections:
            launch_selections = { }
        return not image.has_minimum_launch_selections(launch_selections)

    
    def request_cast(self):
        response = { }
        license_helper = LicenseHelper(cherrypy.request.db, self.logger)
    # WARNING: Decompyle incomplete

    request_cast = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.USER], True, **('requested_actions', 'pass_unauthenticated'))(request_cast))))
    
    def webauthn_register_start(self):
        response = { }
        event = cherrypy.request.json
        if 'username' not in event or 'password' not in event:
            self.logger.warning('Invalid call to webauthn_register_start')
            response['error_message'] = 'Access Denied'
            return response
        auth_resp = None.authenticate()
        if 'error_message' in auth_resp:
            self.logger.warning('Authentication failed on attempt to set 2fa secret for user: (%s)' % event['username'])
            response['error_message'] = auth_resp['error_message']
            return response
        user = None.request.db.getUser(event['username'].strip().lower())
        if not user.get_setting_value('require_2fa', False):
            self.logger.warning('User (%s) attempted to call webauthn_register_start, but require_2fa is false')
            response['error_message'] = 'Two factor enrollment is not enabled'
            return response
        return None._webauthn_register_start(user)

    webauthn_register_start = cherrypy.expose()(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Unauthenticated()(webauthn_register_start))))
    
    def webauthn_authenticated_register_start(self):
        response = { }
        user = cherrypy.request.authenticated_user
        event = cherrypy.request.json
        if user.username != event['username']:
            response['error_message'] = 'Username does not match authenticated user'
            self.logger.warning('Token Username (%s) does not match username field (%s)', user.username, event['username'])
            return response
        if not None.get_setting_value('allow_2fa_self_enrollment', False):
            self.logger.warning('User (%s) attempted to call webauthn_authenticated_register_start', event['username'])
            response['error_message'] = 'Self Enrollment is not permitted'
            return response
        response = None._webauthn_register_start(user)
        if response.get('error_message') == 'Access Denied':
            response['error_message'] = 'Webauthn Register Failed'
        return response

    webauthn_authenticated_register_start = cherrypy.expose()(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.USER], False, **('requested_actions', 'read_only'))(webauthn_authenticated_register_start))))
    
    def _webauthn_register_start(self, user):
        response = { }
        if not user.get_setting_value('allow_webauthn_2fa', True):
            response['error_message'] = 'WebAuthn is not permitted for user.'
            self.logger.warning('User (%s) called _webauthn_register_start, but webauthn is disabled.', user.username)
            return response
        request_id = None.uuid4().hex
        prompt_timeout = int(self._db.get_config_setting_value('auth', 'webauthn_request_lifetime')) * 1000
        registration_options = webauthn.generate_registration_options(cherrypy.request.headers['HOST'], 'Kasm Workspaces', user.username, user.user_id.hex, AuthenticatorSelectionCriteria(UserVerificationRequirement.REQUIRED, **('user_verification',)), prompt_timeout, **('rp_id', 'rp_name', 'user_name', 'user_id', 'authenticator_selection', 'timeout'))
        registration_options = json.loads(webauthn.options_to_json(registration_options))
        cherrypy.request.db.create_webauthn_request(registration_options['challenge'], request_id, **('challenge', 'request_id'))
        response['registration_options'] = registration_options
        response['request_id'] = request_id
        return response

    
    def webauthn_register_finish(self):
        response = { }
        event = cherrypy.request.json
        if 'username' not in event or 'password' not in event:
            self.logger.warning('Invalid call to webauthn_register_finish')
            response['error_message'] = 'Access Denied'
            return response
        auth_resp = None.authenticate()
        if 'error_message' in auth_resp:
            self.logger.warning('Authentication failed on attempt to set 2fa secret for user: (%s)' % event['username'])
            response['error_message'] = auth_resp['error_message']
            return response
        user = None.request.db.getUser(event['username'].strip().lower())
        response = self._webauthn_register_finish(event, user)
        return response

    webauthn_register_finish = cherrypy.expose()(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Unauthenticated()(webauthn_register_finish))))
    
    def webauthn_authenticated_register_finish(self):
        event = cherrypy.request.json
        user = cherrypy.request.authenticated_user
        response = { }
        if user.username != event['username']:
            response['error_message'] = 'Username does not match authenticated user'
            self.logger.warning('Token Username (%s) does not match username field (%s)', user.username, event['username'])
            return response
        if not None.get_setting_value('allow_2fa_self_enrollment', False):
            self.logger.warning('User (%s) attempted to call webauthn_authenticated_register_finish, but allow_2fa_self_enrollment is set to False', event['username'])
            response['error_message'] = 'Self Enrollment is not permitted'
            return response
        response = None._webauthn_register_finish(event, user)
        if response.get('error_message') == 'Access Denied':
            response['error_message'] = 'WebAuthn Register Failed'
        return response

    webauthn_authenticated_register_finish = cherrypy.expose()(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.USER], False, **('requested_actions', 'read_only'))(webauthn_authenticated_register_finish))))
    
    def _webauthn_register_finish(self, event, user):
        response = { }
        if 'credential' not in event or 'request_id' not in event:
            self.logger.warning('Invalid call to _webauthn_register_finish, missing request_id or credential')
            response['error_message'] = 'Access Denied'
            return response
        if not None.get_setting_value('allow_webauthn_2fa', True):
            self.logger.warning('User (%s) called _webauthn_register_finish, but webauthn is disabled.', user.username)
            response['error_message'] = 'WebAuthn is not permitted for user.'
            return response
    # WARNING: Decompyle incomplete

    
    def _webauthn_generate_auth_options(self, user):
        response = { }
        request_id = uuid.uuid4().hex
        prompt_timeout = int(self._db.get_config_setting_value('auth', 'webauthn_request_lifetime')) * 1000
        allowed_credentials = []
        for credential in user.webauthn_credentials:
            allowed_credentials.append(PublicKeyCredentialDescriptor(credential.authenticator_credential_id, **('id',)))
        authentication_options = webauthn.generate_authentication_options(cherrypy.request.headers['HOST'], allowed_credentials, prompt_timeout, **('rp_id', 'allow_credentials', 'timeout'))
        authentication_options = json.loads(authentication_options.model_dump_json())
        cherrypy.request.db.create_webauthn_request(authentication_options['challenge'], request_id, **('challenge', 'request_id'))
        response['webauthn_authentication_options'] = authentication_options
        response['request_id'] = request_id
        return response

    
    def webauthn_get_auth_options(self):
        user = cherrypy.request.authenticated_user
        response = { }
        if not user.set_webauthn:
            self.logger.warning('User (%s) called webauthn_get_auth_options, but they do not have any credentials')
            response['error_message'] = 'No WebAuthn Credentials'
            return response
        return None._webauthn_generate_auth_options(user)

    webauthn_get_auth_options = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.USER], False, **('requested_actions', 'read_only'))(webauthn_get_auth_options))))
    
    def webauthn_authenticate(self):
        response = { }
        event = cherrypy.request.json
        if 'username' not in event and 'password' not in event or 'webauthn_credential' not in event:
            self.logger.warning('Missing username, password or webauthn_credential in webauthn_auth')
            response['error_message'] = 'Access Denied'
            return response
        auth_resp = None.authenticate()
        if 'error_message' in auth_resp:
            self.logger.warning('Authentication failed on webuathn_auth attempt for user: (%s)' % event['username'])
            response['error_message'] = auth_resp['error_message']
            return response
        user = None.request.db.getUser(event['username'].strip().lower())
        if user is None:
            self.logger.warning('Invalid user (%s)' % event['username'])
            response['error_message'] = 'Access Denied'
            return response
        if not None.get_setting_value('allow_webauthn_2fa', True):
            response['error_message'] = 'WebAuthn is not permitted for user.'
            self.logger.warning('User (%s) called webauthn_authenticate, but webauthn is disabled.', event['username'])
            return response
        if None.locked:
            self.logger.warning('webauthn_auth failed for locked account: (%s)' % event['username'])
            response['error_message'] = 'Access Denied'
            return response
    # WARNING: Decompyle incomplete

    webauthn_authenticate = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Unauthenticated()(webauthn_authenticate))))
    
    def _generate_auth_resp(self, user, event, response):
        cherrypy.request.db.remove_expired_session_tokens(user)
        session_token = cherrypy.request.db.createSessionToken(user)
        priv_key = str.encode(self._db.get_config_setting_value_cached('auth', '
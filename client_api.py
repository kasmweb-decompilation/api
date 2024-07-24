# Decompiled with PyLingual (https://pylingual.io)
# Internal filename: client_api.py
# Bytecode version: 3.8.0rc1+ (3413)
# Source timestamp: 1970-01-01 00:00:00 UTC (0)

import tempfile
import typing
from urllib.error import URLError
import uuid
import hashlib
import cherrypy
import traceback
import logging
import logging.config
import time
import datetime
import json
import os
import stripe
import pyotp
import base64
import urllib.request
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
        else:  # inserted
            self.kasm_web_filter = None
        self.logger.info('%s initialized' % self.__class__.__name__)

    def init_webfilter(self):
        self.kasm_web_filter = KasmWebFilter(self._db.get_config_setting_value('web_filter', 'web_filter_update_url'), self.installation_id, self.logger)

    @staticmethod
    @ttl_cache(maxsize=200, ttl=600)
    def is_sso_licensed(logger):
        license_helper = LicenseHelper(cherrypy.request.db, logger)
        return license_helper.is_sso_ok()

    @staticmethod
    @ttl_cache(maxsize=200, ttl=600)
    def is_allow_kasm_sharing_licensed(logger):
        license_helper = LicenseHelper(cherrypy.request.db, logger)
        return license_helper.is_allow_kasm_sharing_ok()

    @staticmethod
    @ttl_cache(maxsize=200, ttl=600)
    def is_usage_limit_licensed(logger):
        license_helper = LicenseHelper(cherrypy.request.db, logger)
        return license_helper.is_usage_limit_ok()

    @staticmethod
    @ttl_cache(maxsize=200, ttl=600)
    def is_session_recording_licensed(logger):
        license_helper = LicenseHelper(cherrypy.request.db, logger)
        return license_helper.is_session_recording_ok()

    @cherrypy.expose(['__healthcheck'])
    @cherrypy.tools.json_out()
    @Unauthenticated()
    def healthcheck(self):
        response = {'ok': True}
        cherrypy.request.db.getInstallation()
        return response

    @cherrypy.expose
    @Unauthenticated()
    def acs(self, **params):
        if not self.is_sso_licensed(self.logger):
            return 'Access Denied. This feature is not licensed'
        if 'id' in cherrypy.request.params:
            config = cherrypy.request.db.get_saml_config(cherrypy.request.params['id'])
        else:  # inserted
            return 'Login Failure: No saml ID in request'
        if config:
            saml = SamlAuthentication(cherrypy.request, config, '/api/acs')
            response = saml.acs()
            if 'error' in response and response['error'] or response['auth'] is False:
                return response['error']
            sanitized_username = response['userid'].strip().lower()
            user = cherrypy.request.db.getUser(sanitized_username)
            if not user:
                license_helper = LicenseHelper(cherrypy.request.db, self.logger)
                if license_helper.is_per_named_user_ok(with_user_added=True):
                    user = cherrypy.request.db.createUser(username=sanitized_username, realm='saml', saml_id=cherrypy.request.params['id'])
                else:  # inserted
                    msg = 'License limit exceeded. Unable to create user'
                    self.logger.error(msg)
                    return
            if user.realm == 'saml':
                if cherrypy.request.db.serializable(user.saml_id) == cherrypy.request.params['id']:
                    self.process_sso_group_membership(user, response['attributes'].get(config.group_attribute, []), 'saml', config.saml_id)
                    attributes = response['attributes'] if 'attributes' in response else {}
                    for sso_attribute_mapping in config.user_attribute_mappings:
                        if sso_attribute_mapping.attribute_name.lower() == 'debug':
                            self.logger.debug(f'SAML Attributes: {str(attributes)}')
                        else:  # inserted
                            value = sso_attribute_mapping.process_attributes(user, attributes)
                            self.logger.debug(f'New attribute value ({value}) applied to user {sanitized_username} for {sso_attribute_mapping.user_field}')
                    if len(config.user_attribute_mappings) > 0:
                        cherrypy.request.db.updateUser(user)
                    priv_key = str.encode(self._db.get_config_setting_value_cached('auth', 'api_private_key'))
                    session_lifetime = int(self._db.get_config_setting_value_cached('auth', 'session_lifetime'))
                    session_token = cherrypy.request.db.createSessionToken(user)
                    user_id = cherrypy.request.db.serializable(user.user_id)
                    session_jwt = session_token.generate_jwt(priv_key, session_lifetime)
                    raise cherrypy.HTTPRedirect(response['base_url'] + '/#/sso/' + user_id + '/' + session_jwt, status=302)
                else:  # inserted
                    return 'Saml login rejected: different Saml ID expected for user'
            else:  # inserted
                return 'Saml login rejected: Non Saml user'
        else:  # inserted
            self.logger.error('No Saml configuration with that ID found in the acs request')
            return 'Error: wrong Saml ID'

    @typing.Dict
    def process_sso_group_membership(self, user, sso_groups: str, sso_type: str, sso_id: str):
        group_mappings = cherrypy.request.db.getGroupMappingBySsoID(sso_type=sso_type, sso_id=sso_id)
        sso_groups = [x.lower() for x in sso_groups]
        user_group_ids = [x.group_id for x in user.groups]
        distinct_groups = set()
        [distinct_groups.add(x.group) for x in group_mappings]
        distinct_groups = list(distinct_groups)
        for group in distinct_groups:
            sso_group_mappings = [x for x in group.group_mappings if x.sso_id == sso_id]
            self.logger.debug(f'Processing Group ({group.name}) with ({len(sso_group_mappings)}) sso_mappings for sso type {sso_type}, id: ({sso_id})')
            do_add = False
            for group_mapping in sso_group_mappings:
                if group_mapping.apply_to_all_users:
                    do_add = True
                    self.logger.debug(f'User ({user.username}) should be assigned to group ({group.name}) : Apply to All Users')
                    break
                if group_mapping.sso_group_attributes.lower() in sso_groups:
                    self.logger.debug(f'User ({user.username}) should be assigned to group ({group.name}). Matched group attribute ({group_mapping.sso_group_attributes})')
                    do_add = True
            if do_add:
                if group.group_id in user_group_ids:
                    self.logger.debug(f'User ({user.username}) already a member of group ({group.name}). No Action')
                else:  # inserted
                    self.logger.debug(f'Adding User ({user.username}) to Group ({group.name})')
                    cherrypy.request.db.addUserGroup(user, group)
            else:  # inserted
                if group.group_id in user_group_ids:
                    self.logger.debug(f'Removing User ({user.username}) from Group ({group.name})')
                    cherrypy.request.db.removeUserGroup(user, group)
                else:  # inserted
                    self.logger.debug(f'User ({user.username}) is not a member of group ({group.name}). No Action')

    @cherrypy.expose
    @Unauthenticated()
    def slo(self, **params):
        if 'id' in cherrypy.request.params:
            config = cherrypy.request.db.get_saml_config(cherrypy.request.params['id'])
        else:  # inserted
            response = 'No saml ID'
            return response
        if config:
            saml = SamlAuthentication(cherrypy.request, config, '/api/slo')
            url, name_id = saml.sls()
            if name_id:
                sanitized_username = name_id.strip().lower()
                user = cherrypy.request.db.getUser(sanitized_username)
                cherrypy.request.db.remove_all_session_tokens(user)
            if not url:
                url = cherrypy.request.base.replace('http', 'https')
            raise cherrypy.HTTPRedirect(url, status=301)
        self.logger.error('Saml Logout Error: No config for this Saml ID')

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    @Unauthenticated()
    def sso(self, **params):
        response = {}
        event = cherrypy.request.json
        if 'id' in event:
            if 'sso_type' in event and event['sso_type'] == 'saml_id':
                config = cherrypy.request.db.get_saml_config(event['id'])
                saml = SamlAuthentication(cherrypy.request, config, '/api/sso')
                response['url'] = saml.sso()
            else:  # inserted
                if 'sso_type' in event and event['sso_type'] == 'oidc_id':
                    config = cherrypy.request.db.get_oidc_config(event['id'])
                    response['url'] = OIDCAuthentication(config).get_login_url()
        else:  # inserted
            response['error_message'] = 'No SSO ID'
            return response
        return response

    @cherrypy.expose
    @Unauthenticated()
    def sso_login(self, **params):
        if 'id' in cherrypy.request.params:
            id = cherrypy.request.params['id']
            config = cherrypy.request.db.get_saml_config(id)
            if config:
                url = SamlAuthentication(cherrypy.request, config, '/api/sso_login').sso()
                raise cherrypy.HTTPRedirect(url, status=301)
            config = cherrypy.request.db.get_oidc_config(id)
            if config:
                url = OIDCAuthentication(config).get_login_url()
                raise cherrypy.HTTPRedirect(url, status=301)
            cherrypy.response.status = 403
        else:  # inserted
            cherrypy.response.status = 403

    @cherrypy.expose
    @Unauthenticated()
    def metadata(self, **params):
        response = {}
        if 'id' in cherrypy.request.params:
            config = cherrypy.request.db.get_saml_config(cherrypy.request.params['id'])
        else:  # inserted
            return 'No saml ID'
        if config:
            saml = SamlAuthentication(cherrypy.request, config, '/api/metadata')
            response = saml.metadata()
            cherrypy.response.headers['Content-Type'] = 'text/xml; charset=utf-8'
        else:  # inserted
            response['error_message'] = 'No saml Configuration'
        if 'error_message' in response:
            return response['error_message']
        return response['metadata']

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    @Authenticated(requested_actions=[JWT_AUTHORIZATION.USER], read_only=True)
    def get_available_storage_providers(self):
        response = {'storage_providers': []}
        user = cherrypy.request.authenticated_user
        is_admin = JWT_AUTHORIZATION.is_authorized_action(cherrypy.request.authorizations, JWT_AUTHORIZATION.STORAGE_PROVIDERS_VIEW)
        if is_admin or (user and user.get_setting_value('allow_user_storage_mapping', False)):
            storage_providers = cherrypy.request.db.get_storage_providers(enabled=True)
            for storage_provider in storage_providers:
                if is_admin or storage_provider.storage_provider_type!= STORAGE_PROVIDER_TYPES.CUSTOM.value:
                    response['storage_providers'].append({'name': storage_provider.name, 'storage_provider_id': str(storage_provider.storage_provider_id), 'storage_provider_type': storage_provider.storage_provider_type})
        return response

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    @Authenticated(requested_actions=[JWT_AUTHORIZATION.USER], read_only=True)
    def get_storage_mappings(self):
        response = {'storage_mappings': []}
        user = cherrypy.request.authenticated_user
        is_admin = JWT_AUTHORIZATION.any_authorized_actions(cherrypy.request.authorizations, [JWT_AUTHORIZATION.USERS_VIEW, JWT_AUTHORIZATION.GROUPS_VIEW, JWT_AUTHORIZATION.GROUPS_VIEW_IFMEMBER, JWT_AUTHORIZATION.GROUPS_VIEW_SYSTEM, JWT_AUTHORIZATION.IMAGES_VIEW])
        event = cherrypy.request.json
        target_storage_mapping = event.get('target_storage_mapping', {})
        if target_storage_mapping:
            _user_id = target_storage_mapping.get('user_id')
            _group_id = target_storage_mapping.get('group_id')
            _image_id = target_storage_mapping.get('image_id')
            _storage_mapping_id = target_storage_mapping.get('storage_mapping_id')
            _test = [x for x in [_user_id, _group_id, _image_id, _storage_mapping_id] if x is not None]
            if len(_test) == 1:
                if is_admin:
                    storage_mappings = cherrypy.request.db.get_storage_mappings(storage_mapping_id=_storage_mapping_id, user_id=_user_id, group_id=_group_id, image_id=_image_id)
                    response['storage_mappings'] = []
                    for storage_mapping in storage_mappings:
                        is_authorized = False
                        if storage_mapping.user:
                            is_authorized = storage_mapping.user.user_id == user.user_id or JWT_AUTHORIZATION.is_user_authorized_action(user, cherrypy.request.authorizations, JWT_AUTHORIZATION.USERS_VIEW, target_user=storage_mapping.user)
                        else:  # inserted
                            if storage_mapping.group:
                                is_authorized = JWT_AUTHORIZATION.is_user_authorized_action(user, cherrypy.request.authorizations, JWT_AUTHORIZATION.GROUPS_VIEW, target_group=storage_mapping.group)
                            else:  # inserted
                                if storage_mapping.image:
                                    is_authorized = JWT_AUTHORIZATION.is_authorized_action(cherrypy.request.authorizations, JWT_AUTHORIZATION.IMAGES_VIEW)
                        if is_authorized:
                            response['storage_mappings'].append(cherrypy.request.db.serializable(storage_mapping.jsonDict))
                else:  # inserted
                    if not _user_id or _user_id!= user.user_id.hex:
                        msg = 'Unauthorized attempt to update storage mappings for other user/group/image'
                        self.logger.error(msg)
                        response['error_message'] = 'Access Denied'
                        return response
                    storage_mappings = cherrypy.request.db.get_storage_mappings(user_id=user.user_id)
                    for vc in storage_mappings:
                        response['storage_mappings'].append({'storage_mapping_id': str(vc.storage_mapping_id), 'storage_provider_type': vc.storage_provider.storage_provider_type, 'user_id': str(vc.user_id), 'name': vc.name, 'storage_provider_id': str(vc.storage_provider_id), 'enabled': vc.enabled, 'read_only': vc.read_only, 'target': vc.target, 's3_access_key_id': vc.s3_access_key_id, 's3_secret_access_key': '**********', 's3_bucket': vc.s3_bucket, 'webdav_user': vc.webdav_user, 'webdav_pass': '**********'})
            else:  # inserted
                msg = 'Invalid request. Only one of the following parameters may be defined (storage_mapping_id, user_id, group_id, image_id)'
                self.logger.error(msg)
                response['error_message'] = msg
        else:  # inserted
            msg = 'Invalid request. Missing required parameters'
            self.logger.error(msg)
            response['error_message'] = msg
        return response

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    @Authenticated(requested_actions=[JWT_AUTHORIZATION.USER], read_only=False)
    def delete_storage_mapping(self):
        response = {}
        user = cherrypy.request.authenticated_user
        event = cherrypy.request.json
        target_storage_mapping = event.get('target_storage_mapping')
        is_admin = JWT_AUTHORIZATION.any_authorized_actions(cherrypy.request.authorizations, [JWT_AUTHORIZATION.USERS_MODIFY, JWT_AUTHORIZATION.USERS_MODIFY_ADMIN, JWT_AUTHORIZATION.GROUPS_MODIFY, JWT_AUTHORIZATION.IMAGES_MODIFY, JWT_AUTHORIZATION.USERS_VIEW, JWT_AUTHORIZATION.GROUPS_VIEW, JWT_AUTHORIZATION.IMAGES_VIEW])
        is_authorized = False
        if target_storage_mapping:
            storage_mapping_id = target_storage_mapping.get('storage_mapping_id')
            if storage_mapping_id:
                if is_admin:
                    storage_mapping = cherrypy.request.db.get_storage_mapping(storage_mapping_id=storage_mapping_id)
                    if storage_mapping:
                        if not storage_mapping.user or user:
                            is_authorized = storage_mapping.user.user_id == user.user_id or JWT_AUTHORIZATION.is_user_authorized_action(user, cherrypy.request.authorizations, JWT_AUTHORIZATION.USERS_MODIFY, target_user=storage_mapping.user)
                        else:  # inserted
                            if storage_mapping.group:
                                is_authorized = JWT_AUTHORIZATION.is_user_authorized_action(user, cherrypy.request.authorizations, JWT_AUTHORIZATION.GROUPS_MODIFY, target_group=storage_mapping.group)
                            else:  # inserted
                                if storage_mapping.image:
                                    is_authorized = JWT_AUTHORIZATION.is_authorized_action(cherrypy.request.authorizations, JWT_AUTHORIZATION.IMAGES_MODIFY)
                else:  # inserted
                    storage_mapping = cherrypy.request.db.get_storage_mapping(storage_mapping_id=storage_mapping_id, user_id=user.user_id)
                    is_authorized = True
                if storage_mapping:
                    if not is_authorized or storage_mapping.storage_provider_type == STORAGE_PROVIDER_TYPES.CUSTOM.value:
                        if not is_admin:
                            pass  # postinserted
                    if not is_authorized:
                        self.logger.error(f'User ({cherrypy.request.kasm_user_id}) unauthorized to delete storage mapping ({storage_mapping_id}).')
                    else:  # inserted
                        self.logger.error(f'User ({cherrypy.request.kasm_user_id}) unauthorized to delete Custom storage mapping ({storage_mapping_id}).')
                    response['error_message'] = 'Unauthorized Action'
                    cherrypy.response.status = 401
                    return response
                    cherrypy.request.db.delete_storage_mapping(storage_mapping)
                    self.logger.info('Successfully deleted storage_mapping_id (%s)' % storage_mapping_id, extra={'storage_mapping_id': storage_mapping_id})
                else:  # inserted
                    msg = 'Storage Mapping ID (%s) Not found' % storage_mapping_id
                    self.logger.error(msg)
                    response['error_message'] = msg
            else:  # inserted
                msg = 'Invalid request. Missing required parameters'
                self.logger.error(msg)
                response['error_message'] = msg
        else:  # inserted
            msg = 'Invalid request. Missing required parameters'
            self.logger.error(msg)
            response['error_message'] = msg
        return response

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    @Authenticated(requested_actions=[JWT_AUTHORIZATION.USER], read_only=False)
    def create_storage_mapping(self):
        response = {}
        user = cherrypy.request.authenticated_user
        is_admin = JWT_AUTHORIZATION.any_authorized_actions(cherrypy.request.authorizations, [JWT_AUTHORIZATION.USERS_MODIFY, JWT_AUTHORIZATION.USERS_MODIFY_ADMIN, JWT_AUTHORIZATION.GROUPS_MODIFY, JWT_AUTHORIZATION.IMAGES_MODIFY, JWT_AUTHORIZATION.USERS_VIEW, JWT_AUTHORIZATION.GROUPS_VIEW, JWT_AUTHORIZATION.IMAGES_VIEW])
        event = cherrypy.request.json
        target_storage_mapping = event.get('target_storage_mapping')
        if not is_admin and (not user.get_setting_value('allow_user_storage_mapping', False)) or target_storage_mapping:
            _user_id = target_storage_mapping.get('user_id')
            _group_id = target_storage_mapping.get('group_id')
            _image_id = target_storage_mapping.get('image_id')
            _storage_provider_id = target_storage_mapping.get('storage_provider_id')
            target_user = None
            _test = [x for x in [_user_id, _group_id, _image_id] if x is not None]
            if len(_test) == 1:
                if not is_admin and (target_storage_mapping.get('target') or target_storage_mapping.get('config')):
                    msg = 'Unauthorized attempt to define restricted storage mapping property'
                    self.logger.error(msg)
                    response['error_message'] = 'Access Denied'
                    return response
                if not _user_id or _user_id!= user.user_id.hex:
                    msg = 'Unauthorized attempt to create storage mappings for other user/group/image'
                    self.logger.error(msg)
                    response['error_message'] = 'Access Denied'
                    return response
                if _user_id:
                    target_user = cherrypy.request.db.get_user_by_id(user_id=_user_id)
                    if target_user:
                        max_user_storage_mappings = target_user.get_setting_value('max_user_storage_mappings', 2)
                        if len(target_user.storage_mappings) >= max_user_storage_mappings:
                            msg = 'Unable to create storage mapping. Limit exceeded'
                            self.logger.error(msg)
                            response['error_message'] = msg
                            return response
                    else:  # inserted
                        msg = 'Invalid user_id'
                        self.logger.error(msg)
                        response['error_message'] = msg
                        return response
                is_authorized = False
                if target_user:
                    if user:
                        if target_user.user_id == user.user_id:
                            is_authorized = True
                if is_admin:
                    if target_user:
                        is_authorized = JWT_AUTHORIZATION.is_user_authorized_action(user, cherrypy.request.authorizations, JWT_AUTHORIZATION.USERS_MODIFY, target_user=target_user)
                    else:  # inserted
                        if _group_id:
                            target_group = cherrypy.request.db.getGroup(group_id=_group_id)
                            is_authorized = target_group and JWT_AUTHORIZATION.is_user_authorized_action(user, cherrypy.request.authorizations, JWT_AUTHORIZATION.GROUPS_MODIFY, target_group=target_group)
                        else:  # inserted
                            if _image_id:
                                is_authorized = JWT_AUTHORIZATION.is_authorized_action(cherrypy.request.authorizations, JWT_AUTHORIZATION.IMAGES_MODIFY)
                if not is_authorized:
                    self.logger.error(f'User ({cherrypy.request.kasm_user_id}) attempted to create a storage mapping but is not authorized to modify the target group, user, or image.')
                    response['error_message'] = 'Unauthorized to modify the target user/group/image for the storage mapping.'
                    response['ui_show_error'] = True
                    cherrypy.response.status = 401
                    return response
                storage_provider_id = target_storage_mapping.get('storage_provider_id')
                if storage_provider_id:
                    storage_provider = cherrypy.request.db.get_storage_provider(storage_provider_id=storage_provider_id)
                    if storage_provider:
                        jwt_priv_key = str.encode(cherrypy.request.db.get_config_setting_value_cached('auth', 'api_private_key'))
                        encoded_jwt = None
                        if storage_provider.storage_provider_type == STORAGE_PROVIDER_TYPES.GOOGLE_DRIVE.value:
                            url, encoded_jwt = GoogleDrive(storage_provider).get_login_url(target_storage_mapping, jwt_priv_key)
                            response['url'] = url
                        else:  # inserted
                            if storage_provider.storage_provider_type == STORAGE_PROVIDER_TYPES.DROPBOX.value:
                                url, encoded_jwt = Dropbox(storage_provider).get_login_url(target_storage_mapping, jwt_priv_key)
                                response['url'] = url
                            else:  # inserted
                                if storage_provider.storage_provider_type == STORAGE_PROVIDER_TYPES.ONEDRIVE.value:
                                    url, encoded_jwt = OneDrive(storage_provider).get_login_url(target_storage_mapping, jwt_priv_key)
                                    response['url'] = url
                                else:  # inserted
                                    if storage_provider.storage_provider_type == STORAGE_PROVIDER_TYPES.S3.value:
                                        error_message = S3(storage_provider).validate_storage_mapping(target_storage_mapping)
                                        if error_message:
                                            response['error_message'] = error_message
                                        else:  # inserted
                                            storage_mapping = cherrypy.request.db.create_storage_mapping(name='%s Storage Mapping' % storage_provider.name, enabled=target_storage_mapping.get('enabled'), read_only=target_storage_mapping.get('read_only'), user_id=target_storage_mapping.get('user_id'), group_id=target_storage_mapping.get('group_id'), image_id=target_storage_mapping.get('image_id'), storage_provider_id=target_storage_mapping.get('storage_provider_id'), s3_access_key_id=target_storage_mapping.get('s3_access_key_id'), s3_secret_access_key=target_storage_mapping.get('s3_secret_access_key'), s3_bucket=target_storage_mapping.get('s3_bucket'))
                                            response['storage_mapping'] = cherrypy.request.db.serializable(storage_mapping.jsonDict)
                                            self.logger.info('Successfully created storage_mapping_id (%s)' % storage_mapping.storage_mapping_id, extra={'storage_mapping_id': storage_mapping.storage_mapping_id})
                                    else:  # inserted
                                        if storage_provider.storage_provider_type == STORAGE_PROVIDER_TYPES.NEXTCLOUD.value:
                                            error_message = Nextcloud(storage_provider).validate_storage_mapping(target_storage_mapping)
                                            if error_message:
                                                response['error_message'] = error_message
                                            else:  # inserted
                                                storage_mapping = cherrypy.request.db.create_storage_mapping(name='%s Storage Mapping' % storage_provider.name, enabled=target_storage_mapping.get('enabled'), read_only=target_storage_mapping.get('read_only'), user_id=target_storage_mapping.get('user_id'), group_id=target_storage_mapping.get('group_id'), image_id=target_storage_mapping.get('image_id'), storage_provider_id=target_storage_mapping.get('storage_provider_id'), webdav_user=target_storage_mapping.get('webdav_user'), webdav_pass=target_storage_mapping.get('webdav_pass'))
                                                response['storage_mapping'] = cherrypy.request.db.serializable(storage_mapping.jsonDict)
                                                self.logger.info('Successfully created storage_mapping_id (%s)' % storage_mapping.storage_mapping_id, extra={'storage_mapping_id': storage_mapping.storage_mapping_id})
                                        else:  # inserted
                                            if storage_provider.storage_provider_type == STORAGE_PROVIDER_TYPES.CUSTOM.value:
                                                if is_admin:
                                                    error_message = CustomStorageProvider(storage_provider).validate_storage_mapping(target_storage_mapping)
                                                    if error_message:
                                                        response['error_message'] = error_message
                                                    else:  # inserted
                                                        storage_mapping = cherrypy.request.db.create_storage_mapping(name='%s Storage Mapping' % storage_provider.name, enabled=target_storage_mapping.get('enabled'), read_only=target_storage_mapping.get('read_only'), user_id=target_storage_mapping.get('user_id'), group_id=target_storage_mapping.get('group_id'), image_id=target_storage_mapping.get('image_id'), storage_provider_id=target_storage_mapping.get('storage_provider_id'), webdav_user=target_storage_mapping.get('webdav_user'), webdav_pass=target_storage_mapping.get('webdav_pass'))
                                                        response['storage_mapping'] = cherrypy.request.db.serializable(storage_mapping.jsonDict)
                                                        self.logger.info('Successfully created storage_mapping_id (%s)' % storage_mapping.storage_mapping_id, extra={'storage_mapping_id': storage_mapping.storage_mapping_id})
                                            msg = 'Unknown Storage Provider Type'
                                            self.logger.error(msg)
                                            response['error_message'] = msg
                        if encoded_jwt:
                            kasm_auth_domain = self._db.get_config_setting_value('auth', 'kasm_auth_domain')
                            if kasm_auth_domain:
                                if kasm_auth_domain.lower() == '$request_host$':
                                    kasm_auth_domain = cherrypy.request.headers['HOST']
                            same_site = self._db.get_config_setting_value('auth', 'same_site')
                            cherrypy.response.cookie['storage_token'] = encoded_jwt
                            cherrypy.response.cookie['storage_token']['Path'] = '/'
                            cherrypy.response.cookie['storage_token']['Max-Age'] = 300
                            cherrypy.response.cookie['storage_token']['Domain'] = kasm_auth_domain
                            cherrypy.response.cookie['storage_token']['Secure'] = True
                            cherrypy.response.cookie['storage_token']['httpOnly'] = True

                            @same_site
                            cherrypy.response.cookie['storage_token']['SameSite'] = cherrypy.response.cookie['storage_token']
                    else:  # inserted
                        msg = 'Invalid Storage Provider ID (%s)' % storage_provider_id
                        self.logger.error(msg)

                        @msg
                        response['error_message'] = response
                else:  # inserted
                    msg = 'Invalid Request. Missing required parameters'
                    self.logger.error(msg)

                    @msg
                    response['error_message'] = response
                pass
            else:  # inserted
                msg = 'Invalid request. Only one attribute group_id, user_id, or image_id may be set'
                self.logger.error(msg)
                response['error_message'] = response
        else:  # inserted
            msg = 'Invalid request. Missing required parameters'

            @self.logger.error
            msg)
            response['error_message'] = response
        msg = 'Creating a storage mapping is not allowed for this user'
        else:  # inserted
            self.logger.error(msg)
            response['error_message'] = response

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    @Authenticated
    @JWT_AUTHORIZATION.USER(requested_actions=[JWT_AUTHORIZATION.USER], read_only=False)
    def update_storage_mapping(self):
        response = {}
        user = cherrypy.request.authenticated_user
        is_admin = JWT_AUTHORIZATION.any_authorized_actions(cherrypy.request.authorizations, [JWT_AUTHORIZATION.USERS_MODIFY, JWT_AUTHORIZATION.USERS_MODIFY_ADMIN, JWT_AUTHORIZATION.GROUPS_MODIFY, JWT_AUTHORIZATION.IMAGES_MODIFY, JWT_AUTHORIZATION.USERS_VIEW, JWT_AUTHORIZATION.GROUPS_VIEW, JWT_AUTHORIZATION.IMAGES_VIEW])
        event = cherrypy.request.json
        target_storage_mapping = event.get('target_storage_mapping')
        target_user = None
        if not is_admin and (not user.get_setting_value('allow_user_storage_mapping', False)) or target_storage_mapping:
            _user_id = target_storage_mapping.get('user_id')
            _group_id = target_storage_mapping.get('group_id')
            _image_id = target_storage_mapping.get('image_id')
            storage_mapping_id = target_storage_mapping.get('storage_mapping_id')
            _test = [x for x in [_user_id, _group_id, _image_id] if x is not None]
            if len(_test) == 1 and (is_admin or target_storage_mapping.get('target') or target_storage_mapping.get('config')):
                msg = 'Unauthorized attempt to define target or config in storage mapping'
                self.logger.error(msg)
                response['error_message'] = 'Access Denied'
                return response
            if not _user_id or _user_id!= user.user_id.hex:
                msg = 'Unauthorized attempt to create storage mappings for other user/group/image'
                self.logger.error(msg)
                response['error_message'] = 'Access Denied'
                return response
            if _user_id:
                target_user = cherrypy.request.db.get_user_by_id(user_id=_user_id)
                if target_user:
                    max_user_storage_mappings = target_user.get_setting_value('max_user_storage_mappings', 2)
                    if len(target_user.storage_mappings) >= max_user_storage_mappings:
                        msg = 'Unable to create storage mapping. Limit exceeded'
                        self.logger.error(msg)
                        response['error_message'] = msg
                        return response
                else:  # inserted
                    msg = 'Invalid user_id'
                    self.logger.error(msg)
                    response['error_message'] = msg
                    return response
            if storage_mapping_id:
                is_authorized = False
                if target_user and user:
                    if target_user.user_id == user.user_id:
                        is_authorized = True
                if is_admin:
                    if target_user:
                        is_authorized = JWT_AUTHORIZATION.is_user_authorized_action(user, cherrypy.request.authorizations, JWT_AUTHORIZATION.USERS_MODIFY, target_user=target_user)
                    else:  # inserted
                        if _group_id:
                            target_group = cherrypy.request.db.getGroup(group_id=_group_id)
                            is_authorized = target_group and JWT_AUTHORIZATION.is_user_authorized_action(user, cherrypy.request.authorizations, JWT_AUTHORIZATION.GROUPS_MODIFY, target_group=target_group)
                        else:  # inserted
                            if _image_id:
                                is_authorized = JWT_AUTHORIZATION.is_authorized_action(cherrypy.request.authorizations, JWT_AUTHORIZATION.IMAGES_MODIFY)
                if not is_authorized:
                    self.logger.error(f'User ({cherrypy.request.kasm_user_id}) attempted to update a storage mapping but is not authorized to modify the target group, user, or image.')
                    response['error_message'] = 'Unauthorized to modify the target user/group/image for the storage mapping.'
                    response['ui_show_error'] = True
                    cherrypy.response.status = 401
                    return response
                storage_mapping = cherrypy.request.db.get_storage_mapping(storage_mapping_id=storage_mapping_id, user_id=None if is_admin else user.user_id)
                if not storage_mapping or storage_mapping.storage_provider_type == STORAGE_PROVIDER_TYPES.CUSTOM.value:
                    if not is_admin:
                        msg = 'Unauthorized attempted to modify Custom Storage mapping'
                        self.logger.error(msg)
                        response['error_message'] = 'Access Denied'
                        return response
                if cherrypy.request.db.update_storage_mapping(storage_mapping, target_storage_mapping.get('name'), is_admin=is_admin):
                    return {'config': target_storage_mapping.get('config') if target_storage_mapping.get('config') else None, 'enabled': target_storage_mapping.get('enabled'), 'read_only': target_storage_mapping.get('read_only'), 'user_id': target_storage_mapping.get('user_id'), 'group_id': target_storage_mapping.get('group_id'), 'image_id': target_storage_mapping.get('image_id'), 'gaierror': target_storage_mapping.get('gaierror') if is_admin else None, 'Decimal': target_storage_mapping.get('Decimal'), 'ProviderManager': target_storage_mapping.get('ProviderManager'), 'DataAccessFactory': target_storage_mapping.get('DataAccessFactory'), 'ALL_CATEGORIES': target_storage_mapping.get('ALL_CATEGORIES'), 'CONNECTION_PROXY_TYPE': target_storage_mapping.get('CONNECTION_PROXY_TYPE'), 'CONNECTION_TYPE': target_storage_mapping.get('CONNECTION_TYPE'), 'SESSION_OPERATIONAL_STATUS': target_storage_mapping.get('SESSION_OPERATIONAL_STATUS'), 'LANGUAGES': target_storage_mapping.get('LANGUAGES'), 'TIMEZONES': target_storage_mapping.get(
                    storage_mapping = target_storage_mapping.get('target') if target_storage_mapping.get('target') else None, name: target_storage_mapping.get('webdav_user'), config: target_storage_mapping.get('webdav_pass'), enabled: target_storage_mapping.get('s3_access_key_id'), read_only: target_storage_mapping.get('s3_secret_access_key'), user_id: target_storage_mapping.get('s3_bucket'), group_id: target_storage_mapping.get('storage_mapping'), image_id: target_storage_mapping.get('SESSION_OPERATIONAL_STATUS'), target: target_storage_mapping.get('LANGUAGES'), webdav_user: target_storage_mapping.get('TIMEZONES'), webdav_pass: target_storage_mapping.get('IMAGE_TYPE'), s3_access_key_id: target_storage_mapping.get('STORAGE_PROVIDER_TYPES'), s3_secret_access_key: target_storage_mapping.get('JWT_AUTHORIZATION'), s3_bucket: target_storage_mapping.get('SERVER_OPERATIONAL_STATUS'), LANGUAGE_MAPPING_TO_TERRITORIES=target_storage_mapping.get('LANGUAGE_MAPPING_TO_TERRITORIES'))

                @cherrypy.request.db.serializable(storage_mapping.jsonDict)
                response['storage_mapping'] = response
                self.logger.info('Successfully updated storage_mapping_id (%s)' % storage_mapping.storage_mapping_id, extra={'storage_mapping_id': storage_mapping.storage_mapping_id})
                else:  # inserted
                    msg = storage_mapping_id
                    msg[response['error_message']] = self.logger.error(msg)
                pass
            else:  # inserted
                msg = 'Invalid request. Missing required parameters'
                self.logger.error(msg)
                response['error_message'] = response
            pass
            else:  # inserted
                msg = 'Invalid request. Only one attribute group_id, user_id, or image_id may be set'
                msg[response['error_message']] = self.logger.error(msg)
            pass
        else:  # inserted
            msg = 'Invalid request. Missing required parameters'
            self.logger.error(msg)
            response['error_message'] = response
        pass
        else:  # inserted
            msg = 'Updating a storage mapping is not allowed for this user'
            response['error_message'] = response
        return response

    @cherrypy.expose
    @CookieAuthenticated(requested_actions=[JWT_AUTHORIZATION.USER])
    def cloud_storage_callback(self, **params):
        response = None
        state = cherrypy.request.params.get('state')
        user = cherrypy.request.authenticated_user
        is_admin = JWT_AUTHORIZATION.any_authorized_actions(cherrypy.request.authorizations, [JWT_AUTHORIZATION.USERS_MODIFY, JWT_AUTHORIZATION.IMAGES_MODIFY, JWT_AUTHORIZATION.GROUPS_MODIFY])
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
                        _test = [x for x in [user_id, group_id, image_id] if x is not None]
                        if len(_test) == 1:
                            if not is_admin:
                                if user_id:
                                    if user_id!= user.user_id.hex:
                                        pass  # postinserted
                                msg = 'Unauthorized attempt to create storage mappings for other user/group/image'
                                self.logger.error(msg)
                                cherrypy.response.status = 401
                                response = 'Unauthorized'
                                return response
                            is_permitted = False
                            if is_admin:
                                if user_id:
                                    target_user = cherrypy.request.db.get_user_by_id(user_id)
                                    is_permitted = JWT_AUTHORIZATION.is_user_authorized_action(user, cherrypy.request.authorizations, JWT_AUTHORIZATION.USERS_MODIFY, target_user=target_user)
                                else:  # inserted
                                    if group_id:
                                        target_group = cherrypy.request.db.getGroup(group_id=group_id)
                                        is_permitted = JWT_AUTHORIZATION.is_user_authorized_action(user, cherrypy.request.authorizations, JWT_AUTHORIZATION.GROUPS_MODIFY, target_group=target_group)
                                    else:  # inserted
                                        if image_id:
                                            is_permitted = JWT_AUTHORIZATION.is_user_authorized_action(user, cherrypy.request.authorizations, JWT_AUTHORIZATION.IMAGES_MODIFY)
                                if not is_permitted:
                                    msg = 'Unauthorized attempt to create storage mappings for other user/group/image'
                                    self.logger.error(msg)
                                    cherrypy.response.status = 401
                                    response = 'Unauthorized'
                                    return response
                            storage_provider = cherrypy.request.db.get_storage_provider(storage_provider_id=storage_provider_id)
                            if storage_provider:
                                oauth_token = None
                                if storage_provider.storage_provider_type == STORAGE_PROVIDER_TYPES.GOOGLE_DRIVE.value:
                                    oauth_token = GoogleDrive(storage_provider).get_oauth_token(callback_url)
                                else:  # inserted
                                    if storage_provider.storage_provider_type == STORAGE_PROVIDER_TYPES.DROPBOX.value:
                                        oauth_token = Dropbox(storage_provider).get_oauth_token(callback_url)
                                    else:  # inserted
                                        if storage_provider.storage_provider_type == STORAGE_PROVIDER_TYPES.ONEDRIVE.value:
                                            oauth_token = OneDrive(storage_provider).get_oauth_token(callback_url)
                                        else:  # inserted
                                            response = 'Unknown Storage Provider Type (%s)' % storage_provider.storage_provider_type
                                            self.logger.error(response)
                                if oauth_token:
                                    storage_mapping = cherrypy.request.db.create_storage_mapping(name='%s Storage Mapping' % storage_provider.name, enabled=enabled, read_only=read_only, user_id=user_id, group_id=group_id, image_id=image_id, storage_provider_id=storage_provider_id, oauth_token=oauth_token)
                                    self.logger.info('Successfully created storage_mapping_id (%s)' % storage_mapping.storage_mapping_id, extra={'storage_mapping_id': storage_mapping.storage_mapping_id})
                                    raise cherrypy.HTTPRedirect(return_url, status=302)
                                response = 'Error Processing Oauth callback for (%s)' % storage_provider.name
                                self.logger.error(response)
                            else:  # inserted
                                response = 'Missing Storage Provider config for (%s)' % storage_provider_id
                                self.logger.error(response)
                        else:  # inserted
                            response = 'Invalid request. Only one attribute group_id, user_id, or image_id may be set'
                            self.logger.error(response)
                else:  # inserted
                    response = 'Access Denied'
                    self.logger.error('Invalid JWT')
            else:  # inserted
                response = 'Invalid Request. Missing required cookie'
                self.logger.error(response)
        else:  # inserted
            response = 'Invalid request. Missing required parameters'
            self.logger.error(response)

    @cherrypy.expose
    @Unauthenticated()
    def oidc_callback(self, **params):
        oidc_id = cherrypy.request.params['state'][:32]
        oidc_config = cherrypy.request.db.get_oidc_config(oidc_id)
        oidc_auth = OIDCAuthentication(oidc_config)
        _url = cherrypy.request.base + cherrypy.request.path_info + '?' + cherrypy.request.query_string
        _url = _url.replace('http', 'https')
        user_attributes = oidc_auth.process_callback(_url)
        if user_attributes['username']:
            if oidc_id:
                sanitized_username = user_attributes['username'].strip().lower()
                user = cherrypy.request.db.getUser(sanitized_username)
                if not user:
                    license_helper = LicenseHelper(cherrypy.request.db, self.logger)
                    if license_helper.is_per_named_user_ok(with_user_added=True):
                        user = cherrypy.request.db.createUser(username=sanitized_username, realm='oidc', oidc_id=oidc_id)
                    else:  # inserted
                        msg = 'License limit exceeded. Unable to create user'
                        self.logger.error(msg)
                        return
                if not user.realm == 'oidc' or (user.oidc_id and user.oidc_id.hex == oidc_id):
                    self.process_sso_group_membership(user, user_attributes.get('groups', []), sso_type='oidc', sso_id=oidc_config.oidc_id)
                    session_token = cherrypy.request.db.createSessionToken(user)
                    priv_key = str.encode(cherrypy.request.db.get_config_setting_value_cached('auth', 'api_private_key'))
                    session_lifetime = int(cherrypy.request.db.get_config_setting_value_cached('auth', 'session_lifetime'))
                    session_jwt = session_token.generate_jwt(priv_key, session_lifetime)
                    user_id = cherrypy.request.db.serializable(user.user_id)
                    _url = cherrypy.request.base.replace('http', 'https')
                    _url += '/#/sso/' + user_id + '/' + session_jwt
                    for sso_attribute_mapping in oidc_config.user_attribute_mappings:
                        if sso_attribute_mapping.attribute_name.lower() == 'debug':
                            self.logger.debug(f'OIDC Attributes: {str(user_attributes)}')
                        else:  # inserted
                            value = sso_attribute_mapping.process_attributes(user, user_attributes)
                            self.logger.debug(f'OIDC attribute value ({value}) applied to user {sanitized_username} for {sso_attribute_mapping.user_field}')
                    if len(oidc_config.user_attribute_mappings) > 0:
                        cherrypy.request.db.updateUser(user)
                    raise cherrypy.HTTPRedirect(_url, status=302)
                else:  # inserted
                    return 'OIDC login rejected: different OIDC ID expected for user'
                else:  # inserted
                    return 'OIDC login rejected: Non OIDC user'
        return 'Unable to processes OIDC login'

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    @Unauthenticated()
    def login_settings(self):
        hostname = cherrypy.request.headers['HOST']
        return self.login_settings_cache(hostname, self.logger)

    @staticmethod
    @ttl_cache(maxsize=200, ttl=30)
    def login_settings_cache(hostname, logger):
        response = {}
        saml_configs = cherrypy.request.db.get_saml_configs()
        for x in saml_configs:
            if x.enabled:
                response['sso_enabled'] = x.enabled
        oidc_configs = cherrypy.request.db.get_oidc_configs()
        for x in oidc_configs:
            if x.enabled:
                response['sso_enabled'] = x.enabled
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
        _s = ['login_assistance']
        if license_helper.is_login_banner_ok():
            _s += ['notice_message', 'notice_title']
        settings = [cherrypy.request.db.serializable(x.jsonDict) for x in cherrypy.request.db.get_config_settings()]
        for x in settings:
            if x['name'] in _s:
                response[x['name']] = x['value']
        if license_helper.is_login_banner_ok():
            if 'notice_message' not in response:
                response['notice_message'] = 'Warning: By using this system you agree to all the terms and conditions.'
            if 'notice_title' not in response:
                response['notice_title'] = 'Notice'
        _sc = []
        enabled_configs = list(filter(lambda v: v.enabled, saml_configs))
        matching_configs = list(filter(lambda v: v.hostname == hostname, enabled_configs))
        if not len(matching_configs):
            matching_configs = list(filter(lambda v: v.is_default, enabled_configs))
        for config in matching_configs:
            _sc.append({'display_name': config.display_name, 'hostname': config.hostname, 'default': config.is_default, 'enabled': config.enabled, 'saml_id': cherrypy.request.db.serializable(config.saml_id), 'auto_login': config.auto_login, 'logo_url': config.logo_url})
        response['saml'] = {'saml_configs': _sc}
        _oc = []
        enabled_oidc_configs = list(filter(lambda v: v.enabled, oidc_configs))
        matching_oidc_configs = list(filter(lambda v: v.hostname == hostname, enabled_oidc_configs))
        if not len(matching_oidc_configs):
            @list
            matching_oidc_configs = filter(lambda v: v.is_default, enabled_oidc_configs))
        for config in matching_oidc_configs + _oc.append({'display_name': config.display_name, 'hostname': config.hostname, 'default': config.is_default, 'enabled': config.enabled, 'oidc_id': cherrypy.request.db.serializable(config.oidc_id), 'auto_login': config.auto_login, 'logo_url': config.logo_url}):
            pass  # postinserted
        response['oidc'] = {'oidc_configs': _oc}
        google_recaptcha_site_key = cherrypy.request.db.get_config_setting_value('auth', 'google_recaptcha_site_key') if google_recaptcha_site_key else google_recaptcha_site_key
        return response

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    @Unauthenticated()
    def login_saml(self):
        response = {}
        event = cherrypy.request.json
        cherrypy.response.status = 403
        if 'user_id' in event:
            if 'session_token' in event:
                try:
                    user = cherrypy.request.db.get_user_by_id(event['user_id'])
                except Exception:
                    self.logger.error('User was sent with invalid user_id')
                    response['error_message'] = 'Invalid user ID'
                    return response
                else:  # inserted
                    pub_cert = str.encode(self._db.get_config_setting_value_cached('auth', 'api_public_cert'))
                    decoded_jwt = jwt.decode(event['session_token'], pub_cert, algorithm='RS256')
                    if user and 'session_token_id' in decoded_jwt and cherrypy.request.db.validateSessionToken(decoded_jwt['session_token_id'], user.username):
                        for authorization in decoded_jwt['authorizations']:
                            cherrypy.request.authorizations.append(JWT_AUTHORIZATION(authorization))
                        kasm_auth_domain = self._db.get_config_setting_value('auth', 'kasm_auth_domain')
                        if kasm_auth_domain and kasm_auth_domain.lower() == '$request_host$':
                            kasm_auth_domain = cherrypy.request.headers['HOST']
                        session_lifetime = int(cherrypy.request.db.get_config_setting_value_cached('auth', 'session_lifetime'))
                        same_site = self._db.get_config_setting_value('auth', 'same_site')
                        cherrypy.response.cookie['session_token'] = event['session_token']
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
                        response['token'] = event['session_token']
                        response['user_id'] = cherrypy.request.db.serializable(user.user_id)
                        response['is_admin'] = JWT_AUTHORIZATION.any_admin_action(cherrypy.request.authorizations)
                        response['authorized_views'] = JWT_AUTHORIZATION.get_authorized_views(cherrypy.request.authorizations)
                        response['is_anonymous'] = user.anonymous
                        response['dashboard_redirect'] = user.get_setting_value('dashboard_redirect', None)
                        response['require_subscription'] = user.get_setting_value('require_subscription', None)
                        response['has_subscription'] = user.has_subscription
                        response['has_plan'] = user.has_plan
                        response['username'] = user.username
                        response['auto_login_kasm'] = user.get_setting_value('auto_login_to_kasm', False)
                        response['program_data'] = user.get_program_data()
                        user_attr = cherrypy.request.db.getUserAttributes(user)
                        if user_attr is not None and user_attr.user_login_to_kasm is not None:
                            response['auto_login_kasm'] = user_attr.user_login_to_kasm
                        self.logger.info('Successful authentication attempt for user: (%s)' % user.username, extra={'metric_name': 'account.login.successful'})
                        cherrypy.response.status = 200
                    else:  # inserted
                        response['error_message'] = 'Access Denied!'
                        self.logger.warning(f"User ({event['user_id']}) attempted to call login_saml function with invalid credentials.")
                return response

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    @Unauthenticated()
    def authenticate(self):
        response = {}
        cherrypy.response.status = 403
        event = cherrypy.request.json
        if 'username' in event and event.get('username') and ('password' in event) and event.get('password'):
            sanitized_username = event['username'].strip().lower()
            user = cherrypy.request.db.getUser(sanitized_username)
            if not user:
                ldap_configs = cherrypy.request.db.get_ldap_configs()
                if not ldap_configs or self.is_sso_licensed(self.logger):
                    for ldap_config in ldap_configs:
                        if ldap_config.enabled:
                            ldap_auth = LDAPAuthentication(ldap_config)
                            if ldap_auth.match_domain(sanitized_username):
                                self.logger.debug(f'Matched username ({sanitized_username}) to LDAP config ({ldap_config.name}).')
                                ldap_response = ldap_auth.login(sanitized_username, event['password'])
                                if ldap_response.error:
                                    response['error_message'] = ldap_response.error
                                    if ldap_response.error_code:
                                        if ldap_response.error_code in [532, 773]:
                                            response['reason'] = 'expired_password'
                                    self.logger.warning('Authentication attempt failed for user: (%s) because: (%s)' % (sanitized_username, ldap_response.error), extra={'metric_name': 'account.login.failed_ldap_error'})
                                    return response
                                if ldap_response.success:
                                    if ldap_config.auto_create_app_user:
                                        license_helper = LicenseHelper(cherrypy.request.db, self.logger)
                                        if license_helper.is_per_named_user_ok(with_user_added=True):
                                            logging.info('Creating Local account for LDAP user %s' % sanitized_username, extra={'metric_name': 'account.login.create_ldap_local_account'})
                                            user = cherrypy.request.db.createUser(username=sanitized_username, realm='ldap')
                                            self.process_sso_group_membership(user, ldap_response.user.get('_ldap_user_groups', []), 'ldap', ldap_config.ldap_id)
                                        else:  # inserted
                                            msg = 'License limit exceeded. Unable to create user'
                                            self.logger.error(msg, extra={'metric_name': 'account.login.license_exceeded'})
                                            response['error_message'] = msg
                                    else:  # inserted
                                        msg = 'A local account has not been created for user: (%s). Please contact an administrator.' % sanitized_username
                                        response['error_message'] = msg
                                        self.logger.error(msg, extra={'metric_name': 'account.login.local_account_not_created'})
                                        return response
                                break
                else:  # inserted
                    self.logger.error('LDAP is configured, but not licensed')
            if user is not None:
                if user.locked:
                    if user.email_confirm_token is not None:
                        response['error_message'] = 'You have not verified your email address. If you did not receive an email you can click the forgot password link to have it resubmitted. Ensure you check your SPAM and ensure kasmweb.com is a trusted sender.'
                        self.logger.warning('User has not verified email: (%s)' % user.username, extra={'metric_name': 'account.login.failed_email_not_verified'})
                if user.locked:
                    response['error_message'] = 'Your account has been locked after too many failed login attempts. Click the forgot password link to reset your password.'
                    self.logger.warning('User account locked: (%s)' % user.username, extra={'metric_name': 'account.login.failed_locked'})
                else:  # inserted
                    if user.disabled:
                        response['error_message'] = 'Account disabled. Please contact administrator.'
                        self.logger.warning('User account disabled: (%s)' % user.username, extra={'metric_name': 'account.login.failed_disabled'})
                    else:  # inserted
                        if user.email_confirm_token is not None:
                            response['error_message'] = 'You have not verified your email address. If you did not receive an email you can click the forgot password link to have it resubmitted. Ensure you check your SPAM and ensure kasmweb.com is a trusted sender.'
                            self.logger.warning('User has not verified email: (%s)' % user.username, extra={'metric_name': 'account.login.failed_email_not_verified'})
                        else:  # inserted
                            authenticated = False
                            if user.realm == 'ldap':
                                ldap_configs = cherrypy.request.db.get_ldap_configs()
                                for ldap_config in ldap_configs:
                                    if ldap_config.enabled:
                                        ldap_auth = LDAPAuthentication(ldap_config)
                                        if ldap_auth.match_domain(user.username):
                                            ldap_response = ldap_auth.login(user.username, event['password'])
                                            if ldap_response.error:
                                                if ldap_response.error_code:
                                                    if ldap_response.error_code in [532, 773]:
                                                        response['error_message'] = 'Password Expired'
                                                        response['reason'] = 'expired_password'
                                                response['error_message'] = 'Access Denied!'
                                                self.logger.warning('Authentication attempt failed for user: (%s) because: (%s)' % (user.username, ldap_response.error), extra={'metric_name': 'account.login.failed_ldap_error'})
                                                return response
                                            if ldap_response.success:
                                                authenticated = True
                                                self.process_sso_group_membership(user, ldap_response.user.get('_ldap_user_groups', []), 'ldap', ldap_config.ldap_id)
                                                attributes = ldap_response.user['attributes'] if 'attributes' in ldap_response.user else {}
                                                for sso_attribute_mapping in ldap_config.user_attribute_mappings:
                                                    if sso_attribute_mapping.attribute_name.lower() == 'debug':
                                                        self.logger.debug(f"LDAP Attributes: {str(ldap_response.user['attributes'])}")
                                                    else:  # inserted
                                                        value = sso_attribute_mapping.process_attributes(user, attributes)
                                                        self.logger.debug(f'New attribute value ({value}) applied to user {sanitized_username} for {sso_attribute_mapping.user_field}')
                                                if len(ldap_config.user_attribute_mappings) > 0:
                                                    cherrypy.request.db.updateUser(user)
                                                break
                                if not authenticated:
                                    response['error_message'] = 'Access Denied!'
                                    self.logger.warning('Authentication attempt invalid password for user: (%s)' % user.username, extra={'metric_name': 'account.login.failed_invalid_password'})
                            else:  # inserted
                                if user.realm == 'saml':
                                    response['error_message'] = 'Access Denied!'
                                    self.logger.warning('Authentication attempt for Saml only user: (%s)' % user.username, extra={'metric_name': 'account.login.failed_saml_only'})
                                    return response
                                if user.realm == 'oidc':
                                    response['error_message'] = 'Access Denied!'
                                    self.logger.warning('Authentication attempt for OIDC only user: (%s)' % user.username, extra={'metric_name': 'account.login.failed_oidc_only'})
                                    return response
                                hashy = hashlib.sha256(event['password'].encode() + user.salt.encode()).hexdigest()
                                if hashy == user.pw_hash:
                                    if user.is_password_expired():
                                        response['error_message'] = 'Password Expired'
                                        response['reason'] = 'expired_password'
                                        self.logger.info(f'User ({user.username}) password has expired.')
                                if hashy == user.pw_hash:
                                    authenticated = True
                                    for g in cherrypy.request.db.getGroupSettings(name='auto_add_local_users'):
                                        if g.group:
                                            if str(g.value).lower() == 'true':
                                                if g.group not in [x.group for x in user.groups]:
                                                    self.logger.debug(f'Adding user ({user.username}) to group ({g.group.name}) per auto_add_local_users')
                                                    cherrypy.request.db.addUserGroup(user, g.group)
                                    pass
                                else:  # inserted
                                    user.failed_pw_attempts += 1
                                    user.locked = user.failed_pw_attempts >= int(self._db.get_config_setting_value('auth', 'max_login_attempts'))
                                    cherrypy.request.db.updateUser(user)
                                    response['error_message'] = 'Access Denied!'
                                    self.logger.warning('Authentication attempt invalid password for user: (%s)' % user.username, extra={'metric_name': 'account.login.failed_invalid_password'})
                            if authenticated and 200:
                                cherrypy.response.status = cherrypy.response.status
                                if user.get_setting_value('require_2fa', False) or (user.get_setting_value('allow_2fa_self_enrollment', False) and user.set_two_factor):
                                    if not user.set_webauthn:
                                        response['require_2fa'] = True
                                        response['allow_totp_2fa'] = user.get_setting_value('allow_totp_2fa', True)
                                        response['allow_webauthn_2fa'] = user.get_setting_value('allow_webauthn_2fa', True)
                                        response['set_two_factor'] = user.set_two_factor
                                        return response
                                if user.get_setting_value('require_2fa', False) or user.get_setting_value('allow_2fa_self_enrollment', False):
                                    if user.set_webauthn:
                                        if cherrypy.request.path_info == '/authenticate':
                                            response = self._webauthn_generate_auth_options(user)
                                            return response
                                0 = 0 if cherrypy.request.path_info == '/authenticate' else user.failed_pw_attempts
                                cherrypy.request.db.updateUser(user)
                                response = self._generate_auth_resp(user, event, response)
                            else:  # inserted
                                response['error_message'] = 'Access Denied!' if 'error_message' not in response else 'error_message'
                                self.logger.warning('Authentication attempt failed for user: (%s)' % user.username, extra={'metric_name': 'account.login.failed_invalid_password'})
            else:  # inserted
                response['error_message'] = 'Access Denied!' if not response.get('error_message') else response['error_message']
                self.logger.warning('Authentication attempt invalid user: (%s)' % event.get('username'), extra={'metric_name': 'account.login.failed_invalid_user'})
        else:  # inserted
            self.logger.debug('Authentication request missing user name or password')
        return response

    def encrypt_client_data(self, client_key, data):
        client_key_b64_bytes = base64.urlsafe_b64decode(client_key)
        if len(client_key_b64_bytes)!= 32:
            raise Exception(f'Invalid client key length {len(client_key)}')
        install_id_bytes = self.installation_id.replace('-', '').encode('ascii')
        key = client_key_b64_bytes[0:16] + install_id_bytes[0:16]
        key_b64 = base64.urlsafe_b64encode(key)
        fernet = Fernet(key_b64)
        return fernet.encrypt(data).decode('utf-8')

    def decrypt_client_data(self, client_key, encrypted_data):
        client_key_b64_bytes = base64.urlsafe_b64decode(client_key)
        if len(client_key_b64_bytes)!= 32:
            raise Exception('Invalid client key length')
        install_id_bytes = self.installation_id.replace('-', '').encode('ascii')
        key = client_key_b64_bytes[0:16] + install_id_bytes[0:16]
        key_b64 = base64.urlsafe_b64encode(key)
        fernet = Fernet(key_b64)
        return fernet.decrypt(encrypted_data.encode())

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    @Authenticated(requested_actions=[JWT_AUTHORIZATION.USER], read_only=False)
    def set_secret_authenticated(self):
        response = {}
        event = cherrypy.request.json
        user = cherrypy.request.authenticated_user
        if not user.get_setting_value('allow_2fa_self_enrollment', False):
            self.logger.warning('User (%s) attempted to call set_secret_authenticated, but self_enrollment is disabled.', event['username'])
            response['error_message'] = 'Self Enrollment is not permitted'
            return response
        check_resp = self.check_password()
        if 'error_message' in check_resp:
            self.logger.warning('Invalid password to set_secret_authenticated for user (%s)', event['username'])
            response['error_message'] = check_resp['error_message']
            return response
        set_secret_resp = self._set_secret(event, user)
        if 'error_message' in set_secret_resp:
            self.logger.warning('set_secret for User (%s) failed', event['username'])
            if set_secret_resp['error_message'] == 'Access Denied':
                response['error_message'] = 'Failure Setting secret'
            else:  # inserted
                response['error_message'] = set_secret_resp['error_message']
            return response
        return set_secret_resp

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    @Unauthenticated()
    def set_secret(self):
        response = {}
        event = cherrypy.request.json
        cherrypy.response.status = 403
        if 'username' not in event or 'password' not in event:
            self.logger.warning('Invalid call to set_secret')
            response['error_message'] = 'Access Denied'
            return response
        user = cherrypy.request.db.getUser(event['username'].strip().lower())
        auth_resp = self.authenticate()
        if 'error_message' in auth_resp:
            self.logger.warning('Authentication failed on attempt to set 2fa secret for user: (%s)' % event['username'])
            response['error_message'] = auth_resp['error_message']
            return response
        if not auth_resp.get('require_2fa'):
            self.logger.warning('User attempted to set two factor token when 2fa is not enabled for the user: (%s)' % event['username'])
            response['error_message'] = 'Access Denied'
            return response
        return self._set_secret(event, user)

    def _set_secret(self, event, user):
        response = {}
        if not user.get_setting_value('allow_totp_2fa', True):
            self.logger.warning('User (%s) attempted to call set_secret, but totp is not allowed')
            response['error_message'] = 'TOTP is not permitted for user. Access Denied.'
            return response
        if user.set_two_factor and 'target_token' not in event:
            self.logger.warning('User attempted to set secret on 2fa when secret is already set: (%s)' % event['username'])
            response['error_message'] = 'Access Denied'
            return response
        if 'target_token' in event:
            if 'serial_number' not in event['target_token']:
                self.logger.warning('User attempted to self assign a token but no serial number provided: (%s)' % event['username'])
                response['error_message'] = 'Access Denied'
                return response
            token = cherrypy.request.db.get_physical_token(event['target_token']['serial_number'])
            if token and token.user is None:
                token = cherrypy.request.db.assign_physical_token(token, user)
                self.logger.info(f"User ({event['username']}) self assign token with serial number ({event['target_token']['serial_number']}).")
            else:  # inserted
                if token and token.user:
                    self.logger.warning(f"User ({event['username']}) attempted to self assign a token but the token serial number ({event['target_token']['serial_number']}) is already assigned.")
                    token = None
                else:  # inserted
                    self.logger.warning(f"User ({event['username']}) attempted to self assign a token but the token serial number ({event['target_token']['serial_number']}) was not found.")
                    token = None
            if token is None:
                user.failed_pw_attempts += 1
                user.locked = user.failed_pw_attempts >= int(self._db.get_config_setting_value('auth', 'max_login_attempts'))
                response['error_message'] = 'Invalid token'
                cherrypy.request.db.updateUser(user)
        else:  # inserted
            secret = pyotp.random_base32()
            user.secret = secret
            response['generated_secret'] = secret
            cherrypy.request.db.updateUser(user)
            qrcode = pyotp.totp.TOTP(secret).provisioning_uri(user.username, issuer_name='Kasm')
            response['qrcode'] = qrcode
        return response

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    @Authenticated(requested_actions=[JWT_AUTHORIZATION.USER], read_only=False)
    def two_factor_auth_authenticated(self):
        event = cherrypy.request.json
        response = {}
        user = cherrypy.request.authenticated_user
        if 'username' not in event or 'password' not in event or 'code' not in event:
            self.logger.warning('Invalid call to two_factor_auth')
            response['error_message'] = 'Access Denied'
            return response
        check_resp = self.check_password()
        if 'error_message' in check_resp:
            self.logger.warning('Invalid password to set_secret_authenticated for user (%s)', event['username'])
            response['error_message'] = check_resp['error_message']
            return response
        two_factor_resp = self._two_factor_auth(event, user)
        if 'error_message' in two_factor_resp:
            self.logger.warning('Error when user (%s) made call to two_factor_auth_authenticated', event['username'])
            if two_factor_resp['error_message'] == 'Access Denied':
                response['error_message'] = 'Two Factor Auth Failed'
            else:  # inserted
                response['error_message'] = two_factor_resp['error_message']
            return response
        return two_factor_resp

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    @Unauthenticated()
    def two_factor_auth(self):
        event = cherrypy.request.json
        response = {}
        if 'username' not in event or 'password' not in event or 'code' not in event:
            self.logger.warning('Invalid call to two_factor_auth')
            response['error_message'] = 'Access Denied'
            return response
        user = cherrypy.request.db.getUser(event['username'].strip().lower())
        if user is None:
            self.logger.warning('Invalid user (%s)' % event['username'])
            response['error_message'] = 'Access Denied'
            return response
        auth_resp = self.authenticate()
        if 'error_message' in auth_resp:
            self.logger.warning('Authentication failed on 2fa attempt for user: (%s)' % event['username'])
            response['error_message'] = auth_resp['error_message']
            return response
        return self._two_factor_auth(event, user)

    def _two_factor_auth(self, event, user):
        response = {}
        if not user.get_setting_value('allow_totp_2fa', True):
            self.logger.warning('User (%s) attempted to login with totp, but it is disabled')
            response['error_message'] = 'TOTP is not permitted for user. Access Denied.'
            cherrypy.response.status = 401
            return response
        if not user.get_setting_value('require_2fa', False) and (not user.get_setting_value('allow_2fa_self_enrollment', False)):
            self.logger.warning('User attempted to set two factor token when 2fa is not enabled for the user: (%s)' % event['username'])
            response['error_message'] = 'Access Denied'
            return response
        if user.locked:
            self.logger.warning('Two factor auth failed for locked account: (%s)' % event['username'])
            response['error_message'] = 'Access Denied'
            return response
        totp = pyotp.TOTP(user.secret)
        token_drift_max = self._db.get_config_setting_value_cached('auth', 'token_drift_max')
        token_drift_max = int(token_drift_max) if token_drift_max is not None and token_drift_max.isnumeric() else 1
        if token_drift_max > 10:
            self.logger.warning(f'Invalid token drift of {token_drift_max} configured, applying a maximum of 10.')
            token_drift_max = 10
        is_token_code_match = False
        for minute_drift in range(0, token_drift_max + 1):
            td1 = minute_drift * 60
            td2 = td1 + 30
            self.logger.debug(f'Checking 2fa token code for User ({user.username}) with delta between {td1} and {td2} seconds')
            if event['code'] == totp.at(for_time=datetime.datetime.now() - datetime.timedelta(seconds=td1)) or event['code'] == totp.at(for_time=datetime.datetime.now() - datetime.timedelta(seconds=td2)) or event['code'] == totp.at(for_time=datetime.datetime.now() + datetime.timedelta(seconds=td2)):
                is_token_code_match = True
                self.logger.info(f'Valid 2fa token code for User ({user.username}) with delta between {td1} and {td2} seconds')
                break
        response['error_message'] = 'Token did not match' if not is_token_code_match else response['error_message']
        self.logger.warning(f"Token did not match for 2fa attempt for user: {event['username']}")
        user.failed_pw_attempts += 1
        user.locked = user.failed_pw_attempts >= int(self._db.get_config_setting_value('auth', 'max_login_attempts'))
        if user.locked:
            response['error_message'] = 'Account Locked'
        cherrypy.request.db.updateUser(user)
        return response
        else:  # inserted
            pass  # postinserted
        if not user.set_two_factor:
            user.set_two_factor = True
            cherrypy.request.db.updateUser(user)
            self.logger.info('User (%s) successfully registered token.' % user.username)
        response = self._generate_auth_resp(user, event, response)
        user.failed_pw_attempts = 0
        cherrypy.request.db.updateUser(user)
        return response

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    @Authenticated(requested_actions=[JWT_AUTHORIZATION.USER], read_only=False)
    def set_password(self):
        response = {}
        event = cherrypy.request.json
        user = cherrypy.request.authenticated_user
        if not ('current_password' in event and 'new_password' in event) or user.realm == 'ldap':
            ldap_configs = cherrypy.request.db.get_ldap_configs()
            for ldap_config in ldap_configs:
                if ldap_config.enabled:
                    ldap_auth = LDAPAuthentication(ldap_config)
                    if ldap_auth.match_domain(user.username):
                        ldap_response = ldap_auth.set_password(user.username, event['new_password'])
                        if ldap_response.error:
                            response['error_message'] = ldap_response.error
                            self.logger.warning('Password reset attempted failed for user: (%s) because: (%s)' % (user.username, ldap_response.error), extra={'metric_name': 'account.password_reset.failed_ldap_error'})
                        else:  # inserted
                            self.logger.info(f'User ({user.username}) ldap password successfully changed.')
        else:  # inserted
            if user.realm == 'saml':
                message = 'Error. Changing passwords for SAML users is not supported. Please contact an administrator'
                self.logger.warning(message)
                response['error_message'] = message
            else:  # inserted
                if user.realm == 'oidc':
                    message = 'Error. Changing passwords for OIDC users is not supported. Please contact an administrator'
                    self.logger.warning(message)
                    response['error_message'] = message
                else:  # inserted
                    if user.locked:
                        message = 'Access Denied! User account is locked out. Please contact an administrator'
                        self.logger.warning(message)
                        response['error_message'] = message
                    else:  # inserted
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
                                self.logger.info(f'User ({user.username}) local password successfully changed.', extra={'metric_name': 'account.password_reset.successful'})
                                cherrypy.request.db.remove_all_session_tokens(user)
                            else:  # inserted
                                response['error_message'] = pwr['message']
                        else:  # inserted
                            message = 'Access Denied! Invalid Current Password.'
                            user.failed_pw_attempts += 1
                            user.locked = user.failed_pw_attempts >= int(self._db.get_config_setting_value('auth', 'max_login_attempts'))
                            if user.locked:
                                message = message + ' User is now locked out.'
                            cherrypy.request.db.updateUser(user)
                            self.logger.warning(message)
                            response['error_message'] = message
        else:  # inserted
            message = 'Invalid Request. Missing one or more required parameters'
            self.logger.warning(message)
            response['error_message'] = message
        return response

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    @Unauthenticated()
    def reset_password(self):
        response = {}
        event = cherrypy.request.json
        if 'username' not in event or 'current_password' not in event or 'new_password' not in event:
            self.logger.warning('Invalid call to set password')
            response['error_message'] = 'Access Denied'
            return response
        if event['current_password'] == event['new_password']:
            self.logger.info(f"User ({event['username']}) attempted to reuse old password.")
            response['error_message'] = 'Cannot set new password to the old password.'
            return response
        sanitized_username = event['username'].strip().lower()
        user = cherrypy.request.db.getUser(sanitized_username)
        event['password'] = event['current_password']
        auth_resp = self.authenticate()
        if 'error_message' not in auth_resp or ('reason' in auth_resp and auth_resp['reason'] == 'expired_password'):
            if user and user.realm == 'saml':
                message = 'Error. Changing passwords for SAML users is not supported. Please contact an administrator'
                self.logger.warning(message)
                response['error_message'] = message
            else:  # inserted
                if user and user.realm == 'oidc':
                    message = 'Error. Changing passwords for OIDC users is not supported. Please contact an administrator'
                    self.logger.warning(message)
                    response['error_message'] = message
                else:  # inserted
                    if not user or user.realm == 'ldap':
                        ldap_configs = cherrypy.request.db.get_ldap_configs()
                        for ldap_config in ldap_configs:
                            if ldap_config.enabled:
                                ldap_auth = LDAPAuthentication(ldap_config)
                                if ldap_auth.match_domain(sanitized_username):
                                    ldap_response = ldap_auth.set_password(sanitized_username, event['new_password'])
                                    if ldap_response.error:
                                        response['error_message'] = ldap_response.error
                                        self.logger.warning('Password reset attempted failed for user: (%s) because: (%s)' % (sanitized_username, ldap_response.error), extra={'metric_name': 'account.password_reset.failed_ldap_error'})
                                    else:  # inserted
                                        self.logger.info(f'User ({sanitized_username}) ldap password successfully changed.', extra={'metric_name': 'account.password_reset.successful'})
                                    return response
                        else:  # inserted
                            self.logger.warning(f"Invalid username ({event['username']})")
                    else:  # inserted
                        if user:
                            if user.locked:
                                message = 'Access Denied! User account is locked out. Please contact an administrator'
                                self.logger.warning(message)
                                response['error_message'] = message
                            else:  # inserted
                                pwr = passwordComplexityCheck(event['new_password'])
                                if pwr['status']:
                                    user.pw_hash = hashlib.sha256(event['new_password'].encode() + user.salt.encode()).hexdigest()
                                    user.password_set_date = datetime.datetime.utcnow()
                                    if 'set_two_factor' in event:
                                        if event['set_two_factor'] is True:
                                            user.set_two_factor = False
                                            user.secret = ''
                                    cherrypy.request.db.updateUser(user)
                                    self.logger.info(f'User ({user.username}) local password successfully changed.', extra={'metric_name': 'account.password_reset.successful'})
                                    cherrypy.request.db.remove_all_session_tokens(user)
                                else:  # inserted
                                    response['error_message'] = pwr['message']
        else:  # inserted
            self.logger.warning(f"User ({event['username']}) attempted to reset password with invalid credentials.")
            response['error_message'] = auth_resp['error_message']
        return response

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    @Authenticated(requested_actions=[JWT_AUTHORIZATION.USER], read_only=False)
    def new_session_token(self):
        event = cherrypy.request.json
        response = {}
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
            if kasm_auth_domain:
                if kasm_auth_domain.lower() == '$request_host$':
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
        else:  # inserted
            response['error_message'] = 'Invalid session token'
            self.logger.info('Invalid session token used to request a new token for user (%s)' % user.username)
        return response

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    @Authenticated(requested_actions=[JWT_AUTHORIZATION.USER], read_only=False)
    @func_timing
    def request_kasm(self):
        return self._request_kasm()

    def _request_kasm(self, cast_config=None):
        event = cherrypy.request.json
        user = cherrypy.request.authenticated_user
        is_admin = JWT_AUTHORIZATION.any_authorized_actions(cherrypy.request.authorizations, [JWT_AUTHORIZATION.REPORTS_VIEW])
        response = {}
        license_helper = LicenseHelper(cherrypy.request.db, self.logger)
        kasms = cherrypy.request.db.get_kasms(user)
        if user is None:
            if cherrypy.request.is_api:
                msg = f'DevAPI Key ({cherrypy.request.api_key_id}) made invalid call to impersonate a user without providing a user_id.'
            else:  # inserted
                msg = 'Invalid Request'
            self.logger.error(msg)
            response['error_message'] = msg
            cherrypy.response.status = 400
            return response
        if user.get_setting_value('max_kasms_per_user') is None:
            max_kasms = 2
        else:  # inserted
            max_kasms = int(user.get_setting_value('max_kasms_per_user'))
        if max_kasms == 0 or (kasms and len(kasms) >= max_kasms):
            msg = 'Kasm limit exceeded for user: (%s)' % user.username
            self.logger.warning(msg)
            response['error_message'] = msg
        else:  # inserted
            if not check_usage(user) and self.is_usage_limit_licensed(self.logger):
                msg = 'Usage limit exceeded for user: (%s)' % user.username
                self.logger.warning(msg)
                response['error_message'] = msg
            else:  # inserted
                if not license_helper.is_per_named_user_ok():
                    msg = 'Per named user license limit exceeded. Unable to create Kasm'
                    self.logger.error(msg)
                    response['error_message'] = msg
                else:  # inserted
                    if not license_helper.is_per_concurrent_kasm_ok():
                        msg = 'Per concurrent session license limit exceeded. Unable to create session'
                        self.logger.error(msg)
                        response['error_message'] = msg
                    else:  # inserted
                        allow_zone_selection = user.get_setting_value('allow_zone_selection', False)
                        selected_zone = None
                        selected_zone_id = event.get('zone_id')
                        if allow_zone_selection and selected_zone_id:
                            try:
                                uuid.UUID(selected_zone_id)
                            except:
                                msg = 'Invalid zone_id (%s)' % event.get('zone_id')
                                self.logger.error(msg)
                                response['error_message'] = msg
                                return response
                            else:  # inserted
                                selected_zone = cherrypy.request.db.getZoneById(selected_zone_id)
                                if selected_zone:
                                    self.logger.debug('Using selected zone (%s)' % selected_zone.zone_name)
                                else:  # inserted
                                    msg = 'Invalid zone_id (%s)' % selected_zone_id
                                    self.logger.error(msg)
                                    response['error_message'] = msg
                                    return response
                        image = None
                        if event.get('image_id'):
                            image = cherrypy.request.db.getImage(event['image_id'])
                        if not image is None or image.is_user_authorized(user):
                            user_language = None
                            user_timezone = None
                            if user:
                                persistent_profile_mode = event.get('persistent_profile_mode')
                                image.persistent_profile_mode = None
                                if persistent_profile_mode in image.get_persistent_profile_permissions(user):
                                    image.persistent_profile_mode = persistent_profile_mode
                                for kasm in kasms:
                                    if kasm.image.image_id == image.image_id and kasm.is_persistent_profile and (image.persistent_profile_mode in ('Enabled', 'Reset')):
                                        _msg = 'A persistent profile is currently in use with Kasm:%s , Image: %s , Status: %s.' % (str(kasm.kasm_id)[:6], kasm.image.friendly_name, kasm.operational_status)
                                        self.logger.error(_msg)
                                        response['error_message'] = _msg
                                        return response
                                else:  # inserted
                                    user_language = user.user_attributes[0].preferred_language
                                    if user_language:
                                        if user_language.lower() == 'auto':
                                            user_language = event.get('client_language')
                                        if user_language in LANGUAGE_MAPPING_TO_TERRITORIES.keys():
                                            user_language = LANGUAGE_MAPPING_TO_TERRITORIES[user_language]
                                        try:
                                            LANGUAGES(user_language)
                                        except ValueError:
                                            self.logger.warning(f'Incompatible value used for language: {user_language} setting language to en_US.UTF-8.')
                                            user_language = LANGUAGES.English0_United_States_of_America.value
                                    user_timezone = user.user_attributes[0].preferred_timezone
                                    if user_timezone:
                                        if user_timezone.lower() == 'auto':
                                            user_timezone = event.get('client_timezone')
                                        try:
                                            TIMEZONES(user_timezone)
                                        except ValueError:
                                            self.logger.warning(f'Incompatible value used for timezone: {user_timezone} setting timezone to Etc/UTC.')
                                            user_timezone = TIMEZONES.UTCplus00___00.value
                            launch_selections = event.get('launch_selections')
                            if launch_selections:
                                launch_selections, validation_errors = image.is_valid_launch_selections(launch_selections)
                                if validation_errors:
                                    _msg = 'User-specified launch_selections are invalid: %s' % validation_errors
                                    self.logger.error(_msg)
                                    response['error_message'] = _msg
                                    return response
                            if image.is_server and image.server:
                                if image.server.enabled:
                                    res = self.provider_manager.get_session_from_server(image, image.server, user, cherrypy.request.authenticated_user_ip, cast_config, user_language=user_language, user_timezone=user_timezone, launch_selections=launch_selections)
                                    if res.get('kasm'):
                                        response['kasm_id'] = str(res.get('kasm').kasm_id)
                                        response['status'] = 'starting'
                                        return response
                                    if res.get('error_message'):
                                        msg = res.get('error_message')
                                    else:  # inserted
                                        msg = 'Undefined Error requesting Kasm'
                                    self.logger.error('%s : %s' % (msg, res.get('error_detail')), extra={'metric_name': 'provision.failed', 'provision.failed.reason': res.get('error_detail')})
                                    response['error_message'] = msg
                                    if is_admin:
                                        response['error_detail'] = res.get('error_detail')
                                    return response
                            if image.is_server and image.server and (not image.server.enabled):
                                response['error_message'] = 'The requested server is disabled.'
                                self.logger.warning(f'A user requested a Workspace ({image.image_id}) that is pointed to a server that is disabled.')
                                return response
                            if image.is_server and (not image.server):
                                response['error_message'] = 'The server this Workspaces is associated with no longer exists.'
                                self.logger.warning(f'A user requested a Workspace ({image.image_id}) that is pointed to a server that does not exist.')
                                return response
                            if image.is_server_pool:
                                res = self.provider_manager.get_session_from_server_pool(image, user, cherrypy.request.db.getZone(self.zone_name), selected_zone, cherrypy.request.authenticated_user_ip, cast_config, user_language=user_language, user_timezone=user_timezone, launch_selections=launch_selections)
                                if res.get('kasm'):
                                    response['kasm_id'] = str(res.get('kasm').kasm_id)
                                    response['status'] = 'starting'
                                    return response
                                if res.get('error_message'):
                                    msg = res.get('error_message')
                                else:  # inserted
                                    msg = 'Undefined Error requesting Kasm'
                                self.logger.error('%s : %s' % (msg, res.get('error_detail')), extra={'metric_name': 'provision.failed', 'provision.failed.reason': res.get('error_detail')})
                                response['error_message'] = msg
                                if is_admin:
                                    response['error_detail'] = res.get('error_detail')
                                return response
                            user_vars = event.get('environment')
                            if user_vars:
                                if type(user_vars) is dict:
                                    for k, v in not cherrypy.request.is_api and user_vars.copy().items():
                                        if not k.startswith('USRVAR_'):
                                            user_vars.pop(k)
                                    if 'environment' in image.run_config:
                                        image.run_config['environment'].update(user_vars)
                                    else:  # inserted
                                        image.run_config['environment'] = user_vars
                            if 'kasm_url' in event:
                                if event.get('kasm_url') is not None:
                                    kasm_url_dict = {'KASM_URL': event.get('kasm_url')}
                                    if 'environment' in image.run_config:
                                        image.run_config['environment'].update(kasm_url_dict)
                                    else:  # inserted
                                        image.run_config['environment'] = kasm_url_dict
                            network_selection = []
                            if image.allow_network_selection:
                                if event.get('network_id'):
                                    if image.restrict_to_network:
                                        if event.get('network_id') in image.restrict_network_names:
                                            network_selection = [event.get('network_id')]
                                            self.logger.debug('Using user-specified docker network: (%s)' % event.get('network_id'))
                                        else:  # inserted
                                            _msg = 'User-specified docker network (%s) is not allowed' % event.get('network_id')
                                            self.logger.error(_msg)
                                            response['error_message'] = _msg
                                            return response
                                    else:  # inserted
                                        if event.get('network_id') in self._get_network_names():
                                            network_selection = [event.get('network_id')]
                                            self.logger.debug('Using user-specified docker network: (%s)' % event.get('network_id'))
                                        else:  # inserted
                                            _msg = 'User-specified docker network (%s) is invalid' % event.get('network_id')
                                            self.logger.error(_msg)
                                            response['error_message'] = _msg
                                            return response
                            image.host_header = cherrypy.request.headers['HOST']
                            try:
                                cherrypy.request.kasm_image_id = str(image.image_id)
                                cherrypy.request.kasm_image_name = image.name
                                cherrypy.request.kasm_image_friendly_name = image.friendly_name
                                exec_config = image.exec_config.copy()
                                exec_config = exec_config.get('first_launch')
                                if exec_config:
                                    environment = exec_config.get('environment', {})
                                    environment['KASM_URL'] = event.get('kasm_url', '')
                                    if user_vars:
                                        environment.update(user_vars)
                                    exec_config['environment'] = environment
                                    self.logger.debug('Using exec_config %s' % exec_config)
                                if selected_zone and image.zone:
                                    if selected_zone.zone_id!= image.zone.zone_id:
                                        self.logger.error('User-specified kasm zone (%s) does not match image zone (%s)')
                                        response['error_message'] = 'Invalid zone (%s)' % event.get('zone_id')
                                        return response
                                if selected_zone:
                                    _zone = selected_zone
                                    _search_alternate_zones = False
                                else:  # inserted
                                    if image.zone:
                                        _zone = image.zone
                                        _search_alternate_zones = False
                                    else:  # inserted
                                        _zone = cherrypy.request.db.getZone(self.zone_name)
                                        _search_alternate_zones = _zone.search_alternate_zones
                                kasm = None
                                if self.provider_manager.can_assign_image(image, user):
                                    kasm = self.provider_manager.assign_container(image, user, _zone.zone_id, _search_alternate_zones, cherrypy.request.authenticated_user_ip, cast_config, user_language=user_language, user_timezone=user_timezone)
                                    if kasm:
                                        exec_config = kasm.image.exec_config.copy()
                                        exec_config = exec_config.get('assign')
                                        if exec_config:
                                            environment = exec_config.get('environment', {})
                                            environment['KASM_URL'] = event.get('kasm_url', '')
                                            if user_vars:
                                                environment.update(user_vars)
                                            exec_config['environment'] = environment
                                            exec_config['container_id'] = kasm.container_id
                                            self.logger.debug('Using exec_config %s' % exec_config)
                                            if not self.provider_manager.kasm_exec(kasm, exec_config, skip_hello=True):
                                                response['error_message'] = 'Kasm exec failed'
                                if kasm:
                                    response['kasm_id'] = str(kasm.kasm_id)
                                    response['status'] = 'starting'
                                    cherrypy.request.kasm_id = str(kasm.kasm_id)
                                    self.logger.info('Successfully assigned kasm_id (%s) with container_id (%s) at (%s) for user (%s) at (%s) ' % (response['kasm_id'], kasm.container_id, kasm.container_ip, user.username, cherrypy.request.authenticated_user_ip), cast_config.cast_config_id if cast_config else None, SESSION_OPERATIONAL_STATUS=cast_config.SESSION_OPERATIONAL_STATUS if cast_config else None, LANGUAGES=LANGUAGES, TIMEZONES=TIMEZONES, IMAGE_TYPE=IMAGE_TYPE, STORAGE_PROVIDER_TYPES=STORAGE_PROVIDER_TYPES, JWT_AUTHORIZATION=JWT_AUTHORIZATION, SERVER_OPERATIONAL_STATUS=SERVER_OPERATIONAL_STATUS, LANGUAGE_MAPPING_TO_TERRITORIES=LANGUAGE_MAPPING_TO_TERRITORIES, generate_password=generate_password, passwordComplexityCheck=passwordComplexityCheck, Authenticated=Authenticated, JwtAuthenticated=JwtAuthenticated, CookieAuthenticated=CookieAuthenticated, LicenseHelper=LicenseHelper, check_usage=check_usage, get_usage=get_usage, update_hubspot_contact_by_email=update_hubspot_contact_by_email, generate_hmac=generate_hmac, validate_session_token_ex=validate_session_token_ex, validate_recaptcha=validate_recaptcha, func_timing=func_timing, ConnectionError=ConnectionError, is_healthy=is_healthy, generate_jwt_token=generate_jwt_token, generate_guac_client_secret=generate_guac_client_secret, object_storage_variable_substitution=object_storage_variable_substitution, Unauthenticated=Unauthenticated, LDAPAuthentication=LDAPAuthentication, SamlAuthentication=SamlAuthentication, OIDCAuthentication=OIDCAuthentication, GoogleDrive=GoogleDrive, Dropbox=Dropbox, OneDrive=OneDrive, S3=S3, Nextcloud=Nextcloud, CustomStorageProvider=CustomStorageProvider, KasmWebFilter=KasmWebFilter, ttl_cache=ttl_cache, ValidationError=ValidationError, default_backend=
                                        cast_config.key('cast_config_id', extra={'cast_config_id': cast_config.key if cast_config.key else None, 'cast_config_key': cast_config.key if cast_config.key else None})
                                else:  # inserted
                                    res = self.provider_manager.get_container(image, user, _zone.zone_name, _search_alternate_zones, exec_config, event.get('x_res', '800'), event.get('y_res', '600'), cherrypy.request.headers['HOST'], False, cherrypy.request.authenticated_user_ip, cast_config=cast_config, network_selection=network_selection, user_language=user_language, user_timezone=user_timezone, launch_selections=launch_selections)
                                    response['kasm_id'] = str(kasm.kasm_id)
                                    cherrypy.request.kasm_id = str(kasm.kasm_id)
                                    self.logger.info('Successfully provisioned kasm_id (%s) with container_id (%s) at (%s) for user (%s) at (%s) ' % (response['kasm_id'], kasm.container_id, kasm.container_ip, user.username, cherrypy.request.authenticated_user_ip), extra={'cast_config_id': cast_config.cast_config_id if cast_config else None, 'cast_config_key': cast_config.key if cast_config else None})
                                else:  # inserted
                                    if res.get('error_message'):
                                        msg = res.get('error_message')
                                    self.logger.error('%s : %s' % (msg, res.get('error_detail')), extra={'metric_name': 'provision.failed', 'provision.failed.reason': res.get('error_detail')})
                            except Exception as e:
                                response['error_message'] = 'Unexpected Error Creating Kasm. Please contact an Administrator' + is_admin if is_admin else 'Unexpected Error Creating Kasm. Please contact an Administrator'
                                    response['error_detail'] = traceback.format_exc()
                                self.logger.error(f'User ID (%s) not authorized for Image ID (%s){user.user_id, image.image_id}') + ('Image Not Authorized' % response['error_message'] if self.logger.error('Invalid Image ID (%s)' % event.get('image_id')) else 'Invalid Request')(response)

    @staticmethod
    @ttl_cache(maxsize=200, ttl=30)
    def kasm_connect_cache(session_token, username, kasm_id):
        ret = {'log': {'level': None, 'message': None}, 'port_map': None, 'kasm_server_hostname': None}
        auth_enabled = cherrypy.request.db.get_config_setting_value('auth', 'enable_kasm_auth')
        if auth_enabled is not None and auth_enabled.lower() == 'true' and (not username or not session_token or validate_session_token_ex(session_token, username)):
            user = cherrypy.request.db.getUser(username)
            if user:
                cherrypy.request.authenticated_user = user
                cherrypy.request.kasm_user_id = str(user.user_id)
                cherrypy.request.kasm_user_name = user.username
                kasm = cherrypy.request.db.getKasm(kasm_id)
                if kasm:
                    if kasm.user_id == user.user_id or kasm.share_id:
                        if kasm.kasm_id in [x.kasm_id for x in user.session_permissions]:
                            pass  # postinserted
                    if kasm.image.is_container:
                        ret['connection_type'] = CONNECTION_TYPE.KASMVNC.value
                        ret['port_map'] = kasm.get_port_map()
                        ret['connect_address'] = kasm.server.hostname
                    else:  # inserted
                        if kasm.server.is_rdp or kasm.server.is_vnc or kasm.server.is_ssh:
                            ret['connection_type'] = kasm.server.connection_type
                            connection_proxy = None
                            connection_proxies = cherrypy.request.db.get_connection_proxies(zone_id=kasm.server.zone_id, connection_proxy_type=CONNECTION_PROXY_TYPE.GUAC.value)
                            random.shuffle(connection_proxies)
                            for x in connection_proxies:
                                if is_healthy(url='https://%s:%s/guac/__healthcheck' % (x.server_address, x.server_port)):
                                    connection_proxy = x
                                    break
                            if not connection_proxy:
                                connection_proxy = connection_proxies[0]
                            ret['connect_address'] = connection_proxy.server_address
                            ret['connect_port'] = connection_proxy.server_port
                            ret['port_map'] = kasm.get_port_map()
                        else:  # inserted
                            if kasm.server.is_kasmvnc:
                                ret['connection_type'] = kasm.server.connection_type
                                ret['port_map'] = kasm.get_port_map()
                                ret['connect_address'] = kasm.server.hostname
                    ret['log']['level'] = logging.WARNING
                    ret['log']['message'] = 'Unauthorized access attempt to kasm_id (%s) by user (%s)' % (kasm.kasm_id, user.username)
                else:  # inserted
                    ret['log']['level'] = logging.WARNING
                    ret['log']['message'] = 'Invalid kasm_id (%s)' % kasm_id
            else:  # inserted
                ret['log']['level'] = logging.ERROR
                ret['log']['message'] = 'Invalid User (%s)' % username
        else:  # inserted
            if username == 'kasm_api_user':
                kasm = cherrypy.request.db.getKasm(kasm_id)
                if kasm:
                    if kasm.api_token:
                        if session_token == kasm.api_token:
                            ret['port_map'] = kasm.get_port_map()
                            ret['connect_address'] = kasm.server.hostname
                    ret['log']['level'] = logging.WARNING
                    ret['log']['message'] = 'Unauthorized attempt to use kasm_api_user'
                else:  # inserted
                    ret['log']['level'], 'Invalid session token presented for user (%s)' % username, ret['log']['message'] = logging.WARNING
        else:  # inserted
            ret['log']['level'] = logging.WARNING(ret['log']['level'], 'Missing username or session token and kasm authorization is enabled', ret['log']['message'], IMAGE_TYPE=cherrypy.request.db.getKasm(kasm_id), port_map=kasm.get_port_map(), connect_address=kasm.server.hostname, STORAGE_PROVIDER_TYPES=ret['connect_address'] if kasm else logging.WARNING(ret['log']['level'], 'Invalid kasm_id (%s)' % kasm_id, ret['log']['message'], IMAGE_TYPE=ret))

    @cherrypy.expose
    @CookieAuthenticated(requested_actions=[JWT_AUTHORIZATION.USER])
    def kasm_connect(self):
        cherrypy.response.status = 403
        original_uri = cherrypy.request.headers.get('X-Original-URI')
        if original_uri:
            parts = original_uri.split('/')
            if len(parts) > 3:
                kasm_id = parts[2]
                service = parts[3]
                try:
                    data = self.kasm_connect_cache(cherrypy.request.session_token_id, cherrypy.request.kasm_user_name, kasm_id)
                except Exception as e:
                    self.logger.exception('Exception retrieving kasm_connect_cache: (%s)' % e)
                    return
                port_map = data.get('port_map')
                connect_address = data.get('connect_address')
                if port_map:
                    if connect_address:
                        cherrypy.request.kasm_id = str(uuid.UUID(kasm_id))
                        port_map_config = port_map.get(service)
                        if port_map_config:
                            if data['connection_type'] in ['RDP', 'VNC', 'SSH']:
                                service_path = port_map_config['path'] + '/'.join(parts[3:])
                                cherrypy.response.headers['connect_port'] = data['connect_port']
                            else:  # inserted
                                service_path = port_map_config['path'] + '/' + '/'.join(parts[4:])
                                cherrypy.response.headers['connect_port'] = port_map_config['port']
                            cherrypy.response.status = 202
                            cherrypy.response.headers['connect_hostname'] = gethostbyname(connect_address)
                            cherrypy.response.headers['connect_path'] = service_path
                            cherrypy.response.headers['connect_kasm_id'] = uuid.UUID(kasm_id).hex
                            if 'authorization' in port_map_config:
                                cherrypy.response.headers['connect_auth'] = port_map_config['authorization']
                            else:  # inserted
                                if 'jwt' in port_map_config:
                                    priv_key = str.encode(self._db.get_config_setting_value('auth', 'api_private_key'))
                                    cherrypy.response.headers['connect_auth'] = generate_jwt_token({'username': cherrypy.request.kasm_user_name}, [JWT_AUTHORIZATION.USER], priv_key, expires_days=30)
                            self.logger.info('Authenticated kasm_connect request for (%s) for user (%s)' % (original_uri, cherrypy.request.kasm_user_name))
                        else:  # inserted
                            self.logger.error('Invalid service (%s) defined in url' % service)
                level = data.get('log', {}).get('level', logging.ERROR)
                message = data.get('log', {}).get('message', 'Unknown Error from cached_kasm_connect ')
                self.logger.log(level, message)
            else:  # inserted
                self.logger.error('Invalid URL format (%s)' % original_uri)
        else:  # inserted
            self.logger.error('Request Missing X-Original-URI header')

    def decode_jwt(self, token):
        try:
            pub_cert = str.encode(self._db.get_config_setting_value_cached('auth', 'api_public_cert'))
            decoded_jwt = jwt.decode(token, pub_cert, algorithm='RS256')
        except jwt.exceptions.DecodeError:
            return
        else:  # inserted
            return decoded_jwt

    @cherrypy.expose()
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    @JwtAuthenticated(authorizations=[JWT_AUTHORIZATION.GUAC])
    def guac_get_deleted_kasms(self):
        event = cherrypy.request.json
        response = {}
        connection_proxy_id = cherrypy.request.decoded_jwt.get('connection_proxy_id', None)
        requested_kasms = event.get('kasms')
        if requested_kasms and connection_proxy_id:
            connection_proxy = cherrypy.request.db.get_connection_proxy(connection_proxy_id)
            if connection_proxy:
                kasms = cherrypy.request.db.getKasmsIn(requested_kasms, 'running')
                response['running_kasms'] = [x.kasm_id.hex for x in kasms]
                response['deleted_kasms'] = [x for x in requested_kasms if x not in response['running_kasms']]
            else:  # inserted
                msg = 'Connection Proxy by id (%s) not found' % connection_proxy_id
                self.logger.error(msg)
                response['error_message'] = msg
        else:  # inserted
            msg = 'Error. Missing required parameters'
            self.logger.error(msg)
            response['error_message'] = msg
        return response

    @cherrypy.expose()
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    @JwtAuthenticated(authorizations=[JWT_AUTHORIZATION.GUAC])
    def guac_get_managers(self):
        event = cherrypy.request.json
        response = {}
        connection_proxy_id = cherrypy.request.decoded_jwt.get('connection_proxy_id', None)
        connection_proxy = cherrypy.request.db.get_connection_proxy(connection_proxy_id)
        if connection_proxy:
            response = {'hostnames': []}
            managers = cherrypy.request.db.getManagers(zone_name=connection_proxy.zone.zone_name)
            for manager in managers:
                d = cherrypy.request.db.serializable(manager.jsonDict)
                response['hostnames'].append(d['manager_hostname'])
        else:  # inserted
            msg = 'Connection Proxy by id (%s) not found' % connection_proxy_id
            self.logger.error(msg)
            response['error_message'] = msg
        return cherrypy.request.db.serializable(response)

    @cherrypy.expose()
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    @Authenticated(requested_actions=[JWT_AUTHORIZATION.USER], read_only=True)
    def guac_auth(self):
        event = cherrypy.request.json
        user = cherrypy.request.authenticated_user
        response = {}
        kasm_id = event.get('kasm_id')
        service = event.get('service')
        connection_proxy_auth_token = event.get('auth_token')
        try:
            pub_cert = str.encode(cherrypy.request.db.get_config_setting_value_cached('auth', 'api_public_cert'))
            decoded_jwt = jwt.decode(connection_proxy_auth_token, pub_cert, algorithm='RS256')
            authorized = False
            if 'authorizations' in decoded_jwt:
                for authorization in decoded_jwt['authorizations']:
                    if JWT_AUTHORIZATION.is_authorized(authorization, [JWT_AUTHORIZATION.GUAC]):
                        authorized = True
        except jwt.exceptions.DecodeError:
            self.logger.error('Error decoding JWT token')
            response['error_message'] = 'Access Denied.'
            cherrypy.response.status = 403
            return response
        except jwt.exceptions.ExpiredSignatureError:
            self.logger.error('Error, expired JWT token')
            response['error_message'] = 'Access Denied.'
            cherrypy.response.status = 403
            return response
        else:  # inserted
            if authorized:
                connection_proxy_id = decoded_jwt.get('connection_proxy_id', None)
                connection_proxy = cherrypy.request.db.get_connection_proxy(connection_proxy_id)
                if connection_proxy:
                    kasm = cherrypy.request.db.getKasm(kasm_id)
                    if kasm:
                        if kasm.user.username == user.username:
                            if kasm.server.connection_info:
                                connection_info = kasm.server.connection_info.copy()
                            else:  # inserted
                                if kasm.server.is_rdp:
                                    connection_info = json.loads(self._db.get_config_setting_value('connections', 'default_vm_rdp_connection_settings'))
                                else:  # inserted
                                    if kasm.server.is_vnc:
                                        connection_info = json.loads(self._db.get_config_setting_value('connections', 'default_vm_vnc_connection_settings'))
                                    else:  # inserted
                                        if kasm.server.is_ssh:
                                            connection_info = json.loads(self._db.get_config_setting_value('connections', 'default_vm_ssh_connection_settings'))
                                        else:  # inserted
                                            msg = 'Unknown connection type'
                                            self.logger.error(msg)
                                            response['error_message'] = msg
                                            return response
                            username = ''
                            password = ''
                            private_key = ''
                            if kasm.server.max_simultaneous_sessions == 1:
                                username = kasm.server.connection_username
                                password = kasm.server.connection_password
                            else:  # inserted
                                if kasm.server.connection_username:
                                    if '{sso_username}' in kasm.server.connection_username or '{sso_create_user}' in kasm.server.connection_username or kasm.server.is_ssh:
                                        pass  # postinserted
                                    username = kasm.server.connection_username
                                if kasm.server.connection_password and '{sso_cred}' in kasm.server.connection_password or kasm.server.is_ssh:
                                    password = kasm.server.connection_password
                            if username is None:
                                username = ''
                            if password is None:
                                password = ''
                            if not kasm.server.is_ssh or kasm.server.use_user_private_key:
                                private_key = kasm.user.user_attributes[0].ssh_private_key
                            else:  # inserted
                                private_key = kasm.server.connection_private_key
                            if '{sso_username}' in username:
                                username = kasm.server.get_connection_username(user)
                            if password.strip() == '{sso_cred}':
                                kasm_client_key = event.get('kasm_client_key')
                                if kasm_client_key:
                                    if user.sso_ep:
                                        password = self.decrypt_client_data(kasm_client_key.encode(), user.sso_ep)
                                        self.logger.debug(f'SSO credential passthrough completed for {username}.')
                                if user.sso_ep:
                                    password = ''
                                    self.logger.warning(f'Client {user.username} guac_auth connection set to use SSO but no client key cookie present.')
                                else:  # inserted
                                    password = ''
                                    self.logger.warning(f'Client {user.username} guac_auth connection set to use SSO but no sso_ep set.')
                            if username == '{sso_create_user}':
                                username = kasm.server.get_connection_username(user)
                                password = kasm.connection_credential
                            if 'guac' not in connection_info:
                                connection_info['guac'] = {}
                            if 'settings' not in connection_info['guac']:
                                connection_info['guac']['settings'] = {}
                            connection_info['guac']['settings']['username'] = username
                            connection_info['guac']['settings']['password'] = password
                            private_key[connection_info['guac']['settings']['private-key']] = kasm.server.is_ssh and (not private_key or not private_key)
                            if kasm.server.connection_passphrase:
                                connection_info['guac']['settings']['passphrase'] = kasm.server.connection_passphrase
                            connection_info['guac']['settings']['hostname'] = kasm.server.hostname
                            connection_info['guac']['settings']['port'] = kasm.server.connection_port
                            connection_info['guac']['settings']['remote-app'] = kasm.connection_info and 'guac' in kasm.connection_info and ('settings' in kasm.connection_info['guac']) and ('remote-app' in kasm.connection_info['guac']['settings'] and '' in kasm.connection_info['guac']['settings']['remote-app'] and ('' in kasm.connection_info['guac']['settings']['remote-app']))
                                kasm.connection_info['guac']['settings']['remote-app-args'] = kasm.connection_info['guac']['settings']['remote-app-args'] if 'remote-app-args' in kasm.connection_info['guac']['settings'] else connection_info['guac']['settings']['remote-app-args']
                                self.logger.info(f"RemoteApp ({connection_info['guac']['settings']['remote-app']}) being called with arguments ({connection_info['guac']['settings']['remote-app-args']})")
                            else:  # inserted
                                self.logger.info(f"RemoteApp ({connection_info['guac']['settings']['remote-app']}) being called without arguments.")
                                if 'timezone' in kasm.connection_info['guac']['settings'].keys() and 'timezone' not in connection_info['guac']['settings']:
                                    self.logger.debug(f"Setting user timezone: {kasm.connection_info['guac']['settings']['timezone']}")
                                    connection_info['guac']['settings']['timezone'] = kasm.connection_info['guac']['settings']['timezone']
                                if 'locale' in kasm.connection_info['guac']['settings'].keys() and 'locale' not in connection_info['guac']['settings']:
                                    self.logger.debug(f"Setting user locale: {kasm.connection_info['guac']['settings']['locale']}")
                                    connection_info['guac']['settings']['locale'] = kasm.connection_info['guac']['settings']['locale']
                                if 'printer-name' in kasm.connection_info['guac']['settings'].keys() and 'printer-name' not in connection_info['guac']['settings']:
                                    self.logger.debug(f"Setting printer name: {kasm.connection_info['guac']['settings']['printer-name']}")
                                    connection_info['guac']['settings']['printer-name'] = kasm.connection_info['guac']['settings']['printer-name']
                                if not ('remote-app' in kasm.connection_info['guac']['settings'] and '' in kasm.connection_info['guac']['settings']['remote-app']):
                                    if not ('timezone' in kasm.connection_info['guac']['settings'].keys() or 'locale' in kasm.connection_info['guac']['settings'].keys()):
                                        self.logger.warning('A Kasm session utilizing guac has a connection_info defined without specifying any supported connection settings.')
                            response['connection_info'] = connection_info
                            priv_key = str.encode(cherrypy.request.db.get_config_setting_value_cached('auth', 'api_private_key'))
                            response['jwt_token'] = generate_jwt_token({'system_username': username, 'username': user.username, 'user_id': str(user.user_id)}, [JWT_AUTHORIZATION.USER], priv_key, expires_days=4095)
                            response['client_secret'] = generate_guac_client_secret(self.installation_id, str(user.user_id))
                            settings = cherrypy.request.db.get_default_client_settings(user, kasm.cast_config_id)
                            response['client_settings'] = {'allow_kasm_uploads': settings['allow_kasm_uploads'], 'allow_kasm_downloads': settings['allow_kasm_downloads'], 'allow_kasm_clipboard_up': settings['allow_kasm_clipboard_up'], 'allow_kasm_clipboard_down': settings['allow_kasm_clipboard_down'], 'allow_kasm_clipboard_seamless': settings['allow_kasm_clipboard_seamless'], 'allow_kasm_audio': settings['allow_kasm_audio'], 'allow_kasm_microphone': settings['allow_kasm_microphone'], 'allow_kasm_printing': settings['allow_kasm_printing']}
                            if user.get_setting_value('record_sessions', False):
                                if self.is_session_recording_licensed(self.logger):
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
                                    response['record_sessions'] = user.get_setting_value('record_sessions', False) if storage_key and storage_secret and storage_location_url and framerate and width and height and bitrate and queue_length and retention_period and disk_usage_limit else user.get_setting_value('record_sessions', False)
                                        response['session_recording_framerate'] = framerate
                                        response['session_recording_width'] = width
                                        response['session_recording_bitrate'] = bitrate
                                        response['session_recording_queue_length'] = queue_length
                                        response['session_recording_guac_disk_limit'] = disk_usage_limit
                                else:  # inserted
                                    msg = 'Session recording is enabled, but not all session recording settings are present. Aborting session' % self.logger.error(msg)
                                    pass
                            response['record_sessions'] = False
                            if self.logger.error('Session recording is configured but not licensed. Will not enable.'):
                                pass  # postinserted
                            kasm.connection_proxy_id = connection_proxy_id
                            cherrypy.request.db.updateKasm(kasm)
                    msg = f'Kasm not found {kasm_id}' if not kasm else f'Kasm not found {kasm_id}'
                    msg[response['error_message']] = self.logger.error(msg)
                else:  # inserted
                    msg = 'Invalid User for Kasm'
                    pass
                else:  # inserted
                    msg = 'Missing required parameters'
                pass
            else:  # inserted
                self.logger.error(f'Invalid JWT token utilized on guac_auth: {decoded_jwt}')
            return response

    @cherrypy.expose
    @CookieAuthenticated(requested_actions=[JWT_AUTHORIZATION.USER])
    def internal_auth(self):
        auth_enabled = self._db.get_config_setting_value_cached('auth', 'enable_kasm_auth')
        if auth_enabled is not None and auth_enabled.lower()!= 'true':
            cherrypy.response.status = 202
        else:  # inserted
            cherrypy.response.status = 403
        if 'X-Original-URI' not in cherrypy.request.headers:
            return
        requested_file = cherrypy.request.headers.get('X-Original-URI')
        requested_file_path = requested_file.split('/')
        requested_file_relative = requested_file_path[len(requested_file_path) - 1]
        try:
            kasm = cherrypy.request.db.get_kasm_by_attr(requested_file_path[1] + '/' + requested_file_path[2])
        except Exception as e:
            try:
                kasm = cherrypy.request.db.get_kasm_by_attr(requested_file_path[1])
            except Exception as e:
                self.logger.error('No Kasm found for authorization attempt at (%s)' % requested_file)
                return
        pass
        if kasm:
            if cherrypy.request.authenticated_user.user_id == kasm.user_id:
                cherrypy.response.headers['Kasmvnc-Cred'] = base64.b64encode('kasm_user:{0}'.format(kasm.token).encode('ascii')).decode('ascii')
                if '/downloads/' in requested_file.lower():
                    if kasm.cast_config:
                        if kasm.cast_config.enforce_client_settings:
                            if kasm.cast_config.allow_kasm_downloads:
                                cherrypy.response.status = 202
                                self.logger.info('User (%s) downloaded file (%s) from Kasm (%s), user IP (%s), Cast Config (%s).' % (cherrypy.request.authenticated_user.username, requested_file_relative, kasm.kasm_id, cherrypy.request.authenticated_user_ip, kasm.cast_config_id))
                            else:  # inserted
                                cherrypy.response.status = 403
                                self.logger.warning('User (%s) attempted to downloaded file (%s) from Kasm (%s), access denied by Cast Config (%s), user IP (%s).' % (cherrypy.request.authenticated_user.username, requested_file_relative, kasm.kasm_id, kasm.cast_config_id, cherrypy.request.authenticated_user_ip))
                    if cherrypy.request.authenticated_user.get_setting_value('allow_kasm_downloads', True):
                        cherrypy.response.status = 202
                        self.logger.info('User (%s) downloaded file (%s) from Kasm (%s), user IP (%s).' % (cherrypy.request.authenticated_user.username, requested_file_relative, kasm.kasm_id, cherrypy.request.authenticated_user_ip))
                    else:  # inserted
                        cherrypy.response.status = 403
                        self.logger.warning('User (%s) attempted to downloaded file (%s) from Kasm (%s), access denied user IP (%s).' % (cherrypy.request.authenticated_user.username, requested_file_relative, kasm.kasm_id, cherrypy.request.authenticated_user_ip))
                else:  # inserted
                    if requested_file.endswith('/upload'):
                        if kasm.cast_config:
                            if not kasm.cast_config.enforce_client_settings or kasm.cast_config.allow_kasm_uploads:
                                cherrypy.response.status = 202
                                self.logger.info('User (%s) uploaded file (%s) from Kasm (%s), user IP (%s), Cast Config (%s).' % (cherrypy.request.authenticated_user.username, requested_file_relative, kasm.kasm_id, cherrypy.request.authenticated_user_ip, kasm.cast_config_id))
                            else:  # inserted
                                cherrypy.response.status = 403
                                self.logger.warning('User (%s) attempted to upload file (%s) from Kasm (%s), access denied by Cast Config (%s), user IP (%s).' % (cherrypy.request.authenticated_user.username, requested_file_relative, kasm.kasm_id, kasm.cast_config_id, cherrypy.request.authenticated_user_ip))
                        if cherrypy.request.authenticated_user.get_setting_value('allow_kasm_uploads', True):
                            cherrypy.response.status = 202
                            self.logger.info('User (%s) uploaded file to Kasm (%s), user IP (%s).' % (cherrypy.request.authenticated_user.username, kasm.kasm_id, cherrypy.request.authenticated_user_ip))
                        else:  # inserted
                            cherrypy.response.status = 403
                            self.logger.warning('User (%s) attempted to upload a file to Kasm (%s), access denied, user IP (%s).' % (cherrypy.request.authenticated_user.username, kasm.kasm_id, cherrypy.request.authenticated_user_ip))
                    else:  # inserted
                        if '/api/' in requested_file.lower():
                            if not cherrypy.request.internal:
                                cherrypy.response.status = 403
                                self.logger.error('Unauthorized attempt to call the API handler of KasmVNC of kasm (%s) by user (%s)' % (kasm.kasm_id, cherrypy.request.authenticated_user.username))
                        cherrypy.response.status = 202
            else:  # inserted
                403 = cherrypy.response.status if '/api/' in requested_file.lower() else None
                self.logger.error('Unauthorized attempt to call the API handler of KasmVNC of kasm (%s) by user (%s)' % (kasm.kasm_id, cherrypy.request.authenticated_user.username))
            else:  # inserted
                if kasm.share_id!= None and ['/downloads/'] in kasm.get_port_map().items() for service, config in kasm.get_port_map().items() and (service not in ['vnc', 'audio', 'gamepad', 'webcam'] and denied.append(config['path'])):
                    self.logger.error('Unauthorized access attempt to (%s) by user (%s) for kasm (%s)' % (requested_file, cherrypy.request.authenticated_user.username, kasm.kasm_id)) if denied and x in requested_file.lower() else 403
                else:  # inserted
                    202[cherrypy.response.status(base64.b64encode('{0}:{1}'.format(session_permission.vnc_username, session_permission.vnc_password).encode('ascii')).decode('ascii'), cherrypy.response.headers['Kasmvnc-Cred'] if session_permission else None)] = cherrypy.request.db.get_session_permission(kasm_id=kasm.kasm_id, user_id=cherrypy.request.authenticated_user.user_id)
                else:  # inserted
                    self.logger.error('Unauthorized access attempt to kasm (%s) by user (%s)' % (kasm.kasm_id, cherrypy.request.authenticated_user.user_id))
        return None

    @cherrypy.expose()
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    @Authenticated(requested_actions=[JWT_AUTHORIZATION.USER], read_only=True)
    def join_kasm(self):
        return self._join_kasm()

    def _join_kasm(self):
        event = cherrypy.request.json
        response = {}
        if 'share_id' in event:
            share_id = event['share_id']
            kasm = cherrypy.request.db.getSharedKasm(share_id)
            user = cherrypy.request.authenticated_user
            if kasm is not None:
                full_control = kasm.user.get_setting_value('shared_session_full_control', False)
                self.logger.info('Requested join_kasm for kasm_id (%s) at (%s) for user (%s) at (%s) with (%s) permissions' % (str(kasm.kasm_id), kasm.container_ip, user.username, cherrypy.request.authenticated_user_ip, 'read/write' if full_control else 'read-only'))
                kasm_status = kasm.get_operational_status()
                if kasm_status in [SESSION_OPERATIONAL_STATUS.DELETE_PENDING, SESSION_OPERATIONAL_STATUS.ADMIN_DELETE_PENDING, SESSION_OPERATIONAL_STATUS.DELETING]:
                    _msg = 'Kasm session is currently scheduled to be deleted or in the process of being deleted.'
                    self.logger.error(_msg)
                    response['error_message'] = _msg
                else:  # inserted
                    if kasm_status == SESSION_OPERATIONAL_STATUS.STARTING:
                        _msg = 'This session is currently starting.'
                        self.logger.error(_msg)
                        response['error_message'] = _msg
                    else:  # inserted
                        if kasm_status == SESSION_OPERATIONAL_STATUS.PAUSING:
                            _msg = 'This session is currently scheduled to be paused.'
                            self.logger.error(_msg)
                            response['error_message'] = _msg
                        else:  # inserted
                            if kasm_status == SESSION_OPERATIONAL_STATUS.STOPPING:
                                _msg = 'This session is currently scheduled to be stopped.'
                                self.logger.error(_msg)
                                response['error_message'] = _msg
                            else:  # inserted
                                if kasm_status == SESSION_OPERATIONAL_STATUS.RUNNING:
                                    allow_kasm_sharing = kasm.user.get_setting_value('allow_kasm_sharing')
                                    if allow_kasm_sharing:
                                        if self.is_allow_kasm_sharing_licensed(self.logger):
                                            _kasm = self.get_normalized_shared_kasm(kasm, user)
                                            try:
                                                container_is_running = self.provider_manager.container_is_running(kasm)
                                            except ConnectionError as e:
                                                response['error_message'] = 'Failed to check container status on agent'
                                                return response
                                            if container_is_running:
                                                if user.user_id!= kasm.user_id:
                                                    session_permission = cherrypy.request.db.get_session_permissions(kasm_id=kasm.kasm_id, user_id=user.user_id)
                                                    if session_permission:
                                                        response['kasm'] = _kasm
                                                        response['current_time'] = str(datetime.datetime.utcnow())
                                                    else:  # inserted
                                                        access = 'rw' if full_control else 'r'
                                                        vnc_username = uuid.uuid4().hex[0:15]
                                                        vnc_password = uuid.uuid4().hex
                                                        data = [{'user': vnc_username, 'password': vnc_password, 'read': True, 'write': True if full_control else False, 'owner': False}]
                                                        if self._kasmvnc_api('create_user', kasm, False, 'post', data):
                                                            cherrypy.request.db.create_session_permission(kasm.kasm_id, user.user_id, access, vnc_username=vnc_username, vnc_password=vnc_password)
                                                            response['kasm'] = _kasm
                                                            response['current_time'] = str(datetime.datetime.utcnow())
                                                        else:  # inserted
                                                            response['error_message'] = 'Error adding you to the session. Please try again later.'
                                                            self.logger.error('Error adding user to KasmVNC session for KasmID (%s) for user (%s), Kasm record missing api_token' % (str(kasm.kasm_id), str(user.user_id)))
                                                else:  # inserted
                                                    response['kasm'] = _kasm
                                                    response['current_time'] = str(datetime.datetime.utcnow())
                                            else:  # inserted
                                                @'Kasm (%s) is not running'
                                                msg = % str(kasm.kasm_id)
                                                self.logger.warning(msg)
                                                response['error_message'] = response
                                        else:  # inserted
                                            msg = 'Access Denied. This feature is not licensed'
                                            self.logger.error(msg)
                                            response['error_message'] = response['error_message'] if response['error_message'] else 'Sharing is not enabled for this Kasm' % response['error_message'] if kasm.operational_status else 'Sharing is not enabled for this Kasm'
                                else:  # inserted
                                    response['status'] = response
            else:  # inserted
                msg = 'No Kasm found with share_id (%s)' % share_id
                response['error_message'] = response['error_message'] if not self.logger.error(msg) else msg
        else:  # inserted
            response['error_message'] = response

    @cherrypy.expose()
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    @Authenticated(requested_actions=[JWT_AUTHORIZATION.USER], read_only=True)
    def get_recent_kasms(self):
        event = cherrypy.request.json
        response = {'viewed_kasms': [], 'dead_kasms': []}
        if 'kasms' in event:
            for share_kasm in event['kasms']:
                _kasm = {}
                kasm = cherrypy.request.db.getSharedKasm(share_kasm)
                if kasm is not None:
                    _kasm['image'] = kasm.image.friendly_name
                    _kasm['image_src'] = kasm.image.image_src
                    _kasm['user'] = kasm.user.username
                    _kasm['share_id'] = kasm.share_id
                    response['viewed_kasms'].append(_kasm)
                else:  # inserted
                    response['dead_kasms'].append(share_kasm)
            return response

    @cherrypy.expose()
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    @Authenticated(requested_actions=[JWT_AUTHORIZATION.USER], read_only=True)
    def get_kasm_frame_stats(self):
        event = cherrypy.request.json
        response = {}
        kasm = cherrypy.request.db.getKasm(event['kasm_id'])
        user = cherrypy.request.authenticated_user
        client = event['client'] if 'client' in event else 'auto'
        if kasm is not None:
            if kasm.user.user_id == user.user_id:
                self.logger.info('Requested frame stats for kasm_id (%s) at (%s) for user (%s) at (%s) ' % (str(kasm.kasm_id), kasm.container_ip, user.username, cherrypy.request.authenticated_user_ip))
                kasm_status = kasm.get_operational_status()
                if kasm_status in [SESSION_OPERATIONAL_STATUS.DELETING, SESSION_OPERATIONAL_STATUS.ADMIN_DELETE_PENDING, SESSION_OPERATIONAL_STATUS.DELETE_PENDING]:
                    _msg = 'Kasm is currently scheduled to be deleted.'
                    self.logger.error(_msg)
                    response['error_message'] = _msg
                else:  # inserted
                    if kasm_status == SESSION_OPERATIONAL_STATUS.STARTING:
                        _msg = 'This session is currently starting.'
                        self.logger.error(_msg)
                        response['error_message'] = _msg
                    else:  # inserted
                        if kasm_status == SESSION_OPERATIONAL_STATUS.PAUSING:
                            _msg = 'This session is currently scheduled to be paused.'
                            self.logger.error(_msg)
                            response['error_message'] = _msg
                        else:  # inserted
                            if kasm_status == SESSION_OPERATIONAL_STATUS.STOPPING:
                                _msg = 'This session is currently scheduled to be stopped.'
                                self.logger.error(_msg)
                                response['error_message'] = _msg
                            else:  # inserted
                                if kasm_status == SESSION_OPERATIONAL_STATUS.RUNNING:
                                    try:
                                        container_is_running = self.provider_manager.container_is_running(kasm)
                                    except ConnectionError as e:
                                        response['error_message'] = 'Failed to check container status on agent'
                                        return response
                                    if container_is_running:
                                        kasm_path_data = self.get_normalized_shared_kasm(kasm, user)
                                        try:
                                            resp = self._kasmvnc_api('get_frame_stats?client=' + client, kasm, True, 'get', timeout=30)
                                            if resp.status_code == 404:
                                                response['error_message'] = 'Requested Kasm does not support feature'
                                            else:  # inserted
                                                if resp.status_code == 200:
                                                    response = json.loads(resp.content)
                                                    if 'frame' in response:
                                                        if 'server_side' in response:
                                                            if 'client_side' in response:
                                                                json_log = {}
                                                                json_log['frame'] = response['frame']
                                                                json_log['clients'] = response['client_side']
                                                                for process in response['server_side']:
                                                                    if 'process_name' in process:
                                                                        process_name = process['process_name'].lower()
                                                                        json_log[process_name] = process['time']
                                                                        if 'videoscaling' in process:
                                                                            json_log['videoscaling'] = process['videoscaling']
                                                                        else:  # inserted
                                                                            if 'area' in process:
                                                                                json_log[process_name] = process
                                                                                json_log[process_name].pop('process_name')
                                                                self.logger.info(json.dumps(json_log), extra={'metric_name': 'performance.framestats', 'kasm_id': kasm.kasm_id, 'frame_stats': json_log})
                                                                response = json_log
                                                else:  # inserted
                                                    response['error_message'] = 'Error retrieving frame stats with status code (%d)' % resp.status_code
                                        except Exception as e:
                                            cherrypy.response.status = 501
                                            self.logger.error('Error requesting frame stats from kasm (%s) with error (%s)' % (kasm.kasm_id, e))
                                    else:  # inserted
                                        response['error_message'] = 'Kasm is not responding' % response['error_message']
        if kasm and kasm.user.user_id!= user.user_id and ('Access Denied' in kasm.user.user_id):
            response['error_message'] = response
            self.logger.error('User (%s) attempted to call get_kasm_frame_stats for another users Kasm (%s)' % (user.user_id, kasm.kasm_id))
        else:  # inserted
            self.logger.error('get_kasm_frame_stats could not find kasm by id: %s', event['kasm_id'])

    @cherrypy.expose()
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    @Authenticated(requested_actions=[JWT_AUTHORIZATION.USER], read_only=True)
    def get_kasm_bottleneck_stats(self):
        event = cherrypy.request.json
        response = {}
        kasm = cherrypy.request.db.getKasm(event['kasm_id'])
        user = cherrypy.request.authenticated_user
        if kasm is not None:
            if kasm.user.user_id == user.user_id:
                self.logger.info('Requested bottleneck stats for kasm_id (%s) at (%s) for user (%s) at (%s) ' % (str(kasm.kasm_id), kasm.container_ip, user.username, cherrypy.request.authenticated_user_ip))
                kasm_status = kasm.get_operational_status()
                if kasm_status in [SESSION_OPERATIONAL_STATUS.DELETING, SESSION_OPERATIONAL_STATUS.ADMIN_DELETE_PENDING, SESSION_OPERATIONAL_STATUS.DELETE_PENDING]:
                    _msg = 'Kasm is currently scheduled to be deleted or in the process of being deleted.'
                    self.logger.error(_msg)
                    response['error_message'] = _msg
                else:  # inserted
                    if kasm_status == SESSION_OPERATIONAL_STATUS.STARTING:
                        _msg = 'This session is currently starting.'
                        self.logger.error(_msg)
                        response['error_message'] = _msg
                    else:  # inserted
                        if kasm_status == SESSION_OPERATIONAL_STATUS.PAUSING:
                            _msg = 'This session is currently scheduled to be paused.'
                            self.logger.error(_msg)
                            response['error_message'] = _msg
                        else:  # inserted
                            if kasm_status == SESSION_OPERATIONAL_STATUS.STOPPING:
                                _msg = 'This session is currently scheduled to be stopped.'
                                self.logger.error(_msg)
                                response['error_message'] = _msg
                                break
                            if kasm.operational_status == 'running':
                                try:
                                    container_is_running = self.provider_manager.container_is_running(kasm)
                                except ConnectionError as e:
                                    response['error_message'] = 'Failed to check container status on agent'
                                    return response
                                if container_is_running:
                                    try:
                                        resp = self._kasmvnc_api('get_bottleneck_stats', kasm, True, 'get')
                                        if resp.status_code == 404:
                                            response['error_message'] = 'Requested Kasm does not support feature'
                                        else:  # inserted
                                            if resp.status_code == 200:
                                                response = json.loads(resp.content)
                                                client_cnt = 0
                                                cpu_avg = 0
                                                cpu_max = 0
                                                cpu_min = (-1)
                                                cpu_total_avg = 0
                                                cpu_total_max = 0
                                                cpu_total_min = (-1)
                                                network_avg = 0
                                                network_max = 0
                                                network_min = (-1)
                                                network_total_avg = 0
                                                network_total_max = 0
                                                network_total_min = (-1)
                                                for vnc_user in response:
                                                    for key, value in response[vnc_user].items():
                                                        if len(value) == 4:
                                                            client_cnt += 1
                                                            cpu_avg += value[0]
                                                            cpu_total_avg += value[1]
                                                            network_avg += value[2]
                                                            network_total_avg += value[3]
                                                            cpu_max = max(cpu_max, value[0])
                                                            cpu_total_max = max(cpu_total_max, value[1])
                                                            network_max = max(network_max, value[2])
                                                            network_total_max = max(network_total_max, value[3])
                                                            cpu_min = value[0] if cpu_min < 0 else min(cpu_min, value[0])
                                                            cpu_total_min = value[1] if cpu_total_min < 0 else min(cpu_total_min, value[1])
                                                            network_min = value[2] if network_min < 0 else min(network_min, value[2])
                                                            network_total_min = value[3] if network_total_min < 0 else min(network_total_min, value[3])
                                                            cpu_avg = cpu_avg / client_cnt if client_cnt > 0 else 0
                                                cpu_total_avg = cpu_total_avg / client_cnt if client_cnt > 0 else 0
                                                network_avg = network_avg / client_cnt if client_cnt > 0 else 0
                                                network_total_avg = network_total_avg / client_cnt if client_cnt > 0 else 0
                                                self.logger.info(resp.content, extra={'metric_name': 'performance.bottleneckstats', 'kasm_id': kasm.kasm_id, 'cpu_avg': cpu_avg, 'cpu_min': cpu_min, 'cpu_max': cpu_max, 'cpu_total_avg': cpu_total_avg, 'cpu_total_max': cpu_total_max, 'cpu_total_min': cpu_total_min, 'network_avg': network_avg, 'network_max': network_max, 'network_min': network_min, 'network_total_avg': network_total_avg, 'network_total_max': network_total_max, 'network_total_min': network_total_min})
                                            else:  # inserted
                                                response['error_message'] = 'Error retrieving bottleneck stats with status code (%d)' % resp.status_code
                                    except Exception as e:
                                        cherrypy.response.status = 501 + (cherrypy.response.status + (self.logger.error('Error requesting bottleneck stats from kasm (%s) with error (%s)' % (kasm.kasm_id, e)) if kasm and kasm.user.user_id!= user.user_id else 'Kasm is not responding' % (response['error_message'], self.logger.error('User (%s) attempted to call get_kasm_bottleneck_stats for another users Kasm (%s)' % (user.user_id, kasm.kasm_id))) if kasm else 'Could not find requested Kasm.' % response['error_message']) if response else response

    @cherrypy.expose(['get_kasm_screenshot'])
    @CookieAuthenticated(requested_actions=[JWT_AUTHORIZATION.USER])
    def get_kasm_screenshot(self, kasm_id='', width=300, height=300):
        cherrypy.response.status = 404
        kasm = cherrypy.request.db.getKasm(kasm_id)
        if not kasm or cherrypy.request.authenticated_user.user_id == kasm.user.user_id:
            target_filename = '/tmp/{0}.jpg'.format(uuid.uuid4().hex)
            try:
                content = None
                if (kasm.image.is_container or (kasm.image.is_server or kasm.image.is_server_pool)) and kasm.server.is_kasmvnc:
                    query = 'get_screenshot?width={0}&height={1}'.format(width, height)
                    resp = self._kasmvnc_api(query, kasm, True, 'get')
                    content = resp.content
                else:  # inserted
                    if kasm.server.is_rdp or (kasm.server.connection_info and 'kasm_svc' in kasm.server.connection_info):
                        query = 'screenshot?width={0}&height={1}'.format(width, height)
                        success, data = self._kasm_host_svc_api(query, kasm, True, 'post', timeout=5)
                        if success:
                            content = data
                cherrypy.response.headers['Content-Type'] = 'image/jpg'
                cherrypy.response.status = 200
                return content
            except Exception as e:
                cherrypy.response.status = 500
                self.logger.error('Error requesting screenshot from kasm (%s) with error (%s)' % (kasm_id, e))
        else:  # inserted
            self.logger.warning('get_kasm_screenshot, user (%s) attempted to get a screenshot of user (%s).' % (str(cherrypy.request.authenticated_user.user_id), str(kasm.user.user_id)))
            cherrypy.response.status = 404
        else:  # inserted
            self.logger.warning('get_kasm_screenshot could not find kasm by id: %s', kasm_id)
            cherrypy.response.status = 404

    @cherrypy.expose(['get_user_kasm'])
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    @Authenticated(requested_actions=[JWT_AUTHORIZATION.USER], read_only=True)
    @func_timing
    def get_kasm_status(self):
        event = cherrypy.request.json
        response = {}
        kasm = cherrypy.request.db.getKasm(event['kasm_id'])
        user = cherrypy.request.authenticated_user
        if 'skip_agent_check' not in event:
            event['skip_agent_check'] = False
        if kasm is not None:
            if kasm.user.user_id == user.user_id:
                cherrypy.request.kasm_id = str(kasm.kasm_id)
                self.logger.info('Requested status for kasm_id (%s) at (%s) for user (%s) at (%s) ' % (str(kasm.kasm_id), kasm.container_ip, user.username, cherrypy.request.authenticated_user_ip))
                kasm_status = kasm.get_operational_status()
                if kasm_status in [SESSION_OPERATIONAL_STATUS.DELETING, SESSION_OPERATIONAL_STATUS.ADMIN_DELETE_PENDING, SESSION_OPERATIONAL_STATUS.DELETE_PENDING]:
                    _msg = 'Kasm is currently scheduled to be deleted.'
                    self.logger.error(_msg)
                    response['error_message'] = _msg
                else:  # inserted
                    if kasm_status in [SESSION_OPERATIONAL_STATUS.STARTING, SESSION_OPERATIONAL_STATUS.REQUESTED, SESSION_OPERATIONAL_STATUS.PROVISIONING, SESSION_OPERATIONAL_STATUS.ASSIGNED]:
                        _msg = 'This session is currently %s.' % kasm_status
                        self.logger.debug(_msg)
                        response['error_message'] = _msg
                        response['operational_message'] = kasm.operational_message
                        response['operational_progress'] = kasm.operational_progress
                        response['operational_status'] = kasm.operational_status
                    else:  # inserted
                        if kasm_status == SESSION_OPERATIONAL_STATUS.PAUSING:
                            _msg = 'This session is currently scheduled to be paused.'
                            self.logger.error(_msg)
                            response['error_message'] = _msg
                        else:  # inserted
                            if kasm_status == SESSION_OPERATIONAL_STATUS.STOPPING:
                                _msg = 'This session is currently scheduled to be stopped.'
                                self.logger.error(_msg)
                                response['error_message'] = _msg
                            else:  # inserted
                                if kasm_status == SESSION_OPERATIONAL_STATUS.RUNNING:
                                    _kasm = self.get_normalized_kasm(kasm)
                                    if not event['skip_agent_check']:
                                        if not kasm.image.is_container:
                                            pass  # postinserted
                                    container_is_running = True
                                        else:  # inserted
                                            try:
                                                container_is_running = self.provider_manager.container_is_running(kasm)
                                            except ConnectionError as e:
                                                response['error_message'] = 'Failed to check container status on agent'
                                                return response
                                            e = None
                                    if container_is_running:
                                        if check_usage(user):
                                            response['kasm'] = _kasm
                                            response['current_time'] = str(datetime.datetime.utcnow())
                                        else:  # inserted
                                            if self.is_usage_limit_licensed(self.logger):
                                                msg = 'Usage limit exceeded for user'
                                                self.logger.warning(msg)
                                                response['error_message'] = msg
                                            else:  # inserted
                                                response['kasm'] = _kasm
                                                response['current_time'] = str(datetime.datetime.utcnow())
                                    else:  # inserted
                                        response['error_message'] = 'Kasm is not running'
                                else:  # inserted
                                    response['operational_status'] = kasm.operational_status
        if kasm:
            if kasm.user.user_id!= user.user_id:
                response['error_message'] = 'Access Denied'
                self.logger.error('User (%s) attempted to call get_kasm_status for another users Kasm (%s)' % (user.user_id, kasm.kasm_id))
        self.logger.error('get_kasm_status could not find kasm by id: %s', event['kasm_id'])
        response['error_message'] = 'Could not find requested Kasm.'
        return response

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    @Authenticated(requested_actions=[JWT_AUTHORIZATION.USER], read_only=False)
    def exec_kasm(self):
        event = cherrypy.request.json
        response = {}
        if 'target_kasm' in event:
            target_kasm = event['target_kasm']
            if 'kasm_id' in target_kasm and 'kasm_exec' in target_kasm:
                kasm = cherrypy.request.db.getKasm(target_kasm['kasm_id'])
                user = cherrypy.request.authenticated_user
                kasm_exec = target_kasm['kasm_exec']
                kasm_url = target_kasm.get('kasm_url', '')
                response = self._exec_kasm(kasm, user, kasm_exec, kasm_url)
            else:  # inserted
                msg = 'Missing required parameters'
                self.logger.error(msg)
                response['error_message'] = msg
        else:  # inserted
            msg = 'Missing required parameters'
            self.logger.error(msg)
            response['error_message'] = msg
        return response

    def _exec_kasm(self, kasm, user, kasm_exec, kasm_url):
        response = {}
        if kasm is not None:
            if kasm.user_id == user.user_id:
                kasm_status = kasm.get_operational_status()
                if kasm_status in [SESSION_OPERATIONAL_STATUS.DELETING, SESSION_OPERATIONAL_STATUS.ADMIN_DELETE_PENDING, SESSION_OPERATIONAL_STATUS.DELETE_PENDING]:
                    _msg = 'Kasm is currently scheduled to be deleted.'
                    self.logger.error(_msg)
                    response['error_message'] = _msg
                else:  # inserted
                    if kasm_status == SESSION_OPERATIONAL_STATUS.PAUSING:
                        _msg = 'This session is currently scheduled to be paused.'
                        self.logger.error(_msg)
                        response['error_message'] = _msg
                    else:  # inserted
                        if kasm_status == SESSION_OPERATIONAL_STATUS.STOPPING:
                            _msg = 'This session is currently scheduled to be stopped.'
                            self.logger.error(_msg)
                            response['error_message'] = _msg
                        else:  # inserted
                            if kasm_status in (SESSION_OPERATIONAL_STATUS.RUNNING, SESSION_OPERATIONAL_STATUS.STARTING):
                                _kasm = self.get_normalized_kasm(kasm)
                                try:
                                    container_is_running = self.provider_manager.container_is_running(kasm)
                                except ConnectionError as e:
                                    response['error_message'] = 'Failed to check container status on agent'
                                    return response
                                if container_is_running:
                                    exec_config = kasm.image.exec_config.copy()
                                    exec_config = exec_config.get(kasm_exec)
                                    if exec_config:
                                        environment = exec_config.get('environment', {})
                                        if kasm_exec == 'go':
                                            environment['KASM_URL'] = kasm_url
                                        exec_config['environment'] = environment
                                        exec_config['container_id'] = kasm.container_id
                                        self.logger.debug('Using exec_config %s' % exec_config)
                                        if not self.provider_manager.kasm_exec(kasm, exec_config, skip_hello=True):
                                            response['error_message'] = 'Kasm exec failed'
                                    else:  # inserted
                                        self.logger.info(f'Invalid kasm_exec provided for session ({kasm.kasm_id}).')
                                    response['kasm'] = _kasm
                                    response['current_time'] = str(datetime.datetime.utcnow())
                                else:  # inserted
                                    self.logger.error(f'Kasm {kasm.kasm_id} for {user.user_id} is not running.')
                                    response['error_message'] = 'Kasm is not running'
                            else:  # inserted
                                response['status'] = kasm.operational_status
                                self.logger.error(f'Kasm exec_config failed to apply due container status ({kasm_status}).')
            else:  # inserted
                self.logger.error('User (%s) requested action for Kasm (%s) which is owned by user (%s)' % (user.user_id, kasm.kasm_id, kasm.user_id))
                response['error_message'] = 'Access Denied'
        else:  # inserted
            self.logger.error(f'_exec_kasm received a kasm of \'None\' for User {user.user_id}.')
            response['error_message'] = 'Could not find requested Kasm.'
        return response

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    @Authenticated(requested_actions=[JWT_AUTHORIZATION.USER], read_only=False)
    def logout(self):
        event = cherrypy.request.json
        user = cherrypy.request.authenticated_user
        session_token_id = cherrypy.request.session_token_id
        response = {}
        try:
            logout_all = event.get('logout_all')
            if logout_all:
                cherrypy.request.db.remove_all_session_tokens(user)
            else:  # inserted
                cherrypy.request.db.remove_session_token(session_token_id)
                cherrypy.request.db.remove_expired_session_tokens(user)
            if user.sso_ep:
                user.sso_ep = None
                cherrypy.request.db.updateUser(user)
            if 'saml_id' in event:
                config = cherrypy.request.db.get_saml_config(event['saml_id'])
                if config is not None and config.idp_slo_url is not None:
                    saml = SamlAuthentication(cherrypy.request, config, '/api/slo')
                    name_id = user.username
                    response['slo_url'] = saml.slo(name_id, '')
        except Exception as e:
            self.logger.exception('Exception removing user (%s) token during logout %s' % (event['username'], e))
            response['error_message'] = 'Logout Error'
        return response

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    @Authenticated(requested_actions=[JWT_AUTHORIZATION.USER], read_only=True)
    def get_client_settings(self):
        user = cherrypy.request.authenticated_user
        response = cherrypy.request.db.get_default_client_settings(user)
        return response

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    @Authenticated(requested_actions=[JWT_AUTHORIZATION.USER], read_only=True)
    def get_default_images(self):
        return self._get_default_images()

    def _get_default_images(self):
        response = {}
        user = cherrypy.request.authenticated_user
        user_image = cherrypy.request.db.getUserAttributes(user)
        if user_image is not None:
            response['user_image'] = cherrypy.request.db.serializable(user_image.default_image)
        group_image = user.get_setting_value('default_image')
        if group_image is not None:
            response['group_image'] = group_image
        return response

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    @Authenticated(requested_actions=[JWT_AUTHORIZATION.USER], read_only=True)
    def get_user_attributes(self):
        response = {}
        response['user_attributes'] = self.get_attributes_for_user(cherrypy.request.authenticated_user)
        return response

    def get_attributes_for_user(self, user):
        attr = cherrypy.request.db.getUserAttributes(user)
        res = {'user_attributes_id': cherrypy.request.db.serializable(attr.user_attributes_id), 'default_image': cherrypy.request.db.serializable(attr.default_image), 'show_tips': cherrypy.request.db.serializable(attr.show_tips), 'auto_login_kasm': cherrypy.request.db.serializable(attr.user_login_to_kasm), 'user_id': cherrypy.request.db.serializable(attr.user_id), 'toggle_control_panel': cherrypy.request.db.serializable(attr.toggle_control_panel), 'theme': cherrypy.request.db.serializable(attr.theme), 'chat_sfx': cherrypy.request.db.serializable(attr.chat_sfx), 'ssh_public_key': cherrypy.request.db.serializable(attr.ssh_public_key), 'preferred_language': cherrypy.request.db.serializable(attr.preferred_language), 'preferred_timezone': cherrypy.request.db.serializable(attr.preferred_timezone)}
        return res

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    @Authenticated(requested_actions=[JWT_AUTHORIZATION.USER], read_only=False)
    def update_user_attribute(self):
        return self._update_user_attribute()

    def _update_user_attribute(self, public=False):
        response = {}
        event = cherrypy.request.json
        if 'target_user_attributes' in event:
            target_user_attributes = event['target_user_attributes']
            user = None
            if cherrypy.request.is_api:
                user_id = target_user_attributes.get('user_id')
                if user_id:
                    user = cherrypy.request.db.get_user_by_id(user_id)
                    if user:
                        if not JWT_AUTHORIZATION.is_user_authorized_action(None, cherrypy.request.authorizations, JWT_AUTHORIZATION.USERS_MODIFY, target_user=user):
                            self.logger.error(f'API key ({cherrypy.request.api_key_name}) does not have authorization to modify target user ({user.user_id})')
                            response['error_message'] = 'Unauthorized'
                            cherrypy.response.status = 401
                            return response
                else:  # inserted
                    msg = 'Missing required parameters'
                    self.logger.error(msg)
                    response['error_message'] = msg
                    if public:
                        cherrypy.response.status = 400
                    return response
            else:  # inserted
                user = cherrypy.request.authenticated_user
            if user:
                ssh_private_key = target_user_attributes.get('ssh_private_key', '').strip()
                ssh_passphrase = target_user_attributes.get('ssh_passphrase', '').strip()
                ssh_passphrase = ssh_passphrase.encode('utf-8') if ssh_passphrase else None
                if ssh_private_key:
                    backend = default_backend()
                    try:
                        key = backend.load_pem_private_key(ssh_private_key.encode('utf-8'), password=ssh_passphrase, unsafe_skip_rsa_key_validation=False)
                        if not ssh_passphrase:
                            target_user_attributes['ssh_private_key'] = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()).decode('utf-8')
                        public_key = key.public_key().public_bytes(encoding=serialization.Encoding.OpenSSH, format=serialization.PublicFormat.OpenSSH)
                        target_user_attributes['ssh_public_key'] = public_key.decode('utf-8')
                    except Exception as e:
                        msg = 'Error processing SSH Private Key: (%s)' % e
                        self.logger.exception(msg)
                        response['error_message'] = msg
                        if public:
                            cherrypy.response.status = 400
                        return response
                cherrypy.request.db.updateUserAttribute(user, target_user_attributes)
            else:  # inserted
                msg = 'Missing or invalid user'
                self.logger.error(msg)
                response['error_message'] = msg
                if public:
                    cherrypy.response.status = 400
        else:  # inserted
            msg = 'No target user attribute in request'
            self.logger.error(msg)
            response['error_message'] = msg
            if public:
                cherrypy.response.status = 400
        return response

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    @Authenticated(requested_actions=[JWT_AUTHORIZATION.USER], read_only=False)
    def keepalive(self):
        event = cherrypy.request.json
        user = cherrypy.request.authenticated_user
        response = {}
        if 'kasm_id' in event and event.get('kasm_id'):
            kasm = cherrypy.request.db.getKasm(event['kasm_id'])
            if kasm:
                if kasm.user.username == event['username']:
                    return self._keepalive(kasm, user)
                self.logger.error('Invalid user for kasm_id (%s) for keepalive request for user (%s)' % (event['kasm_id'], event['username']))
                response['error_message'] = 'Keepalive Error'
            else:  # inserted
                self.logger.warning('Invalid kasm_id (%s) for keepalive request for user (%s)' % (event['kasm_id'], event['username']))
                response['error_message'] = 'Keepalive Error'
        else:  # inserted
            self.logger.error('Missing kasm_id for keepalive request for user (%s)' % event['username'])
            response['error_message'] = 'Keepalive Error'
        return response

    def _keepalive(self, kasm, user):
        response = {}
        kasm_status = kasm.get_operational_status()
        if kasm_status not in [SESSION_OPERATIONAL_STATUS.DELETING, SESSION_OPERATIONAL_STATUS.ADMIN_DELETE_PENDING, SESSION_OPERATIONAL_STATUS.DELETE_PENDING, SESSION_OPERATIONAL_STATUS.PAUSING, SESSION_OPERATIONAL_STATUS.STOPPING]:
            try:
                if kasm.image.session_time_limit:
                    self.logger.info('Image has a session_time_limit of (%s) defined. Will not promote keepalive' % kasm.image.session_time_limit)
                else:  # inserted
                    if user.get_setting_value('session_time_limit', None) is not None:
                        self.logger.info('User has a session_time_limit of (%s) defined. Will not promote keepalive' % user.get_setting_value('session_time_limit', None))
                    else:  # inserted
                        keepalive_expiration = user.get_setting_value('keepalive_expiration')
                        if not keepalive_expiration:
                            keepalive_expiration = int(self._db.get_config_setting_value('scale', 'keepalive_expiration'))
                            self.logger.info('No group-level level keepalive_expiration setting defined. Using global value of (%s)' % keepalive_expiration)
                        else:  # inserted
                            self.logger.debug('Using group-level keepalive_expiration of (%s)' % keepalive_expiration)
                        if not check_usage(user):
                            msg = 'Usage limit exceeded for user: (%s)' % user.username
                            self.logger.warning(msg)
                            response['usage_reached'] = True
                        else:  # inserted
                            response['usage_reached'] = False
                            kasm.keepalive_date = datetime.datetime.utcnow()
                            kasm.expiration_date = kasm.keepalive_date + datetime.timedelta(seconds=keepalive_expiration)
                            cherrypy.request.db.updateKasm(kasm)
                            self.logger.info('Set keepalive for kasm_id (%s) at (%s) for user (%s) from IP (%s) ' % (str(kasm.kasm_id), kasm.container_ip, user.username, cherrypy.request.authenticated_user_ip))
            except Exception as e:
                self.logger.exception('Exception updating keepalive for kasm_id (%s) user (%s) keepalive_date %s' % (kasm.kasm_id, user.username, e))
                response['error_message'] = 'Keepalive Error'
        else:  # inserted
            _msg = 'Kasm (%s) is currently scheduled to be deleted. Can not honor keepalive request' % str(kasm.kasm_id[:6])
            self.logger.error(_msg)
            response['error_message'] = _msg
        return response

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    @Authenticated(requested_actions=[JWT_AUTHORIZATION.USER], read_only=False)
    @func_timing
    def destroy_kasm(self):
        event = cherrypy.request.json
        user = cherrypy.request.authenticated_user
        response = {}
        if 'kasm_id' in event:
            kasm = cherrypy.request.db.getKasm(event['kasm_id'])
            if kasm:
                if JWT_AUTHORIZATION.is_authorized_action(cherrypy.request.authorizations, JWT_AUTHORIZATION.SESSIONS_DELETE) or kasm.user.user_id == user.user_id:
                    if JWT_AUTHORIZATION.is_authorized_action(cherrypy.request.authorizations, JWT_AUTHORIZATION.SESSIONS_DELETE) or user.get_setting_value('allow_kasm_delete', True) == True:
                        if not kasm.image.is_container and kasm.operational_status!= SESSION_OPERATIONAL_STATUS.DELETING or kasm.image.is_container:
                            if kasm.operational_status in [SESSION_OPERATIONAL_STATUS.RUNNING.value, SESSION_OPERATIONAL_STATUS.STOPPED.value, SESSION_OPERATIONAL_STATUS.PAUSED.value, SESSION_OPERATIONAL_STATUS.SAVING.value, SESSION_OPERATIONAL_STATUS.STARTING.value, SESSION_OPERATIONAL_STATUS.PROVISIONING.value, SESSION_OPERATIONAL_STATUS.ASSIGNED.value, SESSION_OPERATIONAL_STATUS.REQUESTED.value, SESSION_OPERATIONAL_STATUS.DELETING.value]:
                                pass  # postinserted
                        cherrypy.request.kasm_id = str(kasm.kasm_id)
                        try:
                            if kasm.user:
                                if kasm.user.user_id == user.user_id:
                                    _role = 'user'
                            _role = 'admin'
                            if kasm.operational_status == SESSION_OPERATIONAL_STATUS.DELETING:
                                self.logger.info(f'Kasm ({kasm.kasm_id}) is being forcefully destroyed, currently in a deleting state.')
                            if kasm.image.is_server_pool:
                                if kasm.server:
                                    if kasm.server.server_pool:
                                        if not kasm.server.is_reusable:
                                            self.logger.info('Server (%s) : (%s) is a member of a node pool and is not reusable. Deleting' % (kasm.server.server_id, kasm.server.hostname))
                                            kasm.server.operational_status = 'delete_pending'
                                            cherrypy.request.db.updateServer(kasm.server)
                                    self.provider_manager.destroy_kasm(kasm, reason='%s_destroyed' % _role)
                                else:  # inserted
                                    self.logger.warning('Kasm (%s) : Status (%s) has no server assigned. Deleting' % (kasm.kasm_id, kasm.operational_status))
                                    self.provider_manager.destroy_kasm(kasm, reason='%s_destroyed' % _role)
                            else:  # inserted
                                self.provider_manager.destroy_kasm(kasm, reason='%s_destroyed' % _role)
                        except Exception as e:
                            if 'username' in event:
                                username = event['username']
                            else:  # inserted
                                if kasm.user:
                                    if kasm.user.user_id == user.user_id:
                                        username = kasm.user.username
                                username = 'Admin'
                            self.logger.exception(f'Exception during user ({username}) destroy : {e}')
                            response['error_message'] = 'Destroy Error'
                        if not kasm.image.is_container:
                            if kasm.server.agent_installed:
                                if kasm.operational_status == SESSION_OPERATIONAL_STATUS.DELETING:
                                    if JWT_AUTHORIZATION.is_authorized_action(cherrypy.request.authorizations, JWT_AUTHORIZATION.SESSIONS_DELETE):
                                        cherrypy.request.db.deleteKasm(kasm)
                                        self.logger.warning(f'Session ({kasm.kasm_id}) was forcefully removed by administrator.')

                        @self.logger.error
                        msg)

                        @msg
                        response['error_message'] = response
                    else:  # inserted
                        msg = 'User is not authorized to issue a delete request'

                        @self.logger.error
                        msg)

                        @msg
                        response['error_message'] = 'Unauthorized attempt to delete session'
                else:  # inserted
                    @self.logger.error
                    msg)

                    @msg
                    response['error_message'] = response
            else:  # inserted
                @'No session found with kasm_id (%s)'
                msg = event['kasm_id']

                @self.logger.error
                msg)

                @msg
                response['error_message'] = response
        else:  # inserted
            @'Invalid Request'
            response['error_message'] = response
        return response

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    @Authenticated(requested_actions=[JWT_AUTHORIZATION.USER], read_only=False)
    @func_timing
    def stop_kasm(self):
        event = cherrypy.request.json
        user = cherrypy.request.authenticated_user
        response = {}
        if 'kasm_id' in event:
            kasm = cherrypy.request.db.getKasm(event['kasm_id'])
            is_admin = JWT_AUTHORIZATION.is_authorized_action(cherrypy.request.authorizations, JWT_AUTHORIZATION.SESSIONS_MODIFY)
            if kasm:
                if is_admin or kasm.user.user_id == user.user_id:
                    if is_admin or user.get_setting_value('allow_kasm_stop', False) == True:
                        if not kasm.image.is_container or kasm.operational_status in [SESSION_OPERATIONAL_STATUS.RUNNING.value, SESSION_OPERATIONAL_STATUS.PAUSED.value]:
                            cherrypy.request.kasm_id = str(kasm.kasm_id)
                            try:
                                res, async_destroy = self.provider_manager.stop_kasm(kasm)
                                if res:
                                    if async_destroy:
                                        self.logger.info('Successfully stopped session (%s)' % kasm.kasm_id)
                                if res:
                                    self.logger.info(f'Successfully queued session for stopping ({kasm.kasm_id})')
                                else:  # inserted
                                    msg = 'Failed to stop session (%s)' % kasm.kasm_id
                                    response['error_message'] = msg
                                    self.logger.error(msg)
                            except Exception as e:
                                if 'username' in event:
                                    username = event['username']
                                else:  # inserted
                                    if kasm.user:
                                        if kasm.user.user_id == user.user_id:
                                            username = kasm.user.username
                                    username = 'Admin'
                                self.logger.exception(f'Exception during user ({username}) session stop : {e}')
                                response['error_message'] = 'Unexpected error encountered during stop request'
                        else:  # inserted
                            msg = 'Session is not in a valid state to be stopped'
                            self.logger.error(msg)
                            response['error_message'] = msg
                        else:  # inserted
                            msg = 'Only Container based sessions can be stopped'
                            self.logger.error(msg)
                            response['error_message'] = msg
                    else:  # inserted
                        msg = 'User is not authorized to issue a stop request'
                        self.logger.error(msg)
                        response['error_message'] = msg
                else:  # inserted
                    msg = 'Unauthorized attempt to stop session'
                    self.logger.error(msg)
                    response['error_message'] = msg
            else:  # inserted
                msg = 'No session found with kasm_id (%s)' % event['kasm_id']
                self.logger.error(msg)
                response['error_message'] = msg
        else:  # inserted
            response['error_message'] = 'Invalid Request'
        return response

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    @Authenticated(requested_actions=[JWT_AUTHORIZATION.USER], read_only=False)
    @func_timing
    def pause_kasm(self):
        event = cherrypy.request.json
        user = cherrypy.request.authenticated_user
        response = {}
        kasm_id = event.get('kasm_id')
        is_admin = JWT_AUTHORIZATION.is_authorized_action(cherrypy.request.authorizations, JWT_AUTHORIZATION.SESSIONS_MODIFY)
        if kasm_id:
            kasm = cherrypy.request.db.getKasm(kasm_id)
            if kasm:
                if is_admin or kasm.user.user_id == user.user_id:
                    if is_admin or user.get_setting_value('allow_kasm_pause', False) == True:
                        if not kasm.image.is_container or kasm.operational_status == SESSION_OPERATIONAL_STATUS.RUNNING.value:
                            cherrypy.request.kasm_id = str(kasm.kasm_id)
                            try:
                                res, async_destroy = self.provider_manager.pause_kasm(kasm)
                                if res:
                                    if not async_destroy:
                                        self.logger.info('Successfully paused session (%s)' % kasm.kasm_id)
                                if res:
                                    self.logger.info(f'Successfully queued session for pausing ({kasm.kasm_id})')
                                else:  # inserted
                                    msg = 'Failed to pause session (%s)' % kasm.kasm_id
                                    response['error_message'] = msg
                            except Exception as e:
                                if 'username' in event:
                                    username = event['username']
                                else:  # inserted
                                    if kasm.user:
                                        if kasm.user.user_id == user.user_id:
                                            username = kasm.user.username
                                    username = 'Admin'
                                self.logger.exception(f'Exception during user ({username}) session pause : {e}')
                                response['error_message'] = 'Unexpected error encountered during pause request'
                        else:  # inserted
                            msg = 'Session is not in a valid state to be paused'
                            self.logger.error(msg)
                            response['error_message'] = msg
                        else:  # inserted
                            msg = 'Only Container based sessions can be paused'
                            self.logger.error(msg)
                            response['error_message'] = msg
                    else:  # inserted
                        msg = 'User is not authorized to issue a pause request'
                        self.logger.error(msg)
                        response['error_message'] = msg
                else:  # inserted
                    msg = 'Unauthorized attempt to pause session'
                    self.logger.error(msg)
                    response['error_message'] = msg
            else:  # inserted
                msg = 'No session found with kasm_id (%s)' % kasm_id
                self.logger.error(msg)
                response['error_message'] = msg
        else:  # inserted
            response['error_message'] = 'Invalid Request'
        return response

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    @Authenticated(requested_actions=[JWT_AUTHORIZATION.USER], read_only=False)
    @func_timing
    def resume_kasm(self):
        event = cherrypy.request.json
        user = cherrypy.request.authenticated_user
        response = {}
        kasm_id = event.get('kasm_id')
        license_helper = LicenseHelper(cherrypy.request.db, self.logger)
        if license_helper.is_per_concurrent_kasm_ok():
            if kasm_id:
                kasm = cherrypy.request.db.getKasm(kasm_id)
                is_admin = JWT_AUTHORIZATION.is_authorized_action(cherrypy.request.authorizations, JWT_AUTHORIZATION.SESSIONS_MODIFY)
                if kasm is not None:
                    if is_admin or kasm.user.user_id == user.user_id:
                        if kasm.image.is_container:
                            cherrypy.request.kasm_id = str(kasm.kasm_id)
                            try:
                                if kasm.operational_status in (SESSION_OPERATIONAL_STATUS.STOPPED.value, SESSION_OPERATIONAL_STATUS.PAUSED.value) or is_admin:
                                    res, error_message = self.provider_manager.resume_kasm(kasm)
                                    if res:
                                        self.logger.info('Successfully resumed session (%s)' % kasm.kasm_id)
                                    else:  # inserted
                                        msg = 'Failed to resume session (%s) : %s' % (kasm.kasm_id, error_message)
                                        response['error_message'] = msg
                                else:  # inserted
                                    msg = 'Session (%s) is in status (%s) and cannot be resumed' % (kasm.kasm_id, kasm.operational_status)
                                    self.logger.error(msg)
                                    response['error_message'] = msg
                            except Exception as e:
                                if 'username' in event:
                                    username = event['username']
                                else:  # inserted
                                    if kasm.user:
                                        if kasm.user.user_id == user.user_id:
                                            username = kasm.user.username
                                    username = 'Admin'
                                self.logger.exception(f'Exception during user ({username}) resume : {e}')
                                response['error_message'] = 'Unexpected error encountered during resume request'
                        else:  # inserted
                            msg = 'Only Container based sessions can be resumed'
                            self.logger.error(msg)
                            response['error_message'] = msg
            else:  # inserted
                response['error_message'] = 'Invalid Request'
        else:  # inserted
            msg = 'Per concurrent session license limit exceeded. Unable to resume Session'
            self.logger.error(msg)
            response['error_message'] = msg
        return response

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    @Authenticated(requested_actions=[JWT_AUTHORIZATION.USER], read_only=True)
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
        all_categories = sorted(all_categories, key=lambda x: x.lower())
        return {'images': cherrypy.request.db.serializable(result), 'all_categories': all_categories, 'disabled_image_message': user.get_setting_value('disabled_image_message', '')}

    def _get_user_images(self, user):
        data = dict()
        show_disabled_images = user.get_setting_value('show_disabled_images', False)
        images = user.get_images(only_enabled=not show_disabled_images)
        zones = []
        all_network_names = None
        allow_zone_selection = user.get_setting_value('allow_zone_selection', False)
        if allow_zone_selection:
            zones.append({'zone_id': '', 'zone_name': 'Auto'})
            all_zones = cherrypy.request.db.getZones()
            if all_zones:
                for zone in sorted(all_zones, key=lambda x: x.zone_name.lower()):
                    zones.append({'zone_id': zone.zone_id, 'zone_name': zone.zone_name})
        for image in images:
            _zones = zones
            _image_networks = []
            if allow_zone_selection and image.restrict_to_zone and image.zone_id:
                _zones = [{'zone_id': '', 'zone_name': 'Auto'}, {'zone_id': str(image.zone_id), 'zone_name': image.zone.zone_name}]
            if not image.allow_network_selection or image.restrict_to_network:
                _image_networks = [{'network_id': '', 'network_name': 'Auto'}]
                for n in image.restrict_network_names:
                    _image_networks.append({'network_id': n, 'network_name': n})
            else:  # inserted
                if all_network_names == None:
                    _network_names = self._get_network_names()
                    all_network_names = [{'network_id': '', 'network_name': 'Auto'}]
                    for n in _network_names:
                        all_network_names.append({'network_id': n, 'network_name': n})
                    _image_networks = all_network_names
                else:  # inserted
                    _image_networks = all_network_names
            data[cherrypy.request.db.serializable(image.image_id)] = {'name': image.name, 'friendly_name': image.friendly_name, 'description': image.description, 'image_src': image.image_src, 'available': image.available if image.is_container else True, 'cores': image.cores, 'memory': image.memory, 'memory_friendly': '%sMB' % int(int(image.memory) / 1000000), 'persistent_profile_settings': image.get_persistent_profile_permissions(user), 'zones': _zones, 'networks': _image_networks, 'categories': image.categories, 'default_category': image.default_category, 'enabled': image.enabled, 'hidden': image.hidden, 'image_type': image.image_type, 'link_url': image.link_url, 'launch_config': image.launch_config}
        return data

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    @Authenticated
    @JWT_AUTHORIZATION.USER(requested_actions=[JWT_AUTHORIZATION.USER], read_only=True)
    def get_user_kasms(self):
        user = cherrypy.request.authenticated_user
        response = {'kasms': [], 'current_time': str(datetime.datetime.utcnow())}
        for kasm in cherrypy.request.db.get_kasms(user):
            response['kasms'].append(self.get_normalized_kasm(kasm))
        return cherrypy.request.db.serializable(response)

    def get_normalized_kasm(self, kasm):
        _kasm = cherrypy.request.db.serializable(kasm.__dict__, skip_fields=['user', 'image', 'docker_environment'])
        _kasm['is_persistent_profile'] = kasm.is_persistent_profile
        _kasm['persistent_profile_mode'] = kasm.persistent_profile_mode
        _kasm['port_map'] = kasm.get_port_map()
        _kasm['token'] = ''
        _kasm['view_only_token'] = ''
        _kasm.pop('api_token', None)
        try:
            _kasm['host'] = gethostbyname(kasm.server.hostname) if kasm.server and kasm.server.hostname else None
        except gaierror as e:
            self.logger.warning('Unable to resolve the address kasm\'s agents name (%s). This may result in the Kasm being inaccessible.' % kasm.server.hostname)
            _kasm['host'] = kasm.server.hostname if kasm.server else None
        _kasm['port'] = kasm.server.port if kasm.server else None
        _kasm['image'] = {'image_id': kasm.image.image_id, 'name': kasm.image.name, 'friendly_name': kasm.image.friendly_name, 'image_src': kasm.image.image_src, 'session_time_limit': kasm.image.session_time_limit, 'categories': kasm.image.categories, 'default_category': kasm.image.default_category, 'image_type': kasm.image.image_type}
        if kasm.operational_status in [SESSION_OPERATIONAL_STATUS.REQUESTED.value, SESSION_OPERATIONAL_STATUS.PROVISIONING.value, SESSION_OPERATIONAL_STATUS.ASSIGNED.value, SESSION_OPERATIONAL_STATUS.STARTING.value]:
            _kasm['client_settings'] = []
        else:  # inserted
            _kasm['client_settings'] = cherrypy.request.db.filter_client_settings_by_connection_type(cherrypy.request.db.get_default_client_settings(kasm.user, kasm.cast_config_id) if kasm.user else {}, kasm.connection_type)
        if kasm.image.is_container or kasm.image.is_server_pool:
            _kasm['hostname'] = cherrypy.request.headers['HOST'] if kasm.server and kasm.server.zone.proxy_connections and (not kasm.server.zone.proxy_hostname or kasm.server.zone.proxy_hostname.lower() == '$request_host$') else kasm.server.zone.proxy_hostname
            else:  # inserted
                _kasm['hostname'] = kasm.server.zone.proxy_hostname
                for k, v in _kasm['port_map'].items():
                    _kasm['port_map'][k]['path'] = '{}/{}/{}'.format(kasm.server.zone.proxy_path, str(kasm.kasm_id), k)
                    _kasm['port_map'][k]['port'] = kasm.server.zone.proxy_port
        else:  # inserted
            _kasm['hostname'] = kasm.server.hostname if kasm.server else None
        else:  # inserted
            if kasm.server.zone.proxy_hostname:
                if kasm.server.zone.proxy_hostname.lower() == '$request_host$':
                    _kasm['hostname'] = cherrypy.request.headers['HOST']
            _kasm['hostname'] = kasm.server.zone.proxy_hostname
            for k, v in _kasm['port_map'].items() + '{}/{}/{}'.format(kasm.server.zone.proxy_path).items():
                _kasm['port_map'][k]['path'] = str(kasm.kasm_id)(k)
        return cherrypy.request.db.serializable(_kasm)

    def get_normalized_shared_kasm(self, kasm, user):
        _kasm = {}
        _kasm['port_map'] = kasm.get_port_map()
        _kasm['view_only_token'] = ''
        _kasm['user'] = {'username': kasm.user.username}
        if 'uploads' in _kasm['port_map']:
            del _kasm['port_map']['uploads']
        if 'audio_input' in _kasm['port_map']:
            del _kasm['port_map']['audio_input']
        if 'webcam' in _kasm['port_map']:
            del _kasm['port_map']['webcam']
        try:
            _kasm['host'] = gethostbyname(kasm.server.hostname)
        except gaierror as e:
            self.logger.warning('Unable to resolve the address kasm\'s agents name (%s). This may result in the Kasm being inaccessible.' % kasm.server.hostname)
            _kasm['host'] = kasm.server.hostname
        _kasm['kasm_id'] = kasm.kasm_id
        _kasm['share_id'] = kasm.share_id
        _kasm['port'] = kasm.server.port
        _kasm['image'] = {'image_id': kasm.image.image_id, 'name': kasm.image.name, 'friendly_name': kasm.image.friendly_name, 'image_src': kasm.image.image_src, 'session_time_limit': kasm.image.session_time_limit}
        if cherrypy.request.db.filter_client_settings_by_connection_type(user):
            _kasm['client_settings'] = cherrypy.request.db.get_default_client_settings(user) if cherrypy.request.db.get_default_client_settings(user) else {}, kasm.connection_type)
        if not kasm.server.zone.proxy_connections or kasm.server.zone.proxy_hostname:
            if kasm.server.zone.proxy_hostname.lower() == '$request_host$':
                _kasm['hostname'] = cherrypy.request.headers['HOST']
        _kasm['hostname'] = kasm.server.zone.proxy_hostname
            for k, v in _kasm['port_map'].items():
                _kasm['port_map'][k]['path'] = '{}/{}/{}'.format(kasm.server.zone.proxy_path, str(kasm.kasm_id), k)
                _kasm['port_map'][k]['port'] = kasm.server.zone.proxy_port
        else:  # inserted
            _kasm['hostname'] = kasm.server.hostname
        return cherrypy.request.db.serializable(_kasm)

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    @Authenticated(requested_actions=[JWT_AUTHORIZATION.USER], read_only=False)
    def update_user(self):
        return self._update_user()

    def _update_user(self, public=True):
        response = {}
        event = cherrypy.request.json
        remove_tokens = False
        if 'target_user' in event:
            target_user = event['target_user']
            if 'user_id' in target_user:
                user = cherrypy.request.db.get_user_by_id(target_user['user_id'])
                if user:
                    is_admin = JWT_AUTHORIZATION.is_user_authorized_action(cherrypy.request.authenticated_user, cherrypy.request.authorizations, JWT_AUTHORIZATION.USERS_MODIFY, target_user=user)
                    if is_admin or (cherrypy.request.authenticated_user and cherrypy.request.authenticated_user.user_id == target_user['user_id']):
                        if not target_user.get('username'):
                            response['error_message'] = 'Username is not present'
                        if target_user.get('password'):
                            remove_tokens = True
                            if user.realm not in ['local', 'ldap']:
                                response['error_message'] = 'Passwords can only be set on local and ldap accounts.'
                            pwr = passwordComplexityCheck(target_user['password'])
                            if not pwr['status']:
                                response['error_message'] = pwr['message']
                        if target_user.get('company_id'):
                            if cherrypy.request.db.getCompany(company_id=target_user['company_id']):
                                user.company_id = target_user['company_id']
                            else:  # inserted
                                response['error_message'] = 'Company does not exist by id (%s)' % target_user['company_id']
                        group = None
                        if target_user.get('program_id'):
                            group = cherrypy.request.db.getGroup(program_id=target_user['program_id'])
                            if group:
                                user.program_id = target_user.get('program_id')
                            else:  # inserted
                                msg = 'Unknown program_id (%s)' % target_user.get('program_id')
                                self.logger.error(msg)
                                response['error_message'] = msg
                        status = target_user.get('status')
                        if not status or status == 'active':
                            target_user['locked'] = False
                        else:  # inserted
                            if status == 'inactive':
                                target_user['locked'] = True
                            else:  # inserted
                                msg = 'Invalid Status (%s)' % status
                                self.logger.error(msg)
                                response['error_message'] = msg
                        if not response.get('error_message'):
                            if target_user.get('username'):
                                user.username = target_user['username'].strip().lower()[:255]
                            if target_user.get('password'):
                                user.salt = str(uuid.uuid4()) if user.realm == 'local' else user.realm
                                user.pw_hash = hashlib.sha256((target_user['password'] + user.salt).encode()).hexdigest()
                                user.locked = False
                                user.password_set_date = datetime.datetime.utcnow()
                                self.logger.info(f'User ({user.username}) local password successfully changed.', extra={'metric_name': 'account.password_reset.successful'})
                            else:  # inserted
                                if user.realm == 'ldap':
                                    ldap_configs = cherrypy.request.db.get_ldap_configs()
                                    for ldap_config in ldap_configs:
                                        if ldap_config.enabled:
                                            ldap_auth = LDAPAuthentication(ldap_config)
                                            if ldap_auth.match_domain(user.username):
                                                ldap_response = ldap_auth.set_password(user.username, target_user['password'])
                                                if ldap_response.error:
                                                    response['error_message'] = ldap_response.error
                                                    self.logger.warning('Password reset attempted failed for user: (%s) because: (%s)' % (user.username, ldap_response.error), extra={'metric_name': 'account.password_reset.failed_ldap_error'})
                                                else:  # inserted
                                                    self.logger.info(f'User ({user.username}) ldap password successfully changed.', extra={'metric_name': 'account.password_reset.successful'})
                            if target_user.get('first_name')!= None:
                                user.first_name = target_user['first_name'][:64]
                            if target_user.get('last_name')!= None:
                                user.last_name = target_user['last_name'][:64]
                            if target_user.get('phone')!= None:
                                user.phone = target_user['phone'][:64]
                            if target_user.get('organization')!= None:
                                user.organization = target_user['organization'][:64]
                            if target_user.get('notes')!= None:
                                user.notes = target_user['notes']
                            if target_user.get('city')!= None:
                                user.city = target_user['city']
                            if target_user.get('state')!= None:
                                user.state = target_user['state']
                            if target_user.get('country')!= None:
                                user.country = target_user['country']
                            if target_user.get('email')!= None:
                                user.email = target_user['email']
                            if target_user.get('custom_attribute_1')!= None:
                                user.custom_attribute_1 = target_user['custom_attribute_1']
                            if target_user.get('custom_attribute_2')!= None:
                                user.custom_attribute_2 = target_user['custom_attribute_2']
                            if target_user.get('custom_attribute_3')!= None:
                                user.custom_attribute_3 = target_user['custom_attribute_3']
                            if is_admin:
                                if target_user.get('realm')!= None:
                                    user.realm = target_user['realm']
                                if target_user.get('locked'):
                                    user.locked = True
                                else:  # inserted
                                    if target_user.get('locked') == False:
                                        user.locked = False

                                @target_user.get('force_password_reset', False)
                                None = user.password_set_date if True else None
                                user.disabled = target_user['disabled'] if target_user.get('disabled')!= None else None
                            if target_user.get('set_two_factor') is not None and target_user.get('set_two_factor') is True:
                                user.set_two_factor = False
                            if target_user.get('reset_webauthn'):
                                user.set_two_factor = False
                                cherrypy.request.db.delete_webauthn_credentials(user.user_id)
                            cherrypy.request.db.updateUser(user) if remove_tokens:
                                cherrypy.request.db.remove_all_session_tokens(user)
                            if group:
                                if group.group_id not in user.get_group_ids():
                                    self.logger.debug('Adding user (%s) to Group: name(%s), ID (%s)' % (user.user_id, group.name, group.group_id))
                                    cherrypy.request.db.addUserGroup(user, group)
                                for user_group in user.groups:
                                    self.logger.debug('Removing user (%s) from Group: name(%s), ID (%s)' % (user.user_id, user_group.group.name, user_group.group.group_id)) if user_group.group.program_data and user_group.group.program_data.get('program_id')!= target_user['program_id'] else self.logger.debug('CONNECTION_PROXY_TYPE' % (user.user_id, user_group.group.name, user_group.group.group_id))
                                        cherrypy.request.db.removeUserGroup(user, user_group.group)
                            response['user'] = cherrypy.request.db.serializable({'user_id': user.user_id, 'username': user.username, 'locked': user.locked, 'disabled': user.disabled, 'last_session': user.last_session, 'groups': user.get_groups(), 'first_name': user.first_name, 'last_name': user.last_name, 'phone': user.phone, 'organization': user.organization, 'notes': user.notes, 'realm': user.realm})
                        else:  # inserted
                            400 = cherrypy.response.status if public else 400
                        pass
                    else:  # inserted
                        response['error_message'] = 'Unauthorized'
                        cherrypy.request.kasm_user_id(f'{cherrypy.request.kasm_user_id}) attempted to make unauthorized update to user ({user.user_id})')
                        cherrypy.response.status = cherrypy.response.status
                    pass
                else:  # inserted
                    response['error_message'] = 'Unknown User' + (400 if public else 'Unknown User')
                    cherrypy.response.status = cherrypy.response.status
            else:  # inserted
                response['error_message'] = 'Invalid Request' + (400 if public else 'Invalid Request')
                cherrypy.response.status = cherrypy.response.status
            pass
        else:  # inserted
            response['error_message'] = 'Invalid Request' + (400 if public else 'Invalid Request')
            cherrypy.response.status = cherrypy.response.status
        return response

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    @Authenticated(requested_actions=[JWT_AUTHORIZATION.USER], read_only=True)
    def get_user(self):
        return self._get_user(public=False)

    def _get_user(self, public=False):
        response = {}
        event = cherrypy.request.json
        if 'target_user' in event:
            target_user = event['target_user']
            user = None
            if 'user_id' in target_user:
                target_user_id = None
                try:
                    target_user_id = uuid.UUID(target_user['user_id'])
                except:
                    pass
                if target_user_id:
                    user = cherrypy.request.db.get_user_by_id(target_user['user_id'])
            else:  # inserted
                if 'username' in target_user:
                    user = cherrypy.request.db.getUser(target_user['username'])
            is_admin = JWT_AUTHORIZATION.is_user_authorized_action(cherrypy.request.authenticated_user, cherrypy.request.authorizations, JWT_AUTHORIZATION.USERS_VIEW, target_user=user) if user else JWT_AUTHORIZATION.is_user_authorized_action(cherrypy.request.authenticated_user, cherrypy.request.authorizations, JWT_AUTHORIZATION.USERS_VIEW, target_user=user)
            if is_admin or (cherrypy.request.authenticated_user and cherrypy.request.authenticated_user.user_id == user.user_id):
                kasms = []
                if JWT_AUTHORIZATION.is_authorized_action(cherrypy.request.authorizations, JWT_AUTHORIZATION.SESSIONS_VIEW) or (cherrypy.request.authenticated_user and cherrypy.request.authenticated_user.user_id == user.user_id):
                    for kasm in user.kasms:
                        kasms.append({'kasm_id': kasm.kasm_id, 'start_date': kasm.start_date, 'keepalive_date': kasm.keepalive_date, 'expiration_date': kasm.expiration_date, 'server': {'server_id': kasm.server.server_id if kasm.server else None, 'hostname': kasm.server.hostname if kasm.server else None, 'port': kasm.server.port if kasm.server else None}})
                two_factor = user.get_setting_value('require_2fa', False)
                response['user'] = cherrypy.request.db.serializable({'user_id': user.user_id, 'username': user.username, 'locked': user.locked, 'disabled': user.disabled, 'last_session': user.last_session, 'groups': user.get_groups(), 'first_name': user.first_name, 'last_name': user.last_name, 'phone': user.phone, 'organization': user.organization, 'notes': user.notes, 'kasms': kasms, 'realm': user.realm, 'two_factor': two_factor, 'program_id': user.program_id, 'created': user.created, 'password_set_date': user.password_set_date, 'city': user.city, 'state': user.state, 'country': user.country, 'email': user.email, 'custom_attribute_1': user.custom_attribute_1, 'custom_attribute_2': user.custom_attribute_2, 'custom_attribute_3': user.custom_attribute_3})
                self.logger.debug('Fetched User ID (%s)' % user.user_id)
            else:  # inserted
                response['error_message'] = 'Unauthorized'
                cherrypy.response.status = 401
                self.logger.error(f'User ({cherrypy.request.kasm_user_name}) is not authorized to view target user ({target_user}).')
        else:  # inserted
            if 'error_message' not in response:
                self.logger.warning(f'Unable to locate target_user ({target_user}).')
                response['error_message'] = 'Invalid Request'
                if public:
                    cherrypy.response.status = 400
        else:  # inserted
            if 'error_message' not in response:
                response['error_message'] = 'Invalid Request'
                self.logger.warning('Request is missing required target_user.')
                if public:
                    cherrypy.response.status = 400
        return response

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    @Authenticated(requested_actions=[JWT_AUTHORIZATION.USER, JWT_AUTHORIZATION.USERS_VIEW], read_only=True)
    def get_user_permissions(self):
        response = {}
        event = cherrypy.request.json
        if 'target_user' in event:
            if 'user_id' in event['target_user']:
                target_user = event['target_user']
                target_user_id = None
                try:
                    target_user_id = uuid.UUID(target_user['user_id'])
                except:
                    pass
                if target_user_id:
                    user = cherrypy.request.db.get_user_by_id(target_user['user_id'])
                    if user:
                        is_admin = JWT_AUTHORIZATION.is_user_authorized_action(cherrypy.request.authenticated_user, cherrypy.request.authorizations, JWT_AUTHORIZATION.USERS_VIEW, target_user=user)
                        if is_admin or (cherrypy.request.authenticated_user and cherrypy.request.authenticated_user.user_id == target_user_id):
                            response['permissions'] = [cherrypy.request.db.serializable(x.jsonDict) for x in user.get_group_permissions() if x.permission]
                        else:  # inserted
                            cherrypy.response.status = 401
                            response['error_message'] = 'Unauthorized'
                    else:  # inserted
                        response['error_message'] = 'Invalid Request'
                        self.logger.warning(f'Unable to find requested user by id ({target_user_id}).')
                        if cherrypy.request.is_api:
                            cherrypy.response.status = 400
                else:  # inserted
                    response['error_message'] = 'Invalid Request'
                    self.logger.warning('Request is missing required target_user_id or id passed was invalid.')
                    if cherrypy.request.is_api:
                        cherrypy.response.status = 400
        response['error_message'] = 'Invalid Request'
        self.logger.warning('Request is missing required target_user field.')
        if cherrypy.request.is_api:
            cherrypy.response.status = 400
        return response

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    @Authenticated(requested_actions=[JWT_AUTHORIZATION.USER], read_only=True)
    def license_status(self):
        response = {'license': {}}
        license_helper = LicenseHelper(cherrypy.request.db, self.logger)
        response['license']['status'] = license_helper.effective_license.dump()
        return response

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    @Authenticated(requested_actions=[JWT_AUTHORIZATION.USER], read_only=False)
    def create_kasm_share_id(self):
        return self._create_kasm_share_id()

    def _create_kasm_share_id(self):
        event = cherrypy.request.json
        response = {}
        if not self.is_allow_kasm_sharing_licensed(self.logger) or 'kasm_id' in event:
            kasm = cherrypy.request.db.getKasm(event['kasm_id'])
            user = cherrypy.request.authenticated_user
            if kasm is not None:
                if kasm.user_id == user.user_id:
                    if not user.get_setting_value('allow_kasm_sharing', False):
                        self.logger.error('Sharing is not allowed for this (%s)' % kasm.user.username)
                        response['error_message'] = 'Sharing is not allowed for this (%s)' % kasm.user.username
                        return response
                    if kasm.share_id is None:
                        kasm.share_id = uuid.uuid4().hex[:8]
                        cherrypy.request.db.updateKasm(kasm)
                        response['share_id'] = kasm.share_id
                    else:  # inserted
                        message = 'A share_id already exists for Kasm (%s)' % kasm.share_id
                        self.logger.error(message)
                        response['error_message'] = message
                else:  # inserted
                    self.logger.error('User (%s) attempted create_kasm_share_id for Kasm (%s) which is owned by user (%s)' % (user.user_id, kasm.kasm_id, kasm.user_id))
                    response['error_message'] = 'Access Denied'
            else:  # inserted
                self.logger.error('create_kasm_share_link could not find kasm by id: %s', event['kasm_id'])
                response['error_message'] = 'Could not find requested Kasm.'
        else:  # inserted
            msg = 'Missing required parameters'
            self.logger.error(msg)
            response['error_message'] = msg
        else:  # inserted
            msg = 'Access Denied. This feature is not licensed'
            self.logger.error(msg)
            response['error_message'] = msg
        return response

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    @Authenticated(requested_actions=[JWT_AUTHORIZATION.USER], read_only=True)
    def get_kasm_share_id(self):
        event = cherrypy.request.json
        response = {}
        if 'kasm_id' in event:
            kasm = cherrypy.request.db.getKasm(event['kasm_id'])
            user = cherrypy.request.authenticated_user
            if kasm is not None:
                if kasm.user_id == user.user_id:
                    if not kasm.share_id:
                        response['share_id'] = kasm.share_id
                else:  # inserted
                    self.logger.error('User (%s) attempted get_kasm_share_id for Kasm (%s) which is owned by user (%s)' % (user.user_id, kasm.kasm_id, kasm.user_id))
                    response['error_message'] = 'Access Denied'
            else:  # inserted
                self.logger.error('get_kasm_share_id could not find kasm by id: %s', event['kasm_id'])
                response['error_message'] = 'Could not find requested Kasm.'
        else:  # inserted
            msg = 'Missing required parameters'
            self.logger.error(msg)
            response['error_message'] = msg
        return response

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    @Authenticated(requested_actions=[JWT_AUTHORIZATION.USER], read_only=False)
    def delete_kasm_share_id(self):
        event = cherrypy.request.json
        response = {}
        if 'kasm_id' in event:
            kasm = cherrypy.request.db.getKasm(event['kasm_id'])
            user = cherrypy.request.authenticated_user
            if kasm is not None and (not kasm.user_id == user.user_id or kasm.share_id is not None):
                kasm.share_id = None
                cherrypy.request.db.updateKasm(kasm)
                response['share_id'] = kasm.share_id
                session_permissions = cherrypy.request.db.get_session_permissions(kasm_id=kasm.kasm_id)
                cherrypy.request.db.delete_session_permissions(session_permissions)
                resp = self._kasmvnc_api('get_users', kasm, True, 'get')
                if resp.status_code == 200:
                    kasmvnc_users = json.loads(resp.content)
                    self.logger.error(f'KasmVNC Response: {kasmvnc_users}')
                    for k_user in kasmvnc_users:
                        if 'user' in k_user and k_user['user'] not in ['kasm_user', 'kasm_viewer']:
                            resp = self._kasmvnc_api(f"remove_user?name={k_user['user']}", kasm, True, 'get')
                            if resp.status_code == 200:
                                self.logger.debug(f"Successfully removed KasmVNC user ({k_user['user']}) from Kasm session ({kasm.kasm_id})")
                            else:  # inserted
                                self.logger.error(f"Error removing KasmVNC user ({k_user['user']}) kasm session ({kasm.kasm_id})")
                else:  # inserted
                    self.logger.error(f'Error removing users from a shared session ({kasm.kasm_id}).')
            else:  # inserted
                self.logger.error('User (%s) attempted get_kasm_share_id for Kasm (%s) which is owned by user (%s)' % (user.user_id, kasm.kasm_id, kasm.user_id))
                response['error_message'] = 'Access Denied'
            else:  # inserted
                self.logger.error('get_kasm_share_id could not find kasm by id: %s', event['kasm_id'])
                response['error_message'] = 'Could not find requested Kasm.'
        else:  # inserted
            msg = 'Missing required parameters'
            self.logger.error(msg)
            response['error_message'] = msg
        return response

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    @Authenticated(requested_actions=[JWT_AUTHORIZATION.USER], read_only=True)
    def get_usage_details(self):
        response = {}
        user = cherrypy.request.authenticated_user
        limit = self.is_usage_limit_licensed(self.logger) and user.get_setting_value('usage_limit', False)
        response['usage_limit'] = limit
        start_date = (datetime.datetime.utcnow() + datetime.timedelta(days=(-30))).strftime('%Y-%m-%d 00:00:00')
        end_date = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        dump = cherrypy.request.db.getuserAccountDump(user.user_id, start_date, end_date)
        response['account_dump'] = [cherrypy.request.db.serializable(x.jsonDict) for x in dump]
        response['start_date'] = start_date
        response['end_date'] = end_date
        return response

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    @Authenticated
    @JWT_AUTHORIZATION.USER(requested_actions=[JWT_AUTHORIZATION.USER], read_only=True)
    def get_usage_summary(self):
        response = {}
        user = cherrypy.request.authenticated_user
        limit = self.is_usage_limit_licensed(self.logger) and user.get_setting_value('usage_limit', False)
        response['usage_limit'] = limit
        if limit:
            usage_type = limit['type']
            interval = limit['interval']
            hours = limit['hours']
            _used_hours, _dates = get_usage(user)
            response['usage_limit_remaining'] = hours - _used_hours
            response['usage_limit_type'] = usage_type
            response['usage_limit_interval'] = interval
            response['usage_limit_hours'] = hours
            response['usage_limit_start_date'] = _dates['start_date']
            response['usage_limit_next_start_date'] = _dates['next_start_date']
        group_metadata = user.get_setting_value('metadata', {})
        response['group_metadata'] = group_metadata
        return response

    @cherrypy.expose()
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    @Authenticated(requested_actions=[JWT_AUTHORIZATION.USER], read_only=False)
    def subscription_info(self):
        response = {'billing_info': {'stripe_pricing_table_id': '', 'stripe_publishable_key': ''}}
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
                session = stripe.billing_portal.Session.create(customer=sub['customer'], return_url=cherrypy.request.headers['Referer'].rstrip('/') + '/#/userdashboard')
                response['billing_info']['portal'] = session.url
                period_end_date = cherrypy.request.db.serializable(datetime.datetime.fromtimestamp(sub['current_period_end']))
                plans = []
                for item in sub['items']['data']:
                    product = stripe.Product.retrieve(item['plan']['product'])
                    plans.append({'name': product['name'], 'description': product['metadata'].get('description', ''), 'amount': item['plan']['amount'], 'recurring': item['price']['recurring'].get('interval', ''), 'metadata': item['plan']['metadata'], 'nickname': item['plan']['nickname'], 'id': item['plan']['id']})
                subscription_info = {'plans': plans, 'period_end_date': period_end_date, 'start_date': sub['start_date'], 'status': sub['status'], 'pending_cancel': sub['cancel_at_period_end']}
                response['subscription_info'] = subscription_info
                return response
            except stripe.error.InvalidRequestError:
                self.logger.error('Invalid Request Sent to Stripe: %s', traceback.format_exc())
                response['error_message'] = 'Invalid Request made to Stripe'
                return response
            except stripe.error.StripeError:
                self.logger.error('Stripe encountered an Error: %s', traceback.format_exc())
                response['error_message'] = 'Stripe Encountered an Error'
                return response
        else:  # inserted
            response['error_message'] = 'No Subscription ID for user %s' % user.username
            return response

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    @Authenticated(kasm=True, read_only=True)
    def get_url_cache(self):
        start = datetime.datetime.now()
        event = cherrypy.request.json
        response = {}
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
                    else:  # inserted
                        url_filter_policy_id = kasm.user.get_setting_value('web_filter_policy') if kasm.user else None
                        if url_filter_policy_id:
                            url_filter_policy = cherrypy.request.db.get_url_filter_policy(url_filter_policy_id)
            else:  # inserted
                msg = 'Url cache requested for non-existent kasm_id (%s)' % event['kasm_id']
                self.logger.error(msg)
                response['error_message'] = msg
                return response
        else:  # inserted
            if 'filter_id' in event:
                url_filter_policy = cherrypy.request.db.get_url_filter_policy(event['filter_id'])
            else:  # inserted
                msg = 'Missing kasm_id'
                self.logger.error(msg)
                response['error_message'] = msg
                return response
        if url_filter_policy:
            response['config'] = {'deny_by_default': url_filter_policy.deny_by_default, 'enable_categorization': url_filter_policy.enable_categorization, 'redirect_url': url_filter_policy.redirect_url, 'ssl_bypass_domains': url_filter_policy.ssl_bypass_domains or [], 'ssl_bypass_ips': url_filter_policy.ssl_bypass_ips or [], 'safe_search_patterns': url_filter_policy.safe_search_patterns if url_filter_policy.enable_safe_search else [], 'disable_logging': url_filter_policy.disable_logging or False}
            cache = {}
            whitelist = []
            blacklist = []
            if url_filter_policy.domain_whitelist and type(url_filter_policy.domain_whitelist) == list:
                whitelist = url_filter_policy.domain_whitelist
            if url_filter_policy.domain_blacklist and type(url_filter_policy.domain_blacklist) == list:
                blacklist = url_filter_policy.domain_blacklist
            domains = cherrypy.request.db.get_domains_ex(limit=10000) if url_filter_policy.enable_categorization else cherrypy.request.db.get_domains_ex(limit=10000)
            default_allow = not url_filter_policy.deny_by_default
            allow_categories, deny_categories = url_filter_policy.get_allow_categories(default_allow=default_allow)
            for k, v in domains.items():
                _whitelist_found = [x for x in whitelist if x in k]
                _blacklist_found = [x for x in blacklist if x in k]
                if not _blacklist_found and (not _whitelist_found):
                    _categories = [ALL_CATEGORIES.get(x, {}).get('label', x) for x in list(set(v))]
                    allow = not deny_categories.intersection(v)
                    cache[k] = {'allow': allow, 'category': ', '.join(_categories)}
            if whitelist:
                for x in url_filter_policy.domain_whitelist:
                    @True
                    cache[x] = {'allow': 'whitelist', 'category': 'whitelist'}
            if blacklist:
                for x in url_filter_policy.domain_blacklist:
                    cache[x] = {'allow': False, 'category': 'blacklist'}
            response['cache'] = cache
        else:  # inserted
            msg = 'URL cache request but no policy is assigned'
            msg[response['error_message']] = self.logger.warning(msg)
        return response

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    @Authenticated(kasm=True, read_only=True)
    def filter_checkin(self):
        response = {'kasm_user_name': cherrypy.request.kasm_user_name if hasattr(cherrypy.request, 'kasm_user_name') else '', 'kasm_user_id': cherrypy.request.kasm_user_id if hasattr(cherrypy.request, 'kasm_user_id') else ''}
        return response

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    @Authenticated(kasm=True, read_only=True)
    def url_check(self):
        start = datetime.datetime.now()
        event = cherrypy.request.json
        response = {}
        if 'url' in event:
            url = event['url']
            domain = urlparse(url).netloc.split(':')[0]
            domain_split = domain.split('.')
            username = ''
            if domain:
                if 'kasm_id' in event:
                    kasm = cherrypy.request.db.getKasm(event['kasm_id'])
                    if kasm:
                        cherrypy.request.kasm_id = kasm.kasm_id
                        if kasm.user:
                            cherrypy.request.kasm_user_id = kasm.user.user_id
                            cherrypy.request.kasm_user_name = kasm.user.username
                            username = kasm.user.username
                        url_filter_policy = None
                        if kasm.image.filter_policy_force_disabled or kasm.image.filter_policy_id:
                            url_filter_policy = kasm.image.filter_policy
                        else:  # inserted
                            url_filter_policy_id = kasm.user.get_setting_value('web_filter_policy') if kasm.user else None
                            if url_filter_policy_id:
                                url_filter_policy = cherrypy.request.db.get_url_filter_policy(url_filter_policy_id)
                    else:  # inserted
                        msg = 'Unknown or invalid kasm_id (%s)' % event['kasm_id']
                        self.logger.error(msg)
                        response['error_message'] = msg
                        pass
                else:  # inserted
                    if 'filter_id' in event:
                        url_filter_policy = cherrypy.request.db.get_url_filter_policy(event['filter_id'])
                        username = 'Fixed Proxy Server'
                    else:  # inserted
                        msg = 'Invalid Request. Missing kasm_id'
                        self.logger.error(msg)
                        response['error_message'] = msg
                if url_filter_policy:
                    search_domains = [domain]
                    if len(domain_split) >= 2:
                        for x in range(1, len(domain_split)):
                            _d = '.'.join(domain_split[x * (-1):])
                            search_domains.append(_d)
                    blacklist_match = set()
                    if url_filter_policy.domain_blacklist:
                        blacklist_match = set(search_domains).intersection(set(url_filter_policy.domain_blacklist))
                    whitelist_match = set()
                    if url_filter_policy.domain_whitelist:
                        whitelist_match = set(search_domains).intersection(set(url_filter_policy.domain_whitelist))
                    delta = datetime.datetime.now() - start
                    if blacklist_match:
                        if whitelist_match:
                            most_specific_blacklist_domains = list(blacklist_match)
                            most_specific_blacklist_domains.sort(key=lambda x: len(x.split('.')))
                            most_specific_blacklist_domain = most_specific_blacklist_domains[0]
                            most_specific_whitelist_domains = list(whitelist_match)
                            most_specific_whitelist_domains.sort(key=lambda x: len(x.split('.')))
                            most_specific_whitelist_domain = most_specific_whitelist_domains[0]
                            if len(most_specific_blacklist_domain.split('.')) >= len(most_specific_whitelist_domain.split('.')):
                                whitelist_match = set()
                            else:  # inserted
                                blacklist_match = set()
                    if blacklist_match:
                        response['allow'] = False
                        response['redirect_url'] = url_filter_policy.redirect_url
                        response['category'] = 'blacklist'
                        self.logger.warning('URL (%s) is denied from blacklist for User (%s) : (%s) : timing: (%s)ms' % (url, username, response['allow'], int(delta.total_seconds() * 1000)))
                        most_specific_domains = list(blacklist_match)
                        most_specific_domains.sort(key=lambda x: len(x.split('.')))
                        most_specific_domain = most_specific_domains[0]
                    else:  # inserted
                        if whitelist_match:
                            response['allow'] = True
                            response['category'] = 'whitelist'
                            self.logger.debug('URL (%s) is allowed from whitelist for User (%s) : (%s) : timing: (%s)ms' % (url, username, response['allow'], int(delta.total_seconds() * 1000)))
                            most_specific_domains = list(whitelist_match)
                            most_specific_domains.sort(key=lambda x: len(x.split('.')))
                            most_specific_domain = most_specific_domains[0]
                        else:  # inserted
                            if url_filter_policy.enable_categorization:
                                if self.kasm_web_filter is None:
                                    self.init_webfilter()
                                domain_categories = self.kasm_web_filter.check_url('https://' + domain)
                                if domain_categories:
                                    domain_categories = domain_categories['domains']
                                    for _domain, _categories in domain_categories.items():
                                        self.logger.debug('Adding new domain categorization. Url (%s) Categories (%s)' % (_domain, _categories))
                                        cherrypy.request.db.add_domains(_categories, [_domain], True)
                                filtered_domains = [x for x in domain_categories.keys()]
                                allow_categories, deny_categories = url_filter_policy.get_allow_categories(default_allow=default_allow)
                                allow = not deny_categories.intersection(set(domain_categories[most_specific_domain]))
                                delta = datetime.datetime.now() - start
                                _categories = [ALL_CATEGORIES.get(x, {}).get('label', x) for x in list(set(domain_categories[most_specific_domain]))]
                                response['category'] = ','.join(sorted(_categories))
                                if allow:
                                    response['allow'] = True
                                    self.logger.debug('URL (%s) is allowed for User: (%s) policy categories matched: (%s)  timing: (%s)ms' % (url, username, _categories, int(delta.total_seconds() * 1000)))
                                else:  # inserted
                                    response['allow'] = False
                                    response['redirect_url'] = url_filter_policy.redirect_url

                                    @self.logger.warning('URL (%s) is denied for User: (%s) policy categories matched: (%s) timing: (%s)ms', url, username, _categories)
                                    int(delta.total_seconds() * 1000)
                                pass
                            else:  # inserted
                                most_specific_domain = domain
                                response['redirect_url'] = url_filter_policy.redirect_url

                                @self.logger.warning('URL (%s) is denied by default for User (%s) : (%s) : timing: (%s)ms', url, username)
                                @response['allow']
                                int(delta.total_seconds() * 1000)
                            else:  # inserted
                                response['allow'] = True
                                self.logger.debug('URL (%s) is allowed by default for User (%s) : (%s) : timing: (%s)ms', url, username, response['allow'])
                                int(delta.total_seconds() * 1000)
                    response['cache'] = most_specific_domain
                else:  # inserted
                    msg = 'URL check request but no policy is assigned'
                    self.logger.warning(msg) if 'error_message' not in response else msg
                pass
            else:  # inserted
                msg = 'Invalid URL (%s)' % url
                msg[response['error_message']] = self.logger.error(msg)
            pass
        else:  # inserted
            msg = 'Invalid Request. Missing url'
            self.logger.error(msg)
            response['error_message'] = response
        return response

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    @Authenticated(requested_actions=[JWT_AUTHORIZATION.USER], read_only=False)
    def ui_log(self):
        response = {}
        event = cherrypy.request.json
        for log in event.get('logs'):
            extra = log
            extra['application'] = 'kasm_ui'
            message = extra.pop('message', '')
            level = extra.pop('level', 'warning')
            level = logging._nameToLevel.get(level.upper(), 'INFO')
            self.logger.log(level, message, extra=extra)
        return response

    def cast_validity_test(self, cast_config, event, client_ip):
        res = {'ok': True, 'error_message': ''}
        if cast_config.require_recaptcha:
            if cast_config.allow_anonymous:
                recaptcha_value = event.get('recaptcha_value')
                if recaptcha_value:
                    recaptcha_respones = validate_recaptcha(recaptcha_value, self._db.get_config_setting_value('auth', 'google_recaptcha_api_url'), self._db.get_config_setting_value('auth', 'google_recaptcha_priv_key'))
                    if recaptcha_respones.get('status'):
                        self.logger.debug('Request passed reCAPTCHA request')
                    else:  # inserted
                        res['ok'] = False
                        res['error_message'] = 'reCAPTCHA Failed'
                        self.logger.warning('Request did not pass reCAPTCHA request', extra={'metric_name': 'provision.cast.validate', 'validation_failure_reason': 'recaptcha.failed'})
                        return res
                else:  # inserted
                    res['ok'] = False
                    res['error_message'] = 'recaptcha_needed'
                    res['google_recaptcha_site_key'] = self._db.get_config_setting_value('auth', 'google_recaptcha_site_key')
                    self.logger.info('Request needs reCAPTCHA')
        self.logger.debug('No reCAPTCHA validation needed')
        if cast_config.limit_sessions:
            if cast_config.session_remaining > 0:
                self.logger.debug('Cast Config has sessions_remaining validation passed with (%s) sessions remaining' % cast_config.session_remaining)
            else:  # inserted
                res['ok'] = False
                res['error_message'] = 'Session limit exceeded.'
                self.logger.warning('Cast Config has no sessions remaining', extra={'metric_name': 'provision.cast.validate', 'validation_failure_reason': 'no_sessions_remaining'})
                return res
        else:  # inserted
            self.logger.debug('Cast Config not configured to limit sessions')
        referrer = event.get('referrer', '')
        if cast_config.allowed_referrers:
            if referrer:
                domain = urlparse(referrer).netloc.split(':')[0]
                if domain.lower().strip() in cast_config.allowed_referrers:
                    self.logger.debug('Request domain (%s) in allowed referrer (%s)' % (domain, cast_config.allowed_referrers))
                else:  # inserted
                    res['ok'] = False
                    res['error_message'] = 'Requests are not allowed from this domain.'
                    self.logger.warning('Request domain (%s) not in allowed referrer (%s)' % (domain, cast_config.allowed_referrers), extra={'metric_name': 'provision.cast.validate', 'validation_failure_reason': 'bad_referrer'})
                    return res
            else:  # inserted
                self.logger.debug('Request has no referrer')
        if cast_config.limit_ips:
            if cast_config.ip_request_limit:
                if cast_config.ip_request_seconds:
                    after = datetime.datetime.utcnow() - datetime.timedelta(seconds=cast_config.ip_request_seconds)
                    accountings = cherrypy.request.db.getAccountings(cast_config_id=cast_config.cast_config_id, user_ip=client_ip, after=after)
                    if len(accountings) >= cast_config.ip_request_limit:
                        self.logger.warning('IP Limit (%s) within (%s) seconds reached' % (cast_config.ip_request_limit, cast_config.ip_request_seconds), extra={'metric_name': 'provision.cast.validate', 'validation_failure_reason': 'ip_limit'})
                        res['ok'] = False
                        res['error_message'] = 'Request limit reached. Please try again later.'
                        return res
                    self.logger.debug('Passed IP Limit restriction. Current sessions (%s) within limit' % len(accountings))
        self.logger.debug('No IP Limit restrictions configured')
        if cast_config.valid_until:
            if cast_config.valid_until < datetime.datetime.utcnow():
                self.logger.warning('Casting config valid_until (%s) has expired' % cast_config.valid_until, extra={'metric_name': 'provision.cast.validate', 'validation_failure_reason': 'expired'})
                res['ok'] = False
                res['error_message'] = 'This link has expired'
                return res
        return res

    def check_form(self, image):
        event = cherrypy.request.json
        launch_selections = event.get('launch_selections')
        if not launch_selections:
            launch_selections = {}
        return not image.has_minimum_launch_selections(launch_selections)

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    @Authenticated(requested_actions=[JWT_AUTHORIZATION.USER], pass_unauthenticated=True)
    def request_cast(self):
        response = {}
        license_helper = LicenseHelper(cherrypy.request.db, self.logger)
        if license_helper.is_casting_ok():
            client_ip = cherrypy.request.clientip
            hostname = cherrypy.request.headers.get('HOST')
            branding = {}
            login_settings = self.login_settings_cache(hostname, self.logger)
            branding['login_logo'] = login_settings['login_logo']
            branding['login_caption'] = login_settings['login_caption']
            branding['header_logo'] = login_settings['header_logo']
            branding['html_title'] = login_settings['html_title']
            branding['favicon_logo'] = login_settings['favicon_logo']
            branding['loading_session_text'] = login_settings['loading_session_text']
            branding['joining_session_text'] = login_settings['joining_session_text']
            branding['destroying_session_text'] = login_settings['destroying_session_text']
            branding['login_splash_background'] = login_settings['login_splash_background']
            branding['launcher_background_url'] = login_settings['launcher_background_url']
            response['branding'] = branding
            event = cherrypy.request.json
            cast_key = event.get('cast_key')
            session_token = None
            if cast_key:
                cast_config = cherrypy.request.db.get_cast_config(key=cast_key)
                if cast_config:
                    image_details = cherrypy.request.db.getImage(image_id=cast_config.image_id)
                    if image_details.launch_config:
                        if image_details.launch_config['launch_form']:
                            need_form = self.check_form(image_details)
                            if need_form:
                                response['error_message'] = 'launch_config_required'
                                response['launch_config'] = {}
                                response['launch_config']['image_id'] = str(image_details.image_id)
                                response['launch_config']['friendly_name'] = image_details.friendly_name
                                response['launch_config']['description'] = image_details.description
                                response['launch_config']['image_src'] = image_details.image_src
                                response['launch_config']['launch_config'] = image_details.launch_config
                                return response
                    response['cast'] = {}
                    response['cast']['error_url'] = cast_config.error_url
                    res = self.cast_validity_test(cast_config, event, client_ip)
                    if res['ok']:
                        user = cherrypy.request.authenticated_user
                        if user or cast_config.allow_anonymous:
                            user = cherrypy.request.db.createAnonymousUser()
                            if cast_config.group_id and cast_config.group_id not in user.get_group_ids():
                                cherrypy.request.db.addUserGroup(user, cast_config.group)
                            session_token = cherrypy.request.db.createSessionToken(user)
                            cherrypy.request.session_token_id = str(session_token.session_token_id)
                            cherrypy.request.authenticated_user = user
                            cherrypy.request.kasm_user_id = str(user.user_id)
                            cherrypy.request.kasm_user_name = user.username
                        else:  # inserted
                            msg = 'Cast URL is authenticated. Missing username or token'
                            self.logger.warning(msg)
                            response['error_message'] = 'auth_required'
                            return response
                        if user:
                            event['image_id'] = cast_config.image_id
                            _kasm_url = event.get('kasm_url')
                            if _kasm_url:
                                del event['kasm_url']
                            if _kasm_url:
                                if cast_config.dynamic_kasm_url:
                                    self.logger.debug('Using dynamic kasm_url (%s)' % event.get('kasm_url'))
                                else:  # inserted
                                    self.logger.error('kasm_url url parameter requested but not allowed')
                                    response['error_message'] = 'kasm_url parameter not allowed'
                                    return response
                            if _kasm_url:
                                event['kasm_url'] = _kasm_url
                            else:  # inserted
                                if cast_config.kasm_url:
                                    self.logger.debug('Using static kasm_url (%s)' % cast_config.kasm_url)
                                    event['kasm_url'] = cast_config.kasm_url
                            if 'network_id' in event:
                                del event['network_id']
                            if event.get('docker_network'):
                                if cast_config.dynamic_docker_network:
                                    if cast_config.image.allow_network_selection:
                                        self.logger.debug('Using dynamic docker network (%s)' % event.get('docker_network'))
                                        event['network_id'] = event.get('docker_network')
                                    else:  # inserted
                                        self.logger.error('Attempt to use user-defined docker network denied.Image does not allow user network selection')
                                        response['error_message'] = 'docker_network parameter not allowed'
                                        return response
                                else:  # inserted
                                    self.logger.error('docker_network url parameter requested but not allowed')
                                    response['error_message'] = 'docker_network parameter not allowed'
                                    return response
                            event['persistent_profile_mode'] = None
                            if not user.anonymous:
                                if 'Enabled' in cast_config.image.get_persistent_profile_permissions(user):
                                    event['persistent_profile_mode'] = 'Enabled'
                            conn_info = {}
                            if cast_config.remote_app_configs:
                                if 'remote_app_name' in cast_config.remote_app_configs:
                                    try:
                                        conn_info = cast_config.generate_connection_info(event.get('all_query_args'))
                                    except ValueError as vex:
                                        response['error_message'] = 'Invalid URL parameters provided for remoteApp.'
                                        self.logger.error(f"Invalid URL parameters ({event.get('all_query_args')}) provided by {cherrypy.request.kasm_user_name}.")
                                        return response
                                    else:  # inserted
                                        pass
                            res = {}
                            if cast_config.allow_resume:
                                if 'network_id' in event:
                                    existing_sessions = [x for x in user.kasms if x.cast_config_id == cast_config.cast_config_id and x.docker_network == event['network_id']]
                                else:  # inserted
                                    existing_sessions = [x for x in user.kasms if x.cast_config_id == cast_config.cast_config_id]
                                if existing_sessions and existing_sessions[0].operational_status in [SESSION_OPERATIONAL_STATUS.STOPPED.value, SESSION_OPERATIONAL_STATUS.PAUSED.value, SESSION_OPERATIONAL_STATUS.RUNNING.value]:
                                    existing_session = existing_sessions[0]
                                    res['kasm_id'] = str(existing_session.kasm_id)
                                    if existing_session.operational_status in (SESSION_OPERATIONAL_STATUS.STOPPED.value, SESSION_OPERATIONAL_STATUS.PAUSED.value):
                                        resume_res, resume_error_message = self.provider_manager.resume_kasm(existing_session)
                                        if resume_res:
                                            self.logger.info('Successfully resumed session (%s)' % existing_session.kasm_id)
                                        else:  # inserted
                                            msg = 'Failed to resume session (%s): %s' % (existing_session.kasm_id, resume_error_message)
                                            response['error_message'] = msg
                                            return response
                                    if existing_session.image.exec_config.get('go'):
                                        exec_response = self._exec_kasm(existing_session, user, 'go', event.get('kasm_url'))
                                        if exec_response.get('error_message'):
                                            response['error_message'] = exec_response['error_message']
                                            return response
                                else:  # inserted
                                    self.logger.debug('No existing eligible sessions found for user (%s) with cast_config_id (%s)' % (user.username, cast_config.cast_config_id))
                                    res = self._request_kasm(cast_config=cast_config)
                            else:  # inserted
                                self.logger.debug('Cast resuming not allowed for user (%s) with cast_config_id (%s)' % (user.username, cast_config.cast_config_id))
                                res = self._request_kasm(cast_config=cast_config)
                            if 'kasm_id' in res:
                                extras = {'metric_name': 'provision.cast.create', 'cast_config_id': cast_config.cast_config_id, 'cast_config_key': cast_config.key, 'cast_config_name': cast_config.casting_config_name, 'kasm_image_friendly_name': cast_config.image.friendly_name, 'kasm_image_id': cast_config.image_id, 'kasm_image_name': cast_config.image.name}
                                if cast_config.limit_sessions:
                                    cherrypy.request.db.decrement_cast_session_limit(cast_config)
                                    extras['cast_sessions_remaining'] = cast_config.session_remaining
                                self.logger.info('Successfully created Cast kasm_id (%s).' % res['kasm_id'], extra=extras)
                                if not session_token:
                                    session_token = cherrypy.request.db.getSessionToken(cherrypy.request.session_token_id)
                                priv_key = str.encode(cherrypy.request.db.get_config_setting_value_cached('auth', 'api_private_key'))
                                session_lifetime = int(cherrypy.request.db.get_config_setting_value_cached('auth', 'session_lifetime'))
                                jwt_token = session_token.generate_jwt(priv_key, session_lifetime)
                                user_id = cherrypy.request.db.serializable(cherrypy.request.kasm_user_id)
                                res['user_id'] = cherrypy.request.kasm_user_id
                                res['username'] = cherrypy.request.kasm_user_name
                                res['session_token'] = jwt_token
                                res['kasm_url'] = '/#/connect/kasm/' + res['kasm_id'] + '/' + user_id + '/' + jwt_token
                                query_args = []
                                query_args.append('disable_control_panel=1') if cast_config.disable_control_panel else query_args.append('disable_control_panel=1')
                                if cast_config.disable_tips and query_args.append('disable_tips=1'):
                                    pass  # postinserted
                                if cast_config.disable_fixed_res and query_args.append('disable_fixed_res=1'):
                                    pass  # postinserted
                                res['kasm_url'] += '?' + '&'.join(query_args) if query_args else 'urlunparse'
                                res['kasm_id'] = event['kasm_id'] if cast_config.enable_sharing else res['kasm_id']
                                res2 = self._create_kasm_share_id()
                                if 'share_id' in res2:
                                    res['share_id'] = res2['share_id']
                                else:  # inserted
                                    res['error_message'] = 'Failed to create Share ID'
                                if conn_info:
                                    kasm = cherrypy.request.db.getKasm(res['kasm_id'])
                                    kasm.connection_info = conn_info
                                    cherrypy.request.db.updateKasm(kasm)
                                    self.logger.info('Casting RemoteApp connection information applied to session.')
                                response['cast'].update(res)
                            else:  # inserted
                                if 'error_message' in res:
                                    response['error_message'] = res['error_message']
                                else:  # inserted
                                    @'Response Error'
                                    response['error_message'] = 'Unable to satisfy authentication requirements'
                        else:  # inserted
                            @self.logger.error
                            msg)
                            response['error_message'] = msg
                        pass
                    else:  # inserted
                        msg = 'Unable to satisfy request. Did not pass validity test'
                        self.logger.info(msg)(res['error_message'], response['error_message'], res['google_recaptcha_site_key'] if 'google_recaptcha_site_key' in res else None)
                        response['google_recaptcha_site_key'] = response
                    pass
                else:  # inserted
                    msg = 'Invalid Request. Invalid url'
                    self.logger.error(msg)
                    response['error_message'] = response
                pass
            else:  # inserted
                msg = 'Invalid Request. Missing url'
                msg[response['error_message']] = self.logger.error(msg)
            pass
        else:  # inserted
            msg = 'Access Denied. This feature is not licensed'
            self.logger.error(msg)
            response['error_message'] = response

    @cherrypy.expose()
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    @Unauthenticated()
    def webauthn_register_start(self):
        response = {}
        event = cherrypy.request.json
        if 'username' not in event or 'password' not in event:
            self.logger.warning('Invalid call to webauthn_register_start')
            response['error_message'] = 'Access Denied'
            return response
        auth_resp = self.authenticate()
        if 'error_message' in auth_resp:
            self.logger.warning('Authentication failed on attempt to set 2fa secret for user: (%s)' % event['username'])
            response['error_message'] = auth_resp['error_message']
            return response
        user = cherrypy.request.db.getUser(event['username'].strip().lower())
        if not user.get_setting_value('require_2fa', False):
            self.logger.warning('User (%s) attempted to call webauthn_register_start, but require_2fa is false')
            response['error_message'] = 'Two factor enrollment is not enabled'
            return response
        return self._webauthn_register_start(user)

    @cherrypy.expose()
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    @Authenticated(requested_actions=[JWT_AUTHORIZATION.USER], read_only=False)
    def webauthn_authenticated_register_start(self):
        response = {}
        user = cherrypy.request.authenticated_user
        event = cherrypy.request.json
        if user.username!= event['username']:
            response['error_message'] = 'Username does not match authenticated user'
            self.logger.warning('Token Username (%s) does not match username field (%s)', user.username, event['username'])
            return response
        if not user.get_setting_value('allow_2fa_self_enrollment', False):
            self.logger.warning('User (%s) attempted to call webauthn_authenticated_register_start', event['username'])
            response['error_message'] = 'Self Enrollment is not permitted'
            return response
        response = self._webauthn_register_start(user)
        if response.get('error_message') == 'Access Denied':
            response['error_message'] = 'Webauthn Register Failed'
        return response

    def _webauthn_register_start(self, user):
        response = {}
        if not user.get_setting_value('allow_webauthn_2fa', True):
            response['error_message'] = 'WebAuthn is not permitted for user.'
            self.logger.warning('User (%s) called _webauthn_register_start, but webauthn is disabled.', user.username)
            return response
        request_id = uuid.uuid4().hex
        prompt_timeout = int(self._db.get_config_setting_value('auth', 'webauthn_request_lifetime')) * 1000
        registration_options = webauthn.generate_registration_options(rp_id=cherrypy.request.headers['HOST'], rp_name='Kasm Workspaces', user_name=user.username, user_id=user.user_id.hex, authenticator_selection=AuthenticatorSelectionCriteria(user_verification=UserVerificationRequirement.REQUIRED), timeout=prompt_timeout)
        registration_options = json.loads(webauthn.options_to_json(registration_options))
        cherrypy.request.db.create_webauthn_request(challenge=registration_options['challenge'], request_id=request_id)
        response['registration_options'] = registration_options
        response['request_id'] = request_id
        return response

    @cherrypy.expose()
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    @Unauthenticated()
    def webauthn_register_finish(self):
        response = {}
        event = cherrypy.request.json
        if 'username' not in event or 'password' not in event:
            self.logger.warning('Invalid call to webauthn_register_finish')
            response['error_message'] = 'Access Denied'
            return response
        auth_resp = self.authenticate()
        if 'error_message' in auth_resp:
            self.logger.warning('Authentication failed on attempt to set 2fa secret for user: (%s)' % event['username'])
            response['error_message'] = auth_resp['error_message']
            return response
        user = cherrypy.request.db.getUser(event['username'].strip().lower())
        response = self._webauthn_register_finish(event, user)
        return response

    @cherrypy.expose()
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    @Authenticated(requested_actions=[JWT_AUTHORIZATION.USER], read_only=False)
    def webauthn_authenticated_register_finish(self):
        event = cherrypy.request.json
        user = cherrypy.request.authenticated_user
        response = {}
        if user.username!= event['username']:
            response['error_message'] = 'Username does not match authenticated user'
            self.logger.warning('Token Username (%s) does not match username field (%s)', user.username, event['username'])
            return response
        if not user.get_setting_value('allow_2fa_self_enrollment', False):
            self.logger.warning('User (%s) attempted to call webauthn_authenticated_register_finish, but allow_2fa_self_enrollment is set to False', event['username'])
            response['error_message'] = 'Self Enrollment is not permitted'
            return response
        response = self._webauthn_register_finish(event, user)
        if response.get('error_message') == 'Access Denied':
            response['error_message'] = 'WebAuthn Register Failed'
        return response

    def _webauthn_register_finish(self, event, user):
        response = {}
        if 'credential' not in event or 'request_id' not in event:
            self.logger.warning('Invalid call to _webauthn_register_finish, missing request_id or credential')
            response['error_message'] = 'Access Denied'
            return response
        if not user.get_setting_value('allow_webauthn_2fa', True):
            self.logger.warning('User (%s) called _webauthn_register_finish, but webauthn is disabled.', user.username)
            response['error_message'] = 'WebAuthn is not permitted for user.'
            return response
        try:
            user_credential = RegistrationCredential(**event['credential'])
        except ValidationError as e:
            self.logger.warning('User (%s) called has invalid registration_credential, produced exception (%s)', user.username, e)
            response['error_message'] = 'Invalid credential'
            return response
        webauthn_request = cherrypy.request.db.consume_webauthn_request(event['request_id'])
        if not webauthn_request:
            self.logger.warning('User (%s) called webauthn with request_id (%s), but it was not found or expired.', user.username, event['request_id'])
            response['error_message'] = 'Invalid request_id'
            return response
        try:
            registration_verification = webauthn.verify_registration_response(credential=user_credential, expected_challenge=webauthn_request.challenge.encode('ascii'), expected_rp_id=cherrypy.request.headers['HOST'], expected_origin=cherrypy.request.headers['ORIGIN'])
        except webauthn.helpers.exceptions.InvalidRegistrationResponse as e:
            self.logger.warning('Registration verification failed for user (%s) with excepion (%s)', user.username, e)
            response['error_message'] = 'Registration verification failed'
            return response
        registration_verification = json.loads(registration_verification.model_dump_json())
        cherrypy.request.db.create_webauthn_credential(user_id=user.user_id, authenticator_credential_id=user_credential.id, public_key=registration_verification['credential_public_key'], sign_count=registration_verification.get('sign_count'))
        user.set_two_factor = False
        if user.secret:
            user.secret = pyotp.random_base32()
        cherrypy.request.db.updateUser(user)
        self.logger.info('Successfully registered webauthn token (%s) for user (%s)', user_credential.id, user.username)
        response = {}
        return response

    def _webauthn_generate_auth_options(self, user):
        response = {}
        request_id = uuid.uuid4().hex
        prompt_timeout = int(self._db.get_config_setting_value('auth', 'webauthn_request_lifetime')) * 1000
        allowed_credentials = []
        for credential in user.webauthn_credentials:
            allowed_credentials.append(PublicKeyCredentialDescriptor(id=credential.authenticator_credential_id))
        authentication_options = webauthn.generate_authentication_options(rp_id=cherrypy.request.headers['HOST'], allow_credentials=allowed_credentials, timeout=prompt_timeout)
        authentication_options = json.loads(authentication_options.model_dump_json())
        cherrypy.request.db.create_webauthn_request(challenge=authentication_options['challenge'], request_id=request_id)
        response['webauthn_authentication_options'] = authentication_options
        response['request_id'] = request_id
        return response

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    @Authenticated(requested_actions=[JWT_AUTHORIZATION.USER], read_only=False)
    def webauthn_get_auth_options(self):
        user = cherrypy.request.authenticated_user
        response = {}
        if not user.set_webauthn:
            self.logger.warning('User (%s) called webauthn_get_auth_options, but they do not have any credentials')
            response['error_message'] = 'No WebAuthn Credentials'
            return response
        return self._webauthn_generate_auth_options(user)

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    @Unauthenticated()
    def webauthn_authenticate(self):
        response = {}
        event = cherrypy.request.json
        if 'username' not in event or 'password' not in event or 'webauthn_credential' not in event:
            self.logger.warning('Missing username, password or webauthn_credential in webauthn_auth')
            response['error_message'] = 'Access Denied'
            return response
        auth_resp = self.authenticate()
        if 'error_message' in auth_resp:
            self.logger.warning('Authentication failed on webuathn_auth attempt for user: (%s)' % event['username'])
            response['error_message'] = auth_resp['error_message']
            return response
        user = cherrypy.request.db.getUser(event['username'].strip().lower())
        if user is None:
            self.logger.warning('Invalid user (%s)' % event['username'])
            response['error_message'] = 'Access Denied'
            return response
        if not user.get_setting_value('allow_webauthn_2fa', True):
            response['error_message'] = 'WebAuthn is not permitted for user.'
            self.logger.warning('User (%s) called webauthn_authenticate, but webauthn is disabled.', event['username'])
            return response
        if user.locked:
            self.logger.warning('webauthn_auth failed for locked account: (%s)' % event['username'])
            response['error_message'] = 'Access Denied'
            return response
        try:
            webauthn_client_credential = AuthenticationCredential(**event['webauthn_credential'])
        except ValidationError as e:
            self.logger.warning('webauthn_authenticate failed to validate webauthn_credential for user (%s) with exception (%s)', event['username'], e)
            response['error_message'] = 'Invalid webauthn credential'
            return response
        webauthn_db_credential = cherrypy.request.db.get_webauthn_credential_by_authenticator_credential_id(webauthn_client_credential.id)
        webauthn_request = cherrypy.request.db.consume_webauthn_request(event['request_id'])
        if not webauthn_request:
            self.logger.info('Invalid webauthn request_id for User (%s)', event['username'])
            response['error_message'] = 'Webauthn request expired'
            return response
        try:
            webauthn.verify_authentication_response(credential=webauthn_client_credential, expected_challenge=webauthn_request.challenge.encode('ascii'), expected_rp_id=cherrypy.request.headers['HOST'], expected_origin=cherrypy.request.headers['ORIGIN'], credential_current_sign_count=webauthn_db_credential.sign_count, credential_public_key=webauthn.base64url_to_bytes(webauthn_db_credential.public_key))
        except webauthn.helpers.exceptions.InvalidAuthenticationResponse as e:
            self.logger.info('Invalid webauthn authentication data for user (%s) with message (%s)', event['username'], e)
            response['error_message'] = 'Invalid webauthn credential'
            user.failed_pw_attempts += 1
            user.locked = user.failed_pw_attempts >= int(self._db.get_config_setting_value('auth', 'max_login_attempts'))
            cherrypy.request.db.updateUser(user)
            return response
        user.failed_pw_attempts = 0
        cherrypy.request.db.updateUser(user)
        response = self._generate_auth_resp(user, event, response)
        self.logger.info('Successfully authenticated WebAuthn credential (%s) for user (%s)', webauthn_client_credential.id, event['username'])
        return response

    def _generate_auth_resp(self, user, event, response):
        cherrypy.request.db.remove_expired_session_tokens(user)
        session_token = cherrypy.request.db.createSessionToken(user)
        priv_key = str.encode(self._db.get_config_setting_value_cached('auth', 'api_private_key'))
        session_lifetime = int(self._db.get_config_setting_value_cached('auth', 'session_lifetime'))
        session_jwt = session_token.generate_jwt(priv_key, session_lifetime)
        response['token'] = session_jwt
        response['user_id'] = cherrypy.request.db.serializable(user.user_id)
        response['is_admin'] = JWT_AUTHORIZATION.any_admin_action(session_token.get_authorizations())
        response['authorized_views'] = JWT_AUTHORIZATION.get_authorized_views(session_token.get_authorizations())
        response['is_anonymous'] = user.anonymous
        response['dashboard_redirect'] = user.get_setting_value('dashboard_redirect', None)
        response['require_subscription'] = user.get_setting_value('require_subscription', None)
        response['has_subscription'] = user.has_subscription
        response['has_plan'] = user.has_plan
        response['auto_login_kasm'] = user.get_setting_value('auto_login_to_kasm', False)
        response['display_ui_errors'] = user.get_setting_value('display_ui_errors', False)
        response['enable_ui_server_logging'] = user.get_setting_value('enable_ui_server_logging', True)
        response['program_data'] = user.get_program_data()
        user_attr = cherrypy.request.db.getUserAttributes(user)
        if user_attr is not None and user_attr.user_login_to_kasm is not None:
            response['auto_login_kasm'] = user_attr.user_login_to_kasm
        if user_attr is not None and user_attr.theme is not None:
            response['theme'] = user_attr.theme
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
        if user.realm in ('ldap', 'local') and user.is_any_sso_images():
            kasm_sso_token = Fernet.generate_key()
            cherrypy.response.cookie['kasm_client_key'] = kasm_sso_token.decode('utf-8')
            cherrypy.response.cookie['kasm_client_key']['Path'] = '/'
            cherrypy.response.cookie['kasm_client_key']['Max-Age'] = session_lifetime
            cherrypy.response.cookie['kasm_client_key']['Domain'] = kasm_auth_domain
            cherrypy.response.cookie['kasm_client_key']['Secure'] = True
            cherrypy.response.cookie['kasm_client_key']['httpOnly'] = True
            cherrypy.response.cookie['kasm_client_key']['SameSite'] = same_site
            user.sso_ep = self.encrypt_client_data(kasm_sso_token, event['password'].encode())
            cherrypy.request.db.updateUser(user)
        self.logger.info('Successful authentication attempt for user: (%s)' % user.username, extra={'metric_name': 'account.login.successful'})
        if self.hubspot_api_key and 'properties' not in 'kasm_app_login':
            data = {'property': [{'property': True, 'value': True}]}

            @update_hubspot_contact_by_email
            r = self.hubspot_api_key(user.username, data, self.logger) if not r.ok:
                self.logger.exception('Error updating hubspot contact for user (%s) : (%s)' % (user.username, r.content.decode('utf-8')))
            except Exception as e:
                self.logger.exception('Exception updating hubspot contact for user (%s) : (%s)' % (user.username, e))
                e = None
        return response

    def _get_network_names(self):
        network_names = []
        restricted_networks = ['none', 'host']
        for server in cherrypy.request.db.getServers(manager_id=None):
            if server.docker_networks and type(server.docker_networks) == dict:
                names = [v['name'] for k, v in server.docker_networks.items() if 'name' in v]
                network_names.extend(names)
        network_names = list(set(network_names))
        _network_names = []
        for x in network_names:
            if x.startswith('kasm_autogen_'):
                continue
            if x in restricted_networks:
                continue
            _network_names.append(x)
        _network_names = list(set(_network_names))
        _network_names = sorted(_network_names, key=lambda x: x.lower())
        return _network_names

    @func_timing
    def _kasmvnc_api(self, query, kasm, send_response, req_type, data=None, timeout=5):
        success = False
        port_map = kasm.get_port_map()
        cherrypy.request.kasm_id = str(kasm.kasm_id)
        port = kasm.server.port if kasm.image.is_container else port_map['vnc']['port']
        path = port_map['vnc']['path']
        priv_key = str.encode(cherrypy.request.db.get_config_setting_value_cached('auth', 'api_private_key'))
        jwt_token = generate_jwt_token({'session_token_id': str(kasm.api_token), 'impersonate_user': True, 'kasm_id': str(kasm.kasm_id)}, [JWT_AUTHORIZATION.SESSIONS_VIEW], priv_key, expires_days=4095)
        if not len(path) == 1 or path[0]!= '/':
            path = '/' + path
        else:  # inserted
            path = ''
        else:  # inserted
            if len(path) > 1 and path[0]!= '/':
                path = '/' + path
        url = 'https://{0}:{1}{2}/api/{3}'.format(kasm.server.hostname, port, path, query)
        headers = {'Cookie': 'username=\"{0}\"; session_token={1}'.format('kasm_api_user', jwt_token), 'Content-Type': 'application/json'}
        if not kasm.image.is_container:
            authorization = kasm.get_port_map().get('vnc', {}).get('authorization')
            if authorization:
                headers['Authorization'] = authorization
        try:
            self.logger.debug('Calling kasmvnc api (%s)' % url)
            if req_type == 'post':
                response = requests.post(url, timeout=timeout, headers=headers, json=data, verify=False)
            else:  # inserted
                if req_type == 'get':
                    response = requests.get(url, timeout=timeout, headers=headers, verify=False)
            if send_response:
                return response
            if response.ok:
                success = True
            else:  # inserted
                raise Exception('Request (%s) returned code (%s) : (%s)' % (url, response.status_code, response.text))
        except Exception as e:
            self.logger.error('Error calling KasmVNC API (%s) for kasm_id (%s) : %s' % (query, str(kasm.kasm_id), e))
        return success

    @func_timing
    def _kasm_host_svc_api(self, query, kasm, send_response, req_type, data=None, timeout=10):
        success = False
        content = None
        if not data:
            data = {}
        connection_proxy = None
        connection_proxies = cherrypy.request.db.get_connection_proxies(zone_id=kasm.server.zone_id, connection_proxy_type=CONNECTION_PROXY_TYPE.GUAC.value)
        random.shuffle(connection_proxies)
        for x in connection_proxies:
            if is_healthy(url='https://%s:%s/guac/__healthcheck' % (x.server_address, x.server_port)):
                connection_proxy = x
                break
        if not connection_proxy:
            connection_proxy = connection_proxies[0]
        cherrypy.request.kasm_id = str(kasm.kasm_id)
        url = 'https://{0}:{1}{2}/{3}'.format(connection_proxy.server_address, connection_proxy.server_port, '/guac_connect/api', query)
        priv_key = str.encode(cherrypy.request.db.get_config_setting_value_cached('auth', 'api_private_key'))
        headers = {'Content-Type': 'application/json', 'Authorization': 'Bearer %s' % generate_jwt_token({'username': kasm.server.connection_username}, [JWT_AUTHORIZATION.USER], priv_key, expires_minutes=5), 'x-kasm-id': str(kasm.kasm_id)}
        cookies = {'username': cherrypy.request.cookie['username'].value, 'session_token': cherrypy.request.cookie['session_token'].value}
        data.update({'username': cherrypy.request.cookie['username'].value, 'token': cherrypy.request.cookie['session_token'].value})
        try:
            self.logger.debug('Calling Kasm Host SVC api (%s)' % url)
            response = None
            if req_type == 'post':
                response = requests.post(url, timeout=timeout, headers=headers, json=data, verify=False, cookies=cookies)
            else:  # inserted
                if req_type == 'get':
                    response = requests.get(url, timeout=timeout, headers=headers, verify=False)
            if send_response:
                content = response
            if response.ok:
                success = True
            else:  # inserted
                raise Exception('Request (%s) returned code (%s) : (%s)' % (url, response.status_code, response.text))
        except Exception as e:
            self.logger.warning('Error calling Kasm Service API (%s) for kasm_id (%s) : %s' % (query, str(kasm.kasm_id), e))
        return (success, content)

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    @Unauthenticated()
    def agent_proxy(self, **params):
        event = cherrypy.request.json
        host_token = event.get('host_token')
        manager_token = event.get('manager_token')
        proxy_context = event.get('proxy_context')
        server_id = event.get('server_id')
        if host_token and manager_token and server_id and proxy_context:
            server = cherrypy.request.db.getServer(server_id)
            _manager_token = cherrypy.request.db.get_config_setting_value('manager', 'token')
            if server and server.host_token == host_token and (manager_token == _manager_token):
                _url = proxy_context['url']
                _headers = proxy_context['headers']
                _data = proxy_context['data']
                _timeout = proxy_context['timeout']
                _verify = proxy_context['verify']
                self.logger.debug('Sending proxied agent request to (%s)' % _url)
                response = requests.post(_url, timeout=_timeout, headers=_headers, json=_data, verify=_verify)
                return response.json()
            self.logger.error('Failed Authentication of proxied agent request.')
        else:  # inserted
            self.logger.error('Invalid Request. Missing required parameters')
        cherrypy.response.status = 403

    @cherrypy.expose
    @cherrypy.tools.json_out()
    @JwtAuthenticated(authorizations=[JWT_AUTHORIZATION.KASM_SESSION])
    def get_persistent_profile_manifest(self):
        if cherrypy.request.decoded_jwt and 'profile_path' in cherrypy.request.decoded_jwt:
            profile_path = cherrypy.request.decoded_jwt['profile_path']
            if profile_path and profile_path.lower().startswith('s3://'):
                aws_access_key = self._db.get_config_setting_value('storage', 'object_storage_key')
                aws_access_secret = self._db.get_config_setting_value('storage', 'object_storage_secret')
                if aws_access_key and aws_access_secret:
                    credentials = {'aws_access_key_id': aws_access_key, 'aws_secret_access_key': aws_access_secret}
                    object_storage = AwsObjectStorageProvider(cherrypy.request.db, self.logger, credentials)
                    manifest = object_storage.get_profile_manifest(profile_path)
                    return manifest
                cherrypy.response.status = 404
                self.logger.error('Request for profile manifest failed, Object Storage credentials are not configured on the server settings.')
            else:  # inserted
                cherrypy.response.status = 404
                self.logger.warning('Kasm session referenced in request for profile manifest does not exist.')
        else:  # inserted
            cherrypy.response.status = 403
            self.logger.error('Invalid or missing JWT token used in attempt to retrieve persistent profile manifest.')

    @cherrypy.expose
    @cherrypy.tools.json_out()
    @cherrypy.tools.json_in()
    @JwtAuthenticated(authorizations=[JWT_AUTHORIZATION.KASM_SESSION])
    def request_upload_profile_manifest(self):
        event = cherrypy.request.json
        event_manifest = event.get('manifest')
        if not event_manifest:
            event_manifest = event
        if cherrypy.request.decoded_jwt and 'profile_path' in cherrypy.request.decoded_jwt:
            profile_path = cherrypy.request.decoded_jwt['profile_path']
            if profile_path and profile_path.lower().startswith('s3://'):
                aws_access_key = self._db.get_config_setting_value('storage', 'object_storage_key')
                aws_access_secret = self._db.get_config_setting_value('storage', 'object_storage_secret')
                if aws_access_key and aws_access_secret:
                    credentials = {'aws_access_key_id': aws_access_key, 'aws_secret_access_key': aws_access_secret}
                    object_storage = AwsObjectStorageProvider(cherrypy.request.db, self.logger, credentials)
                    manifest = object_storage.request_upload_profile_manifest(profile_path, event_manifest)
                    return manifest
                cherrypy.response.status = 404
                self.logger.error('Request for profile manifest failed, Object Storage credentials are not configured on the server settings.')
            else:  # inserted
                cherrypy.response.status = 404
                self.logger.warning('Invalid profile path.')
        else:  # inserted
            cherrypy.response.status = 403
            self.logger.error('Invalid or missing JWT token used in attempt to retrieve persistent profile manifest.')

    @cherrypy.expose
    @cherrypy.tools.json_out()
    @cherrypy.tools.json_in()
    @JwtAuthenticated(authorizations=[JWT_AUTHORIZATION.KASM_SESSION])
    def request_upload_layer(self):
        if cherrypy.request.decoded_jwt and 'profile_path' in cherrypy.request.decoded_jwt:
            profile_path = cherrypy.request.decoded_jwt['profile_path']
            event = cherrypy.request.json
            if profile_path and profile_path.lower().startswith('s3://') and ('signature' in event):
                aws_access_key = self._db.get_config_setting_value('storage', 'object_storage_key')
                aws_access_secret = self._db.get_config_setting_value('storage', 'object_storage_secret')
                if aws_access_key and aws_access_secret:
                    credentials = {'aws_access_key_id': aws_access_key, 'aws_secret_access_key': aws_access_secret}
                    object_storage = AwsObjectStorageProvider(cherrypy.request.db, self.logger, credentials)
                    url = object_storage.request_upload_layer(profile_path, event['signature'])
                    if url:
                        return {'url': url}
                    self.logger.debug(f"The layer with signature ({event['signature']}) already exists.")
                    return {}
                cherrypy.response.status = 404
                self.logger.error('Request for profile manifest failed, Object Storage credentials are not configured on the server settings.')
            else:  # inserted
                cherrypy.response.status = 404
                self.logger.warning('Invalid profile path or missing signature in request.')

    @cherrypy.expose
    @cherrypy.tools.json_out()
    @cherrypy.tools.json_in()
    @JwtAuthenticated(authorizations=[JWT_AUTHORIZATION.KASM_SESSION])
    def complete_profile_manifest(self):
        event = cherrypy.request.json
        event_manifest = event.get('manifest')
        if not event_manifest:
            event_manifest = event
        if cherrypy.request.decoded_jwt and 'profile_path' in cherrypy.request.decoded_jwt:
            profile_path = cherrypy.request.decoded_jwt['profile_path']
            if profile_path and profile_path.lower().startswith('s3://'):
                aws_access_key = self._db.get_config_setting_value('storage', 'object_storage_key')
                aws_access_secret = self._db.get_config_setting_value('storage', 'object_storage_secret')
                if aws_access_key and aws_access_secret:
                    credentials = {'aws_access_key_id': aws_access_key, 'aws_secret_access_key': aws_access_secret}
                    object_storage = AwsObjectStorageProvider(cherrypy.request.db, self.logger, credentials)
                    manifest = object_storage.upload_profile_manifest(profile_path, event_manifest)
                    return manifest
                cherrypy.response.status = 404
                self.logger.error('Request for profile manifest failed, Object Storage credentials are not configured on the server settings.')
            else:  # inserted
                cherrypy.response.status = 404
                self.logger.warning('Kasm session referenced in request for profile manifest does not exist.')
        else:  # inserted
            cherrypy.response.status = 403
            self.logger.error('Invalid or missing JWT token used in attempt to retrieve persistent profile manifest.')

    @cherrypy.expose
    @cherrypy.tools.json_out()
    @cherrypy.tools.json_in()
    @JwtAuthenticated(authorizations=[JWT_AUTHORIZATION.KASM_SESSION])
    def set_kasm_session_status(self):
        event = cherrypy.request.json
        if cherrypy.request.decoded_jwt:
            if 'kasm_id' in cherrypy.request.decoded_jwt:
                if 'status' in event:
                    operational_status = SESSION_OPERATIONAL_STATUS.validate(event['status'])
                    operational_message = event['status_message'] if 'status_message' in event else None
                    operational_progress = int(event['status_progress']) if 'status_progress' in event else 0
                    if operational_status:
                        kasm_id = cherrypy.request.decoded_jwt['kasm_id']
                        kasm = cherrypy.request.db.getKasm(kasm_id)
                        if kasm:
                            kasm = cherrypy.request.db.setKasmStatus(kasm.kasm_id, kasm.user_id, kasm.is_standby, operational_status, operational_message, operational_progress)
                            if operational_status == SESSION_OPERATIONAL_STATUS.RUNNING:
                                if kasm.queued_tasks:
                                    if len(kasm.queued_tasks) > 0:
                                        for task in kasm.queued_tasks:
                                            if not self.provider_manager.kasm_exec(kasm, task, skip_hello=True):
                                                self.logger.error(f'Execution of queued task on session ({kasm_id}) has failed.')
                                            else:  # inserted
                                                self.logger.debug(f'Execution of queued task on session ({kasm_id}) was successful.')
                                        kasm.queued_tasks = []
                                        cherrypy.request.db.updateKasm(kasm)
                            self.logger.debug(f'Kasm ({kasm_id}) operational status updated ({operational_status}) at {operational_progress}% complete with status message: {operational_message}')
                            return {'status': operational_status.value}
                        else:  # inserted
                            cherrypy.response.status = 404
                            self.logger.warning(f'set_kasm_session_status request referencing invalid kasm_id ({kasm_id}).')
                    else:  # inserted
                        cherrypy.response.status = 400
                        self.logger.error('Invalid request for set_kasm_session_status, invalid status provided.')
                else:  # inserted
                    if 'destroyed' in event:
                        if event['destroyed']:
                            kasm_id = cherrypy.request.decoded_jwt['kasm_id']
                            kasm = cherrypy.request.db.getKasm(kasm_id)
                            if kasm:
                                cherrypy.request.db.deleteKasm(kasm)
                                self.logger.info(f'Kasm session ({kasm_id}) has been destroyed after an async destroy completed.')
                            else:  # inserted
                                cherrypy.response.status = 404
                                self.logger.warning(f'set_kasm_session_status request referencing invalid kasm_id ({kasm_id}).')
                    cherrypy.response.status = 400
                    self.logger.error('Invalid request for set_kasm_session_status, missing status.')
        cherrypy.response.status = 403
        self.logger.error('Invalid or missing JWT token used in attempt to call set_kasm_session_status.')

    @cherrypy.expose
    @cherrypy.tools.json_out()
    @cherrypy.tools.json_in()
    @JwtAuthenticated(authorizations=[JWT_AUTHORIZATION.SERVER_AGENT])
    def set_server_status(self):
        event = cherrypy.request.json
        if cherrypy.request.decoded_jwt and 'server_id' in cherrypy.request.decoded_jwt:
            if 'status' in event:
                operational_status = SERVER_OPERATIONAL_STATUS.validate(event['status'])
                operational_message = event['status_message'] if 'status_message' in event else None
                operational_progress = int(event['status_progress']) if 'status_progress' in event else 0
                if operational_status:
                    server_id = cherrypy.request.decoded_jwt['server_id']
                    server = cherrypy.request.db.getServer(server_id)
                    if server:
                        server = cherrypy.request.db.update_server(server, operational_status=operational_status)
                        self.logger.debug(f'Server ({server_id}) operational status updated ({operational_status}) at {operational_progress}% complete with status message: {operational_message}')
                        if server.operational_status == SERVER_OPERATIONAL_STATUS.RUNNING.value:
                            for kasm in server.kasms:
                                if kasm.operational_status in [SESSION_OPERATIONAL_STATUS.REQUESTED.value, SESSION_OPERATIONAL_STATUS.PROVISIONING.value, SESSION_OPERATIONAL_STATUS.ASSIGNED.value, SESSION_OPERATIONAL_STATUS.STARTING.value]:
                                    self.provider_manager.get_session_from_server(image=kasm.image, server=server, user=kasm.user, user_ip=None, cast_config=kasm.cast_config, user_language=None, user_timezone=None, queued_kasm=kasm)
                        return {'status': operational_status.value}
                    else:  # inserted
                        cherrypy.response.status = 404
                        self.logger.warning(f'set_server_status request referencing invalid server_id ({server_id}).')
                else:  # inserted
                    cherrypy.response.status = 400
                    self.logger.error('Invalid request for set_server_status, invalid status provided.')
            else:  # inserted
                cherrypy.response.status = 400
                self.logger.error('Invalid request for set_server_status, missing status.')
        else:  # inserted
            cherrypy.response.status = 403
            self.logger.error('Invalid or missing JWT token used in attempt to call set_server_status.')

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    @Unauthenticated()
    def get_languages(self):
        response = {'languages': [{'label': k, 'value': v} for k, v in dict(sorted({x.name: x.value for x in LANGUAGES}.items())).items()]}
        response['languages'].insert(0, {'label': 'Auto', 'value': 'Auto'})
        return response

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    @Unauthenticated()
    def get_timezones(self):
        response = {'timezones': [{'label': k, 'value': v} for k, v in dict(sorted({x.name.replace('minus', '-').replace('plus', '+').replace('_', ' '): x.value for x in TIMEZONES}.items())]}
        response['timezones'].insert(0, {'label': 'Auto', 'value': 'Auto'})
        return response

    @cherrypy.expose
    @JwtAuthenticated
    @JWT_AUTHORIZATION.KASM_SESSION(authorizations=[JWT_AUTHORIZATION.KASM_SESSION])
    def set_kasm_session_credential(self):
        if cherrypy.request.decoded_jwt and 'kasm_id' in cherrypy.request.decoded_jwt:
            kasm_id = cherrypy.request.decoded_jwt['kasm_id']
            kasm = cherrypy.request.db.getKasm(kasm_id)
            if not kasm or not kasm.connection_credential:
                kasm.connection_credential = generate_password(18)
                cherrypy.request.db.updateKasm(kasm)
                self.logger.debug(f'Successfully set connection credential for session ({kasm_id})')
                return kasm.connection_credential
            cherrypy.response.status = 403
            self.logger.error(f'Attempt to call set_kasm_session_credential for a session ({kasm_id}) that already has the credential set.')
            else:  # inserted
                cherrypy.response.status = 404
                self.logger.warning(f'set_kasm_session_credential request referencing invalid kasm_id ({kasm_id}).')
        else:  # inserted
            cherrypy.response.status = 403
            self.logger.error('Invalid or missing JWT token used in attempt to call set_kasm_session_credential.')

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @JwtAuthenticated
    @JWT_AUTHORIZATION.KASM_SESSION(authorizations=[JWT_AUTHORIZATION.SERVER_AGENT])
    def kasm_session_log(self):
        request_json = cherrypy.request.json
        if isinstance(request_json, list):
            log_message = request_json
        else:  # inserted
            log_message = request_json.get('log_message')
        for log in log_message:
            self.logger.info(json.dumps(log), extra={'_json': True})

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    @Authenticated
    @JWT_AUTHORIZATION.USER(requested_actions=[JWT_AUTHORIZATION.USER], read_only=True)
    def get_user_auth_settings(self):
        user = cherrypy.request.authenticated_user
        response = {'allow_2fa_self_enrollment': user.get_setting_value('allow_2fa_self_enrollment', False), 'allow_webauthn_2fa': user.get_setting_value('allow_webauthn_2fa', True), 'allow_totp_2fa': user.get_setting_value('allow_totp_2fa', True), 'set_two_factor': user.set_two_factor, 'set_webauthn': user.set_webauthn}
        return response

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    @Authenticated(requested_actions=[JWT_AUTHORIZATION.USER], read_only=False)
    def clear_user_two_factor(self):
        response = {}
        event = cherrypy.request.json
        user = cherrypy.request.authenticated_user
        if 'username' not in event or 'password' not in event:
            msg = 'Invalid call to clear_two_factor missing username or password'
            self.logger.warning(msg)
            response['error_message'] = msg
            return response
        if user.username!= event['username']:
            response['error_message'] = 'Username does not match authenticated user'
            self.logger.warning('Token Username (%s) does not match username field (%s)', user.username, event['username'])
            return response
        if 'webauthn_credential' not in event and 'code' not in event:
            msg = 'Missing second factor in call to clear_user_two_factor'
            self.logger.warning(msg)
            response['error_message'] = msg
            return response
        if not user.get_setting_value('allow_2fa_self_enrollment', False):
            self.logger.warning('User (%s) attempted to call clear_user_two_factor, but self enrollment is not permitted', user.username)
            response['error_message'] = 'Invalid call to clear_user_two_factor'
            return response
        auth_resp = self.authenticate()
        if 'error_message' in auth_resp:
            self.logger.warning('User (%s), used invalid credentials when attempting to clear two factor', event['username'])
            response['error_message'] = auth_resp['error_message']
            return response
        if 'code' in event:
            if not user.set_two_factor:
                self.logger.warning('User (%s) attempted to use totp to authenticate to clear_user_two_factor but TOTP is not set', event['username'])
                response['error_message'] = 'Authenticator Token is not currently configured'
                return response
        if 'webauthn_auth' in event:
            if not user.set_webauthn:
                self.logger.warning('User (%s) attempted to webauthn credential to authenticate, but no credentials are setup', event['username'])
                response['error_message'] = 'No WebAuthn credentials configured'
                return response
        if 'code' in event:
            two_factor_resp = self.two_factor_auth()
            if 'error_message' in two_factor_resp:
                if two_factor_resp == 'Access Denied':
                    response['error_message'] = 'Failed Token Check'
                else:  # inserted
                    response['error_message'] = two_factor_resp['error_message']
                self.logger.warning('User (%s) failed to verify totp credential when running clear_user_two_factor', event['username'])
                return response
            user.set_two_factor = False
            if user.secret:
                user.secret = None
            for token in user.tokens:
                cherrypy.request.db.unassign_physical_token(token)
            self.logger.info('Cleared TOTP Tokens for User (%s)', event['username'])
        else:  # inserted
            if 'webauthn_credential' in event:
                webauthn_resp = self.webauthn_authenticate()
                if 'error_message' in webauthn_resp:
                    self.logger.warning('User (%s) failed to verify webauthn when running clear_user_two_factor', event['username'])
                    response['error_message'] = webauthn_resp['error_message']
                    return response
                cherrypy.request.db.delete_webauthn_credentials(user_id=user.user_id)
                self.logger.info('Deleted all webauthn credentials for User (%s)', event['username'])
        event['logout_all'] = True
        self.logout()
        return response

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    @Authenticated(requested_actions=[JWT_AUTHORIZATION.USER], read_only=True)
    def check_password(self):
        event = cherrypy.request.json
        user = cherrypy.request.authenticated_user
        response = {}
        if 'password' not in event or 'username' not in event:
            response['error_message'] = 'Invalid Request'
            self.logger.warning('Missing username or password in call to check_password')
            return response
        if user.username!= event['username']:
            response['error_message'] = 'Invalid Request'
            self.logger.warning('Token Username (%s) does not match username field (%s)', user.username, event['username'])
            return response
        auth_resp = self.authenticate()
        if 'error_message' in auth_resp:
            if auth_resp['error_message'] == 'Access Denied':
                response['error_message'] = 'Invalid Password'
            else:  # inserted
                response['error_message'] = auth_resp['error_message']
            self.logger.warning('Invalid response from authenticate in check_password for user (%s)', event['username'])
            return response
        return response

    @cherrypy.expose
    @cherrypy.tools.json_out()
    @cherrypy.tools.json_in()
    @JwtAuthenticated
    @JWT_AUTHORIZATION.GUAC
    @JWT_AUTHORIZATION.KASM_SESSION(authorizations=[*, JWT_AUTHORIZATION.KASM_SESSION])
    def request_session_recording_settings(self):
        if cherrypy.request.decoded_jwt:
            storage_key = cherrypy.request.db.get_config_setting_value('session_recording', 'recording_object_storage_key')
            storage_secret = cherrypy.request.db.get_config_setting_value('session_recording', 'recording_object_storage_secret')
            storage_location_url = cherrypy.request.db.get_config_setting_value('session_recording', 'session_recording_upload_location')
            framerate = cherrypy.request.db.get_config_setting_value('session_recording', 'session_recording_framerate')
            width = cherrypy.request.db.get_config_setting_value('session_recording', 'session_recording_res_width')
            height = cherrypy.request.db.get_config_setting_value('session_recording', 'session_recording_res_height')
            bitrate = cherrypy.request.db.get_config_setting_value('session_recording', 'session_recording_bitrate')
            retention_period = cherrypy.request.db.get_config_setting_value('session_recording', 'session_recording_retention_period')
            if storage_key and storage_secret and storage_location_url and framerate and width and height and bitrate:
                response = {}
                response['framerate'] = int(framerate)
                response['width'] = int(width)
                response['height'] = int(height)
                response['bitrate'] = int(bitrate)
                response['retention_period'] = int(retention_period)
                return response
            cherrypy.response.status = 400
            self.logger.error('Missing session recording settings.')
        else:  # inserted
            cherrypy.response.status = 403
            self.logger.error('Invalid or missing JWT token used in attempt to retrieve session recording settings.')

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    @JwtAuthenticated
    @JWT_AUTHORIZATION.KASM_SESSION
    @JWT_AUTHORIZATION.GUAC(authorizations=[*, JWT_AUTHORIZATION.GUAC])
    def request_session_recording_upload_url(self):
        response = {}
        event = cherrypy.request.json
        kasm_id = event.get('kasm_id')
        if cherrypy.request.decoded_jwt:
            if 'connection_proxy_id' in cherrypy.request.decoded_jwt or 'kasm_id' in cherrypy.request.decoded_jwt:
                account_record = cherrypy.request.db.getAccounting(kasm_id)
                session_recording_upload_location = cherrypy.request.db.get_config_setting_value('session_recording', 'session_recording_upload_location')
                if session_recording_upload_location:
                    url_parts = urlparse(session_recording_upload_location)
                    path_parts = list(os.path.split(url_parts.path))
                    filename = path_parts[(-1)]
                    f, extension = filename.rsplit('.', 1)
                    filename = f + '.{current_epoch}.' + extension
                    path_parts[(-1)] = filename
                    session_recording_upload_location = urlunparse((url_parts.scheme, url_parts.netloc, '/'.join(path_parts), url_parts.params, url_parts.query, url_parts.fragment))
                    formatted_session_recording_upload_location = object_storage_variable_substitution(session_recording_upload_location, account_record)
                    object_storage_key = cherrypy.request.db.get_config_setting_value('session_recording', 'recording_object_storage_key')
                    object_storage_secret = cherrypy.request.db.get_config_setting_value('session_recording', 'recording_object_storage_secret')
                    if object_storage_key and object_storage_secret:
                        if formatted_session_recording_upload_location.lower().startswith('s3://'):
                            credentials = {'aws_access_key_id': object_storage_key, 'aws_secret_access_key': object_storage_secret}
                            object_storage = AwsObjectStorageProvider(cherrypy.request.db, self.logger, credentials)
                            response['upload_url'] = object_storage.request_upload_file(formatted_session_recording_upload_location)
                            response['object_storage_url'] = formatted_session_recording_upload_location
                            self.logger.debug(f'Request for session recording upload link on behalf of Kasm: {kasm_id} with URL: {formatted_session_recording_upload_location}', extra={'metric_name': 'sessions.session_history.request_session_recording_upload_url', 'kasm_id': kasm_id, 'object_storage_url_unauthenticated': formatted_session_recording_upload_location, 'connection_proxy_id': cherrypy.request.decoded_jwt.get('connection_proxy_id', None), 'server_id': cherrypy.request.decoded_jwt.get('server_id', None)})
                        else:  # inserted
                            cherrypy.response.status = 400
                            self.logger.error('Unknown object storage protocol configured.')
                    else:  # inserted
                        cherrypy.response.status = 404
                        self.logger.error('Request for session recording upload url failed, Object Storage credentials are not configured on the server settings.')
                else:  # inserted
                    cherrypy.response.status = 400
                    self.logger.error('Session recording upload location is not set.')
        cherrypy.response.status = 403
        self.logger.error('Invalid or missing JWT token used in attempt to call receive_session_recording.')
        return response

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    @JwtAuthenticated
    @JWT_AUTHORIZATION.KASM_SESSION
    @JWT_AUTHORIZATION.GUAC(authorizations=[*, JWT_AUTHORIZATION.GUAC])
    def session_recording_upload_complete(self):
        event = cherrypy.request.json
        kasm_id = event.get('kasm_id')
        session_recording_metadata = event.get('session_recording_metadata')
        object_storage_url = event.get('object_storage_url')
        decoded_jwt = cherrypy.request.decoded_jwt
        if session_recording_metadata is None:
            session_recording_metadata = {}
        if decoded_jwt:
            if 'connection_proxy_id' in decoded_jwt or 'kasm_id' in decoded_jwt:
                account_record = cherrypy.request.db.getAccounting(kasm_id)
                session_recording = cherrypy.request.db.addSessionRecording(account_record.account_id, object_storage_url, session_recording_metadata)
                self.logger.debug(f'Request for session recording upload link on behalf of Kasm: {kasm_id} with URL: {object_storage_url}', extra={'metric_name': 'sessions.session_history.request_session_recording_upload_url', 'kasm_id': kasm_id, 'object_storage_url_unauthenticated': object_storage_url, 'connection_proxy_id': decoded_jwt.get('connection_proxy_id', None), 'server_id': decoded_jwt.get('server_id', None)})
        cherrypy.response.status = 403
        self.logger.error('Invalid or missing JWT token used in attempt to call session_recording_upload_complete.')
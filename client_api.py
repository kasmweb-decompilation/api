# uncompyle6 version 3.9.1
# Python bytecode version base 3.8.0 (3413)
# Decompiled from: Python 3.10.12 (main, Nov 20 2023, 15:14:05) [GCC 11.4.0]
# Embedded file name: client_api.py

import tempfile, typing
from urllib.error import URLError
import uuid, hashlib, cherrypy, traceback, logging, logging.config, time, datetime, json, os, stripe, pyotp, base64, urllib.request, requests, ssl, jwt, random, webauthn
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
Morsel._reserved["samesite"] = "SameSite"

class ClientApi(object):

    def __init__(self, config):
        self.config = config
        self.logger = logging.getLogger("client_api_server")
        self._db = DataAccessFactory.createSession(config["database"]["type"], config)
        self.hubspot_api_key = None
        if self._db.config.get("subscription"):
            if self._db.config["subscription"].get("hubspot_api_key"):
                self.hubspot_api_key = self._db.config["subscription"]["hubspot_api_key"].value
        else:
            self.zone_name = self.config["server"]["zone_name"]
            self.provider_manager = ProviderManager(config, self._db, self.logger)
            self.installation_id = str(self._db.getInstallation().installation_id)
            if self._db.hasFilterWithCategorization():
                self.init_webfilter()
            else:
                self.kasm_web_filter = None
        self.logger.info("%s initialized" % self.__class__.__name__)

    def init_webfilter(self):
        self.kasm_web_filter = KasmWebFilter(self._db.get_config_setting_value("web_filter", "web_filter_update_url"), self.installation_id, self.logger)

    @staticmethod
    @ttl_cache(maxsize=200, ttl=600)
    def is_sso_licensed(logger):
        # return true # uncomment to bypass
        license_helper = LicenseHelper(cherrypy.request.db, logger)
        return license_helper.is_sso_ok()

    @staticmethod
    @ttl_cache(maxsize=200, ttl=600)
    def is_allow_kasm_sharing_licensed(logger):
        # return true # uncomment to bypass
        license_helper = LicenseHelper(cherrypy.request.db, logger)
        return license_helper.is_allow_kasm_sharing_ok()

    @staticmethod
    @ttl_cache(maxsize=200, ttl=600)
    def is_usage_limit_licensed(logger):
        # return true # uncomment to bypass
        license_helper = LicenseHelper(cherrypy.request.db, logger)
        return license_helper.is_usage_limit_ok()
        

    @staticmethod
    @ttl_cache(maxsize=200, ttl=600)
    def is_session_recording_licensed(logger):
        # return true # uncomment to bypass
        license_helper = LicenseHelper(cherrypy.request.db, logger)
        return license_helper.is_session_recording_ok()

    @cherrypy.expose(["__healthcheck"])
    @cherrypy.tools.json_out()
    @Unauthenticated()
    def healthcheck(self):
        response = {"ok": True}
        cherrypy.request.db.getInstallation()
        return response

    @cherrypy.expose
    @Unauthenticated()
    def acs(self, **params):
        if not self.is_sso_licensed(self.logger):
            return "Access Denied. This feature is not licensed"
            if "id" in cherrypy.request.params:
                config = cherrypy.request.db.get_saml_config(cherrypy.request.params["id"])
            else:
                return "Login Failure: No saml ID in request"
                if config:
                    saml = SamlAuthentication(cherrypy.request, config, "/api/acs")
                    response = saml.acs()
                    if not ("error" in response and response["error"]):
                        if response["auth"] is False:
                            return response["error"]
                        sanitized_username = response["userid"].strip().lower()
                        user = cherrypy.request.db.getUser(sanitized_username)
                        if not user: # comment lines 106 to 113 to remove
                            license_helper = LicenseHelper(cherrypy.request.db, self.logger)
                            if license_helper.is_per_named_user_ok(with_user_added=True):
                                user = cherrypy.request.db.createUser(username=sanitized_username, realm="saml", saml_id=(cherrypy.request.params["id"]))
                            else:
                                msg = "License limit exceeded. Unable to create user"
                                self.logger.error(msg)
                                return
                        if user.realm == "saml":
                            if cherrypy.request.db.serializable(user.saml_id) == cherrypy.request.params["id"]:
                                self.process_sso_group_membership(user, response["attributes"].get(config.group_attribute, []), "saml", config.saml_id)
                                attributes = response["attributes"] if "attributes" in response else {}
                                for sso_attribute_mapping in config.user_attribute_mappings:
                                    if sso_attribute_mapping.attribute_name.lower() == "debug":
                                        self.logger.debug(f"SAML Attributes: {str(attributes)}")
                                    else:
                                        value = sso_attribute_mapping.process_attributes(user, attributes)
                                        self.logger.debug(f"New attribute value ({value}) applied to user {sanitized_username} for {sso_attribute_mapping.user_field}")
                                else:
                                    if len(config.user_attribute_mappings) > 0:
                                        cherrypy.request.db.updateUser(user)
                                    priv_key = str.encode(self._db.get_config_setting_value_cached("auth", "api_private_key"))
                                    session_lifetime = int(self._db.get_config_setting_value_cached("auth", "session_lifetime"))
                                    session_token = cherrypy.request.db.createSessionToken(user)
                                    user_id = cherrypy.request.db.serializable(user.user_id)
                                    session_jwt = session_token.generate_jwt(priv_key, session_lifetime)
                                    raise cherrypy.HTTPRedirect((response["base_url"] + "/#/sso/" + user_id + "/" + session_jwt), status=302)

                    else:
                        return "Saml login rejected: different Saml ID expected for user"
                else:
                    return "Saml login rejected: Non Saml user"
        else:
            self.logger.error("No Saml configuration with that ID found in the acs request")
            return "Error: wrong Saml ID"

    def process_sso_group_membership(self, user, sso_groups: typing.Dict, sso_type: str, sso_id: str):
        group_mappings = cherrypy.request.db.getGroupMappingBySsoID(sso_type=sso_type, sso_id=sso_id)
        sso_groups = [x.lower() for x in sso_groups]
        user_group_ids = [x.group_id for x in user.groups]
        distinct_groups = set()
        [distinct_groups.add(x.group) for x in group_mappings]
        distinct_groups = list(distinct_groups)
        for group in distinct_groups:
            sso_group_mappings = [x for x in group.group_mappings if x.sso_id == sso_id]
            self.logger.debug(f"Processing Group ({group.name}) with ({len(sso_group_mappings)}) sso_mappings for sso type {sso_type}, id: ({sso_id})")
            do_add = False

        for group_mapping in sso_group_mappings:
            if group_mapping.apply_to_all_users:
                do_add = True
                self.logger.debug(f"User ({user.username}) should be assigned to group ({group.name}) : Apply to All Users")
                break
            else:
                if group_mapping.sso_group_attributes.lower() in sso_groups:
                    self.logger.debug(f"User ({user.username}) should be assigned to group ({group.name}). Matched group attribute ({group_mapping.sso_group_attributes})")
                    do_add = True
                if do_add:
                    if group.group_id in user_group_ids:
                        self.logger.debug(f"User ({user.username}) already a member of group ({group.name}). No Action")
                    else:
                        self.logger.debug(f"Adding User ({user.username}) to Group ({group.name})")
                        cherrypy.request.db.addUserGroup(user, group)
                elif group.group_id in user_group_ids:
                    self.logger.debug(f"Removing User ({user.username}) from Group ({group.name})")
                    cherrypy.request.db.removeUserGroup(user, group)
                else:
                    self.logger.debug(f"User ({user.username}) is not a member of group ({group.name}). No Action")

    @cherrypy.expose
    @Unauthenticated()
    def slo(self, **params):
        if "id" in cherrypy.request.params:
            config = cherrypy.request.db.get_saml_config(cherrypy.request.params["id"])
        else:
            response = "No saml ID"
            return response
            if config:
                saml = SamlAuthentication(cherrypy.request, config, "/api/slo")
                url, name_id = saml.sls()
                if name_id:
                    sanitized_username = name_id.strip().lower()
                    user = cherrypy.request.db.getUser(sanitized_username)
                    cherrypy.request.db.remove_all_session_tokens(user)
                if not url:
                    url = cherrypy.request.base.replace("http", "https")
                raise cherrypy.HTTPRedirect(url, status=301)
            else:
                self.logger.error("Saml Logout Error: No config for this Saml ID")

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    @Unauthenticated()
    def sso(self, **params):
        response = {}
        event = cherrypy.request.json
        if "id" in event:
            if "sso_type" in event and event["sso_type"] == "saml_id":
                config = cherrypy.request.db.get_saml_config(event["id"])
                saml = SamlAuthentication(cherrypy.request, config, "/api/sso")
                response["url"] = saml.sso()
            elif "sso_type" in event and event["sso_type"] == "oidc_id":
                config = cherrypy.request.db.get_oidc_config(event["id"])
                response["url"] = OIDCAuthentication(config).get_login_url()
        else:
            response["error_message"] = "No SSO ID"
            return response
        return response

    @cherrypy.expose
    @Unauthenticated()
    def sso_login(self, **params):
        if "id" in cherrypy.request.params:
            id = cherrypy.request.params["id"]
            config = cherrypy.request.db.get_saml_config(id)
            if config:
                url = SamlAuthentication(cherrypy.request, config, "/api/sso_login").sso()
                raise cherrypy.HTTPRedirect(url, status=301)
            else:
                config = cherrypy.request.db.get_oidc_config(id)
                if config:
                    url = OIDCAuthentication(config).get_login_url()
                    raise cherrypy.HTTPRedirect(url, status=301)
                else:
                    cherrypy.response.status = 403
        else:
            cherrypy.response.status = 403

    @cherrypy.expose
    @Unauthenticated()
    def metadata(self, **params):
        response = {}
        if "id" in cherrypy.request.params:
            config = cherrypy.request.db.get_saml_config(cherrypy.request.params["id"])
        else:
            return "No saml ID"
            if config:
                saml = SamlAuthentication(cherrypy.request, config, "/api/metadata")
                response = saml.metadata()
                cherrypy.response.headers["Content-Type"] = "text/xml; charset=utf-8"
            else:
                response["error_message"] = "No saml Configuration"
            if "error_message" in response:
                return response["error_message"]
            return response["metadata"]

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    @Authenticated(requested_actions=[JWT_AUTHORIZATION.USER], read_only=True)
    def get_available_storage_providersParse error at or near `RETURN_VALUE' instruction at offset 132

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    @Authenticated(requested_actions=[JWT_AUTHORIZATION.USER], read_only=True)
    def get_storage_mappings(self):
        response = {"storage_mappings": []}
        user = cherrypy.request.authenticated_user
        is_admin = JWT_AUTHORIZATION.any_authorized_actions(cherrypy.request.authorizations, [JWT_AUTHORIZATION.USERS_VIEW, JWT_AUTHORIZATION.GROUPS_VIEW, JWT_AUTHORIZATION.GROUPS_VIEW_IFMEMBER, JWT_AUTHORIZATION.GROUPS_VIEW_SYSTEM, JWT_AUTHORIZATION.IMAGES_VIEW])
        event = cherrypy.request.json
        target_storage_mapping = event.get("target_storage_mapping", {})
        if target_storage_mapping:
            _user_id = target_storage_mapping.get("user_id")
            _group_id = target_storage_mapping.get("group_id")
            _image_id = target_storage_mapping.get("image_id")
            _storage_mapping_id = target_storage_mapping.get("storage_mapping_id")
            _test = [x for x in (_user_id, _group_id, _image_id, _storage_mapping_id) if x is not None]
            if len(_test) == 1:
                if is_admin:
                    storage_mappings = cherrypy.request.db.get_storage_mappings(storage_mapping_id=_storage_mapping_id,
                      user_id=_user_id,
                      group_id=_group_id,
                      image_id=_image_id)
                    response["storage_mappings"] = []
                    for storage_mapping in storage_mappings:
                        is_authorized = False

                    if storage_mapping.user:
                        is_authorized = storage_mapping.user.user_id == user.user_id or JWT_AUTHORIZATION.is_user_authorized_action(user, (cherrypy.request.authorizations), (JWT_AUTHORIZATION.USERS_VIEW), target_user=(storage_mapping.user))
                    else:
                        if storage_mapping.group:
                            is_authorized = JWT_AUTHORIZATION.is_user_authorized_action(user, (cherrypy.request.authorizations), (JWT_AUTHORIZATION.GROUPS_VIEW), target_group=(storage_mapping.group))
                        else:
                            if storage_mapping.image:
                                is_authorized = JWT_AUTHORIZATION.is_authorized_action(cherrypy.request.authorizations, JWT_AUTHORIZATION.IMAGES_VIEW)
                            if is_authorized:
                                response["storage_mappings"].append(cherrypy.request.db.serializable(storage_mapping.jsonDict))
                else:
                    if not _user_id or _user_id != user.user_id.hex:
                        msg = "Unauthorized attempt to update storage mappings for other user/group/image"
                        self.logger.error(msg)
                        response["error_message"] = "Access Denied"
                        return response
                    storage_mappings = cherrypy.request.db.get_storage_mappings(user_id=(user.user_id))
                    for vc in storage_mappings:
                        response["storage_mappings"].append({'storage_mapping_id':str(vc.storage_mapping_id), 
                         'storage_provider_type':(vc.storage_provider).storage_provider_type, 
                         'user_id':str(vc.user_id), 
                         'name':vc.name, 
                         'storage_provider_id':str(vc.storage_provider_id), 
                         'enabled':vc.enabled, 
                         'read_only':vc.read_only, 
                         'target':vc.target, 
                         's3_access_key_id':vc.s3_access_key_id, 
                         's3_secret_access_key':"**********", 
                         's3_bucket':vc.s3_bucket, 
                         'webdav_user':vc.webdav_user, 
                         'webdav_pass':"**********"})

            else:
                msg = "Invalid request. Only one of the following parameters may be defined (storage_mapping_id, user_id, group_id, image_id)"
                self.logger.error(msg)
                response["error_message"] = msg
        else:
            msg = "Invalid request. Missing required parameters"
            self.logger.error(msg)
            response["error_message"] = msg
        return response

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    @Authenticated(requested_actions=[JWT_AUTHORIZATION.USER], read_only=False)
    def delete_storage_mapping(self):
        response = {}
        user = cherrypy.request.authenticated_user
        event = cherrypy.request.json
        target_storage_mapping = event.get("target_storage_mapping")
        is_admin = JWT_AUTHORIZATION.any_authorized_actions(cherrypy.request.authorizations, [JWT_AUTHORIZATION.USERS_MODIFY,
         JWT_AUTHORIZATION.USERS_MODIFY_ADMIN,
         JWT_AUTHORIZATION.GROUPS_MODIFY,
         JWT_AUTHORIZATION.IMAGES_MODIFY,
         JWT_AUTHORIZATION.USERS_VIEW,
         JWT_AUTHORIZATION.GROUPS_VIEW,
         JWT_AUTHORIZATION.IMAGES_VIEW])
        is_authorized = False
        if target_storage_mapping:
            storage_mapping_id = target_storage_mapping.get("storage_mapping_id")
            if storage_mapping_id:
                if is_admin:
                    storage_mapping = cherrypy.request.db.get_storage_mapping(storage_mapping_id=storage_mapping_id)
                    if storage_mapping:
                        if storage_mapping.user:
                            is_authorized = user and storage_mapping.user.user_id == user.user_id or JWT_AUTHORIZATION.is_user_authorized_action(user, (cherrypy.request.authorizations), (JWT_AUTHORIZATION.USERS_MODIFY), target_user=(storage_mapping.user))
                        else:
                            if storage_mapping.group:
                                is_authorized = JWT_AUTHORIZATION.is_user_authorized_action(user, (cherrypy.request.authorizations), (JWT_AUTHORIZATION.GROUPS_MODIFY), target_group=(storage_mapping.group))
                            else:
                                if storage_mapping.image:
                                    is_authorized = JWT_AUTHORIZATION.is_authorized_action(cherrypy.request.authorizations, JWT_AUTHORIZATION.IMAGES_MODIFY)
                    else:
                        storage_mapping = cherrypy.request.db.get_storage_mapping(storage_mapping_id=storage_mapping_id, user_id=(user.user_id))
                        is_authorized = True
                elif storage_mapping:
                    if is_authorized:
                        if storage_mapping.storage_provider_type == STORAGE_PROVIDER_TYPES.CUSTOM.value:
                            if not (is_admin or is_authorized):
                                self.logger.error(f"User ({cherrypy.request.kasm_user_id}) unauthorized to delete storage mapping ({storage_mapping_id}).")
                            else:
                                self.logger.error(f"User ({cherrypy.request.kasm_user_id}) unauthorized to delete Custom storage mapping ({storage_mapping_id}).")
                    else:
                        response["error_message"] = "Unauthorized Action"
                        cherrypy.response.status = 401
                        return response
                    cherrypy.request.db.delete_storage_mapping(storage_mapping)
                    self.logger.info(("Successfully deleted storage_mapping_id (%s)" % storage_mapping_id),
                      extra={"storage_mapping_id": storage_mapping_id})
                else:
                    msg = "Storage Mapping ID (%s) Not found" % storage_mapping_id
                    self.logger.error(msg)
                    response["error_message"] = msg
            else:
                msg = "Invalid request. Missing required parameters"
                self.logger.error(msg)
                response["error_message"] = msg
        else:
            msg = "Invalid request. Missing required parameters"
            self.logger.error(msg)
            response["error_message"] = msg
        return response

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    @Authenticated(requested_actions=[JWT_AUTHORIZATION.USER], read_only=False)
    def create_storage_mappingParse error at or near `COME_FROM' instruction at offset 1248_0

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    @Authenticated(requested_actions=[JWT_AUTHORIZATION.USER], read_only=False)
    def update_storage_mapping(self):
        response = {}
        user = cherrypy.request.authenticated_user
        is_admin = JWT_AUTHORIZATION.any_authorized_actions(cherrypy.request.authorizations, [JWT_AUTHORIZATION.USERS_MODIFY,
         JWT_AUTHORIZATION.USERS_MODIFY_ADMIN,
         JWT_AUTHORIZATION.GROUPS_MODIFY,
         JWT_AUTHORIZATION.IMAGES_MODIFY,
         JWT_AUTHORIZATION.USERS_VIEW,
         JWT_AUTHORIZATION.GROUPS_VIEW,
         JWT_AUTHORIZATION.IMAGES_VIEW])
        event = cherrypy.request.json
        target_storage_mapping = event.get("target_storage_mapping")
        target_user = None
        if is_admin or user.get_setting_value("allow_user_storage_mapping", False):
            if target_storage_mapping:
                _user_id = target_storage_mapping.get("user_id")
                _group_id = target_storage_mapping.get("group_id")
                _image_id = target_storage_mapping.get("image_id")
                storage_mapping_id = target_storage_mapping.get("storage_mapping_id")
                _test = [x for x in (_user_id, _group_id, _image_id) if x is not None]
                if len(_test) == 1:
                    if not is_admin:
                        if target_storage_mapping.get("target") or target_storage_mapping.get("config"):
                            msg = "Unauthorized attempt to define target or config in storage mapping"
                            self.logger.error(msg)
                            response["error_message"] = "Access Denied"
                            return response
                        if _user_id:
                            if _user_id != user.user_id.hex:
                                msg = "Unauthorized attempt to create storage mappings for other user/group/image"
                                self.logger.error(msg)
                                response["error_message"] = "Access Denied"
                                return response
                    if _user_id:
                        target_user = cherrypy.request.db.get_user_by_id(user_id=_user_id)
                        if target_user:
                            max_user_storage_mappings = target_user.get_setting_value("max_user_storage_mappings", 2)
                            if len(target_user.storage_mappings) >= max_user_storage_mappings:
                                msg = "Unable to create storage mapping. Limit exceeded"
                                self.logger.error(msg)
                                response["error_message"] = msg
                                return response
                else:
                    msg = "Invalid user_id"
                    self.logger.error(msg)
                    response["error_message"] = msg
                    return response
                if storage_mapping_id:
                    is_authorized = False
                    if target_user and user and target_user.user_id == user.user_id:
                        is_authorized = True
                    else:
                        pass
                    if is_admin:
                        if target_user:
                            is_authorized = JWT_AUTHORIZATION.is_user_authorized_action(user, (cherrypy.request.authorizations), (JWT_AUTHORIZATION.USERS_MODIFY), target_user=target_user)
                elif _group_id:
                    target_group = cherrypy.request.db.getGroup(group_id=_group_id)
                    is_authorized = target_group and JWT_AUTHORIZATION.is_user_authorized_action(user, (cherrypy.request.authorizations), (JWT_AUTHORIZATION.GROUPS_MODIFY), target_group=target_group)
                else:
                    if _image_id:
                        is_authorized = JWT_AUTHORIZATION.is_authorized_action(cherrypy.request.authorizations, JWT_AUTHORIZATION.IMAGES_MODIFY)
                    if not is_authorized:
                        self.logger.error(f"User ({cherrypy.request.kasm_user_id}) attempted to update a storage mapping but is not authorized to modify the target group, user, or image.")
                        response["error_message"] = "Unauthorized to modify the target user/group/image for the storage mapping."
                        response["ui_show_error"] = True
                        cherrypy.response.status = 401
                        return response
                        storage_mapping = cherrypy.request.db.get_storage_mapping(storage_mapping_id=storage_mapping_id,
                          user_id=(None if is_admin else user.user_id))
                        if storage_mapping:
                            if storage_mapping.storage_provider_type == STORAGE_PROVIDER_TYPES.CUSTOM.value:
                                if not is_admin:
                                    msg = "Unauthorized attempted to modify Custom Storage mapping"
                                    self.logger.error(msg)
                                    response["error_message"] = "Access Denied"
                                    return response
                                storage_mapping = cherrypy.request.db.update_storage_mapping(storage_mapping,
                                  name=(target_storage_mapping.get("name")),
                                  config=(target_storage_mapping.get("config") if is_admin else None),
                                  enabled=(target_storage_mapping.get("enabled")),
                                  read_only=(target_storage_mapping.get("read_only")),
                                  user_id=(target_storage_mapping.get("user_id")),
                                  group_id=(target_storage_mapping.get("group_id")),
                                  image_id=(target_storage_mapping.get("image_id")),
                                  target=(target_storage_mapping.get("target") if is_admin else None),
                                  webdav_user=(target_storage_mapping.get("webdav_user")),
                                  webdav_pass=(target_storage_mapping.get("webdav_pass")),
                                  s3_access_key_id=(target_storage_mapping.get("s3_access_key_id")),
                                  s3_secret_access_key=(target_storage_mapping.get("s3_secret_access_key")),
                                  s3_bucket=(target_storage_mapping.get("s3_bucket")))
                                response["storage_mapping"] = cherrypy.request.db.serializable(storage_mapping.jsonDict)
                                self.logger.info(("Successfully updated storage_mapping_id (%s)" % storage_mapping.storage_mapping_id),
                                  extra={"storage_mapping_id": (storage_mapping.storage_mapping_id)})
                            else:
                                msg = "Invalid Storage Mapping ID (%s)" % storage_mapping_id
                                self.logger.error(msg)
                                response["error_message"] = msg
                        else:
                            msg = "Invalid request. Missing required parameters"
                            self.logger.error(msg)
                            response["error_message"] = msg
                    else:
                        msg = "Invalid request. Only one attribute group_id, user_id, or image_id may be set"
                    self.logger.error(msg)
                    response["error_message"] = msg
            else:
                msg = "Invalid request. Missing required parameters"
                self.logger.error(msg)
                response["error_message"] = msg
        else:
            msg = "Updating a storage mapping is not allowed for this user"
            self.logger.error(msg)
            response["error_message"] = msg
        return response

    @cherrypy.expose
    @CookieAuthenticated(requested_actions=[JWT_AUTHORIZATION.USER])
    def cloud_storage_callback(self, **params):
        response = None
        state = cherrypy.request.params.get("state")
        user = cherrypy.request.authenticated_user
        is_admin = JWT_AUTHORIZATION.any_authorized_actions(cherrypy.request.authorizations, [JWT_AUTHORIZATION.USERS_MODIFY, JWT_AUTHORIZATION.IMAGES_MODIFY, JWT_AUTHORIZATION.GROUPS_MODIFY])
        callback_url = cherrypy.request.base + cherrypy.request.path_info + "?" + cherrypy.request.query_string
        callback_url = callback_url.replace("http", "https")
        if state:
            storage_token_cookie = cherrypy.request.cookie.get("storage_token")
            if storage_token_cookie:
                decoded_jwt = self.decode_jwt(storage_token_cookie.value)
                if decoded_jwt:
                    if decoded_jwt.get("state_token") == state:
                        storage_provider_id = decoded_jwt.get("storage_provider_id")
                        user_id = decoded_jwt.get("user_id")
                        group_id = decoded_jwt.get("group_id")
                        image_id = decoded_jwt.get("image_id")
                        return_url = decoded_jwt.get("return_url")
                        enabled = decoded_jwt.get("enabled")
                        read_only = decoded_jwt.get("read_only")
                        if not return_url:
                            return_url = cherrypy.request.base.replace("http", "https")
                            return_url += "/"
                        else:
                            _test = [x for x in (user_id, group_id, image_id) if x is not None]
                            if len(_test) == 1 and not is_admin:
                                if user_id:
                                    if user_id != user.user_id.hex:
                                        msg = "Unauthorized attempt to create storage mappings for other user/group/image"
                                        self.logger.error(msg)
                                        cherrypy.response.status = 401
                                        response = "Unauthorized"
                                        return response
                                    is_permitted = False
                                    if is_admin:
                                        if user_id:
                                            target_user = cherrypy.request.db.get_user_by_id(user_id)
                                            is_permitted = JWT_AUTHORIZATION.is_user_authorized_action(user, (cherrypy.request.authorizations), (JWT_AUTHORIZATION.USERS_MODIFY), target_user=target_user)
                                        else:
                                            if group_id:
                                                target_group = cherrypy.request.db.getGroup(group_id=group_id)
                                                is_permitted = JWT_AUTHORIZATION.is_user_authorized_action(user, (cherrypy.request.authorizations), (JWT_AUTHORIZATION.GROUPS_MODIFY), target_group=target_group)
                                            else:
                                                if image_id:
                                                    is_permitted = JWT_AUTHORIZATION.is_user_authorized_action(user, cherrypy.request.authorizations, JWT_AUTHORIZATION.IMAGES_MODIFY)
                                        if not is_permitted:
                                            msg = "Unauthorized attempt to create storage mappings for other user/group/image"
                                            self.logger.error(msg)
                                            cherrypy.response.status = 401
                                            response = "Unauthorized"
                                            return response
                                else:
                                    storage_provider = cherrypy.request.db.get_storage_provider(storage_provider_id=storage_provider_id)
                                    if storage_provider:
                                        oauth_token = None
                                        if storage_provider.storage_provider_type == STORAGE_PROVIDER_TYPES.GOOGLE_DRIVE.value:
                                            oauth_token = GoogleDrive(storage_provider).get_oauth_token(callback_url)
                                        else:
                                            if storage_provider.storage_provider_type == STORAGE_PROVIDER_TYPES.DROPBOX.value:
                                                oauth_token = Dropbox(storage_provider).get_oauth_token(callback_url)
                                            else:
                                                if storage_provider.storage_provider_type == STORAGE_PROVIDER_TYPES.ONEDRIVE.value:
                                                    oauth_token = OneDrive(storage_provider).get_oauth_token(callback_url)
                                                else:
                                                    response = "Unknown Storage Provider Type (%s)" % storage_provider.storage_provider_type
                                                    self.logger.error(response)
                                        if oauth_token:
                                            storage_mapping = cherrypy.request.db.create_storage_mapping(name=("%s Storage Mapping" % storage_provider.name),
                                              enabled=enabled,
                                              read_only=read_only,
                                              user_id=user_id,
                                              group_id=group_id,
                                              image_id=image_id,
                                              storage_provider_id=storage_provider_id,
                                              oauth_token=oauth_token)
                                            self.logger.info(("Successfully created storage_mapping_id (%s)" % storage_mapping.storage_mapping_id),
                                              extra={"storage_mapping_id": (storage_mapping.storage_mapping_id)})
                                            raise cherrypy.HTTPRedirect(return_url, status=302)
                                        else:
                                            response = "Error Processing Oauth callback for (%s)" % storage_provider.name
                                            self.logger.error(response)
                                    else:
                                        response = "Missing Storage Provider config for (%s)" % storage_provider_id
                                    self.logger.error(response)
                            else:
                                pass
                            response = "Invalid request. Only one attribute group_id, user_id, or image_id may be set"
                            self.logger.error(response)
                    else:
                        response = "Access Denied"
                        self.logger.error("Invalid State Token")
                else:
                    response = "Access Denied"
                    self.logger.error("Invalid JWT")
            else:
                response = "Invalid Request. Missing required cookie"
                self.logger.error(response)
        else:
            response = "Invalid request. Missing required parameters"
            self.logger.error(response)
        return response

    @cherrypy.expose
    @Unauthenticated()
    def oidc_callback(self, **params):
        oidc_id = cherrypy.request.params["state"][None[:32]]
        oidc_config = cherrypy.request.db.get_oidc_config(oidc_id)
        oidc_auth = OIDCAuthentication(oidc_config)
        _url = cherrypy.request.base + cherrypy.request.path_info + "?" + cherrypy.request.query_string
        _url = _url.replace("http", "https")
        user_attributes = oidc_auth.process_callback(_url)
        if user_attributes["username"]:
            if oidc_id:
                sanitized_username = user_attributes["username"].strip().lower()
                user = cherrypy.request.db.getUser(sanitized_username)
                if not user: # comment lines 632 to 639 to remove
                    license_helper = LicenseHelper(cherrypy.request.db, self.logger)
                    if license_helper.is_per_named_user_ok(with_user_added=True):
                        user = cherrypy.request.db.createUser(username=sanitized_username, realm="oidc", oidc_id=oidc_id)
                    else:
                        msg = "License limit exceeded. Unable to create user"
                        self.logger.error(msg)
                        return
                if user.realm == "oidc":
                    if user.oidc_id and user.oidc_id.hex == oidc_id:
                        self.process_sso_group_membership(user, (user_attributes.get("groups", [])), sso_type="oidc", sso_id=(oidc_config.oidc_id))
                        session_token = cherrypy.request.db.createSessionToken(user)
                        priv_key = str.encode(cherrypy.request.db.get_config_setting_value_cached("auth", "api_private_key"))
                        session_lifetime = int(cherrypy.request.db.get_config_setting_value_cached("auth", "session_lifetime"))
                        session_jwt = session_token.generate_jwt(priv_key, session_lifetime)
                        user_id = cherrypy.request.db.serializable(user.user_id)
                        _url = cherrypy.request.base.replace("http", "https")
                        _url += "/#/sso/" + user_id + "/" + session_jwt
                        for sso_attribute_mapping in oidc_config.user_attribute_mappings:
                            if sso_attribute_mapping.attribute_name.lower() == "debug":
                                self.logger.debug(f"OIDC Attributes: {str(user_attributes)}")
                            else:
                                value = sso_attribute_mapping.process_attributes(user, user_attributes)
                                self.logger.debug(f"OIDC attribute value ({value}) applied to user {sanitized_username} for {sso_attribute_mapping.user_field}")
                        else:
                            if len(oidc_config.user_attribute_mappings) > 0:
                                cherrypy.request.db.updateUser(user)
                            raise cherrypy.HTTPRedirect(_url, status=302)

                    else:
                        return "OIDC login rejected: different OIDC ID expected for user"
                else:
                    return "OIDC login rejected: Non OIDC user"
        return "Unable to processes OIDC login"

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    @Unauthenticated()
    def login_settings(self):
        hostname = cherrypy.request.headers["HOST"]
        return self.login_settings_cache(hostname, self.logger)

    @staticmethod
    @ttl_cache(maxsize=200, ttl=30)
    def login_settings_cache(hostname, logger):
        response = {}
        saml_configs = cherrypy.request.db.get_saml_configs()
        for x in saml_configs:
            if x.enabled:
                response["sso_enabled"] = x.enabled
        else:
            oidc_configs = cherrypy.request.db.get_oidc_configs()
            for x in oidc_configs:
                if x.enabled:
                    response["sso_enabled"] = x.enabled
            else:
                branding = None
                license_helper = LicenseHelper(cherrypy.request.db, logger)
                if license_helper.is_branding_ok():
                    branding = cherrypy.request.db.get_effective_branding_config(hostname)
                    if branding:
                        response["login_logo"] = branding.login_logo_url
                        response["login_splash_background"] = branding.login_splash_url
                        response["login_caption"] = branding.login_caption
                        response["header_logo"] = branding.header_logo_url
                        response["html_title"] = branding.html_title
                        response["favicon_logo"] = branding.favicon_logo_url
                        response["loading_session_text"] = branding.loading_session_text
                        response["joining_session_text"] = branding.joining_session_text
                        response["destroying_session_text"] = branding.destroying_session_text
                        response["launcher_background_url"] = branding.launcher_background_url
                if not branding:
                    internal_branding_config = cherrypy.request.db.get_internal_branding_config()
                    response["login_logo"] = internal_branding_config["login_logo_url"]
                    response["login_splash_background"] = internal_branding_config["login_splash_url"]
                    response["login_caption"] = internal_branding_config["login_caption"]
                    response["header_logo"] = internal_branding_config["header_logo_url"]
                    response["html_title"] = internal_branding_config["html_title"]
                    response["favicon_logo"] = internal_branding_config["favicon_logo_url"]
                    response["loading_session_text"] = internal_branding_config["loading_session_text"]
                    response["joining_session_text"] = internal_branding_config["joining_session_text"]
                    response["destroying_session_text"] = internal_branding_config["destroying_session_text"]
                    response["launcher_background_url"] = internal_branding_config["launcher_background_url"]
                _s = ["login_assistance"]
                if license_helper.is_login_banner_ok():
                    _s += ["notice_message", "notice_title"]
                settings = [cherrypy.request.db.serializable(x.jsonDict) for x in cherrypy.request.db.get_config_settings()]
                for x in settings:
                    if x["name"] in _s:
                        response[x["name"]] = x["value"]
                else:
                    if license_helper.is_login_banner_ok():
                        if "notice_message" not in response:
                            response["notice_message"] = "Warning: By using this system you agree to all the terms and conditions."
                        if "notice_title" not in response:
                            response["notice_title"] = "Notice"
                    _sc = []
                    enabled_configs = list(filter((lambda v: v.enabled), saml_configs))
                    matching_configs = list(filter((lambda v: v.hostname == hostname), enabled_configs))
                    if not len(matching_configs):
                        matching_configs = list(filter((lambda v: v.is_default), enabled_configs))

        for config in matching_configs:
            _sc.append({'display_name':config.display_name, 
             'hostname':config.hostname, 
             'default':config.is_default, 
             'enabled':config.enabled, 
             'saml_id':(cherrypy.request.db.serializable)(config.saml_id), 
             'auto_login':config.auto_login, 
             'logo_url':config.logo_url})
        else:
            response["saml"] = {"saml_configs": _sc}
            _oc = []
            enabled_oidc_configs = list(filter((lambda v: v.enabled), oidc_configs))
            matching_oidc_configs = list(filter((lambda v: v.hostname == hostname), enabled_oidc_configs))
            if not len(matching_oidc_configs):
                matching_oidc_configs = list(filter((lambda v: v.is_default), enabled_oidc_configs))
            for config in matching_oidc_configs:
                _oc.append({'display_name':config.display_name, 
                 'hostname':config.hostname, 
                 'default':config.is_default, 
                 'enabled':config.enabled, 
                 'oidc_id':(cherrypy.request.db.serializable)(config.oidc_id), 
                 'auto_login':config.auto_login, 
                 'logo_url':config.logo_url})
            else:
                response["oidc"] = {"oidc_configs": _oc}
                response["recaptcha"] = {"google_recaptcha_site_key": ""}
                google_recaptcha_site_key = cherrypy.request.db.get_config_setting_value("auth", "google_recaptcha_site_key")
                if google_recaptcha_site_key:
                    response["recaptcha"]["google_recaptcha_site_key"] = google_recaptcha_site_key
                return response

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    @Unauthenticated()
    def login_saml(self):
        response = {}
        event = cherrypy.request.json
        cherrypy.response.status = 403
        if "user_id" in event:
            if "session_token" in event:
                try:
                    user = cherrypy.request.db.get_user_by_id(event["user_id"])
                except Exception:
                    self.logger.error("User was sent with invalid user_id")
                    response["error_message"] = "Invalid user ID"
                    return                     return response
                else:
                    pub_cert = str.encode(self._db.get_config_setting_value_cached("auth", "api_public_cert"))
                    decoded_jwt = jwt.decode((event["session_token"]), pub_cert, algorithm="RS256")
                    if user and "session_token_id" in decoded_jwt and cherrypy.request.db.validateSessionToken(decoded_jwt["session_token_id"], user.username):
                        for authorization in decoded_jwt["authorizations"]:
                            cherrypy.request.authorizations.append(JWT_AUTHORIZATION(authorization))
                        else:
                            kasm_auth_domain = self._db.get_config_setting_value("auth", "kasm_auth_domain")
                            if kasm_auth_domain:
                                if kasm_auth_domain.lower() == "$request_host$":
                                    kasm_auth_domain = cherrypy.request.headers["HOST"]
                            session_lifetime = int(cherrypy.request.db.get_config_setting_value_cached("auth", "session_lifetime"))
                            same_site = self._db.get_config_setting_value("auth", "same_site")
                            cherrypy.response.cookie["session_token"] = event["session_token"]
                            cherrypy.response.cookie["session_token"]["Path"] = "/"
                            cherrypy.response.cookie["session_token"]["Max-Age"] = session_lifetime
                            cherrypy.response.cookie["session_token"]["Domain"] = kasm_auth_domain
                            cherrypy.response.cookie["session_token"]["Secure"] = True
                            cherrypy.response.cookie["session_token"]["httpOnly"] = True
                            cherrypy.response.cookie["session_token"]["SameSite"] = same_site
                            cherrypy.response.cookie["username"] = user.username
                            cherrypy.response.cookie["username"]["Path"] = "/"
                            cherrypy.response.cookie["username"]["Max-Age"] = session_lifetime
                            cherrypy.response.cookie["username"]["Domain"] = kasm_auth_domain
                            cherrypy.response.cookie["username"]["Secure"] = True
                            cherrypy.response.cookie["username"]["httpOnly"] = True
                            cherrypy.response.cookie["username"]["SameSite"] = same_site
                            response["token"] = event["session_token"]
                            response["user_id"] = cherrypy.request.db.serializable(user.user_id)
                            response["is_admin"] = JWT_AUTHORIZATION.any_admin_action(cherrypy.request.authorizations)
                            response["authorized_views"] = JWT_AUTHORIZATION.get_authorized_views(cherrypy.request.authorizations)
                            response["is_anonymous"] = user.anonymous
                            response["dashboard_redirect"] = user.get_setting_value("dashboard_redirect", None)
                            response["require_subscription"] = user.get_setting_value("require_subscription", None)
                            response["has_subscription"] = user.has_subscription
                            response["has_plan"] = user.has_plan
                            response["username"] = user.username
                            response["auto_login_kasm"] = user.get_setting_value("auto_login_to_kasm", False)
                            response["program_data"] = user.get_program_data()
                            user_attr = cherrypy.request.db.getUserAttributes(user)
                            if user_attr is not None:
                                if user_attr.user_login_to_kasm is not None:
                                    response["auto_login_kasm"] = user_attr.user_login_to_kasm
                            self.logger.info(("Successful authentication attempt for user: (%s)" % user.username), extra={"metric_name": "account.login.successful"})
                            cherrypy.response.status = 200

                    else:
                        response["error_message"] = "Access Denied!"
                        self.logger.warning(f'User ({event["user_id"]}) attempted to call login_saml function with invalid credentials.')
                    return response

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    @Unauthenticated()
    def authenticateParse error at or near `JUMP_ABSOLUTE' instruction at offset 490_492

    def encrypt_client_data(self, client_key, data):
        client_key_b64_bytes = base64.urlsafe_b64decode(client_key)
        if len(client_key_b64_bytes) != 32:
            raise Exception(f"Invalid client key length {len(client_key)}")
        install_id_bytes = self.installation_id.replace("-", "").encode("ascii")
        key = client_key_b64_bytes[0[:16]] + install_id_bytes[0[:16]]
        key_b64 = base64.urlsafe_b64encode(key)
        fernet = Fernet(key_b64)
        return fernet.encrypt(data).decode("utf-8")

    def decrypt_client_data(self, client_key, encrypted_data):
        client_key_b64_bytes = base64.urlsafe_b64decode(client_key)
        if len(client_key_b64_bytes) != 32:
            raise Exception("Invalid client key length")
        install_id_bytes = self.installation_id.replace("-", "").encode("ascii")
        key = client_key_b64_bytes[0[:16]] + install_id_bytes[0[:16]]
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
        if not user.get_setting_value("allow_2fa_self_enrollment", False):
            self.logger.warning("User (%s) attempted to call set_secret_authenticated, but self_enrollment is disabled.", event["username"])
            response["error_message"] = "Self Enrollment is not permitted"
            return response
        check_resp = self.check_password()
        if "error_message" in check_resp:
            self.logger.warning("Invalid password to set_secret_authenticated for user (%s)", event["username"])
            response["error_message"] = check_resp["error_message"]
            return response
        set_secret_resp = self._set_secret(event, user)
        if "error_message" in set_secret_resp:
            self.logger.warning("set_secret for User (%s) failed", event["username"])
            if set_secret_resp["error_message"] == "Access Denied":
                response["error_message"] = "Failure Setting secret"
            else:
                response["error_message"] = set_secret_resp["error_message"]
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
        if "username" not in event or "password" not in event:
            self.logger.warning("Invalid call to set_secret")
            response["error_message"] = "Access Denied"
            return response
        user = cherrypy.request.db.getUser(event["username"].strip().lower())
        auth_resp = self.authenticate()
        if "error_message" in auth_resp:
            self.logger.warning("Authentication failed on attempt to set 2fa secret for user: (%s)" % event["username"])
            response["error_message"] = auth_resp["error_message"]
            return response
        if not auth_resp.get("require_2fa"):
            self.logger.warning("User attempted to set two factor token when 2fa is not enabled for the user: (%s)" % event["username"])
            response["error_message"] = "Access Denied"
            return response
        return self._set_secret(event, user)

    def _set_secret(self, event, user):
        response = {}
        if not user.get_setting_value("allow_totp_2fa", True):
            self.logger.warning("User (%s) attempted to call set_secret, but totp is not allowed")
            response["error_message"] = "TOTP is not permitted for user. Access Denied."
            return response
        if user.set_two_factor:
            if "target_token" not in event:
                self.logger.warning("User attempted to set secret on 2fa when secret is already set: (%s)" % event["username"])
                response["error_message"] = "Access Denied"
                return response
        elif "target_token" in event:
            if "serial_number" not in event["target_token"]:
                self.logger.warning("User attempted to self assign a token but no serial number provided: (%s)" % event["username"])
                response["error_message"] = "Access Denied"
                return response
            token = cherrypy.request.db.get_physical_token(event["target_token"]["serial_number"])
            if token and token.user is None:
                token = cherrypy.request.db.assign_physical_token(token, user)
                self.logger.info(f'User ({event["username"]}) self assign token with serial number ({event["target_token"]["serial_number"]}).')
            else:
                if token and token.user:
                    self.logger.warning(f'User ({event["username"]}) attempted to self assign a token but the token serial number ({event["target_token"]["serial_number"]}) is already assigned.')
                    token = None
                else:
                    self.logger.warning(f'User ({event["username"]}) attempted to self assign a token but the token serial number ({event["target_token"]["serial_number"]}) was not found.')
                    token = None
            if token is None:
                user.failed_pw_attempts += 1
                user.locked = user.failed_pw_attempts >= int(self._db.get_config_setting_value("auth", "max_login_attempts"))
                response["error_message"] = "Invalid token"
                cherrypy.request.db.updateUser(user)
        else:
            secret = pyotp.random_base32()
            user.secret = secret
            response["generated_secret"] = secret
            cherrypy.request.db.updateUser(user)
            qrcode = pyotp.totp.TOTP(secret).provisioning_uri((user.username), issuer_name="Kasm")
            response["qrcode"] = qrcode
        return response

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    @Authenticated(requested_actions=[JWT_AUTHORIZATION.USER], read_only=False)
    def two_factor_auth_authenticated(self):
        event = cherrypy.request.json
        response = {}
        user = cherrypy.request.authenticated_user
        if "username" not in event or "password" not in event or "code" not in event:
            self.logger.warning("Invalid call to two_factor_auth")
            response["error_message"] = "Access Denied"
            return response
        check_resp = self.check_password()
        if "error_message" in check_resp:
            self.logger.warning("Invalid password to set_secret_authenticated for user (%s)", event["username"])
            response["error_message"] = check_resp["error_message"]
            return response
        two_factor_resp = self._two_factor_auth(event, user)
        if "error_message" in two_factor_resp:
            self.logger.warning("Error when user (%s) made call to two_factor_auth_authenticated", event["username"])
            if two_factor_resp["error_message"] == "Access Denied":
                response["error_message"] = "Two Factor Auth Failed"
            else:
                response["error_message"] = two_factor_resp["error_message"]
            return response
        return two_factor_resp

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    @Unauthenticated()
    def two_factor_auth(self):
        event = cherrypy.request.json
        response = {}
        if "username" not in event or "password" not in event or "code" not in event:
            self.logger.warning("Invalid call to two_factor_auth")
            response["error_message"] = "Access Denied"
            return response
        user = cherrypy.request.db.getUser(event["username"].strip().lower())
        if user is None:
            self.logger.warning("Invalid user (%s)" % event["username"])
            response["error_message"] = "Access Denied"
            return response
        auth_resp = self.authenticate()
        if "error_message" in auth_resp:
            self.logger.warning("Authentication failed on 2fa attempt for user: (%s)" % event["username"])
            response["error_message"] = auth_resp["error_message"]
            return response
        return self._two_factor_auth(event, user)

    def _two_factor_authParse error at or near `JUMP_ABSOLUTE' instruction at offset 500_502

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    @Authenticated(requested_actions=[JWT_AUTHORIZATION.USER], read_only=False)
    def set_password(self):
        response = {}
        event = cherrypy.request.json
        user = cherrypy.request.authenticated_user
        if "current_password" in event:
            if "new_password" in event:
                if user.realm == "ldap":
                    ldap_configs = cherrypy.request.db.get_ldap_configs()
                    for ldap_config in ldap_configs:
                        if ldap_config.enabled:
                            ldap_auth = LDAPAuthentication(ldap_config)
                        if ldap_auth.match_domain(user.username):
                            ldap_response = ldap_auth.set_password(user.username, event["new_password"])
                            if ldap_response.error:
                                response["error_message"] = ldap_response.error
                                self.logger.warning(("Password reset attempted failed for user: (%s) because: (%s)" % (user.username, ldap_response.error)), extra={"metric_name": "account.password_reset.failed_ldap_error"})
                            else:
                                self.logger.info(f"User ({user.username}) ldap password successfully changed.")

                elif user.realm == "saml":
                    message = "Error. Changing passwords for SAML users is not supported. Please contact an administrator"
                    self.logger.warning(message)
                    response["error_message"] = message
                elif user.realm == "oidc":
                    message = "Error. Changing passwords for OIDC users is not supported. Please contact an administrator"
                    self.logger.warning(message)
                    response["error_message"] = message
                elif user.locked:
                    message = "Access Denied! User account is locked out. Please contact an administrator"
                    self.logger.warning(message)
                    response["error_message"] = message
            else:
                hashy = hashlib.sha256(event["current_password"].encode() + user.salt.encode()).hexdigest()
                if hashy == user.pw_hash:
                    pwr = passwordComplexityCheck(event["new_password"])
                    if pwr["status"]:
                        user = cherrypy.request.db.getUser(event["username"])
                        user.pw_hash = hashlib.sha256(event["new_password"].encode() + user.salt.encode()).hexdigest()
                        if "set_two_factor" in event:
                            if event["set_two_factor"] is True:
                                user.set_two_factor = False
                                user.secret = ""
                        cherrypy.request.db.updateUser(user)
                        self.logger.info(f"User ({user.username}) local password successfully changed.", extra={"metric_name": "account.password_reset.successful"})
                        cherrypy.request.db.remove_all_session_tokens(user)
                    else:
                        response["error_message"] = pwr["message"]
                else:
                    message = "Access Denied! Invalid Current Password."
                    user.failed_pw_attempts += 1
                    user.locked = user.failed_pw_attempts >= int(self._db.get_config_setting_value("auth", "max_login_attempts"))
                    if user.locked:
                        message = message + " User is now locked out."
                cherrypy.request.db.updateUser(user)
                self.logger.warning(message)
                response["error_message"] = message
        else:
            message = "Invalid Request. Missing one or more required parameters"
            self.logger.warning(message)
            response["error_message"] = message
        return response

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    @Unauthenticated()
    def reset_password(self):
        response = {}
        event = cherrypy.request.json
        if "username" not in event or "current_password" not in event or "new_password" not in event:
            self.logger.warning("Invalid call to set password")
            response["error_message"] = "Access Denied"
            return response
        if event["current_password"] == event["new_password"]:
            self.logger.info(f'User ({event["username"]}) attempted to reuse old password.')
            response["error_message"] = "Cannot set new password to the old password."
            return response
        sanitized_username = event["username"].strip().lower()
        user = cherrypy.request.db.getUser(sanitized_username)
        event["password"] = event["current_password"]
        auth_resp = self.authenticate()
        if not ("error_message" not in auth_resp or "reason") in auth_resp or auth_resp["reason"] == "expired_password":
            if user:
                if user.realm == "saml":
                    message = "Error. Changing passwords for SAML users is not supported. Please contact an administrator"
                    self.logger.warning(message)
                    response["error_message"] = message
                elif user and user.realm == "oidc":
                    message = "Error. Changing passwords for OIDC users is not supported. Please contact an administrator"
                    self.logger.warning(message)
                    response["error_message"] = message
            elif not user or user.realm == "ldap":
                ldap_configs = cherrypy.request.db.get_ldap_configs()
                for ldap_config in ldap_configs:
                    if ldap_config.enabled:
                        ldap_auth = LDAPAuthentication(ldap_config)
                        if ldap_auth.match_domain(sanitized_username):
                            ldap_response = ldap_auth.set_password(sanitized_username, event["new_password"])
                            if ldap_response.error:
                                response["error_message"] = ldap_response.error
                                self.logger.warning(("Password reset attempted failed for user: (%s) because: (%s)" % (sanitized_username, ldap_response.error)), extra={"metric_name": "account.password_reset.failed_ldap_error"})
                            else:
                                self.logger.info(f"User ({sanitized_username}) ldap password successfully changed.", extra={"metric_name": "account.password_reset.successful"})
                            return response
                        self.logger.warning(f'Invalid username ({event["username"]})')
                    else:
                        if user:
                            if user.locked:
                                message = "Access Denied! User account is locked out. Please contact an administrator"
                                self.logger.warning(message)
                                response["error_message"] = message
                            else:
                                pwr = passwordComplexityCheck(event["new_password"])
                                if pwr["status"]:
                                    user.pw_hash = hashlib.sha256(event["new_password"].encode() + user.salt.encode()).hexdigest()
                                    user.password_set_date = datetime.datetime.utcnow()
                                    if "set_two_factor" in event:
                                        if event["set_two_factor"] is True:
                                            user.set_two_factor = False
                                            user.secret = ""
                                    cherrypy.request.db.updateUser(user)
                                    self.logger.info(f"User ({user.username}) local password successfully changed.", extra={"metric_name": "account.password_reset.successful"})
                                    cherrypy.request.db.remove_all_session_tokens(user)
                                else:
                                    response["error_message"] = pwr["message"]

            else:
                self.logger.warning(f'User ({event["username"]}) attempted to reset password with invalid credentials.')
                response["error_message"] = auth_resp["error_message"]
        return response

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    @Authenticated(requested_actions=[JWT_AUTHORIZATION.USER], read_only=False)
    def new_session_token(self):
        event = cherrypy.request.json
        response = {}
        user = cherrypy.request.db.getUser(event["username"])
        session_token = cherrypy.request.db.updateSessionToken(cherrypy.request.session_token_id)
        if session_token is not None:
            priv_key = str.encode(self._db.get_config_setting_value_cached("auth", "api_private_key"))
            session_lifetime = int(self._db.get_config_setting_value_cached("auth", "session_lifetime"))
            session_jwt = session_token.generate_jwt(priv_key, session_lifetime)
            response["token"] = session_jwt
            response["is_admin"] = JWT_AUTHORIZATION.any_admin_action(cherrypy.request.authorizations)
            response["authorized_views"] = JWT_AUTHORIZATION.get_authorized_views(session_token.get_authorizations())
            response["is_anonymous"] = user.anonymous
            response["dashboard_redirect"] = user.get_setting_value("dashboard_redirect", None)
            response["require_subscription"] = user.get_setting_value("require_subscription", None)
            response["has_subscription"] = user.has_subscription
            response["has_plan"] = user.has_plan
            kasm_auth_domain = self._db.get_config_setting_value("auth", "kasm_auth_domain")
            same_site = self._db.get_config_setting_value("auth", "same_site")
            if kasm_auth_domain:
                if kasm_auth_domain.lower() == "$request_host$":
                    kasm_auth_domain = cherrypy.request.headers["HOST"]
            cherrypy.response.cookie["session_token"] = session_jwt
            cherrypy.response.cookie["session_token"]["Path"] = "/"
            cherrypy.response.cookie["session_token"]["Max-Age"] = session_lifetime
            cherrypy.response.cookie["session_token"]["Domain"] = kasm_auth_domain
            cherrypy.response.cookie["session_token"]["Secure"] = True
            cherrypy.response.cookie["session_token"]["httpOnly"] = True
            cherrypy.response.cookie["session_token"]["SameSite"] = same_site
            cherrypy.response.cookie["username"] = user.username
            cherrypy.response.cookie["username"]["Path"] = "/"
            cherrypy.response.cookie["username"]["Max-Age"] = session_lifetime
            cherrypy.response.cookie["username"]["Domain"] = kasm_auth_domain
            cherrypy.response.cookie["username"]["Secure"] = True
            cherrypy.response.cookie["username"]["httpOnly"] = True
            cherrypy.response.cookie["username"]["SameSite"] = same_site
        else:
            response["error_message"] = "Invalid session token"
            self.logger.info("Invalid session token used to request a new token for user (%s)" % user.username)
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
                msg = f"DevAPI Key ({cherrypy.request.api_key_id}) made invalid call to impersonate a user without providing a user_id."
            else:
                msg = "Invalid Request"
        else:
            self.logger.error(msg)
            response["error_message"] = msg
            cherrypy.response.status = 400
            return response
            if user.get_setting_value("max_kasms_per_user") is None:
                max_kasms = 2
            else:
                max_kasms = int(user.get_setting_value("max_kasms_per_user"))
            if max_kasms == 0 or kasms and len(kasms) >= max_kasms:
                msg = "Kasm limit exceeded for user: (%s)" % user.username
                self.logger.warning(msg)
                response["error_message"] = msg
        if not check_usage(user):
            if self.is_usage_limit_licensed(self.logger):
                msg = "Usage limit exceeded for user: (%s)" % user.username
                self.logger.warning(msg)
                response["error_message"] = msg
        if not license_helper.is_per_named_user_ok(): # comment lines 1221 to 1224 to remove
            msg = "Per named user license limit exceeded. Unable to create Kasm"
            self.logger.error(msg)
            response["error_message"] = msg
        else:
            if not license_helper.is_per_concurrent_kasm_ok(): # comment lines 1226 to 1230 to remove
                msg = "Per concurrent session license limit exceeded. Unable to create session"
                self.logger.error(msg)
                response["error_message"] = msg
            else:
                allow_zone_selection = user.get_setting_value("allow_zone_selection", False)
                selected_zone = None
                selected_zone_id = event.get("zone_id")
        if allow_zone_selection:
            if selected_zone_id:
                try:
                    uuid.UUID(selected_zone_id)
                except:
                    msg = "Invalid zone_id (%s)" % event.get("zone_id")
                    self.logger.error(msg)
                    response["error_message"] = msg
                    return                     return response
                else:
                    selected_zone = cherrypy.request.db.getZoneById(selected_zone_id)
                    if selected_zone:
                        self.logger.debug("Using selected zone (%s)" % selected_zone.zone_name)
                    else:
                        msg = "Invalid zone_id (%s)" % selected_zone_id
                        self.logger.error(msg)
                        response["error_message"] = msg
                        return response
                image = None
                if event.get("image_id"):
                    image = cherrypy.request.db.getImage(event["image_id"])
                if image is not None:
                    if image.is_user_authorized(user):
                        user_language = None
                        user_timezone = None
                        if user:
                            persistent_profile_mode = event.get("persistent_profile_mode")
                            image.persistent_profile_mode = None
                            if persistent_profile_mode in image.get_persistent_profile_permissions(user):
                                image.persistent_profile_mode = persistent_profile_mode
                            for kasm in kasms:
                                if kasm.image.image_id == image.image_id and kasm.is_persistent_profile and image.persistent_profile_mode in ('Enabled',
                                                                                                                                              'Reset'):
                                    _msg = "A persistent profile is currently in use with Kasm:%s , Image: %s , Status: %s." % (
                                     str(kasm.kasm_id)[None[:6]],
                                     kasm.image.friendly_name,
                                     kasm.operational_status)
                                    self.logger.error(_msg)
                                    response["error_message"] = _msg
                                    return response
                            else:
                                user_language = user.user_attributes[0].preferred_language
                                if user_language:
                                    if user_language.lower() == "auto":
                                        user_language = event.get("client_language")
                                    elif user_language in LANGUAGE_MAPPING_TO_TERRITORIES.keys():
                                        user_language = LANGUAGE_MAPPING_TO_TERRITORIES[user_language]
                                    try:
                                        LANGUAGES(user_language)
                                    except ValueError:
                                        self.logger.warning(f"Incompatible value used for language: {user_language} setting language to en_US.UTF-8.")
                                        user_language = LANGUAGES.English0_United_States_of_America.value

                                user_timezone = user.user_attributes[0].preferred_timezone

                            if user_timezone:
                                if user_timezone.lower() == "auto":
                                    user_timezone = event.get("client_timezone")
                                try:
                                    TIMEZONES(user_timezone)
                                except ValueError:
                                    self.logger.warning(f"Incompatible value used for timezone: {user_timezone} setting timezone to Etc/UTC.")
                                    user_timezone = TIMEZONES.UTCplus00___00.value

                        launch_selections = event.get("launch_selections")
                        if launch_selections:
                            launch_selections, validation_errors = image.is_valid_launch_selections(launch_selections)
                            if validation_errors:
                                _msg = "User-specified launch_selections are invalid: %s" % validation_errors
                                self.logger.error(_msg)
                                response["error_message"] = _msg
                                return response
                        if image.is_server and image.server and image.server.enabled:
                            res = self.provider_manager.get_session_from_server(image, (image.server),
                              user,
                              (cherrypy.request.authenticated_user_ip),
                              cast_config,
                              user_language=user_language,
                              user_timezone=user_timezone,
                              launch_selections=launch_selections)
                            if res.get("kasm"):
                                response["kasm_id"] = str(res.get("kasm").kasm_id)
                                response["status"] = "starting"
                                return response
                            if res.get("error_message"):
                                msg = res.get("error_message")
            else:
                msg = "Undefined Error requesting Kasm"
            self.logger.error(("%s : %s" % (msg, res.get("error_detail"))), extra={'metric_name':"provision.failed", 
             'provision.failed.reason':(res.get)("error_detail")})
            response["error_message"] = msg
            if is_admin:
                response["error_detail"] = res.get("error_detail")
            return response
        else:
            if image.is_server:
                if image.server:
                    if not image.server.enabled:
                        response["error_message"] = "The requested server is disabled."
                        self.logger.warning(f"A user requested a Workspace ({image.image_id}) that is pointed to a server that is disabled.")
                        return response
            if image.is_server:
                if not image.server:
                    response["error_message"] = "The server this Workspaces is associated with no longer exists."
                    self.logger.warning(f"A user requested a Workspace ({image.image_id}) that is pointed to a server that does not exist.")
                    return response
            if image.is_server_pool:
                res = self.provider_manager.get_session_from_server_pool(image, user,
                  (cherrypy.request.db.getZone(self.zone_name)),
                  selected_zone,
                  (cherrypy.request.authenticated_user_ip),
                  cast_config,
                  user_language=user_language,
                  user_timezone=user_timezone,
                  launch_selections=launch_selections)
                if res.get("kasm"):
                    response["kasm_id"] = str(res.get("kasm").kasm_id)
                    response["status"] = "starting"
                    return response
                elif res.get("error_message"):
                    msg = res.get("error_message")
                else:
                    msg = "Undefined Error requesting Kasm"
                self.logger.error(("%s : %s" % (msg, res.get("error_detail"))), extra={'metric_name':"provision.failed", 
                 'provision.failed.reason':(res.get)("error_detail")})
                response["error_message"] = msg
                if is_admin:
                    response["error_detail"] = res.get("error_detail")
                return response
            user_vars = event.get("environment")
            if user_vars and type(user_vars) is dict and not cherrypy.request.is_api:
                for k, v in user_vars.copy().items():
                    if not k.startswith("USRVAR_"):
                        user_vars.pop(k)
                    elif "environment" in image.run_config:
                        image.run_config["environment"].update(user_vars)
                    else:
                        image.run_config["environment"] = user_vars

            return response

    @staticmethod
    @ttl_cache(maxsize=200, ttl=30)
    def kasm_connect_cache(session_token, username, kasm_id):
        ret = {'log':{'level':None, 
          'message':None}, 
         'port_map':None, 
         'kasm_server_hostname':None}
        auth_enabled = cherrypy.request.db.get_config_setting_value("auth", "enable_kasm_auth")
        if auth_enabled is not None and auth_enabled.lower() == "true":
            if username and session_token:
                if validate_session_token_ex(session_token, username):
                    user = cherrypy.request.db.getUser(username)
                    if user:
                        cherrypy.request.authenticated_user = user
                        cherrypy.request.kasm_user_id = str(user.user_id)
                        cherrypy.request.kasm_user_name = user.username
                        kasm = cherrypy.request.db.getKasm(kasm_id)
                        if kasm and not kasm.user_id == user.user_id:
                            if not kasm.share_id or kasm.kasm_id in [x.kasm_id for x in user.session_permissions]:
                                if kasm.image.is_container:
                                    ret["connection_type"] = CONNECTION_TYPE.KASMVNC.value
                                    ret["port_map"] = kasm.get_port_map()
                                    ret["connect_address"] = kasm.server.hostname
                                else:
                                    if kasm.server.is_rdp or kasm.server.is_vnc or kasm.server.is_ssh:
                                        ret["connection_type"] = kasm.server.connection_type
                                        connection_proxy = None
                                        connection_proxies = cherrypy.request.db.get_connection_proxies(zone_id=(kasm.server.zone_id),
                                          connection_proxy_type=(CONNECTION_PROXY_TYPE.GUAC.value))
                                        random.shuffle(connection_proxies)
                                        for x in connection_proxies:
                                            if is_healthy(url=("https://%s:%s/guac/__healthcheck" % (
                                             x.server_address,
                                             x.server_port))):
                                                connection_proxy = x
                                                break
                                        else:
                                            if not connection_proxy:
                                                connection_proxy = connection_proxies[0]
                                            ret["connect_address"] = connection_proxy.server_address
                                            ret["connect_port"] = connection_proxy.server_port
                                            ret["port_map"] = kasm.get_port_map()

                                if kasm.server.is_kasmvnc:
                                    ret["connection_type"] = kasm.server.connection_type
                                    ret["port_map"] = kasm.get_port_map()
                                    ret["connect_address"] = kasm.server.hostname
                            else:
                                ret["log"]["level"] = logging.WARNING
                                ret["log"]["message"] = "Unauthorized access attempt to kasm_id (%s) by user (%s)" % (
                                 kasm.kasm_id, user.username)
                        else:
                            ret["log"]["level"] = logging.WARNING
                            ret["log"]["message"] = "Invalid kasm_id (%s)" % kasm_id
                    else:
                        ret["log"]["level"] = logging.ERROR
                        ret["log"]["message"] = "Invalid User (%s)" % username
                else:
                    if username == "kasm_api_user":
                        kasm = cherrypy.request.db.getKasm(kasm_id)
                        if kasm:
                            if kasm.api_token and session_token == kasm.api_token:
                                ret["port_map"] = kasm.get_port_map()
                                ret["connect_address"] = kasm.server.hostname
                            else:
                                ret["log"]["level"] = logging.WARNING
                                ret["log"]["message"] = "Unauthorized attempt to use kasm_api_user"
                        else:
                            ret["log"]["level"] = logging.WARNING
                            ret["log"]["message"] = "Invalid kasm_id (%s)" % kasm_id
                    else:
                        ret["log"]["level"] = logging.WARNING
                        ret["log"]["message"] = "Invalid session token presented for user (%s)" % username
            else:
                ret["log"]["level"] = logging.WARNING
                ret["log"]["message"] = "Missing username or session token and kasm authorization is enabled"
        else:
            kasm = cherrypy.request.db.getKasm(kasm_id)
            if kasm:
                ret["port_map"] = kasm.get_port_map()
                ret["connect_address"] = kasm.server.hostname
            else:
                ret["log"]["level"] = logging.WARNING
                ret["log"]["message"] = "Invalid kasm_id (%s)" % kasm_id
        return ret

    @cherrypy.expose
    @CookieAuthenticated(requested_actions=[JWT_AUTHORIZATION.USER])
    def kasm_connectParse error at or near `CALL_FINALLY' instruction at offset 132

    def decode_jwt(self, token):
        try:
            pub_cert = str.encode(self._db.get_config_setting_value_cached("auth", "api_public_cert"))
            decoded_jwt = jwt.decode(token, pub_cert, algorithm="RS256")
        except jwt.exceptions.DecodeError:
            return
        else:
            return decoded_jwt

    @cherrypy.expose()
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    @JwtAuthenticated(authorizations=[JWT_AUTHORIZATION.GUAC])
    def guac_get_deleted_kasms(self):
        event = cherrypy.request.json
        response = {}
        connection_proxy_id = cherrypy.request.decoded_jwt.get("connection_proxy_id", None)
        requested_kasms = event.get("kasms")
        if requested_kasms:
            if connection_proxy_id:
                connection_proxy = cherrypy.request.db.get_connection_proxy(connection_proxy_id)
                if connection_proxy:
                    kasms = cherrypy.request.db.getKasmsIn(requested_kasms, "running")
                    response["running_kasms"] = [x.kasm_id.hex for x in kasms]
                    response["deleted_kasms"] = [x for x in requested_kasms if x not in response["running_kasms"]]
            else:
                msg = "Connection Proxy by id (%s) not found" % connection_proxy_id
                self.logger.error(msg)
                response["error_message"] = msg
        else:
            msg = "Error. Missing required parameters"
            self.logger.error(msg)
            response["error_message"] = msg
        return response

    @cherrypy.expose()
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    @JwtAuthenticated(authorizations=[JWT_AUTHORIZATION.GUAC])
    def guac_get_managers(self):
        event = cherrypy.request.json
        response = {}
        connection_proxy_id = cherrypy.request.decoded_jwt.get("connection_proxy_id", None)
        connection_proxy = cherrypy.request.db.get_connection_proxy(connection_proxy_id)
        if connection_proxy:
            response = {"hostnames": []}
            managers = cherrypy.request.db.getManagers(zone_name=(connection_proxy.zone.zone_name))
            for manager in managers:
                d = cherrypy.request.db.serializable(manager.jsonDict)
                response["hostnames"].append(d["manager_hostname"])

        else:
            msg = "Connection Proxy by id (%s) not found" % connection_proxy_id
            self.logger.error(msg)
            response["error_message"] = msg
        return cherrypy.request.db.serializable(response)

    @cherrypy.expose()
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    @Authenticated(requested_actions=[JWT_AUTHORIZATION.USER], read_only=True)
    def guac_auth(self):
        event = cherrypy.request.json
        user = cherrypy.request.authenticated_user
        response = {}
        kasm_id = event.get("kasm_id")
        service = event.get("service")
        connection_proxy_auth_token = event.get("auth_token")
        try:
            pub_cert = str.encode(cherrypy.request.db.get_config_setting_value_cached("auth", "api_public_cert"))
            decoded_jwt = jwt.decode(connection_proxy_auth_token, pub_cert, algorithm="RS256")
            authorized = False
            if "authorizations" in decoded_jwt:
                for authorization in decoded_jwt["authorizations"]:
                    if JWT_AUTHORIZATION.is_authorized(authorization, [JWT_AUTHORIZATION.GUAC]):
                        authorized = True

        except jwt.exceptions.DecodeError:
            self.logger.error("Error decoding JWT token")
            response["error_message"] = "Access Denied."
            cherrypy.response.status = 403
            return             return response
        except jwt.exceptions.ExpiredSignatureError:
            self.logger.error("Error, expired JWT token")
            response["error_message"] = "Access Denied."
            cherrypy.response.status = 403
            return             return response
        else:
            if authorized:
                connection_proxy_id = decoded_jwt.get("connection_proxy_id", None)
                connection_proxy = cherrypy.request.db.get_connection_proxy(connection_proxy_id)
                if connection_proxy:
                    kasm = cherrypy.request.db.getKasm(kasm_id)
                    if kasm and kasm.user.username == user.username:
                        if kasm.server.connection_info:
                            connection_info = kasm.server.connection_info.copy()
            elif kasm.server.is_rdp:
                connection_info = json.loads(self._db.get_config_setting_value("connections", "default_vm_rdp_connection_settings"))
            else:
                if kasm.server.is_vnc:
                    connection_info = json.loads(self._db.get_config_setting_value("connections", "default_vm_vnc_connection_settings"))
                else:
                    if kasm.server.is_ssh:
                        connection_info = json.loads(self._db.get_config_setting_value("connections", "default_vm_ssh_connection_settings"))
                    else:
                        msg = "Unknown connection type"
                        self.logger.error(msg)
                        response["error_message"] = msg
                        return response
            username = ""
            password = ""
            private_key = ""
        if kasm.server.max_simultaneous_sessions == 1:
            username = kasm.server.connection_username
            password = kasm.server.connection_password
        else:
            if kasm.server.connection_username:
                if not "{sso_username}" in kasm.server.connection_username:
                    if "{sso_create_user}" in kasm.server.connection_username or kasm.server.is_ssh:
                        username = kasm.server.connection_username
                    if not (kasm.server.connection_password and "{sso_cred}" in kasm.server.connection_password):
                        if kasm.server.is_ssh:
                            password = kasm.server.connection_password
                        if username is None:
                            username = ""
                        if password is None:
                            password = ""
                        if kasm.server.is_ssh:
                            if kasm.server.use_user_private_key:
                                private_key = kasm.user.user_attributes[0].ssh_private_key
                            else:
                                private_key = kasm.server.connection_private_key
                    if "{sso_username}" in username:
                        username = kasm.server.get_connection_username(user)
                    if password.strip() == "{sso_cred}":
                        kasm_client_key = event.get("kasm_client_key")
                        if kasm_client_key and user.sso_ep:
                            password = self.decrypt_client_data(kasm_client_key.encode(), user.sso_ep)
                            self.logger.debug(f"SSO credential passthrough completed for {username}.")
                        else:
                            if user.sso_ep:
                                password = ""
                                self.logger.warning(f"Client {user.username} guac_auth connection set to use SSO but no client key cookie present.")
                            else:
                                password = ""
                                self.logger.warning(f"Client {user.username} guac_auth connection set to use SSO but no sso_ep set.")
                    if username == "{sso_create_user}":
                        username = kasm.server.get_connection_username(user)
                        password = kasm.connection_credential
                    if "guac" not in connection_info:
                        connection_info["guac"] = {}
                    if "settings" not in connection_info["guac"]:
                        connection_info["guac"]["settings"] = {}
                    connection_info["guac"]["settings"]["username"] = username
                    connection_info["guac"]["settings"]["password"] = password
                    if kasm.server.is_ssh:
                        if private_key:
                            connection_info["guac"]["settings"]["private-key"] = private_key
                        if kasm.server.connection_passphrase:
                            connection_info["guac"]["settings"]["passphrase"] = kasm.server.connection_passphrase
                    connection_info["guac"]["settings"]["hostname"] = kasm.server.hostname
                    connection_info["guac"]["settings"]["port"] = kasm.server.connection_port
                    if kasm.connection_info and "guac" in kasm.connection_info and "settings" in kasm.connection_info["guac"]:
                        if "remote-app" in kasm.connection_info["guac"]["settings"] and "" in kasm.connection_info["guac"]["settings"]["remote-app"]:
                            connection_info["guac"]["settings"]["remote-app"] = kasm.connection_info["guac"]["settings"]["remote-app"]
                            if "remote-app-args" in kasm.connection_info["guac"]["settings"]:
                                connection_info["guac"]["settings"]["remote-app-args"] = kasm.connection_info["guac"]["settings"]["remote-app-args"]
                                self.logger.info(f'RemoteApp ({connection_info["guac"]["settings"]["remote-app"]}) being called with arguments ({connection_info["guac"]["settings"]["remote-app-args"]})')
                else:
                    self.logger.info(f'RemoteApp ({connection_info["guac"]["settings"]["remote-app"]}) being called without arguments.')
                if "timezone" in kasm.connection_info["guac"]["settings"].keys():
                    if "timezone" not in connection_info["guac"]["settings"]:
                        self.logger.debug(f'Setting user timezone: {kasm.connection_info["guac"]["settings"]["timezone"]}')
                        connection_info["guac"]["settings"]["timezone"] = kasm.connection_info["guac"]["settings"]["timezone"]
            elif "locale" in kasm.connection_info["guac"]["settings"].keys():
                if "locale" not in connection_info["guac"]["settings"]:
                    self.logger.debug(f'Setting user locale: {kasm.connection_info["guac"]["settings"]["locale"]}')
                    connection_info["guac"]["settings"]["locale"] = kasm.connection_info["guac"]["settings"]["locale"]
            if "printer-name" in kasm.connection_info["guac"]["settings"].keys() and "printer-name" not in connection_info["guac"]["settings"]:
                self.logger.debug(f'Setting printer name: {kasm.connection_info["guac"]["settings"]["printer-name"]}')
                connection_info["guac"]["settings"]["printer-name"] = kasm.connection_info["guac"]["settings"]["printer-name"]
            if "remote-app" in kasm.connection_info["guac"]["settings"] and not "" in kasm.connection_info["guac"]["settings"]["remote-app"] or "timezone" in kasm.connection_info["guac"]["settings"].keys():
                if not "locale" in kasm.connection_info["guac"]["settings"].keys():
                    self.logger.warning("A Kasm session utilizing guac has a connection_info defined without specifying any supported connection settings.")
                response["connection_info"] = connection_info
                priv_key = str.encode(cherrypy.request.db.get_config_setting_value_cached("auth", "api_private_key"))
                response["jwt_token"] = generate_jwt_token({'system_username':username,  'username':user.username,  'user_id':str(user.user_id)}, [JWT_AUTHORIZATION.USER], priv_key, expires_days=4095)
                response["client_secret"] = generate_guac_client_secret(self.installation_id, str(user.user_id))
                settings = cherrypy.request.db.get_default_client_settings(user, kasm.cast_config_id)
                response["client_settings"] = {'allow_kasm_uploads':settings["allow_kasm_uploads"], 
                 'allow_kasm_downloads':settings["allow_kasm_downloads"], 
                 'allow_kasm_clipboard_up':settings["allow_kasm_clipboard_up"], 
                 'allow_kasm_clipboard_down':settings["allow_kasm_clipboard_down"], 
                 'allow_kasm_clipboard_seamless':settings["allow_kasm_clipboard_seamless"], 
                 'allow_kasm_audio':settings["allow_kasm_audio"], 
                 'allow_kasm_microphone':settings["allow_kasm_microphone"], 
                 'allow_kasm_printing':settings["allow_kasm_printing"]}
                if user.get_setting_value("record_sessions", False) and self.is_session_recording_licensed(self.logger):
                    storage_key = cherrypy.request.db.get_config_setting_value("session_recording", "recording_object_storage_key")
                    storage_secret = cherrypy.request.db.get_config_setting_value("session_recording", "recording_object_storage_secret")
                    storage_location_url = cherrypy.request.db.get_config_setting_value("session_recording", "session_recording_upload_location")
                    framerate = cherrypy.request.db.get_config_setting_value("session_recording", "session_recording_framerate")
                    width = cherrypy.request.db.get_config_setting_value("session_recording", "session_recording_res_width")
                    height = cherrypy.request.db.get_config_setting_value("session_recording", "session_recording_res_height")
                    bitrate = cherrypy.request.db.get_config_setting_value("session_recording", "session_recording_bitrate")
                    queue_length = cherrypy.request.db.get_config_setting_value("session_recording", "session_recording_queue_length")
                    retention_period = cherrypy.request.db.get_config_setting_value("session_recording", "session_recording_retention_period")
                    disk_usage_limit = cherrypy.request.db.get_config_setting_value("session_recording", "session_recording_guac_disk_limit")
                    if storage_key and storage_secret and storage_location_url and framerate and width and height and bitrate:
                        if queue_length:
                            if retention_period:
                                if disk_usage_limit:
                                    response["record_sessions"] = user.get_setting_value("record_sessions", False)
                                    response["session_recording_framerate"] = framerate
                                    response["session_recording_width"] = width
                                    response["session_recording_height"] = height
                                    response["session_recording_bitrate"] = bitrate
                                    response["session_recording_queue_length"] = queue_length
                                    response["session_recording_retention_period"] = retention_period
                                    response["session_recording_guac_disk_limit"] = disk_usage_limit
                                else:
                                    msg = "Session recording is enabled, but not all session recording settings are present. Aborting session"
                                    self.logger.error(msg)
                                    response["error_message"] = msg
                                    return response
                            else:
                                response["record_sessions"] = False
                                if user.get_setting_value("record_sessions", False):
                                    self.logger.error("Session recording is configured but not licensed. Will not enable.")
                                kasm.connection_proxy_id = connection_proxy_id
                                cherrypy.request.db.updateKasm(kasm)
                        else:
                            if not kasm:
                                msg = f"Kasm not found {kasm_id}"
                                self.logger.error(msg)
                                response["error_message"] = msg
                            else:
                                msg = "Invalid User for Kasm"
                                self.logger.error(msg)
                                response["error_message"] = msg
                    else:
                        msg = "Missing required parameters"
                        self.logger.error(msg)
                        response["error_message"] = msg
                else:
                    self.logger.error(f"Invalid JWT token utilized on guac_auth: {decoded_jwt}")
                    response["error_message"] = "Access Denied!"
            return response

    @cherrypy.expose
    @CookieAuthenticated(requested_actions=[JWT_AUTHORIZATION.USER])
    def internal_authParse error at or near `CALL_FINALLY' instruction at offset 222

    @cherrypy.expose()
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    @Authenticated(requested_actions=[JWT_AUTHORIZATION.USER], read_only=True)
    def join_kasm(self):
        return self._join_kasm()

    def _join_kasmParse error at or near `POP_BLOCK' instruction at offset 402

    @cherrypy.expose()
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    @Authenticated(requested_actions=[JWT_AUTHORIZATION.USER], read_only=True)
    def get_recent_kasms(self):
        event = cherrypy.request.json
        response = {'viewed_kasms':[],  'dead_kasms':[]}
        if "kasms" in event:
            for share_kasm in event["kasms"]:
                _kasm = {}
                kasm = cherrypy.request.db.getSharedKasm(share_kasm)
                if kasm is not None:
                    _kasm["image"] = kasm.image.friendly_name
                    _kasm["image_src"] = kasm.image.image_src
                    _kasm["user"] = kasm.user.username
                    _kasm["share_id"] = kasm.share_id
                    response["viewed_kasms"].append(_kasm)
                else:
                    response["dead_kasms"].append(share_kasm)
            else:
                return response

    @cherrypy.expose()
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    @Authenticated(requested_actions=[JWT_AUTHORIZATION.USER], read_only=True)
    def get_kasm_frame_statsParse error at or near `POP_BLOCK' instruction at offset 354

    @cherrypy.expose()
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    @Authenticated(requested_actions=[JWT_AUTHORIZATION.USER], read_only=True)
    def get_kasm_bottleneck_statsParse error at or near `POP_BLOCK' instruction at offset 334

    @cherrypy.expose(["get_kasm_screenshot"])
    @CookieAuthenticated(requested_actions=[JWT_AUTHORIZATION.USER])
    def get_kasm_screenshot(self, kasm_id='', width=300, height=300):
        cherrypy.response.status = 404
        kasm = cherrypy.request.db.getKasm(kasm_id)
        if kasm:
            if cherrypy.request.authenticated_user.user_id == kasm.user.user_id:
                target_filename = "/tmp/{0}.jpg".format(uuid.uuid4().hex)
                try:
                    content = None
                    if not (kasm.image.is_container or kasm.image.is_server):
                        if kasm.image.is_server_pool:
                            if kasm.server.is_kasmvnc:
                                query = "get_screenshot?width={0}&height={1}".format(width, height)
                                resp = self._kasmvnc_api(query, kasm, True, "get")
                                content = resp.content
                    elif (kasm.server.is_rdp or kasm.server).connection_info:
                        if "kasm_svc" in kasm.server.connection_info:
                            query = "screenshot?width={0}&height={1}".format(width, height)
                            success, data = self._kasm_host_svc_api(query, kasm, True, "post", timeout=5)
                            if success:
                                content = data
                    cherrypy.response.headers["Content-Type"] = "image/jpg"
                    cherrypy.response.status = 200
                    return                     return content
                            except Exception as e:
                    try:
                        cherrypy.response.status = 500
                        self.logger.error("Error requesting screenshot from kasm (%s) with error (%s)" % (
                         kasm_id, e))
                    finally:
                        e = None
                        del e

            else:
                self.logger.warning("get_kasm_screenshot, user (%s) attempted to get a screenshot of user (%s)." % (
                 str(cherrypy.request.authenticated_user.user_id), str(kasm.user.user_id)))
                cherrypy.response.status = 404
        else:
            self.logger.warning("get_kasm_screenshot could not find kasm by id: %s", kasm_id)
            cherrypy.response.status = 404

    @cherrypy.expose(["get_user_kasm"])
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    @Authenticated(requested_actions=[JWT_AUTHORIZATION.USER], read_only=True)
    @func_timing
    def get_kasm_statusParse error at or near `POP_BLOCK' instruction at offset 450

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    @Authenticated(requested_actions=[JWT_AUTHORIZATION.USER], read_only=False)
    def exec_kasm(self):
        event = cherrypy.request.json
        response = {}
        if "target_kasm" in event:
            target_kasm = event["target_kasm"]
            if "kasm_id" in target_kasm and "kasm_exec" in target_kasm:
                kasm = cherrypy.request.db.getKasm(target_kasm["kasm_id"])
                user = cherrypy.request.authenticated_user
                kasm_exec = target_kasm["kasm_exec"]
                kasm_url = target_kasm.get("kasm_url", "")
                response = self._exec_kasm(kasm, user, kasm_exec, kasm_url)
            else:
                msg = "Missing required parameters"
                self.logger.error(msg)
                response["error_message"] = msg
        else:
            msg = "Missing required parameters"
            self.logger.error(msg)
            response["error_message"] = msg
        return response

    def _exec_kasmParse error at or near `POP_BLOCK' instruction at offset 236

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
            logout_all = event.get("logout_all")
            if logout_all:
                cherrypy.request.db.remove_all_session_tokens(user)
            else:
                cherrypy.request.db.remove_session_token(session_token_id)
                cherrypy.request.db.remove_expired_session_tokens(user)
            if user.sso_ep:
                user.sso_ep = None
                cherrypy.request.db.updateUser(user)
            if "saml_id" in event:
                config = cherrypy.request.db.get_saml_config(event["saml_id"])
                if config is not None:
                    if config.idp_slo_url is not None:
                        saml = SamlAuthentication(cherrypy.request, config, "/api/slo")
                        name_id = user.username
                        response["slo_url"] = saml.slo(name_id, "")
        except Exception as e:
            try:
                self.logger.exception("Exception removing user (%s) token during logout %s" % (event["username"], e))
                response["error_message"] = "Logout Error"
            finally:
                e = None
                del e

        else:
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
            response["user_image"] = cherrypy.request.db.serializable(user_image.default_image)
        group_image = user.get_setting_value("default_image")
        if group_image is not None:
            response["group_image"] = group_image
        return response

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    @Authenticated(requested_actions=[JWT_AUTHORIZATION.USER], read_only=True)
    def get_user_attributes(self):
        response = {}
        response["user_attributes"] = self.get_attributes_for_user(cherrypy.request.authenticated_user)
        return response

    def get_attributes_for_user(self, user):
        attr = cherrypy.request.db.getUserAttributes(user)
        res = {'user_attributes_id':(cherrypy.request.db.serializable)(attr.user_attributes_id), 
         'default_image':(cherrypy.request.db.serializable)(attr.default_image), 
         'show_tips':(cherrypy.request.db.serializable)(attr.show_tips), 
         'auto_login_kasm':(cherrypy.request.db.serializable)(attr.user_login_to_kasm), 
         'user_id':(cherrypy.request.db.serializable)(attr.user_id), 
         'toggle_control_panel':(cherrypy.request.db.serializable)(attr.toggle_control_panel), 
         'theme':(cherrypy.request.db.serializable)(attr.theme), 
         'chat_sfx':(cherrypy.request.db.serializable)(attr.chat_sfx), 
         'ssh_public_key':(cherrypy.request.db.serializable)(attr.ssh_public_key), 
         'preferred_language':(cherrypy.request.db.serializable)(attr.preferred_language), 
         'preferred_timezone':(cherrypy.request.db.serializable)(attr.preferred_timezone)}
        return res

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    @Authenticated(requested_actions=[JWT_AUTHORIZATION.USER], read_only=False)
    def update_user_attribute(self):
        return self._update_user_attribute()

    def _update_user_attributeParse error at or near `POP_BLOCK' instruction at offset 444

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    @Authenticated(requested_actions=[JWT_AUTHORIZATION.USER], read_only=False)
    def keepalive(self):
        event = cherrypy.request.json
        user = cherrypy.request.authenticated_user
        response = {}
        if "kasm_id" in event:
            if event.get("kasm_id"):
                kasm = cherrypy.request.db.getKasm(event["kasm_id"])
                if kasm:
                    if kasm.user.username == event["username"]:
                        return self._keepalive(kasm, user)
                    self.logger.error("Invalid user for kasm_id (%s) for keepalive request for user (%s)" % (
                     event["kasm_id"], event["username"]))
                    response["error_message"] = "Keepalive Error"
            else:
                self.logger.warning("Invalid kasm_id (%s) for keepalive request for user (%s)" % (
                 event["kasm_id"], event["username"]))
                response["error_message"] = "Keepalive Error"
        else:
            self.logger.error("Missing kasm_id for keepalive request for user (%s)" % event["username"])
            response["error_message"] = "Keepalive Error"
        return response

    def _keepalive(self, kasm, user):
        response = {}
        kasm_status = kasm.get_operational_status()
        if kasm_status not in (SESSION_OPERATIONAL_STATUS.DELETING, SESSION_OPERATIONAL_STATUS.ADMIN_DELETE_PENDING, SESSION_OPERATIONAL_STATUS.DELETE_PENDING, SESSION_OPERATIONAL_STATUS.PAUSING, SESSION_OPERATIONAL_STATUS.STOPPING):
            try:
                if kasm.image.session_time_limit:
                    self.logger.info("Image has a session_time_limit of (%s) defined. Will not promote keepalive" % kasm.image.session_time_limit)
                else:
                    if user.get_setting_value("session_time_limit", None) is not None:
                        self.logger.info("User has a session_time_limit of (%s) defined. Will not promote keepalive" % user.get_setting_value("session_time_limit", None))
                    else:
                        keepalive_expiration = user.get_setting_value("keepalive_expiration")
                        if not keepalive_expiration:
                            keepalive_expiration = int(self._db.get_config_setting_value("scale", "keepalive_expiration"))
                            self.logger.info("No group-level level keepalive_expiration setting defined. Using global value of (%s)" % keepalive_expiration)
                        else:
                            self.logger.debug("Using group-level keepalive_expiration of (%s)" % keepalive_expiration)
                        if not check_usage(user):
                            msg = "Usage limit exceeded for user: (%s)" % user.username
                            self.logger.warning(msg)
                            response["usage_reached"] = True
                        else:
                            response["usage_reached"] = False
                            kasm.keepalive_date = datetime.datetime.utcnow()
                            kasm.expiration_date = kasm.keepalive_date + datetime.timedelta(seconds=keepalive_expiration)
                            cherrypy.request.db.updateKasm(kasm)
                            self.logger.info("Set keepalive for kasm_id (%s) at (%s) for user (%s) from IP (%s) " % (
                             str(kasm.kasm_id),
                             kasm.container_ip,
                             user.username,
                             cherrypy.request.authenticated_user_ip))
            except Exception as e:
                try:
                    self.logger.exception("Exception updating keepalive for kasm_id (%s) user (%s) keepalive_date %s" % (
                     kasm.kasm_id, user.username, e))
                    response["error_message"] = "Keepalive Error"
                finally:
                    e = None
                    del e

        else:
            _msg = "Kasm (%s) is currently scheduled to be deleted. Can not honor keepalive request" % str(kasm.kasm_id[None[:6]])
            self.logger.error(_msg)
            response["error_message"] = _msg
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
        if "kasm_id" in event:
            kasm = cherrypy.request.db.getKasm(event["kasm_id"])
            if not kasm or JWT_AUTHORIZATION.is_authorized_action(cherrypy.request.authorizations, JWT_AUTHORIZATION.SESSIONS_DELETE) or kasm.user.user_id == user.user_id:
                if JWT_AUTHORIZATION.is_authorized_action(cherrypy.request.authorizations, JWT_AUTHORIZATION.SESSIONS_DELETE) or user.get_setting_value("allow_kasm_delete", True) == True:
                    if not kasm.image.is_container:
                        if kasm.operational_status != SESSION_OPERATIONAL_STATUS.DELETING or kasm.image.is_container:
                            if kasm.operational_status in (
                             SESSION_OPERATIONAL_STATUS.RUNNING.value,
                             SESSION_OPERATIONAL_STATUS.STOPPED.value,
                             SESSION_OPERATIONAL_STATUS.PAUSED.value,
                             SESSION_OPERATIONAL_STATUS.SAVING.value,
                             SESSION_OPERATIONAL_STATUS.STARTING.value,
                             SESSION_OPERATIONAL_STATUS.PROVISIONING.value,
                             SESSION_OPERATIONAL_STATUS.ASSIGNED.value,
                             SESSION_OPERATIONAL_STATUS.REQUESTED.value,
                             SESSION_OPERATIONAL_STATUS.DELETING.value):
                                cherrypy.request.kasm_id = str(kasm.kasm_id)
                                try:
                                    if kasm.user:
                                        if kasm.user.user_id == user.user_id:
                                            _role = "user"
                                        else:
                                            _role = "admin"
                                    elif kasm.operational_status == SESSION_OPERATIONAL_STATUS.DELETING:
                                        self.logger.info(f"Kasm ({kasm.kasm_id}) is being forcefully destroyed, currently in a deleting state.")
                                    if kasm.image.is_server_pool:
                                        if kasm.server:
                                            if kasm.server.server_pool:
                                                if not kasm.server.is_reusable:
                                                    self.logger.info("Server (%s) : (%s) is a member of a node pool and is not reusable. Deleting" % (
                                                     kasm.server.server_id,
                                                     kasm.server.hostname))
                                                    kasm.server.operational_status = "delete_pending"
                                                    cherrypy.request.db.updateServer(kasm.server)
                                                self.provider_manager.destroy_kasm(kasm, reason=("%s_destroyed" % _role))
                                            else:
                                                self.logger.warning("Kasm (%s) : Status (%s) has no server assigned. Deleting" % (
                                                 kasm.kasm_id,
                                                 kasm.operational_status))
                                                self.provider_manager.destroy_kasm(kasm, reason=("%s_destroyed" % _role))
                                        else:
                                            pass
                                    self.provider_manager.destroy_kasm(kasm, reason=("%s_destroyed" % _role))
                                except Exception as e:
                                    try:
                                        if "username" in event:
                                            username = event["username"]
                                        else:
                                            if kasm.user and kasm.user.user_id == user.user_id:
                                                username = kasm.user.username
                                            else:
                                                username = "Admin"
                                        self.logger.exception(f"Exception during user ({username}) destroy : {e}")
                                        response["error_message"] = "Destroy Error"
                                    finally:
                                        e = None
                                        del e

                        if not kasm.image.is_container:
                            if kasm.server.agent_installed and kasm.operational_status == SESSION_OPERATIONAL_STATUS.DELETING and JWT_AUTHORIZATION.is_authorized_action(cherrypy.request.authorizations, JWT_AUTHORIZATION.SESSIONS_DELETE):
                                cherrypy.request.db.deleteKasm(kasm)
                                self.logger.warning(f"Session ({kasm.kasm_id}) was forcefully removed by administrator.")
                            else:
                                msg = "Session is not in a valid state to be deleted"
                                self.logger.error(msg)
                                response["error_message"] = msg
                        else:
                            msg = "User is not authorized to issue a delete request"
                            self.logger.error(msg)
                            response["error_message"] = msg
                    else:
                        msg = "Unauthorized attempt to delete session"
                        self.logger.error(msg)
                        response["error_message"] = msg
                else:
                    msg = "No session found with kasm_id (%s)" % event["kasm_id"]
                    self.logger.error(msg)
                    response["error_message"] = msg
        else:
            response["error_message"] = "Invalid Request"
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
        if "kasm_id" in event:
            kasm = cherrypy.request.db.getKasm(event["kasm_id"])
            is_admin = JWT_AUTHORIZATION.is_authorized_action(cherrypy.request.authorizations, JWT_AUTHORIZATION.SESSIONS_MODIFY)
            if kasm:
                if is_admin or kasm.user.user_id == user.user_id:
                    if is_admin or user.get_setting_value("allow_kasm_stop", False) == True:
                        if kasm.image.is_container:
                            if kasm.operational_status in (SESSION_OPERATIONAL_STATUS.RUNNING.value,
                             SESSION_OPERATIONAL_STATUS.PAUSED.value):
                                cherrypy.request.kasm_id = str(kasm.kasm_id)
                                try:
                                    res, async_destroy = self.provider_manager.stop_kasm(kasm)
                                    if res and async_destroy:
                                        self.logger.info("Successfully stopped session (%s)" % kasm.kasm_id)
                                    else:
                                        if res:
                                            self.logger.info(f"Successfully queued session for stopping ({kasm.kasm_id})")
                                        else:
                                            msg = "Failed to stop session (%s)" % kasm.kasm_id
                                            response["error_message"] = msg
                                            self.logger.error(msg)
                                except Exception as e:
                                    try:
                                        if "username" in event:
                                            username = event["username"]
                                        else:
                                            if kasm.user and kasm.user.user_id == user.user_id:
                                                username = kasm.user.username
                                            else:
                                                username = "Admin"
                                        self.logger.exception(f"Exception during user ({username}) session stop : {e}")
                                        response["error_message"] = "Unexpected error encountered during stop request"
                                    finally:
                                        e = None
                                        del e

                            else:
                                msg = "Session is not in a valid state to be stopped"
                                self.logger.error(msg)
                                response["error_message"] = msg
                        else:
                            msg = "Only Container based sessions can be stopped"
                            self.logger.error(msg)
                            response["error_message"] = msg
                    else:
                        msg = "User is not authorized to issue a stop request"
                        self.logger.error(msg)
                        response["error_message"] = msg
                else:
                    msg = "Unauthorized attempt to stop session"
                    self.logger.error(msg)
                    response["error_message"] = msg
            else:
                msg = "No session found with kasm_id (%s)" % event["kasm_id"]
                self.logger.error(msg)
                response["error_message"] = msg
        else:
            response["error_message"] = "Invalid Request"
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
        kasm_id = event.get("kasm_id")
        is_admin = JWT_AUTHORIZATION.is_authorized_action(cherrypy.request.authorizations, JWT_AUTHORIZATION.SESSIONS_MODIFY)
        if kasm_id:
            kasm = cherrypy.request.db.getKasm(kasm_id)
            if kasm:
                if is_admin or kasm.user.user_id == user.user_id:
                    if is_admin or user.get_setting_value("allow_kasm_pause", False) == True:
                        if kasm.image.is_container:
                            if kasm.operational_status == SESSION_OPERATIONAL_STATUS.RUNNING.value:
                                cherrypy.request.kasm_id = str(kasm.kasm_id)
                                try:
                                    res, async_destroy = self.provider_manager.pause_kasm(kasm)
                                    if res:
                                        async_destroy or self.logger.info("Successfully paused session (%s)" % kasm.kasm_id)
                                    else:
                                        if res:
                                            self.logger.info(f"Successfully queued session for pausing ({kasm.kasm_id})")
                                        else:
                                            msg = "Failed to pause session (%s)" % kasm.kasm_id
                                            response["error_message"] = msg
                                except Exception as e:
                                    try:
                                        if "username" in event:
                                            username = event["username"]
                                        else:
                                            if kasm.user and kasm.user.user_id == user.user_id:
                                                username = kasm.user.username
                                            else:
                                                username = "Admin"
                                        self.logger.exception(f"Exception during user ({username}) session pause : {e}")
                                        response["error_message"] = "Unexpected error encountered during pause request"
                                    finally:
                                        e = None
                                        del e

                            else:
                                msg = "Session is not in a valid state to be paused"
                                self.logger.error(msg)
                                response["error_message"] = msg
                        else:
                            msg = "Only Container based sessions can be paused"
                            self.logger.error(msg)
                            response["error_message"] = msg
                    else:
                        msg = "User is not authorized to issue a pause request"
                        self.logger.error(msg)
                        response["error_message"] = msg
                else:
                    msg = "Unauthorized attempt to pause session"
                    self.logger.error(msg)
                    response["error_message"] = msg
            else:
                msg = "No session found with kasm_id (%s)" % kasm_id
                self.logger.error(msg)
                response["error_message"] = msg
        else:
            response["error_message"] = "Invalid Request"
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
        kasm_id = event.get("kasm_id")
        license_helper = LicenseHelper(cherrypy.request.db, self.logger)
        if license_helper.is_per_concurrent_kasm_ok():
            if kasm_id:
                kasm = cherrypy.request.db.getKasm(kasm_id)
                is_admin = JWT_AUTHORIZATION.is_authorized_action(cherrypy.request.authorizations, JWT_AUTHORIZATION.SESSIONS_MODIFY)
                if not kasm is not None or is_admin or kasm.user.user_id == user.user_id:
                    if kasm.image.is_container:
                        cherrypy.request.kasm_id = str(kasm.kasm_id)
                        try:
                            if kasm.operational_status in (SESSION_OPERATIONAL_STATUS.STOPPED.value,
                             SESSION_OPERATIONAL_STATUS.PAUSED.value) or is_admin:
                                res, error_message = self.provider_manager.resume_kasm(kasm)
                                if res:
                                    self.logger.info("Successfully resumed session (%s)" % kasm.kasm_id)
                                else:
                                    msg = "Failed to resume session (%s) : %s" % (kasm.kasm_id, error_message)
                                    response["error_message"] = msg
                            else:
                                msg = "Session (%s) is in status (%s) and cannot be resumed" % (kasm.kasm_id,
                                 kasm.operational_status)
                                self.logger.error(msg)
                                response["error_message"] = msg
                        except Exception as e:
                            try:
                                if "username" in event:
                                    username = event["username"]
                                else:
                                    if kasm.user and kasm.user.user_id == user.user_id:
                                        username = kasm.user.username
                                    else:
                                        username = "Admin"
                                self.logger.exception(f"Exception during user ({username}) resume : {e}")
                                response["error_message"] = "Unexpected error encountered during resume request"
                            finally:
                                e = None
                                del e

                    else:
                        msg = "Only Container based sessions can be resumed"
                        self.logger.error(msg)
                        response["error_message"] = msg
            else:
                response["error_message"] = "Invalid Request"
        else:
            msg = "Per concurrent session license limit exceeded. Unable to resume Session"
            self.logger.error(msg)
            response["error_message"] = msg
        return response

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    @Authenticated(requested_actions=[JWT_AUTHORIZATION.USER], read_only=True)
    def get_user_images(self):
        event = cherrypy.request.json
        user = cherrypy.request.db.getUser(event["username"])
        result = []
        all_categories = []
        images = self._get_user_images(user)
        for image_id in images.keys():
            images[image_id]["image_id"] = image_id
            result.append(images[image_id])
            all_categories += images[image_id]["categories"]
        else:
            all_categories = list(set(all_categories))
            all_categories = sorted(all_categories, key=(lambda x: x.lower()))
            return {'images':(cherrypy.request.db.serializable)(result), 
             'all_categories':all_categories, 
             'disabled_image_message':(user.get_setting_value)("disabled_image_message", "")}

    def _get_user_images(self, user):
        data = dict()
        show_disabled_images = user.get_setting_value("show_disabled_images", False)
        images = user.get_images(only_enabled=(not show_disabled_images))
        zones = []
        all_network_names = None
        allow_zone_selection = user.get_setting_value("allow_zone_selection", False)
        if allow_zone_selection:
            zones.append({'zone_id':"",  'zone_name':"Auto"})
            all_zones = cherrypy.request.db.getZones()
            if all_zones:
                for zone in sorted(all_zones, key=(lambda x: x.zone_name.lower())):
                    zones.append({'zone_id':zone.zone_id,  'zone_name':zone.zone_name})

        for image in images:
            _zones = zones
            _image_networks = []
            if allow_zone_selection:
                if image.restrict_to_zone:
                    if image.zone_id:
                        _zones = [
                         {'zone_id':"", 
                          'zone_name':"Auto"},
                         {'zone_id':str(image.zone_id), 
                          'zone_name':(image.zone).zone_name}]
            if image.allow_network_selection:
                if image.restrict_to_network:
                    _image_networks = [
                     {'network_id':"", 
                      'network_name':"Auto"}]
                    for n in image.restrict_network_names:
                        _image_networks.append({'network_id':n,  'network_name':n})

                else:
                    if all_network_names == None:
                        _network_names = self._get_network_names()
                        all_network_names = [{'network_id':"",  'network_name':"Auto"}]
                        for n in _network_names:
                            all_network_names.append({'network_id':n,  'network_name':n})
                        else:
                            _image_networks = all_network_names

                    else:
                        _image_networks = all_network_names
            data[cherrypy.request.db.serializable(image.image_id)] = {'name':image.name,  'friendly_name':image.friendly_name, 
             'description':image.description, 
             'image_src':image.image_src, 
             'available':image.available if (image.is_container) else True, 
             'cores':image.cores, 
             'memory':image.memory, 
             'memory_friendly':"%sMB" % (int(int(image.memory) / 1000000)), 
             'persistent_profile_settings':(image.get_persistent_profile_permissions)(user), 
             'zones':_zones, 
             'networks':_image_networks, 
             'categories':image.categories, 
             'default_category':image.default_category, 
             'enabled':image.enabled, 
             'hidden':image.hidden, 
             'image_type':image.image_type, 
             'link_url':image.link_url, 
             'launch_config':image.launch_config}
        else:
            return data

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    @Authenticated(requested_actions=[JWT_AUTHORIZATION.USER], read_only=True)
    def get_user_kasms(self):
        user = cherrypy.request.authenticated_user
        response = {'kasms':[],  'current_time':str(datetime.datetime.utcnow())}
        for kasm in cherrypy.request.db.get_kasms(user):
            response["kasms"].append(self.get_normalized_kasm(kasm))
        else:
            return cherrypy.request.db.serializable(response)

    def get_normalized_kasm(self, kasm):
        _kasm = cherrypy.request.db.serializable((kasm.__dict__), skip_fields=["user", "image", "docker_environment"])
        _kasm["is_persistent_profile"] = kasm.is_persistent_profile
        _kasm["persistent_profile_mode"] = kasm.persistent_profile_mode
        _kasm["port_map"] = kasm.get_port_map()
        _kasm["token"] = ""
        _kasm["view_only_token"] = ""
        _kasm.pop("api_token", None)
        try:
            _kasm["host"] = gethostbyname(kasm.server.hostname) if (kasm.server and kasm.server.hostname) else None
        except gaierror as e:
            try:
                self.logger.warning("Unable to resolve the address kasm's agents name (%s). This may result in the Kasm being inaccessible." % kasm.server.hostname)
                _kasm["host"] = kasm.server.hostname if kasm.server else None
            finally:
                e = None
                del e

        else:
            _kasm["port"] = kasm.server.port if kasm.server else None
            _kasm["image"] = {'image_id':(kasm.image).image_id, 
             'name':(kasm.image).name, 
             'friendly_name':(kasm.image).friendly_name, 
             'image_src':(kasm.image).image_src, 
             'session_time_limit':(kasm.image).session_time_limit, 
             'categories':(kasm.image).categories, 
             'default_category':(kasm.image).default_category, 
             'image_type':(kasm.image).image_type}
            if kasm.operational_status in (SESSION_OPERATIONAL_STATUS.REQUESTED.value,
             SESSION_OPERATIONAL_STATUS.PROVISIONING.value,
             SESSION_OPERATIONAL_STATUS.ASSIGNED.value,
             SESSION_OPERATIONAL_STATUS.STARTING.value):
                _kasm["client_settings"] = []
            else:
                _kasm["client_settings"] = cherrypy.request.db.filter_client_settings_by_connection_type(cherrypy.request.db.get_default_client_settings(kasm.user, kasm.cast_config_id) if kasm.user else {}, kasm.connection_type)
        if kasm.image.is_container or kasm.image.is_server_pool:
            if kasm.server and kasm.server.zone.proxy_connections:
                if kasm.server.zone.proxy_hostname and kasm.server.zone.proxy_hostname.lower() == "$request_host$":
                    _kasm["hostname"] = cherrypy.request.headers["HOST"]
                else:
                    _kasm["hostname"] = kasm.server.zone.proxy_hostname
                for k, v in _kasm["port_map"].items():
                    _kasm["port_map"][k]["path"] = "{}/{}/{}".format(kasm.server.zone.proxy_path, str(kasm.kasm_id), k)
                    _kasm["port_map"][k]["port"] = kasm.server.zone.proxy_port

            else:
                _kasm["hostname"] = kasm.server.hostname if kasm.server else None
        else:
            if kasm.server.zone.proxy_hostname and kasm.server.zone.proxy_hostname.lower() == "$request_host$":
                _kasm["hostname"] = cherrypy.request.headers["HOST"]
            else:
                _kasm["hostname"] = kasm.server.zone.proxy_hostname
            for k, v in _kasm["port_map"].items():
                _kasm["port_map"][k]["path"] = "{}/{}/{}".format(kasm.server.zone.proxy_path, str(kasm.kasm_id), k)
                _kasm["port_map"][k]["port"] = kasm.server.zone.proxy_port
            else:
                return cherrypy.request.db.serializable(_kasm)

    def get_normalized_shared_kasm(self, kasm, user):
        _kasm = {}
        _kasm["port_map"] = kasm.get_port_map()
        _kasm["view_only_token"] = ""
        _kasm["user"] = {"username": (kasm.user.username)}
        if "uploads" in _kasm["port_map"]:
            del _kasm["port_map"]["uploads"]
        if "audio_input" in _kasm["port_map"]:
            del _kasm["port_map"]["audio_input"]
        if "webcam" in _kasm["port_map"]:
            del _kasm["port_map"]["webcam"]
        try:
            _kasm["host"] = gethostbyname(kasm.server.hostname)
        except gaierror as e:
            try:
                self.logger.warning("Unable to resolve the address kasm's agents name (%s). This may result in the Kasm being inaccessible." % kasm.server.hostname)
                _kasm["host"] = kasm.server.hostname
            finally:
                e = None
                del e

        else:
            _kasm["kasm_id"] = kasm.kasm_id
            _kasm["share_id"] = kasm.share_id
            _kasm["port"] = kasm.server.port
            _kasm["image"] = {'image_id':(kasm.image).image_id, 
             'name':(kasm.image).name, 
             'friendly_name':(kasm.image).friendly_name, 
             'image_src':(kasm.image).image_src, 
             'session_time_limit':(kasm.image).session_time_limit}
            _kasm["client_settings"] = cherrypy.request.db.filter_client_settings_by_connection_type(cherrypy.request.db.get_default_client_settings(user) if user else {}, kasm.connection_type)
            if kasm.server.zone.proxy_connections:
                if kasm.server.zone.proxy_hostname and kasm.server.zone.proxy_hostname.lower() == "$request_host$":
                    _kasm["hostname"] = cherrypy.request.headers["HOST"]
                else:
                    _kasm["hostname"] = kasm.server.zone.proxy_hostname
                for k, v in _kasm["port_map"].items():
                    _kasm["port_map"][k]["path"] = "{}/{}/{}".format(kasm.server.zone.proxy_path, str(kasm.kasm_id), k)
                    _kasm["port_map"][k]["port"] = kasm.server.zone.proxy_port

            else:
                _kasm["hostname"] = kasm.server.hostname
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
        if "target_user" in event:
            target_user = event["target_user"]
            if "user_id" in target_user:
                user = cherrypy.request.db.get_user_by_id(target_user["user_id"])
                if user:
                    is_admin = JWT_AUTHORIZATION.is_user_authorized_action((cherrypy.request.authenticated_user), (cherrypy.request.authorizations), (JWT_AUTHORIZATION.USERS_MODIFY), target_user=user)
                    if not is_admin:
                        if not cherrypy.request.authenticated_user or cherrypy.request.authenticated_user.user_id == target_user["user_id"]:
                            if not target_user.get("username"):
                                response["error_message"] = "Username is not present"
                    elif target_user.get("password"):
                        remove_tokens = True
                        if user.realm not in ('local', 'ldap'):
                            response["error_message"] = "Passwords can only be set on local and ldap accounts."
                        pwr = passwordComplexityCheck(target_user["password"])
                        if not pwr["status"]:
                            response["error_message"] = pwr["message"]
                    if target_user.get("company_id"):
                        if cherrypy.request.db.getCompany(company_id=(target_user["company_id"])):
                            user.company_id = target_user["company_id"]
        else:
            response["error_message"] = "Company does not exist by id (%s)" % target_user["company_id"]
        group = None
        if target_user.get("program_id"):
            group = cherrypy.request.db.getGroup(program_id=(target_user["program_id"]))
            if group:
                user.program_id = target_user.get("program_id")
            else:
                msg = "Unknown program_id (%s)" % target_user.get("program_id")
                self.logger.error(msg)
                response["error_message"] = msg
        else:
            status = target_user.get("status")
            if status:
                if status == "active":
                    target_user["locked"] = False
                else:
                    if status == "inactive":
                        target_user["locked"] = True
                    else:
                        msg = "Invalid Status (%s)" % status
                        self.logger.error(msg)
                        response["error_message"] = msg
        if not response.get("error_message"):
            if target_user.get("username"):
                user.username = target_user["username"].strip().lower()[None[:255]]
            if target_user.get("password"):
                if user.realm == "local":
                    user.salt = str(uuid.uuid4())
                    user.pw_hash = hashlib.sha256((target_user["password"] + user.salt).encode()).hexdigest()
                    user.locked = False
                    user.password_set_date = datetime.datetime.utcnow()
                    self.logger.info(f"User ({user.username}) local password successfully changed.", extra={"metric_name": "account.password_reset.successful"})
                else:
                    if user.realm == "ldap":
                        ldap_configs = cherrypy.request.db.get_ldap_configs()
                        for ldap_config in ldap_configs:
                            if ldap_config.enabled:
                                ldap_auth = LDAPAuthentication(ldap_config)
                                if ldap_auth.match_domain(user.username):
                                    ldap_response = ldap_auth.set_password(user.username, target_user["password"])
                                    if ldap_response.error:
                                        response["error_message"] = ldap_response.error
                                        self.logger.warning(("Password reset attempted failed for user: (%s) because: (%s)" % (user.username, ldap_response.error)), extra={"metric_name": "account.password_reset.failed_ldap_error"})
                            else:
                                self.logger.info(f"User ({user.username}) ldap password successfully changed.", extra={"metric_name": "account.password_reset.successful"})
                        else:
                            if target_user.get("first_name") != None:
                                user.first_name = target_user["first_name"][None[:64]]
                            elif target_user.get("last_name") != None:
                                user.last_name = target_user["last_name"][None[:64]]
                            else:
                                if target_user.get("phone") != None:
                                    user.phone = target_user["phone"][None[:64]]
                                elif target_user.get("organization") != None:
                                    user.organization = target_user["organization"][None[:64]]
                                if target_user.get("notes") != None:
                                    user.notes = target_user["notes"]
                                if target_user.get("city") != None:
                                    user.city = target_user["city"]
                                if target_user.get("state") != None:
                                    user.state = target_user["state"]
                                if target_user.get("country") != None:
                                    user.country = target_user["country"]
                                if target_user.get("email") != None:
                                    user.email = target_user["email"]
                                if target_user.get("custom_attribute_1") != None:
                                    user.custom_attribute_1 = target_user["custom_attribute_1"]
                                if target_user.get("custom_attribute_2") != None:
                                    user.custom_attribute_2 = target_user["custom_attribute_2"]
                                if target_user.get("custom_attribute_3") != None:
                                    user.custom_attribute_3 = target_user["custom_attribute_3"]
                                if is_admin:
                                    if target_user.get("realm") != None:
                                        user.realm = target_user["realm"]
                                    if target_user.get("locked"):
                                        user.locked = True
                                    else:
                                        if target_user.get("locked") == False:
                                            user.locked = False
                                            user.failed_pw_attempts = 0
                                        if target_user.get("force_password_reset", False) == True:
                                            user.password_set_date = None
                                    if target_user.get("disabled") != None:
                                        user.disabled = target_user["disabled"]
                                if target_user.get("set_two_factor") is not None:
                                    if target_user.get("set_two_factor") is True:
                                        user.set_two_factor = False
                                        user.secret = ""
                                    if target_user.get("reset_webauthn"):
                                        user.set_two_factor = False
                                        cherrypy.request.db.delete_webauthn_credentials(user.user_id)
                                    cherrypy.request.db.updateUser(user)
                                    if remove_tokens:
                                        cherrypy.request.db.remove_all_session_tokens(user)
                                    if group:
                                        if group.group_id not in user.get_group_ids():
                                            self.logger.debug("Adding user (%s) to Group: name(%s), ID (%s)" % (
                                             user.user_id, group.name, group.group_id))
                                            cherrypy.request.db.addUserGroup(user, group)
                                        for user_group in user.groups:
                                            if user_group.group.program_data:
                                                if user_group.group.program_data.get("program_id") != target_user["program_id"]:
                                                    self.logger.debug("Removing user (%s) from Group: name(%s), ID (%s)" % (user.user_id, user_group.group.name, user_group.group.group_id))
                                                    cherrypy.request.db.removeUserGroup(user, user_group.group)
                                                else:
                                                    response["user"] = cherrypy.request.db.serializable({'user_id':user.user_id, 
                                                     'username':user.username, 
                                                     'locked':user.locked, 
                                                     'disabled':user.disabled, 
                                                     'last_session':user.last_session, 
                                                     'groups':(user.get_groups)(), 
                                                     'first_name':user.first_name, 
                                                     'last_name':user.last_name, 
                                                     'phone':user.phone, 
                                                     'organization':user.organization, 
                                                     'notes':user.notes, 
                                                     'realm':user.realm})
                                                    self.logger.debug("Updated User ID (%s)" % target_user["user_id"])

                                    else:
                                        if public:
                                            cherrypy.response.status = 400
                                else:
                                    pass
                                response["error_message"] = "Unauthorized"
                                self.logger.warning(f"User ({cherrypy.request.kasm_user_id}) attempted to make unauthorized update to user ({user.user_id})")
                                cherrypy.response.status = 401

                    else:
                        response["error_message"] = "Unknown User"
                        if public:
                            cherrypy.response.status = 400
            else:
                response["error_message"] = "Invalid Request"
                if public:
                    cherrypy.response.status = 400
        else:
            response["error_message"] = "Invalid Request"
            if public:
                cherrypy.response.status = 400
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
        if "target_user" in event:
            target_user = event["target_user"]
            user = None
            if "user_id" in target_user:
                target_user_id = None
                try:
                    target_user_id = uuid.UUID(target_user["user_id"])
                except:
                    pass
                else:
                    if target_user_id:
                        user = cherrypy.request.db.get_user_by_id(target_user["user_id"])
        elif "username" in target_user:
            user = cherrypy.request.db.getUser(target_user["username"])
        if user:
            is_admin = JWT_AUTHORIZATION.is_user_authorized_action((cherrypy.request.authenticated_user), (cherrypy.request.authorizations), (JWT_AUTHORIZATION.USERS_VIEW), target_user=user)
            if not (is_admin or cherrypy.request).authenticated_user or cherrypy.request.authenticated_user.user_id == user.user_id:
                kasms = []
                if not (JWT_AUTHORIZATION.is_authorized_action(cherrypy.request.authorizations, JWT_AUTHORIZATION.SESSIONS_VIEW) or cherrypy.request).authenticated_user or cherrypy.request.authenticated_user.user_id == user.user_id:
                    for kasm in user.kasms:
                        kasms.append({'kasm_id':kasm.kasm_id, 
                         'start_date':kasm.start_date, 
                         'keepalive_date':kasm.keepalive_date, 
                         'expiration_date':kasm.expiration_date, 
                         'server':{'server_id':kasm.server.server_id if (kasm.server) else None, 
                          'hostname':kasm.server.hostname if (kasm.server) else None, 
                          'port':kasm.server.port if (kasm.server) else None}})
                    else:
                        two_factor = user.get_setting_value("require_2fa", False)
                        response["user"] = cherrypy.request.db.serializable({'user_id':user.user_id, 
                         'username':user.username, 
                         'locked':user.locked, 
                         'disabled':user.disabled, 
                         'last_session':user.last_session, 
                         'groups':(user.get_groups)(), 
                         'first_name':user.first_name, 
                         'last_name':user.last_name, 
                         'phone':user.phone, 
                         'organization':user.organization, 
                         'notes':user.notes, 
                         'kasms':kasms, 
                         'realm':user.realm, 
                         'two_factor':two_factor, 
                         'program_id':user.program_id, 
                         'created':user.created, 
                         'password_set_date':user.password_set_date, 
                         'city':user.city, 
                         'state':user.state, 
                         'country':user.country, 
                         'email':user.email, 
                         'custom_attribute_1':user.custom_attribute_1, 
                         'custom_attribute_2':user.custom_attribute_2, 
                         'custom_attribute_3':user.custom_attribute_3})
                        self.logger.debug("Fetched User ID (%s)" % user.user_id)

                else:
                    response["error_message"] = "Unauthorized"
                    cherrypy.response.status = 401
                    self.logger.error(f"User ({cherrypy.request.kasm_user_name}) is not authorized to view target user ({target_user}).")
            else:
                pass
        if "error_message" not in response:
            self.logger.warning(f"Unable to locate target_user ({target_user}).")
            response["error_message"] = "Invalid Request"
            if public:
                cherrypy.response.status = 400
        else:
            if "error_message" not in response:
                response["error_message"] = "Invalid Request"
                self.logger.warning("Request is missing required target_user.")
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
        if "target_user" in event:
            if "user_id" in event["target_user"]:
                target_user = event["target_user"]
                target_user_id = None
                try:
                    target_user_id = uuid.UUID(target_user["user_id"])
                except:
                    pass
                else:
                    if target_user_id:
                        user = cherrypy.request.db.get_user_by_id(target_user["user_id"])
                        if user:
                            is_admin = JWT_AUTHORIZATION.is_user_authorized_action((cherrypy.request.authenticated_user), (cherrypy.request.authorizations), (JWT_AUTHORIZATION.USERS_VIEW), target_user=user)
                            if not is_admin:
                                if not cherrypy.request.authenticated_user or cherrypy.request.authenticated_user.user_id == target_user_id:
                                    response["permissions"] = [cherrypy.request.db.serializable(x.jsonDict) for x in user.get_group_permissions() if x.permission]
                            else:
                                cherrypy.response.status = 401
                                response["error_message"] = "Unauthorized"
                        else:
                            response["error_message"] = "Invalid Request"
                            self.logger.warning(f"Unable to find requested user by id ({target_user_id}).")
                            if cherrypy.request.is_api:
                                cherrypy.response.status = 400
            else:
                response["error_message"] = "Invalid Request"
                self.logger.warning("Request is missing required target_user_id or id passed was invalid.")
                if cherrypy.request.is_api:
                    cherrypy.response.status = 400
        else:
            response["error_message"] = "Invalid Request"
            self.logger.warning("Request is missing required target_user field.")
            if cherrypy.request.is_api:
                cherrypy.response.status = 400
            return response

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    @Authenticated(requested_actions=[JWT_AUTHORIZATION.USER], read_only=True)
    def license_status(self):
        response = {"license": {}}
        license_helper = LicenseHelper(cherrypy.request.db, self.logger)
        response["license"]["status"] = license_helper.effective_license.dump()
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
        if self.is_allow_kasm_sharing_licensed(self.logger):
            if "kasm_id" in event:
                kasm = cherrypy.request.db.getKasm(event["kasm_id"])
                user = cherrypy.request.authenticated_user
                if kasm is not None:
                    if kasm.user_id == user.user_id:
                        if not user.get_setting_value("allow_kasm_sharing", False):
                            self.logger.error("Sharing is not allowed for this (%s)" % kasm.user.username)
                            response["error_message"] = "Sharing is not allowed for this (%s)" % kasm.user.username
                            return response
                        elif kasm.share_id is None:
                            kasm.share_id = uuid.uuid4().hex[None[:8]]
                            cherrypy.request.db.updateKasm(kasm)
                            response["share_id"] = kasm.share_id
                        else:
                            message = "A share_id already exists for Kasm (%s)" % kasm.share_id
                            self.logger.error(message)
                            response["error_message"] = message
                    else:
                        self.logger.error("User (%s) attempted create_kasm_share_id for Kasm (%s) which is owned by user (%s)" % (user.user_id,
                         kasm.kasm_id,
                         kasm.user_id))
                        response["error_message"] = "Access Denied"
                else:
                    self.logger.error("create_kasm_share_link could not find kasm by id: %s", event["kasm_id"])
                    response["error_message"] = "Could not find requested Kasm."
            else:
                msg = "Missing required parameters"
                self.logger.error(msg)
                response["error_message"] = msg
        else:
            msg = "Access Denied. This feature is not licensed"
            self.logger.error(msg)
            response["error_message"] = msg
        return response

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    @Authenticated(requested_actions=[JWT_AUTHORIZATION.USER], read_only=True)
    def get_kasm_share_id(self):
        event = cherrypy.request.json
        response = {}
        if "kasm_id" in event:
            kasm = cherrypy.request.db.getKasm(event["kasm_id"])
            user = cherrypy.request.authenticated_user
            if kasm is not None:
                if kasm.user_id == user.user_id:
                    if not kasm.share_id:
                        response["share_id"] = kasm.share_id
                else:
                    self.logger.error("User (%s) attempted get_kasm_share_id for Kasm (%s) which is owned by user (%s)" % (user.user_id,
                     kasm.kasm_id,
                     kasm.user_id))
                    response["error_message"] = "Access Denied"
            else:
                self.logger.error("get_kasm_share_id could not find kasm by id: %s", event["kasm_id"])
                response["error_message"] = "Could not find requested Kasm."
        else:
            msg = "Missing required parameters"
            self.logger.error(msg)
            response["error_message"] = msg
        return response

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    @Authenticated(requested_actions=[JWT_AUTHORIZATION.USER], read_only=False)
    def delete_kasm_share_id(self):
        event = cherrypy.request.json
        response = {}
        if "kasm_id" in event:
            kasm = cherrypy.request.db.getKasm(event["kasm_id"])
            user = cherrypy.request.authenticated_user
            if kasm is not None:
                if kasm.user_id == user.user_id:
                    if kasm.share_id is not None:
                        kasm.share_id = None
                        cherrypy.request.db.updateKasm(kasm)
                        response["share_id"] = kasm.share_id
                        session_permissions = cherrypy.request.db.get_session_permissions(kasm_id=(kasm.kasm_id))
                        cherrypy.request.db.delete_session_permissions(session_permissions)
                        resp = self._kasmvnc_api("get_users", kasm, True, "get")
                        if resp.status_code == 200:
                            kasmvnc_users = json.loads(resp.content)
                            self.logger.error(f"KasmVNC Response: {kasmvnc_users}")
                            for k_user in kasmvnc_users:
                                if "user" in k_user and k_user["user"] not in ('kasm_user',
                                                                               'kasm_viewer'):
                                    resp = self._kasmvnc_api(f'remove_user?name={k_user["user"]}', kasm, True, "get")
                                    if resp.status_code == 200:
                                        self.logger.debug(f'Successfully removed KasmVNC user ({k_user["user"]}) from Kasm session ({kasm.kasm_id})')
                                    else:
                                        self.logger.error(f'Error removing KasmVNC user ({k_user["user"]}) kasm session ({kasm.kasm_id})')

                        else:
                            self.logger.error(f"Error removing users from a shared session ({kasm.kasm_id}).")
                else:
                    self.logger.error("User (%s) attempted get_kasm_share_id for Kasm (%s) which is owned by user (%s)" % (
                     user.user_id,
                     kasm.kasm_id,
                     kasm.user_id))
                    response["error_message"] = "Access Denied"
            else:
                self.logger.error("get_kasm_share_id could not find kasm by id: %s", event["kasm_id"])
                response["error_message"] = "Could not find requested Kasm."
        else:
            msg = "Missing required parameters"
            self.logger.error(msg)
            response["error_message"] = msg
        return response

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    @Authenticated(requested_actions=[JWT_AUTHORIZATION.USER], read_only=True)
    def get_usage_details(self):
        response = {}
        user = cherrypy.request.authenticated_user
        limit = self.is_usage_limit_licensed(self.logger) and user.get_setting_value("usage_limit", False)
        response["usage_limit"] = limit
        start_date = (datetime.datetime.utcnow() + datetime.timedelta(days=(-30))).strftime("%Y-%m-%d 00:00:00")
        end_date = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        dump = cherrypy.request.db.getuserAccountDump(user.user_id, start_date, end_date)
        response["account_dump"] = [cherrypy.request.db.serializable(x.jsonDict) for x in dump]
        response["start_date"] = start_date
        response["end_date"] = end_date
        return response

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    @Authenticated(requested_actions=[JWT_AUTHORIZATION.USER], read_only=True)
    def get_usage_summary(self):
        response = {}
        user = cherrypy.request.authenticated_user
        limit = self.is_usage_limit_licensed(self.logger) and user.get_setting_value("usage_limit", False)
        response["usage_limit"] = limit
        if limit:
            usage_type = limit["type"]
            interval = limit["interval"]
            hours = limit["hours"]
            _used_hours, _dates = get_usage(user)
            response["usage_limit_remaining"] = hours - _used_hours
            response["usage_limit_type"] = usage_type
            response["usage_limit_interval"] = interval
            response["usage_limit_hours"] = hours
            response["usage_limit_start_date"] = _dates["start_date"]
            response["usage_limit_next_start_date"] = _dates["next_start_date"]
        group_metadata = user.get_setting_value("metadata", {})
        response["group_metadata"] = group_metadata
        return response

    @cherrypy.expose()
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    @Authenticated(requested_actions=[JWT_AUTHORIZATION.USER], read_only=False)
    def subscription_infoParse error at or near `POP_TOP' instruction at offset 420

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    @Authenticated(kasm=True, read_only=True)
    def get_url_cache(self):
        start = datetime.datetime.now()
        event = cherrypy.request.json
        response = {}
        if "kasm_id" in event:
            kasm = cherrypy.request.db.getKasm(event["kasm_id"])
            if kasm:
                cherrypy.request.kasm_id = kasm.kasm_id
                if kasm.user:
                    cherrypy.request.kasm_user_id = kasm.user.user_id
                    cherrypy.request.kasm_user_name = kasm.user.username
                url_filter_policy = None
                if not kasm.image.filter_policy_force_disabled:
                    if kasm.image.filter_policy_id:
                        url_filter_policy = kasm.image.filter_policy
                    else:
                        url_filter_policy_id = kasm.user.get_setting_value("web_filter_policy") if kasm.user else None
                        if url_filter_policy_id:
                            url_filter_policy = cherrypy.request.db.get_url_filter_policy(url_filter_policy_id)
                        else:
                            msg = "Url cache requested for non-existent kasm_id (%s)" % event["kasm_id"]
                            self.logger.error(msg)
                            response["error_message"] = msg
                            return response
                elif "filter_id" in event:
                    url_filter_policy = cherrypy.request.db.get_url_filter_policy(event["filter_id"])
            else:
                msg = "Missing kasm_id"
                self.logger.error(msg)
                response["error_message"] = msg
                return response
            if url_filter_policy:
                response["config"] = {'deny_by_default':url_filter_policy.deny_by_default,  'enable_categorization':url_filter_policy.enable_categorization, 
                 'redirect_url':url_filter_policy.redirect_url, 
                 'ssl_bypass_domains':url_filter_policy.ssl_bypass_domains or [], 
                 'ssl_bypass_ips':url_filter_policy.ssl_bypass_ips or [], 
                 'safe_search_patterns':url_filter_policy.safe_search_patterns if (url_filter_policy.enable_safe_search) else [], 
                 'disable_logging':url_filter_policy.disable_logging or False}
                cache = {}
                whitelist = []
                blacklist = []
                if url_filter_policy.domain_whitelist:
                    if type(url_filter_policy.domain_whitelist) == list:
                        whitelist = url_filter_policy.domain_whitelist
                if url_filter_policy.domain_blacklist:
                    if type(url_filter_policy.domain_blacklist) == list:
                        blacklist = url_filter_policy.domain_blacklist
                if url_filter_policy.enable_categorization:
                    domains = cherrypy.request.db.get_domains_ex(limit=10000)
                    default_allow = not url_filter_policy.deny_by_default
                    allow_categories, deny_categories = url_filter_policy.get_allow_categories(default_allow=default_allow)
                    for k, v in domains.items():
                        _whitelist_found = [x for x in whitelist if x in k]
                        _blacklist_found = [x for x in blacklist if x in k]

                    if not _blacklist_found:
                        if not _whitelist_found:
                            _categories = [ALL_CATEGORIES.get(x, {}).get("label", x) for x in list(set(v))]
                            allow = not deny_categories.intersection(v)
                            cache[k] = {'allow':allow, 
                             'category':(", ".join)(_categories)}
            elif whitelist:
                for x in url_filter_policy.domain_whitelist:
                    cache[x] = {'allow':True,  'category':"whitelist"}

        elif blacklist:
            for x in url_filter_policy.domain_blacklist:
                cache[x] = {'allow':False,  'category':"blacklist"}
            else:
                response["cache"] = cache

        else:
            msg = "URL cache request but no policy is assigned"
            self.logger.warning(msg)
            response["error_message"] = msg
        return response

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    @Authenticated(kasm=True, read_only=True)
    def filter_checkin(self):
        response = {'kasm_user_name':cherrypy.request.kasm_user_name if (hasattr(cherrypy.request, "kasm_user_name")) else "", 
         'kasm_user_id':cherrypy.request.kasm_user_id if (hasattr(cherrypy.request, "kasm_user_id")) else ""}
        return response

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    @Authenticated(kasm=True, read_only=True)
    def url_check(self):
        start = datetime.datetime.now()
        event = cherrypy.request.json
        response = {}
        if "url" in event:
            url = event["url"]
            domain = urlparse(url).netloc.split(":")[0]
            domain_split = domain.split(".")
            username = ""
            if domain:
                if "kasm_id" in event:
                    kasm = cherrypy.request.db.getKasm(event["kasm_id"])
                    if kasm:
                        cherrypy.request.kasm_id = kasm.kasm_id
                        if kasm.user:
                            cherrypy.request.kasm_user_id = kasm.user.user_id
                            cherrypy.request.kasm_user_name = kasm.user.username
                            username = kasm.user.username
                        url_filter_policy = None
                        if not kasm.image.filter_policy_force_disabled:
                            if kasm.image.filter_policy_id:
                                url_filter_policy = kasm.image.filter_policy
                            else:
                                url_filter_policy_id = kasm.user.get_setting_value("web_filter_policy") if kasm.user else None
                                if url_filter_policy_id:
                                    url_filter_policy = cherrypy.request.db.get_url_filter_policy(url_filter_policy_id)
                    else:
                        msg = "Unknown or invalid kasm_id (%s)" % event["kasm_id"]
                        self.logger.error(msg)
                        response["error_message"] = msg
            elif "filter_id" in event:
                url_filter_policy = cherrypy.request.db.get_url_filter_policy(event["filter_id"])
                username = "Fixed Proxy Server"
        else:
            msg = "Invalid Request. Missing kasm_id"
            self.logger.error(msg)
            response["error_message"] = msg
        if url_filter_policy:
            search_domains = [
             domain]
            if len(domain_split) >= 2:
                for x in range(1, len(domain_split)):
                    _d = ".".join(domain_split[(x * -1)[:None]])
                    search_domains.append(_d)
                else:
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
                            most_specific_blacklist_domains.sort(key=(lambda x: len(x.split("."))))
                            most_specific_blacklist_domain = most_specific_blacklist_domains[0]
                            most_specific_whitelist_domains = list(whitelist_match)
                            most_specific_whitelist_domains.sort(key=(lambda x: len(x.split("."))))
                            most_specific_whitelist_domain = most_specific_whitelist_domains[0]
                            if len(most_specific_blacklist_domain.split(".")) >= len(most_specific_whitelist_domain.split(".")):
                                whitelist_match = set()
                            else:
                                blacklist_match = set()
                        elif blacklist_match:
                            response["allow"] = False
                            response["redirect_url"] = url_filter_policy.redirect_url
                            response["category"] = "blacklist"
                            self.logger.warning("URL (%s) is denied from blacklist for User (%s) : (%s) : timing: (%s)ms" % (
                             url,
                             username,
                             response["allow"],
                             int(delta.total_seconds() * 1000)))
                            most_specific_domains = list(blacklist_match)
                            most_specific_domains.sort(key=(lambda x: len(x.split("."))))
                            most_specific_domain = most_specific_domains[0]
                        else:
                            if whitelist_match:
                                response["allow"] = True
                                response["category"] = "whitelist"
                                self.logger.debug("URL (%s) is allowed from whitelist for User (%s) : (%s) : timing: (%s)ms" % (
                                 url,
                                 username,
                                 response["allow"],
                                 int(delta.total_seconds() * 1000)))
                                most_specific_domains = list(whitelist_match)
                                most_specific_domains.sort(key=(lambda x: len(x.split("."))))
                                most_specific_domain = most_specific_domains[0]
                            else:
                                if url_filter_policy.enable_categorization:
                                    if self.kasm_web_filter is None:
                                        self.init_webfilter()
                                    else:
                                        domain_categories = self.kasm_web_filter.check_url("https://" + domain)
                                        if domain_categories:
                                            domain_categories = domain_categories["domains"]
                                            for _domain, _categories in domain_categories.items():
                                                self.logger.debug("Adding new domain categorization. Url (%s) Categories (%s)" % (
                                                 _domain, _categories))
                                                cherrypy.request.db.add_domains(_categories, [_domain], True)
                                            else:
                                                filtered_domains = [x for x in domain_categories.keys()]
                                                filtered_domains.sort(key=(lambda x: len(x.split("."))))
                                                most_specific_domain = filtered_domains[0]
                                                default_allow = not url_filter_policy.deny_by_default
                                                allow_categories, deny_categories = url_filter_policy.get_allow_categories(default_allow=default_allow)
                                                allow = not deny_categories.intersection(set(domain_categories[most_specific_domain]))
                                                delta = datetime.datetime.now() - start
                                                _categories = [ALL_CATEGORIES.get(x, {}).get("label", x) for x in list(set(domain_categories[most_specific_domain]))]
                                                response["category"] = ",".join(sorted(_categories))

                                            if allow:
                                                response["allow"] = True
                                                self.logger.debug("URL (%s) is allowed for User: (%s) policy categories matched: (%s)  timing: (%s)ms" % (
                                                 url,
                                                 username,
                                                 _categories,
                                                 int(delta.total_seconds() * 1000)))
                                        else:
                                            response["allow"] = False
                                        response["redirect_url"] = url_filter_policy.redirect_url
                                        self.logger.warning("URL (%s) is denied for User: (%s) policy categories matched: (%s) timing: (%s)ms" % (
                                         url,
                                         username,
                                         _categories,
                                         int(delta.total_seconds() * 1000)))
                                else:
                                    most_specific_domain = domain
                                    response["category"] = "none"
                                    if url_filter_policy.deny_by_default:
                                        response["allow"] = False
                                        response["redirect_url"] = url_filter_policy.redirect_url
                                        self.logger.warning("URL (%s) is denied by default for User (%s) : (%s) : timing: (%s)ms" % (
                                         url,
                                         username,
                                         response["allow"],
                                         int(delta.total_seconds() * 1000)))
                                    else:
                                        response["allow"] = True
                                        self.logger.debug("URL (%s) is allowed by default for User (%s) : (%s) : timing: (%s)ms" % (
                                         url,
                                         username,
                                         response["allow"],
                                         int(delta.total_seconds() * 1000)))
                        response["cache"] = most_specific_domain
                    else:
                        msg = "URL check request but no policy is assigned"
                        self.logger.warning(msg)
                        if "error_message" not in response:
                            response["error_message"] = msg

            else:
                msg = "Invalid URL (%s)" % url
                self.logger.error(msg)
                response["error_message"] = msg
        else:
            msg = "Invalid Request. Missing url"
            self.logger.error(msg)
            response["error_message"] = msg
        return response

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    @Authenticated(requested_actions=[JWT_AUTHORIZATION.USER], read_only=False)
    def ui_log(self):
        response = {}
        event = cherrypy.request.json
        for log in event.get("logs"):
            extra = log
            extra["application"] = "kasm_ui"
            message = extra.pop("message", "")
            level = extra.pop("level", "warning")
            level = logging._nameToLevel.get(level.upper(), "INFO")
            self.logger.log(level, message, extra=extra)
        else:
            return response

    def cast_validity_test(self, cast_config, event, client_ip):
        res = {'ok':True,  'error_message':""}
        if cast_config.require_recaptcha:
            if cast_config.allow_anonymous:
                recaptcha_value = event.get("recaptcha_value")
                if recaptcha_value:
                    recaptcha_respones = validate_recaptcha(recaptcha_value, self._db.get_config_setting_value("auth", "google_recaptcha_api_url"), self._db.get_config_setting_value("auth", "google_recaptcha_priv_key"))
                    if recaptcha_respones.get("status"):
                        self.logger.debug("Request passed reCAPTCHA request")
                    else:
                        res["ok"] = False
                        res["error_message"] = "reCAPTCHA Failed"
                        self.logger.warning("Request did not pass reCAPTCHA request", extra={'metric_name':"provision.cast.validate",  'validation_failure_reason':"recaptcha.failed"})
                        return res
                else:
                    res["ok"] = False
                    res["error_message"] = "recaptcha_needed"
                    res["google_recaptcha_site_key"] = self._db.get_config_setting_value("auth", "google_recaptcha_site_key")
                    self.logger.info("Request needs reCAPTCHA")
            else:
                self.logger.debug("No reCAPTCHA validation needed")
        elif cast_config.limit_sessions:
            if cast_config.session_remaining > 0:
                self.logger.debug("Cast Config has sessions_remaining validation passed with (%s) sessions remaining" % cast_config.session_remaining)
            else:
                res["ok"] = False
                res["error_message"] = "Session limit exceeded."
                self.logger.warning("Cast Config has no sessions remaining", extra={'metric_name':"provision.cast.validate",  'validation_failure_reason':"no_sessions_remaining"})
                return res
        else:
            self.logger.debug("Cast Config not configured to limit sessions")
        referrer = event.get("referrer", "")
        if cast_config.allowed_referrers:
            if referrer:
                domain = urlparse(referrer).netloc.split(":")[0]
                if domain.lower().strip() in cast_config.allowed_referrers:
                    self.logger.debug("Request domain (%s) in allowed referrer (%s)" % (domain, cast_config.allowed_referrers))
                else:
                    res["ok"] = False
                    res["error_message"] = "Requests are not allowed from this domain."
                    self.logger.warning(("Request domain (%s) not in allowed referrer (%s)" % (domain, cast_config.allowed_referrers)),
                      extra={'metric_name':"provision.cast.validate", 
                     'validation_failure_reason':"bad_referrer"})
                    return res
            else:
                self.logger.debug("Request has no referrer")
        elif cast_config.limit_ips and cast_config.ip_request_limit and cast_config.ip_request_seconds:
            after = datetime.datetime.utcnow() - datetime.timedelta(seconds=(cast_config.ip_request_seconds))
            accountings = cherrypy.request.db.getAccountings(cast_config_id=(cast_config.cast_config_id), user_ip=client_ip,
              after=after)
            if len(accountings) >= cast_config.ip_request_limit:
                self.logger.warning(("IP Limit (%s) within (%s) seconds reached" % (cast_config.ip_request_limit,
                 cast_config.ip_request_seconds)),
                  extra={'metric_name':"provision.cast.validate", 
                 'validation_failure_reason':"ip_limit"})
                res["ok"] = False
                res["error_message"] = "Request limit reached. Please try again later."
                return res
            self.logger.debug("Passed IP Limit restriction. Current sessions (%s) within limit" % len(accountings))
        else:
            self.logger.debug("No IP Limit restrictions configured")
        if cast_config.valid_until:
            if cast_config.valid_until < datetime.datetime.utcnow():
                self.logger.warning(("Casting config valid_until (%s) has expired" % cast_config.valid_until), extra={'metric_name':"provision.cast.validate", 
                 'validation_failure_reason':"expired"})
                res["ok"] = False
                res["error_message"] = "This link has expired"
                return res
        return res

    def check_form(self, image):
        event = cherrypy.request.json
        launch_selections = event.get("launch_selections")
        if not launch_selections:
            launch_selections = {}
        return not image.has_minimum_launch_selections(launch_selections)

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    @Authenticated(requested_actions=[JWT_AUTHORIZATION.USER], pass_unauthenticated=True)
    def request_castParse error at or near `POP_BLOCK' instruction at offset 1048

    @cherrypy.expose()
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    @Unauthenticated()
    def webauthn_register_start(self):
        response = {}
        event = cherrypy.request.json
        if "username" not in event or "password" not in event:
            self.logger.warning("Invalid call to webauthn_register_start")
            response["error_message"] = "Access Denied"
            return response
        auth_resp = self.authenticate()
        if "error_message" in auth_resp:
            self.logger.warning("Authentication failed on attempt to set 2fa secret for user: (%s)" % event["username"])
            response["error_message"] = auth_resp["error_message"]
            return response
        user = cherrypy.request.db.getUser(event["username"].strip().lower())
        if not user.get_setting_value("require_2fa", False):
            self.logger.warning("User (%s) attempted to call webauthn_register_start, but require_2fa is false")
            response["error_message"] = "Two factor enrollment is not enabled"
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
        if user.username != event["username"]:
            response["error_message"] = "Username does not match authenticated user"
            self.logger.warning("Token Username (%s) does not match username field (%s)", user.username, event["username"])
            return response
        if not user.get_setting_value("allow_2fa_self_enrollment", False):
            self.logger.warning("User (%s) attempted to call webauthn_authenticated_register_start", event["username"])
            response["error_message"] = "Self Enrollment is not permitted"
            return response
        response = self._webauthn_register_start(user)
        if response.get("error_message") == "Access Denied":
            response["error_message"] = "Webauthn Register Failed"
        return response

    def _webauthn_register_start(self, user):
        response = {}
        if not user.get_setting_value("allow_webauthn_2fa", True):
            response["error_message"] = "WebAuthn is not permitted for user."
            self.logger.warning("User (%s) called _webauthn_register_start, but webauthn is disabled.", user.username)
            return response
        request_id = uuid.uuid4().hex
        prompt_timeout = int(self._db.get_config_setting_value("auth", "webauthn_request_lifetime")) * 1000
        registration_options = webauthn.generate_registration_options(rp_id=(cherrypy.request.headers["HOST"]),
          rp_name="Kasm Workspaces",
          user_name=(user.username),
          user_id=(user.user_id.hex),
          authenticator_selection=AuthenticatorSelectionCriteria(user_verification=(UserVerificationRequirement.REQUIRED)),
          timeout=prompt_timeout)
        registration_options = json.loads(webauthn.options_to_json(registration_options))
        cherrypy.request.db.create_webauthn_request(challenge=(registration_options["challenge"]),
          request_id=request_id)
        response["registration_options"] = registration_options
        response["request_id"] = request_id
        return response

    @cherrypy.expose()
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    @Unauthenticated()
    def webauthn_register_finish(self):
        response = {}
        event = cherrypy.request.json
        if "username" not in event or "password" not in event:
            self.logger.warning("Invalid call to webauthn_register_finish")
            response["error_message"] = "Access Denied"
            return response
        auth_resp = self.authenticate()
        if "error_message" in auth_resp:
            self.logger.warning("Authentication failed on attempt to set 2fa secret for user: (%s)" % event["username"])
            response["error_message"] = auth_resp["error_message"]
            return response
        user = cherrypy.request.db.getUser(event["username"].strip().lower())
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
        if user.username != event["username"]:
            response["error_message"] = "Username does not match authenticated user"
            self.logger.warning("Token Username (%s) does not match username field (%s)", user.username, event["username"])
            return response
        if not user.get_setting_value("allow_2fa_self_enrollment", False):
            self.logger.warning("User (%s) attempted to call webauthn_authenticated_register_finish, but allow_2fa_self_enrollment is set to False", event["username"])
            response["error_message"] = "Self Enrollment is not permitted"
            return response
        response = self._webauthn_register_finish(event, user)
        if response.get("error_message") == "Access Denied":
            response["error_message"] = "WebAuthn Register Failed"
        return response

    def _webauthn_register_finishParse error at or near `POP_BLOCK' instruction at offset 150

    def _webauthn_generate_auth_options(self, user):
        response = {}
        request_id = uuid.uuid4().hex
        prompt_timeout = int(self._db.get_config_setting_value("auth", "webauthn_request_lifetime")) * 1000
        allowed_credentials = []
        for credential in user.webauthn_credentials:
            allowed_credentials.append(PublicKeyCredentialDescriptor(id=(credential.authenticator_credential_id)))
        else:
            authentication_options = webauthn.generate_authentication_options(rp_id=(cherrypy.request.headers["HOST"]),
              allow_credentials=allowed_credentials,
              timeout=prompt_timeout)
            authentication_options = json.loads(authentication_options.model_dump_json())
            cherrypy.request.db.create_webauthn_request(challenge=(authentication_options["challenge"]),
              request_id=request_id)
            response["webauthn_authentication_options"] = authentication_options
            response["request_id"] = request_id
            return response

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    @Authenticated(requested_actions=[JWT_AUTHORIZATION.USER], read_only=False)
    def webauthn_get_auth_options(self):
        user = cherrypy.request.authenticated_user
        response = {}
        if not user.set_webauthn:
            self.logger.warning("User (%s) called webauthn_get_auth_options, but they do not have any credentials")
            response["error_message"] = "No WebAuthn Credentials"
            return response
        return self._webauthn_generate_auth_options(user)

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    @Unauthenticated()
    def webauthn_authenticateParse error at or near `POP_BLOCK' instruction at offset 330

    def _generate_auth_resp(self, user, event, response):
        cherrypy.request.db.remove_expired_session_tokens(user)
        session_token = cherrypy.request.db.createSessionToken(user)
        priv_key = str.encode(self._db.get_config_setting_value_cached("auth", "api_private_key"))
        session_lifetime = int(self._db.get_config_setting_value_cached("auth", "session_lifetime"))
        session_jwt = session_token.generate_jwt(priv_key, session_lifetime)
        response["token"] = session_jwt
        response["user_id"] = cherrypy.request.db.serializable(user.user_id)
        response["is_admin"] = JWT_AUTHORIZATION.any_admin_action(session_token.get_authorizations())
        response["authorized_views"] = JWT_AUTHORIZATION.get_authorized_views(session_token.get_authorizations())
        response["is_anonymous"] = user.anonymous
        response["dashboard_redirect"] = user.get_setting_value("dashboard_redirect", None)
        response["require_subscription"] = user.get_setting_value("require_subscription", None)
        response["has_subscription"] = user.has_subscription
        response["has_plan"] = user.has_plan
        response["auto_login_kasm"] = user.get_setting_value("auto_login_to_kasm", False)
        response["display_ui_errors"] = user.get_setting_value("display_ui_errors", False)
        response["enable_ui_server_logging"] = user.get_setting_value("enable_ui_server_logging", True)
        response["program_data"] = user.get_program_data()
        user_attr = cherrypy.request.db.getUserAttributes(user)
        if user_attr is not None:
            if user_attr.user_login_to_kasm is not None:
                response["auto_login_kasm"] = user_attr.user_login_to_kasm
        if user_attr is not None:
            if user_attr.theme is not None:
                response["theme"] = user_attr.theme
        kasm_auth_domain = self._db.get_config_setting_value("auth", "kasm_auth_domain")
        same_site = self._db.get_config_setting_value("auth", "same_site")
        if kasm_auth_domain:
            if kasm_auth_domain.lower() == "$request_host$":
                kasm_auth_domain = cherrypy.request.headers["HOST"]
        cherrypy.response.cookie["session_token"] = session_jwt
        cherrypy.response.cookie["session_token"]["Path"] = "/"
        cherrypy.response.cookie["session_token"]["Max-Age"] = session_lifetime
        cherrypy.response.cookie["session_token"]["Domain"] = kasm_auth_domain
        cherrypy.response.cookie["session_token"]["Secure"] = True
        cherrypy.response.cookie["session_token"]["httpOnly"] = True
        cherrypy.response.cookie["session_token"]["SameSite"] = same_site
        cherrypy.response.cookie["username"] = user.username
        cherrypy.response.cookie["username"]["Path"] = "/"
        cherrypy.response.cookie["username"]["Max-Age"] = session_lifetime
        cherrypy.response.cookie["username"]["Domain"] = kasm_auth_domain
        cherrypy.response.cookie["username"]["Secure"] = True
        cherrypy.response.cookie["username"]["httpOnly"] = True
        cherrypy.response.cookie["username"]["SameSite"] = same_site
        if user.realm in ('ldap', 'local'):
            if user.is_any_sso_images():
                kasm_sso_token = Fernet.generate_key()
                cherrypy.response.cookie["kasm_client_key"] = kasm_sso_token.decode("utf-8")
                cherrypy.response.cookie["kasm_client_key"]["Path"] = "/"
                cherrypy.response.cookie["kasm_client_key"]["Max-Age"] = session_lifetime
                cherrypy.response.cookie["kasm_client_key"]["Domain"] = kasm_auth_domain
                cherrypy.response.cookie["kasm_client_key"]["Secure"] = True
                cherrypy.response.cookie["kasm_client_key"]["httpOnly"] = True
                cherrypy.response.cookie["kasm_client_key"]["SameSite"] = same_site
                user.sso_ep = self.encrypt_client_data(kasm_sso_token, event["password"].encode())
                cherrypy.request.db.updateUser(user)
        self.logger.info(("Successful authentication attempt for user: (%s)" % user.username), extra={"metric_name": "account.login.successful"})
        if self.hubspot_api_key:
            data = {"properties": [{'property':"kasm_app_login",  'value':True}]}
            try:
                r = update_hubspot_contact_by_email(self.hubspot_api_key, user.username, data, self.logger)
                if not r.ok:
                    self.logger.exception("Error updating hubspot contact for user (%s) : (%s)" % (
                     user.username, r.content.decode("utf-8")))
            except Exception as e:
                try:
                    self.logger.exception("Exception updating hubspot contact for user (%s) : (%s)" % (user.username, e))
                finally:
                    e = None
                    del e

        return response

    def _get_network_names(self):
        network_names = []
        restricted_networks = [
         "none",
         "host"]
        for server in cherrypy.request.db.getServers(manager_id=None):
            if server.docker_networks and type(server.docker_networks) == dict:
                names = [v["name"] for k, v in server.docker_networks.items() if "name" in v]
                network_names.extend(names)
            network_names = list(set(network_names))
            _network_names = []
            for x in network_names:
                if x.startswith("kasm_autogen_"):
                    continue
                elif x in restricted_networks:
                    continue
                else:
                    _network_names.append(x)
            else:
                _network_names = list(set(_network_names))
                _network_names = sorted(_network_names, key=(lambda x: x.lower()))
                return _network_names

    @func_timing
    def _kasmvnc_api(self, query, kasm, send_response, req_type, data=None, timeout=5):
        success = False
        port_map = kasm.get_port_map()
        cherrypy.request.kasm_id = str(kasm.kasm_id)
        port = kasm.server.port if kasm.image.is_container else port_map["vnc"]["port"]
        path = port_map["vnc"]["path"]
        priv_key = str.encode(cherrypy.request.db.get_config_setting_value_cached("auth", "api_private_key"))
        jwt_token = generate_jwt_token({'session_token_id':str(kasm.api_token),  'impersonate_user':True,  'kasm_id':str(kasm.kasm_id)}, [JWT_AUTHORIZATION.SESSIONS_VIEW], priv_key, expires_days=4095)
        if len(path) == 1:
            if path[0] != "/":
                path = "/" + path
            else:
                path = ""
        elif len(path) > 1 and path[0] != "/":
            path = "/" + path
        url = "https://{0}:{1}{2}/api/{3}".format(kasm.server.hostname, port, path, query)
        headers = {'Cookie':('username="{0}"; session_token={1}'.format)("kasm_api_user", jwt_token), 
         'Content-Type':"application/json"}
        authorization = kasm.image.is_container or kasm.get_port_map().get("vnc", {}).get("authorization")
        if authorization:
            headers["Authorization"] = authorization
        try:
            self.logger.debug("Calling kasmvnc api (%s)" % url)
            if req_type == "post":
                response = requests.post(url, timeout=timeout, headers=headers, json=data, verify=False)
            else:
                if req_type == "get":
                    response = requests.get(url, timeout=timeout, headers=headers, verify=False)
                elif send_response:
                    return                     return response
                if response.ok:
                    success = True
                else:
                    raise Exception("Request (%s) returned code (%s) : (%s)" % (url, response.status_code, response.text))
        except Exception as e:
            try:
                self.logger.error("Error calling KasmVNC API (%s) for kasm_id (%s) : %s" % (
                 query, str(kasm.kasm_id), e))
            finally:
                e = None
                del e

        else:
            return success

    @func_timing
    def _kasm_host_svc_api(self, query, kasm, send_response, req_type, data=None, timeout=10):
        success = False
        content = None
        if not data:
            data = {}
        connection_proxy = None
        connection_proxies = cherrypy.request.db.get_connection_proxies(zone_id=(kasm.server.zone_id),
          connection_proxy_type=(CONNECTION_PROXY_TYPE.GUAC.value))
        random.shuffle(connection_proxies)
        for x in connection_proxies:
            if is_healthy(url=("https://%s:%s/guac/__healthcheck" % (
             x.server_address,
             x.server_port))):
                connection_proxy = x
                break
            if not connection_proxy:
                connection_proxy = connection_proxies[0]
            cherrypy.request.kasm_id = str(kasm.kasm_id)
            url = "https://{0}:{1}{2}/{3}".format(connection_proxy.server_address, connection_proxy.server_port, "/guac_connect/api", query)
            priv_key = str.encode(cherrypy.request.db.get_config_setting_value_cached("auth", "api_private_key"))
            headers = {'Content-Type':"application/json", 
             'Authorization':"Bearer %s" % (generate_jwt_token({"username": (kasm.server.connection_username)}, [JWT_AUTHORIZATION.USER], priv_key, expires_minutes=5)), 
             'x-kasm-id':str(kasm.kasm_id)}
            cookies = {'username':(cherrypy.request.cookie["username"]).value, 
             'session_token':(cherrypy.request.cookie["session_token"]).value}
            data.update({'username':(cherrypy.request.cookie["username"]).value, 
             'token':(cherrypy.request.cookie["session_token"]).value})
            try:
                self.logger.debug("Calling Kasm Host SVC api (%s)" % url)
                response = None
                if req_type == "post":
                    response = requests.post(url, timeout=timeout, headers=headers, json=data, verify=False, cookies=cookies)
                else:
                    if req_type == "get":
                        response = requests.get(url, timeout=timeout, headers=headers, verify=False)
                    elif send_response:
                        content = response
                    if response.ok:
                        success = True
                    else:
                        raise Exception("Request (%s) returned code (%s) : (%s)" % (url, response.status_code, response.text))
            except Exception as e:
                try:
                    self.logger.warning("Error calling Kasm Service API (%s) for kasm_id (%s) : %s" % (
                     query, str(kasm.kasm_id), e))
                finally:
                    e = None
                    del e

            else:
                return (
                 success, content)

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    @Unauthenticated()
    def agent_proxy(self, **params):
        event = cherrypy.request.json
        host_token = event.get("host_token")
        manager_token = event.get("manager_token")
        proxy_context = event.get("proxy_context")
        server_id = event.get("server_id")
        if host_token and manager_token and server_id and proxy_context:
            server = cherrypy.request.db.getServer(server_id)
            _manager_token = cherrypy.request.db.get_config_setting_value("manager", "token")
            if server:
                if server.host_token == host_token:
                    if manager_token == _manager_token:
                        _url = proxy_context["url"]
                        _headers = proxy_context["headers"]
                        _data = proxy_context["data"]
                        _timeout = proxy_context["timeout"]
                        _verify = proxy_context["verify"]
                        self.logger.debug("Sending proxied agent request to (%s)" % _url)
                        response = requests.post(_url, timeout=_timeout, headers=_headers, json=_data, verify=_verify)
                        return response.json()
            self.logger.error("Failed Authentication of proxied agent request.")
        else:
            self.logger.error("Invalid Request. Missing required parameters")
        cherrypy.response.status = 403

    @cherrypy.expose
    @cherrypy.tools.json_out()
    @JwtAuthenticated(authorizations=[JWT_AUTHORIZATION.KASM_SESSION])
    def get_persistent_profile_manifest(self):
        if cherrypy.request.decoded_jwt:
            if "profile_path" in cherrypy.request.decoded_jwt:
                profile_path = cherrypy.request.decoded_jwt["profile_path"]
                if profile_path and profile_path.lower().startswith("s3://"):
                    aws_access_key = self._db.get_config_setting_value("storage", "object_storage_key")
                    aws_access_secret = self._db.get_config_setting_value("storage", "object_storage_secret")
                    if aws_access_key:
                        if aws_access_secret:
                            credentials = {'aws_access_key_id':aws_access_key, 
                             'aws_secret_access_key':aws_access_secret}
                            object_storage = AwsObjectStorageProvider(cherrypy.request.db, self.logger, credentials)
                            manifest = object_storage.get_profile_manifest(profile_path)
                            return manifest
                    cherrypy.response.status = 404
                    self.logger.error("Request for profile manifest failed, Object Storage credentials are not configured on the server settings.")
            else:
                cherrypy.response.status = 404
                self.logger.warning("Kasm session referenced in request for profile manifest does not exist.")
        else:
            cherrypy.response.status = 403
            self.logger.error("Invalid or missing JWT token used in attempt to retrieve persistent profile manifest.")

    @cherrypy.expose
    @cherrypy.tools.json_out()
    @cherrypy.tools.json_in()
    @JwtAuthenticated(authorizations=[JWT_AUTHORIZATION.KASM_SESSION])
    def request_upload_profile_manifest(self):
        event = cherrypy.request.json
        event_manifest = event.get("manifest")
        if not event_manifest:
            event_manifest = event
        if cherrypy.request.decoded_jwt:
            if "profile_path" in cherrypy.request.decoded_jwt:
                profile_path = cherrypy.request.decoded_jwt["profile_path"]
                if profile_path and profile_path.lower().startswith("s3://"):
                    aws_access_key = self._db.get_config_setting_value("storage", "object_storage_key")
                    aws_access_secret = self._db.get_config_setting_value("storage", "object_storage_secret")
                    if aws_access_key:
                        if aws_access_secret:
                            credentials = {'aws_access_key_id':aws_access_key, 
                             'aws_secret_access_key':aws_access_secret}
                            object_storage = AwsObjectStorageProvider(cherrypy.request.db, self.logger, credentials)
                            manifest = object_storage.request_upload_profile_manifest(profile_path, event_manifest)
                            return manifest
                    cherrypy.response.status = 404
                    self.logger.error("Request for profile manifest failed, Object Storage credentials are not configured on the server settings.")
            else:
                cherrypy.response.status = 404
                self.logger.warning("Invalid profile path.")
        else:
            cherrypy.response.status = 403
            self.logger.error("Invalid or missing JWT token used in attempt to retrieve persistent profile manifest.")

    @cherrypy.expose
    @cherrypy.tools.json_out()
    @cherrypy.tools.json_in()
    @JwtAuthenticated(authorizations=[JWT_AUTHORIZATION.KASM_SESSION])
    def request_upload_layer(self):
        if cherrypy.request.decoded_jwt:
            if "profile_path" in cherrypy.request.decoded_jwt:
                profile_path = cherrypy.request.decoded_jwt["profile_path"]
                event = cherrypy.request.json
                if profile_path:
                    if profile_path.lower().startswith("s3://") and "signature" in event:
                        aws_access_key = self._db.get_config_setting_value("storage", "object_storage_key")
                        aws_access_secret = self._db.get_config_setting_value("storage", "object_storage_secret")
                        if aws_access_key and aws_access_secret:
                            credentials = {'aws_access_key_id':aws_access_key, 
                             'aws_secret_access_key':aws_access_secret}
                            object_storage = AwsObjectStorageProvider(cherrypy.request.db, self.logger, credentials)
                            url = object_storage.request_upload_layer(profile_path, event["signature"])
                            if url:
                                return {"url": url}
                            self.logger.debug(f'The layer with signature ({event["signature"]}) already exists.')
                            return {}
                    else:
                        cherrypy.response.status = 404
                        self.logger.error("Request for profile manifest failed, Object Storage credentials are not configured on the server settings.")
                else:
                    cherrypy.response.status = 404
                    self.logger.warning("Invalid profile path or missing signature in request.")

    @cherrypy.expose
    @cherrypy.tools.json_out()
    @cherrypy.tools.json_in()
    @JwtAuthenticated(authorizations=[JWT_AUTHORIZATION.KASM_SESSION])
    def complete_profile_manifest(self):
        event = cherrypy.request.json
        event_manifest = event.get("manifest")
        if not event_manifest:
            event_manifest = event
        if cherrypy.request.decoded_jwt:
            if "profile_path" in cherrypy.request.decoded_jwt:
                profile_path = cherrypy.request.decoded_jwt["profile_path"]
                if profile_path and profile_path.lower().startswith("s3://"):
                    aws_access_key = self._db.get_config_setting_value("storage", "object_storage_key")
                    aws_access_secret = self._db.get_config_setting_value("storage", "object_storage_secret")
                    if aws_access_key:
                        if aws_access_secret:
                            credentials = {'aws_access_key_id':aws_access_key, 
                             'aws_secret_access_key':aws_access_secret}
                            object_storage = AwsObjectStorageProvider(cherrypy.request.db, self.logger, credentials)
                            manifest = object_storage.upload_profile_manifest(profile_path, event_manifest)
                            return manifest
                    cherrypy.response.status = 404
                    self.logger.error("Request for profile manifest failed, Object Storage credentials are not configured on the server settings.")
            else:
                cherrypy.response.status = 404
                self.logger.warning("Kasm session referenced in request for profile manifest does not exist.")
        else:
            cherrypy.response.status = 403
            self.logger.error("Invalid or missing JWT token used in attempt to retrieve persistent profile manifest.")

    @cherrypy.expose
    @cherrypy.tools.json_out()
    @cherrypy.tools.json_in()
    @JwtAuthenticated(authorizations=[JWT_AUTHORIZATION.KASM_SESSION])
    def set_kasm_session_status(self):
        event = cherrypy.request.json
        if cherrypy.request.decoded_jwt:
            if "kasm_id" in cherrypy.request.decoded_jwt:
                if "status" in event:
                    operational_status = SESSION_OPERATIONAL_STATUS.validate(event["status"])
                    operational_message = event["status_message"] if "status_message" in event else None
                    operational_progress = int(event["status_progress"]) if "status_progress" in event else 0
                    if operational_status:
                        kasm_id = cherrypy.request.decoded_jwt["kasm_id"]
                        kasm = cherrypy.request.db.getKasm(kasm_id)
                        if kasm:
                            kasm = cherrypy.request.db.setKasmStatus(kasm.kasm_id, kasm.user_id, kasm.is_standby, operational_status, operational_message, operational_progress)
                            if operational_status == SESSION_OPERATIONAL_STATUS.RUNNING and kasm.queued_tasks:
                                if len(kasm.queued_tasks) > 0:
                                    for task in kasm.queued_tasks:
                                        if not self.provider_manager.kasm_exec(kasm, task, skip_hello=True):
                                            self.logger.error(f"Execution of queued task on session ({kasm_id}) has failed.")
                                        else:
                                            self.logger.debug(f"Execution of queued task on session ({kasm_id}) was successful.")
                                    else:
                                        kasm.queued_tasks = []
                                        cherrypy.request.db.updateKasm(kasm)

                                self.logger.debug(f"Kasm ({kasm_id}) operational status updated ({operational_status}) at {operational_progress}% complete with status message: {operational_message}")
                                return {"status": (operational_status.value)}
                                cherrypy.response.status = 404
                                self.logger.warning(f"set_kasm_session_status request referencing invalid kasm_id ({kasm_id}).")
                            else:
                                pass
                        else:
                            cherrypy.response.status = 400
                            self.logger.error("Invalid request for set_kasm_session_status, invalid status provided.")
                    else:
                        pass
            elif "destroyed" in event:
                if event["destroyed"]:
                    kasm_id = cherrypy.request.decoded_jwt["kasm_id"]
                    kasm = cherrypy.request.db.getKasm(kasm_id)
                    if kasm:
                        cherrypy.request.db.deleteKasm(kasm)
                        self.logger.info(f"Kasm session ({kasm_id}) has been destroyed after an async destroy completed.")
                else:
                    cherrypy.response.status = 404
                    self.logger.warning(f"set_kasm_session_status request referencing invalid kasm_id ({kasm_id}).")
            else:
                cherrypy.response.status = 400
                self.logger.error("Invalid request for set_kasm_session_status, missing status.")
        else:
            cherrypy.response.status = 403
            self.logger.error("Invalid or missing JWT token used in attempt to call set_kasm_session_status.")

    @cherrypy.expose
    @cherrypy.tools.json_out()
    @cherrypy.tools.json_in()
    @JwtAuthenticated(authorizations=[JWT_AUTHORIZATION.SERVER_AGENT])
    def set_server_status(self):
        event = cherrypy.request.json
        if cherrypy.request.decoded_jwt:
            if "server_id" in cherrypy.request.decoded_jwt:
                if "status" in event:
                    operational_status = SERVER_OPERATIONAL_STATUS.validate(event["status"])
                    operational_message = event["status_message"] if "status_message" in event else None
                    operational_progress = int(event["status_progress"]) if "status_progress" in event else 0
                    if operational_status:
                        server_id = cherrypy.request.decoded_jwt["server_id"]
                        server = cherrypy.request.db.getServer(server_id)
                        if server:
                            server = cherrypy.request.db.update_server(server, operational_status=operational_status)
                            self.logger.debug(f"Server ({server_id}) operational status updated ({operational_status}) at {operational_progress}% complete with status message: {operational_message}")
                            if server.operational_status == SERVER_OPERATIONAL_STATUS.RUNNING.value:
                                for kasm in server.kasms:
                                    if kasm.operational_status in (SESSION_OPERATIONAL_STATUS.REQUESTED.value,
                                     SESSION_OPERATIONAL_STATUS.PROVISIONING.value,
                                     SESSION_OPERATIONAL_STATUS.ASSIGNED.value,
                                     SESSION_OPERATIONAL_STATUS.STARTING.value):
                                        self.provider_manager.get_session_from_server(image=(kasm.image),
                                          server=server,
                                          user=(kasm.user),
                                          user_ip=None,
                                          cast_config=(kasm.cast_config),
                                          user_language=None,
                                          user_timezone=None,
                                          queued_kasm=kasm)
                                else:
                                    return {"status": (operational_status.value)}
                                    cherrypy.response.status = 404
                                    self.logger.warning(f"set_server_status request referencing invalid server_id ({server_id}).")

                            else:
                                pass
                        else:
                            cherrypy.response.status = 400
                            self.logger.error("Invalid request for set_server_status, invalid status provided.")
                    else:
                        pass
            else:
                cherrypy.response.status = 400
                self.logger.error("Invalid request for set_server_status, missing status.")
        else:
            cherrypy.response.status = 403
            self.logger.error("Invalid or missing JWT token used in attempt to call set_server_status.")

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    @Unauthenticated()
    def get_languages(self):
        response = {"languages": [{'label':k,  'value':v} for k, v in dict(sorted({x.name: x.value for x in LANGUAGES}.items())).items()]}
        response["languages"].insert(0, {'label':"Auto",  'value':"Auto"})
        return response

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    @Unauthenticated()
    def get_timezones(self):
        response = {"timezones": [{'label':k,  'value':v} for k, v in dict(sorted({x.name.replace("minus", "-").replace("plus", "+").replace("___", ":").replace("__", "/").replace("_", " "): x.value for x in TIMEZONES}.items())).items()]}
        response["timezones"].insert(0, {'label':"Auto",  'value':"Auto"})
        return response

    @cherrypy.expose
    @JwtAuthenticated(authorizations=[JWT_AUTHORIZATION.KASM_SESSION])
    def set_kasm_session_credential(self):
        if cherrypy.request.decoded_jwt:
            if "kasm_id" in cherrypy.request.decoded_jwt:
                kasm_id = cherrypy.request.decoded_jwt["kasm_id"]
                kasm = cherrypy.request.db.getKasm(kasm_id)
                if kasm:
                    if not kasm.connection_credential:
                        kasm.connection_credential = generate_password(18)
                        cherrypy.request.db.updateKasm(kasm)
                        self.logger.debug(f"Successfully set connection credential for session ({kasm_id})")
                        return kasm.connection_credential
                    cherrypy.response.status = 403
                    self.logger.error(f"Attempt to call set_kasm_session_credential for a session ({kasm_id}) that already has the credential set.")
            else:
                cherrypy.response.status = 404
                self.logger.warning(f"set_kasm_session_credential request referencing invalid kasm_id ({kasm_id}).")
        else:
            cherrypy.response.status = 403
            self.logger.error("Invalid or missing JWT token used in attempt to call set_kasm_session_credential.")

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @JwtAuthenticated(authorizations=[JWT_AUTHORIZATION.KASM_SESSION, JWT_AUTHORIZATION.SERVER_AGENT])
    def kasm_session_log(self):
        request_json = cherrypy.request.json
        if isinstance(request_json, list):
            log_message = request_json
        else:
            log_message = request_json.get("log_message")
        for log in log_message:
            self.logger.info((json.dumps(log)), extra={"_json": True})

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    @Authenticated(requested_actions=[JWT_AUTHORIZATION.USER], read_only=True)
    def get_user_auth_settings(self):
        user = cherrypy.request.authenticated_user
        response = {'allow_2fa_self_enrollment':(user.get_setting_value)("allow_2fa_self_enrollment", False), 
         'allow_webauthn_2fa':(user.get_setting_value)("allow_webauthn_2fa", True), 
         'allow_totp_2fa':(user.get_setting_value)("allow_totp_2fa", True), 
         'set_two_factor':user.set_two_factor, 
         'set_webauthn':user.set_webauthn}
        return response

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    @Authenticated(requested_actions=[JWT_AUTHORIZATION.USER], read_only=False)
    def clear_user_two_factor(self):
        response = {}
        event = cherrypy.request.json
        user = cherrypy.request.authenticated_user
        if "username" not in event or "password" not in event:
            msg = "Invalid call to clear_two_factor missing username or password"
            self.logger.warning(msg)
            response["error_message"] = msg
            return response
        if user.username != event["username"]:
            response["error_message"] = "Username does not match authenticated user"
            self.logger.warning("Token Username (%s) does not match username field (%s)", user.username, event["username"])
            return response
        if "webauthn_credential" not in event:
            if "code" not in event:
                msg = "Missing second factor in call to clear_user_two_factor"
                self.logger.warning(msg)
                response["error_message"] = msg
                return response
        if not user.get_setting_value("allow_2fa_self_enrollment", False):
            self.logger.warning("User (%s) attempted to call clear_user_two_factor, but self enrollment is not permitted", user.username)
            response["error_message"] = "Invalid call to clear_user_two_factor"
            return response
        auth_resp = self.authenticate()
        if "error_message" in auth_resp:
            self.logger.warning("User (%s), used invalid credentials when attempting to clear two factor", event["username"])
            response["error_message"] = auth_resp["error_message"]
            return response
        if "code" in event:
            if not user.set_two_factor:
                self.logger.warning("User (%s) attempted to use totp to authenticate to clear_user_two_factor but TOTP is not set", event["username"])
                response["error_message"] = "Authenticator Token is not currently configured"
                return response
        if "webauthn_auth" in event:
            if not user.set_webauthn:
                self.logger.warning("User (%s) attempted to webauthn credential to authenticate, but no credentials are setup", event["username"])
                response["error_message"] = "No WebAuthn credentials configured"
                return response
        if "code" in event:
            two_factor_resp = self.two_factor_auth()
            if "error_message" in two_factor_resp:
                if two_factor_resp == "Access Denied":
                    response["error_message"] = "Failed Token Check"
                else:
                    response["error_message"] = two_factor_resp["error_message"]
                self.logger.warning("User (%s) failed to verify totp credential when running clear_user_two_factor", event["username"])
                return response
            user.set_two_factor = False
            if user.secret:
                user.secret = None
            for token in user.tokens:
                cherrypy.request.db.unassign_physical_token(token)
            else:
                self.logger.info("Cleared TOTP Tokens for User (%s)", event["username"])

        else:
            if "webauthn_credential" in event:
                webauthn_resp = self.webauthn_authenticate()
                if "error_message" in webauthn_resp:
                    self.logger.warning("User (%s) failed to verify webauthn when running clear_user_two_factor", event["username"])
                    response["error_message"] = webauthn_resp["error_message"]
                    return response
                cherrypy.request.db.delete_webauthn_credentials(user_id=(user.user_id))
                self.logger.info("Deleted all webauthn credentials for User (%s)", event["username"])
            event["logout_all"] = True
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
        if "password" not in event or "username" not in event:
            response["error_message"] = "Invalid Request"
            self.logger.warning("Missing username or password in call to check_password")
            return response
        if user.username != event["username"]:
            response["error_message"] = "Invalid Request"
            self.logger.warning("Token Username (%s) does not match username field (%s)", user.username, event["username"])
            return response
        auth_resp = self.authenticate()
        if "error_message" in auth_resp:
            if auth_resp["error_message"] == "Access Denied":
                response["error_message"] = "Invalid Password"
            else:
                response["error_message"] = auth_resp["error_message"]
            self.logger.warning("Invalid response from authenticate in check_password for user (%s)", event["username"])
            return response
        return response

    @cherrypy.expose
    @cherrypy.tools.json_out()
    @cherrypy.tools.json_in()
    @JwtAuthenticated(authorizations=[JWT_AUTHORIZATION.GUAC, JWT_AUTHORIZATION.KASM_SESSION])
    def request_session_recording_settings(self):
        if cherrypy.request.decoded_jwt:
            storage_key = cherrypy.request.db.get_config_setting_value("session_recording", "recording_object_storage_key")
            storage_secret = cherrypy.request.db.get_config_setting_value("session_recording", "recording_object_storage_secret")
            storage_location_url = cherrypy.request.db.get_config_setting_value("session_recording", "session_recording_upload_location")
            framerate = cherrypy.request.db.get_config_setting_value("session_recording", "session_recording_framerate")
            width = cherrypy.request.db.get_config_setting_value("session_recording", "session_recording_res_width")
            height = cherrypy.request.db.get_config_setting_value("session_recording", "session_recording_res_height")
            bitrate = cherrypy.request.db.get_config_setting_value("session_recording", "session_recording_bitrate")
            retention_period = cherrypy.request.db.get_config_setting_value("session_recording", "session_recording_retention_period")
            if storage_key:
                if storage_secret:
                    if storage_location_url:
                        if framerate:
                            if width:
                                if height:
                                    if bitrate:
                                        response = {}
                                        response["framerate"] = int(framerate)
                                        response["width"] = int(width)
                                        response["height"] = int(height)
                                        response["bitrate"] = int(bitrate)
                                        response["retention_period"] = int(retention_period)
                                        return response
            cherrypy.response.status = 400
            self.logger.error("Missing session recording settings.")
        else:
            cherrypy.response.status = 403
            self.logger.error("Invalid or missing JWT token used in attempt to retrieve session recording settings.")

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    @JwtAuthenticated(authorizations=[JWT_AUTHORIZATION.KASM_SESSION, JWT_AUTHORIZATION.GUAC])
    def request_session_recording_upload_url(self):
        response = {}
        event = cherrypy.request.json
        kasm_id = event.get("kasm_id")
        if not cherrypy.request.decoded_jwt or "connection_proxy_id" in cherrypy.request.decoded_jwt or "kasm_id" in cherrypy.request.decoded_jwt:
            account_record = cherrypy.request.db.getAccounting(kasm_id)
            session_recording_upload_location = cherrypy.request.db.get_config_setting_value("session_recording", "session_recording_upload_location")
            if session_recording_upload_location:
                url_parts = urlparse(session_recording_upload_location)
                path_parts = list(os.path.split(url_parts.path))
                filename = path_parts[-1]
                f, extension = filename.rsplit(".", 1)
                filename = f + ".{current_epoch}." + extension
                path_parts[-1] = filename
                session_recording_upload_location = urlunparse((url_parts.scheme, url_parts.netloc, "/".join(path_parts), url_parts.params, url_parts.query, url_parts.fragment))
                formatted_session_recording_upload_location = object_storage_variable_substitution(session_recording_upload_location, account_record)
                object_storage_key = cherrypy.request.db.get_config_setting_value("session_recording", "recording_object_storage_key")
                object_storage_secret = cherrypy.request.db.get_config_setting_value("session_recording", "recording_object_storage_secret")
                if object_storage_key:
                    if object_storage_secret:
                        if formatted_session_recording_upload_location.lower().startswith("s3://"):
                            credentials = {'aws_access_key_id':object_storage_key, 
                             'aws_secret_access_key':object_storage_secret}
                            object_storage = AwsObjectStorageProvider(cherrypy.request.db, self.logger, credentials)
                            response["upload_url"] = object_storage.request_upload_file(formatted_session_recording_upload_location)
                            response["object_storage_url"] = formatted_session_recording_upload_location
                            self.logger.debug(f"Request for session recording upload link on behalf of Kasm: {kasm_id} with URL: {formatted_session_recording_upload_location}", extra={'metric_name':"sessions.session_history.request_session_recording_upload_url", 
                             'kasm_id':kasm_id, 
                             'object_storage_url_unauthenticated':formatted_session_recording_upload_location, 
                             'connection_proxy_id':(cherrypy.request.decoded_jwt.get)("connection_proxy_id", None), 
                             'server_id':(cherrypy.request.decoded_jwt.get)("server_id", None)})
                    else:
                        cherrypy.response.status = 400
                        self.logger.error("Unknown object storage protocol configured.")
                else:
                    cherrypy.response.status = 404
                    self.logger.error("Request for session recording upload url failed, Object Storage credentials are not configured on the server settings.")
            else:
                cherrypy.response.status = 400
                self.logger.error("Session recording upload location is not set.")
        else:
            cherrypy.response.status = 403
            self.logger.error("Invalid or missing JWT token used in attempt to call receive_session_recording.")
        return response

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    @JwtAuthenticated(authorizations=[JWT_AUTHORIZATION.KASM_SESSION, JWT_AUTHORIZATION.GUAC])
    def session_recording_upload_complete(self):
        event = cherrypy.request.json
        kasm_id = event.get("kasm_id")
        session_recording_metadata = event.get("session_recording_metadata")
        object_storage_url = event.get("object_storage_url")
        decoded_jwt = cherrypy.request.decoded_jwt
        if session_recording_metadata is None:
            session_recording_metadata = {}
        elif not decoded_jwt or "connection_proxy_id" in decoded_jwt or "kasm_id" in decoded_jwt:
            account_record = cherrypy.request.db.getAccounting(kasm_id)
            session_recording = cherrypy.request.db.addSessionRecording(account_record.account_id, object_storage_url, session_recording_metadata)
            self.logger.debug(f"Request for session recording upload link on behalf of Kasm: {kasm_id} with URL: {object_storage_url}", extra={'metric_name':"sessions.session_history.request_session_recording_upload_url", 
             'kasm_id':kasm_id, 
             'object_storage_url_unauthenticated':object_storage_url, 
             'connection_proxy_id':(decoded_jwt.get)("connection_proxy_id", None), 
             'server_id':(decoded_jwt.get)("server_id", None)})
        else:
            cherrypy.response.status = 403
            self.logger.error("Invalid or missing JWT token used in attempt to call session_recording_upload_complete.")

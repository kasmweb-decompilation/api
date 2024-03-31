# Decompiled with PyLingual (https://pylingual.io)
# Internal filename: public_api.py
# Bytecode version: 3.8.0rc1+ (3413)
# Source timestamp: 1970-01-01 00:00:00 UTC (0)

import uuid
import json
import cherrypy
import datetime
import requests
from utils import Authenticated, func_timing
from admin_api import AdminApi
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from data.enums import SESSION_OPERATIONAL_STATUS, JWT_AUTHORIZATION
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

class PublicAPI(AdminApi):

    def __init__(self, config):
        super(PublicAPI, self).__init__(config)
        self.zone_name = self.config['server']['zone_name']

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    @Authenticated
    @JWT_AUTHORIZATION.USER(requested_actions=[JWT_AUTHORIZATION.USER], read_only=False)
    @func_timing
    def request_kasm(self):
        response = {}
        event = cherrypy.request.json
        if hasattr(cherrypy.request, 'authenticated_user') and cherrypy.request.authenticated_user:
            user = cherrypy.request.authenticated_user
        else:
            user = cherrypy.request.db.createAnonymousUser()
            if user:
                cherrypy.request.authenticated_user = user
                cherrypy.request.kasm_user_id = str(user.user_id)
                cherrypy.request.kasm_user_name = user.username
        if user:
            if 'image_id' not in event:
                default_images = self._get_default_images()
                if 'group_image' in default_images and 'user_image' in default_images and (default_images['group_image'] is not None):
                    event['image_id'] = default_images['group_image']
                    if default_images['user_image'] is not None:
                        event['image_id'] = default_images['user_image']
                    if 'image_id' not in event:
                        response['error_message'] = 'No Default Image Found'
                        return response
                else:
                    response['error_message'] = 'No Default Image Found'
                    return response
            res = self._request_kasm()
            if 'kasm_id' in res:
                session_token = cherrypy.request.db.createSessionToken(user)
                user_id = cherrypy.request.db.serializable(user.user_id)
                res['user_id'] = user_id
                res['username'] = user.username
                res['session_token'] = str(session_token.session_token_id)
                res['kasm_url'] = '/#/connect/kasm/' + res['kasm_id'] + '/' + user_id + '/' + str(session_token.session_token_id)
                if 'enable_sharing' in event and event['enable_sharing'] is True:
                    event['kasm_id'] = res['kasm_id']
                    res2 = self._create_kasm_share_id()
                    if 'share_id' in res2:
                        res['share_id'] = res2['share_id']
                    else:
                        res['error_message'] = 'Failed to create Share ID'
                if 'connection_info' in event:
                    kasm = cherrypy.request.db.getKasm(res['kasm_id'])
                    kasm.connection_info = event['connection_info']
                    cherrypy.request.db.updateKasm(kasm)
                response = res
            elif 'error_message' in res:
                response['error_message'] = res['error_message']
            else:
                response['error_message'] = 'Response Error'
        else:
            response['error_message'] = 'Error Creating User'
        return response

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    @Authenticated
    @JWT_AUTHORIZATION.USER(requested_actions=[JWT_AUTHORIZATION.USER], read_only=True)
    @func_timing
    def join_kasm(self):
        response = {}
        event = cherrypy.request.json
        if 'share_id' not in event:
            response['error_message'] = 'Missing Parameters: share_id is missing'
            return response
        if hasattr(cherrypy.request, 'authenticated_user') and cherrypy.request.authenticated_user:
            user = cherrypy.request.authenticated_user
        else:
            user = cherrypy.request.db.createAnonymousUser()
            if user:
                cherrypy.request.authenticated_user = user
                cherrypy.request.kasm_user_id = str(user.user_id)
                cherrypy.request.kasm_user_name = user.username
        if user:
            res = self._join_kasm()
            if 'kasm' in res:
                session_token = cherrypy.request.db.createSessionToken(user)
                user_id = cherrypy.request.db.serializable(user.user_id)
                token = cherrypy.request.db.serializable(str(session_token.session_token_id))
                res['user_id'] = user_id
                res['username'] = user.username
                res['session_token'] = str(session_token.session_token_id)
                res['kasm_url'] = '/#/connect/join/' + res['kasm']['share_id'] + '/' + user_id + '/' + token
                response = res
            elif 'error_message' in res:
                response['error_message'] = res['error_message']
            else:
                response['error_message'] = 'Response Error'
        else:
            response['error_message'] = 'Error Creating User'
        return response

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    @Authenticated
    @JWT_AUTHORIZATION.USER(requested_actions=[JWT_AUTHORIZATION.USER], read_only=True)
    @func_timing
    def get_kasm_status(self):
        response = {}
        event = cherrypy.request.json
        if hasattr(cherrypy.request, 'authenticated_user'):
            user = cherrypy.request.authenticated_user
            session_token = cherrypy.request.db.createSessionToken(user)
            res = super().get_kasm_status()
            if 'error_message' in res:
                response['error_message'] = res['error_message']
                return response
            if 'kasm' in res:
                res['kasm_url'] = '/#/connect/kasm/' + res['kasm']['kasm_id'] + '/' + str(user.user_id) + '/' + str(session_token.session_token_id)
                response = res
            else:
                response = res
        else:
            response['error_message'] = 'No User sent with request'
        return response

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    @Authenticated
    @JWT_AUTHORIZATION.SESSIONS_MODIFY(requested_actions=[JWT_AUTHORIZATION.SESSIONS_MODIFY], read_only=False)
    @func_timing
    def exec_command_kasm(self):
        response = {}
        event = cherrypy.request.json
        kasm = cherrypy.request.db.getKasm(event['kasm_id']) if 'kasm_id' in event else None
        user = cherrypy.request.authenticated_user
        if kasm is not None and user is not None and (kasm.user.user_id == user.user_id) and ('exec_config' in event):
            self.logger.info('Dev API called from the IP (%s) to execute command on kasm_id (%s) with IP (%s) for user (%s). Exec_config: (%s)' % (cherrypy.request.authenticated_user_ip, str(kasm.kasm_id), kasm.container_ip, user.username, str(event['exec_config'])))
            _kasm = self.get_normalized_kasm(kasm)
            if kasm.get_operational_status() in SESSION_OPERATIONAL_STATUS.RUNNING and self.provider_manager.container_is_running(kasm):
                event['exec_config']['container_id'] = kasm.container_id
                if not self.provider_manager.kasm_exec(kasm, event['exec_config'], skip_hello=True):
                    response['error_message'] = 'Kasm exec failed'
                else:
                    response['kasm'] = _kasm
                    response['current_time'] = str(datetime.datetime.utcnow())
            else:
                self.logger.error(f'Kasm {kasm.kasm_id} for {user.user_id} is not running or responding, operations status is {kasm.operational_status}.')
                response['error_message'] = 'Kasm is not running or is not responding'
        else:
            self.logger.error('Inalid request request to exec_command_kasm, missing required data')
            response['error_message'] = 'Invalid request, check paramemters'
        return response

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @Authenticated
    @JWT_AUTHORIZATION.USER(requested_actions=[JWT_AUTHORIZATION.USER], read_only=True)
    @func_timing
    def get_kasm_screenshot(self, kasm_id='', width=300, height=300):
        response = {}
        event = cherrypy.request.json
        if hasattr(cherrypy.request, 'authenticated_user') and 'kasm_id' in event:
            user = cherrypy.request.authenticated_user
            cherrypy.request.session_token_id = str(cherrypy.request.db.createSessionToken(user).session_token_id)
            cherrypy.request.cookie['username'] = user.username
            cherrypy.request.cookie['session_token'] = cherrypy.request.session_token_id
            height = event['width'] if 'width' in event else height
            width = event['height'] if 'height' in event else width
            res = super().get_kasm_screenshot(event['kasm_id'], width, height)
            if cherrypy.response.status == 200:
                return res
        else:
            cherrypy.response.status = 400

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    @Authenticated
    @JWT_AUTHORIZATION.USER(requested_actions=[JWT_AUTHORIZATION.USER], read_only=True)
    @func_timing
    def get_kasm_frame_stats(self):
        response = {}
        event = cherrypy.request.json
        if hasattr(cherrypy.request, 'authenticated_user'):
            user = cherrypy.request.authenticated_user
            session_token = cherrypy.request.db.createSessionToken(user)
            res = super().get_kasm_frame_stats()
            if 'error_message' in res:
                response['error_message'] = res['error_message']
                return response
            response = res
        else:
            response['error_message'] = 'No User sent with request'
        return response

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    @Authenticated
    @JWT_AUTHORIZATION.USER(requested_actions=[JWT_AUTHORIZATION.USER], read_only=True)
    @func_timing
    def get_kasm_bottleneck_stats(self):
        response = {}
        event = cherrypy.request.json
        if hasattr(cherrypy.request, 'authenticated_user'):
            user = cherrypy.request.authenticated_user
            session_token = cherrypy.request.db.createSessionToken(user)
            res = super().get_kasm_bottleneck_stats()
            if 'error_message' in res:
                response['error_message'] = res['error_message']
                return response
            response = res
        else:
            response['error_message'] = 'No User sent with request'
        return response

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    @Authenticated
    @JWT_AUTHORIZATION.USERS_CREATE(requested_actions=[JWT_AUTHORIZATION.USERS_CREATE], read_only=False)
    @func_timing
    def create_user(self):
        return self._create_user(public=True)

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    @Authenticated
    @JWT_AUTHORIZATION.USERS_VIEW(requested_actions=[JWT_AUTHORIZATION.USERS_VIEW], read_only=True)
    @func_timing
    def get_user(self):
        return self._get_user(public=True)

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    @Authenticated
    @JWT_AUTHORIZATION.USERS_MODIFY(requested_actions=[JWT_AUTHORIZATION.USERS_MODIFY], read_only=False)
    @func_timing
    def update_user(self):
        return self._update_user(public=True)

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    @Authenticated
    @JWT_AUTHORIZATION.USERS_DELETE(requested_actions=[JWT_AUTHORIZATION.USERS_DELETE], read_only=False)
    @func_timing
    def delete_user(self):
        return self._delete_user(public=True)

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    @Authenticated
    @JWT_AUTHORIZATION.USERS_AUTH_SESSION(requested_actions=[JWT_AUTHORIZATION.USERS_AUTH_SESSION], read_only=False)
    @func_timing
    def logout_user(self):
        return self._logout_user(public=True)

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    @Authenticated
    @JWT_AUTHORIZATION.USERS_AUTH_SESSION(requested_actions=[JWT_AUTHORIZATION.USERS_AUTH_SESSION], read_only=True)
    @func_timing
    def get_login(self):
        response = {}
        event = cherrypy.request.json
        target_user = event.get('target_user')
        if target_user:
            user_id = target_user.get('user_id')
            if user_id:
                user = cherrypy.request.db.get_user_by_id(user_id)
                if user:
                    host = cherrypy.request.headers['Host']
                    session_token = cherrypy.request.db.createSessionToken(user)
                    response['url'] = 'https://' + host + '/#/connect/login/dash/' + user.user_id.hex + '/' + str(session_token.session_token_id)
                else:
                    msg = 'No user found with id: (%s)' % user_id
                    self.logger.error(msg)
                    response['error_message'] = msg
                    cherrypy.response.status = 400
            else:
                msg = 'Invalid Request: Missing required parameters'
                self.logger.error(msg)
                response['error_message'] = msg
                cherrypy.response.status = 400
        else:
            msg = 'Invalid Request: Missing required parameters'
            self.logger.error(msg)
            response['error_message'] = msg
            cherrypy.response.status = 400
        return response

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @Authenticated
    @JWT_AUTHORIZATION.USERS_VIEW(requested_actions=[JWT_AUTHORIZATION.USERS_VIEW], read_only=True)
    @func_timing
    def get_ssh_public_key(self):
        data = self._get_attributes(public=True)
        if data:
            ssh_public_key = data.get('user_attributes', {}).get('ssh_public_key')
            if ssh_public_key:
                cherrypy.response.headers['Content-Type'] = 'application/octet-stream'
                cherrypy.response.headers['Content-Disposition'] = 'attachment; filename="id_rsa.pub"'
                return ssh_public_key.encode('utf-8')
        cherrypy.response.headers['Content-Type'] = 'application/json'
        return json.dumps(data)

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    @Authenticated
    @JWT_AUTHORIZATION.USERS_VIEW(requested_actions=[JWT_AUTHORIZATION.USERS_VIEW], read_only=True)
    @func_timing
    def get_attributes(self):
        return self._get_attributes(public=True)

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    @Authenticated
    @JWT_AUTHORIZATION.USERS_MODIFY(requested_actions=[JWT_AUTHORIZATION.USERS_MODIFY], read_only=True)
    @func_timing
    def update_user_attributes(self):
        return self._update_user_attribute(public=True)

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    @Authenticated
    @JWT_AUTHORIZATION.GROUPS_MODIFY(requested_actions=[JWT_AUTHORIZATION.GROUPS_MODIFY], read_only=True)
    @func_timing
    def add_user_group(self):
        return self._add_user_group(public=True)

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    @Authenticated
    @JWT_AUTHORIZATION.GROUPS_MODIFY(requested_actions=[JWT_AUTHORIZATION.GROUPS_MODIFY], read_only=True)
    @func_timing
    def remove_user_group(self):
        return self._remove_user_group(public=True)

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    @Authenticated
    @JWT_AUTHORIZATION.SESSIONS_MODIFY(requested_actions=[JWT_AUTHORIZATION.SESSIONS_MODIFY], read_only=True)
    @func_timing
    def keepalive(self):
        response = {}
        event = cherrypy.request.json
        kasm_id = event.get('kasm_id')
        if kasm_id:
            kasm = cherrypy.request.authenticated_kasm
            user = kasm.user
            return self._keepalive(kasm, user)
        msg = 'Invalid Request: Missing required parameters'
        self.logger.error(msg)
        response['error_message'] = msg
        cherrypy.response.status = 400
        return response

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    @Authenticated
    @JWT_AUTHORIZATION.LICENSES_CREATE(requested_actions=[JWT_AUTHORIZATION.LICENSES_CREATE], read_only=False)
    @func_timing
    def activate(self):
        event = cherrypy.request.json
        return self._activate(activation_key=event.get('activation_key'), seats=event.get('seats'), issued_to=event.get('issued_to'), public=True)

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    @Authenticated
    @JWT_AUTHORIZATION.STAGING_VIEW(requested_actions=[JWT_AUTHORIZATION.STAGING_VIEW], read_only=True)
    @func_timing
    def get_staging_config(self):
        return self._get_staging_config(public=True)

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    @Authenticated
    @JWT_AUTHORIZATION.STAGING_CREATE(requested_actions=[JWT_AUTHORIZATION.STAGING_CREATE], read_only=False)
    @func_timing
    def create_staging_config(self):
        return self._create_staging_config(public=True)

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    @Authenticated
    @JWT_AUTHORIZATION.STAGING_MODIFY(requested_actions=[JWT_AUTHORIZATION.STAGING_MODIFY], read_only=False)
    @func_timing
    def update_staging_config(self):
        return self._update_staging_config(public=True)

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    @Authenticated
    @JWT_AUTHORIZATION.STAGING_DELETE(requested_actions=[JWT_AUTHORIZATION.STAGING_DELETE], read_only=False)
    @func_timing
    def delete_staging_config(self):
        return self._delete_staging_config(public=True)

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    @Authenticated
    @JWT_AUTHORIZATION.USERS_AUTH_SESSION(requested_actions=[JWT_AUTHORIZATION.USERS_AUTH_SESSION], read_only=True)
    @func_timing
    def get_session_tokens(self):
        return self._get_session_tokens(public=True)

    @(False,)
    def _get_session_tokens(self, public):
        response = {}
        event = cherrypy.request.json
        target_user = event.get('target_user')
        if target_user:
            user_id = target_user.get('user_id')
            if user_id:
                user = cherrypy.request.db.get_user_by_id(user_id)
                if user:
                    response['session_tokens'] = []
                    for x in user.session_tokens:
                        data = x.output(int(cherrypy.request.db.get_config_setting_value('auth', 'session_lifetime')))
                        response['session_tokens'].append(data)
                else:
                    msg = 'No user found with id: (%s)' % user_id
                    self.logger.error(msg)
                    response['error_message'] = msg
                    if public:
                        cherrypy.response.status = 400
            else:
                msg = 'Invalid Request: Missing required parameters'
                self.logger.error(msg)
                response['error_message'] = msg
                if public:
                    cherrypy.response.status = 400
        else:
            msg = 'Invalid Request: Missing required parameters'
            self.logger.error(msg)
            response['error_message'] = msg
            if public:
                cherrypy.response.status = 400
        return response

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    @Authenticated
    @JWT_AUTHORIZATION.USERS_AUTH_SESSION(requested_actions=[JWT_AUTHORIZATION.USERS_AUTH_SESSION], read_only=True)
    @func_timing
    def get_session_token(self):
        return self._get_session_token(public=True)

    @(False,)
    def _get_session_token(self, public):
        response = {}
        event = cherrypy.request.json
        target_session_token = event.get('target_session_token')
        if target_session_token:
            session_token = target_session_token.get('session_token')
            if session_token:
                session_token_obj = cherrypy.request.db.getSessionToken(session_token)
                if session_token_obj:
                    data = session_token_obj.output(int(cherrypy.request.db.get_config_setting_value('auth', 'session_lifetime')))
                    response['session_token'] = data
                else:
                    msg = 'Session Token (%s) not found' % session_token
                    self.logger.error(msg)
                    response['error_message'] = msg
                    if public:
                        cherrypy.response.status = 400
            else:
                msg = 'Invalid Request: Missing required parameters'
                self.logger.error(msg)
                response['error_message'] = msg
                if public:
                    cherrypy.response.status = 400
        else:
            msg = 'Invalid Request: Missing required parameters'
            self.logger.error(msg)
            response['error_message'] = msg
            if public:
                cherrypy.response.status = 400
        return response

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    @Authenticated
    @JWT_AUTHORIZATION.USERS_AUTH_SESSION(requested_actions=[JWT_AUTHORIZATION.USERS_AUTH_SESSION], read_only=False)
    @func_timing
    def create_session_token(self):
        return self._create_session_token(public=True)

    @(False,)
    def _create_session_token(self, public):
        response = {}
        event = cherrypy.request.json
        target_user = event.get('target_user')
        if target_user:
            user_id = target_user.get('user_id')
            if user_id:
                user = cherrypy.request.db.get_user_by_id(user_id)
                if user:
                    session_token_obj = cherrypy.request.db.createSessionToken(user)
                    data = session_token_obj.output(int(cherrypy.request.db.get_config_setting_value('auth', 'session_lifetime')))
                    response['session_token'] = data
                else:
                    msg = 'No user found with id: (%s)' % user_id
                    self.logger.error(msg)
                    response['error_message'] = msg
                    if public:
                        cherrypy.response.status = 400
            else:
                msg = 'Invalid Request: Missing required parameters'
                self.logger.error(msg)
                response['error_message'] = msg
                if public:
                    cherrypy.response.status = 400
        else:
            msg = 'Invalid Request: Missing required parameters'
            self.logger.error(msg)
            response['error_message'] = msg
            if public:
                cherrypy.response.status = 400
        return response

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    @Authenticated
    @JWT_AUTHORIZATION.USERS_AUTH_SESSION(requested_actions=[JWT_AUTHORIZATION.USERS_AUTH_SESSION], read_only=False)
    @func_timing
    def update_session_token(self):
        return self._update_session_token(public=True)

    @(False,)
    def _update_session_token(self, public):
        response = {}
        event = cherrypy.request.json
        target_session_token = event.get('target_session_token')
        if target_session_token:
            session_token = target_session_token.get('session_token')
            if session_token:
                session_token_obj = cherrypy.request.db.getSessionToken(session_token)
                if session_token_obj:
                    updated_session_token_obj = cherrypy.request.db.updateSessionToken(session_token_obj.session_token_id)
                    data = updated_session_token_obj.output(int(cherrypy.request.db.get_config_setting_value('auth', 'session_lifetime')))
                    response['session_token'] = data
                else:
                    msg = 'Session Token (%s) not found' % session_token
                    self.logger.error(msg)
                    response['error_message'] = msg
                    if public:
                        cherrypy.response.status = 400
            else:
                msg = 'Invalid Request: Missing required parameters'
                self.logger.error(msg)
                response['error_message'] = msg
                if public:
                    cherrypy.response.status = 400
        else:
            msg = 'Invalid Request: Missing required parameters'
            self.logger.error(msg)
            response['error_message'] = msg
            if public:
                cherrypy.response.status = 400
        return response

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    @Authenticated
    @JWT_AUTHORIZATION.USERS_AUTH_SESSION(requested_actions=[JWT_AUTHORIZATION.USERS_AUTH_SESSION], read_only=False)
    @func_timing
    def delete_session_token(self):
        return self._delete_session_token(public=True)

    def _delete_session_token(self, public=False):
        response = {}
        event = cherrypy.request.json
        target_session_token = event.get('target_session_token')
        if target_session_token:
            session_token = target_session_token.get('session_token')
            if session_token:
                session_token_obj = cherrypy.request.db.getSessionToken(session_token)
                if session_token_obj:
                    cherrypy.request.db.delete_session_token(session_token_obj)
                else:
                    msg = 'Session Token (%s) not found' % session_token
                    self.logger.error(msg)
                    response['error_message'] = msg
                    if public:
                        cherrypy.response.status = 400
            else:
                msg = 'Invalid Request: Missing required parameters'
                self.logger.error(msg)
                response['error_message'] = msg
                if public:
                    cherrypy.response.status = 400
        else:
            msg = 'Invalid Request: Missing required parameters'
            self.logger.error(msg)
            response['error_message'] = msg
            if public:
                cherrypy.response.status = 400
        return response

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    @Authenticated
    @JWT_AUTHORIZATION.USERS_AUTH_SESSION(requested_actions=[JWT_AUTHORIZATION.USERS_AUTH_SESSION], read_only=False)
    @func_timing
    def delete_session_tokens(self):
        return self._delete_session_tokens(public=True)

    @(False,)
    def _delete_session_tokens(self, public):
        response = {}
        event = cherrypy.request.json
        target_user = event.get('target_user')
        if target_user:
            user_id = target_user.get('user_id')
            if user_id:
                user = cherrypy.request.db.get_user_by_id(user_id)
                if user:
                    cherrypy.request.db.remove_all_session_tokens(user)
                else:
                    msg = 'No user found with id: (%s)' % user_id
                    self.logger.error(msg)
                    response['error_message'] = msg
                    if public:
                        cherrypy.response.status = 400
            else:
                msg = 'Invalid Request: Missing required parameters'
                self.logger.error(msg)
                response['error_message'] = msg
                if public:
                    cherrypy.response.status = 400
        else:
            msg = 'Invalid Request: Missing required parameters'
            self.logger.error(msg)
            response['error_message'] = msg
            if public:
                cherrypy.response.status = 400
        return response

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    @Authenticated
    @JWT_AUTHORIZATION.SESSIONS_MODIFY(requested_actions=[JWT_AUTHORIZATION.SESSIONS_MODIFY], read_only=False)
    def delete_session_permissions(self):
        return self._delete_session_permissions(public=True)

    @(False,)
    def _delete_session_permissions(self, public):
        response = {}
        event = cherrypy.request.json
        target_session_permissions = event.get('target_session_permissions')
        if target_session_permissions:
            kasm_id = target_session_permissions.get('kasm_id')
            user_ids = target_session_permissions.get('user_ids')
            if kasm_id and user_ids:
                if type(user_ids) == list:
                    session_permission_objs = []
                    for user_id in user_ids:
                        session_permission = cherrypy.request.db.get_session_permission(user_id=user_id, kasm_id=kasm_id)
                        if session_permission:
                            session_permission_objs.append(session_permission)
                        else:
                            msg = 'No session_permissions found with kasm_id: (%s) and user_id: (%s)' % (kasm_id, user_id)
                            self.logger.error(msg)
                            response['error_message'] = msg
                            if public:
                                cherrypy.response.status = 400
                            return response
                    else:
                        if session_permission_objs:
                            data = [{'user': x.vnc_username} for x in session_permission_objs]
                            log_data = [cherrypy.request.db.serializable(x.jsonDict) for x in session_permission_objs]
                            if self._kasmvnc_api('remove_user', session_permission_objs[0].kasm, False, 'post', data):
                                cherrypy.request.db.delete_session_permissions(session_permission_objs)
                                for x in log_data:
                                    self.logger.debug('Successfully deleted KasmVNC permission for user (%s), vnc_username: (%s) , access: (%s)' % (x['username'], x['vnc_username'], x['access']), extra={'kasm_id': x['kasm_id'], 'kasm_user_id': x['user_id'], 'kasm_user_name': x['username']})
                            else:
                                msg = 'Failed to delete session_permission_ids (%s)' % [x.session_permission_id.hex for x in session_permission_objs]
                                self.logger.error(msg)
                                response['error_message'] = msg
                                if public:
                                    cherrypy.response.status = 500
                                return response
            msg = 'Invalid Request: Missing required parameters'
            self.logger.error(msg)
            response['error_message'] = msg
            if public:
                cherrypy.response.status = 400
        else:
            msg = 'Invalid Request: Missing required parameters'
            self.logger.error(msg)
            response['error_message'] = msg
            if public:
                cherrypy.response.status = 400
        return response

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    @Authenticated
    @JWT_AUTHORIZATION.SESSIONS_MODIFY(requested_actions=[JWT_AUTHORIZATION.SESSIONS_MODIFY], read_only=False)
    def delete_all_session_permissions(self):
        return self._delete_all_session_permissions(public=True)

    @(False,)
    def _delete_all_session_permissions(self, public):
        response = {}
        event = cherrypy.request.json
        target_session_permissions = event.get('target_session_permissions')
        if target_session_permissions:
            kasm_id = target_session_permissions.get('kasm_id')
            if kasm_id:
                session_permission_objs = []
                session_permissions = cherrypy.request.db.get_session_permissions(kasm_id=kasm_id)
                if session_permissions:
                    data = [{'user': x.vnc_username} for x in session_permissions]
                    log_data = [cherrypy.request.db.serializable(x.jsonDict) for x in session_permissions]
                    if self._kasmvnc_api('remove_user', session_permissions[0].kasm, False, 'post', data):
                        cherrypy.request.db.delete_session_permissions(session_permissions)
                        for x in log_data:
                            self.logger.debug('Successfully deleted KasmVNC permission for user (%s), vnc_username: (%s) , access: (%s)' % (x['username'], x['vnc_username'], x['access']), extra={'kasm_id': x['kasm_id'], 'kasm_user_id': x['user_id'], 'kasm_user_name': x['username']})
                    else:
                        msg = 'Failed to delete session_permission_ids (%s)' % [x.session_permission_id.hex for x in session_permissions]
                        self.logger.error(msg)
                        response['error_message'] = msg
                        if public:
                            cherrypy.response.status = 500
                        return response
                else:
                    msg = 'No session permissions found for kasm_id (%s)' % kasm_id
                    self.logger.warning(msg)
            else:
                msg = 'Invalid Request: Missing required parameters'
                self.logger.error(msg)
                response['error_message'] = msg
                if public:
                    cherrypy.response.status = 400
        else:
            msg = 'Invalid Request: Missing required parameters'
            self.logger.error(msg)
            response['error_message'] = msg
            if public:
                cherrypy.response.status = 400
        return response

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    @Authenticated
    @JWT_AUTHORIZATION.SESSIONS_MODIFY(requested_actions=[JWT_AUTHORIZATION.SESSIONS_MODIFY], read_only=False)
    @func_timing
    def set_session_permissions(self):
        return self._set_session_permissions(public=True)

    @(False,)
    def _set_session_permissions(self, public):
        response = {}
        event = cherrypy.request.json
        target_session_permissions = event.get('target_session_permissions')
        if target_session_permissions:
            kasm_id = target_session_permissions.get('kasm_id')
            session_permissions = target_session_permissions.get('session_permissions')
            if kasm_id and session_permissions and (type(session_permissions) == list):
                kasm = cherrypy.request.db.getKasm(kasm_id)
                if kasm:
                    _provisional_permissions = []
                    for permission_request in session_permissions:
                        user_id = permission_request.get('user_id')
                        access = permission_request.get('access')
                        if user_id and access != None:
                            user = cherrypy.request.db.get_user_by_id(user_id)
                            if user:
                                _provisional_permission_request = {'access': access, 'user': user}
                                session_permission = cherrypy.request.db.get_session_permission(user_id=user_id, kasm_id=kasm_id)
                                if session_permission:
                                    _provisional_permission_request['vnc_username'] = session_permission.vnc_username
                                    _provisional_permission_request['vnc_password'] = session_permission.vnc_password
                                    _provisional_permission_request['existing_record'] = session_permission
                                else:
                                    _provisional_permission_request['vnc_username'] = uuid.uuid4().hex[0:15]
                                    _provisional_permission_request['vnc_password'] = uuid.uuid4().hex
                                    _provisional_permission_request['existing_record'] = None
                                _provisional_permission_request['request_data'] = {'user': _provisional_permission_request['vnc_username'], 'password': _provisional_permission_request['vnc_password'], 'read': True if 'r' in _provisional_permission_request['access'] else False, 'write': True if 'w' in _provisional_permission_request['access'] else False, 'owner': True if 'o' in _provisional_permission_request['access'] else False}
                                _provisional_permissions.append(_provisional_permission_request)
                            else:
                                msg = 'No user found with id: (%s)' % user_id
                                self.logger.error(msg)
                                response['error_message'] = msg
                                if public:
                                    cherrypy.response.status = 400
                                break
                        else:
                            msg = 'Invalid Request: Missing required parameters'
                            self.logger.error(msg)
                            response['error_message'] = msg
                            if public:
                                cherrypy.response.status = 400
                            break
                    response['session_permissions'] = []
                    if _provisional_permissions:
                        data = [x['request_data'] for x in _provisional_permissions]
                        if self._kasmvnc_api('create_user', kasm, False, 'post', data):
                            for provisional_permission in _provisional_permissions:
                                self.logger.debug('Successfully added KasmVNC permission for user (%s), vnc_username: (%s) , access: (%s)' % (provisional_permission['user'].username, provisional_permission['vnc_username'], provisional_permission['access']), extra={'kasm_id': kasm.kasm_id, 'kasm_user_id': provisional_permission['user'].user_id, 'kasm_user_name': provisional_permission['user'].username})
                                if provisional_permission['existing_record']:
                                    session_permission = cherrypy.request.db.update_session_permission(provisional_permission['existing_record'], provisional_permission['access'])
                                else:
                                    session_permission = cherrypy.request.db.create_session_permission(kasm_id, provisional_permission['user'].user_id, provisional_permission['access'], provisional_permission['vnc_username'], provisional_permission['vnc_password'])
                                response['session_permissions'].append(cherrypy.request.db.serializable(session_permission.jsonDict))
                        else:
                            msg = 'Error with request'
                            self.logger.error(msg)
                            response['error_message'] = msg
                            if public:
                                cherrypy.response.status = 400
                else:
                    msg = 'No session found with kasm_id (%s)' % kasm_id
                    self.logger.error(msg)
                    response['error_message'] = msg
                    if public:
                        cherrypy.response.status = 400
            else:
                msg = 'Invalid Request: Missing required parameters'
                self.logger.error(msg)
                response['error_message'] = msg
                if public:
                    cherrypy.response.status = 400
        else:
            msg = 'Invalid Request: Missing required parameters'
            self.logger.error(msg)
            response['error_message'] = msg
            if public:
                cherrypy.response.status = 400
        return response

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    @Authenticated
    @JWT_AUTHORIZATION.SESSIONS_MODIFY(requested_actions=[JWT_AUTHORIZATION.SESSIONS_MODIFY], read_only=False)
    @func_timing
    def set_all_session_permissions(self):
        return self._set_all_session_permissions(public=True)

    @(False,)
    def _set_all_session_permissions(self, public):
        response = {}
        event = cherrypy.request.json
        target_session_permissions = event.get('target_session_permissions')
        if target_session_permissions:
            kasm_id = target_session_permissions.get('kasm_id')
            access = target_session_permissions.get('access')
            if kasm_id and access != None:
                kasm = cherrypy.request.db.getKasm(kasm_id)
                if kasm:
                    _provisional_permissions = []
                    for session_permission in kasm.session_permissions:
                        _provisional_permission_request = {'access': access, 'user': session_permission.user}
                        _provisional_permission_request['vnc_username'] = session_permission.vnc_username
                        _provisional_permission_request['vnc_password'] = session_permission.vnc_password
                        _provisional_permission_request['existing_record'] = session_permission
                        _provisional_permission_request['request_data'] = {'user': _provisional_permission_request['vnc_username'], 'password': _provisional_permission_request['vnc_password'], 'read': True if 'r' in _provisional_permission_request['access'] else False, 'write': True if 'w' in _provisional_permission_request['access'] else False, 'owner': True if 'o' in _provisional_permission_request['access'] else False}
                        _provisional_permissions.append(_provisional_permission_request)
                    response['session_permissions'] = []
                    if _provisional_permissions:
                        data = [x['request_data'] for x in _provisional_permissions]
                        if self._kasmvnc_api('create_user', kasm, False, 'post', data):
                            for provisional_permission in _provisional_permissions:
                                self.logger.debug('Successfully added KasmVNC permission for user (%s), vnc_username: (%s) , access: (%s)' % (provisional_permission['user'].username, provisional_permission['vnc_username'], provisional_permission['access']), extra={'kasm_id': kasm.kasm_id, 'kasm_user_id': provisional_permission['user'].user_id, 'kasm_user_name': provisional_permission['user'].username})
                                if provisional_permission['existing_record']:
                                    session_permission = cherrypy.request.db.update_session_permission(provisional_permission['existing_record'], provisional_permission['access'])
                                else:
                                    session_permission = cherrypy.request.db.create_session_permission(kasm_id, provisional_permission['user'].user_id, provisional_permission['access'], provisional_permission['vnc_username'], provisional_permission['vnc_password'])
                                response['session_permissions'].append(cherrypy.request.db.serializable(session_permission.jsonDict))
                        else:
                            msg = 'Error with request'
                            self.logger.error(msg)
                            response['error_message'] = msg
                            if public:
                                cherrypy.response.status = 400
                else:
                    msg = 'No session found with kasm_id (%s)' % kasm_id
                    self.logger.error(msg)
                    response['error_message'] = msg
                    if public:
                        cherrypy.response.status = 400
            else:
                msg = 'Invalid Request: Missing required parameters'
                self.logger.error(msg)
                response['error_message'] = msg
                if public:
                    cherrypy.response.status = 400
        else:
            msg = 'Invalid Request: Missing required parameters'
            self.logger.error(msg)
            response['error_message'] = msg
            if public:
                cherrypy.response.status = 400
        return response

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    @Authenticated
    @JWT_AUTHORIZATION.SESSIONS_VIEW(requested_actions=[JWT_AUTHORIZATION.SESSIONS_VIEW], read_only=True)
    def get_session_permissions(self):
        return self._get_session_permissions(public=True)

    def _get_session_permissions(self, public=False):
        response = {}
        event = cherrypy.request.json
        target_session_permissions = event.get('target_session_permissions')
        if target_session_permissions:
            kasm_id = target_session_permissions.get('kasm_id')
            user_id = target_session_permissions.get('user_id')
            session_permission_id = target_session_permissions.get('session_permission_id')
            if any([kasm_id, user_id, session_permission_id]):
                session_permissions = cherrypy.request.db.get_session_permissions(session_permission_id=session_permission_id, user_id=user_id, kasm_id=kasm_id)
                response['session_permissions'] = [cherrypy.request.db.serializable(x.jsonDict) for x in session_permissions]
            else:
                msg = 'Invalid Request: Missing required parameters'
                self.logger.error(msg)
                response['error_message'] = msg
                if public:
                    cherrypy.response.status = 400
        return response

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    @Authenticated
    @JWT_AUTHORIZATION.CASTING_VIEW(requested_actions=[JWT_AUTHORIZATION.CASTING_VIEW], read_only=True)
    @func_timing
    def get_cast_configs(self):
        return self._get_cast_configs()

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    @Authenticated
    @JWT_AUTHORIZATION.CASTING_VIEW(requested_actions=[JWT_AUTHORIZATION.CASTING_VIEW], read_only=True)
    @func_timing
    def get_cast_config(self):
        return self._get_cast_config(public=True)

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    @Authenticated
    @JWT_AUTHORIZATION.CASTING_DELETE(requested_actions=[JWT_AUTHORIZATION.CASTING_DELETE], read_only=False)
    def delete_cast_config(self):
        return self._delete_cast_config(public=True)

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    @Authenticated
    @JWT_AUTHORIZATION.CASTING_MODIFY(requested_actions=[JWT_AUTHORIZATION.CASTING_MODIFY], read_only=False)
    @func_timing
    def update_cast_config(self):
        return self._update_cast_config(public=True)

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    @Authenticated
    @JWT_AUTHORIZATION.CASTING_CREATE(requested_actions=[JWT_AUTHORIZATION.CASTING_CREATE], read_only=False)
    @func_timing
    def create_cast_config(self):
        return self._create_cast_config(public=True)

    @cherrypy.expose
    @cherrypy.tools.json_out()
    @cherrypy.tools.json_in()
    @Authenticated
    @JWT_AUTHORIZATION.SESSION_RECORDINGS_VIEW(requested_actions=[JWT_AUTHORIZATION.SESSION_RECORDINGS_VIEW], read_only=True)
    def get_session_recordings(self):
        return self._get_session_recordings(public=True)

    @cherrypy.expose
    @cherrypy.tools.json_out()
    @cherrypy.tools.json_in()
    @Authenticated
    @JWT_AUTHORIZATION.SESSION_RECORDINGS_VIEW(requested_actions=[JWT_AUTHORIZATION.SESSION_RECORDINGS_VIEW], read_only=True)
    def get_sessions_recordings(self):
        return self._get_sessions_recordings(public=True)
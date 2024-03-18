# Source Generated with Decompyle++
# File: admin_api.pyc (Python 3.8)

from multiprocessing.sharedctypes import Value
import os
import uuid
import json
import cherrypy
import datetime
import logging.config as logging
import random
import string
import typing
import re
import base64
import yaml
import io
import pyzipper
import base64
import urllib.request as urllib
import certifi
import jwt
import math

try:
    from zoneinfo import ZoneInfoNotFoundError
finally:
    pass
except ImportError:
    from backports.zoneinfo import ZoneInfoNotFoundError


from provider_manager import ProviderManager
from data.data_access_factory import DataAccessFactory
from data.keygen import generate_ssl_certs
from data.categories import ALL_CATEGORIES, SAFE_SEARCH_PATTERNS
from data.enums import AZURE_AUTHORITY, SESSION_OPERATIONAL_STATUS, STORAGE_PROVIDER_TYPES, JWT_AUTHORIZATION, SERVER_OPERATIONAL_STATUS, OS_TYPES, SERVER_TYPE
from data.data_utils import is_sanitized
from utils import Authenticated, is_valid_email_address, passwordComplexityCheck, LicenseHelper, validate_volume_config, get_interval, validate_usage_limit, get_usage, validate_overlapping_domains, IPAddressHelper, validate_safe_search_patterns, parse_multiline_input, process_json_props, JsonValidationException, validate_session_token_ex, parse_docker_image, JwtAuthenticated, generate_jwt_token, CookieAuthenticated, create_session_recording_request_log, validate_launch_config, Unauthenticated
from client_api import ClientApi
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography import x509
from packaging import version
from authentication.ldap_auth import LDAPAuthentication
from licensing import Activation
from zipfile import ZipFile
from sqlalchemy.exc import IntegrityError
from io import BytesIO
from storage_providers import GoogleDrive, Dropbox, OneDrive, S3, Nextcloud, CustomStorageProvider
from copy import deepcopy
from urllib.parse import urlparse
from providers.aws_provider import AwsObjectStorageProvider

class AdminApi(ClientApi):
    
    def __init__(self, config):
        self.config = config
        self._db = DataAccessFactory.createSession(config['database']['type'], config)
        self._db = DataAccessFactory.createSession(config['database']['type'], config)
        self.logger = logging.getLogger('admin_api_server')
        self.logger.info('%s initialized' % self.__class__.__name__)
        self.provider_manager = ProviderManager(config, self._db, self.logger, **('logger',))

    
    def get_report(self):
        response = { }
        event = cherrypy.request.json
    # WARNING: Decompyle incomplete

    get_report = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.REPORTS_VIEW], True, **('requested_actions', 'read_only'))(get_report))))
    
    def log_query(self, event):
        query = " \n                    SELECT \n                        host, \n                        ingest_date, \n                        data->>'application' as application, \n                        levelname, \n                        data->>'funcname' as funcname, \n                        kasm_user_name, \n                        data->>'message' as message, \n                        data->>'exc_info' as traceback,\n                        data->>'error_stack' as error_stack,\n                        data->>'name' as process,\n                        data->>'request_ip' as client_ip,\n                        data->>'user_agent' as user_agent,\n                        data->>'allow' as allow,\n                        data->>'url' as url,\n                        data->>'site' as site,\n                        data->>'domain' as domain,\n                        data->>'category' as category\n                        \n                    FROM logs \n                    WHERE \n                        ingest_date < to_timestamp('$end_date', 'YYYYMMDD HH24:MI') AND\n                        ingest_date > to_timestamp('$start_date', 'YYYYMMDD HH24:MI')\t  \n                "
        if 'filters' in event:
            for key, value in event['filters'].items():
                if key == 'process':
                    query += " AND data->>'name' LIKE '%" + cherrypy.request.db.escape_string(value) + "%'"
                    continue
                if key == 'search':
                    query += " AND LOWER(data->>'message') LIKE LOWER('%" + cherrypy.request.db.escape_string(value) + "%')"
                    continue
                if key == 'application':
                    query += " AND LOWER(data->>'application') LIKE LOWER('%" + cherrypy.request.db.escape_string(value) + "%')"
                    continue
                if key == 'searchUser':
                    query += " AND LOWER(kasm_user_name) LIKE LOWER('%" + cherrypy.request.db.escape_string(value) + "%')"
                    continue
                if key == 'metricName':
                    query += " AND LOWER(metric_name) LIKE LOWER('%" + cherrypy.request.db.escape_string(value) + "%')"
                    continue
                if key == 'allowed':
                    query += " AND LOWER(data->>'allow') LIKE LOWER('%" + cherrypy.request.db.escape_string(value) + "%')"
                    continue
                if key == 'category':
                    query += " AND LOWER(data->>'category') LIKE LOWER('%" + cherrypy.request.db.escape_string(value) + "%')"
                    continue
                if key == 'site':
                    query += " AND LOWER(data->>'site') LIKE LOWER('%" + cherrypy.request.db.escape_string(value) + "%')"
                    continue
                if key == 'levelname':
                    query += ' AND (' + cherrypy.request.db.escape_string(key) + " = '" + cherrypy.request.db.escape_string(value) + "'"
                    if value == 'DEBUG':
                        query += ' OR ' + cherrypy.request.db.escape_string(key) + " = '" + 'INFO' + "'"
                        query += ' OR ' + cherrypy.request.db.escape_string(key) + " = '" + 'WARNING' + "'"
                        query += ' OR ' + cherrypy.request.db.escape_string(key) + " = '" + 'ERROR' + "'"
                        query += ' OR ' + cherrypy.request.db.escape_string(key) + " = '" + 'CRITICAL' + "')"
                    if value == 'INFO':
                        query += ' OR ' + cherrypy.request.db.escape_string(key) + " = '" + 'WARNING' + "'"
                        query += ' OR ' + cherrypy.request.db.escape_string(key) + " = '" + 'ERROR' + "'"
                        query += ' OR ' + cherrypy.request.db.escape_string(key) + " = '" + 'CRITICAL' + "')"
                    if value == 'WARNING':
                        query += ' OR ' + cherrypy.request.db.escape_string(key) + " = '" + 'ERROR' + "'"
                        query += ' OR ' + cherrypy.request.db.escape_string(key) + " = '" + 'CRITICAL' + "')"
                    if value == 'ERROR':
                        query += ' OR ' + cherrypy.request.db.escape_string(key) + " = '" + 'CRITICAL' + "')"
                    if value == 'CRITICAL':
                        query += ')'
                        continue
                        query += ' AND ' + cherrypy.request.db.escape_string(key) + " = '" + cherrypy.request.db.escape_string(value) + "'"
        if 'exclude_filters' in event:
            for key, value in event['exclude_filters'].items():
                if key == 'metricName':
                    query += " AND (metric_name is NULL or LOWER(metric_name) NOT LIKE LOWER('%" + cherrypy.request.db.escape_string(value) + "%'))"
                    continue
                    query += ' ORDER BY ingest_date DESC LIMIT $limit'
                    return query

    
    def get_alert_report(self):
        response = { }
        return response

    get_alert_report = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.REPORTS_VIEW], True, **('requested_actions', 'read_only'))(get_alert_report))))
    
    def get_distinct_hosts(self):
        response = { }
        query = 'SELECT  DISTINCT host FROM logs'
        rows = cherrypy.request.db.execute_native_query(query).fetchall()
        if len(rows) > 0:
            response['data'] = []
            for row in rows:
                d_row = { }
                for key, value in row.items():
                    d_row[key] = value
                response['data'].append(d_row)
        return response

    get_distinct_hosts = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.REPORTS_VIEW], True, **('requested_actions', 'read_only'))(get_distinct_hosts))))
    
    def get_agent_report(self):
        response = { }
        event = cherrypy.request.json
        agents = []
        servers = self._get_servers()
        for server in servers['servers']:
            if not server.get('last_reported'):
                continue
            agent = { }
            agent['name'] = server['hostname']
            agent['disk_space'] = server['disk_stats']['total']
            agent['disk_space_used'] = server['disk_stats']['used']
            agent['disk_space_free'] = server['disk_stats']['free']
            agent['memory_total'] = server['memory_stats']['total']
            agent['memory_used'] = server['memory_stats']['used']
            agent['memory_free'] = server['memory_stats']['available']
            agent['kasms'] = len(server['kasms'])
            agent['server_id'] = server['server_id']
            if agent['disk_space_used'] / agent['disk_space'] > 0.85:
                agent['health'] = 'Disk Warning'
            if agent['memory_used'] / agent['memory_total'] > 0.9:
                agent['health'] = 'Memory Warning'
            if 'health' not in agent:
                agent['health'] = 'Healthy'
            agents.append(agent)
        response['agents'] = agents
        return response

    get_agent_report = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.REPORTS_VIEW], True, **('requested_actions', 'read_only'))(get_agent_report))))
    
    def get_groups(self):
        response = { }
        groups = cherrypy.request.db.getGroups()
        if groups:
            f_groups = []
            for group in groups:
                if JWT_AUTHORIZATION.is_user_authorized_action(cherrypy.request.authenticated_user, cherrypy.request.authorizations, JWT_AUTHORIZATION.GROUPS_VIEW, group, **('target_group',)):
                    group_mappings = []
                    for group_mapping in group.group_mappings:
                        group_mappings.append(group_mapping.jsonDict)
                    f_groups.append({
                        'group_id': group.group_id,
                        'name': group.name,
                        'description': group.description,
                        'priority': group.priority,
                        'is_system': group.is_system,
                        'group_metadata': group.group_metadata,
                        'group_mappings': group_mappings })
                    continue
                    response['groups'] = cherrypy.request.db.serializable(f_groups)
                    return response

    get_groups = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.GROUPS_VIEW,
        JWT_AUTHORIZATION.GROUPS_VIEW_IFMEMBER,
        JWT_AUTHORIZATION.GROUPS_VIEW_SYSTEM], True, **('requested_actions', 'read_only'))(get_groups))))
    
    def create_group(self):
        response = { }
        event = cherrypy.request.json
        if 'target_group' in event:
            target_group = event['target_group']
            if 'name' in target_group and 'priority' in target_group:
                existing_group = (lambda .0 = None: [ x for x in .0 if x.name == target_group['name'] ])(cherrypy.request.db.getGroups())
                if not existing_group:
                    pri = int(target_group['priority'])
                    if pri > 0 and pri < 4096:
                        new_group = cherrypy.request.db.createGroup(target_group['name'], target_group.get('description'), target_group['priority'], target_group.get('group_metadata'), **('name', 'description', 'priority', 'group_metadata'))
                        self.logger.info('Created Group (%s) - (%s)' % (new_group.group_id, new_group.name))
                        response['group_mappings'] = []
                        if 'group_mappings' in target_group:
                            for group_mapping in target_group('group_mappings'):
                                group_mapping_retrieved = cherrypy.request.db.createGroupMapping(group_mapping.get('group_id'), group_mapping.get('ldap_id'), group_mapping.get('saml_id'), group_mapping.get('oidc_id'), group_mapping.get('sso_group_attributes'), group_mapping.get('apply_to_all_users'), **('group_id', 'ldap_id', 'saml_id', 'oidc_id', 'sso_group_attributes', 'apply_to_all_users'))
                                response['group_mappings'].append(group_mapping_retrieved.jsonDict)
                        response['group'] = cherrypy.request.db.serializable(new_group.jsonDict)
                    else:
                        msg = 'Invalid priority value (%s)' % target_group.get('priority')
                        self.logger.error(msg)
                        response['error_message'] = msg
                else:
                    msg = 'Group (%s) already exists' % target_group.get('name')
                    self.logger.error(msg)
                    response['error_message'] = msg
            else:
                msg = 'Invalid Request. Missing required parameters'
                self.logger.error(msg)
                response['error_message'] = msg
        else:
            msg = 'Invalid Request. Missing required parameters'
            self.logger.error(msg)
            response['error_message'] = msg
        return response

    create_group = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.GROUPS_CREATE], False, **('requested_actions', 'read_only'))(create_group))))
    
    def update_group(self):
        response = { }
        event = cherrypy.request.json
        if 'target_group' in event:
            target_group = event['target_group']
            group_id = target_group.get('group_id')
            if group_id:
                
                try:
                    group_id = uuid.UUID(group_id)
                finally:
                    pass
                group_id = None
                if group_id:
                    group = cherrypy.request.db.getGroup(group_id)
                    if group:
                        if JWT_AUTHORIZATION.is_user_authorized_action(cherrypy.request.authenticated_user, cherrypy.request.authorizations, JWT_AUTHORIZATION.GROUPS_MODIFY, group, **('target_group',)):
                            updated_group = cherrypy.request.db.update_group(group, target_group.get('name'), target_group.get('description'), target_group.get('priority'), target_group.get('group_metadata'), **('name', 'description', 'priority', 'group_metadata'))
                            self.logger.info('Updated Group (%s) - (%s)' % (updated_group.group_id, updated_group.name))
                            response['group_mappings'] = []
                            if 'group_mappings' in target_group:
                                for group_mapping in target_group('group_mappings'):
                                    group_mapping_retrieved = cherrypy.request.db.getGroupMapping(group_mapping['sso_group_id'], **('sso_group_id',))
                                    if group_mapping_retrieved:
                                        group_mapping_retrieved = cherrypy.request.db.updateGroupMappin(group_mapping_retrieved, group_mapping.get('ldap_id'), group_mapping.get('saml_id'), group_mapping.get('oidc_id'), group_mapping.get('sso_group_attributes'), group_mapping.get('apply_to_all_users'), **('group_mapping', 'ldap_id', 'saml_id', 'oidc_id', 'sso_group_attributes', 'apply_to_all_users'))
                                        continue
                                    group_mapping_retrieved = cherrypy.request.db.createGroupMappin(group_mapping.get('group_id'), group_mapping.get('ldap_id'), group_mapping.get('saml_id'), group_mapping.get('oidc_id'), group_mapping.get('sso_group_attributes'), group_mapping.get('apply_to_all_users'), **('group_id', 'ldap_id', 'saml_id', 'oidc_id', 'sso_group_attributes', 'apply_to_all_users'))
                                response['group_mappings'].append(group_mapping_retrieved.jsonDict)
                            response['group'] = cherrypy.request.db.serializable(updated_group.jsonDict)
                        else:
                            msg = 'User not authorized to modify the target group.'
                            cherrypy.response.status = 401
                            self.logger.warning(msg)
                            response['error_message'] = msg
                    else:
                        msg = 'Invalid Request. group does not exit by that id'
                        self.logger.error(msg)
                        response['error_message'] = msg
                else:
                    msg = 'Invalid Request. group_id must be a uuid'
                    self.logger.error(msg)
                    response['error_message'] = msg

            msg = 'Invalid Request. Missing required parameters'
            self.logger.error(msg)
            response['error_message'] = msg
        else:
            msg = 'Invalid Request. Missing required parameters'
            self.logger.error(msg)
            response['error_message'] = msg
        return response

    update_group = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.GROUPS_MODIFY,
        JWT_AUTHORIZATION.GROUPS_MODIFY_IFMEMBER,
        JWT_AUTHORIZATION.GROUPS_MODIFY_SYSTEM], False, **('requested_actions', 'read_only'))(update_group))))
    
    def delete_group(self):
        response = { }
        event = cherrypy.request.json
        force = False
        if 'force' in event:
            if isinstance(event['force'], bool):
                force = event['force']
            else:
                msg = "Invalid Request. 'force' option must be boolean"
                self.logger.error(msg)
                response['error_message'] = msg
                return response
            if None in event and 'group_id' in event['target_group']:
                target_group = event['target_group']
                group = cherrypy.request.db.getGroup(target_group['group_id'])
                if group:
                    if group.is_system:
                        msg = 'Group (%s) is a protected group and cannot be deleted' % group.name
                        self.logger.error(msg)
                        response['error_message'] = msg
                    elif group.cast_configs:
                        configs = ','.join((lambda .0: [ str(x.cast_config_id) for x in .0 ])(group.cast_configs))
                        msg = 'Group (%s) is referenced in Cast configuration (%s) and cannot be deleted' % (group.name, configs)
                        self.logger.error(msg)
                        response['error_message'] = msg
                    elif force:
                        cherrypy.request.db.delete_group(group)
                    else:
                        num_users = len(group.users.all())
                        if num_users > 0:
                            msg = "Group contains (%s) users and 'force' option not set to True" % num_users
                            self.logger.error(msg)
                            response['error_message'] = msg
                        else:
                            cherrypy.request.db.delete_group(group)
                else:
                    msg = 'Group %s does not exist' % target_group.get('group_id')
                    self.logger.error(msg)
                    response['error_message'] = msg
            else:
                msg = 'Invalid Request: Missing required parameters'
                self.logger.error(msg)
                response['error_message'] = msg
        return response

    delete_group = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.GROUPS_DELETE], False, **('requested_actions', 'read_only'))(delete_group))))
    
    def add_user_group(self):
        return self._add_user_group()

    add_user_group = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.GROUPS_MODIFY,
        JWT_AUTHORIZATION.GROUPS_MODIFY_IFMEMBER,
        JWT_AUTHORIZATION.GROUPS_MODIFY_SYSTEM], False, **('requested_actions', 'read_only'))(add_user_group))))
    
    def _add_user_group(self, public = (False,)):
        response = { }
        event = cherrypy.request.json
        target_user = event.get('target_user')
        target_group = event.get('target_group')
        if target_user and 'user_id' in target_user and target_group and 'group_id' in target_group:
            group = cherrypy.request.db.getGroup(event['target_group']['group_id'])
            user = cherrypy.request.db.get_user_by_id(event['target_user']['user_id'])
            if user is None:
                msg = 'Invalid User ID (%s)' % event['target_user']['user_id']
                self.logger.error(msg)
                response['error_message'] = msg
                if public:
                    cherrypy.response.status = 400
            elif group is None:
                msg = 'Invalid Group ID (%s)' % event['target_group']['group_id']
                self.logger.error(msg)
                response['error_message'] = msg
                if public:
                    cherrypy.response.status = 400
                elif None((lambda .0 = None: [ g for g in .0 if g.group_id == group.group_id ])(user.groups)) > 0:
                    msg = 'User (%s) is already a member of group (%s)' % (event['target_user']['user_id'], event['target_group']['group_id'])
                    self.logger.error(msg)
                    response['error_message'] = msg
                    if public:
                        cherrypy.response.status = 400
                    elif JWT_AUTHORIZATION.is_user_authorized_action(cherrypy.request.authenticated_user, cherrypy.request.authorizations, JWT_AUTHORIZATION.GROUPS_MODIFY, group, **('target_group',)):
                        cherrypy.request.db.addUserGroup(user, group)
                        self.logger.info('Added user (%s) to group (%s)' % (user.username, group.name))
                    else:
                        msg = f'''User ({cherrypy.request.kasm_user_id}) made unauthorized attempt to modify group ({group.name})'''
                        self.logger.warning(msg)
                        response['error_message'] = 'Unauthorized'
                        cherrypy.response.status = 401
                else:
                    msg = 'Invalid Request: Missing required parameters'
                    self.logger.error(msg)
                    response['error_message'] = msg
                    if public:
                        cherrypy.response.status = 400
        return response

    
    def remove_user_group(self):
        return self._remove_user_group()

    remove_user_group = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.GROUPS_MODIFY,
        JWT_AUTHORIZATION.GROUPS_MODIFY_IFMEMBER,
        JWT_AUTHORIZATION.GROUPS_MODIFY_SYSTEM], False, **('requested_actions', 'read_only'))(remove_user_group))))
    
    def _remove_user_group(self, public = (False,)):
        response = { }
        event = cherrypy.request.json
        target_user = event.get('target_user')
        target_group = event.get('target_group')
        if target_user and 'user_id' in target_user and target_group and 'group_id' in target_group:
            group = cherrypy.request.db.getGroup(event['target_group']['group_id'])
            user = cherrypy.request.db.get_user_by_id(event['target_user']['user_id'])
            if user is None:
                msg = 'Invalid User ID (%s)' % event['target_user']['user_id']
                self.logger.error(msg)
                response['error_message'] = msg
                if public:
                    cherrypy.response.status = 400
            elif group is None:
                msg = 'Invalid Group ID (%s)' % event['target_group']['group_id']
                self.logger.error(msg)
                response['error_message'] = msg
                if public:
                    cherrypy.response.status = 400
                elif group not in (lambda .0: [ x.group for x in .0 ])(user.groups):
                    msg = 'User (%s) is not a member of group (%s)' % (event['target_user']['user_id'], event['target_group']['group_id'])
                    self.logger.error(msg)
                    response['error_message'] = msg
                    if public:
                        cherrypy.response.status = 400
                    elif JWT_AUTHORIZATION.is_user_authorized_action(cherrypy.request.authenticated_user, cherrypy.request.authorizations, JWT_AUTHORIZATION.GROUPS_MODIFY, group, **('target_group',)):
                        cherrypy.request.db.removeUserGroup(user, group)
                        self.logger.info('Removed user (%s) from group (%s)' % (user.username, group.name))
                    else:
                        msg = f'''User ({cherrypy.request.kasm_user_id}) made unauthorized attempt to modify group ({group.name})'''
                        self.logger.warning(msg)
                        response['error_message'] = 'Unauthorized'
                        cherrypy.response.status = 401
                else:
                    msg = 'Invalid Request: Missing required parameters'
                    self.logger.error(msg)
                    response['error_message'] = msg
                    if public:
                        cherrypy.response.status = 400
        return response

    
    def get_users_group(self):
        response = { }
        event = cherrypy.request.json
        target_group = event.get('target_group')
        if target_group and 'group_id' in target_group:
            group = cherrypy.request.db.getGroup(event['target_group']['group_id'])
            if group is not None:
                if JWT_AUTHORIZATION.is_user_authorized_action(cherrypy.request.authenticated_user, cherrypy.request.authorizations, JWT_AUTHORIZATION.GROUPS_VIEW, group, **('target_group',)):
                    users = group.get_users(event['page'] if 'page' in event else None, event['page_size'] if 'page_size' in event else None, event['filters'] if 'filters' in event else [], event['sort_by'] if 'sort_by' in event else None, event['sort_direction'] if 'sort_direction' in event else 'desc', **('page', 'page_size', 'filters', 'sort_by', 'sort_direction'))
                    response['users'] = cherrypy.request.db.serializable(users['users'])
                    response['total'] = cherrypy.request.db.serializable(users['total'])
                else:
                    msg = f'''User ({cherrypy.request.kasm_user_id}) made unauthorized attempt to view a group ({group.name})'''
                    self.logger.warning(msg)
                    response['error_message'] = 'Unauthorized'
                    cherrypy.response.status = 401
            else:
                msg = 'Invalid Group ID (%s)' % event['target_group']['group_id']
                self.logger.error(msg)
                response['error_message'] = msg
        else:
            msg = 'Invalid Request: Missing required parameters'
            self.logger.error(msg)
            response['error_message'] = msg
        return response

    get_users_group = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.GROUPS_VIEW,
        JWT_AUTHORIZATION.GROUPS_VIEW_IFMEMBER,
        JWT_AUTHORIZATION.GROUPS_VIEW_SYSTEM], True, **('requested_actions', 'read_only'))(get_users_group))))
    
    def get_user_groups_settings(self):
        response = { }
        event = cherrypy.request.json
    # WARNING: Decompyle incomplete

    get_user_groups_settings = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.USERS_VIEW], True, **('requested_actions', 'read_only'))(get_user_groups_settings))))
    
    def get_settings_group(self):
        response = { }
        event = cherrypy.request.json
        target_group = event.get('target_group')
        if target_group and 'group_id' in target_group and target_group['group_id'] != '':
            group = cherrypy.request.db.getGroup(event['target_group']['group_id'])
            if group is not None:
                if JWT_AUTHORIZATION.is_user_authorized_action(cherrypy.request.authenticated_user, cherrypy.request.authorizations, JWT_AUTHORIZATION.GROUPS_VIEW, group, **('target_group',)):
                    response['settings'] = (lambda .0: [ cherrypy.request.db.serializable(x.jsonDict) for x in .0 ])(group.settings)
                else:
                    msg = f'''User ({cherrypy.request.kasm_user_id}) made unauthorized attempt to view group ({group.name}) settings.'''
                    self.logger.warning(msg)
                    response['error_message'] = 'Unauthorized'
                    cherrypy.response.status = 401
            else:
                default_settings = cherrypy.request.db.getDefaultGroupSettings()
                response['settings'] = (lambda .0: [ cherrypy.request.db.serializable(x.jsonDict) for x in .0 ])(default_settings)
        return response

    get_settings_group = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.GROUPS_VIEW,
        JWT_AUTHORIZATION.GROUPS_VIEW_IFMEMBER,
        JWT_AUTHORIZATION.GROUPS_VIEW_SYSTEM], True, **('requested_actions', 'read_only'))(get_settings_group))))
    
    def add_settings_group(self):
        response = { }
        event = cherrypy.request.json
        target_group = event.get('target_group')
        target_setting = event.get('target_setting')
    # WARNING: Decompyle incomplete

    add_settings_group = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.GROUPS_MODIFY,
        JWT_AUTHORIZATION.GROUPS_MODIFY_IFMEMBER,
        JWT_AUTHORIZATION.GROUPS_MODIFY_SYSTEM], False, **('requested_actions', 'read_only'))(add_settings_group))))
    
    def update_settings_group(self):
        response = { }
        event = cherrypy.request.json
        target_group = event.get('target_group')
        target_setting = event.get('target_setting')
    # WARNING: Decompyle incomplete

    update_settings_group = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.GROUPS_MODIFY,
        JWT_AUTHORIZATION.GROUPS_MODIFY_IFMEMBER,
        JWT_AUTHORIZATION.GROUPS_MODIFY_SYSTEM], False, **('requested_actions', 'read_only'))(update_settings_group))))
    
    def remove_settings_group(self):
        response = { }
        event = cherrypy.request.json
        group_setting_id = event.get('group_setting_id')
        if group_setting_id:
            gs = cherrypy.request.db.getGroupSetting(group_setting_id)
            if gs:
                if JWT_AUTHORIZATION.is_user_authorized_action(cherrypy.request.authenticated_user, cherrypy.request.authorizations, JWT_AUTHORIZATION.GROUPS_MODIFY, gs.group, **('target_group',)):
                    cherrypy.request.db.deleteGroupSetting(gs)
                else:
                    msg = f'''User ({cherrypy.request.kasm_user_id}) made unauthorized attempt to modify group ({gs.group.name}).'''
                    self.logger.warning(msg)
                    response['error_message'] = 'Unauthorized'
                    cherrypy.response.status = 401
            else:
                msg = 'Group setting does not exist'
                self.logger.error(msg)
                response['error_message'] = msg
        else:
            msg = 'Invalid request'
            self.logger.error(msg)
            response['error_message'] = msg
        return response

    remove_settings_group = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.GROUPS_MODIFY,
        JWT_AUTHORIZATION.GROUPS_MODIFY_IFMEMBER,
        JWT_AUTHORIZATION.GROUPS_MODIFY_SYSTEM], False, **('requested_actions', 'read_only'))(remove_settings_group))))
    
    def get_images(self):
        _images = []
        images = cherrypy.request.db.getImages(False, **('only_enabled',))
        for x in images:
            _image = cherrypy.request.db.serializable(x.jsonDict)
            _image['server'] = { }
            if x.server:
                _image['server']['hostname'] = x.server.hostname
            _image['server_pool'] = { }
            if x.server_pool:
                _image['server_pool']['server_pool_name'] = x.server_pool.server_pool_name
            _images.append(_image)
        return {
            'images': _images }

    get_images = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.IMAGES_VIEW], True, **('requested_actions', 'read_only'))(get_images))))
    
    def get_user_images(self):
        response = { }
        event = cherrypy.request.json
    # WARNING: Decompyle incomplete

    get_user_images = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.USERS_VIEW,
        JWT_AUTHORIZATION.IMAGES_VIEW], True, **('requested_actions', 'read_only'))(get_user_images))))
    
    def get_images_group(self):
        response = { }
        event = cherrypy.request.json
        target_group = event.get('target_group')
        if target_group and 'group_id' in target_group and target_group['group_id'] != '':
            group = cherrypy.request.db.getGroup(event['target_group']['group_id'])
            if group is not None:
                if JWT_AUTHORIZATION.is_user_authorized_action(cherrypy.request.authenticated_user, cherrypy.request.authorizations, JWT_AUTHORIZATION.GROUPS_VIEW, group, **('target_group',)):
                    response['images'] = (lambda .0: [ cherrypy.request.db.serializable(x.jsonDict) for x in .0 ])(group.images)
                else:
                    msg = f'''User ({cherrypy.request.kasm_user_id}) made unauthorized attempt to view a group\'s ({group.name}) images.'''
                    self.logger.warning(msg)
                    response['error_message'] = 'Unauthorized'
                    cherrypy.response.status = 401
            else:
                msg = 'Request group does not exist'
                self.logger.error(msg)
                response['error_message'] = msg
        else:
            msg = 'Invalid Request: Missing group id'
            self.logger.error(msg)
            response['error_message'] = msg
        return response

    get_images_group = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.GROUPS_VIEW,
        JWT_AUTHORIZATION.GROUPS_VIEW_IFMEMBER,
        JWT_AUTHORIZATION.GROUPS_VIEW_SYSTEM], True, **('requested_actions', 'read_only'))(get_images_group))))
    
    def add_images_group(self):
        response = { }
        event = cherrypy.request.json
        target_group = event.get('target_group')
        target_image = event.get('target_image')
        if target_group and 'group_id' in target_group and target_image and 'image_id' in target_image:
            group = cherrypy.request.db.getGroup(event['target_group']['group_id'])
            image = cherrypy.request.db.getImage(event['target_image']['image_id'])
            if JWT_AUTHORIZATION.is_user_authorized_action(cherrypy.request.authenticated_user, cherrypy.request.authorizations, JWT_AUTHORIZATION.GROUPS_MODIFY, group, **('target_group',)):
                cherrypy.request.db.addImageGroup(image, group)
            else:
                msg = f'''User ({cherrypy.request.kasm_user_id}) made unauthorized attempt to modify a group\'s ({group.name}) images.'''
                self.logger.warning(msg)
                response['error_message'] = 'Unauthorized'
                cherrypy.response.status = 401
        else:
            msg = 'Invalid request, missing group or image id'
            self.logger.error(msg)
            response['error_message'] = msg
        return response

    add_images_group = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.GROUPS_MODIFY,
        JWT_AUTHORIZATION.GROUPS_MODIFY_IFMEMBER,
        JWT_AUTHORIZATION.GROUPS_MODIFY_SYSTEM], False, **('requested_actions', 'read_only'))(add_images_group))))
    
    def remove_images_group(self):
        response = { }
        event = cherrypy.request.json
        target_group = event.get('target_group')
        target_image = event.get('target_image')
        if target_group and 'group_id' in target_group and target_image and 'image_id' in target_image:
            group = cherrypy.request.db.getGroup(event['target_group']['group_id'])
            image = cherrypy.request.db.getImage(event['target_image']['image_id'])
            if group and image:
                if JWT_AUTHORIZATION.is_user_authorized_action(cherrypy.request.authenticated_user, cherrypy.request.authorizations, JWT_AUTHORIZATION.GROUPS_MODIFY, group, **('target_group',)):
                    cherrypy.request.db.removeImageGroup(image, group)
                else:
                    msg = f'''User ({cherrypy.request.kasm_user_id}) made unauthorized attempt to remove a group\'s ({group.name}) image.'''
                    self.logger.warning(msg)
                    response['error_message'] = 'Unauthorized'
                    cherrypy.response.status = 401
            else:
                msg = 'Group or image does not exist'
                self.logger.error(msg)
                response['error_message'] = msg
        else:
            msg = 'Invalid request, missing group or image id'
            self.logger.error(msg)
            response['error_message'] = msg
        return response

    remove_images_group = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.GROUPS_MODIFY,
        JWT_AUTHORIZATION.GROUPS_MODIFY_IFMEMBER,
        JWT_AUTHORIZATION.GROUPS_MODIFY_SYSTEM], False, **('requested_actions', 'read_only'))(remove_images_group))))
    
    def get_users(self):
        response = { }
        request = cherrypy.request.json
        users = cherrypy.request.db.getUsers(request['anonymous'] if 'anonymous' in request else False, request['anonymous_only'] if 'anonymous_only' in request else False, request['page'] if 'page' in request else None, request['page_size'] if 'page_size' in request else None, request['filters'] if 'filters' in request else [], request['sort_by'] if 'sort_by' in request else None, request['sort_direction'] if 'sort_direction' in request else 'desc', **('include_anonymous', 'only_anonymous', 'page', 'page_size', 'filters', 'sort_by', 'sort_direction'))
        user_count = cherrypy.request.db.getUserCount(request['anonymous'] if 'anonymous' in request else False, request['anonymous_only'] if 'anonymous_only' in request else False, request['filters'] if 'filters' in request else [], **('include_anonymous', 'only_anonymous', 'filters'))
        if users:
            f_users = []
            for user in users:
                kasms = []
                if JWT_AUTHORIZATION.is_authorized_action(cherrypy.request.authorizations, JWT_AUTHORIZATION.SESSIONS_VIEW):
                    for kasm in user.kasms:
                        kasms.append({
                            'kasm_id': kasm.kasm_id,
                            'start_date': kasm.start_date,
                            'keepalive_date': kasm.keepalive_date,
                            'expiration_date': kasm.expiration_date,
                            'server': {
                                'server_id': kasm.server.server_id if kasm.image.is_container and kasm.server else None,
                                'hostname': kasm.server.hostname if kasm.image.is_container and kasm.server else None,
                                'port': kasm.server.port if kasm.image.is_container and kasm.server else None } })
                groups = []
                if JWT_AUTHORIZATION.is_authorized_action(cherrypy.request.authorizations, JWT_AUTHORIZATION.GROUPS_VIEW):
                    groups = user.get_groups()
                company = None
                if JWT_AUTHORIZATION.is_authorized_action(cherrypy.request.authorizations, JWT_AUTHORIZATION.COMPANIES_VIEW):
                    company = user.company
                f_users.append({
                    'user_id': str(user.user_id),
                    'username': user.username,
                    'anonymous': user.anonymous,
                    'locked': user.locked,
                    'disabled': user.disabled,
                    'last_session': str(user.last_session),
                    'groups': groups,
                    'first_name': user.first_name,
                    'last_name': user.last_name,
                    'phone': user.phone,
                    'organization': user.organization,
                    'notes': user.notes,
                    'kasms': kasms,
                    'realm': user.realm,
                    'company': cherrypy.request.db.serializable(company.jsonDict) if company else { },
                    'created': user.created })
            response['users'] = cherrypy.request.db.serializable(f_users)
            response['total'] = user_count
            response['page'] = request['page'] if 'page' in request and request['page'] >= 0 else 0
        return response

    get_users = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.USERS_VIEW], True, **('requested_actions', 'read_only'))(get_users))))
    
    def logout_user(self):
        return self._logout_user()

    logout_user = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.USERS_AUTH_SESSION], False, **('requested_actions', 'read_only'))(logout_user))))
    
    def _logout_user(self, public = (False,)):
        response = { }
        event = cherrypy.request.json
    # WARNING: Decompyle incomplete

    
    def delete_user(self):
        return self._delete_user()

    delete_user = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.USERS_DELETE], False, **('requested_actions', 'read_only'))(delete_user))))
    
    def _delete_user(self, public = (False,)):
        response = { }
        event = cherrypy.request.json
        force = False
    # WARNING: Decompyle incomplete

    
    def create_user(self):
        return self._create_user()

    create_user = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.USERS_CREATE], False, **('requested_actions', 'read_only'))(create_user))))
    
    def _create_user(self, public = (False,)):
        response = { }
        event = cherrypy.request.json
    # WARNING: Decompyle incomplete

    
    def get_settings(self):
        response = {
            'settings': (lambda .0: [ cherrypy.request.db.serializable(x.jsonDict) for x in .0 ])(cherrypy.request.db.get_config_settings(True, **('sanitize',))) }
        response['settings'] = sorted(response['settings'], (lambda s: (s['category'], s['name'])), **('key',))
        return response

    get_settings = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.SETTINGS_VIEW], True, **('requested_actions', 'read_only'))(get_settings))))
    
    def update_setting(self):
        response = { }
        event = cherrypy.request.json
        return response

    update_setting = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.SETTINGS_MODIFY_CAST,
        JWT_AUTHORIZATION.SETTINGS_MODIFY_AUTH,
        JWT_AUTHORIZATION.SETTINGS_MODIFY_FILTER,
        JWT_AUTHORIZATION.SETTINGS_MODIFY_IMAGES,
        JWT_AUTHORIZATION.SETTINGS_MODIFY_LICENSE,
        JWT_AUTHORIZATION.SETTINGS_MODIFY_LOGGING,
        JWT_AUTHORIZATION.SETTINGS_MODIFY_MANAGER,
        JWT_AUTHORIZATION.SETTINGS_MODIFY_SCALE,
        JWT_AUTHORIZATION.SETTINGS_MODIFY_STORAGE,
        JWT_AUTHORIZATION.SETTINGS_MODIFY_SUBSCRIPTION,
        JWT_AUTHORIZATION.SETTINGS_MODIFY_CONNECTIONS,
        JWT_AUTHORIZATION.SETTINGS_MODIFY], False, **('requested_actions', 'read_only'))(update_setting))))
    
    def get_kasms(self):
        response = {
            'kasms': [] }
        kasms = cherrypy.request.db.get_kasms()
        if kasms:
            for kasm in kasms:
                d = self.get_normalized_kasm(kasm)
                d['user'] = {
                    'username': kasm.user.username if kasm.user else '' }
                _zone_name = kasm.server.zone.zone_name if kasm.server and kasm.server.zone else ''
                if kasm.operational_status in (SESSION_OPERATIONAL_STATUS.REQUESTED.value, SESSION_OPERATIONAL_STATUS.PROVISIONING.value, SESSION_OPERATIONAL_STATUS.ASSIGNED.value):
                    hostname = None
                    port = None
                    provider = None
                elif kasm.image.is_container:
                    pass
                
                hostname = kasm.server.zone.proxy_hostname
                port = kasm.server.port if kasm.image.is_container else kasm.server.zone.proxy_port
                provider = kasm.server.provider if kasm.image.is_container else kasm.image.image_type
                d['server'] = {
                    'hostname': hostname,
                    'port': port,
                    'provider': provider,
                    'zone_name': _zone_name }
                response['kasms'].append(d)
                response['current_time'] = str(datetime.datetime.utcnow())
        return response

    get_kasms = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.SESSIONS_VIEW], True, **('requested_actions', 'read_only'))(get_kasms))))
    
    def get_kasm(self):
        response = { }
        event = cherrypy.request.json
        if 'target_kasm' in event:
            kasm_id = event['target_kasm'].get('kasm_id')
            if kasm_id:
                
                try:
                    kasm_id = uuid.UUID(kasm_id)
                finally:
                    pass
                kasm_id = None
                if kasm_id:
                    kasm = cherrypy.request.db.getKasm(kasm_id)
                    if kasm:
                        d = self.get_normalized_kasm(kasm)
                        d['user'] = {
                            'username': kasm.user.username if kasm.user else '' }
                        d['server'] = {
                            'hostname': kasm.server.hostname if kasm.server else None,
                            'port': kasm.server.port if kasm.server else None,
                            'provider': kasm.server.provider if kasm.server else None,
                            'zone_name': kasm.server.manager.zone.zone_name if kasm.server and kasm.server.manager and kasm.server.manager.zone else '' }
                        response['kasm'] = d
                        response['current_time'] = str(datetime.datetime.utcnow())
                    else:
                        msg = 'Invalid Request. Invalid kasm_id'
                        self.logger.error(msg)
                        response['error_message'] = msg
                else:
                    msg = 'Invalid Request. Missing kasm_id'
                    self.logger.error(msg)
                    response['error_message'] = msg

                msg = 'Invalid Request. Missing target_kasm'
                self.logger.error(msg)
                response['error_message'] = msg
                return response

    get_kasm = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.SESSIONS_VIEW], True, **('requested_actions', 'read_only'))(get_kasm))))
    
    def update_image(self):
        response = { }
        event = cherrypy.request.json
        target_image = event.get('target_image')
    # WARNING: Decompyle incomplete

    update_image = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.IMAGES_MODIFY,
        JWT_AUTHORIZATION.IMAGES_MODIFY_RESOURCES], False, **('requested_actions', 'read_only'))(update_image))))
    
    def create_image(self):
        response = { }
        event = cherrypy.request.json
        target_image = event.get('target_image')
    # WARNING: Decompyle incomplete

    create_image = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.IMAGES_CREATE], False, **('requested_actions', 'read_only'))(create_image))))
    
    def create_image_from_session(self):
        response = { }
        event = cherrypy.request.json
        target_kasm = event.get('target_kasm', { })
        kasm_id = target_kasm.get('kasm_id')
        docker_image = target_kasm.get('docker_image')
        author = target_kasm.get('author')
        message = target_kasm.get('message')
        changes = target_kasm.get('changes')
        registry_url = target_kasm.get('registry_url')
        registry_username = target_kasm.get('registry_username')
        registry_password = target_kasm.get('registry_password')
        if kasm_id and docker_image:
            (registry, repository, tag) = parse_docker_image(docker_image)
            if registry:
                repository = registry + '/' + repository
            kasm = cherrypy.request.db.getKasm(kasm_id)
            if kasm:
                kasm.operational_status = SESSION_OPERATIONAL_STATUS.SAVING.value
                cherrypy.request.db.updateKasm(kasm)
                new_image = cherrypy.request.db.clone_image(kasm.image)
                (res, err) = self.provider_manager.commit_kasm(kasm, repository, tag, author, message, changes, registry_url, registry_username, registry_password)
                if res:
                    new_image.friendly_name = 'Snapshot of ' + new_image.friendly_name + ' - (%s)' % tag
                    new_image.available = False
                    new_image.name = docker_image
                    new_image.docker_registry = registry_url
                    new_image.docker_user = registry_username
                    new_image.docker_token = registry_password
                    new_image.persistent_profile_path = None
                    new_image = cherrypy.request.db.createImage(new_image, False, **('install',))
                    response['image'] = cherrypy.request.db.serializable(new_image.jsonDict)
                    self.logger.info('Successfully created image (%s:%s) from kasm_id (%s)' % (repository, tag, str(kasm.kasm_id)))
                else:
                    msg = 'Error creating image (%s:%s) from kasm_id (%s) : %s' % (repository, tag, str(kasm.kasm_id), err)
                    response['error_message'] = err
                    self.logger.error(msg)
                    return response
            msg = 'Kasm (%s) Does not Exist' % kasm_id
            self.logger.error(msg)
            response['error_message'] = msg
        else:
            msg = 'Invalid Request: Missing required parameters'
            self.logger.error(msg)
            response['error_message'] = msg
        return response

    create_image_from_session = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.IMAGES_CREATE], **('requested_actions',))(create_image_from_session))))
    
    def delete_image(self):
        response = { }
        event = cherrypy.request.json
        target_image = event.get('target_image')
        if target_image and 'image_id' in target_image:
            image = cherrypy.request.db.getImage(target_image['image_id'])
            if image:
                if image.cast_configs:
                    msg = 'Image (%s): ID (%s) currently has (%s) associated Casting Config(s) and cannot be deleted' % (image.friendly_name, image.image_id, len(image.cast_configs))
                    self.logger.error(msg)
                    response['error_message'] = msg
                else:
                    num_kasms = len(image.kasms)
                    if num_kasms == 0:
                        cherrypy.request.db.delete_image(image)
                    else:
                        msg = 'Image (%s): ID (%s) currently has (%s) associated Kasm(s) and cannot be deleted' % (image.friendly_name, image.image_id, num_kasms)
                        self.logger.error(msg)
                        response['error_message'] = msg
            else:
                msg = 'Image(%s) Does not Exist' % target_image['image_id']
                self.logger.error(msg)
                response['error_message'] = msg
        else:
            msg = 'Invalid Request: Missing required parameters'
            self.logger.error(msg)
            response['error_message'] = msg
        return response

    delete_image = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.IMAGES_DELETE], False, **('requested_actions', 'read_only'))(delete_image))))
    
    def get_servers(self):
        event = cherrypy.request.json
        target_server = event.get('target_server')
        server_id = target_server['server_id'] if target_server else None
        servers = self._get_servers(server_id)['servers']
        response = {
            'servers': [] }
        for server in servers:
            server_type = SERVER_TYPE(server['server_type'])
            if server_type == SERVER_TYPE.HOST or JWT_AUTHORIZATION.is_authorized_action(cherrypy.request.authorizations, JWT_AUTHORIZATION.AGENTS_VIEW):
                response['servers'].append(server)
                continue
                if JWT_AUTHORIZATION.is_authorized_action(cherrypy.request.authorizations, JWT_AUTHORIZATION.SERVERS_VIEW):
                    response['servers'].append(server)
                    continue
                    return response

    get_servers = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.SERVERS_VIEW,
        JWT_AUTHORIZATION.AGENTS_VIEW], True, **('requested_actions', 'read_only'))(get_servers))))
    
    def _get_servers(self, server_id = (None,)):
        response = {
            'servers': [] }
        servers = cherrypy.request.db.getServers(None, server_id, **('manager_id', 'server_id'))
        if servers:
            priv_key = str.encode(self._db.get_config_setting_value('auth', 'api_private_key'))
            for server in servers:
                d = cherrypy.request.db.serializable(server.jsonDict)
                d['autoscale_config'] = {
                    'autoscale_config_id': server.autoscale_config_id,
                    'autoscale_config_name': server.autoscale_config.autoscale_config_name if server.autoscale_config else None }
                d['zone'] = {
                    'zone_id': server.zone_id,
                    'zone_name': server.zone.zone_name if server.zone else None }
                if server_id:
                    d['registration_jwt'] = generate_jwt_token({
                        'server_id': str(server.server_id) }, [
                        JWT_AUTHORIZATION.SERVER_AGENT], priv_key, 3650, **('expires_days',))
                d['kasms'] = []
                for kasm in server.kasms:
                    d['kasms'].append({
                        'kasm_id': kasm.kasm_id,
                        'start_date': kasm.start_date,
                        'keepalive_date': kasm.keepalive_date,
                        'user': {
                            'username': kasm.user.username if kasm.user else '',
                            'user_id': kasm.user.user_id if kasm.user else '' } })
                response['servers'].append(d)
        return cherrypy.request.db.serializable(response)

    
    def create_server(self):
        response = { }
        event = cherrypy.request.json
        target_server = event.get('target_server')
    # WARNING: Decompyle incomplete

    create_server = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.SERVERS_CREATE,
        JWT_AUTHORIZATION.AGENTS_CREATE], False, **('requested_actions', 'read_only'))(create_server))))
    
    def update_server(self):
        response = { }
        event = cherrypy.request.json
        target_server = event.get('target_server')
    # WARNING: Decompyle incomplete

    update_server = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.SERVERS_MODIFY,
        JWT_AUTHORIZATION.AGENTS_MODIFY], False, **('requested_actions', 'read_only'))(update_server))))
    
    def delete_server(self):
        response = { }
        event = cherrypy.request.json
        force = False
        if 'force' in event:
            if isinstance(event['force'], bool):
                force = event['force']
            else:
                msg = "Invalid Request. 'force' option must be boolean"
                self.logger.error(msg)
                response['error_message'] = msg
                return response
            target_server = None.get('target_server')
            if target_server:
                server_id = target_server.get('server_id')
                if server_id:
                    server = cherrypy.request.db.getServer(server_id)
                    if server:
                        num_kasms = len(server.kasms)
                        if not num_kasms > 0 and force:
                            msg = "Server contains (%s) kasms and 'force' option not set to True" % num_kasms
                            self.logger.error(msg)
                            response['error_message'] = msg
                        elif not num_kasms > 0 and JWT_AUTHORIZATION.is_authorized_action(cherrypy.request.authorizations, JWT_AUTHORIZATION.SESSIONS_DELETE):
                            self.logger.error(f'''Server has user sessions, but the user ({cherrypy.request.kasm_user_id}) is not authorized to delete user sessions.''')
                            response['error_message'] = 'Unauthorized to delete user sessions.'
                            response['ui_show_error'] = True
                        else:
                            server.operational_status = SERVER_OPERATIONAL_STATUS.DELETE_PENDING.value
                            cherrypy.request.db.updateServer(server)
                    else:
                        msg = 'Server (%s) Does not Exist' % server_id
                        self.logger.error(msg)
                        response['error_message'] = msg
                else:
                    msg = 'Invalid Request: Missing required parameters'
                    self.logger.error(msg)
                    response['error_message'] = msg
            else:
                msg = 'Invalid Request: Missing required parameters'
                self.logger.error(msg)
                response['error_message'] = msg
        return response

    delete_server = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.SERVERS_DELETE], False, **('requested_actions', 'read_only'))(delete_server))))
    
    def destroy_agent_kasms(self):
        response = { }
        event = cherrypy.request.json
        target_server = event.get('target_server')
        if target_server:
            server_id = target_server.get('server_id')
            if server_id:
                server = cherrypy.request.db.getServer(server_id)
                if server:
                    for kasm in server.kasms:
                        kasm.operational_status = 'admin_delete_pending'
                        cherrypy.request.db.updateKasm(kasm)
                else:
                    msg = 'Server (%s) Does not Exist' % server_id
                    self.logger.error(msg)
                    response['error_message'] = msg
            else:
                msg = 'Invalid Request: Missing required parameters'
                self.logger.error(msg)
                response['error_message'] = msg
        else:
            msg = 'Invalid Request: Missing required parameters'
            self.logger.error(msg)
            response['error_message'] = msg
        return response

    destroy_agent_kasms = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.SESSIONS_DELETE], False, **('requested_actions', 'read_only'))(destroy_agent_kasms))))
    
    def set_saml_config(self):
        response = { }
        license_helper = LicenseHelper(cherrypy.request.db, self.logger)
        if license_helper.is_sso_ok():
            event = cherrypy.request.json
            target_saml_config = event.get('target_saml_config')
            if target_saml_config:
                config = cherrypy.request.db.set_saml_config(True, False, False, target_saml_config.get('enabled'), target_saml_config.get('adfs'), target_saml_config.get('group_attribute'), target_saml_config.get('is_default'), target_saml_config.get('hostname'), target_saml_config.get('display_name'), target_saml_config.get('sp_entity_id'), target_saml_config.get('sp_acs_url'), target_saml_config.get('sp_slo_url'), target_saml_config.get('sp_name_id'), target_saml_config.get('sp_x509_cert'), target_saml_config.get('sp_private_key'), target_saml_config.get('idp_entity_id'), target_saml_config.get('idp_sso_url'), target_saml_config.get('idp_slo_url'), target_saml_config.get('idp_x509_cert'), True, False, False, False, False, False, False, True, True, False, False, 'http://www.w3.org/2000/09/xmldsig#rsa-sha1', 'http://www.w3.org/2000/09/xmldsig#sha1', target_saml_config.get('logo_url'), **('strict', 'debug', 'auto_login', 'enabled', 'adfs', 'group_attribute', 'is_default', 'hostname', 'display_name', 'sp_entity_id', 'sp_acs_url', 'sp_slo_url', 'sp_name_id', 'sp_x509_cert', 'sp_private_key', 'idp_entity_id', 'idp_sso_url', 'idp_slo_url', 'idp_x509_cert', 'want_attribute_statement', 'name_id_encrypted', 'authn_request_signed', 'logout_request_signed', 'logout_response_signed', 'sign_metadata', 'want_messages_signed', 'want_assertions_signed', 'want_name_id', 'want_name_id_encrypted', 'want_assertions_encrypted', 'signature_algorithm', 'digest_algorithm', 'logo_url'))
                response['saml_config'] = cherrypy.request.db.serializable(config.jsonDict)
                self.logger.info('Created SAML Config (%s)' % config.saml_id)
            else:
                msg = 'Invalid Request. Missing target_saml_config'
                self.logger.error(msg)
                response['error_message'] = msg
        else:
            msg = 'Access Denied. This feature is not licensed'
            self.logger.error(msg)
            response['error_message'] = msg
        return response

    set_saml_config = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.AUTH_CREATE], False, **('requested_actions', 'read_only'))(set_saml_config))))
    
    def update_saml_config(self):
        response = { }
        license_helper = LicenseHelper(cherrypy.request.db, self.logger)
    # WARNING: Decompyle incomplete

    update_saml_config = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.AUTH_MODIFY], False, **('requested_actions', 'read_only'))(update_saml_config))))
    
    def delete_saml_config(self):
        response = { }
        event = cherrypy.request.json
        target_saml_config = event.get('target_saml_config')
        if target_saml_config:
            if 'saml_id' in target_saml_config:
                saml_config = cherrypy.request.db.get_saml_config(target_saml_config['saml_id'])
                if saml_config:
                    cherrypy.request.db.delete_saml_config(saml_config)
                else:
                    msg = 'SAML config (%s) does not exist' % target_saml_config.get('saml_id')
                    self.logger.error(msg)
                    response['error_message'] = msg
            else:
                msg = 'Invalid Request. Missing saml_id'
                self.logger.error(msg)
                response['error_message'] = msg
        else:
            msg = 'Invalid Request. Missing target_saml_config'
            self.logger.error(msg)
            response['error_message'] = msg
        return response

    delete_saml_config = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.AUTH_DELETE], False, **('requested_actions', 'read_only'))(delete_saml_config))))
    
    def get_saml_config(self):
        response = { }
        event = cherrypy.request.json
        target_saml_config = event.get('target_saml_config')
        if target_saml_config:
            if 'saml_id' in target_saml_config:
                config = cherrypy.request.db.get_saml_config(target_saml_config['saml_id'])
                if config:
                    response['saml_config'] = cherrypy.request.db.serializable(config.jsonDict)
                else:
                    msg = 'SAML config (%s) does not exist' % target_saml_config.get('saml_id')
                    self.logger.error(msg)
                    response['error_message'] = msg
            else:
                msg = 'Invalid Request. Missing saml_id'
                self.logger.error(msg)
                response['error_message'] = msg
        else:
            msg = 'Invalid Request. Missing target_saml_config'
            self.logger.error(msg)
            response['error_message'] = msg
        return response

    get_saml_config = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.AUTH_VIEW], True, **('requested_actions', 'read_only'))(get_saml_config))))
    
    def get_saml_configs(self):
        response = { }
        configs = cherrypy.request.db.get_saml_configs()
        if configs:
            response['saml_configs'] = (lambda .0: [ cherrypy.request.db.serializable(x.jsonDict) for x in .0 ])(configs)
        else:
            response['error_message'] = 'No SAML configurations'
        return response

    get_saml_configs = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.AUTH_VIEW], True, **('requested_actions', 'read_only'))(get_saml_configs))))
    
    def get_ldap_configs(self):
        response = { }
        configs = cherrypy.request.db.get_ldap_configs()
        response['ldap_configs'] = (lambda .0: [ cherrypy.request.db.serializable(x.jsonDict) for x in .0 ])(configs)
        return response

    get_ldap_configs = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.AUTH_VIEW], True, **('requested_actions', 'read_only'))(get_ldap_configs))))
    
    def get_ldap_config(self):
        response = { }
        event = cherrypy.request.json
        target_ldap_config = event.get('target_ldap_config')
        if target_ldap_config:
            if 'ldap_id' in target_ldap_config:
                config = cherrypy.request.db.get_ldap_config(target_ldap_config['ldap_id'])
                if config:
                    response['ldap_config'] = cherrypy.request.db.serializable(config.jsonDict)
                else:
                    msg = 'LDAP config (%s) does not exist' % target_ldap_config.get('ldap_id')
                    self.logger.error(msg)
                    response['error_message'] = msg
            else:
                msg = 'Invalid Request. Missing ldap_id'
                self.logger.error(msg)
                response['error_message'] = msg
        else:
            msg = 'Invalid Request. Missing target_ldap_config'
            self.logger.error(msg)
            response['error_message'] = msg
        return response

    get_ldap_config = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.AUTH_VIEW], True, **('requested_actions', 'read_only'))(get_ldap_config))))
    
    def create_ldap_config(self):
        response = { }
        license_helper = LicenseHelper(cherrypy.request.db, self.logger)
        if license_helper.is_sso_ok():
            event = cherrypy.request.json
            target_ldap_config = event.get('target_ldap_config')
            if target_ldap_config:
                missing_args = []
                required_values = [
                    'name',
                    'enabled',
                    'url',
                    'auto_create_app_user',
                    'search_base',
                    'search_filter',
                    'group_membership_filter']
                for x in required_values:
                    if x not in target_ldap_config:
                        missing_args.append(x)
                        continue
                        if missing_args:
                            msg = 'Invalid Request. Missing required argument(s): (%s)' % str(missing_args)
                            self.logger.warning(msg)
                            response['error_message'] = msg
                        else:
                            config = cherrypy.request.db.create_ldap_config(target_ldap_config.get('name'), target_ldap_config.get('enabled'), target_ldap_config.get('url'), target_ldap_config.get('auto_create_app_user'), target_ldap_config.get('search_base'), target_ldap_config.get('search_filter'), target_ldap_config.get('email_attribute'), target_ldap_config.get('search_subtree'), target_ldap_config.get('service_account_dn'), target_ldap_config.get('service_account_password'), target_ldap_config.get('connection_timeout'), target_ldap_config.get('group_membership_filter'), target_ldap_config.get('username_domain_match'), **('name', 'enabled', 'url', 'auto_create_app_user', 'search_base', 'search_filter', 'email_attribute', 'search_subtree', 'service_account_dn', 'service_account_password', 'connection_timeout', 'group_membership_filter', 'username_domain_match'))
                            response['ldap_config'] = cherrypy.request.db.serializable(config.jsonDict)
                    else:
                        msg = 'Invalid Request. Missing target_ldap_config'
                        self.logger.error(msg)
                        response['error_message'] = msg
                msg = 'Access Denied. This feature is not licensed'
                self.logger.error(msg)
                response['error_message'] = msg
                return response

    create_ldap_config = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.AUTH_CREATE], False, **('requested_actions', 'read_only'))(create_ldap_config))))
    
    def update_ldap_config(self):
        response = { }
        license_helper = LicenseHelper(cherrypy.request.db, self.logger)
        if license_helper.is_sso_ok():
            event = cherrypy.request.json
            target_ldap_config = event.get('target_ldap_config')
            if target_ldap_config:
                if 'ldap_id' in target_ldap_config:
                    ldap_config = cherrypy.request.db.get_ldap_config(target_ldap_config['ldap_id'])
                    if ldap_config:
                        config = cherrypy.request.db.update_ldap_config(ldap_config, target_ldap_config.get('name'), target_ldap_config.get('enabled'), target_ldap_config.get('url'), target_ldap_config.get('auto_create_app_user'), target_ldap_config.get('search_base'), target_ldap_config.get('search_filter'), target_ldap_config.get('email_attribute'), target_ldap_config.get('search_subtree'), target_ldap_config.get('service_account_dn'), target_ldap_config.get('service_account_password'), target_ldap_config.get('group_membership_filter'), target_ldap_config.get('username_domain_match'), **('ldap_config', 'name', 'enabled', 'url', 'auto_create_app_user', 'search_base', 'search_filter', 'email_attribute', 'search_subtree', 'service_account_dn', 'service_account_password', 'group_membership_filter', 'username_domain_match'))
                        response['ldap_config'] = cherrypy.request.db.serializable(config.jsonDict)
                    else:
                        msg = 'LDAP config (%s) does not exist' % target_ldap_config.get('ldap_id')
                        self.logger.error(msg)
                        response['error_message'] = msg
                else:
                    msg = 'Invalid Request. Missing ldap_id'
                    self.logger.error(msg)
                    response['error_message'] = msg
            else:
                msg = 'Invalid Request. Missing target_ldap_config'
                self.logger.error(msg)
                response['error_message'] = msg
        else:
            msg = 'Access Denied. This feature is not licensed'
            self.logger.error(msg)
            response['error_message'] = msg
        return response

    update_ldap_config = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.AUTH_MODIFY], False, **('requested_actions', 'read_only'))(update_ldap_config))))
    
    def delete_ldap_config(self):
        response = { }
        event = cherrypy.request.json
        target_ldap_config = event.get('target_ldap_config')
        if target_ldap_config:
            if 'ldap_id' in target_ldap_config:
                ldap_config = cherrypy.request.db.get_ldap_config(target_ldap_config['ldap_id'])
                if ldap_config:
                    cherrypy.request.db.delete_ldap_config(ldap_config)
                else:
                    msg = 'LDAP config (%s) does not exist' % target_ldap_config.get('ldap_id')
                    self.logger.error(msg)
                    response['error_message'] = msg
            else:
                msg = 'Invalid Request. Missing ldap_id'
                self.logger.error(msg)
                response['error_message'] = msg
        else:
            msg = 'Invalid Request. Missing target_ldap_config'
            self.logger.error(msg)
            response['error_message'] = msg
        return response

    delete_ldap_config = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.AUTH_DELETE], False, **('requested_actions', 'read_only'))(delete_ldap_config))))
    
    def test_ldap_config(self):
        response = { }
        event = cherrypy.request.json
        target_ldap_config = event.get('target_ldap_config')
        target_user = event.get('target_user')
        if target_ldap_config:
            if target_user and 'username' in target_user and 'password' in target_user:
                if 'ldap_id' in target_ldap_config:
                    ldap_config = cherrypy.request.db.get_ldap_config(target_ldap_config['ldap_id'])
                    if ldap_config:
                        ldap_auth = LDAPAuthentication(ldap_config)
                        ldap_response = ldap_auth.login(target_user['username'], target_user['password'])
                        if ldap_response.success:
                            msg = 'Login test successful'
                            self.logger.info(msg)
                            response['message'] = msg
                        else:
                            msg = ldap_response.message
                            self.logger.info(msg)
                            response['error_message'] = msg
                    else:
                        msg = 'LDAP config (%s) does not exist' % target_ldap_config.get('ldap_id')
                        self.logger.error(msg)
                        response['error_message'] = msg
                else:
                    msg = 'Invalid Request. Missing ldap_id'
                    self.logger.error(msg)
                    response['error_message'] = msg
            else:
                msg = 'Invalid Request. Missing target_user or username / password properties'
                self.logger.error(msg)
                response['error_message'] = msg
        else:
            msg = 'Invalid Request. Missing target_ldap_config'
            self.logger.error(msg)
            response['error_message'] = msg
        return response

    test_ldap_config = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.AUTH_VIEW], True, **('requested_actions', 'read_only'))(test_ldap_config))))
    
    def get_server_custom_network_names(self):
        response = { }
        response['network_names'] = self._get_network_names()
        return response

    get_server_custom_network_names = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.AGENTS_VIEW,
        JWT_AUTHORIZATION.SERVERS_VIEW,
        JWT_AUTHORIZATION.IMAGES_VIEW], True, **('requested_actions', 'read_only'))(get_server_custom_network_names))))
    
    def system_info(self):
        response = {
            'system_info': {
                'db': { },
                'api': { },
                'license': { },
                'update': { } } }
        update_information = cherrypy.request.db.getInstallation().update_information
        build_id = os.getenv('KASM_BUILD_ID', '0.0.0.dev')
        update_available = False
        if update_information and type(update_information) == dict and 'latest_version' in update_information:
            update_available = version.parse('.'.join(build_id.split('.')[:3])) < version.parse(update_information['latest_version'])
        license_helper = LicenseHelper(cherrypy.request.db, self.logger)
        response['system_info']['db']['alembic_version'] = cherrypy.request.db.getAlembicVersion()
        response['system_info']['db']['host'] = self.config['database']['host']
        response['system_info']['db']['installation_id'] = str(cherrypy.request.db.getInstallation().installation_id)
        response['system_info']['api']['server_id'] = self.config['server']['server_id']
        response['system_info']['api']['server_hostname'] = self.config['server']['server_hostname']
        response['system_info']['api']['build_id'] = build_id
        response['system_info']['api']['zone_name'] = self.config['server']['zone_name']
        response['system_info']['license']['status'] = license_helper.effective_license.dump()
        response['system_info']['license']['status']['limit_remaining'] = license_helper.get_limit_remaining()
        response['system_info']['update']['status'] = update_information
        response['system_info']['update']['update_available'] = update_available
        return response

    system_info = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.SYSTEM_VIEW], True, **('requested_actions', 'read_only'))(system_info))))
    
    def get_licenses(self):
        licenses = cherrypy.request.db.getLicenses()
        return {
            'licenses': (lambda .0: [ cherrypy.request.db.serializable(x.jsonDict) for x in .0 ])(licenses) }

    get_licenses = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.LICENSES_VIEW], True, **('requested_actions', 'read_only'))(get_licenses))))
    
    def add_license(self):
        response = { }
        event = cherrypy.request.json
    # WARNING: Decompyle incomplete

    add_license = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.LICENSES_CREATE], False, **('requested_actions', 'read_only'))(add_license))))
    
    def delete_license(self):
        response = { }
        event = cherrypy.request.json
        if 'license_id' in event:
            license_id = event.get('license_id')
            
            try:
                license_id = uuid.UUID(license_id)
            finally:
                pass
            license_id = None
            if license_id:
                license = cherrypy.request.db.getLicense(license_id)
                if license:
                    cherrypy.request.db.deleteLicense(license)
                else:
                    msg = 'license_id (%s) does not exist' % str(license_id)
                    self.logger.error(msg)
                    response['error_message'] = msg
            else:
                msg = 'Invalid Request. license_id must be a UUID'
                self.logger.error(msg)
                response['error_message'] = msg

        msg = 'Invalid Request. Missing license_id'
        self.logger.error(msg)
        response['error_message'] = msg
        return response

    delete_license = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.LICENSES_DELETE], False, **('requested_actions', 'read_only'))(delete_license))))
    
    def activate(self):
        event = cherrypy.request.json
        return self._activate(event.get('activation_key'), event.get('seats'), event.get('issued_to'), False, **('activation_key', 'seats', 'issued_to', 'public'))

    activate = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.LICENSES_CREATE], False, **('requested_actions', 'read_only'))(activate))))
    
    def _activate(self, activation_key, seats, issued_to, public = (None, None, None, False)):
        response = { }
    # WARNING: Decompyle incomplete

    
    def get_managers(self):
        response = {
            'managers': [] }
        managers = cherrypy.request.db.getManagers()
        if managers:
            for manager in managers:
                d = cherrypy.request.db.serializable(manager.jsonDict)
                d['servers'] = []
                for server in manager.servers:
                    d['servers'].append({
                        'server_id': server.server_id,
                        'hostname': server.hostname })
                response['managers'].append(d)
        return cherrypy.request.db.serializable(response)

    get_managers = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.MANAGERS_VIEW], True, **('requested_actions', 'read_only'))(get_managers))))
    
    def delete_manager(self):
        response = { }
        event = cherrypy.request.json
        target_manager = event.get('target_manager')
    # WARNING: Decompyle incomplete

    delete_manager = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.MANAGERS_DELETE], False, **('requested_actions', 'read_only'))(delete_manager))))
    
    def get_zones(self):
        response = {
            'zones': [] }
        event = cherrypy.request.json
        brief = event.get('brief')
        zones = cherrypy.request.db.getZones()
        if zones:
            for zone in zones:
                d = cherrypy.request.db.serializable(zone.jsonDict)
                d['managers'] = []
                if not brief:
                    d['servers'] = (lambda .0: [ cherrypy.request.db.serializable(x.jsonDict) for x in .0 ])(zone.get_zone_servers())
                d['num_kasms'] = len(zone.get_zone_kasms())
                for manager in zone.managers:
                    d['managers'].append({
                        'manager_id': manager.manager_id,
                        'manager_hostname': manager.manager_hostname })
                session_operational_status_filter = [
                    SESSION_OPERATIONAL_STATUS.RUNNING.value,
                    SESSION_OPERATIONAL_STATUS.SAVING.value,
                    SESSION_OPERATIONAL_STATUS.STARTING.value]
                available_resources = self.provider_manager.get_available_resources(zone.zone_name, session_operational_status_filter, **('zone_name', 'session_operational_status_filter'))
                d['available_cores'] = available_resources['cores']
                d['available_memory'] = available_resources['memory']
                d['available_gpus'] = available_resources['gpus']
                response['zones'].append(d)
        return cherrypy.request.db.serializable(response)

    get_zones = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.ZONES_VIEW], True, **('requested_actions', 'read_only'))(get_zones))))
    
    def update_zone(self):
        response = { }
        event = cherrypy.request.json
        if 'target_zone' in event:
            target_zone = event['target_zone']
            zone_id = target_zone.get('zone_id')
            if zone_id:
                
                try:
                    zone_id = uuid.UUID(zone_id)
                finally:
                    pass
                zone_id = None
                if zone_id:
                    zone = cherrypy.request.db.getZoneById(zone_id, **('zone_id',))
                    if zone:
                        updated_zone = cherrypy.request.db.updateZone(zone, target_zone.get('zone_name'), target_zone.get('load_strategy'), target_zone.get('search_alternate_zones'), target_zone.get('prioritize_static_agents'), target_zone.get('allow_origin_domain'), target_zone.get('upstream_auth_address'), target_zone.get('proxy_connections'), target_zone.get('proxy_hostname'), target_zone.get('proxy_path'), target_zone.get('proxy_port'), **('zone_name', 'load_strategy', 'search_alternate_zones', 'prioritize_static_agents', 'allow_origin_domain', 'upstream_auth_address', 'proxy_connections', 'proxy_hostname', 'proxy_path', 'proxy_port'))
                        self.logger.info('Updated Zone (%s) - (%s)' % (updated_zone.zone_id, updated_zone.zone_name))
                        response['zone'] = cherrypy.request.db.serializable(updated_zone.jsonDict)
                    else:
                        msg = 'Invalid Request. Zone does not exit by that id'
                        self.logger.error(msg)
                        response['error_message'] = msg
                else:
                    msg = 'Invalid Request. zone_id must be a uuid'
                    self.logger.error(msg)
                    response['error_message'] = msg

            msg = 'Invalid Request. Missing required parameters'
            self.logger.error(msg)
            response['error_message'] = msg
        else:
            msg = 'Invalid Request. Missing required parameters'
            self.logger.error(msg)
            response['error_message'] = msg
        return response

    update_zone = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.ZONES_MODIFY], False, **('requested_actions', 'read_only'))(update_zone))))
    
    def create_zone(self):
        response = { }
        event = cherrypy.request.json
        if 'target_zone' in event:
            target_zone = event['target_zone']
            if 'zone_name' in target_zone:
                existing_zone = cherrypy.request.db.getZone(target_zone['zone_name'])
                if not existing_zone:
                    new_zone = cherrypy.request.db.createZone(target_zone.get('zone_name'), target_zone.get('load_strategy'), target_zone.get('prioritize_static_agents'), target_zone.get('search_alternate_zones'), target_zone.get('allow_origin_domain'), target_zone.get('upstream_auth_address'), target_zone.get('proxy_connections'), target_zone.get('proxy_hostname'), target_zone.get('proxy_path'), target_zone.get('proxy_port'), **('zone_name', 'load_strategy', 'prioritize_static_agents', 'search_alternate_zones', 'allow_origin_domain', 'upstream_auth_address', 'proxy_connections', 'proxy_hostname', 'proxy_path', 'proxy_port'))
                    self.logger.info('Created Zone (%s) - (%s)' % (new_zone.zone_id, new_zone.zone_name))
                    response['zone'] = cherrypy.request.db.serializable(new_zone.jsonDict)
                else:
                    msg = 'Zone (%s) already exists' % target_zone.get('zone_name')
                    self.logger.error(msg)
                    response['error_message'] = msg
            else:
                msg = 'Invalid Request. Missing required parameters'
                self.logger.error(msg)
                response['error_message'] = msg
        else:
            msg = 'Invalid Request. Missing required parameters'
            self.logger.error(msg)
            response['error_message'] = msg
        return response

    create_zone = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.ZONES_CREATE], False, **('requested_actions', 'read_only'))(create_zone))))
    
    def delete_zone(self):
        response = { }
        event = cherrypy.request.json
        target_zone = event.get('target_zone')
    # WARNING: Decompyle incomplete

    delete_zone = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.ZONES_DELETE], False, **('requested_actions', 'read_only'))(delete_zone))))
    
    def get_api_configs(self):
        response = { }
        api_configs = (lambda .0: [ cherrypy.request.db.serializable(x.jsonDict) for x in .0 ])(cherrypy.request.db.getApiConfigs())
        response['api_configs'] = api_configs
        return response

    get_api_configs = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.DEVAPI_VIEW], True, **('requested_actions', 'read_only'))(get_api_configs))))
    
    def create_api_configs(self):
        response = { }
        event = cherrypy.request.json
        license_helper = LicenseHelper(cherrypy.request.db, self.logger)
        if license_helper.is_developer_api_ok():
            if event.get('api_config') and event['api_config'].get('name'):
                api = event['api_config']
                target_user = cherrypy.request.db.get_user_by_id(api['user_id']) if 'user_id' in api else None
                if 'user_id' not in api or target_user is not None:
                    _api_key = self.generate_random_string(12)
                    _api_key_secret = self.generate_random_string(32)
                    expires = datetime.datetime.strptime(api['expires'], '%Y-%m-%d %H:%M:%S') if 'expires' in api and api['expires'] is not None else None
                    api = cherrypy.request.db.createApiConfig(api['name'], _api_key, _api_key_secret, api['enabled'], api['read_only'], expires, **('name', 'api_key', 'api_key_secret', 'enabled', 'read_only', 'expires'))
                    response['api_config'] = cherrypy.request.db.serializable(api.jsonDict)
                    response['api_config']['api_key_secret'] = _api_key_secret
                else:
                    response['error_message'] = 'Api Name already exists'
                    response['api_config'] = cherrypy.request.db.serializable(api)
            else:
                response['error_message'] = 'API Config missing required parameter'
        else:
            msg = 'Access Denied. This feature is not licensed'
            self.logger.error(msg)
            response['error_message'] = msg
        return response

    create_api_configs = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.GLOBAL_ADMIN], False, **('requested_actions', 'read_only'))(create_api_configs))))
    
    def generate_random_string(self, length):
        return ''.join((lambda .0: for _ in .0:
random.choice(string.ascii_letters + string.digits))(range(length)))

    
    def delete_api_configs(self):
        response = { }
        event = cherrypy.request.json
        if event['api_Id']:
            api = cherrypy.request.db.getApiConfig(event['api_Id'])
            cherrypy.request.db.deleteApiConfig(api)
        else:
            response['error_message'] = 'Missing Api ID'
        return response

    delete_api_configs = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.DEVAPI_DELETE], False, **('requested_actions', 'read_only'))(delete_api_configs))))
    
    def update_api_configs(self):
        response = { }
        license_helper = LicenseHelper(cherrypy.request.db, self.logger)
        if license_helper.is_developer_api_ok():
            event = cherrypy.request.json
            api = event.get('target_api')
            if api and 'api_id' in api:
                expires = datetime.datetime.strptime(api['expires'], '%Y-%m-%d %H:%M:%S') if 'expires' in api and api['expires'] is not None else None
                cherrypy.request.db.updateApiConfig(api['api_id'], api['name'] if 'name' in api else None, api['enabled'] if 'enabled' in api else None, api['read_only'] if 'read_only' in api else None, expires, **('api_id', 'name', 'enabled', 'read_only', 'expires'))
            else:
                response['error_message'] = 'Missing Target Api or api_id.'
        else:
            msg = 'Access Denied. This feature is not licensed'
            self.logger.error(msg)
            response['error_message'] = msg
        return response

    update_api_configs = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.DEVAPI_MODIFY], False, **('requested_actions', 'read_only'))(update_api_configs))))
    
    def get_usage_summary(self):
        response = { }
        event = cherrypy.request.json
        if 'user_id' in event:
            user = cherrypy.request.db.get_user_by_id(event['user_id'])
            limit = user.get_setting_value('usage_limit', False)
            response['usage_limit'] = limit
            if limit:
                usage_type = limit['type']
                interval = limit['interval']
                hours = limit['hours']
                (_used_hours, _dates) = get_usage(user)
                response['usage_limit_remaining'] = hours - _used_hours
                response['usage_limit_type'] = type
                response['usage_limit_interval'] = interval
                response['usage_limit_hours'] = hours
                response['usage_limit_start_date'] = _dates['start_date']
                response['usage_limit_next_start_date'] = _dates['next_start_date']
            else:
                response['error_message'] = 'Error: Missing Required Parameter'
        return response

    get_usage_summary = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.USERS_VIEW], True, **('requested_actions', 'read_only'))(get_usage_summary))))
    
    def get_user_usage_dump(self):
        response = { }
        event = cherrypy.request.json
        user = cherrypy.request.db.get_user_by_id(event['user_id'])
        limit = user.get_setting_value('usage_limit', False)
        response['usage_limit'] = limit
        start_date = (datetime.datetime.utcnow() + datetime.timedelta(-30, **('days',))).strftime('%Y-%m-%d 00:00:00')
        end_date = datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
        out_dump = []
        if JWT_AUTHORIZATION.is_authorized_action(cherrypy.request.authorizations, JWT_AUTHORIZATION.SESSIONS_VIEW):
            dump = cherrypy.request.db.getuserAccountDump(user.user_id, start_date, end_date)
            images = cherrypy.request.db.getImages(False, **('only_enabled',))
            for entry in dump:
                entry = cherrypy.request.db.serializable(entry.jsonDict)
                for image in images:
                    if str(image.image_id.hex) == entry.get('image_id') or image.image_src:
                        entry['image_src'] = image.image_src
                out_dump.append(entry)
        response['account_dump'] = out_dump
        response['start_date'] = start_date
        response['end_date'] = end_date
        return response

    get_user_usage_dump = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.USERS_VIEW], True, **('requested_actions', 'read_only'))(get_user_usage_dump))))
    
    def create_company(self):
        response = { }
        event = cherrypy.request.json
        if 'target_company' in event:
            target_company = event['target_company']
            if 'company_name' in target_company:
                company = cherrypy.request.db.getCompany(target_company['company_name'], **('company_name',))
                if not company:
                    company = cherrypy.request.db.createCompany(target_company['company_name'], target_company.get('street'), target_company.get('city'), target_company.get('zip'), target_company.get('country'), **('company_name', 'street', 'city', 'zip', 'country'))
                    response['company'] = cherrypy.request.db.serializable(company.jsonDict)
                else:
                    msg = 'Invalid Request: Company already exists by name (%s)' % target_company['company_name']
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

    create_company = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.COMPANIES_CREATE], False, **('requested_actions', 'read_only'))(create_company))))
    
    def update_company(self):
        response = { }
        event = cherrypy.request.json
    # WARNING: Decompyle incomplete

    update_company = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.COMPANIES_MODIFY], False, **('requested_actions', 'read_only'))(update_company))))
    
    def delete_company(self):
        response = { }
        event = cherrypy.request.json
        if 'target_company' in event:
            target_company = event['target_company']
            if 'company_id' in target_company:
                company = cherrypy.request.db.getCompany(target_company['company_id'], **('company_id',))
                if company:
                    cherrypy.request.db.deleteCompany(company)
                else:
                    msg = 'Invalid Request: Company does not exists by id (%s)' % target_company['company_id']
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

    delete_company = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.COMPANIES_DELETE], False, **('requested_actions', 'read_only'))(delete_company))))
    
    def get_company(self):
        response = { }
        event = cherrypy.request.json
        if 'target_company' in event:
            target_company = event['target_company']
            if 'company_id' in target_company:
                company = cherrypy.request.db.getCompany(target_company['company_id'], **('company_id',))
                if company:
                    response['company'] = cherrypy.request.db.serializable(company.jsonDict)
                else:
                    msg = 'Invalid Request: Company does not exists by id (%s)' % target_company['company_id']
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

    get_company = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.COMPANIES_VIEW], True, **('requested_actions', 'read_only'))(get_company))))
    
    def get_companies(self):
        response = {
            'companies': [] }
        event = cherrypy.request.json
        for company in cherrypy.request.db.getCompanies():
            response['companies'].append(cherrypy.request.db.serializable(company.jsonDict))
        return response

    get_companies = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.COMPANIES_VIEW], True, **('requested_actions', 'read_only'))(get_companies))))
    
    def get_url_filter_policies(self):
        response = { }
        url_filter_policies = cherrypy.request.db.get_url_filter_policies()
        response['url_filter_policies'] = (lambda .0: [ cherrypy.request.db.serializable(x.jsonDict) for x in .0 ])(url_filter_policies)
        return response

    get_url_filter_policies = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.WEBFILTERS_VIEW], True, **('requested_actions', 'read_only'))(get_url_filter_policies))))
    
    def create_url_filter_policy(self):
        response = { }
        event = cherrypy.request.json
        target_url_filter_policy = event.get('target_url_filter_policy')
    # WARNING: Decompyle incomplete

    create_url_filter_policy = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.WEBFILTERS_CREATE], False, **('requested_actions', 'read_only'))(create_url_filter_policy))))
    
    def update_url_filter_policy(self):
        response = { }
        event = cherrypy.request.json
        target_url_filter_policy = event.get('target_url_filter_policy')
    # WARNING: Decompyle incomplete

    update_url_filter_policy = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.WEBFILTERS_MODIFY], False, **('requested_actions', 'read_only'))(update_url_filter_policy))))
    
    def delete_url_filter_policy(self):
        response = { }
        event = cherrypy.request.json
        filter_policy_id = event.get('filter_policy_id')
        if filter_policy_id:
            filter_policy = cherrypy.request.db.get_url_filter_policy(filter_policy_id)
            if filter_policy:
                group_settings = cherrypy.request.db.getGroupSettings('web_filter_policy', filter_policy_id, **('name', 'value'))
                if group_settings:
                    group_names = (lambda .0: [ x.group.name for x in .0 ])(group_settings)
                    msg = 'Unable to delete filter policy (%s). Policy in use by group(s) (%s)' % (filter_policy.filter_policy_name, group_names)
                    self.logger.error(msg)
                    response['error_message'] = msg
                elif filter_policy.images:
                    image_names = (lambda .0: [ x.friendly_name for x in .0 ])(filter_policy.images)
                    msg = 'Unable to delete filter policy (%s). Policy in use by image(s) (%s)' % (filter_policy.filter_policy_name, image_names)
                    self.logger.error(msg)
                    response['error_message'] = msg
                else:
                    cherrypy.request.db.deleteApiConfig(filter_policy)
                    self.logger.info('Deleted filter policy: (%s)' % filter_policy_id)
            else:
                msg = 'Filter policy with id (%s) does not exist' % filter_policy_id
                self.logger.error(msg)
                response['error_message'] = msg
        else:
            msg = 'Invalid Request. Missing required parameters'
            self.logger.error(msg)
            response['error_message'] = msg
        return response

    delete_url_filter_policy = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.WEBFILTERS_DELETE], False, **('requested_actions', 'read_only'))(delete_url_filter_policy))))
    
    def get_all_categories(self):
        _categories = []
        for k, v in ALL_CATEGORIES.items():
            _categories.append({
                'id': k,
                'label': v['label'] })
        _categories = sorted(_categories, (lambda i: i['label']), **('key',))
        return {
            'categories': _categories }

    get_all_categories = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.WEBFILTERS_VIEW], True, **('requested_actions', 'read_only'))(get_all_categories))))
    
    def get_safe_search_patterns(self):
        return {
            'safe_search_patterns': SAFE_SEARCH_PATTERNS }

    get_safe_search_patterns = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.WEBFILTERS_VIEW], True, **('requested_actions', 'read_only'))(get_safe_search_patterns))))
    
    def get_attributes(self):
        return self._get_attributes()

    get_attributes = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.USERS_VIEW], True, **('requested_actions', 'read_only'))(get_attributes))))
    
    def _get_attributes(self, public = (False,)):
        response = { }
        event = cherrypy.request.json
        target_user = event.get('target_user')
        if target_user:
            user_id = target_user.get('user_id')
            username = target_user.get('username')
            if user_id or username:
                if user_id:
                    user = cherrypy.request.db.get_user_by_id(user_id)
                else:
                    user = cherrypy.request.db.getUser(username)
                if user:
                    response['user_attributes'] = self.get_attributes_for_user(user)
                elif user_id:
                    pass
                
                msg = username
                self.logger.error(msg)
                response['error_message'] = msg
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

    
    def get_branding_configs(self):
        response = { }
        branding_configs = cherrypy.request.db.get_branding_configs()
        response['branding_configs'] = (lambda .0: [ cherrypy.request.db.serializable(x.jsonDict) for x in .0 ])(branding_configs)
        return response

    get_branding_configs = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.BRANDINGS_VIEW], True, **('requested_actions', 'read_only'))(get_branding_configs))))
    
    def delete_branding_config(self):
        response = { }
        event = cherrypy.request.json
        branding_config_id = event.get('branding_config_id')
        if branding_config_id:
            branding_config = cherrypy.request.db.get_branding_config(branding_config_id)
            if branding_config:
                self.logger.info('Deleting Branding Config (%s) : (%s)' % (branding_config.branding_config_id, branding_config.name))
                cherrypy.request.db.delete_branding_config(branding_config)
            else:
                msg = 'Branding config with id (%s) does not exist' % branding_config_id
                self.logger.error(msg)
                response['error_message'] = msg
        else:
            msg = 'Invalid Request. Missing required parameters'
            self.logger.error(msg)
            response['error_message'] = msg
        return response

    delete_branding_config = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.BRANDINGS_DELETE], False, **('requested_actions', 'read_only'))(delete_branding_config))))
    
    def create_branding_config(self):
        response = { }
        event = cherrypy.request.json
        license_helper = LicenseHelper(cherrypy.request.db, self.logger)
        if license_helper.is_branding_ok():
            target_branding_config = event.get('target_branding_config')
            if target_branding_config:
                required_parameters = [
                    'name',
                    'hostname',
                    'favicon_logo_url',
                    'header_logo_url',
                    'html_title',
                    'login_caption',
                    'login_logo_url',
                    'login_splash_url',
                    'loading_session_text',
                    'joining_session_text',
                    'destroying_session_text',
                    'launcher_background_url']
                ok = True
                for x in required_parameters:
                    if x not in target_branding_config:
                        ok = False
                        continue
                        if ok:
                            branding_config = cherrypy.request.db.create_branding_config(target_branding_config.get('name'), target_branding_config.get('favicon_logo_url'), target_branding_config.get('header_logo_url'), target_branding_config.get('html_title'), target_branding_config.get('login_caption'), target_branding_config.get('login_logo_url'), target_branding_config.get('login_splash_url'), target_branding_config.get('loading_session_text'), target_branding_config.get('joining_session_text'), target_branding_config.get('destroying_session_text'), target_branding_config.get('is_default'), target_branding_config.get('hostname'), target_branding_config.get('launcher_background_url'), **('name', 'favicon_logo_url', 'header_logo_url', 'html_title', 'login_caption', 'login_logo_url', 'login_splash_url', 'loading_session_text', 'joining_session_text', 'destroying_session_text', 'is_default', 'hostname', 'launcher_background_url'))
                            self.logger.info('Created Branding Config (%s) - (%s)' % (branding_config.branding_config_id, branding_config.name))
                            response['branding_config'] = cherrypy.request.db.serializable(branding_config.jsonDict)
                        else:
                            msg = 'Invalid Request. Missing required parameters'
                            self.logger.error(msg)
                            response['error_message'] = msg
                    else:
                        msg = 'Invalid Request. Missing required parameters'
                        self.logger.error(msg)
                        response['error_message'] = msg
                msg = 'Access Denied. This feature is not licensed'
                self.logger.error(msg)
                response['error_message'] = msg
                return response

    create_branding_config = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.BRANDINGS_CREATE], False, **('requested_actions', 'read_only'))(create_branding_config))))
    
    def update_branding_config(self):
        response = { }
        event = cherrypy.request.json
        license_helper = LicenseHelper(cherrypy.request.db, self.logger)
        if license_helper.is_branding_ok():
            target_branding_config = event.get('target_branding_config')
            if target_branding_config:
                branding_config_id = target_branding_config.get('branding_config_id')
                if branding_config_id:
                    branding_config = cherrypy.request.db.get_branding_config(branding_config_id)
                    if branding_config:
                        updated_branding_config = cherrypy.request.db.update_branding_config(branding_config, target_branding_config.get('name'), target_branding_config.get('favicon_logo_url'), target_branding_config.get('header_logo_url'), target_branding_config.get('html_title'), target_branding_config.get('login_caption'), target_branding_config.get('login_logo_url'), target_branding_config.get('login_splash_url'), target_branding_config.get('loading_session_text'), target_branding_config.get('joining_session_text'), target_branding_config.get('destroying_session_text'), target_branding_config.get('is_default'), target_branding_config.get('hostname'), target_branding_config.get('launcher_background_url'), **('branding_config', 'name', 'favicon_logo_url', 'header_logo_url', 'html_title', 'login_caption', 'login_logo_url', 'login_splash_url', 'loading_session_text', 'joining_session_text', 'destroying_session_text', 'is_default', 'hostname', 'launcher_background_url'))
                        self.logger.info('Updated Branding Config (%s) - (%s)' % (updated_branding_config.branding_config_id, updated_branding_config.name))
                        response['branding_config'] = cherrypy.request.db.serializable(branding_config.jsonDict)
                    else:
                        msg = 'Branding config with id (%s) does not exist' % branding_config_id
                        self.logger.error(msg)
                        response['error_message'] = msg
                else:
                    msg = 'Invalid Request. Missing required parameters'
                    self.logger.error(msg)
                    response['error_message'] = msg
            else:
                msg = 'Invalid Request. Missing required parameters'
                self.logger.error(msg)
                response['error_message'] = msg
        else:
            msg = 'Access Denied. This feature is not licensed'
            self.logger.error(msg)
            response['error_message'] = msg
        return response

    update_branding_config = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.BRANDINGS_MODIFY], False, **('requested_actions', 'read_only'))(update_branding_config))))
    
    def get_staging_configs(self):
        response = { }
        staging_configs = cherrypy.request.db.get_staging_configs()
        response['staging_configs'] = (lambda .0: [ cherrypy.request.db.serializable(x.jsonDict) for x in .0 ])(staging_configs)
        return response

    get_staging_configs = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.STAGING_VIEW], True, **('requested_actions', 'read_only'))(get_staging_configs))))
    
    def get_staging_config(self):
        return self._get_staging_config()

    get_staging_config = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.STAGING_VIEW], True, **('requested_actions', 'read_only'))(get_staging_config))))
    
    def _get_staging_config(self, public = (False,)):
        response = { }
        event = cherrypy.request.json
        target_staging_config = event.get('target_staging_config')
        if target_staging_config:
            staging_config_id = target_staging_config.get('staging_config_id')
            if staging_config_id:
                staging_config = cherrypy.request.db.get_staging_config(staging_config_id)
                if staging_config:
                    response['staging_config'] = cherrypy.request.db.serializable(staging_config.jsonDict)
                else:
                    msg = 'Staging config with id (%s) does not exist' % staging_config_id
                    self.logger.error(msg)
                    response['error_message'] = msg
                    if public:
                        cherrypy.response.status = 400
                    
            msg = 'Invalid Request. Missing required parameters'
            self.logger.error(msg)
            response['error_message'] = msg
            if public:
                cherrypy.response.status = 400
            else:
                msg = 'Invalid Request. Missing required parameters'
                self.logger.error(msg)
                response['error_message'] = msg
                if public:
                    cherrypy.response.status = 400
        return response

    
    def delete_staging_config(self):
        return self._delete_staging_config()

    delete_staging_config = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.STAGING_DELETE], False, **('requested_actions', 'read_only'))(delete_staging_config))))
    
    def _delete_staging_config(self, public = (False,)):
        response = { }
        event = cherrypy.request.json
        target_staging_config = event.get('target_staging_config')
        if target_staging_config:
            staging_config_id = target_staging_config.get('staging_config_id')
            if staging_config_id:
                staging_config = cherrypy.request.db.get_staging_config(staging_config_id)
                if staging_config:
                    self.logger.info('Deleting Staging Config ID (%s) : Zone (%s) : Image (%s)' % (staging_config.staging_config_id, staging_config.zone_name, staging_config.image_friendly_name))
                    cherrypy.request.db.delete_staging_config(staging_config)
                else:
                    msg = 'Staging config with id (%s) does not exist' % staging_config_id
                    self.logger.error(msg)
                    response['error_message'] = msg
                    if public:
                        cherrypy.response.status = 400
                    
            msg = 'Invalid Request. Missing required parameters'
            self.logger.error(msg)
            response['error_message'] = msg
            if public:
                cherrypy.response.status = 400
            else:
                msg = 'Invalid Request. Missing required parameters'
                self.logger.error(msg)
                response['error_message'] = msg
                if public:
                    cherrypy.response.status = 400
        return response

    
    def create_staging_config(self):
        return self._create_staging_config()

    create_staging_config = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.STAGING_CREATE], False, **('requested_actions', 'read_only'))(create_staging_config))))
    
    def _create_staging_config(self, public = (False,)):
        response = { }
        event = cherrypy.request.json
        license_helper = LicenseHelper(cherrypy.request.db, self.logger)
        if license_helper.is_staging_ok():
            target_staging_config = event.get('target_staging_config')
            if target_staging_config:
                required_parameters = [
                    'zone_id',
                    'image_id',
                    'num_sessions',
                    'expiration']
                ok = True
                for x in required_parameters:
                    if x not in target_staging_config:
                        ok = False
                        continue
                        if ok:
                            staging_config = cherrypy.request.db.create_staging_config(target_staging_config.get('zone_id'), target_staging_config.get('server_pool_id'), target_staging_config.get('autoscale_config_id'), target_staging_config.get('image_id'), target_staging_config.get('num_sessions'), target_staging_config.get('expiration'), target_staging_config.get('allow_kasm_audio'), target_staging_config.get('allow_kasm_uploads'), target_staging_config.get('allow_kasm_downloads'), target_staging_config.get('allow_kasm_clipboard_down'), target_staging_config.get('allow_kasm_clipboard_up'), target_staging_config.get('allow_kasm_microphone'), target_staging_config.get('allow_kasm_gamepad'), target_staging_config.get('allow_kasm_webcam'), target_staging_config.get('allow_kasm_printing'), **('zone_id', 'server_pool_id', 'autoscale_config_id', 'image_id', 'num_sessions', 'expiration', 'allow_kasm_audio', 'allow_kasm_uploads', 'allow_kasm_downloads', 'allow_kasm_clipboard_down', 'allow_kasm_clipboard_up', 'allow_kasm_microphone', 'allow_kasm_gamepad', 'allow_kasm_webcam', 'allow_kasm_printing'))
                            self.logger.info('Created  Staging Config ID (%s) : Zone (%s) : Image (%s)' % (staging_config.staging_config_id, staging_config.zone_name, staging_config.image_friendly_name))
                            response['staging_config'] = cherrypy.request.db.serializable(staging_config.jsonDict)
                        else:
                            msg = 'Invalid Request. Missing required parameters'
                            self.logger.error(msg)
                            response['error_message'] = msg
                            if public:
                                cherrypy.response.status = 400
                            else:
                                msg = 'Invalid Request. Missing required parameters'
                                self.logger.error(msg)
                                response['error_message'] = msg
                                if public:
                                    cherrypy.response.status = 400
                                else:
                                    msg = 'Access Denied. This feature is not licensed'
                                    self.logger.error(msg)
                                    response['error_message'] = msg
                                    if public:
                                        cherrypy.response.status = 400
        return response

    
    def update_staging_config(self):
        return self._update_staging_config()

    update_staging_config = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.STAGING_MODIFY], False, **('requested_actions', 'read_only'))(update_staging_config))))
    
    def _update_staging_config(self, public = (False,)):
        response = { }
        event = cherrypy.request.json
        license_helper = LicenseHelper(cherrypy.request.db, self.logger)
        if license_helper.is_staging_ok():
            target_staging_config = event.get('target_staging_config')
            if target_staging_config:
                staging_config_id = target_staging_config.get('staging_config_id')
                if staging_config_id:
                    staging_config = cherrypy.request.db.get_staging_config(staging_config_id)
                    if staging_config:
                        updated_staging_config = cherrypy.request.db.update_staging_config(staging_config, target_staging_config.get('zone_id'), target_staging_config.get('server_pool_id'), target_staging_config.get('autoscale_config_id'), target_staging_config.get('image_id'), target_staging_config.get('num_sessions'), target_staging_config.get('expiration'), target_staging_config.get('allow_kasm_audio'), target_staging_config.get('allow_kasm_uploads'), target_staging_config.get('allow_kasm_downloads'), target_staging_config.get('allow_kasm_clipboard_down'), target_staging_config.get('allow_kasm_clipboard_up'), target_staging_config.get('allow_kasm_microphone'), target_staging_config.get('allow_kasm_gamepad'), target_staging_config.get('allow_kasm_webcam'), target_staging_config.get('allow_kasm_printing'), **('staging_config', 'zone_id', 'server_pool_id', 'autoscale_config_id', 'image_id', 'num_sessions', 'expiration', 'allow_kasm_audio', 'allow_kasm_uploads', 'allow_kasm_downloads', 'allow_kasm_clipboard_down', 'allow_kasm_clipboard_up', 'allow_kasm_microphone', 'allow_kasm_gamepad', 'allow_kasm_webcam', 'allow_kasm_printing'))
                        self.logger.info('Updated Staging Config ID (%s) : Zone (%s) : Image (%s)' % (updated_staging_config.staging_config_id, updated_staging_config.zone_name, updated_staging_config.image_friendly_name))
                        response['staging_config'] = cherrypy.request.db.serializable(updated_staging_config.jsonDict)
                    else:
                        msg = 'Staging config with id (%s) does not exist' % staging_config_id
                        self.logger.error(msg)
                        response['error_message'] = msg
                        if public:
                            cherrypy.response.status = 400
                        else:
                            msg = 'Invalid Request. Missing required parameters'
                            self.logger.error(msg)
                            response['error_message'] = msg
                            if public:
                                cherrypy.response.status = 400
                            else:
                                msg = 'Invalid Request. Missing required parameters'
                                self.logger.error(msg)
                                response['error_message'] = msg
                                if public:
                                    cherrypy.response.status = 400
                                else:
                                    msg = 'Access Denied. This feature is not licensed'
                                    self.logger.error(msg)
                                    response['error_message'] = msg
                                    if public:
                                        cherrypy.response.status = 400
        return response

    
    def get_cast_configs(self):
        return self._get_cast_configs()

    get_cast_configs = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.CASTING_VIEW], True, **('requested_actions', 'read_only'))(get_cast_configs))))
    
    def _get_cast_configs(self):
        response = { }
        cast_configs = cherrypy.request.db.get_cast_configs()
        response['cast_configs'] = (lambda .0: [ cherrypy.request.db.serializable(x.jsonDict) for x in .0 ])(cast_configs)
        return response

    
    def get_cast_config(self):
        return self._get_cast_config()

    get_cast_config = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.CASTING_VIEW], True, **('requested_actions', 'read_only'))(get_cast_config))))
    
    def _get_cast_config(self, public = (False,)):
        response = { }
        event = cherrypy.request.json
        cast_config_id = event.get('cast_config_id')
        if cast_config_id:
            cast_config = cherrypy.request.db.get_cast_config(cast_config_id)
            if cast_config:
                response['cast_config'] = cherrypy.request.db.serializable(cast_config.jsonDict)
            else:
                msg = 'Cast config with id (%s) does not exist' % cast_config_id
                self.logger.error(msg)
                response['error_message'] = msg
                if public:
                    cherrypy.response.status = 400
                else:
                    msg = 'Invalid Request. Missing required parameters'
                    self.logger.error(msg)
                    response['error_message'] = msg
                    if public:
                        cherrypy.response.status = 400
        return response

    
    def delete_cast_config(self):
        return self._delete_cast_config()

    delete_cast_config = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.CASTING_DELETE], False, **('requested_actions', 'read_only'))(delete_cast_config))))
    
    def _delete_cast_config(self, public = (False,)):
        response = { }
        event = cherrypy.request.json
        cast_config_id = event.get('cast_config_id')
        if cast_config_id:
            cast_config = cherrypy.request.db.get_cast_config(cast_config_id)
            if cast_config:
                self.logger.info('Deleting Cast Config ID (%s) :Image (%s)' % (cast_config.cast_config_id, cast_config.image_friendly_name))
                cherrypy.request.db.delete_cast_config(cast_config)
            else:
                msg = 'Cast config with id (%s) does not exist' % cast_config_id
                self.logger.error(msg)
                response['error_message'] = msg
                if public:
                    cherrypy.response.status = 400
                else:
                    msg = 'Invalid Request. Missing required parameters'
                    self.logger.error(msg)
                    response['error_message'] = msg
                    if public:
                        cherrypy.response.status = 400
        return response

    
    def create_cast_config(self):
        return self._create_cast_config()

    create_cast_config = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.CASTING_CREATE], False, **('requested_actions', 'read_only'))(create_cast_config))))
    
    def _create_cast_config(self, public = (False,)):
        response = { }
        event = cherrypy.request.json
        license_helper = LicenseHelper(cherrypy.request.db, self.logger)
        if license_helper.is_casting_ok():
            target_cast_config = event.get('target_cast_config')
            if target_cast_config:
                required_parameters = [
                    'key']
                ok = True
                for x in required_parameters:
                    if x not in target_cast_config:
                        self.logger.warning('Missing (%s) parameter' % x)
                        ok = False
                        continue
                        for json_prop in ('allowed_referrers',):
                            if json_prop in target_cast_config or target_cast_config[json_prop] == '':
                                target_cast_config[json_prop] = []
                                continue
                            if type(target_cast_config[json_prop]) != list:
                                target_cast_config[json_prop] = parse_multiline_input(target_cast_config[json_prop])
                                continue
                                if ok:
                                    duplicate_key = cherrypy.request.db.get_cast_config(target_cast_config.get('key'), **('key',))
                                    duplicate_name = cherrypy.request.db.get_cast_config(target_cast_config.get('casting_config_name'), **('name',))
                                    if not duplicate_key and duplicate_name:
                                        remote_app_configs = { }
                                        if target_cast_config.get('remote_app_configs'):
                                            remote_app_configs = json.loads(target_cast_config.get('remote_app_configs'))
                                        cast_config = cherrypy.request.db.create_cast_config(target_cast_config.get('image_id'), target_cast_config.get('allowed_referrers'), target_cast_config.get('limit_sessions'), target_cast_config.get('session_remaining'), target_cast_config.get('limit_ips'), target_cast_config.get('ip_request_limit'), target_cast_config.get('ip_request_seconds'), target_cast_config.get('error_url'), target_cast_config.get('enable_sharing'), target_cast_config.get('disable_control_panel'), target_cast_config.get('disable_tips'), target_cast_config.get('disable_fixed_res'), target_cast_config.get('key'), target_cast_config.get('allow_anonymous'), target_cast_config.get('group_id'), target_cast_config.get('require_recaptcha'), target_cast_config.get('kasm_url'), target_cast_config.get('dynamic_kasm_url'), target_cast_config.get('dynamic_docker_network'), target_cast_config.get('allow_resume'), target_cast_config.get('enforce_client_settings'), target_cast_config.get('allow_kasm_audio'), target_cast_config.get('allow_kasm_uploads'), target_cast_config.get('allow_kasm_downloads'), target_cast_config.get('allow_kasm_clipboard_down'), target_cast_config.get('allow_kasm_clipboard_up'), target_cast_config.get('allow_kasm_microphone'), target_cast_config.get('allow_kasm_sharing'), target_cast_config.get('kasm_audio_default_on'), target_cast_config.get('kasm_ime_mode_default_on'), target_cast_config.get('allow_kasm_gamepad'), target_cast_config.get('allow_kasm_webcam'), target_cast_config.get('allow_kasm_printing'), target_cast_config.get('valid_until'), target_cast_config.get('casting_config_name'), remote_app_configs, **('image_id', 'allowed_referrers', 'limit_sessions', 'session_remaining', 'limit_ips', 'ip_request_limit', 'ip_request_seconds', 'error_url', 'enable_sharing', 'disable_control_panel', 'disable_tips', 'disable_fixed_res', 'key', 'allow_anonymous', 'group_id', 'require_recaptcha', 'kasm_url', 'dynamic_kasm_url', 'dynamic_docker_network', 'allow_resume', 'enforce_client_settings', 'allow_kasm_audio', 'allow_kasm_uploads', 'allow_kasm_downloads', 'allow_kasm_clipboard_down', 'allow_kasm_clipboard_up', 'allow_kasm_microphone', 'allow_kasm_sharing', 'kasm_audio_default_on', 'kasm_ime_mode_default_on', 'allow_kasm_gamepad', 'allow_kasm_webcam', 'allow_kasm_printing', 'valid_until', 'casting_config_name', 'remote_app_configs'))
                                        self.logger.info('Created  Cast Config ID (%s) : Image (%s) - Configuration Name (%s)' % (cast_config.cast_config_id, cast_config.image_friendly_name, cast_config.casting_config_name))
                                        response['cast_config'] = cherrypy.request.db.serializable(cast_config.jsonDict)
                                    else:
                                        msg = 'A Cast config with existing key (%s) OR configuration name (%s) exists. Key/Configuration Name must be unique' % (target_cast_config.get('key'), target_cast_config.get('casting_config_name'))
                                        self.logger.error(msg)
                                        response['error_message'] = msg
                                        if public:
                                            cherrypy.response.status = 400
                                        else:
                                            msg = 'Invalid Request. Missing required parameters'
                                            self.logger.error(msg)
                                            response['error_message'] = msg
                                            if public:
                                                cherrypy.response.status = 400
                                            else:
                                                msg = 'Invalid Request. Missing required parameters'
                                                self.logger.error(msg)
                                                response['error_message'] = msg
                                                if public:
                                                    cherrypy.response.status = 400
                                                else:
                                                    msg = 'Access Denied. This feature is not licensed'
                                                    self.logger.error(msg)
                                                    response['error_message'] = msg
                                                    if public:
                                                        cherrypy.response.status = 400
        return response

    
    def update_cast_config(self):
        return self._update_cast_config()

    update_cast_config = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.CASTING_MODIFY], False, **('requested_actions', 'read_only'))(update_cast_config))))
    
    def _update_cast_config(self, public = (False,)):
        response = { }
        event = cherrypy.request.json
        license_helper = LicenseHelper(cherrypy.request.db, self.logger)
        if license_helper.is_casting_ok():
            target_cast_config = event.get('target_cast_config')
            if target_cast_config:
                cast_config_id = target_cast_config.get('cast_config_id')
                if cast_config_id:
                    cast_config = cherrypy.request.db.get_cast_config(cast_config_id)
                    if cast_config:
                        if not cast_config.group_id or str(cast_config.group_id.hex) == target_cast_config.get('group_id'):
                            if target_cast_config.get('group_id'):
                                target_group = cherrypy.request.db.getGroup(target_cast_config.get('group_id'), **('group_id',))
                                if not JWT_AUTHORIZATION.is_user_authorized_action(cherrypy.request.authenticated_user, cherrypy.request.authorizations, JWT_AUTHORIZATION.GROUPS_MODIFY, target_group, **('target_group',)):
                                    self.logger.error(f'''The user ({cherrypy.request.kasm_user_id}) does not have read permissions to the target group ({target_cast_config.get('group_id')}).''')
                                    response['error_message'] = 'Unauthorized Action.'
                                    if public:
                                        cherrypy.response.status = 401
                                    return response
                                if not None.group_id and JWT_AUTHORIZATION.is_user_authorized_action(cherrypy.request.authenticated_user, cherrypy.request.authorizations, JWT_AUTHORIZATION.GROUPS_MODIFY, cast_config.group, **('target_group',)):
                                    self.logger.error(f'''The user ({cherrypy.request.kasm_user_id}) does not have read permissions to the source group ({str(cast_config.group_id.hex)}).''')
                                    response['error_message'] = 'Unauthorized Action.'
                                    if public:
                                        cherrypy.response.status = 401
                                    return response
                                for json_prop in None:
                                    if json_prop in target_cast_config or target_cast_config[json_prop] == '':
                                        target_cast_config[json_prop] = []
                                    elif type(target_cast_config[json_prop]) != list:
                                        target_cast_config[json_prop] = parse_multiline_input(target_cast_config[json_prop])
                                        continue
                                        target_key = target_cast_config.get('key')
                                        duplicate_config = cherrypy.request.db.get_cast_config(target_key, **('key',))
                                        duplicate_name = cherrypy.request.db.get_cast_config(target_cast_config.get('casting_config_name'), **('name',))
                                        if duplicate_config or duplicate_config.cast_config_id == cast_config.cast_config_id:
                                            if duplicate_name or duplicate_name.cast_config_id == cast_config.cast_config_id:
                                                remote_app_configs = None
                                                if target_cast_config.get('remote_app_configs'):
                                                    remote_app_configs = json.loads(target_cast_config.get('remote_app_configs'))
                                                updated_cast_config = cherrypy.request.db.update_cast_config(cast_config, target_cast_config.get('image_id'), target_cast_config.get('allowed_referrers'), target_cast_config.get('limit_sessions'), target_cast_config.get('session_remaining'), target_cast_config.get('limit_ips'), target_cast_config.get('ip_request_limit'), target_cast_config.get('ip_request_seconds'), target_cast_config.get('error_url'), target_cast_config.get('enable_sharing'), target_cast_config.get('disable_control_panel'), target_cast_config.get('disable_tips'), target_cast_config.get('disable_fixed_res'), target_cast_config.get('key'), target_cast_config.get('allow_anonymous'), target_cast_config.get('group_id'), target_cast_config.get('require_recaptcha'), target_cast_config.get('kasm_url'), target_cast_config.get('dynamic_kasm_url'), target_cast_config.get('dynamic_docker_network'), target_cast_config.get('allow_resume'), target_cast_config.get('enforce_client_settings'), target_cast_config.get('allow_kasm_audio'), target_cast_config.get('allow_kasm_uploads'), target_cast_config.get('allow_kasm_downloads'), target_cast_config.get('allow_kasm_clipboard_down'), target_cast_config.get('allow_kasm_clipboard_up'), target_cast_config.get('allow_kasm_microphone'), target_cast_config.get('allow_kasm_sharing'), target_cast_config.get('kasm_audio_default_on'), target_cast_config.get('kasm_ime_mode_default_on'), target_cast_config.get('allow_kasm_gamepad'), target_cast_config.get('allow_kasm_webcam'), target_cast_config.get('allow_kasm_printing'), target_cast_config.get('valid_until'), target_cast_config.get('casting_config_name'), remote_app_configs, **('cast_config', 'image_id', 'allowed_referrers', 'limit_sessions', 'session_remaining', 'limit_ips', 'ip_request_limit', 'ip_request_seconds', 'error_url', 'enable_sharing', 'disable_control_panel', 'disable_tips', 'disable_fixed_res', 'key', 'allow_anonymous', 'group_id', 'require_recaptcha', 'kasm_url', 'dynamic_kasm_url', 'dynamic_docker_network', 'allow_resume', 'enforce_client_settings', 'allow_kasm_audio', 'allow_kasm_uploads', 'allow_kasm_downloads', 'allow_kasm_clipboard_down', 'allow_kasm_clipboard_up', 'allow_kasm_microphone', 'allow_kasm_sharing', 'kasm_audio_default_on', 'kasm_ime_mode_default_on', 'allow_kasm_gamepad', 'allow_kasm_webcam', 'allow_kasm_printing', 'valid_until', 'casting_config_name', 'remote_app_configs'))
                                                self.logger.info('Updated Cast Config ID (%s) : Image (%s)' % (updated_cast_config.cast_config_id, updated_cast_config.image_friendly_name))
                                                response['cast_config'] = cherrypy.request.db.serializable(updated_cast_config.jsonDict)
                                            else:
                                                msg = 'A Cast config with existing key (%s) or Configuratin Name (%s) exists. Keys must be unique' % (target_cast_config.get('key'), target_cast_config.get('casting_config_name'))
                                                self.logger.error(msg)
                                                response['error_message'] = msg
                                                if public:
                                                    cherrypy.response.status = 400
                                                else:
                                                    msg = 'Cast config with id (%s) does not exist' % cast_config_id
                                                    self.logger.error(msg)
                                                    response['error_message'] = msg
                                                    if public:
                                                        cherrypy.response.status = 400
                                                    else:
                                                        msg = 'Invalid Request. Missing required parameters'
                                                        self.logger.error(msg)
                                                        response['error_message'] = msg
                                                        if public:
                                                            cherrypy.response.status = 400
                                                        else:
                                                            msg = 'Invalid Request. Missing required parameters'
                                                            self.logger.error(msg)
                                                            response['error_message'] = msg
                                                            if public:
                                                                cherrypy.response.status = 400
                                                            else:
                                                                msg = 'Access Denied. This feature is not licensed'
                                                                self.logger.error(msg)
                                                                response['error_message'] = msg
                                                                if public:
                                                                    cherrypy.response.status = 400
        return response

    
    def get_oidc_configs(self):
        response = { }
        oidc_configs = cherrypy.request.db.get_oidc_configs()
        response['oidc_configs'] = (lambda .0: [ cherrypy.request.db.serializable(x.jsonDict) for x in .0 ])(oidc_configs)
        return response

    get_oidc_configs = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.AUTH_VIEW], True, **('requested_actions', 'read_only'))(get_oidc_configs))))
    
    def create_oidc_config(self):
        response = { }
        event = cherrypy.request.json
        license_helper = LicenseHelper(cherrypy.request.db, self.logger)
        if license_helper.is_sso_ok():
            target_oidc_config = event.get('target_oidc_config')
            if target_oidc_config:
                required_parameters = [
                    'display_name',
                    'client_id',
                    'client_secret',
                    'auth_url',
                    'token_url',
                    'scope',
                    'redirect_url',
                    'user_info_url',
                    'username_attribute']
                ok = True
                for x in required_parameters:
                    if x not in target_oidc_config:
                        self.logger.warning('Missing (%s) parameter' % x)
                        ok = False
                        continue
                        for json_prop in ('scope',):
                            if json_prop in target_oidc_config or target_oidc_config[json_prop] == '':
                                target_oidc_config[json_prop] = []
                                continue
                            target_oidc_config[json_prop] = parse_multiline_input(target_oidc_config[json_prop], False, **('to_lower',))
                        if ok:
                            oidc_config = cherrypy.request.db.create_oidc_config(target_oidc_config.get('auto_login'), target_oidc_config.get('enabled'), target_oidc_config.get('is_default'), target_oidc_config.get('hostname'), target_oidc_config.get('display_name'), target_oidc_config.get('client_id'), target_oidc_config.get('client_secret'), target_oidc_config.get('auth_url'), target_oidc_config.get('token_url'), target_oidc_config.get('scope'), target_oidc_config.get('redirect_url'), target_oidc_config.get('user_info_url'), target_oidc_config.get('logo_url'), target_oidc_config.get('username_attribute'), target_oidc_config.get('groups_attribute'), target_oidc_config.get('debug'), **('auto_login', 'enabled', 'is_default', 'hostname', 'display_name', 'client_id', 'client_secret', 'auth_url', 'token_url', 'scope', 'redirect_url', 'user_info_url', 'logo_url', 'username_attribute', 'groups_attribute', 'debug'))
                            self.logger.info('Created OIDC Config ID (%s) : Name (%s)' % (oidc_config.oidc_id, oidc_config.display_name))
                            response['oidc_config'] = cherrypy.request.db.serializable(oidc_config.jsonDict)
                        else:
                            msg = 'Invalid Request. Missing required parameters'
                            self.logger.error(msg)
                            response['error_message'] = msg
                    else:
                        msg = 'Invalid Request. Missing required parameters'
                        self.logger.error(msg)
                        response['error_message'] = msg
                msg = 'Access Denied. This feature is not licensed'
                self.logger.error(msg)
                response['error_message'] = msg
                return response

    create_oidc_config = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.AUTH_CREATE], False, **('requested_actions', 'read_only'))(create_oidc_config))))
    
    def update_oidc_config(self):
        response = { }
        event = cherrypy.request.json
        license_helper = LicenseHelper(cherrypy.request.db, self.logger)
        if license_helper.is_sso_ok():
            target_oidc_config = event.get('target_oidc_config')
            if target_oidc_config:
                oidc_id = target_oidc_config.get('oidc_id')
                if oidc_id:
                    oidc_config = cherrypy.request.db.get_oidc_config(oidc_id)
                    if oidc_config:
                        for json_prop in ('scope',):
                            if json_prop in target_oidc_config or target_oidc_config[json_prop] == '':
                                target_oidc_config[json_prop] = []
                                continue
                            target_oidc_config[json_prop] = parse_multiline_input(target_oidc_config[json_prop], False, **('to_lower',))
                        updated_oidc_config = cherrypy.request.db.update_oidc_config(oidc_config, target_oidc_config.get('auto_login'), target_oidc_config.get('enabled'), target_oidc_config.get('is_default'), target_oidc_config.get('hostname'), target_oidc_config.get('display_name'), target_oidc_config.get('client_id'), target_oidc_config.get('client_secret'), target_oidc_config.get('auth_url'), target_oidc_config.get('token_url'), target_oidc_config.get('scope'), target_oidc_config.get('redirect_url'), target_oidc_config.get('user_info_url'), target_oidc_config.get('logo_url'), target_oidc_config.get('username_attribute'), target_oidc_config.get('groups_attribute'), target_oidc_config.get('debug'), **('oidc_config', 'auto_login', 'enabled', 'is_default', 'hostname', 'display_name', 'client_id', 'client_secret', 'auth_url', 'token_url', 'scope', 'redirect_url', 'user_info_url', 'logo_url', 'username_attribute', 'groups_attribute', 'debug'))
                        self.logger.info('Created OIDC Config ID (%s) : Name (%s)' % (updated_oidc_config.oidc_id, updated_oidc_config.display_name))
                        response['oidc_config'] = cherrypy.request.db.serializable(updated_oidc_config.jsonDict)
                    else:
                        msg = 'OIDC config with id (%s) does not exist' % oidc_id
                        self.logger.error(msg)
                        response['error_message'] = msg
                else:
                    msg = 'Invalid Request. Missing required parameters'
                    self.logger.error(msg)
                    response['error_message'] = msg
            else:
                msg = 'Invalid Request. Missing required parameters'
                self.logger.error(msg)
                response['error_message'] = msg
        else:
            msg = 'Access Denied. This feature is not licensed'
            self.logger.error(msg)
            response['error_message'] = msg
        return response

    update_oidc_config = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.AUTH_MODIFY], False, **('requested_actions', 'read_only'))(update_oidc_config))))
    
    def delete_oidc_config(self):
        response = { }
        event = cherrypy.request.json
        oidc_config_id = event.get('oidc_config_id')
        if oidc_config_id:
            oidc_config = cherrypy.request.db.get_oidc_config(oidc_config_id)
            if oidc_config:
                self.logger.info('Deleting OIDC Config ID (%s) : Name (%s)' % (oidc_config.oidc_id, oidc_config.display_name))
                cherrypy.request.db.delete_oidc_config(oidc_config)
            else:
                msg = 'OIDC config with id (%s) does not exist' % oidc_config_id
                self.logger.error(msg)
                response['error_message'] = msg
        else:
            msg = 'Invalid Request. Missing required parameters'
            self.logger.error(msg)
            response['error_message'] = msg
        return response

    delete_oidc_config = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.AUTH_DELETE], False, **('requested_actions', 'read_only'))(delete_oidc_config))))
    
    def get_all_ssos(self):
        SSOConfig = typing.NamedTuple('SSOConfig', str, str, str, **('id', 'sso_type', 'name'))
        response = { }
        
        try:
            sso_configs = []
            ldap_configs = cherrypy.request.db.get_ldap_configs()
            for ldap_config in ldap_configs:
                sso_configs.append(SSOConfig(str(ldap_config.ldap_id), 'ldap', ldap_config.name, **('id', 'sso_type', 'name')))
            saml_configs = cherrypy.request.db.get_saml_configs()
            for saml_config in saml_configs:
                sso_configs.append(SSOConfig(str(saml_config.saml_id), 'saml', saml_config.display_name, **('id', 'sso_type', 'name')))
            oidc_configs = cherrypy.request.db.get_oidc_configs()
            for oidc_config in oidc_configs:
                sso_configs.append(SSOConfig(str(oidc_config.oidc_id), 'oidc', oidc_config.display_name, **('id', 'sso_type', 'name')))
            response['ssos'] = sso_configs
        finally:
            pass
        except Exception:
            msg = 'Unable to retrieve all SSO settings'
            self.logger.exception(msg)
            response['error_message'] = msg
        

        return response

    get_all_ssos = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.AUTH_VIEW], True, **('requested_actions', 'read_only'))(get_all_ssos))))
    
    def get_sso_attribute_mapping_fields(self):
        response = {
            'fields': cherrypy.request.db.get_sso_attribute_mapping_fields() }
        return response

    get_sso_attribute_mapping_fields = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.AUTH_VIEW], True, **('requested_actions', 'read_only'))(get_sso_attribute_mapping_fields))))
    
    def get_sso_attribute_mappings(self):
        response = { }
        event = cherrypy.request.json
        sso_id = event.get('sso_id')
        if sso_id:
            sso_config = cherrypy.request.db.get_ldap_config(sso_id)
            if sso_config is None:
                sso_config = cherrypy.request.db.get_saml_config(sso_id)
            if sso_config is None:
                sso_config = cherrypy.request.db.get_oidc_config(sso_id)
            if sso_config is not None:
                attribute_mappings = []
                for sso_attribute_mapping in sso_config.user_attribute_mappings:
                    attribute_mappings.append(sso_attribute_mapping.jsonDict)
                response['attribute_mappings'] = cherrypy.request.db.serializable(attribute_mappings)
            else:
                msg = 'Invalid Request. SSO id is not valid'
                self.logger.error(msg)
                response['error_message'] = msg
                return response
        msg = 'Invalid Request. Missing required parameters'
        self.logger.error(msg)
        response['error_message'] = msg
        return response

    get_sso_attribute_mappings = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.AUTH_VIEW], True, **('requested_actions', 'read_only'))(get_sso_attribute_mappings))))
    
    def add_sso_attribute_mapping(self):
        response = { }
        event = cherrypy.request.json
        sso_mapping = event.get('target_sso_attribute_mapping')
        if sso_mapping and 'sso_id' in sso_mapping and 'attribute_name' in sso_mapping and 'user_field' in sso_mapping:
            sso_id = sso_mapping.get('sso_id')
            if cherrypy.request.db.get_ldap_config(sso_id):
                sso_type = 'ldap'
            elif cherrypy.request.db.get_saml_config(sso_id):
                sso_type = 'saml'
            elif cherrypy.request.db.get_oidc_config(sso_id):
                sso_type = 'oidc'
            else:
                msg = 'Invalid Request. SSO id is not valid'
                self.logger.error(msg)
                response['error_message'] = msg
                return response
            sso_attribute_mapping = None.request.db.create_sso_attribute_mapping(sso_mapping.get('attribute_name'), sso_mapping.get('user_field'), sso_id if sso_type == 'ldap' else None, sso_id if sso_type == 'saml' else None, sso_id if sso_type == 'oidc' else None, **('attribute_name', 'user_field', 'ldap_id', 'saml_id', 'oidc_id'))
            response['sso_attribute_mapping'] = cherrypy.request.db.serializable(sso_attribute_mapping.jsonDict)
        else:
            msg = 'Invalid Request. Missing required parameters'
            self.logger.error(msg)
            response['error_message'] = msg
        return response

    add_sso_attribute_mapping = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.AUTH_MODIFY], **('requested_actions',))(add_sso_attribute_mapping))))
    
    def delete_sso_attribute_mapping(self):
        response = { }
        event = cherrypy.request.json
        sso_attribute_id = event.get('sso_attribute_id')
        if sso_attribute_id:
            sso_attribute_mapping = cherrypy.request.db.get_sso_attribute_mapping(sso_attribute_id, **('sso_attribute_id',))
            if sso_attribute_mapping:
                cherrypy.request.db.delete_sso_attribute_mapping(sso_attribute_mapping, **('sso_attribute_mapping',))
            else:
                msg = f'''SSO attribute mapping with id ({sso_attribute_id}) does not exist'''
                self.logger.error(msg)
                response['error_message'] = msg
        else:
            msg = 'Invalid Request. Missing required parameters'
            self.logger.error(msg)
            response['error_message'] = msg
        return response

    delete_sso_attribute_mapping = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.AUTH_MODIFY], **('requested_actions',))(delete_sso_attribute_mapping))))
    
    def update_sso_attribute_mapping(self):
        response = { }
        event = cherrypy.request.json
        sso_attribute_mapping = event.get('target_sso_attribute_mapping')
        if sso_attribute_mapping:
            if not sso_attribute_mapping.get('sso_attribute_id') and sso_attribute_mapping.get('attribute_name') or sso_attribute_mapping.get('user_field'):
                msg = 'SSO Attribute mapping update missing required fields'
                self.logger.error(msg)
                response['error_message'] = msg
            else:
                target = cherrypy.request.db.get_sso_attribute_mapping(sso_attribute_mapping.get('sso_attribute_id'), **('sso_attribute_id',))
                if target:
                    updated_sso_attribute_mapping = cherrypy.request.db.update_sso_attribute_mapping(target, sso_attribute_mapping.get('attribute_name'), sso_attribute_mapping.get('user_field', False), **('attribute_name', 'user_field'))
                    response['sso_attribute_mapping'] = cherrypy.request.db.serializable(updated_sso_attribute_mapping.jsonDict)
                else:
                    msg = f'''SSO Attribute mapping id ({sso_attribute_mapping.get('sso_attribute_id')}) does not exist'''
                    self.logger.error(msg)
                    response['error_message'] = msg
        else:
            msg = 'Invalid Request. Missing required parameters'
            self.logger.error(msg)
            response['error_message'] = msg
        return response

    update_sso_attribute_mapping = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.AUTH_MODIFY], **('requested_actions',))(update_sso_attribute_mapping))))
    
    def add_sso_mapping_group(self):
        response = { }
        event = cherrypy.request.json
        sso_mapping = event.get('target_sso_mapping')
        if sso_mapping:
            pass
        msg = 'Invalid Request. Missing required parameters'
        self.logger.error(msg)
        response['error_message'] = msg
        return response

    add_sso_mapping_group = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.GROUPS_MODIFY,
        JWT_AUTHORIZATION.GROUPS_MODIFY_IFMEMBER], **('requested_actions',))(add_sso_mapping_group))))
    
    def get_sso_mappings_group(self):
        response = { }
        event = cherrypy.request.json
        group_id = event.get('group_id')
        if group_id:
            group = cherrypy.request.db.getGroup(group_id, **('group_id',))
            if group:
                group_mappings = []
                for group_mapping in group.group_mappings:
                    group_mappings.append(group_mapping.jsonDict)
                response['group_mappings'] = cherrypy.request.db.serializable(group_mappings)
            else:
                msg = f'''Group with id ({group_id}) does not exist'''
                self.logger.error(msg)
                response['error_message'] = msg
        else:
            msg = 'Invalid Request. Missing required parameters'
            self.logger.error(msg)
            response['error_message'] = msg
        return response

    get_sso_mappings_group = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.GROUPS_VIEW,
        JWT_AUTHORIZATION.GROUPS_VIEW_IFMEMBER,
        JWT_AUTHORIZATION.GROUPS_VIEW_SYSTEM], True, **('requested_actions', 'read_only'))(get_sso_mappings_group))))
    
    def delete_sso_mapping_group(self):
        response = { }
        event = cherrypy.request.json
        sso_group_id = event.get('sso_group_id')
        if sso_group_id:
            group_mapping = cherrypy.request.db.getGroupMapping(sso_group_id, **('sso_group_id',))
            if group_mapping:
                cherrypy.request.db.deleteGroupMapping(group_mapping, **('group_mapping',))
            else:
                msg = f'''SSO to group mapping with id ({sso_group_id}) does not exist'''
                self.logger.error(msg)
                response['error_message'] = msg
        else:
            msg = 'Invalid Request. Missing required parameters'
            self.logger.error(msg)
            response['error_message'] = msg
        return response

    delete_sso_mapping_group = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.GROUPS_MODIFY,
        JWT_AUTHORIZATION.GROUPS_MODIFY_IFMEMBER,
        JWT_AUTHORIZATION.GROUPS_MODIFY_SYSTEM], **('requested_actions',))(delete_sso_mapping_group))))
    
    def update_sso_mapping_group(self):
        response = { }
        event = cherrypy.request.json
        sso_group_mapping = event.get('target_sso_mapping')
        sso_group_id = sso_group_mapping.get('sso_group_id')
        if sso_group_id:
            if not sso_group_mapping.get('apply_to_all_users') and sso_group_mapping.get('sso_group_attributes'):
                msg = 'SSO group attributes must be defined if mapping is not assigned to all users'
                self.logger.error(msg)
                response['error_message'] = msg
            else:
                group_mapping = cherrypy.request.db.getGroupMapping(sso_group_mapping.get('sso_group_id'), **('sso_group_id',))
                if group_mapping:
                    cherrypy.request.db.updateGroupMapping(group_mapping, sso_group_mapping.get('sso_group_attributes'), sso_group_mapping.get('apply_to_all_users', False), **('group_mapping', 'sso_group_attributes', 'apply_to_all_users'))
                else:
                    msg = f'''SSO to group mapping with id ({sso_group_mapping.get('sso_group_id')}) does not exist'''
                    self.logger.error(msg)
                    response['error_message'] = msg
        else:
            msg = 'Invalid Request. Missing required parameters'
            self.logger.error(msg)
            response['error_message'] = msg
        return response

    update_sso_mapping_group = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.GROUPS_MODIFY,
        JWT_AUTHORIZATION.GROUPS_MODIFY_IFMEMBER,
        JWT_AUTHORIZATION.GROUPS_MODIFY_SYSTEM], **('requested_actions',))(update_sso_mapping_group))))
    
    def get_server_file_mappings(self):
        file_mappings = { }
        storage_mappings = { }
        storage_mapping_destinations = []
        response = { }
        if cherrypy.request.decoded_jwt and 'server_id' in cherrypy.request.decoded_jwt:
            server_id = cherrypy.request.decoded_jwt['server_id']
            server = cherrypy.request.db.getServer(server_id)
            if server:
                for image in server.images:
                    for file in image.file_mappings:
                        if file.os_type == OS_TYPES.WINDOWS:
                            priv_key = str.encode(self._db.get_config_setting_value('auth', 'api_private_key'))
                            encoded_jwt = generate_jwt_token({
                                'file_map_id': str(file.file_map_id) }, [
                                JWT_AUTHORIZATION.SERVER_AGENT], priv_key, 10, **('expires_minutes',))
                            file_mappings[str(file.file_map_id)] = {
                                'jwt_token': encoded_jwt,
                                'destination': file.destination,
                                'is_readable': file.is_readable,
                                'is_writable': file.is_writable,
                                'is_executable': file.is_executable }
                            continue
                            for storage_mapping in (lambda .0: [ x for x in .0 if x.storage_provider.enabled ])(image.storage_mappings):
                                if not storage_mapping.target:
                                    pass
                                target = storage_mapping.storage_provider.default_target
                                if target in storage_mapping_destinations:
                                    target += '_%s' % storage_mapping.storage_mapping_id.hex[:8]
                                storage_mapping_destinations.append(target)
                                (_config, emblem_config) = self.provider_manager.refresh_storage_mapping_config(storage_mapping, False, target)
                                storage_mappings[target] = _config
                            continue
                            if server.server_pool:
                                for image in server.server_pool.images:
                                    for file in image.file_mappings:
                                        if file.os_type == OS_TYPES.WINDOWS:
                                            priv_key = str.encode(self._db.get_config_setting_value('auth', 'api_private_key'))
                                            encoded_jwt = generate_jwt_token({
                                                'file_map_id': str(file.file_map_id) }, [
                                                JWT_AUTHORIZATION.SERVER_AGENT], priv_key, 10, **('expires_minutes',))
                                            file_mappings[str(file.file_map_id)] = {
                                                'jwt_token': encoded_jwt,
                                                'destination': file.destination,
                                                'is_readable': file.is_readable,
                                                'is_writable': file.is_writable,
                                                'is_executable': file.is_executable }
                                            continue
                                            continue
                                            response['file_mappings'] = file_mappings
                                            response['storage_mappings'] = storage_mappings
                                        else:
                                            self.logger.error('Invalid request for server file mappings, server does not exist.')
                                            response['error_message'] = 'Access Denied!'
                                    self.logger.error('Invalid request, JWT token missing server_id.')
                                    response['error_message'] = 'Access Denied!'
                                    return response

    get_server_file_mappings = cherrypy.expose()(cherrypy.tools.json_out()(JwtAuthenticated([
        JWT_AUTHORIZATION.SERVER_AGENT], **('authorizations',))(get_server_file_mappings)))
    
    def get_file_mapping_contents(self):
        if cherrypy.request.decoded_jwt and 'file_map_id' in cherrypy.request.decoded_jwt:
            file_map = cherrypy.request.db.get_file_map(cherrypy.request.decoded_jwt['file_map_id'], **('file_map_id',))
            if file_map:
                cherrypy.response.headers['Content-Type'] = 'application/octet-stream'
                cherrypy.response.status = 200
                if file_map.file_type == 'binary':
                    return base64.b64decode(file_map.content.encode('ascii'))
                return None.content.encode('utf-8')
            cherrypy.response.status = 404
            self.logger.error(f'''Attempt to retrieve file mapping ID ({cherrypy.request.decoded_jwt['file_map_id']}) that does not exist.''')
        else:
            cherrypy.response.status = 403
            self.logger.error('Invalid or missing JWT token used in attempt to retrieve file mapping contents.')

    get_file_mapping_contents = cherrypy.expose(JwtAuthenticated([
        JWT_AUTHORIZATION.AGENT,
        JWT_AUTHORIZATION.SERVER_AGENT], **('authorizations',))(get_file_mapping_contents))
    
    def get_file_mappings(self):
        response = { }
        event = cherrypy.request.json
        image_id = event.get('image_id')
        group_id = event.get('group_id')
        user_id = event.get('user_id')
        kasm_id = event.get('kasm_id')
        file_mappings = cherrypy.request.db.get_file_mappings(group_id, image_id, user_id, kasm_id, **('group_id', 'image_id', 'user_id', 'kasm_id'))
        response['file_mappings'] = []
        for file_map in file_mappings:
            if not file_map.image or JWT_AUTHORIZATION.is_authorized_action(cherrypy.request.authorizations, JWT_AUTHORIZATION.IMAGES_VIEW):
                if not file_map.group or JWT_AUTHORIZATION.is_user_authorized_action(cherrypy.request.authenticated_user, cherrypy.request.authorizations, JWT_AUTHORIZATION.GROUPS_VIEW, file_map.group, **('target_group',)):
                    if file_map.user and JWT_AUTHORIZATION.is_user_authorized_action(cherrypy.request.authenticated_user, cherrypy.request.authorizations, JWT_AUTHORIZATION.USERS_VIEW, file_map.user, **('target_user',)):
                        file_map_dict = file_map.jsonDict
                        if file_map.file_type == 'text':
                            file_map_dict['content'] = file_map.content
            response['file_mappings'].append(cherrypy.request.db.serializable(file_map_dict))
        return response

    get_file_mappings = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.GROUPS_VIEW,
        JWT_AUTHORIZATION.USERS_VIEW,
        JWT_AUTHORIZATION.IMAGES_VIEW], True, **('requested_actions', 'read_only'))(get_file_mappings))))
    
    def create_file_map(self):
        response = { }
        event = cherrypy.request.json
        target_file_map = event.get('target_file_map')
        if target_file_map:
            image_id = target_file_map.get('image_id')
            group_id = target_file_map.get('group_id')
            user_id = target_file_map.get('user_id')
            is_writable = target_file_map.get('is_writable', False)
            is_readable = target_file_map.get('is_readable', True)
            is_executable = target_file_map.get('is_executable', False)
            file_type = target_file_map.get('file_type', 'text')
            name = target_file_map.get('name')
            description = target_file_map.get('description')
            destination = target_file_map.get('destination')
            content = target_file_map.get('content')
            if name and content:
                if image_id and group_id or user_id:
                    authorized = False
                    if image_id and JWT_AUTHORIZATION.is_authorized_action(cherrypy.request.authorizations, JWT_AUTHORIZATION.IMAGES_MODIFY):
                        authorized = True
                    if group_id:
                        group = cherrypy.request.db.getGroup(group_id, **('group_id',))
                        if group and JWT_AUTHORIZATION.is_user_authorized_action(cherrypy.request.authenticated_user, cherrypy.request.authorizations, JWT_AUTHORIZATION.GROUPS_MODIFY, group, **('target_group',)):
                            authorized = True
                    if user_id:
                        user = cherrypy.request.db.get_user_by_id(user_id)
                        if user and JWT_AUTHORIZATION.is_user_authorized_action(cherrypy.request.authenticated_user, cherrypy.request.authorizations, JWT_AUTHORIZATION.USERS_MODIFY, user, **('target_user',)):
                            authorized = True
                    if not authorized:
                        self.logger.error(f'''Unauthorized attempt to create a file mapping by user ({cherrypy.request.kasm_user_name}).''')
                        cherrypy.response.status = 401
                        response['ui_show_error'] = True
                        response['error_message'] = 'Unauthorized Action'
                    else:
                        file_map = cherrypy.request.db.create_file_map(name, description, content, destination, file_type, is_readable, is_writable, is_executable, user_id, group_id, image_id, **('name', 'description', 'content', 'destination', 'file_type', 'is_readable', 'is_writable', 'is_executable', 'user_id', 'group_id', 'image_id'))
                        response['file_map'] = cherrypy.request.db.serializable(file_map.jsonDict)
                else:
                    self.logger.error('Invalid request, file map must be associated with a group, user, or image.')
                    response['error_message'] = 'Invalid Request'
            else:
                msg = 'Invalid Request, missing required fields.'
                self.logger.error(msg)
                response['error_message'] = msg
        else:
            msg = 'Invalid Request. Missing required parameters'
            self.logger.error(msg)
            response['error_message'] = msg
        return response

    create_file_map = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.GROUPS_MODIFY,
        JWT_AUTHORIZATION.GROUPS_MODIFY_IFMEMBER,
        JWT_AUTHORIZATION.GROUPS_MODIFY_SYSTEM,
        JWT_AUTHORIZATION.USERS_MODIFY,
        JWT_AUTHORIZATION.USERS_MODIFY_ADMIN,
        JWT_AUTHORIZATION.IMAGES_MODIFY], **('requested_actions',))(create_file_map))))
    
    def update_file_map(self):
        response = { }
        event = cherrypy.request.json
        target_file_map = event.get('target_file_map')
        if target_file_map:
            file_map_id = target_file_map.get('file_map_id')
            is_writable = target_file_map.get('is_writable', False)
            is_readable = target_file_map.get('is_readable', True)
            is_executable = target_file_map.get('is_executable', False)
            file_type = target_file_map.get('file_type', 'text')
            name = target_file_map.get('name')
            description = target_file_map.get('description')
            destination = target_file_map.get('destination')
            content = target_file_map.get('content')
            if file_map_id and name and content:
                file_map = cherrypy.request.db.get_file_map(file_map_id, **('file_map_id',))
                if file_map:
                    if not file_map.image or JWT_AUTHORIZATION.is_authorized_action(cherrypy.request.authorizations, JWT_AUTHORIZATION.IMAGES_MODIFY):
                        if (file_map.group or JWT_AUTHORIZATION.is_user_authorized_action(cherrypy.request.authenticated_user, cherrypy.request.authorizations, JWT_AUTHORIZATION.GROUPS_MODIFY, file_map.group, **('target_group',)) or file_map.user) and JWT_AUTHORIZATION.is_user_authorized_action(cherrypy.request.authenticated_user, cherrypy.request.authorizations, JWT_AUTHORIZATION.USERS_MODIFY, file_map.user, **('target_user',)):
                            file_map = cherrypy.request.db.update_file_map(file_map, name, description, content, destination, file_type, is_readable, is_writable, is_executable, **('file_map', 'name', 'description', 'content', 'destination', 'file_type', 'is_readable', 'is_writable', 'is_executable'))
                            response['file_map'] = cherrypy.request.db.serializable(file_map.jsonDict)
                        else:
                            self.logger.error(f'''User ({cherrypy.request.kasm_user_id}) attempted to modify file mapping ({file_map_id}) but is not authorized.''')
                            cherrypy.response.status = 401
                            response['ui_show_error'] = True
                            response['error_message'] = 'Unauthorized Request'
                    else:
                        self.logger.error(f'''Unable to find referenced file map {file_map_id}''')
                        response['error_message'] = 'Unable to find referenced file map.'
                else:
                    msg = 'Invalid Request, missing required fields.'
                    self.logger.error(msg)
                    response['error_message'] = msg
            else:
                msg = 'Invalid Request. Missing required parameters.'
                self.logger.error(msg)
                response['error_message'] = msg
        return response

    update_file_map = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.GROUPS_MODIFY,
        JWT_AUTHORIZATION.GROUPS_MODIFY_IFMEMBER,
        JWT_AUTHORIZATION.GROUPS_MODIFY_SYSTEM,
        JWT_AUTHORIZATION.USERS_MODIFY,
        JWT_AUTHORIZATION.USERS_MODIFY_ADMIN,
        JWT_AUTHORIZATION.IMAGES_MODIFY], **('requested_actions',))(update_file_map))))
    
    def upload_file_mapping(self, ufile, name, description, destination, file_type, image_id, group_id, user_id, is_writable, is_readable, is_executable, file_map_id = ('binary', None, None, None, 'false', 'true', 'false', None)):
        response = { }
        is_writable = True if is_writable.lower() == 'true' else False
        is_readable = True if is_readable.lower() == 'true' else False
        is_executable = True if is_executable.lower() == 'true' else False
        image_id = None if image_id == 'null' else image_id
        group_id = None if group_id == 'null' else group_id
        group = None
        target_user_id = None if user_id == 'null' else user_id
        target_user = None
        file_map_id = None if file_map_id == 'null' else file_map_id
        if group_id:
            group = cherrypy.request.db.getGroup(group_id, **('group_id',))
        if target_user_id:
            target_user = cherrypy.request.db.get_user_by_id(target_user_id)
        if not image_id or JWT_AUTHORIZATION.is_authorized_action(cherrypy.request.authorizations, JWT_AUTHORIZATION.IMAGES_MODIFY):
            if (group or JWT_AUTHORIZATION.is_user_authorized_action(cherrypy.request.authenticated_user, cherrypy.request.authorizations, JWT_AUTHORIZATION.GROUPS_MODIFY, group, **('target_group',)) or target_user) and JWT_AUTHORIZATION.is_user_authorized_action(cherrypy.request.authenticated_user, cherrypy.request.authorizations, JWT_AUTHORIZATION.USERS_MODIFY, target_user, **('target_user',)):
                if file_map_id and type(ufile) == str and ufile == '[object Object]':
                    all_data_b64 = None
                elif type(ufile) == cherrypy._cpreqbody.Part and hasattr(ufile, 'file'):
                    max_size = 5000000
                    size = 0
                    all_data = bytearray()
                    data = ufile.file.read(8192)
                    if not data:
                        pass
                    else:
                        all_data += data
                        size += len(data)
                        if size > max_size:
                            pass
                        
                        if size > max_size:
                            msg = f'''Upload file mapping failed, size of file greater than limit of {max_size} bytes.'''
                            self.logger.error(msg)
                            response['error_message'] = msg
                            return response
                        all_data_b64 = None.b64encode(all_data).decode('ascii')
                else:
                    msg = 'Invalid Request, missing required fields.'
                    self.logger.error(msg)
                    response['error_message'] = msg
                    return response
                if None:
                    file_map = cherrypy.request.db.get_file_map(file_map_id, **('file_map_id',))
                    if file_map:
                        file_map = cherrypy.request.db.update_file_map(file_map, name, description, all_data_b64, destination, file_type, is_readable, is_writable, is_executable, **('file_map', 'name', 'description', 'content', 'destination', 'file_type', 'is_readable', 'is_writable', 'is_executable'))
                    else:
                        self.logger.error(f'''Unable to find referenced file map {file_map_id}''')
                        response['error_message'] = 'Unable to find referenced file map.'
                elif name and description:
                    if image_id and group_id or target_user_id:
                        file_map = cherrypy.request.db.create_file_map(name, description, all_data_b64, destination, file_type, is_readable, is_writable, is_executable, target_user_id, group_id, image_id, **('name', 'description', 'content', 'destination', 'file_type', 'is_readable', 'is_writable', 'is_executable', 'user_id', 'group_id', 'image_id'))
                        response['file_map'] = cherrypy.request.db.serializable(file_map.jsonDict)
                    else:
                        self.logger.error('Invalid request, file map must be associated with a group, user, or image.')
                        response['error_message'] = 'Invalid Request'
                else:
                    msg = 'Invalid Request, missing required fields.'
                    self.logger.error(msg)
                    response['error_message'] = msg
            else:
                self.logger.error(f'''User ({cherrypy.request.kasm_user_id}) attempted to modify file mapping ({file_map_id}) but is not authorized.''')
                cherrypy.response.status = 401
                response['ui_show_error'] = True
                response['error_message'] = 'Unauthorized Request'
        return response

    upload_file_mapping = cherrypy.expose(cherrypy.tools.json_out()(CookieAuthenticated([
        JWT_AUTHORIZATION.IMAGES_MODIFY,
        JWT_AUTHORIZATION.GROUPS_MODIFY,
        JWT_AUTHORIZATION.GROUPS_MODIFY_IFMEMBER,
        JWT_AUTHORIZATION.GROUPS_MODIFY_SYSTEM,
        JWT_AUTHORIZATION.USERS_MODIFY,
        JWT_AUTHORIZATION.USERS_MODIFY_ADMIN], **('requested_actions',))(upload_file_mapping)))
    
    def delete_file_map(self):
        response = { }
        event = cherrypy.request.json
        target_file_map = event.get('target_file_map', { })
        file_map_id = target_file_map.get('file_map_id')
        if file_map_id:
            file_map = cherrypy.request.db.get_file_map(file_map_id, **('file_map_id',))
            if file_map:
                if not file_map.image or JWT_AUTHORIZATION.is_authorized_action(cherrypy.request.authorizations, JWT_AUTHORIZATION.IMAGES_MODIFY):
                    if (file_map.group or JWT_AUTHORIZATION.is_user_authorized_action(cherrypy.request.authenticated_user, cherrypy.request.authorizations, JWT_AUTHORIZATION.GROUPS_MODIFY, file_map.group, **('target_group',)) or file_map.user) and JWT_AUTHORIZATION.is_user_authorized_action(cherrypy.request.authenticated_user, cherrypy.request.authorizations, JWT_AUTHORIZATION.USERS_MODIFY, file_map.user, **('target_user',)):
                        cherrypy.request.db.delete_file_map(file_map, **('file_map',))
                    else:
                        response['error_message'] = 'Unauthorized Request'
                        cherrypy.response.status = 401
                        response['ui_show_error'] = True
                        self.logger.error(f'''User ({cherrypy.request.kasm_user_name}) attempted to delete a file mapping with improper authorization.''')
                else:
                    self.logger.error(f'''File mapping with id ({file_map_id}) does not exist''')
                    response['error_message'] = 'Unable to find referenced file map.'
            else:
                msg = 'Invalid Request. Missing required parameters'
                self.logger.error(msg)
                response['error_message'] = msg
        return response

    delete_file_map = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.GROUPS_MODIFY,
        JWT_AUTHORIZATION.GROUPS_MODIFY_IFMEMBER,
        JWT_AUTHORIZATION.GROUPS_MODIFY_SYSTEM,
        JWT_AUTHORIZATION.USERS_MODIFY,
        JWT_AUTHORIZATION.USERS_MODIFY_ADMIN,
        JWT_AUTHORIZATION.IMAGES_MODIFY], **('requested_actions',))(delete_file_map))))
    
    def get_connection_proxies(self):
        response = { }
        connection_proxies = cherrypy.request.db.get_connection_proxies()
        response['connection_proxies'] = (lambda .0: [ cherrypy.request.db.serializable(x.jsonDict) for x in .0 ])(connection_proxies)
        return response

    get_connection_proxies = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.CONNECTION_PROXY_VIEW], True, **('requested_actions', 'read_only'))(get_connection_proxies))))
    
    def create_connection_proxy(self):
        response = { }
        event = cherrypy.request.json
        target_connection_proxy = event.get('target_connection_proxy')
        if target_connection_proxy:
            connection_proxy = cherrypy.request.db.create_connection_proxy(target_connection_proxy.get('server_address'), target_connection_proxy.get('server_port'), target_connection_proxy.get('connection_proxy_type'), target_connection_proxy.get('auth_token'), target_connection_proxy.get('zone_id'), **('server_address', 'server_port', 'connection_proxy_type', 'auth_token', 'zone_id'))
            response['connection_proxy'] = cherrypy.request.db.serializable(connection_proxy.jsonDict)
        else:
            msg = 'Invalid Request. Missing required parameters'
            self.logger.error(msg)
            response['error_message'] = msg
        return response

    create_connection_proxy = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.CONNECTION_PROXY_CREATE], **('requested_actions',))(create_connection_proxy))))
    
    def update_connection_proxy(self):
        response = { }
        event = cherrypy.request.json
        target_connection_proxy = event.get('target_connection_proxy')
        connection_proxy_id = target_connection_proxy.get('connection_proxy_id')
        if connection_proxy_id:
            connection_proxy = cherrypy.request.db.get_connection_proxy(connection_proxy_id)
            if connection_proxy:
                updated_connection_proxy = cherrypy.request.db.update_connection_proxy(connection_proxy, target_connection_proxy.get('server_address'), target_connection_proxy.get('server_port'), target_connection_proxy.get('connection_proxy_type'), target_connection_proxy.get('auth_token'), target_connection_proxy.get('zone_id'), **('server_address', 'server_port', 'connection_proxy_type', 'auth_token', 'zone_id'))
                response['connection_proxy'] = cherrypy.request.db.serializable(updated_connection_proxy.jsonDict)
            else:
                msg = 'Invalid Request. Missing required parameters'
                self.logger.error(msg)
                response['error_message'] = msg
        return response

    update_connection_proxy = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.CONNECTION_PROXY_MODIFY], **('requested_actions',))(update_connection_proxy))))
    
    def delete_connection_proxy(self):
        response = { }
        event = cherrypy.request.json
        target_connection_proxy = event.get('target_connection_proxy')
        connection_proxy_id = target_connection_proxy.get('connection_proxy_id')
        if connection_proxy_id:
            connection_proxy = cherrypy.request.db.get_connection_proxy(connection_proxy_id)
            if connection_proxy:
                cherrypy.request.db.delete_connection_proxy(connection_proxy)
            else:
                msg = f'''Connection Proxy with id ({connection_proxy_id}) does not exist'''
                self.logger.error(msg)
                response['error_message'] = msg
        else:
            msg = 'Invalid Request. Missing required parameters'
            self.logger.error(msg)
            response['error_message'] = msg
        return response

    delete_connection_proxy = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.CONNECTION_PROXY_DELETE], **('requested_actions',))(delete_connection_proxy))))
    
    def upload_physical_tokens(self, ufile, zippw):
        response = { }
        upload_filename = ufile.filename
    # WARNING: Decompyle incomplete

    upload_physical_tokens = cherrypy.tools.json_out()(cherrypy.expose(CookieAuthenticated([
        JWT_AUTHORIZATION.PHYSICAL_TOKENS_CREATE], **('requested_actions',))(upload_physical_tokens)))
    
    def unassign_physical_token(self):
        response = { }
        event = cherrypy.request.json
        if 'target_token' in event and 'serial_number' in event['target_token']:
            token = cherrypy.request.db.get_physical_token(event['target_token']['serial_number'])
            if token or token.user:
                token = cherrypy.request.db.unassign_physical_token(token)
                response['token'] = cherrypy.request.db.serializable(token.jsonDict)
            else:
                msg = f'''Invalid Request. Specified token ({event['target_token']['serial_number']}) did not exist.'''
                self.logger.error(msg)
                response['error_message'] = msg
        else:
            msg = 'Invalid Request. Missing required parameters'
            self.logger.error(msg)
            response['error_message'] = msg
        return response

    unassign_physical_token = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.PHYSICAL_TOKENS_MODIFY], False, **('requested_actions', 'read_only'))(unassign_physical_token))))
    
    def assign_physical_token(self):
        response = { }
        event = cherrypy.request.json
        if 'target_user' in event and 'user_id' in event['target_user'] and 'target_token' in event and 'serial_number' in event['target_token']:
            user = cherrypy.request.db.get_user_by_id(event['target_user']['user_id'])
            token = cherrypy.request.db.get_physical_token(event['target_token']['serial_number'])
            if user and token:
                token = cherrypy.request.db.assign_physical_token(token, user)
                response['physical_token'] = cherrypy.request.db.serializable(token.jsonDict)
                self.logger.info(f'''Physical token ({token.serial_number}) assigned to user ({user.username}) with seed ({user.secret})''')
            else:
                msg = f'''Invalid Request. Specified user ({event['target_user']['user_id']}) or token ({event['target_token']['serial_number']}) did not exist.'''
                self.logger.error(msg)
                response['error_message'] = msg
        else:
            msg = 'Invalid Request. Missing required parameters'
            self.logger.error(msg)
            response['error_message'] = msg
        return response

    assign_physical_token = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.PHYSICAL_TOKENS_MODIFY], False, **('requested_actions', 'read_only'))(assign_physical_token))))
    
    def delete_physical_token(self):
        response = { }
        event = cherrypy.request.json
        if 'target_token' in event and 'serial_number' in event['target_token']:
            token = cherrypy.request.db.get_physical_token(event['target_token']['serial_number'])
            if token:
                username = token.user.username if token.user else ''
                cherrypy.request.db.delete_physical_token(token)
                self.logger.info(f'''Deleted physical token ({event['target_token']['serial_number']}) and unassigned from user ({username}).''')
                response['tokens_deleted'] = 1
            else:
                msg = f'''Delete token failed, unable to find token with serial number {event['target_token']['serial_number']}'''
                self.logger.info(msg)
                response['error_message'] = msg
        elif 'target_token' in event and 'seed_filename' in event['target_token']:
            response['tokens_deleted'] = cherrypy.request.db.delete_physical_tokens_by_file(event['target_token']['seed_filename'])
            self.logger.info(f'''Deleted {response['tokens_deleted']} by filename {event['target_token']['seed_filename']}''')
        else:
            msg = 'Invalid Request. Missing required parameters'
            self.logger.error(msg)
            response['error_message'] = msg
        return response

    delete_physical_token = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.PHYSICAL_TOKENS_DELETE], False, **('requested_actions', 'read_only'))(delete_physical_token))))
    
    def get_physical_tokens(self):
        response = { }
        tokens = cherrypy.request.db.get_physical_tokens()
        if tokens:
            response['physical_tokens'] = (lambda .0: [ cherrypy.request.db.serializable(x.jsonDict) for x in .0 ])(tokens)
        return response

    get_physical_tokens = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.PHYSICAL_TOKENS_VIEW], True, **('requested_actions', 'read_only'))(get_physical_tokens))))
    
    def get_server_pools(self):
        response = {
            'server_pools': [] }
        server_pools = cherrypy.request.db.get_server_pools()
        for server_pool in server_pools:
            _sp = cherrypy.request.db.serializable(server_pool.jsonDict)
            _sp['servers'] = []
            for server in server_pool.servers:
                _sp['servers'].append({
                    'server_id': str(server.server_id),
                    'hostname': server.hostname,
                    'friendly_name': server.friendly_name })
            response['server_pools'].append(_sp)
        return response

    get_server_pools = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.SERVER_POOLS_VIEW], True, **('requested_actions', 'read_only'))(get_server_pools))))
    
    def create_server_pool(self):
        response = { }
        event = cherrypy.request.json
        target_server_pool = event.get('target_server_pool')
        if target_server_pool:
            server_pool = cherrypy.request.db.create_server_pool(target_server_pool.get('server_pool_name'), target_server_pool.get('server_pool_type'), **('server_pool_name', 'server_pool_type'))
            response['server_pool'] = cherrypy.request.db.serializable(server_pool.jsonDict)
        else:
            msg = 'Invalid Request. Missing required parameters'
            self.logger.error(msg)
            response['error_message'] = msg
        return response

    create_server_pool = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.SERVER_POOLS_CREATE], **('requested_actions',))(create_server_pool))))
    
    def update_server_pool(self):
        response = { }
        event = cherrypy.request.json
        target_server_pool = event.get('target_server_pool')
        server_pool_id = target_server_pool.get('server_pool_id')
        if server_pool_id:
            server_pool = cherrypy.request.db.get_server_pool(server_pool_id)
            if server_pool:
                server_pool = cherrypy.request.db.update_server_pool(server_pool, target_server_pool.get('server_pool_name'), target_server_pool.get('server_pool_type'), **('server_pool_name', 'server_pool_type'))
                response['server_pool'] = cherrypy.request.db.serializable(server_pool.jsonDict)
            else:
                msg = f'''Server Pool with id ({server_pool_id}) does not exist'''
                self.logger.error(msg)
                response['error_message'] = msg
        else:
            msg = 'Invalid Request. Missing required parameters'
            self.logger.error(msg)
            response['error_message'] = msg
        return response

    update_server_pool = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.SERVER_POOLS_MODIFY], **('requested_actions',))(update_server_pool))))
    
    def delete_server_pool(self):
        response = { }
        event = cherrypy.request.json
        target_server_pool = event.get('target_server_pool')
        server_pool_id = target_server_pool.get('server_pool_id')
        if server_pool_id:
            server_pool = cherrypy.request.db.get_server_pool(server_pool_id)
            if server_pool:
                cherrypy.request.db.delete_server_pool(server_pool)
            else:
                msg = f'''Server Pool with id ({server_pool_id}) does not exist'''
                self.logger.error(msg)
                response['error_message'] = msg
        else:
            msg = 'Invalid Request. Missing required parameters'
            self.logger.error(msg)
            response['error_message'] = msg
        return response

    delete_server_pool = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.SERVER_POOLS_DELETE], **('requested_actions',))(delete_server_pool))))
    
    def get_autoscale_configs(self):
        response = { }
        autoscale_configs = cherrypy.request.db.get_autoscale_configs()
        response['autoscale_configs'] = []
        for auto_scale_config in autoscale_configs:
            asc_dict = cherrypy.request.db.serializable(auto_scale_config.jsonDict)
            if auto_scale_config.vm_provider_config:
                asc_dict['vm_provider_config'] = {
                    'vm_provider_display_name': auto_scale_config.vm_provider_config.vm_provider_display_name }
            response['autoscale_configs'].append(asc_dict)
        return response

    get_autoscale_configs = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.AUTOSCALE_VIEW], True, **('requested_actions', 'read_only'))(get_autoscale_configs))))
    
    def create_autoscale_config(self):
        response = { }
        event = cherrypy.request.json
        target_autoscale_config = event.get('target_autoscale_config')
        if not LicenseHelper(cherrypy.request.db, self.logger).is_auto_scaling_ok():
            msg = 'Access Denied. Auto Scaling is not licensed'
            self.logger.error(msg)
            return {
                'error_message': msg }
    # WARNING: Decompyle incomplete

    create_autoscale_config = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.AUTOSCALE_CREATE], **('requested_actions',))(create_autoscale_config))))
    
    def update_autoscale_config(self):
        response = { }
        event = cherrypy.request.json
        target_autoscale_config = event.get('target_autoscale_config', { })
        autoscale_config_id = target_autoscale_config.get('autoscale_config_id')
        if not LicenseHelper(cherrypy.request.db, self.logger).is_auto_scaling_ok():
            msg = 'Access Denied. Auto Scaling is not licensed'
            self.logger.error(msg)
            return {
                'error_message': msg }
    # WARNING: Decompyle incomplete

    update_autoscale_config = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.AUTOSCALE_MODIFY], **('requested_actions',))(update_autoscale_config))))
    
    def delete_autoscale_config(self):
        response = { }
        event = cherrypy.request.json
        autoscale_config_id = event.get('autoscale_config_id')
        if autoscale_config_id:
            autoscale_config = cherrypy.request.db.get_autoscale_config(autoscale_config_id)
            if autoscale_config:
                cherrypy.request.db.delete_autoscale_config(autoscale_config)
            else:
                msg = f'''AutoScale Config with id ({autoscale_config_id}) does not exist'''
                self.logger.error(msg)
                response['error_message'] = msg
        else:
            msg = 'Invalid Request. Missing required parameters'
            self.logger.error(msg)
            response['error_message'] = msg
        return response

    delete_autoscale_config = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.AUTOSCALE_DELETE], **('requested_actions',))(delete_autoscale_config))))
    
    def create_schedule(self):
        response = { }
        event = cherrypy.request.json
        target_schedule = event.get('target_schedule', { })
        if target_schedule:
            if target_schedule.get('autoscale_config_id'):
                
                try:
                    schedule = cherrypy.request.db.create_schedule(target_schedule.get('autoscale_config_id'), target_schedule.get('days_of_the_week'), target_schedule.get('active_start_time'), target_schedule.get('active_end_time'), target_schedule.get('timezone'), **('autoscale_config_id', 'days_of_the_week', 'active_start_time', 'active_end_time', 'timezone'))
                    response['schedule'] = cherrypy.request.db.serializable(schedule.jsonDict)
                finally:
                    pass
                except ZoneInfoNotFoundError:
                    msg = 'Received an invalid timezone value'
                    self.logger.error(msg)
                    response['error_message'] = msg
                

            self.logger.error('Invalid Request. Unknown schedule type.')
            response['error_message'] = 'Invalid Request. Missing required parameters'
        else:
            msg = 'Invalid Request. Missing required parameters'
            self.logger.error(msg)
            response['error_message'] = msg
        return response

    create_schedule = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.AUTOSCALE_SCHEDULE_CREATE], **('requested_actions',))(create_schedule))))
    
    def get_schedule(self):
        response = { }
        event = cherrypy.request.json
        target_schedule_id = event.get('target_schedule_id')
        if target_schedule_id:
            schedule = cherrypy.request.db.get_schedule(target_schedule_id, **('schedule_id',))
            response['schedule'] = cherrypy.request.db.serializable(schedule.jsonDict)
        else:
            msg = 'Invalid Request. Missing required parameters'
            self.logger.error(msg)
            response['error_message'] = msg
        return response

    get_schedule = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.AUTOSCALE_SCHEDULE_VIEW], True, **('requested_actions', 'read_only'))(get_schedule))))
    
    def get_schedules(self):
        response = { }
        event = cherrypy.request.json
        if event.get('target_autoscale_config_id'):
            schedules = cherrypy.request.db.get_schedules(event.get('target_autoscale_config_id'), **('autoscale_config_id',))
            response['schedules'] = (lambda .0: [ cherrypy.request.db.serializable(x.jsonDict) for x in .0 ])(schedules)
        else:
            self.logger.error('Invalid Request. Unknown schedule type.')
            response['error_message'] = 'Invalid Request. Missing required parameters'
        return response

    get_schedules = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.AUTOSCALE_SCHEDULE_VIEW], True, **('requested_actions', 'read_only'))(get_schedules))))
    
    def update_schedule(self):
        response = { }
        event = cherrypy.request.json
        target_schedule = event.get('target_schedule', { })
        if target_schedule:
            schedule_id = target_schedule.get('target_schedule_id')
            if schedule_id:
                schedule = cherrypy.request.db.get_schedule(schedule_id, **('schedule_id',))
                if schedule:
                    
                    try:
                        schedule = cherrypy.request.db.update_schedule(schedule, target_schedule.get('days_of_the_week'), target_schedule.get('active_start_time'), target_schedule.get('active_end_time'), target_schedule.get('timezone'), **('schedule', 'days_of_the_week', 'active_start_time', 'active_end_time', 'timezone'))
                        response['schedule'] = cherrypy.request.db.serializable(schedule.jsonDict)
                    finally:
                        pass
                    except ZoneInfoNotFoundError:
                        msg = 'Received an invalid timezone value'
                        self.logger.error(msg)
                        response['error_message'] = msg
                    

                self.logger.error(f'''Unable to find referenced schedule {schedule_id}''')
                response['error_message'] = 'Unable to find referenced schedule.'
            else:
                self.logger.error('Invalid Request. Missing schedule id')
                response['error_message'] = 'Invalid Request. Missing required parameters'
        else:
            msg = 'Invalid Request. Missing required parameters'
            self.logger.error(msg)
            response['error_message'] = msg
        return response

    update_schedule = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.AUTOSCALE_SCHEDULE_MODIFY], **('requested_actions',))(update_schedule))))
    
    def delete_schedule(self):
        response = { }
        event = cherrypy.request.json
        target_schedule_id = event.get('target_schedule_id')
        if target_schedule_id:
            schedule = cherrypy.request.db.get_schedule(target_schedule_id, **('schedule_id',))
            if schedule:
                cherrypy.request.db.delete_schedule(schedule, **('schedule',))
            else:
                self.logger.error(f'''Unable to find referenced schedule {target_schedule_id}''')
                response['error_message'] = 'Unable to find referenced schedule.'
        else:
            msg = 'Invalid Request. Missing required parameters'
            self.logger.error(msg)
            response['error_message'] = msg
        return response

    delete_schedule = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.AUTOSCALE_SCHEDULE_DELETE], **('requested_actions',))(delete_schedule))))
    
    def get_vm_provider_configs(self):
        response = {
            'vm_provider_configs': [] }
        response['vm_provider_configs'] += (lambda .0: [ cherrypy.request.db.serializable(x.jsonDict) for x in .0 ])(cherrypy.request.db.get_vm_provider_configs())
        return response

    get_vm_provider_configs = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.VM_PROVIDER_VIEW], True, **('requested_actions', 'read_only'))(get_vm_provider_configs))))
    
    def get_vm_provider_config(self):
        response = { }
        event = cherrypy.request.json
        target_vm_provider_config = event.get('target_vm_provider_config', { })
        provider_name = target_vm_provider_config.get('vm_provider_name')
        vm_provider_config_id = target_vm_provider_config.get('vm_provider_config_id')
        vm_provider_config = cherrypy.request.db.get_vm_provider_config(vm_provider_config_id, provider_name, **('vm_provider_config_id', 'provider_name'))
        response['vm_provider_config'] = cherrypy.request.db.serializable(vm_provider_config.jsonDict)
        return response

    get_vm_provider_config = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.VM_PROVIDER_VIEW], True, **('requested_actions', 'read_only'))(get_vm_provider_config))))
    
    def create_vm_provider_config(self):
        response = { }
        event = cherrypy.request.json
        target_vm_provider_config = event.get('target_vm_provider_config', { })
        provider_name = target_vm_provider_config.get('vm_provider_name')
        if not LicenseHelper(cherrypy.request.db, self.logger).is_auto_scaling_ok():
            msg = 'Access Denied. Auto Scaling is not licensed'
            self.logger.error(msg)
            return {
                'error_message': msg }
    # WARNING: Decompyle incomplete

    create_vm_provider_config = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.VM_PROVIDER_CREATE], **('requested_actions',))(create_vm_provider_config))))
    
    def update_vm_provider_config(self):
        response = { }
        event = cherrypy.request.json
        target_vm_provider_config = event.get('target_vm_provider_config')
        vm_provider_config_id = target_vm_provider_config.get('vm_provider_config_id')
        provider_name = target_vm_provider_config.get('vm_provider_name')
        if not LicenseHelper(cherrypy.request.db, self.logger).is_auto_scaling_ok():
            msg = 'Access Denied. Auto Scaling is not licensed'
            self.logger.error(msg)
            return {
                'error_message': msg }
    # WARNING: Decompyle incomplete

    update_vm_provider_config = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.VM_PROVIDER_MODIFY], **('requested_actions',))(update_vm_provider_config))))
    
    def _create_update_azure_provider(target_provider_config, azure_config, update, is_vm = (None, False, False)):
        data = process_json_props(target_provider_config, [
            'azure_image_reference',
            'azure_tags',
            'azure_config_override'], [], [], **('data', 'dict_props', 'list_props', 'not_empty_props'))
        if data.get('azure_authority') and data.get('azure_authority') not in AZURE_AUTHORITY.__members__:
            raise ValueError(f'''Azure Authority must be one of {(lambda .0: [ str(x) for x in .0 ])(AZURE_AUTHORITY.__members__)}''')
        kwargs = {
            'azure_subscription_id': None.get('azure_subscription_id'),
            'azure_resource_group': data.get('azure_resource_group'),
            'azure_tenant_id': data.get('azure_tenant_id'),
            'azure_client_id': data.get('azure_client_id'),
            'azure_client_secret': data.get('azure_client_secret'),
            'azure_region': data.get('azure_region'),
            'azure_authority': data.get('azure_authority') }
    # WARNING: Decompyle incomplete

    _create_update_azure_provider = staticmethod(_create_update_azure_provider)
    
    def _create_update_aws_provider(self, target_provider_config, aws_config, update, is_vm = (None, False, False)):
        data = process_json_props(target_provider_config, [
            'aws_ec2_custom_tags',
            'aws_ec2_config_override'], [
            'aws_ec2_security_group_ids'], [], **('data', 'dict_props', 'list_props', 'not_empty_props'))
        kwargs = {
            'aws_access_key_id': data.get('aws_access_key_id'),
            'aws_secret_access_key': data.get('aws_secret_access_key') }
    # WARNING: Decompyle incomplete

    
    def _create_update_digital_ocean_provider(target_provider_config, digital_ocean_config, update, is_vm = (None, False, False)):
        data = process_json_props(target_provider_config, [], [], [], **('data', 'dict_props', 'list_props', 'not_empty_props'))
        kwargs = {
            'digital_ocean_token': data.get('digital_ocean_token') }
    # WARNING: Decompyle incomplete

    _create_update_digital_ocean_provider = staticmethod(_create_update_digital_ocean_provider)
    
    def _create_update_oci_provider(target_provider_config, oci_config, update, is_vm = (None, False, False)):
        data = process_json_props(target_provider_config, [
            'oci_custom_tags',
            'oci_config_override'], [
            'oci_nsg_ocids',
            'oci_availability_domains'], [], **('data', 'dict_props', 'list_props', 'not_empty_props'))
        kwargs = {
            'oci_user_ocid': data.get('oci_user_ocid'),
            'oci_private_key': data.get('oci_private_key'),
            'oci_fingerprint': data.get('oci_fingerprint'),
            'oci_tenancy_ocid': data.get('oci_tenancy_ocid'),
            'oci_region': data.get('oci_region'),
            'oci_compartment_ocid': data.get('oci_compartment_ocid') }
    # WARNING: Decompyle incomplete

    _create_update_oci_provider = staticmethod(_create_update_oci_provider)
    
    def _create_update_gcp_provider(target_provider_config, gcp_config, update, is_vm = (None, False, False)):
        data = process_json_props(target_provider_config, [
            'gcp_credentials',
            'gcp_custom_labels',
            'gcp_service_account',
            'gcp_config_override'], [
            'gcp_network_tags',
            'gcp_metadata',
            'gcp_guest_accelerators'], [], **('data', 'dict_props', 'list_props', 'not_empty_props'))
        kwargs = {
            'gcp_credentials': data.get('gcp_credentials'),
            'gcp_project': data.get('gcp_project') }
    # WARNING: Decompyle incomplete

    _create_update_gcp_provider = staticmethod(_create_update_gcp_provider)
    
    def _create_update_vsphere_provider(target_provider_config, vsphere_config, update, is_vm = (None, False, True)):
        data = process_json_props(target_provider_config, [], [], [], **('data', 'dict_props', 'list_props', 'not_empty_props'))
        kwargs = dict()
    # WARNING: Decompyle incomplete

    _create_update_vsphere_provider = staticmethod(_create_update_vsphere_provider)
    
    def _create_update_openstack_provider(target_provider_config, openstack_config, update, is_vm = (None, False, True)):
        data = process_json_props(target_provider_config, [
            'openstack_config_override',
            'openstack_metadata'], [
            'openstack_security_groups'], [], **('data', 'dict_props', 'list_props', 'not_empty_props'))
        kwargs = dict()
    # WARNING: Decompyle incomplete

    _create_update_openstack_provider = staticmethod(_create_update_openstack_provider)
    
    def delete_vm_provider_config(self):
        response = { }
        event = cherrypy.request.json
        target_vm_provider_config = event.get('target_vm_provider_config', { })
        vm_provider_config_id = target_vm_provider_config.get('vm_provider_config_id')
        provider_name = target_vm_provider_config.get('vm_provider_name')
        if vm_provider_config_id and provider_name:
            vm_provider_config = cherrypy.request.db.get_vm_provider_config(vm_provider_config_id, provider_name, **('vm_provider_config_id', 'provider_name'))
            if vm_provider_config:
                cherrypy.request.db.delete_vm_provider_config(vm_provider_config)
            else:
                msg = f'''Unable to find provider ID {vm_provider_config_id}'''
                self.logger.error(msg)
                response['error_message'] = msg
                return response
        msg = 'Invalid Request. Missing required parameters'
        self.logger.error(msg)
        response['error_message'] = msg
        return response

    delete_vm_provider_config = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.VM_PROVIDER_DELETE], **('requested_actions',))(delete_vm_provider_config))))
    
    def get_dns_provider_configs(self):
        response = {
            'dns_provider_configs': [] }
        response['dns_provider_configs'] += (lambda .0: [ cherrypy.request.db.serializable(x.jsonDict) for x in .0 ])(cherrypy.request.db.get_dns_provider_configs())
        return response

    get_dns_provider_configs = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.DNS_PROVIDERS_VIEW], True, **('requested_actions', 'read_only'))(get_dns_provider_configs))))
    
    def get_dns_provider_config(self):
        response = { }
        event = cherrypy.request.json
        target_dns_provider_config = event.get('target_dns_provider_config', { })
        provider_name = target_dns_provider_config.get('dns_provider_name')
        dns_provider_config_id = target_dns_provider_config.get('dns_provider_config_id')
        dns_provider_config = cherrypy.request.db.get_dns_provider_config(dns_provider_config_id, provider_name, **('dns_provider_config_id', 'provider_name'))
        response['dns_provider_config'] = cherrypy.request.db.serializable(dns_provider_config.jsonDict)
        return response

    get_dns_provider_config = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.DNS_PROVIDERS_VIEW], True, **('requested_actions', 'read_only'))(get_dns_provider_config))))
    
    def delete_dns_provider_config(self):
        response = { }
        event = cherrypy.request.json
        target_dns_provider_config = event.get('target_dns_provider_config', { })
        dns_provider_config_id = target_dns_provider_config.get('dns_provider_config_id')
        dns_provider_name = target_dns_provider_config.get('dns_provider_name')
        if dns_provider_config_id and dns_provider_name:
            dns_provider_config = cherrypy.request.db.get_dns_provider_config(dns_provider_config_id, dns_provider_name, **('dns_provider_config_id', 'provider_name'))
            if dns_provider_config:
                cherrypy.request.db.delete_dns_provider_config(dns_provider_config)
            else:
                msg = f'''Unable to find provider ID {dns_provider_config_id}'''
                self.logger.error(msg)
                response['error_message'] = msg
                return response
        msg = 'Invalid Request. Missing required parameters'
        self.logger.error(msg)
        response['error_message'] = msg
        return response

    delete_dns_provider_config = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.DNS_PROVIDERS_DELETE], **('requested_actions',))(delete_dns_provider_config))))
    
    def create_dns_provider_config(self):
        response = { }
        event = cherrypy.request.json
        target_dns_provider_config = event.get('target_dns_provider_config', { })
        dns_provider_name = target_dns_provider_config.get('dns_provider_name')
        if not LicenseHelper(cherrypy.request.db, self.logger).is_auto_scaling_ok():
            msg = 'Access Denied. Auto Scaling is not licensed'
            self.logger.error(msg)
            return {
                'error_message': msg }
        if None:
            if dns_provider_name == 'azure':
                response['dns_provider_config'] = self._create_update_azure_provider(target_dns_provider_config, False, **('target_provider_config', 'is_vm'))
                return response
            if None == 'aws':
                response['dns_provider_config'] = self._create_update_aws_provider(target_dns_provider_config, False, **('target_provider_config', 'is_vm'))
                return response
            if None == 'digital_ocean':
                response['dns_provider_config'] = self._create_update_digital_ocean_provider(target_dns_provider_config, False, **('target_provider_config', 'is_vm'))
                return response
            if None == 'oci':
                response['dns_provider_config'] = self._create_update_oci_provider(target_dns_provider_config, False, **('target_provider_config', 'is_vm'))
                return response
            if None == 'gcp':
                response['dns_provider_config'] = self._create_update_gcp_provider(target_dns_provider_config, False, **('target_provider_config', 'is_vm'))
                return response
            msg = f'''{dns_provider_name}) does not exist'''
            self.logger.error(msg)
            response['error_message'] = msg
        else:
            msg = 'Invalid Request. Missing required parameters'
            self.logger.error(msg)
            response['error_message'] = msg
        return response

    create_dns_provider_config = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.DNS_PROVIDERS_CREATE], **('requested_actions',))(create_dns_provider_config))))
    
    def update_dns_provider_config(self):
        response = { }
        event = cherrypy.request.json
        target_dns_provider_config = event.get('target_dns_provider_config')
        dns_provider_config_id = target_dns_provider_config.get('dns_provider_config_id')
        dns_provider_name = target_dns_provider_config.get('dns_provider_name')
        if not LicenseHelper(cherrypy.request.db, self.logger).is_auto_scaling_ok():
            msg = 'Access Denied. Auto Scaling is not licensed'
            self.logger.error(msg)
            return {
                'error_message': msg }
    # WARNING: Decompyle incomplete

    update_dns_provider_config = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.DNS_PROVIDERS_MODIFY], **('requested_actions',))(update_dns_provider_config))))
    
    def export_data(self):
        event = cherrypy.request.json
        response = { }
        key = event.get('export_key', '').strip()
        tables = event.get('tables')
    # WARNING: Decompyle incomplete

    export_data = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.SYSTEM_EXPORT_DATA], True, **('requested_actions', 'read_only'))(export_data))))
    
    def export_schema(self):
        event = cherrypy.request.json
        response = cherrypy.request.db.export_schema(event.get('tables'), **('tables',))
        return {
            'schema': yaml.dump(response) }

    export_schema = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.SYSTEM_EXPORT_DATA], True, **('requested_actions', 'read_only'))(export_schema))))
    
    def import_data(self):
        event = cherrypy.request.json
        response = { }
        import_data = event.get('import_data')
        import_format = event.get('import_format')
        import_key = event.get('import_key')
        sanity_test = event.get('sanity_test')
    # WARNING: Decompyle incomplete

    import_data = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.SYSTEM_IMPORT_DATA], **('requested_actions',))(import_data))))
    
    def register_component(self, token = (None,)):
        response = { }
        event = cherrypy.request.json
        target_component = event.get('target_component')
        target_token = event.get('registration_token')
        target_type = target_component.get('type').lower()
        if token is None:
            token = event.get('token')
        authorized = False
        registration_token = self._db.get_config_setting_value('auth', 'registration_token')
        if target_token and registration_token and registration_token == target_token:
            authorized = True
        elif (token or len(token.split('.')) == 3 or target_token) and len(target_token.split('.')) == 3:
            token = token if token else target_token
            pub_cert = str.encode(self._db.get_config_setting_value('auth', 'api_public_cert'))
            decoded_jwt = jwt.decode(token, pub_cert, 'RS256', **('algorithm',))
            if 'authorizations' in decoded_jwt:
                for authorization in decoded_jwt['authorizations']:
                    if not JWT_AUTHORIZATION.is_authorized(authorization, [
                        JWT_AUTHORIZATION.SERVER_AGENT]) or target_type == 'server_agent':
                        if JWT_AUTHORIZATION.is_authorized(authorization, [
                            JWT_AUTHORIZATION.GUAC]) and target_type == 'connection_proxy':
                            authorized = True
                            continue
                            if not authorized:
                                self.logger.error(f'''Invalid JWT token utilized on register_component: {decoded_jwt}''')
                            elif token and target_type == 'connection_proxy' and 'id' in target_component:
                                component_id = target_component.get('id')
                                connection_proxy = cherrypy.request.db.get_connection_proxy(component_id)
                                if connection_proxy:
                                    if connection_proxy.auth_token == token:
                                        authorized = True
                                    else:
                                        self.logger.error(f'''Invalid auth token for connection_proxy ({component_id}).''')
                                else:
                                    self.logger.error(f'''Connection Proxy by id ({component_id}) not found to look up auth_token.''')
                            else:
                                self.logger.error('Unable to find valid registration token, auth token, or JWT')
        if target_component and 'type' in target_component:
            if authorized:
                if target_type == 'connection_proxy':
                    connection_proxy = None
                    component_id = target_component.get('id')
                    zone_id = target_component.get('zone_id')
                    zone_name = target_component.get('zone_name')
                    server_address = target_component.get('server_address')
                    if component_id:
                        connection_proxy = cherrypy.request.db.get_connection_proxy(component_id, **('connection_proxy_id',))
                    if not zone_id:
                        if zone_name:
                            zone = cherrypy.request.db.getZone(zone_name, **('zone_name',))
                            if zone:
                                zone_id = zone.zone_id
                            else:
                                self.logger.warning(f'''Zone ({zone_name}) does not exist! Creating Zone.''')
                                zone = cherrypy.request.db.createZone(zone_name, **('zone_name',))
                                zone_id = zone.zone_id
                        else:
                            zones = cherrypy.request.db.getZones()
                            if len(zones) == 1:
                                zone_id = zones[0].zone_id
                    if not server_address:
                        if 'X-Forwarded-For' in cherrypy.request.headers:
                            server_address = cherrypy.request.headers['X-Forwarded-For']
                        else:
                            server_address = cherrypy.request.remote.ip
                    server_port = target_component['server_port'] if 'server_port' in target_component else 443
                    connection_proxy_type = target_component['connection_proxy_type'] if 'connection_proxy_type' in target_component else 'GUAC'
                    if connection_proxy:
                        cherrypy.request.db.update_connection_proxy(connection_proxy, server_address, server_port, connection_proxy_type, zone_id, None, **('connection_proxy', 'server_address', 'server_port', 'connection_proxy_type', 'zone_id', 'auth_token'))
                    elif zone_id and connection_proxy is None:
                        msg = 'Component registration failed, a Zone ID was not provided and more than one zone exists.'
                        self.logger.error(msg)
                        response['error_message'] = msg
                    else:
                        connection_proxy = cherrypy.request.db.create_connection_proxy(server_address, server_port, connection_proxy_type, zone_id, component_id, None, **('server_address', 'server_port', 'connection_proxy_type', 'zone_id', 'connection_proxy_id', 'auth_token'))
                    if connection_proxy:
                        response['connection_proxy'] = cherrypy.request.db.serializable(connection_proxy.jsonDict)
                        response['connection_proxy']['public_jwt_cert'] = self._db.get_config_setting_value('auth', 'api_public_cert')
                        priv_key = str.encode(cherrypy.request.db.get_config_setting('auth', 'api_private_key').value)
                        response['connection_proxy']['auth_token'] = generate_jwt_token({
                            'connection_proxy_id': str(connection_proxy.connection_proxy_id) }, [
                            JWT_AUTHORIZATION.GUAC], priv_key, 365, **('expires_days',))
                    
                if target_type == 'server_agent':
                    server_id = target_component.get('id')
                    service_status = target_component.get('service_status')
                    server = cherrypy.request.db.getServer(server_id)
                    if server:
                        if server.agent_installed and server.operational_status not in (SERVER_OPERATIONAL_STATUS.DESTROYING,):
                            old_status = server.operational_status
                            server = cherrypy.request.db.update_server(server, SERVER_OPERATIONAL_STATUS.RUNNING.value, **('operational_status',))
                            self.logger.debug(f'''Agent has checked on on Server ({server_id}), status changed from ({old_status}) to (running)''')
                            response['operational_status'] = SERVER_OPERATIONAL_STATUS.RUNNING.value
                            server_agent = { }
                            priv_key = str.encode(self._db.get_config_setting_value('auth', 'api_private_key'))
                            server_agent['agent_jwt_token'] = generate_jwt_token({
                                'server_id': server_id }, [
                                JWT_AUTHORIZATION.SERVER_AGENT], priv_key, 1095, **('expires_days',))
                            if 'auto_configure' in target_component and target_component['auto_configure']:
                                hostname = target_component['hostname'] if 'hostname' in target_component and target_component['hostname'] else server_id
                                server_agent['public_jwt_cert'] = self._db.get_config_setting_value('auth', 'api_public_cert')
                                cert_and_key = generate_ssl_certs(hostname, 3650, **('days',))
                                server_agent['server_cert'] = cert_and_key[1]
                                server_agent['server_key'] = cert_and_key[0]
                                server_agent['multi_user'] = False if server.max_simultaneous_sessions <= 1 else True
                                if server.connection_username:
                                    pass
                                server_agent['user_sso'] = True if '{sso_username}' in server.connection_username or server.connection_username == '{sso_create_user}' else False
                            if old_status == SERVER_OPERATIONAL_STATUS.RUNNING.value and service_status and service_status == 'running':
                                for kasm in server.kasms:
                                    if kasm.operational_status in (SESSION_OPERATIONAL_STATUS.REQUESTED.value, SESSION_OPERATIONAL_STATUS.PROVISIONING.value, SESSION_OPERATIONAL_STATUS.ASSIGNED.value, SESSION_OPERATIONAL_STATUS.STARTING.value):
                                        self.logger.info(f'''Server ({server.server_id}) has checked in, launching session ({kasm.kasm_id}) with current status of {kasm.operational_status}''')
                                        self.provider_manager.get_session_from_server(kasm.image, server, kasm.user, None, kasm.cast_config, None, None, kasm, **('image', 'server', 'user', 'user_ip', 'cast_config', 'user_language', 'user_timezone', 'queued_kasm'))
                                        continue
                                        response['server_agent'] = server_agent
                                    elif server.agent_installed:
                                        msg = f'''Attempt to register a server agent for a server ({server_id}), which is being destroyed.'''
                                        self.logger.info(msg)
                                        response['error_message'] = 'Access Denied!'
                                    else:
                                        msg = f'''Attempt to register a server agent for a server ({server_id}) that is not supposed to have an agent installed.'''
                                        self.logger.error(msg)
                                        response['error_message'] = 'Access Denied!'
                                msg = f'''Attempt to register a server agent for a non-existing server ({server_id})'''
                                self.logger.error(msg)
                                response['error_message'] = 'Access Denied!'
                            else:
                                msg = f'''Attempt to register an invalid component ({target_type}).'''
                                self.logger.error(msg)
                                response['error_message'] = 'Access Denied!'
                        else:
                            msg = 'Unauthorized attempt to register a component.'
                            self.logger.error(msg)
                            response['error_message'] = 'Access Denied!'
                    else:
                        msg = f'''Invalid Request. Missing required parameters: {event}'''
                        self.logger.error(msg)
                        response['error_message'] = 'Access Denied!'
        return response

    register_component = cherrypy.tools.json_in()(cherrypy.tools.json_out()(cherrypy.expose(Unauthenticated()(register_component))))
    
    def available_architectures(self):
        arch_normalizer = {
            'aarch64': 'arm64',
            'amd64': 'amd64',
            'x86_64': 'amd64' }
        archs = []
        servers = self._get_servers()
        if 'servers' in servers:
            for server in servers['servers']:
                if isinstance(server['docker_info'], dict):
                    arch = arch_normalizer.get(server['docker_info'].get('Architecture'))
                    if arch not in archs:
                        archs.append(arch)
                        continue
                        return archs

    
    def addSlash(self, path):
        if not path.endswith('/'):
            path += '/'
        return path

    
    def get_registries(self):
        response = {
            'registries': [],
            'architectures': [] }
        refresh = False
        archs = self.available_architectures()
        response['architectures'] = archs
        registries = cherrypy.request.db.get_registries()
    # WARNING: Decompyle incomplete

    get_registries = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.REGISTRIES_VIEW], True, **('requested_actions', 'read_only'))(get_registries))))
    
    def create_registry(self):
        response = { }
        event = cherrypy.request.json
        if 'registry' in event:
            return self._create_registry(self.addSlash(event['registry']))
        msg = None
        self.logger.error(msg)
        response['error_message'] = msg
        return response

    create_registry = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.REGISTRIES_CREATE], False, **('requested_actions', 'read_only'))(create_registry))))
    
    def _create_registry(self, registry_url, update, registry_id = (False, None)):
        valid_schema = '1.0'
        current_schema = ''
        response = { }
    # WARNING: Decompyle incomplete

    
    def update_registry(self):
        response = { }
        event = cherrypy.request.json
    # WARNING: Decompyle incomplete

    update_registry = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.REGISTRIES_MODIFY], False, **('requested_actions', 'read_only'))(update_registry))))
    
    def registry_auto_updates(self):
        response = { }
        event = cherrypy.request.json
    # WARNING: Decompyle incomplete

    registry_auto_updates = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.REGISTRIES_MODIFY], False, **('requested_actions', 'read_only'))(registry_auto_updates))))
    
    def delete_registry(self):
        response = { }
        event = cherrypy.request.json
        if 'registry_id' in event:
            self._delete_registry(event['registry_id'])
        else:
            response['error_message'] = 'Missing Registry ID'
        return response

    delete_registry = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.REGISTRIES_DELETE], False, **('requested_actions', 'read_only'))(delete_registry))))
    
    def _delete_registry(self, registry_id):
        api = cherrypy.request.db.get_registry(registry_id)
        cherrypy.request.db.delete_registry(api)

    
    def get_storage_providers(self):
        response = { }
        storage_providers = cherrypy.request.db.get_storage_providers()
        response['storage_providers'] = (lambda .0: [ cherrypy.request.db.serializable(x.jsonDict) for x in .0 ])(storage_providers)
        return response

    get_storage_providers = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.STORAGE_PROVIDERS_VIEW], True, **('requested_actions', 'read_only'))(get_storage_providers))))
    
    def create_storage_provider(self):
        response = { }
        event = cherrypy.request.json
        target_storage_provider = event.get('target_storage_provider', { })
        storage_provider_type = target_storage_provider.get('storage_provider_type')
        return response

    create_storage_provider = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.STORAGE_PROVIDERS_CREATE], **('requested_actions',))(create_storage_provider))))
    
    def update_storage_provider(self):
        response = { }
        event = cherrypy.request.json
        target_storage_provider = event.get('target_storage_provider', { })
        storage_provider_id = target_storage_provider.get('storage_provider_id')
        storage_provider_type = target_storage_provider.get('storage_provider_type')
        if storage_provider_id:
            storage_provider = cherrypy.request.db.get_storage_provider(storage_provider_id, **('storage_provider_id',))
            if storage_provider:
                for json_prop in ('scope',):
                    if json_prop in target_storage_provider or target_storage_provider[json_prop] == '':
                        target_storage_provider[json_prop] = []
                        continue
                    target_storage_provider[json_prop] = parse_multiline_input(target_storage_provider[json_prop], False, **('to_lower',))
                data = process_json_props(target_storage_provider, [
                    'auth_url_options',
                    'volume_config',
                    'mount_config'], [
                    'scope'], [], **('data', 'dict_props', 'list_props', 'not_empty_props'))
                if target_storage_provider:
                    storage_provider = cherrypy.request.db.update_storage_provider(storage_provider, target_storage_provider.get('storage_provider_type'), target_storage_provider.get('client_id'), target_storage_provider.get('client_secret'), target_storage_provider.get('auth_url'), target_storage_provider.get('token_url'), target_storage_provider.get('webdav_url'), data.get('scope'), target_storage_provider.get('redirect_url'), data.get('auth_url_options'), data.get('volume_config'), data.get('mount_config'), target_storage_provider.get('root_drive_url'), target_storage_provider.get('default_target'), target_storage_provider.get('enabled'), **('storage_provider', 'storage_provider_type', 'client_id', 'client_secret', 'auth_url', 'token_url', 'webdav_url', 'scope', 'redirect_url', 'auth_url_options', 'volume_config', 'mount_config', 'root_drive_url', 'default_target', 'enabled'))
                    response['storage_provider'] = cherrypy.request.db.serializable(storage_provider.jsonDict)
                    self.logger.info('Successfully updated storage_provider_id (%s)' % storage_provider.storage_provider_id, {
                        'storage_provider_id': storage_provider.storage_provider_id }, **('extra',))
                else:
                    msg = 'No storage provider found with id (%s)' % storage_provider_id
                    self.logger.error(msg)
                    response['error_message'] = msg
            else:
                msg = 'Invalid Request. Missing required parameters'
                self.logger.error(msg)
                response['error_message'] = msg
        return response

    update_storage_provider = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.STORAGE_PROVIDERS_MODIFY], **('requested_actions',))(update_storage_provider))))
    
    def delete_storage_provider(self):
        response = { }
        event = cherrypy.request.json
        target_storage_provider = event.get('target_storage_provider', { })
        storage_provider_id = target_storage_provider.get('storage_provider_id')
        if storage_provider_id:
            storage_provider = cherrypy.request.db.get_storage_provider(storage_provider_id, **('storage_provider_id',))
            if storage_provider:
                cherrypy.request.db.delete_storage_provider(storage_provider)
                self.logger.info('Successfully deleted storage_provider_id (%s)' % storage_provider_id, {
                    'storage_provider_id': storage_provider_id }, **('extra',))
            else:
                msg = 'No storage provider with id (%s) found' % storage_provider_id
                self.logger.error(msg)
                response['error_message'] = msg
        else:
            msg = 'Invalid Request. Missing required parameters'
            self.logger.error(msg)
            response['error_message'] = msg
        return response

    delete_storage_provider = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.STORAGE_PROVIDERS_DELETE], **('requested_actions',))(delete_storage_provider))))
    
    def get_permissions(self):
        response = { }
        response['permissions'] = []
        for permission in JWT_AUTHORIZATION:
            if int(permission) >= 100:
                response['permissions'].append({
                    'name': str(permission),
                    'permission_id': int(permission),
                    'friendly_name': permission.get_friendly_name(),
                    'description': permission.description })
                continue
                return response

    get_permissions = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.GLOBAL_ADMIN], True, **('requested_actions', 'read_only'))(get_permissions))))
    
    def add_permissions_group(self):
        return self._add_permissions_group()

    add_permissions_group = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.GLOBAL_ADMIN], False, **('requested_actions', 'read_only'))(add_permissions_group))))
    
    def _add_permissions_group(self, replace = (False,)):
        response = { }
        event = cherrypy.request.json
        target_group = event.get('target_group')
        target_api_config = event.get('target_api_config')
        target_permissions = event.get('target_permissions')
        failed_permissions_applied = 0
        if target_permissions:
            for permission_id in target_permissions:
                if not JWT_AUTHORIZATION.is_valid_value(permission_id):
                    msg = f'''The specified permission id ({permission_id}) is invalid.'''
                    self.logger.error(msg)
                    response['error_message'] = msg
                    cherrypy.response.status = 400
                    return response
                if target_group and 'group_id' in target_group and target_group['group_id'] != '' and target_permissions:
                    group = cherrypy.request.db.getGroup(target_group['group_id'])
                    if group is not None:
                        if replace:
                            for current_permission in group.permissions:
                                cherrypy.request.db.delete_group_permission(current_permission)
                        response['permissions'] = []
                        for permission_id in target_permissions:
                            permission = JWT_AUTHORIZATION(permission_id)
                            if not group.has_permission(permission):
                                gp = cherrypy.request.db.create_group_permission(permission, group.group_id, **('group_id',))
                                response['permissions'].append(cherrypy.request.db.serializable(gp.jsonDict))
                                continue
                            failed_permissions_applied += 1
                            self.logger.info(f'''The group ({target_group['group_id']}) already has the permission ({permission}).''')
                    else:
                        msg = 'The specified group does not exist.'
                        self.logger.error(msg)
                        response['error_message'] = msg
                        cherrypy.response.status = 400
                elif target_api_config and 'api_id' in target_api_config and target_permissions:
                    api = cherrypy.request.db.getApiConfig(target_api_config['api_id'])
                    if api:
                        if replace:
                            for current_permission in api.permissions:
                                cherrypy.request.db.delete_group_permission(current_permission)
                        response['permissions'] = []
                        for permission_id in target_permissions:
                            permission = JWT_AUTHORIZATION(permission_id)
                            if not api.has_permission(permission):
                                gp = cherrypy.request.db.create_group_permission(permission, api.api_id, **('api_id',))
                                response['permissions'].append(cherrypy.request.db.serializable(gp.jsonDict))
                            else:
                                failed_permissions_applied += 1
                                self.logger.info(f'''The API Config ({target_api_config['api_id']}) already has the permission ({permission}).''')
                    else:
                        msg = f'''The specified API config ({target_api_config['api_id']}) does not exist.'''
                        self.logger.error(msg)
                        response['error_message'] = msg
                        cherrypy.response.status = 400
                else:
                    msg = 'Invalid request, missing required value.'
                    self.logger.error(msg)
                    response['error_message'] = msg
                    cherrypy.response.status = 400
        if failed_permissions_applied > 0:
            response['error_message'] = f'''{len(target_permissions) - failed_permissions_applied} permissions added, {failed_permissions_applied} already part of the group.'''
        return response

    
    def replace_permissions_group(self):
        return self._add_permissions_group(True)

    replace_permissions_group = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.GLOBAL_ADMIN], False, **('requested_actions', 'read_only'))(replace_permissions_group))))
    
    def remove_permissions_group(self):
        response = { }
        event = cherrypy.request.json
        group_permission_id = event.get('group_permission_id')
        if group_permission_id:
            gp = cherrypy.request.db.get_group_permission(group_permission_id)
            if gp:
                gp = cherrypy.request.db.delete_group_permission(gp)
            else:
                msg = 'The specified permission does not exist.'
                self.logger.error(msg)
                response['error_message'] = msg
                cherrypy.response.status = 400
        else:
            msg = 'Invalid request, missing required value.'
            self.logger.error(msg)
            response['error_message'] = msg
            cherrypy.response.status = 400
        return response

    remove_permissions_group = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.GLOBAL_ADMIN], False, **('requested_actions', 'read_only'))(remove_permissions_group))))
    
    def get_permissions_group(self):
        response = { }
        event = cherrypy.request.json
        target_group = event.get('target_group')
        target_api_config = event.get('target_api_config')
        if target_group and 'group_id' in target_group and target_group['group_id'] != '':
            group = cherrypy.request.db.getGroup(target_group['group_id'])
            if group is not None:
                response['permissions'] = (lambda .0: [ cherrypy.request.db.serializable(x.jsonDict) for x in .0 if x.permission ])(group.permissions)
            elif target_api_config and 'api_id' in target_api_config:
                api = cherrypy.request.db.getApiConfig(target_api_config['api_id'])
                if api is not None:
                    response['permissions'] = (lambda .0: [ cherrypy.request.db.serializable(x.jsonDict) for x in .0 if x.permission ])(api.permissions)
        return response

    get_permissions_group = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.GLOBAL_ADMIN], True, **('requested_actions', 'read_only'))(get_permissions_group))))
    
    def get_session_recording(self):
        return self._get_session_recordings()

    get_session_recording = cherrypy.expose(cherrypy.tools.json_out()(cherrypy.tools.json_in()(Authenticated([
        JWT_AUTHORIZATION.SESSION_RECORDINGS_VIEW], True, **('requested_actions', 'read_only'))(get_session_recording))))
    
    def _get_session_recordings(self, public = (False,)):
        response = { }
        object_storage = None
        event = cherrypy.request.json
        target_kasm_id = event.get('target_kasm_id')
        preauth_download_link = event.get('preauth_download_link', False)
        page = event.get('page', 1)
        pages = 1
        per_page = 5
        total_duration = 0
        total = 0
    # WARNING: Decompyle incomplete

    
    def get_sessions_recordings(self):
        return self._get_sessions_recordings()

    get_sessions_recordings = cherrypy.expose(cherrypy.tools.json_out()(cherrypy.tools.json_in()(Authenticated([
        JWT_AUTHORIZATION.SESSION_RECORDINGS_VIEW], True, **('requested_actions', 'read_only'))(get_sessions_recordings))))
    
    def _get_sessions_recordings(self, public = (False,)):
        response = { }
        object_storage = None
        event = cherrypy.request.json
        target_kasm_ids = event.get('target_kasm_ids', [])
        preauth_download_link = event.get('preauth_download_link', False)
    # WARNING: Decompyle incomplete

    
    def get_session_history(self):
        response = { }
        event = cherrypy.request.json
        preauth_download_link = event.get('preauth_download_link', False)
        filters = event.get('filters', [])
        or_filters = event.get('or_filters', [])
        object_storage = None
        if preauth_download_link and JWT_AUTHORIZATION.is_authorized_action(cherrypy.request.authorizations, JWT_AUTHORIZATION.SESSION_RECORDINGS_VIEW):
            object_storage_key = cherrypy.request.db.get_config_setting_value('session_recording', 'recording_object_storage_key')
            object_storage_secret = cherrypy.request.db.get_config_setting_value('session_recording', 'recording_object_storage_secret')
            if object_storage_key and object_storage_secret:
                credentials = {
                    'aws_access_key_id': object_storage_key,
                    'aws_secret_access_key': object_storage_secret }
                object_storage = AwsObjectStorageProvider(cherrypy.request.db, self.logger, credentials)
        error_message = ''
    # WARNING: Decompyle incomplete

    get_session_history = cherrypy.expose(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Authenticated([
        JWT_AUTHORIZATION.SESSIONS_VIEW], True, **('requested_actions', 'read_only'))(get_session_history))))


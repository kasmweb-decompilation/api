# decompyle3 version 3.9.1
# Python bytecode version base 3.8.0 (3413)
# Decompiled from: Python 3.8.18 (default, Aug 25 2023, 13:20:30) 
# [GCC 11.4.0]
# Embedded file name: admin_api.py

from multiprocessing.sharedctypes import Value
import os, uuid, json, cherrypy, datetime, logging.config, random, string, typing, re, base64, yaml, io, pyzipper, base64, urllib.request, certifi, jwt, math
try:
    from zoneinfo import ZoneInfoNotFoundError
except ImportError:
    from backports.zoneinfo import ZoneInfoNotFoundError
else:
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
            self._db = DataAccessFactory.createSession(config["database"]["type"], config)
            self._db = DataAccessFactory.createSession(config["database"]["type"], config)
            self.logger = logging.getLogger("admin_api_server")
            self.logger.info("%s initialized" % self.__class__.__name__)
            self.provider_manager = ProviderManager(config, (self._db), logger=(self.logger))

        @cherrypy.expose
        @cherrypy.tools.json_in()
        @cherrypy.tools.json_out()
        @Authenticated(requested_actions=[JWT_AUTHORIZATION.REPORTS_VIEW], read_only=True)
        def get_report(self):
            response = {}
            event = cherrypy.request.json
            try:
                if "name" not in event:
                    raise ValueError("Request missing name field")
                report = cherrypy.request.db.getReport(name=(event["name"]))
                if "end_date" not in event or "start_date" not in event:
                    if "delta" not in event:
                        raise ValueError("The get_report API call requires a start_date and end_date or a delta parameter.")
                    if "limit" not in event or event["limit"] > 1000:
                        event["limit"] = 1000
                    if "delta" in event:
                        event["end_date"] = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d %H:%M")
                        event["start_date"] = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=(event["delta"]))).strftime("%Y%m%d %H:%M")
                    if event["name"] == "logs":
                        query = self.log_query(event)
                    else:
                        query = report.query
                    query = query.replace("$start_date", cherrypy.request.db.escape_string(event["start_date"]))
                    query = query.replace("$end_date", cherrypy.request.db.escape_string(event["end_date"]))
                    query = query.replace("$limit", cherrypy.request.db.escape_string(str(event["limit"])))
                if "filters" in event:
                    if event["name"] != "logs":
                        for key, value in event["filters"].items():
                            query = query.replace("${0}".format(key), cherrypy.request.db.escape_string(value))

                    if report.report_type == "scalar":
                        response["data"] = cherrypy.request.db.execute_native_query(query).scalar()
                if report.report_type == "table":
                    rows = cherrypy.request.db.execute_native_query(query).fetchall()
                    if len(rows) > 0:
                        response["data"] = []
                        for row in rows:
                            d_row = {}
                            for key, value in row.items():
                                d_row[key] = value if (not isinstance(value, datetime.datetime)) else (value.strftime("%Y%m%d%H%M"))

                            response["data"].append(d_row)

                elif report.report_type == "timeseries":
                    if "resolution" not in event or event["resolution"] not in (1,
                                                                                10,
                                                                                60,
                                                                                1440):
                        event["resolution"] = 10
                    query = query.replace("$resolution", str(event["resolution"]))
                    rows = cherrypy.request.db.execute_native_query(query).fetchall()
                    if len(rows) > 0:
                        if "_time" not in rows[0]:
                            raise ValueError("Invalid timeseries report query, missing _time field.")
                        response["name"] = report.name
                        response["labels"] = []
                        for key in rows[0].keys():
                            if key != "_time":
                                response[key] = []

                        for row in rows:
                            for key, value in row.items():
                                if key == "_time":
                                    response["labels"].append(value if (not isinstance(value, datetime.datetime)) else (value.strftime("%Y%m%d%H%M")))
                                else:
                                    response[key].append(value)

                if report is None:
                    raise ValueError("Report '{0}' does not exist".format(event["name"]))
            except ValueError as vex:
                try:
                    self.logger.error(str(vex))
                    response["error_message"] = str(vex)
                finally:
                    vex = None
                    del vex

            else:
                return response

        def log_query(self, event):
            query = " \n                    SELECT \n                        host, \n                        ingest_date, \n                        data->>'application' as application, \n                        levelname, \n                        data->>'funcname' as funcname, \n                        kasm_user_name, \n                        data->>'message' as message, \n                        data->>'exc_info' as traceback,\n                        data->>'error_stack' as error_stack,\n                        data->>'name' as process,\n                        data->>'request_ip' as client_ip,\n                        data->>'user_agent' as user_agent,\n                        data->>'allow' as allow,\n                        data->>'url' as url,\n                        data->>'site' as site,\n                        data->>'domain' as domain,\n                        data->>'category' as category\n                        \n                    FROM logs \n                    WHERE \n                        ingest_date < to_timestamp('$end_date', 'YYYYMMDD HH24:MI') AND\n                        ingest_date > to_timestamp('$start_date', 'YYYYMMDD HH24:MI')\t  \n                "
            if "filters" in event:
                for (key, value) in event["filters"].items():
                    if key == "process":
                        query += " AND data->>'name' LIKE '%" + cherrypy.request.db.escape_string(value) + "%'"
                    elif key == "search":
                        query += " AND LOWER(data->>'message') LIKE LOWER('%" + cherrypy.request.db.escape_string(value) + "%')"
                    elif key == "application":
                        query += " AND LOWER(data->>'application') LIKE LOWER('%" + cherrypy.request.db.escape_string(value) + "%')"
                    elif key == "searchUser":
                        query += " AND LOWER(kasm_user_name) LIKE LOWER('%" + cherrypy.request.db.escape_string(value) + "%')"
                    elif key == "metricName":
                        query += " AND LOWER(metric_name) LIKE LOWER('%" + cherrypy.request.db.escape_string(value) + "%')"
                    elif key == "allowed":
                        query += " AND LOWER(data->>'allow') LIKE LOWER('%" + cherrypy.request.db.escape_string(value) + "%')"
                    elif key == "category":
                        query += " AND LOWER(data->>'category') LIKE LOWER('%" + cherrypy.request.db.escape_string(value) + "%')"
                    elif key == "site":
                        query += " AND LOWER(data->>'site') LIKE LOWER('%" + cherrypy.request.db.escape_string(value) + "%')"
                    else:
                        if key == "levelname":
                            query += " AND (" + cherrypy.request.db.escape_string(key) + " = '" + cherrypy.request.db.escape_string(value) + "'"
                            if value == "DEBUG":
                                query += " OR " + cherrypy.request.db.escape_string(key) + " = '" + "INFO" + "'"
                                query += " OR " + cherrypy.request.db.escape_string(key) + " = '" + "WARNING" + "'"
                                query += " OR " + cherrypy.request.db.escape_string(key) + " = '" + "ERROR" + "'"
                                query += " OR " + cherrypy.request.db.escape_string(key) + " = '" + "CRITICAL" + "')"
                            if value == "INFO":
                                query += " OR " + cherrypy.request.db.escape_string(key) + " = '" + "WARNING" + "'"
                                query += " OR " + cherrypy.request.db.escape_string(key) + " = '" + "ERROR" + "'"
                                query += " OR " + cherrypy.request.db.escape_string(key) + " = '" + "CRITICAL" + "')"
                            if value == "WARNING":
                                query += " OR " + cherrypy.request.db.escape_string(key) + " = '" + "ERROR" + "'"
                                query += " OR " + cherrypy.request.db.escape_string(key) + " = '" + "CRITICAL" + "')"
                            if value == "ERROR":
                                query += " OR " + cherrypy.request.db.escape_string(key) + " = '" + "CRITICAL" + "')"
                            if not value == "CRITICAL":
                                query += ")"
                            query += " AND " + cherrypy.request.db.escape_string(key) + " = '" + cherrypy.request.db.escape_string(value) + "'"

                if "exclude_filters" in event:
                    for (key, value) in event["exclude_filters"].items():
                        if key == "metricName":
                            query += " AND (metric_name is NULL or LOWER(metric_name) NOT LIKE LOWER('%" + cherrypy.request.db.escape_string(value) + "%'))"

                query += " ORDER BY ingest_date DESC LIMIT $limit"
                return query

        @cherrypy.expose
        @cherrypy.tools.json_in()
        @cherrypy.tools.json_out()
        @Authenticated(requested_actions=[JWT_AUTHORIZATION.REPORTS_VIEW], read_only=True)
        def get_alert_report(self):
            response = {}
            return response

        @cherrypy.expose
        @cherrypy.tools.json_in()
        @cherrypy.tools.json_out()
        @Authenticated(requested_actions=[JWT_AUTHORIZATION.REPORTS_VIEW], read_only=True)
        def get_distinct_hosts(self):
            response = {}
            query = "SELECT  DISTINCT host FROM logs"
            rows = cherrypy.request.db.execute_native_query(query).fetchall()
            if len(rows) > 0:
                response["data"] = []
                for row in rows:
                    d_row = {}
                    for (key, value) in row.items():
                        d_row[key] = value

                    response["data"].append(d_row)

                return response

        @cherrypy.expose
        @cherrypy.tools.json_in()
        @cherrypy.tools.json_out()
        @Authenticated(requested_actions=[JWT_AUTHORIZATION.REPORTS_VIEW], read_only=True)
        def get_agent_report(self):
            response = {}
            event = cherrypy.request.json
            agents = []
            servers = self._get_servers()
            for server in servers["servers"]:
                if not server.get("last_reported"):
                    pass
                else:
                    agent = {}
                    agent["name"] = server["hostname"]
                    agent["disk_space"] = server["disk_stats"]["total"]
                    agent["disk_space_used"] = server["disk_stats"]["used"]
                    agent["disk_space_free"] = server["disk_stats"]["free"]
                    agent["memory_total"] = server["memory_stats"]["total"]
                    agent["memory_used"] = server["memory_stats"]["used"]
                    agent["memory_free"] = server["memory_stats"]["available"]
                    agent["kasms"] = len(server["kasms"])
                    agent["server_id"] = server["server_id"]
                    if agent["disk_space_used"] / agent["disk_space"] > 0.85:
                        agent["health"] = "Disk Warning"
                    if agent["memory_used"] / agent["memory_total"] > 0.9:
                        agent["health"] = "Memory Warning"
                    if "health" not in agent:
                        agent["health"] = "Healthy"
                    agents.append(agent)
                response["agents"] = agents
                return response

        @cherrypy.expose
        @cherrypy.tools.json_in()
        @cherrypy.tools.json_out()
        @Authenticated(requested_actions=[JWT_AUTHORIZATION.GROUPS_VIEW, JWT_AUTHORIZATION.GROUPS_VIEW_IFMEMBER, JWT_AUTHORIZATION.GROUPS_VIEW_SYSTEM], read_only=True)
        def get_groups(self):
            response = {}
            groups = cherrypy.request.db.getGroups()
            if groups:
                f_groups = []
                for group in groups:
                    if JWT_AUTHORIZATION.is_user_authorized_action((cherrypy.request.authenticated_user), (cherrypy.request.authorizations), (JWT_AUTHORIZATION.GROUPS_VIEW), target_group=group):
                        group_mappings = []
                        for group_mapping in group.group_mappings:
                            group_mappings.append(group_mapping.jsonDict)

                        f_groups.append({'group_id':group.group_id, 
                         'name':group.name, 
                         'description':group.description, 
                         'priority':group.priority, 
                         'is_system':group.is_system, 
                         'group_metadata':group.group_metadata, 
                         'group_mappings':group_mappings})
                    response["groups"] = cherrypy.request.db.serializable(f_groups)

                return response

        @cherrypy.expose
        @cherrypy.tools.json_in()
        @cherrypy.tools.json_out()
        @Authenticated(requested_actions=[JWT_AUTHORIZATION.GROUPS_CREATE], read_only=False)
        def create_group(self):
            response = {}
            event = cherrypy.request.json
            if "target_group" in event:
                target_group = event["target_group"]
                if "name" in target_group and "priority" in target_group:
                    existing_group = [x for x in cherrypy.request.db.getGroups() if x.name == target_group["name"]]
                    if not existing_group:
                        pri = int(target_group["priority"])
                        if pri > 0 and pri < 4096:
                            new_group = cherrypy.request.db.createGroup(name=(target_group["name"]),
                              description=(target_group.get("description")),
                              priority=(target_group["priority"]),
                              group_metadata=(target_group.get("group_metadata")))
                            self.logger.info("Created Group (%s) - (%s)" % (new_group.group_id, new_group.name))
                            response["group_mappings"] = []
                            if "group_mappings" in target_group:
                                for group_mapping in target_group("group_mappings"):
                                    group_mapping_retrieved = cherrypy.request.db.createGroupMapping(group_id=(group_mapping.get("group_id")),
                                      ldap_id=(group_mapping.get("ldap_id")),
                                      saml_id=(group_mapping.get("saml_id")),
                                      oidc_id=(group_mapping.get("oidc_id")),
                                      sso_group_attributes=(group_mapping.get("sso_group_attributes")),
                                      apply_to_all_users=(group_mapping.get("apply_to_all_users")))
                                    response["group_mappings"].append(group_mapping_retrieved.jsonDict)

                            response["group"] = cherrypy.request.db.serializable(new_group.jsonDict)
                        else:
                            msg = "Invalid priority value (%s)" % target_group.get("priority")
                            self.logger.error(msg)
                            response["error_message"] = msg
                    else:
                        msg = "Group (%s) already exists" % target_group.get("name")
                        self.logger.error(msg)
                        response["error_message"] = msg
                else:
                    msg = "Invalid Request. Missing required parameters"
                    self.logger.error(msg)
                    response["error_message"] = msg
            else:
                msg = "Invalid Request. Missing required parameters"
                self.logger.error(msg)
                response["error_message"] = msg
            return response

        @cherrypy.expose
        @cherrypy.tools.json_in()
        @cherrypy.tools.json_out()
        @Authenticated(requested_actions=[JWT_AUTHORIZATION.GROUPS_MODIFY, JWT_AUTHORIZATION.GROUPS_MODIFY_IFMEMBER, JWT_AUTHORIZATION.GROUPS_MODIFY_SYSTEM], read_only=False)
        def update_group(self):
            response = {}
            event = cherrypy.request.json
            if "target_group" in event:
                target_group = event["target_group"]
                group_id = target_group.get("group_id")
                if group_id:
                    try:
                        group_id = uuid.UUID(group_id)
                    except:
                        group_id = None

                    if group_id:
                        group = cherrypy.request.db.getGroup(group_id)
                        if group:
                            if JWT_AUTHORIZATION.is_user_authorized_action((cherrypy.request.authenticated_user), (cherrypy.request.authorizations), (JWT_AUTHORIZATION.GROUPS_MODIFY), target_group=group):
                                updated_group = cherrypy.request.db.update_group(group, name=(target_group.get("name")),
                                  description=(target_group.get("description")),
                                  priority=(target_group.get("priority")),
                                  group_metadata=(target_group.get("group_metadata")))
                                self.logger.info("Updated Group (%s) - (%s)" % (updated_group.group_id,
                                 updated_group.name))
                                response["group_mappings"] = []
                                if "group_mappings" in target_group:
                                    for group_mapping in target_group("group_mappings"):
                                        group_mapping_retrieved = cherrypy.request.db.getGroupMapping(sso_group_id=(group_mapping["sso_group_id"]))
                                        if group_mapping_retrieved:
                                            group_mapping_retrieved = cherrypy.request.db.updateGroupMappin(group_mapping=group_mapping_retrieved,
                                              ldap_id=(group_mapping.get("ldap_id")),
                                              saml_id=(group_mapping.get("saml_id")),
                                              oidc_id=(group_mapping.get("oidc_id")),
                                              sso_group_attributes=(group_mapping.get("sso_group_attributes")),
                                              apply_to_all_users=(group_mapping.get("apply_to_all_users")))
                                        else:
                                            group_mapping_retrieved = cherrypy.request.db.createGroupMappin(group_id=(group_mapping.get("group_id")),
                                              ldap_id=(group_mapping.get("ldap_id")),
                                              saml_id=(group_mapping.get("saml_id")),
                                              oidc_id=(group_mapping.get("oidc_id")),
                                              sso_group_attributes=(group_mapping.get("sso_group_attributes")),
                                              apply_to_all_users=(group_mapping.get("apply_to_all_users")))

                                    response["group_mappings"].append(group_mapping_retrieved.jsonDict)
                                response["group"] = cherrypy.request.db.serializable(updated_group.jsonDict)
                            else:
                                msg = "User not authorized to modify the target group."
                                cherrypy.response.status = 401
                                self.logger.warning(msg)
                                response["error_message"] = msg
                        else:
                            msg = "Invalid Request. group does not exit by that id"
                            self.logger.error(msg)
                            response["error_message"] = msg
                    else:
                        msg = "Invalid Request. group_id must be a uuid"
                        self.logger.error(msg)
                        response["error_message"] = msg
                else:
                    msg = "Invalid Request. Missing required parameters"
                    self.logger.error(msg)
                    response["error_message"] = msg
            else:
                msg = "Invalid Request. Missing required parameters"
                self.logger.error(msg)
                response["error_message"] = msg
            return response

        @cherrypy.expose
        @cherrypy.tools.json_in()
        @cherrypy.tools.json_out()
        @Authenticated(requested_actions=[JWT_AUTHORIZATION.GROUPS_DELETE], read_only=False)
        def delete_group(self):
            response = {}
            event = cherrypy.request.json
            force = False
            if "force" in event:
                if isinstance(event["force"], bool):
                    force = event["force"]
                else:
                    msg = "Invalid Request. 'force' option must be boolean"
                    self.logger.error(msg)
                    response["error_message"] = msg
                    return response
            if "target_group" in event and "group_id" in event["target_group"]:
                target_group = event["target_group"]
                group = cherrypy.request.db.getGroup(target_group["group_id"])
                if group:
                    if group.is_system:
                        msg = "Group (%s) is a protected group and cannot be deleted" % group.name
                        self.logger.error(msg)
                        response["error_message"] = msg
                    elif group.cast_configs:
                        configs = ",".join([str(x.cast_config_id) for x in group.cast_configs])
                        msg = "Group (%s) is referenced in Cast configuration (%s) and cannot be deleted" % (group.name,
                         configs)
                        self.logger.error(msg)
                        response["error_message"] = msg
                    elif force:
                        cherrypy.request.db.delete_group(group)
                    else:
                        num_users = len(group.users.all())
                        if num_users > 0:
                            msg = "Group contains (%s) users and 'force' option not set to True" % num_users
                            self.logger.error(msg)
                            response["error_message"] = msg
                        else:
                            cherrypy.request.db.delete_group(group)
                else:
                    msg = "Group %s does not exist" % target_group.get("group_id")
                    self.logger.error(msg)
                    response["error_message"] = msg
            else:
                msg = "Invalid Request: Missing required parameters"
                self.logger.error(msg)
                response["error_message"] = msg
            return response

        @cherrypy.expose
        @cherrypy.tools.json_in()
        @cherrypy.tools.json_out()
        @Authenticated(requested_actions=[JWT_AUTHORIZATION.GROUPS_MODIFY, JWT_AUTHORIZATION.GROUPS_MODIFY_IFMEMBER, JWT_AUTHORIZATION.GROUPS_MODIFY_SYSTEM], read_only=False)
        def add_user_group(self):
            return self._add_user_group()

        def _add_user_group(self, public=False):
            response = {}
            event = cherrypy.request.json
            target_user = event.get("target_user")
            target_group = event.get("target_group")
            if target_userand "user_id" in target_user and "user_id" in target_user and "group_id" in target_group:
                group = cherrypy.request.db.getGroup(event["target_group"]["group_id"])
                user = cherrypy.request.db.get_user_by_id(event["target_user"]["user_id"])
                if user is None:
                    msg = "Invalid User ID (%s)" % event["target_user"]["user_id"]
                    self.logger.error(msg)
                    response["error_message"] = msg
                    if public:
                        cherrypy.response.status = 400
                elif group is None:
                    msg = "Invalid Group ID (%s)" % event["target_group"]["group_id"]
                    self.logger.error(msg)
                    response["error_message"] = msg
                    if public:
                        cherrypy.response.status = 400
                elif len([g for g in user.groups if g.group_id == group.group_id]) > 0:
                    msg = "User (%s) is already a member of group (%s)" % (event["target_user"]["user_id"],
                     event["target_group"]["group_id"])
                    self.logger.error(msg)
                    response["error_message"] = msg
                    if public:
                        cherrypy.response.status = 400
                elif JWT_AUTHORIZATION.is_user_authorized_action((cherrypy.request.authenticated_user), (cherrypy.request.authorizations), (JWT_AUTHORIZATION.GROUPS_MODIFY), target_group=group):
                    cherrypy.request.db.addUserGroup(user, group)
                    self.logger.info("Added user (%s) to group (%s)" % (user.username, group.name))
                else:
                    msg = f"User ({cherrypy.request.kasm_user_id}) made unauthorized attempt to modify group ({group.name})"
                    self.logger.warning(msg)
                    response["error_message"] = "Unauthorized"
                    cherrypy.response.status = 401
            else:
                msg = "Invalid Request: Missing required parameters"
                self.logger.error(msg)
                response["error_message"] = msg
                if public:
                    cherrypy.response.status = 400
            return response

        @cherrypy.expose
        @cherrypy.tools.json_in()
        @cherrypy.tools.json_out()
        @Authenticated(requested_actions=[JWT_AUTHORIZATION.GROUPS_MODIFY, JWT_AUTHORIZATION.GROUPS_MODIFY_IFMEMBER, JWT_AUTHORIZATION.GROUPS_MODIFY_SYSTEM], read_only=False)
        def remove_user_group(self):
            return self._remove_user_group()

        def _remove_user_group(self, public=False):
            response = {}
            event = cherrypy.request.json
            target_user = event.get("target_user")
            target_group = event.get("target_group")
            if target_userand "user_id" in target_user and "user_id" in target_user and "group_id" in target_group:
                group = cherrypy.request.db.getGroup(event["target_group"]["group_id"])
                user = cherrypy.request.db.get_user_by_id(event["target_user"]["user_id"])
                if user is None:
                    msg = "Invalid User ID (%s)" % event["target_user"]["user_id"]
                    self.logger.error(msg)
                    response["error_message"] = msg
                    if public:
                        cherrypy.response.status = 400
                elif group is None:
                    msg = "Invalid Group ID (%s)" % event["target_group"]["group_id"]
                    self.logger.error(msg)
                    response["error_message"] = msg
                    if public:
                        cherrypy.response.status = 400
                elif group not in [x.group for x in user.groups]:
                    msg = "User (%s) is not a member of group (%s)" % (event["target_user"]["user_id"],
                     event["target_group"]["group_id"])
                    self.logger.error(msg)
                    response["error_message"] = msg
                    if public:
                        cherrypy.response.status = 400
                elif JWT_AUTHORIZATION.is_user_authorized_action((cherrypy.request.authenticated_user), (cherrypy.request.authorizations), (JWT_AUTHORIZATION.GROUPS_MODIFY), target_group=group):
                    cherrypy.request.db.removeUserGroup(user, group)
                    self.logger.info("Removed user (%s) from group (%s)" % (user.username, group.name))
                else:
                    msg = f"User ({cherrypy.request.kasm_user_id}) made unauthorized attempt to modify group ({group.name})"
                    self.logger.warning(msg)
                    response["error_message"] = "Unauthorized"
                    cherrypy.response.status = 401
            else:
                msg = "Invalid Request: Missing required parameters"
                self.logger.error(msg)
                response["error_message"] = msg
                if public:
                    cherrypy.response.status = 400
            return response

        @cherrypy.expose
        @cherrypy.tools.json_in()
        @cherrypy.tools.json_out()
        @Authenticated(requested_actions=[JWT_AUTHORIZATION.GROUPS_VIEW, JWT_AUTHORIZATION.GROUPS_VIEW_IFMEMBER, JWT_AUTHORIZATION.GROUPS_VIEW_SYSTEM], read_only=True)
        def get_users_group(self):
            response = {}
            event = cherrypy.request.json
            target_group = event.get("target_group")
            if target_group and "group_id" in target_group:
                group = cherrypy.request.db.getGroup(event["target_group"]["group_id"])
                if group is not None:
                    if JWT_AUTHORIZATION.is_user_authorized_action((cherrypy.request.authenticated_user), (cherrypy.request.authorizations), (JWT_AUTHORIZATION.GROUPS_VIEW), target_group=group):
                        users = group.get_users(page=(event["page"] if "page" in event else None),
                          page_size=(event["page_size"] if "page_size" in event else None),
                          filters=(event["filters"] if "filters" in event else []),
                          sort_by=(event["sort_by"] if "sort_by" in event else None),
                          sort_direction=(event["sort_direction"] if "sort_direction" in event else "desc"))
                        response["users"] = cherrypy.request.db.serializable(users["users"])
                        response["total"] = cherrypy.request.db.serializable(users["total"])
                    else:
                        msg = f"User ({cherrypy.request.kasm_user_id}) made unauthorized attempt to view a group ({group.name})"
                        self.logger.warning(msg)
                        response["error_message"] = "Unauthorized"
                        cherrypy.response.status = 401
                else:
                    msg = "Invalid Group ID (%s)" % event["target_group"]["group_id"]
                    self.logger.error(msg)
                    response["error_message"] = msg
            else:
                msg = "Invalid Request: Missing required parameters"
                self.logger.error(msg)
                response["error_message"] = msg
            return response

        @cherrypy.expose
        @cherrypy.tools.json_in()
        @cherrypy.tools.json_out()
        @Authenticated(requested_actions=[JWT_AUTHORIZATION.USERS_VIEW], read_only=True)
        def get_user_groups_settings(self):
            response = {}
            event = cherrypy.request.json
            try:
                if "target_user" not in event:
                    raise ValueError("Missing 'target_user' parameter")
                target_user = event["target_user"]
                if "username" not in target_user:
                    raise ValueError("Missing 'target_user.username' parameter")
                username = target_user["username"]
                user = cherrypy.request.db.getUser(username)
                if not user:
                    raise ValueError("No user '{}' found".format(username))
                settings = cherrypy.request.db.getDefaultGroupSettings()
                for setting in settings:
                    setting.value = user.get_setting_value(setting.name, setting.value)

                response["settings"] = [cherrypy.request.db.serializable(x.jsonDict) for x in settings]
            except ValueError as error:
                try:
                    msg = "Invalid Request: " + str(error)
                    self.logger.error(msg)
                    response["error_message"] = msg
                finally:
                    error = None
                    del error

            else:
                return response

        @cherrypy.expose
        @cherrypy.tools.json_in()
        @cherrypy.tools.json_out()
        @Authenticated(requested_actions=[JWT_AUTHORIZATION.GROUPS_VIEW, JWT_AUTHORIZATION.GROUPS_VIEW_IFMEMBER, JWT_AUTHORIZATION.GROUPS_VIEW_SYSTEM], read_only=True)
        def get_settings_group(self):
            response = {}
            event = cherrypy.request.json
            target_group = event.get("target_group")
            if target_group and "group_id" in target_group and target_group["group_id"] != "":
                group = cherrypy.request.db.getGroup(event["target_group"]["group_id"])
                if group is not None:
                    if JWT_AUTHORIZATION.is_user_authorized_action((cherrypy.request.authenticated_user), (cherrypy.request.authorizations), (JWT_AUTHORIZATION.GROUPS_VIEW), target_group=group):
                        response["settings"] = [cherrypy.request.db.serializable(x.jsonDict) for x in group.settings]
                    else:
                        msg = f"User ({cherrypy.request.kasm_user_id}) made unauthorized attempt to view group ({group.name}) settings."
                        self.logger.warning(msg)
                        response["error_message"] = "Unauthorized"
                        cherrypy.response.status = 401
            else:
                default_settings = cherrypy.request.db.getDefaultGroupSettings()
                response["settings"] = [cherrypy.request.db.serializable(x.jsonDict) for x in default_settings]
            return response

        @cherrypy.expose
        @cherrypy.tools.json_in()
        @cherrypy.tools.json_out()
        @Authenticated(requested_actions=[JWT_AUTHORIZATION.GROUPS_MODIFY, JWT_AUTHORIZATION.GROUPS_MODIFY_IFMEMBER, JWT_AUTHORIZATION.GROUPS_MODIFY_SYSTEM], read_only=False)
        def add_settings_groupParse error at or near `JUMP_FORWARD' instruction at offset 1056

        @cherrypy.expose
        @cherrypy.tools.json_in()
        @cherrypy.tools.json_out()
        @Authenticated(requested_actions=[JWT_AUTHORIZATION.GROUPS_MODIFY, JWT_AUTHORIZATION.GROUPS_MODIFY_IFMEMBER, JWT_AUTHORIZATION.GROUPS_MODIFY_SYSTEM], read_only=False)
        def update_settings_groupParse error at or near `JUMP_FORWARD' instruction at offset 1014

        @cherrypy.expose
        @cherrypy.tools.json_in()
        @cherrypy.tools.json_out()
        @Authenticated(requested_actions=[JWT_AUTHORIZATION.GROUPS_MODIFY, JWT_AUTHORIZATION.GROUPS_MODIFY_IFMEMBER, JWT_AUTHORIZATION.GROUPS_MODIFY_SYSTEM], read_only=False)
        def remove_settings_groupParse error at or near `RETURN_VALUE' instruction at offset 198

        @cherrypy.expose
        @cherrypy.tools.json_in()
        @cherrypy.tools.json_out()
        @Authenticated(requested_actions=[JWT_AUTHORIZATION.IMAGES_VIEW], read_only=True)
        def get_images(self):
            _images = []
            images = cherrypy.request.db.getImages(only_enabled=False)
            for x in images:
                _image = cherrypy.request.db.serializable(x.jsonDict)
                _image["server"] = {}
                if x.server:
                    _image["server"]["hostname"] = x.server.hostname
                _image["server_pool"] = {}
                if x.server_pool:
                    _image["server_pool"]["server_pool_name"] = x.server_pool.server_pool_name
                _images.append(_image)

            return {"images": _images}

        @cherrypy.expose
        @cherrypy.tools.json_in()
        @cherrypy.tools.json_out()
        @Authenticated(requested_actions=[JWT_AUTHORIZATION.USERS_VIEW, JWT_AUTHORIZATION.IMAGES_VIEW], read_only=True)
        def get_user_images(self):
            response = {}
            event = cherrypy.request.json
            try:
                if "target_user" not in event:
                    raise ValueError("Missing 'target_user' parameter")
                target_user = event["target_user"]
                if "username" not in target_user:
                    raise ValueError("Missing 'target_user.username' parameter")
                username = target_user["username"]
                user = cherrypy.request.db.getUser(username)
                if not user:
                    raise ValueError("User '{}' not found".format(username))
                result = []
                if JWT_AUTHORIZATION.all_authorized_actions(cherrypy.request.authorizations, [JWT_AUTHORIZATION.IMAGES_VIEW, JWT_AUTHORIZATION.USERS_VIEW]):
                    images = self._get_user_images(user)
                    for image_id in images.keys():
                        images[image_id]["image_id"] = image_id
                        result.append(images[image_id])

                response["images"] = cherrypy.request.db.serializable(result)
            except ValueError as error:
                try:
                    msg = "Invalid Request: " + str(error)
                    self.logger.error(msg)
                    response["error_message"] = msg
                finally:
                    error = None
                    del error

            else:
                return response

        @cherrypy.expose
        @cherrypy.tools.json_in()
        @cherrypy.tools.json_out()
        @Authenticated(requested_actions=[JWT_AUTHORIZATION.GROUPS_VIEW, JWT_AUTHORIZATION.GROUPS_VIEW_IFMEMBER, JWT_AUTHORIZATION.GROUPS_VIEW_SYSTEM], read_only=True)
        def get_images_groupParse error at or near `RETURN_VALUE' instruction at offset 232

        @cherrypy.expose
        @cherrypy.tools.json_in()
        @cherrypy.tools.json_out()
        @Authenticated(requested_actions=[JWT_AUTHORIZATION.GROUPS_MODIFY, JWT_AUTHORIZATION.GROUPS_MODIFY_IFMEMBER, JWT_AUTHORIZATION.GROUPS_MODIFY_SYSTEM], read_only=False)
        def add_images_group(self):
            response = {}
            event = cherrypy.request.json
            target_group = event.get("target_group")
            target_image = event.get("target_image")
            if target_groupand "group_id" in target_group and "group_id" in target_group and "image_id" in target_image:
                group = cherrypy.request.db.getGroup(event["target_group"]["group_id"])
                image = cherrypy.request.db.getImage(event["target_image"]["image_id"])
                if JWT_AUTHORIZATION.is_user_authorized_action((cherrypy.request.authenticated_user), (cherrypy.request.authorizations), (JWT_AUTHORIZATION.GROUPS_MODIFY), target_group=group):
                    cherrypy.request.db.addImageGroup(image, group)
                else:
                    msg = f"User ({cherrypy.request.kasm_user_id}) made unauthorized attempt to modify a group's ({group.name}) images."
                    self.logger.warning(msg)
                    response["error_message"] = "Unauthorized"
                    cherrypy.response.status = 401
            else:
                msg = "Invalid request, missing group or image id"
                self.logger.error(msg)
                response["error_message"] = msg
            return response

        @cherrypy.expose
        @cherrypy.tools.json_in()
        @cherrypy.tools.json_out()
        @Authenticated(requested_actions=[JWT_AUTHORIZATION.GROUPS_MODIFY, JWT_AUTHORIZATION.GROUPS_MODIFY_IFMEMBER, JWT_AUTHORIZATION.GROUPS_MODIFY_SYSTEM], read_only=False)
        def remove_images_group(self):
            response = {}
            event = cherrypy.request.json
            target_group = event.get("target_group")
            target_image = event.get("target_image")
            if target_groupand "group_id" in target_group and "group_id" in target_group and "image_id" in target_image:
                group = cherrypy.request.db.getGroup(event["target_group"]["group_id"])
                image = cherrypy.request.db.getImage(event["target_image"]["image_id"])
                if group and image:
                    if JWT_AUTHORIZATION.is_user_authorized_action((cherrypy.request.authenticated_user), (cherrypy.request.authorizations), (JWT_AUTHORIZATION.GROUPS_MODIFY), target_group=group):
                        cherrypy.request.db.removeImageGroup(image, group)
                    else:
                        msg = f"User ({cherrypy.request.kasm_user_id}) made unauthorized attempt to remove a group's ({group.name}) image."
                        self.logger.warning(msg)
                        response["error_message"] = "Unauthorized"
                        cherrypy.response.status = 401
                else:
                    msg = "Group or image does not exist"
                    self.logger.error(msg)
                    response["error_message"] = msg
            else:
                msg = "Invalid request, missing group or image id"
                self.logger.error(msg)
                response["error_message"] = msg
            return response

        @cherrypy.expose
        @cherrypy.tools.json_in()
        @cherrypy.tools.json_out()
        @Authenticated(requested_actions=[JWT_AUTHORIZATION.USERS_VIEW], read_only=True)
        def get_users(self):
            response = {}
            request = cherrypy.request.json
            users = cherrypy.request.db.getUsers(include_anonymous=(request["anonymous"] if "anonymous" in request else False),
              only_anonymous=(request["anonymous_only"] if "anonymous_only" in request else False),
              page=(request["page"] if "page" in request else None),
              page_size=(request["page_size"] if "page_size" in request else None),
              filters=(request["filters"] if "filters" in request else []),
              sort_by=(request["sort_by"] if "sort_by" in request else None),
              sort_direction=(request["sort_direction"] if "sort_direction" in request else "desc"))
            user_count = cherrypy.request.db.getUserCount(include_anonymous=(request["anonymous"] if "anonymous" in request else False),
              only_anonymous=(request["anonymous_only"] if "anonymous_only" in request else False),
              filters=(request["filters"] if "filters" in request else []))
            if users:
                f_users = []
                for user in users:
                    kasms = []
                    if JWT_AUTHORIZATION.is_authorized_action(cherrypy.request.authorizations, JWT_AUTHORIZATION.SESSIONS_VIEW):
                        for kasm in user.kasms:
                            kasms.append({'kasm_id':kasm.kasm_id, 
                             'start_date':kasm.start_date, 
                             'keepalive_date':kasm.keepalive_date, 
                             'expiration_date':kasm.expiration_date, 
                             'server':{'server_id':kasm.server.server_id if (kasm.image.is_container) and (kasm.server) else None, 
                              'hostname':kasm.server.hostname if (kasm.image.is_container) and (kasm.server) else None, 
                              'port':kasm.server.port if (kasm.image.is_container) and (kasm.server) else None}})

                        groups = []
                        if JWT_AUTHORIZATION.is_authorized_action(cherrypy.request.authorizations, JWT_AUTHORIZATION.GROUPS_VIEW):
                            groups = user.get_groups()
                        company = None
                        if JWT_AUTHORIZATION.is_authorized_action(cherrypy.request.authorizations, JWT_AUTHORIZATION.COMPANIES_VIEW):
                            company = user.company
                        f_users.append({'user_id':str(user.user_id), 
                         'username':user.username, 
                         'anonymous':user.anonymous, 
                         'locked':user.locked, 
                         'disabled':user.disabled, 
                         'last_session':str(user.last_session), 
                         'groups':groups, 
                         'first_name':user.first_name, 
                         'last_name':user.last_name, 
                         'phone':user.phone, 
                         'organization':user.organization, 
                         'notes':user.notes, 
                         'kasms':kasms, 
                         'realm':user.realm, 
                         'company':cherrypy.request.db.serializable(company.jsonDict) if company else {}, 
                         'created':user.created})
                    response["users"] = cherrypy.request.db.serializable(f_users)
                    response["total"] = user_count

                if "page" in request:
                    response["page"] = request["page"] if request["page"] >= 0 else 0
                return response

        @cherrypy.expose
        @cherrypy.tools.json_in()
        @cherrypy.tools.json_out()
        @Authenticated(requested_actions=[JWT_AUTHORIZATION.USERS_AUTH_SESSION], read_only=False)
        def logout_user(self):
            return self._logout_user()

        def _logout_user(self, public=False):
            response = {}
            event = cherrypy.request.json
            if "target_user" in event:
                target_user = event["target_user"]
                if "user_id" in target_user:
                    user = None
                    try:
                        user_id = uuid.UUID(target_user["user_id"])
                        user = cherrypy.request.db.get_user_by_id(user_id)
                    except ValueError:
                        self.logger.error(f'user_id ({target_user["user_id"]}) in logout_user not UUID')
                    except Exception as e:
                        try:
                            self.logger.exception(f'Exception getting user by id for user {target_user["user_id"]} during logout_user {e}')
                        finally:
                            e = None
                            del e

                    if user:
                        try:
                            cherrypy.request.db.remove_expired_session_tokens(user)
                            if user.session_tokens:
                                self.logger.debug(f'Logging out all sessions for user {target_user["user_id"]}')
                                cherrypy.request.db.remove_all_session_tokens(user)
                            else:
                                self.logger.debug(f'No sessions to logout for user {target_user["user_id"]}')
                        except Exception as e:
                            try:
                                self.logger.exception("Exception logging out user (%s) token during logout_user %s" % (event["username"], e))
                                response["error_message"] = "Logout Error"
                                if public:
                                    cherrypy.response.status = 400
                            finally:
                                e = None
                                del e

                    else:
                        msg = "Unknown user (%s)" % target_user["user_id"]
                        self.logger.error(msg)
                        response["error_message"] = msg
                        if public:
                            cherrypy.response.status = 400
                else:
                    msg = "Invalid Request: Missing required user_id"
                    self.logger.error(msg)
                    response["error_message"] = msg
                    if public:
                        cherrypy.response.status = 400
            else:
                msg = "Invalid Request: Missing required target_user"
                self.logger.error(msg)
                response["error_message"] = msg
                if public:
                    cherrypy.response.status = 400
            return response

        @cherrypy.expose
        @cherrypy.tools.json_in()
        @cherrypy.tools.json_out()
        @Authenticated(requested_actions=[JWT_AUTHORIZATION.USERS_DELETE], read_only=False)
        def delete_user(self):
            return self._delete_user()

        def _delete_user(self, public=False):
            response = {}
            event = cherrypy.request.json
            force = False
            if "force" in event:
                if isinstance(event["force"], bool):
                    force = event["force"]
                else:
                    msg = "Invalid Request. 'force' option must be boolean"
                    self.logger.error(msg)
                    response["error_message"] = msg
                    return response
            if "target_user" in event:
                target_user = event["target_user"]
                if "user_id" in target_user:
                    user = cherrypy.request.db.get_user_by_id(target_user["user_id"])
                    if user:
                        if JWT_AUTHORIZATION.is_user_authorized_action((cherrypy.request.authenticated_user), (cherrypy.request.authorizations), (JWT_AUTHORIZATION.USERS_DELETE), target_user=user):
                            num_kasms = len(user.kasms)
                            if num_kasms > 0 and not force:
                                msg = "Users contains (%s) kasms and 'force' option not set to True" % num_kasms
                                self.logger.error(msg)
                                response["error_message"] = msg
                                if public:
                                    cherrypy.response.status = 400
                            elif len(user.kasms) == 0 or JWT_AUTHORIZATION.is_authorized_action(cherrypy.request.authorizations, JWT_AUTHORIZATION.SESSIONS_DELETE):
                                for kasm in user.kasms:
                                    try:
                                        self.provider_manager.destroy_kasm(kasm, "admin_destroyed")
                                    except Exception as e:
                                        try:
                                            self.logger.exception("Exception during user (%s) destroy : %s" % (event["username"], e))
                                        finally:
                                            e = None
                                            del e

                                cherrypy.request.db.deleteUser(user)
                                self.logger.debug("Deleting User ID (%s)" % target_user["user_id"])
                            else:
                                if cherrypy.request.is_api:
                                    msg = f"API Key ({cherrypy.request.api_key_name}) unauthorized for deleting the requested user ({user.username}) sessions."
                                else:
                                    msg = f"User ({cherrypy.request.kasm_user_name}) unauthorized for deleting the requested user's ({user.username}) sessions."
                                self.logger.warning(msg)
                                response["error_message"] = msg
                                cherrypy.response.status = 401
                        else:
                            if cherrypy.request.is_api:
                                msg = f"API Key ({cherrypy.request.api_key_name}) unauthorized for deleting the requested user ({user.username})."
                            else:
                                msg = f"User ({cherrypy.request.kasm_user_name}) unauthorized for deleting the requested user ({user.username})."
                            self.logger.warning(msg)
                            response["error_message"] = msg
                            cherrypy.response.status = 401
                    else:
                        msg = "Unknown user (%s)" % target_user["user_id"]
                        self.logger.error(msg)
                        response["error_message"] = msg
                        if public:
                            cherrypy.response.status = 400
                else:
                    msg = "Invalid Request: Missing required parameters"
                    self.logger.error(msg)
                    response["error_message"] = msg
                    if public:
                        cherrypy.response.status = 400
            else:
                msg = "Invalid Request: Missing required parameters"
                self.logger.error(msg)
                response["error_message"] = msg
                if public:
                    cherrypy.response.status = 400
            return response

        @cherrypy.expose
        @cherrypy.tools.json_in()
        @cherrypy.tools.json_out()
        @Authenticated(requested_actions=[JWT_AUTHORIZATION.USERS_CREATE], read_only=False)
        def create_user(self):
            return self._create_user()

        def _create_user(self, public=False):
            response = {}
            event = cherrypy.request.json
            if "target_user" in event:
                target_user = event["target_user"]
                if "username" in target_user:
                    password = target_user.get("password")
                    if not password:
                        if public:
                            password = uuid.uuid4().hex
                    if password:
                        if not target_user.get("company_id") or cherrypy.request.db.getCompany(company_id=(target_user["company_id"])):
                            group = None
                            if target_user.get("program_id"):
                                group = cherrypy.request.db.getGroup(program_id=(target_user["program_id"]))
                            if not target_user.get("program_id") or group:
                                license_helper = LicenseHelper(cherrypy.request.db, self.logger)
                                if license_helper.is_per_named_user_ok(with_user_added=True):
                                    try:
                                        user = cherrypy.request.db.createUser(username=(target_user["username"]), password=password,
                                          first_name=(target_user.get("first_name")),
                                          last_name=(target_user.get("last_name")),
                                          phone=(target_user.get("phone")),
                                          organization=(target_user.get("organization")),
                                          notes=(target_user.get("notes")),
                                          locked=(target_user.get("locked")),
                                          disabled=(target_user.get("disabled")),
                                          company_id=(target_user.get("company_id")),
                                          group=group,
                                          program_id=(target_user.get("program_id")),
                                          realm=(target_user.get("realm")),
                                          oidc_id=(target_user.get("oidc_id")),
                                          saml_id=(target_user.get("saml_id")),
                                          password_set_date=(datetime.datetime.utcnow()))
                                    except ValueError as e:
                                        msg = "Error creating user (%s): (%s)" % (target_user.get("username"), e)
                                        self.logger.error(msg)
                                        response["error_message"] = msg
                                        if public:
                                            cherrypy.response.status = 400
                                        return response
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
                                        self.logger.info("Create New User (%s)" % user.username)
                                else:
                                    msg = "License limit exceeded. Unable to create user"
                                    self.logger.error(msg)
                                    response["error_message"] = msg
                                    if public:
                                        cherrypy.response.status = 403
                            else:
                                msg = "Unknown program_id (%s)" % target_user.get("program_id")
                                self.logger.error(msg)
                                response["error_message"] = msg
                                if public:
                                    cherrypy.response.status = 400
                        else:
                            msg = "Invalid Request: Company does not exist"
                            self.logger.error(msg)
                            response["error_message"] = msg
                            if public:
                                cherrypy.response.status = 400
                    else:
                        msg = "Invalid Request: Missing required parameters"
                        self.logger.error(msg)
                        response["error_message"] = msg
                        if public:
                            cherrypy.response.status = 400
                else:
                    msg = "Invalid Request: Missing required parameters"
                    self.logger.error(msg)
                    response["error_message"] = msg
                    if public:
                        cherrypy.response.status = 400
            else:
                msg = "Invalid Request: Missing required parameters"
                self.logger.error(msg)
                response["error_message"] = msg
                if public:
                    cherrypy.response.status = 400
            return response

        @cherrypy.expose
        @cherrypy.tools.json_in()
        @cherrypy.tools.json_out()
        @Authenticated(requested_actions=[JWT_AUTHORIZATION.SETTINGS_VIEW], read_only=True)
        def get_settings(self):
            response = {"settings": [cherrypy.request.db.serializable(x.jsonDict) for x in cherrypy.request.db.get_config_settings(sanitize=True)]}
            response["settings"] = sorted((response["settings"]), key=(lambda s: (s["category"], s["name"])))
            return response

        @cherrypy.expose
        @cherrypy.tools.json_in()
        @cherrypy.tools.json_out()
        @Authenticated(requested_actions=[JWT_AUTHORIZATION.SETTINGS_MODIFY_CAST, JWT_AUTHORIZATION.SETTINGS_MODIFY_AUTH, JWT_AUTHORIZATION.SETTINGS_MODIFY_FILTER,
         JWT_AUTHORIZATION.SETTINGS_MODIFY_IMAGES, JWT_AUTHORIZATION.SETTINGS_MODIFY_LICENSE, JWT_AUTHORIZATION.SETTINGS_MODIFY_LOGGING,
         JWT_AUTHORIZATION.SETTINGS_MODIFY_MANAGER, JWT_AUTHORIZATION.SETTINGS_MODIFY_SCALE, JWT_AUTHORIZATION.SETTINGS_MODIFY_STORAGE,
         JWT_AUTHORIZATION.SETTINGS_MODIFY_SUBSCRIPTION, JWT_AUTHORIZATION.SETTINGS_MODIFY_CONNECTIONS, JWT_AUTHORIZATION.SETTINGS_MODIFY],
          read_only=False)
        def update_setting(self):
            response = {}
            event = cherrypy.request.json
            if "setting_id" in event and "value" in event:
                setting = cherrypy.request.db.get_config_setting_by_id(event["setting_id"])
                if setting:
                    license_ok = False
                    if setting.name in ('notice_message', 'notice_title', 'hec_token',
                                        'log_protocol'):
                        license_helper = LicenseHelper(cherrypy.request.db, self.logger)
                        if setting.name in ('notice_message', 'notice_title'):
                            license_ok = license_helper.is_login_banner_ok()
                        elif setting.name == "hec_token":
                            license_ok = license_helper.is_login_banner_ok()
                        elif setting.name == "log_protocol" and event["value"] in ('splunk',
                                                                                   'elasticsearch'):
                            license_ok = license_helper.is_login_banner_ok()
                        else:
                            license_ok = True
                    else:
                        license_ok = True
                    if JWT_AUTHORIZATION.is_user_authorized_action((cherrypy.request.authenticated_user), (cherrypy.request.authorizations), (JWT_AUTHORIZATION.SETTINGS_MODIFY), target_setting=setting):
                        if not license_ok:
                            msg = "Access Denied. Setting (%s) is not licensed" % setting.title
                            self.logger.error(msg)
                            response["error_message"] = msg
                        else:
                            value_type = setting.__dict__["value_type"]
                            if value_type == "int":
                                try:
                                    event["value"].isdigit()
                                    if int(event["value"]) < 0:
                                        raise ValueError
                                    cherrypy.request.db.update_config_setting(event["setting_id"], event["value"])
                                except Exception:
                                    msg = "Value Error: Invalid Type"
                                    self.logger.error(msg)
                                    response["error_message"] = msg
                                    return response

                            elif value_type == "float":
                                try:
                                    event["value"].isdigit()
                                    if float(event["value"]) < 0:
                                        raise ValueError
                                    cherrypy.request.db.update_config_setting(event["setting_id"], event["value"])
                                except Exception:
                                    msg = "Value Error: Invalid Type"
                                    self.logger.error(msg)
                                    response["error_message"] = msg
                                    return response

                            elif value_type == "json" or value_type == "json_pass":
                                try:
                                    json.loads(event["value"])
                                    cherrypy.request.db.update_config_setting(event["setting_id"], event["value"])
                                except Exception:
                                    msg = "Value Error: Invalid JSON"
                                    self.logger.error(msg)
                                    response["error_message"] = msg
                                    return response

                            else:
                                if is_sanitized(event["value"]):
                                    msg = "Value Error: Invalid Entry"
                                    self.logger.error(msg)
                                    response["error_message"] = msg
                                    return response
                                cherrypy.request.db.update_config_setting(event["setting_id"], event["value"])
                    else:
                        msg = f"User ({cherrypy.request.kasm_user_name}) is not authorized to make changes to this setting ({setting.name})"
                        self.logger.warning(msg)
                        response["error_message"] = msg
                        cherrypy.response.status = 401
                else:
                    msg = "Invalid Request: No setting found with id (%s)" % event["setting_id"]
                    self.logger.error(msg)
                    response["error_message"] = msg
            else:
                msg = "Invalid Request: Missing required parameters"
                self.logger.error(msg)
                response["error_message"] = msg
            return response

        @cherrypy.expose
        @cherrypy.tools.json_in()
        @cherrypy.tools.json_out()
        @Authenticated(requested_actions=[JWT_AUTHORIZATION.SESSIONS_VIEW], read_only=True)
        def get_kasms(self):
            response = {"kasms": []}
            kasms = cherrypy.request.db.get_kasms()
            if kasms:
                for kasm in kasms:
                    d = self.get_normalized_kasm(kasm)
                    d["user"] = {"username": (kasm.user.username if kasm.user else "")}
                    if kasm.server:
                        _zone_name = kasm.server.zone.zone_name if kasm.server.zone else ""
                        if kasm.operational_status in (
                         SESSION_OPERATIONAL_STATUS.REQUESTED.value,
                         SESSION_OPERATIONAL_STATUS.PROVISIONING.value,
                         SESSION_OPERATIONAL_STATUS.ASSIGNED.value):
                            hostname = None
                            port = None
                            provider = None
                        else:
                            hostname = kasm.server.hostname if kasm.image.is_container else kasm.server.zone.proxy_hostname
                            port = kasm.server.port if kasm.image.is_container else kasm.server.zone.proxy_port
                            provider = kasm.server.provider if kasm.image.is_container else kasm.image.image_type
                        d["server"] = {
                          'hostname': hostname,
                          'port': port,
                          'provider': provider,
                          'zone_name': _zone_name}
                        response["kasms"].append(d)
                        response["current_time"] = str(datetime.datetime.utcnow())

                return response

        @cherrypy.expose
        @cherrypy.tools.json_in()
        @cherrypy.tools.json_out()
        @Authenticated(requested_actions=[JWT_AUTHORIZATION.SESSIONS_VIEW], read_only=True)
        def get_kasm(self):
            response = {}
            event = cherrypy.request.json
            if "target_kasm" in event:
                kasm_id = event["target_kasm"].get("kasm_id")
                if kasm_id:
                    try:
                        kasm_id = uuid.UUID(kasm_id)
                    except:
                        kasm_id = None

                    if kasm_id:
                        kasm = cherrypy.request.db.getKasm(kasm_id)
                        if kasm:
                            d = self.get_normalized_kasm(kasm)
                            d["user"] = {"username": (kasm.user.username if kasm.user else "")}
                            d["server"] = {'hostname':kasm.server.hostname if (kasm.server) else None, 
                             'port':kasm.server.port if (kasm.server) else None, 
                             'provider':kasm.server.provider if (kasm.server) else None, 
                             'zone_name':kasm.server.manager.zone.zone_name if kasm.server and kasm.server.manager and (kasm.server.manager.zone) else ""}
                            response["kasm"] = d
                            response["current_time"] = str(datetime.datetime.utcnow())
                    else:
                        msg = "Invalid Request. Invalid kasm_id"
                        self.logger.error(msg)
                        response["error_message"] = msg
                else:
                    msg = "Invalid Request. Missing kasm_id"
                    self.logger.error(msg)
                    response["error_message"] = msg
            else:
                msg = "Invalid Request. Missing target_kasm"
                self.logger.error(msg)
                response["error_message"] = msg
            return response

        @cherrypy.expose
        @cherrypy.tools.json_in()
        @cherrypy.tools.json_out()
        @Authenticated(requested_actions=[JWT_AUTHORIZATION.IMAGES_MODIFY, JWT_AUTHORIZATION.IMAGES_MODIFY_RESOURCES], read_only=False)
        def update_imageParse error at or near `ROT_TWO' instruction at offset 284

        @cherrypy.expose
        @cherrypy.tools.json_in()
        @cherrypy.tools.json_out()
        @Authenticated(requested_actions=[JWT_AUTHORIZATION.IMAGES_CREATE], read_only=False)
        def create_imageParse error at or near `ROT_TWO' instruction at offset 148

        @cherrypy.expose
        @cherrypy.tools.json_in()
        @cherrypy.tools.json_out()
        @Authenticated(requested_actions=[JWT_AUTHORIZATION.IMAGES_CREATE])
        def create_image_from_session(self):
            response = {}
            event = cherrypy.request.json
            target_kasm = event.get("target_kasm", {})
            kasm_id = target_kasm.get("kasm_id")
            docker_image = target_kasm.get("docker_image")
            author = target_kasm.get("author")
            message = target_kasm.get("message")
            changes = target_kasm.get("changes")
            registry_url = target_kasm.get("registry_url")
            registry_username = target_kasm.get("registry_username")
            registry_password = target_kasm.get("registry_password")
            if kasm_id and docker_image:
                (registry, repository, tag) = parse_docker_image(docker_image)
                if registry:
                    repository = registry + "/" + repository
                kasm = cherrypy.request.db.getKasm(kasm_id)
                if kasm:
                    kasm.operational_status = SESSION_OPERATIONAL_STATUS.SAVING.value
                    cherrypy.request.db.updateKasm(kasm)
                    new_image = cherrypy.request.db.clone_image(kasm.image)
                    (res, err) = self.provider_manager.commit_kasm(kasm, repository, tag, author, message, changes, registry_url, registry_username, registry_password)
                    if res:
                        new_image.friendly_name = "Snapshot of " + new_image.friendly_name + " - (%s)" % tag
                        new_image.available = False
                        new_image.name = docker_image
                        new_image.docker_registry = registry_url
                        new_image.docker_user = registry_username
                        new_image.docker_token = registry_password
                        new_image.persistent_profile_path = None
                        new_image = cherrypy.request.db.createImage(new_image, install=False)
                        response["image"] = cherrypy.request.db.serializable(new_image.jsonDict)
                        self.logger.info("Successfully created image (%s:%s) from kasm_id (%s)" % (repository,
                         tag,
                         str(kasm.kasm_id)))
                    else:
                        msg = "Error creating image (%s:%s) from kasm_id (%s) : %s" % (repository,
                         tag,
                         str(kasm.kasm_id),
                         err)
                        response["error_message"] = err
                        self.logger.error(msg)
                        return response
                else:
                    msg = "Kasm (%s) Does not Exist" % kasm_id
                    self.logger.error(msg)
                    response["error_message"] = msg
            else:
                msg = "Invalid Request: Missing required parameters"
                self.logger.error(msg)
                response["error_message"] = msg
            return response

        @cherrypy.expose
        @cherrypy.tools.json_in()
        @cherrypy.tools.json_out()
        @Authenticated(requested_actions=[JWT_AUTHORIZATION.IMAGES_DELETE], read_only=False)
        def delete_imageParse error at or near `RETURN_VALUE' instruction at offset 242

        @cherrypy.expose
        @cherrypy.tools.json_in()
        @cherrypy.tools.json_out()
        @Authenticated(requested_actions=[JWT_AUTHORIZATION.SERVERS_VIEW, JWT_AUTHORIZATION.AGENTS_VIEW], read_only=True)
        def get_servers(self):
            event = cherrypy.request.json
            target_server = event.get("target_server")
            server_id = target_server["server_id"] if target_server else None
            servers = self._get_servers(server_id)["servers"]
            response = {"servers": []}
            for server in servers:
                server_type = SERVER_TYPE(server["server_type"])
                if server_type == SERVER_TYPE.HOST:
                    if not JWT_AUTHORIZATION.is_authorized_action(cherrypy.request.authorizations, JWT_AUTHORIZATION.AGENTS_VIEW):
                        response["servers"].append(server)
                    if JWT_AUTHORIZATION.is_authorized_action(cherrypy.request.authorizations, JWT_AUTHORIZATION.SERVERS_VIEW):
                        response["servers"].append(server)
                return response

        def _get_servers(self, server_id=None):
            response = {"servers": []}
            servers = cherrypy.request.db.getServers(manager_id=None, server_id=server_id)
            if servers:
                priv_key = str.encode(self._db.get_config_setting_value("auth", "api_private_key"))
                for server in servers:
                    d = cherrypy.request.db.serializable(server.jsonDict)
                    d["autoscale_config"] = {'autoscale_config_id':server.autoscale_config_id, 
                     'autoscale_config_name':server.autoscale_config.autoscale_config_name if (server.autoscale_config) else None}
                    d["zone"] = {'zone_id':server.zone_id, 
                     'zone_name':server.zone.zone_name if (server.zone) else None}
                    if server_id:
                        d["registration_jwt"] = generate_jwt_token({"server_id": (str(server.server_id))}, [JWT_AUTHORIZATION.SERVER_AGENT], priv_key, expires_days=3650)
                    d["kasms"] = []
                    for kasm in server.kasms:
                        d["kasms"].append({'kasm_id':kasm.kasm_id, 
                         'start_date':kasm.start_date, 
                         'keepalive_date':kasm.keepalive_date, 
                         'user':{'username':kasm.user.username if (kasm.user) else "", 
                          'user_id':kasm.user.user_id if (kasm.user) else ""}})

                    response["servers"].append(d)

                return cherrypy.request.db.serializable(response)

        @cherrypy.expose
        @cherrypy.tools.json_in()
        @cherrypy.tools.json_out()
        @Authenticated(requested_actions=[JWT_AUTHORIZATION.SERVERS_CREATE, JWT_AUTHORIZATION.AGENTS_CREATE], read_only=False)
        def create_server(self):
            response = {}
            event = cherrypy.request.json
            target_server = event.get("target_server")
            if target_server:
                if target_server.get("connection_private_key"):
                    ssh_private_key = target_server.get("connection_private_key")
                    passphrase = target_server.get("connection_passphrase")
                    passphrase = passphrase.encode("utf-8") if passphrase else None
                    try:
                        if not passphrase:
                            private_key = serialization.load_pem_private_key((ssh_private_key.encode("utf-8")), password=passphrase, unsafe_skip_rsa_key_validation=False)
                            target_server["connection_private_key"] = private_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()).decode("utf-8")
                    except Exception as e:
                        msg = f"Error processing SSH Private Key: {e}"
                        self.logger.exception(msg)
                        response["error_message"] = msg
                        return response

                target_server_type = target_server.get("server_type")
                if target_server_type and target_server_type == SERVER_TYPE.HOST and JWT_AUTHORIZATION.is_authorized_action(cherrypy.request.authorizations, JWT_AUTHORIZATION.AGENTS_CREATE) or target_server_type == SERVER_TYPE.DESKTOP and JWT_AUTHORIZATION.is_authorized_action(cherrypy.request.authorizations, JWT_AUTHORIZATION.SERVERS_CREATE):
                    data = process_json_props(data=target_server, dict_props=[
                     "connection_info"],
                      list_props=[],
                      not_empty_props=[])
                    agent_installed = target_server.get("agent_installed", False)
                    operational_status = SESSION_OPERATIONAL_STATUS.RUNNING.value if (not agent_installed) else (SESSION_OPERATIONAL_STATUS.STARTING.value)
                    cherrypy.request.db.create_server(server_type=(target_server.get("server_type")),
                      enabled=(target_server.get("enabled")),
                      hostname=(target_server.get("hostname")),
                      friendly_name=(target_server.get("friendly_name")),
                      connection_type=(target_server.get("connection_type")),
                      connection_port=(target_server.get("connection_port")),
                      connection_info=(data.get("connection_info")),
                      connection_username=(target_server.get("connection_username")),
                      connection_password=(target_server.get("connection_password")),
                      max_simultaneous_sessions=(target_server.get("max_simultaneous_sessions")),
                      zone_id=(target_server.get("zone_id")),
                      server_pool_id=(target_server.get("server_pool_id")),
                      connection_private_key=(target_server.get("connection_private_key")),
                      connection_passphrase=(target_server.get("connection_passphrase")),
                      use_user_private_key=(target_server.get("use_user_private_key", False)),
                      agent_installed=agent_installed,
                      operational_status=operational_status)
                else:
                    self.logger.error(f"User ({cherrypy.request.kasm_user_id}) is not authorized to create a server of type ({target_server_type}).")
                    response["error_message"] = "Unauthorized Action"
                    cherrypy.response.status = 401
            else:
                msg = "Invalid Request: Missing required parameters"
                self.logger.error(msg)
                response["error_message"] = msg
            return response

        @cherrypy.expose
        @cherrypy.tools.json_in()
        @cherrypy.tools.json_out()
        @Authenticated(requested_actions=[JWT_AUTHORIZATION.SERVERS_MODIFY, JWT_AUTHORIZATION.AGENTS_MODIFY], read_only=False)
        def update_server(self):
            response = {}
            event = cherrypy.request.json
            target_server = event.get("target_server")
            if target_server:
                server_id = target_server.get("server_id")
                if server_id:
                    server = cherrypy.request.db.getServer(server_id)
                    if server:
                        if target_server:
                            if target_server.get("connection_private_key") and not is_sanitized(target_server.get("connection_private_key")):
                                ssh_private_key = target_server.get("connection_private_key")
                                passphrase = target_server.get("connection_passphrase")
                                passphrase = passphrase.encode("utf-8") if passphrase else None
                                try:
                                    if not passphrase:
                                        private_key = serialization.load_pem_private_key((ssh_private_key.encode("utf-8")), password=passphrase, unsafe_skip_rsa_key_validation=False)
                                        target_server["connection_private_key"] = private_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()).decode("utf-8")
                                except Exception as e:
                                    msg = f"Error processing SSH Private Key: {e}"
                                    self.logger.exception(msg)
                                    response["error_message"] = msg
                                    return response

                        data = process_json_props(data=target_server, dict_props=[
                         "connection_info"],
                          list_props=[],
                          not_empty_props=[])
                        target_server_type = target_server.get("server_type")
                        if target_server_type and target_server_type == SERVER_TYPE.HOST and JWT_AUTHORIZATION.is_authorized_action(cherrypy.request.authorizations, JWT_AUTHORIZATION.AGENTS_MODIFY) or target_server_type == SERVER_TYPE.DESKTOP and JWT_AUTHORIZATION.is_authorized_action(cherrypy.request.authorizations, JWT_AUTHORIZATION.SERVERS_MODIFY):
                            _updated_server = cherrypy.request.db.update_server(server=server,
                              server_type=(target_server.get("server_type")),
                              enabled=(target_server.get("enabled")),
                              hostname=(target_server.get("hostname")),
                              friendly_name=(target_server.get("friendly_name")),
                              connection_type=(target_server.get("connection_type")),
                              connection_port=(target_server.get("connection_port")),
                              connection_info=(data.get("connection_info")),
                              connection_username=(target_server.get("connection_username")),
                              connection_password=(target_server.get("connection_password")),
                              max_simultaneous_sessions=(target_server.get("max_simultaneous_sessions")),
                              zone_id=(target_server.get("zone_id")),
                              server_pool_id=(target_server.get("server_pool_id")),
                              cores_override=(target_server.get("cores_override")),
                              memory_override=(target_server.get("memory_override")),
                              gpus_override=(target_server.get("gpus_override")),
                              prune_images_mode=(target_server.get("prune_images_mode")),
                              connection_private_key=(target_server.get("connection_private_key")),
                              connection_passphrase=(target_server.get("connection_passphrase")),
                              use_user_private_key=(target_server.get("use_user_private_key", False)),
                              agent_installed=(target_server.get("agent_installed", False)))
                            response["server"] = cherrypy.request.db.serializable(_updated_server.jsonDict)
                        else:
                            self.logger.error(f"User ({cherrypy.request.kasm_user_id}) is not authorized to update a server of type ({target_server_type}).")
                            response["error_message"] = "Unauthorized Action"
                            cherrypy.response.status = 401
                    else:
                        msg = "Server (%s) Does not Exist" % server_id
                        self.logger.error(msg)
                        response["error_message"] = msg
                else:
                    msg = "Invalid Request: Missing required parameters"
                    self.logger.error(msg)
                    response["error_message"] = msg
            else:
                msg = "Invalid Request: Missing required parameters"
                self.logger.error(msg)
                response["error_message"] = msg
            return response

        @cherrypy.expose
        @cherrypy.tools.json_in()
        @cherrypy.tools.json_out()
        @Authenticated(requested_actions=[JWT_AUTHORIZATION.SERVERS_DELETE], read_only=False)
        def delete_server(self):
            response = {}
            event = cherrypy.request.json
            force = False
            if "force" in event:
                if isinstance(event["force"], bool):
                    force = event["force"]
                else:
                    msg = "Invalid Request. 'force' option must be boolean"
                    self.logger.error(msg)
                    response["error_message"] = msg
                    return response
            target_server = event.get("target_server")
            if target_server:
                server_id = target_server.get("server_id")
                if server_id:
                    server = cherrypy.request.db.getServer(server_id)
                    if server:
                        num_kasms = len(server.kasms)
                        if num_kasms > 0 and not force:
                            msg = "Server contains (%s) kasms and 'force' option not set to True" % num_kasms
                            self.logger.error(msg)
                            response["error_message"] = msg
                        elif num_kasms > 0 and not JWT_AUTHORIZATION.is_authorized_action(cherrypy.request.authorizations, JWT_AUTHORIZATION.SESSIONS_DELETE):
                            self.logger.error(f"Server has user sessions, but the user ({cherrypy.request.kasm_user_id}) is not authorized to delete user sessions.")
                            response["error_message"] = "Unauthorized to delete user sessions."
                            response["ui_show_error"] = True
                        else:
                            server.operational_status = SERVER_OPERATIONAL_STATUS.DELETE_PENDING.value
                            cherrypy.request.db.updateServer(server)
                    else:
                        msg = "Server (%s) Does not Exist" % server_id
                        self.logger.error(msg)
                        response["error_message"] = msg
                else:
                    msg = "Invalid Request: Missing required parameters"
                    self.logger.error(msg)
                    response["error_message"] = msg
            else:
                msg = "Invalid Request: Missing required parameters"
                self.logger.error(msg)
                response["error_message"] = msg
            return response

        @cherrypy.expose
        @cherrypy.tools.json_in()
        @cherrypy.tools.json_out()
        @Authenticated(requested_actions=[JWT_AUTHORIZATION.SESSIONS_DELETE], read_only=False)
        def destroy_agent_kasmsParse error at or near `RETURN_VALUE' instruction at offset 174

        @cherrypy.expose
        @cherrypy.tools.json_in()
        @cherrypy.tools.json_out()
        @Authenticated(requested_actions=[JWT_AUTHORIZATION.AUTH_CREATE], read_only=False)
        def set_saml_config(self):
            response = {}
            license_helper = LicenseHelper(cherrypy.request.db, self.logger)
            if license_helper.is_sso_ok():
                event = cherrypy.request.json
                target_saml_config = event.get("target_saml_config")
                if target_saml_config:
                    config = cherrypy.request.db.set_saml_config(strict=True,
                      debug=False,
                      auto_login=False,
                      enabled=(target_saml_config.get("enabled")),
                      adfs=(target_saml_config.get("adfs")),
                      group_attribute=(target_saml_config.get("group_attribute")),
                      is_default=(target_saml_config.get("is_default")),
                      hostname=(target_saml_config.get("hostname")),
                      display_name=(target_saml_config.get("display_name")),
                      sp_entity_id=(target_saml_config.get("sp_entity_id")),
                      sp_acs_url=(target_saml_config.get("sp_acs_url")),
                      sp_slo_url=(target_saml_config.get("sp_slo_url")),
                      sp_name_id=(target_saml_config.get("sp_name_id")),
                      sp_x509_cert=(target_saml_config.get("sp_x509_cert")),
                      sp_private_key=(target_saml_config.get("sp_private_key")),
                      idp_entity_id=(target_saml_config.get("idp_entity_id")),
                      idp_sso_url=(target_saml_config.get("idp_sso_url")),
                      idp_slo_url=(target_saml_config.get("idp_slo_url")),
                      idp_x509_cert=(target_saml_config.get("idp_x509_cert")),
                      want_attribute_statement=True,
                      name_id_encrypted=False,
                      authn_request_signed=False,
                      logout_request_signed=False,
                      logout_response_signed=False,
                      sign_metadata=False,
                      want_messages_signed=False,
                      want_assertions_signed=True,
                      want_name_id=True,
                      want_name_id_encrypted=False,
                      want_assertions_encrypted=False,
                      signature_algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1",
                      digest_algorithm="http://www.w3.org/2000/09/xmldsig#sha1",
                      logo_url=(target_saml_config.get("logo_url")))
                    response["saml_config"] = cherrypy.request.db.serializable(config.jsonDict)
                    self.logger.info("Created SAML Config (%s)" % config.saml_id)
                else:
                    msg = "Invalid Request. Missing target_saml_config"
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
        @Authenticated(requested_actions=[JWT_AUTHORIZATION.AUTH_MODIFY], read_only=False)
        def update_saml_config(self):
            response = {}
            license_helper = LicenseHelper(cherrypy.request.db, self.logger)
            if license_helper.is_sso_ok():
                event = cherrypy.request.json
                target_saml_config = event.get("target_saml_config")
                if target_saml_config:
                    if "saml_id" in target_saml_config:
                        saml_config = cherrypy.request.db.get_saml_config(target_saml_config["saml_id"])
                        if saml_config:
                            if "security" in target_saml_config:
                                if target_saml_config["security"] == "":
                                    target_saml_config["security"] = {}
                                else:
                                    try:
                                        target_saml_config["security"] = json.loads(target_saml_config["security"])
                                    except Exception as e:
                                        msg = "Invalid json format for security json"
                                        self.logger.error(msg)
                                        response["error_message"] = msg
                                        return response

                            config = cherrypy.request.db.update_saml_config(saml_config=saml_config,
                              strict=True,
                              debug=(target_saml_config.get("debug")),
                              auto_login=(target_saml_config.get("auto_login")),
                              group_attribute=(target_saml_config.get("group_attribute")),
                              enabled=(target_saml_config.get("enabled")),
                              adfs=(target_saml_config.get("adfs")),
                              is_default=(target_saml_config.get("is_default")),
                              hostname=(target_saml_config.get("hostname")),
                              display_name=(target_saml_config.get("display_name")),
                              sp_entity_id=(target_saml_config.get("sp_entity_id")),
                              sp_acs_url=(target_saml_config.get("sp_acs_url")),
                              sp_slo_url=(target_saml_config.get("sp_slo_url")),
                              sp_name_id=(target_saml_config.get("sp_name_id")),
                              sp_x509_cert=(target_saml_config.get("sp_x509_cert")),
                              sp_private_key=(target_saml_config.get("sp_private_key")),
                              idp_entity_id=(target_saml_config.get("idp_entity_id")),
                              idp_sso_url=(target_saml_config.get("idp_sso_url")),
                              idp_slo_url=(target_saml_config.get("idp_slo_url")),
                              idp_x509_cert=(target_saml_config.get("idp_x509_cert")),
                              want_attribute_statement=(target_saml_config.get("want_attribute_statement")),
                              name_id_encrypted=(target_saml_config.get("name_id_encrypted")),
                              authn_request_signed=(target_saml_config.get("authn_request_signed")),
                              logout_request_signed=(target_saml_config.get("logout_request_signed")),
                              logout_response_signed=(target_saml_config.get("logout_response_signed")),
                              sign_metadata=(target_saml_config.get("sign_metadata")),
                              want_messages_signed=(target_saml_config.get("want_messages_signed")),
                              want_assertions_signed=(target_saml_config.get("want_assertions_signed")),
                              want_name_id=(target_saml_config.get("want_name_id")),
                              want_name_id_encrypted=(target_saml_config.get("want_name_id_encrypted")),
                              want_assertions_encrypted=(target_saml_config.get("want_assertions_encrypted")),
                              signature_algorithm=(target_saml_config.get("signature_algorithm")),
                              digest_algorithm=(target_saml_config.get("digest_algorithm")),
                              logo_url=(target_saml_config.get("logo_url")))
                            response["saml_config"] = cherrypy.request.db.serializable(config.jsonDict)
                        else:
                            msg = "SAML config (%s) does not exist" % target_saml_config.get("saml_id")
                            self.logger.error(msg)
                            response["error_message"] = msg
                    else:
                        msg = "Invalid Request. Missing saml_id"
                        self.logger.error(msg)
                        response["error_message"] = msg
                else:
                    msg = "Invalid Request. Missing target_saml_config"
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
        @Authenticated(requested_actions=[JWT_AUTHORIZATION.AUTH_DELETE], read_only=False)
        def delete_saml_configParse error at or near `RETURN_VALUE' instruction at offset 160

        @cherrypy.expose
        @cherrypy.tools.json_in()
        @cherrypy.tools.json_out()
        @Authenticated(requested_actions=[JWT_AUTHORIZATION.AUTH_VIEW], read_only=True)
        def get_saml_configParse error at or near `RETURN_VALUE' instruction at offset 166

        @cherrypy.expose
        @cherrypy.tools.json_in()
        @cherrypy.tools.json_out()
        @Authenticated(requested_actions=[JWT_AUTHORIZATION.AUTH_VIEW], read_only=True)
        def get_saml_configs(self):
            response = {}
            configs = cherrypy.request.db.get_saml_configs()
            if configs:
                response["saml_configs"] = [cherrypy.request.db.serializable(x.jsonDict) for x in configs]
            else:
                response["error_message"] = "No SAML configurations"
            return response

        @cherrypy.expose
        @cherrypy.tools.json_in()
        @cherrypy.tools.json_out()
        @Authenticated(requested_actions=[JWT_AUTHORIZATION.AUTH_VIEW], read_only=True)
        def get_ldap_configs(self):
            response = {}
            configs = cherrypy.request.db.get_ldap_configs()
            response["ldap_configs"] = [cherrypy.request.db.serializable(x.jsonDict) for x in configs]
            return response

        @cherrypy.expose
        @cherrypy.tools.json_in()
        @cherrypy.tools.json_out()
        @Authenticated(requested_actions=[JWT_AUTHORIZATION.AUTH_VIEW], read_only=True)
        def get_ldap_configParse error at or near `RETURN_VALUE' instruction at offset 166

        @cherrypy.expose
        @cherrypy.tools.json_in()
        @cherrypy.tools.json_out()
        @Authenticated(requested_actions=[JWT_AUTHORIZATION.AUTH_CREATE], read_only=False)
        def create_ldap_config(self):
            response = {}
            license_helper = LicenseHelper(cherrypy.request.db, self.logger)
            if license_helper.is_sso_ok():
                event = cherrypy.request.json
                target_ldap_config = event.get("target_ldap_config")
                if target_ldap_config:
                    missing_args = []
                    required_values = [
                     "name","enabled","url","auto_create_app_user","search_base","search_filter",
                     "group_membership_filter"]
                    for x in required_values:
                        if x not in target_ldap_config:
                            missing_args.append(x)

                    if missing_args:
                        msg = "Invalid Request. Missing required argument(s): (%s)" % str(missing_args)
                        self.logger.warning(msg)
                        response["error_message"] = msg
                    else:
                        config = cherrypy.request.db.create_ldap_config(name=(target_ldap_config.get("name")),
                          enabled=(target_ldap_config.get("enabled")),
                          url=(target_ldap_config.get("url")),
                          auto_create_app_user=(target_ldap_config.get("auto_create_app_user")),
                          search_base=(target_ldap_config.get("search_base")),
                          search_filter=(target_ldap_config.get("search_filter")),
                          email_attribute=(target_ldap_config.get("email_attribute")),
                          search_subtree=(target_ldap_config.get("search_subtree")),
                          service_account_dn=(target_ldap_config.get("service_account_dn")),
                          service_account_password=(target_ldap_config.get("service_account_password")),
                          connection_timeout=(target_ldap_config.get("connection_timeout")),
                          group_membership_filter=(target_ldap_config.get("group_membership_filter")),
                          username_domain_match=(target_ldap_config.get("username_domain_match")))
                        response["ldap_config"] = cherrypy.request.db.serializable(config.jsonDict)
                else:
                    msg = "Invalid Request. Missing target_ldap_config"
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
        @Authenticated(requested_actions=[JWT_AUTHORIZATION.AUTH_MODIFY], read_only=False)
        def update_ldap_config(self):
            response = {}
            license_helper = LicenseHelper(cherrypy.request.db, self.logger)
            if license_helper.is_sso_ok():
                event = cherrypy.request.json
                target_ldap_config = event.get("target_ldap_config")
                if target_ldap_config:
                    if "ldap_id" in target_ldap_config:
                        ldap_config = cherrypy.request.db.get_ldap_config(target_ldap_config["ldap_id"])
                        if ldap_config:
                            config = cherrypy.request.db.update_ldap_config(ldap_config=ldap_config,
                              name=(target_ldap_config.get("name")),
                              enabled=(target_ldap_config.get("enabled")),
                              url=(target_ldap_config.get("url")),
                              auto_create_app_user=(target_ldap_config.get("auto_create_app_user")),
                              search_base=(target_ldap_config.get("search_base")),
                              search_filter=(target_ldap_config.get("search_filter")),
                              email_attribute=(target_ldap_config.get("email_attribute")),
                              search_subtree=(target_ldap_config.get("search_subtree")),
                              service_account_dn=(target_ldap_config.get("service_account_dn")),
                              service_account_password=(target_ldap_config.get("service_account_password")),
                              group_membership_filter=(target_ldap_config.get("group_membership_filter")),
                              username_domain_match=(target_ldap_config.get("username_domain_match")))
                            response["ldap_config"] = cherrypy.request.db.serializable(config.jsonDict)
                        else:
                            msg = "LDAP config (%s) does not exist" % target_ldap_config.get("ldap_id")
                            self.logger.error(msg)
                            response["error_message"] = msg
                    else:
                        msg = "Invalid Request. Missing ldap_id"
                        self.logger.error(msg)
                        response["error_message"] = msg
                else:
                    msg = "Invalid Request. Missing target_ldap_config"
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
        @Authenticated(requested_actions=[JWT_AUTHORIZATION.AUTH_DELETE], read_only=False)
        def delete_ldap_configParse error at or near `RETURN_VALUE' instruction at offset 160

        @cherrypy.expose
        @cherrypy.tools.json_in()
        @cherrypy.tools.json_out()
        @Authenticated(requested_actions=[JWT_AUTHORIZATION.AUTH_VIEW], read_only=True)
        def test_ldap_configParse error at or near `JUMP_FORWARD' instruction at offset 262

        @cherrypy.expose
        @cherrypy.tools.json_in()
        @cherrypy.tools.json_out()
        @Authenticated(requested_actions=[JWT_AUTHORIZATION.AGENTS_VIEW, JWT_AUTHORIZATION.SERVERS_VIEW, JWT_AUTHORIZATION.IMAGES_VIEW], read_only=True)
        def get_server_custom_network_names(self):
            response = {}
            response["network_names"] = self._get_network_names()
            return response

        @cherrypy.expose
        @cherrypy.tools.json_in()
        @cherrypy.tools.json_out()
        @Authenticated(requested_actions=[JWT_AUTHORIZATION.SYSTEM_VIEW], read_only=True)
        def system_info(self):
            response = {"system_info": {'db':{},  'api':{},  'license':{},  'update':{}}}
            update_information = cherrypy.request.db.getInstallation().update_information
            build_id = os.getenv("KASM_BUILD_ID", "0.0.0.dev")
            update_available = False
            if update_information:
                if type(update_information) == dict:
                    if "latest_version" in update_information:
                        update_available = version.parse(".".join(build_id.split(".")[:3])) < version.parse(update_information["latest_version"])
                license_helper = LicenseHelper(cherrypy.request.db, self.logger)
                response["system_info"]["db"]["alembic_version"] = cherrypy.request.db.getAlembicVersion()
                response["system_info"]["db"]["host"] = self.config["database"]["host"]
                response["system_info"]["db"]["installation_id"] = str(cherrypy.request.db.getInstallation().installation_id)
                response["system_info"]["api"]["server_id"] = self.config["server"]["server_id"]
                response["system_info"]["api"]["server_hostname"] = self.config["server"]["server_hostname"]
                response["system_info"]["api"]["build_id"] = build_id
                response["system_info"]["api"]["zone_name"] = self.config["server"]["zone_name"]
                response["system_info"]["license"]["status"] = license_helper.effective_license.dump()
                response["system_info"]["license"]["status"]["limit_remaining"] = license_helper.get_limit_remaining()
                response["system_info"]["update"]["status"] = update_information
                response["system_info"]["update"]["update_available"] = update_available
                return response

        @cherrypy.expose
        @cherrypy.tools.json_in()
        @cherrypy.tools.json_out()
        @Authenticated(requested_actions=[JWT_AUTHORIZATION.LICENSES_VIEW], read_only=True)
        def get_licenses(self):
            licenses = cherrypy.request.db.getLicenses()
            return {"licenses": [cherrypy.request.db.serializable(x.jsonDict) for x in licenses]}

        @cherrypy.expose
        @cherrypy.tools.json_in()
        @cherrypy.tools.json_out()
        @Authenticated(requested_actions=[JWT_AUTHORIZATION.LICENSES_CREATE], read_only=False)
        def add_license(self):
            response = {}
            event = cherrypy.request.json
            if "license_key" in event:
                try:
                    (key, decoded_license_data) = cherrypy.request.db.process_key(event.get("license_key"))
                    if decoded_license_data.get("key_type") == "activation":
                        response = self._activate(key)
                    else:
                        license = cherrypy.request.db.addLicense(event["license_key"])
                        response["license"] = cherrypy.request.db.serializable(license.jsonDict)
                except Exception as e:
                    try:
                        msg = "Invalid License: %s" % str(e)
                        self.logger.error(msg)
                        response["error_message"] = msg
                    finally:
                        e = None
                        del e

            else:
                msg = "Invalid Request. Missing license_key"
                self.logger.error(msg)
                response["error_message"] = msg
            return response

        @cherrypy.expose
        @cherrypy.tools.json_in()
        @cherrypy.tools.json_out()
        @Authenticated(requested_actions=[JWT_AUTHORIZATION.LICENSES_DELETE], read_only=False)
        def delete_license(self):
            response = {}
            event = cherrypy.request.json
            if "license_id" in event:
                license_id = event.get("license_id")
                try:
                    license_id = uuid.UUID(license_id)
                except:
                    license_id = None
                else:
                    if license_id:
                        license = cherrypy.request.db.getLicense(license_id)
                        if license:
                            cherrypy.request.db.deleteLicense(license)
                        else:
                            msg = "license_id (%s) does not exist" % str(license_id)
                            self.logger.error(msg)
                            response["error_message"] = msg
                    else:
                        msg = "Invalid Request. license_id must be a UUID"
                        self.logger.error(msg)
                        response["error_message"] = msg
            else:
                msg = "Invalid Request. Missing license_id"
                self.logger.error(msg)
                response["error_message"] = msg
            return response

        @cherrypy.expose
        @cherrypy.tools.json_in()
        @cherrypy.tools.json_out()
        @Authenticated(requested_actions=[JWT_AUTHORIZATION.LICENSES_CREATE], read_only=False)
        def activate(self):
            event = cherrypy.request.json
            return self._activate(activation_key=(event.get("activation_key")),
              seats=(event.get("seats")),
              issued_to=(event.get("issued_to")),
              public=False)

        def _activate(self, activation_key=None, seats=None, issued_to=None, public=False):
            response = {}
            if activation_key:
                license_url = self._db.get_config_setting_value("licensing", "license_server_url")
                if license_url:
                    activation = Activation(license_url, self.logger)
                    try:
                        installation_id = str(self._db.getInstallation().installation_id)
                        (license_key, error) = activation.activate(activation_key=activation_key,
                          installation_id=installation_id,
                          seats=seats,
                          issued_to=issued_to)
                        if license_key:
                            license = cherrypy.request.db.addLicense(license_key)
                            response["license"] = cherrypy.request.db.serializable(license.jsonDict)
                        else:
                            msg = "Error during activation: %s" % error
                            self.logger.error(msg)
                            response["error_message"] = msg
                            if public:
                                cherrypy.response.status = 400
                    except Exception as e:
                        try:
                            msg = "Exception activating license: %s" % e
                            self.logger.exception(msg)
                            response["error_message"] = "Unhandled error during activation."
                            if public:
                                cherrypy.response.status = 500
                        finally:
                            e = None
                            del e

                else:
                    msg = "Missing license_server_url Setting"
                    self.logger.error(msg)
                    response["error_message"] = msg
                    if public:
                        cherrypy.response.status = 400
            else:
                msg = "Invalid Request. Missing activation_key"
                self.logger.error(msg)
                response["error_message"] = msg
                if public:
                    cherrypy.response.status = 400
            return response

        @cherrypy.expose
        @cherrypy.tools.json_in()
        @cherrypy.tools.json_out()
        @Authenticated(requested_actions=[JWT_AUTHORIZATION.MANAGERS_VIEW], read_only=True)
        def get_managers(self):
            response = {"managers": []}
            managers = cherrypy.request.db.getManagers()
            if managers:
                for manager in managers:
                    d = cherrypy.request.db.serializable(manager.jsonDict)
                    d["servers"] = []
                    for server in manager.servers:
                        d["servers"].append({'server_id':server.server_id, 
                         'hostname':server.hostname})

                    response["managers"].append(d)

                return cherrypy.request.db.serializable(response)

        @cherrypy.expose
        @cherrypy.tools.json_in()
        @cherrypy.tools.json_out()
        @Authenticated(requested_actions=[JWT_AUTHORIZATION.MANAGERS_DELETE], read_only=False)
        def delete_manager(self):
            response = {}
            event = cherrypy.request.json
            target_manager = event.get("target_manager")
            if target_manager:
                manager_id = target_manager.get("manager_id")
                if manager_id:
                    try:
                        manager_id = uuid.UUID(manager_id)
                    except Exception as e:
                        try:
                            manager_id = None
                        finally:
                            e = None
                            del e

                    else:
                        if manager_id:
                            manager = cherrypy.request.db.getManager(manager_id)
                            if manager:
                                self.logger.info("Deleting Manager (%s)" % manager_id)
                                cherrypy.request.db.deleteManager(manager)
                            else:
                                msg = "Server (%s) Does not Exist" % manager_id
                                self.logger.warning(msg)
                                response["error_message"] = msg
                        else:
                            msg = "Invalid Request: manager_id must be a uuid"
                            self.logger.error(msg)
                            response["error_message"] = msg
                else:
                    msg = "Invalid Request: Missing required parameters"
                    self.logger.error(msg)
                    response["error_message"] = msg
            else:
                msg = "Invalid Request: Missing required parameters"
                self.logger.error(msg)
                response["error_message"] = msg
            return response

        @cherrypy.expose
        @cherrypy.tools.json_in()
        @cherrypy.tools.json_out()
        @Authenticated(requested_actions=[JWT_AUTHORIZATION.ZONES_VIEW], read_only=True)
        def get_zones(self):
            response = {"zones": []}
            event = cherrypy.request.json
            brief = event.get("brief")
            zones = cherrypy.request.db.getZones()
            if zones:
                for zone in zones:
                    d = cherrypy.request.db.serializable(zone.jsonDict)
                    d["managers"] = []
                    if not brief:
                        d["servers"] = [cherrypy.request.db.serializable(x.jsonDict) for x in zone.get_zone_servers()]
                    d["num_kasms"] = len(zone.get_zone_kasms())
                    for manager in zone.managers:
                        d["managers"].append({'manager_id':manager.manager_id, 
                         'manager_hostname':manager.manager_hostname})

                    session_operational_status_filter = [
                     SESSION_OPERATIONAL_STATUS.RUNNING.value,
                     SESSION_OPERATIONAL_STATUS.SAVING.value,
                     SESSION_OPERATIONAL_STATUS.STARTING.value]
                    available_resources = self.provider_manager.get_available_resources(zone_name=(zone.zone_name), session_operational_status_filter=session_operational_status_filter)
                    d["available_cores"] = available_resources["cores"]
                    d["available_memory"] = available_resources["memory"]
                    d["available_gpus"] = available_resources["gpus"]
                    response["zones"].append(d)

                return cherrypy.request.db.serializable(response)

        @cherrypy.expose
        @cherrypy.tools.json_in()
        @cherrypy.tools.json_out()
        @Authenticated(requested_actions=[JWT_AUTHORIZATION.ZONES_MODIFY], read_only=False)
        def update_zone(self):
            response = {}
            event = cherrypy.request.json
            if "target_zone" in event:
                target_zone = event["target_zone"]
                zone_id = target_zone.get("zone_id")
                if zone_id:
                    try:
                        zone_id = uuid.UUID(zone_id)
                    except:
                        zone_id = None

                    if zone_id:
                        zone = cherrypy.request.db.getZoneById(zone_id=zone_id)
                        if zone:
                            updated_zone = cherrypy.request.db.updateZone(zone, zone_name=(target_zone.get("zone_name")),
                              load_strategy=(target_zone.get("load_strategy")),
                              search_alternate_zones=(target_zone.get("search_alternate_zones")),
                              prioritize_static_agents=(target_zone.get("prioritize_static_agents")),
                              allow_origin_domain=(target_zone.get("allow_origin_domain")),
                              upstream_auth_address=(target_zone.get("upstream_auth_address")),
                              proxy_connections=(target_zone.get("proxy_connections")),
                              proxy_hostname=(target_zone.get("proxy_hostname")),
                              proxy_path=(target_zone.get("proxy_path")),
                              proxy_port=(target_zone.get("proxy_port")))
                            self.logger.info("Updated Zone (%s) - (%s)" % (updated_zone.zone_id,
                             updated_zone.zone_name))
                            response["zone"] = cherrypy.request.db.serializable(updated_zone.jsonDict)
                        else:
                            msg = "Invalid Request. Zone does not exit by that id"
                            self.logger.error(msg)
                            response["error_message"] = msg
                    else:
                        msg = "Invalid Request. zone_id must be a uuid"
                        self.logger.error(msg)
                        response["error_message"] = msg
                else:
                    msg = "Invalid Request. Missing required parameters"
                    self.logger.error(msg)
                    response["error_message"] = msg
            else:
                msg = "Invalid Request. Missing required parameters"
                self.logger.error(msg)
                response["error_message"] = msg
            return response

        @cherrypy.expose
        @cherrypy.tools.json_in()
        @cherrypy.tools.json_out()
        @Authenticated(requested_actions=[JWT_AUTHORIZATION.ZONES_CREATE], read_only=False)
        def create_zone(self):
            response = {}
            event = cherrypy.request.json
            if "target_zone" in event:
                target_zone = event["target_zone"]
                if "zone_name" in target_zone:
                    existing_zone = cherrypy.request.db.getZone(target_zone["zone_name"])
                    if not existing_zone:
                        new_zone = cherrypy.request.db.createZone(zone_name=(target_zone.get("zone_name")),
                          load_strategy=(target_zone.get("load_strategy")),
                          prioritize_static_agents=(target_zone.get("prioritize_static_agents")),
                          search_alternate_zones=(target_zone.get("search_alternate_zones")),
                          allow_origin_domain=(target_zone.get("allow_origin_domain")),
                          upstream_auth_address=(target_zone.get("upstream_auth_address")),
                          proxy_connections=(target_zone.get("proxy_connections")),
                          proxy_hostname=(target_zone.get("proxy_hostname")),
                          proxy_path=(target_zone.get("proxy_path")),
                          proxy_port=(target_zone.get("proxy_port")))
                        self.logger.info("Created Zone (%s) - (%s)" % (new_zone.zone_id, new_zone.zone_name))
                        response["zone"] = cherrypy.request.db.serializable(new_zone.jsonDict)
                    else:
                        msg = "Zone (%s) already exists" % target_zone.get("zone_name")
                        self.logger.error(msg)
                        response["error_message"] = msg
                else:
                    msg = "Invalid Request. Missing required parameters"
                    self.logger.error(msg)
                    response["error_message"] = msg
            else:
                msg = "Invalid Request. Missing required parameters"
                self.logger.error(msg)
                response["error_message"] = msg
            return response

        @cherrypy.expose
        @cherrypy.tools.json_in()
        @cherrypy.tools.json_out()
        @Authenticated(requested_actions=[JWT_AUTHORIZATION.ZONES_DELETE], read_only=False)
        def delete_zone(self):
            response = {}
            event = cherrypy.request.json
            target_zone = event.get("target_zone")
            if target_zone:
                zone_id = target_zone.get("zone_id")
                if zone_id:
                    try:
                        zone_id = uuid.UUID(zone_id)
                    except Exception as e:
                        try:
                            zone_id = None
                        finally:
                            e = None
                            del e

                    if zone_id:
                        zone = cherrypy.request.db.getZoneById(zone_id)
                        if zone:
                            if zone.managers:
                                msg = "Zone (%s): (%s) is in use by (%s) managers and cannot be deleted" % (zone.zone_id,
                                 zone.zone_name,
                                 len(zone.managers))
                                self.logger.error(msg)
                                response["error_message"] = msg
                            elif zone.servers:
                                msg = "Zone (%s): (%s) is in use by (%s) servers and cannot be deleted" % (zone.zone_id,
                                 zone.zone_name,
                                 len(zone.servers))
                                self.logger.error(msg)
                                response["error_message"] = msg
                            else:
                                self.logger.info("Deleting Zone (%s) : (%s)" % (zone.zone_id, zone.zone_name))
                                cherrypy.request.db.deleteZone(zone)
                        else:
                            msg = "Zone (%s) Does not Exist" % zone_id
                            self.logger.warning(msg)
                            response["error_message"] = msg
                    else:
                        msg = "Invalid Request: manager_id must be a uuid"
                        self.logger.error(msg)
                        response["error_message"] = msg
                else:
                    msg = "Invalid Request: Missing required parameters"
                    self.logger.error(msg)
                    response["error_message"] = msg
            else:
                msg = "Invalid Request: Missing required parameters"
                self.logger.error(msg)
                response["error_message"] = msg
            return response

        @cherrypy.expose
        @cherrypy.tools.json_in()
        @cherrypy.tools.json_out()
        @Authenticated(requested_actions=[JWT_AUTHORIZATION.DEVAPI_VIEW], read_only=True)
        def get_api_configs(self):
            response = {}
            api_configs = [cherrypy.request.db.serializable(x.jsonDict) for x in cherrypy.request.db.getApiConfigs()]
            response["api_configs"] = api_configs
            return response

        @cherrypy.expose
        @cherrypy.tools.json_in()
        @cherrypy.tools.json_out()
        @Authenticated(requested_actions=[JWT_AUTHORIZATION.GLOBAL_ADMIN], read_only=False)
        def create_api_configs(self):
            response = {}
            event = cherrypy.request.json
            license_helper = LicenseHelper(cherrypy.request.db, self.logger)
            if license_helper.is_developer_api_ok():
                if event.get("api_config") and event["api_config"].get("name"):
                    api = event["api_config"]
                    target_user = cherrypy.request.db.get_user_by_id(api["user_id"]) if "user_id" in api else None
                    if "user_id" not in api or target_user is not None:
                        _api_key = self.generate_random_string(12)
                        _api_key_secret = self.generate_random_string(32)
                        expires = datetime.datetime.strptime(api["expires"], "%Y-%m-%d %H:%M:%S") if ("expires" in api) and (api["expires"] is not None) else None
                        api = cherrypy.request.db.createApiConfig(name=(api["name"]),
                          api_key=_api_key,
                          api_key_secret=_api_key_secret,
                          enabled=(api["enabled"]),
                          read_only=(api["read_only"]),
                          expires=expires)
                        response["api_config"] = cherrypy.request.db.serializable(api.jsonDict)
                        response["api_config"]["api_key_secret"] = _api_key_secret
                    else:
                        response["error_message"] = "Api Name already exists"
                        response["api_config"] = cherrypy.request.db.serializable(api)
                else:
                    response["error_message"] = "API Config missing required parameter"
            else:
                msg = "Access Denied. This feature is not licensed"
                self.logger.error(msg)
                response["error_message"] = msg
            return response

        def generate_random_string(self, length):
            return "".join((random.choice(string.ascii_letters + string.digits) for _ in range(length)))

        @cherrypy.expose
        @cherrypy.tools.json_in()
        @cherrypy.tools.json_out()
        @Authenticated(requested_actions=[JWT_AUTHORIZATION.DEVAPI_DELETE], read_only=False)
        def delete_api_configs(self):
            response = {}
            event = cherrypy.request.json
            if event["api_Id"]:
                api = cherrypy.request.db.getApiConfig(event["api_Id"])
                cherrypy.request.db.deleteApiConfig(api)
            else:
                response["error_message"] = "Missing Api ID"
            return response

        @cherrypy.expose
        @cherrypy.tools.json_in()
        @cherrypy.tools.json_out()
        @Authenticated(requested_actions=[JWT_AUTHORIZATION.DEVAPI_MODIFY], read_only=False)
        def update_api_configs(self):
            response = {}
            license_helper = LicenseHelper(cherrypy.request.db, self.logger)
            if license_helper.is_developer_api_ok():
                event = cherrypy.request.json
                api = event.get("target_api")
                if api and "api_id" in api:
                    expires = datetime.datetime.strptime(api["expires"], "%Y-%m-%d %H:%M:%S") if ("expires" in api) and (api["expires"] is not None) else None
                    cherrypy.request.db.updateApiConfig(api_id=(api["api_id"]),
                      name=(api["name"] if "name" in api else None),
                      enabled=(api["enabled"] if "enabled" in api else None),
                      read_only=(api["read_only"] if "read_only" in api else None),
                      expires=expires)
                else:
                    response["error_message"] = "Missing Target Api or api_id."
            else:
                msg = "Access Denied. This feature is not licensed"
                self.logger.error(msg)
                response["error_message"] = msg
            return response

        @cherrypy.expose
        @cherrypy.tools.json_in()
        @cherrypy.tools.json_out()
        @Authenticated(requested_actions=[JWT_AUTHORIZATION.USERS_VIEW], read_only=True)
        def get_usage_summary(self):
            response = {}
            event = cherrypy.request.json
            if "user_id" in event:
                user = cherrypy.request.db.get_user_by_id(event["user_id"])
                limit = user.get_setting_value("usage_limit", False)
                response["usage_limit"] = limit
                if limit:
                    usage_type = limit["type"]
                    interval = limit["interval"]
                    hours = limit["hours"]
                    (_used_hours, _dates) = get_usage(user)
                    response["usage_limit_remaining"] = hours - _used_hours
                    response["usage_limit_type"] = type
                    response["usage_limit_interval"] = interval
                    response["usage_limit_hours"] = hours
                    response["usage_limit_start_date"] = _dates["start_date"]
                    response["usage_limit_next_start_date"] = _dates["next_start_date"]
            else:
                response["error_message"] = "Error: Missing Required Parameter"
            return response

        @cherrypy.expose
        @cherrypy.tools.json_in()
        @cherrypy.tools.json_out()
        @Authenticated(requested_actions=[JWT_AUTHORIZATION.USERS_VIEW], read_only=True)
        def get_user_usage_dump(self):
            response = {}
            event = cherrypy.request.json
            user = cherrypy.request.db.get_user_by_id(event["user_id"])
            limit = user.get_setting_value("usage_limit", False)
            response["usage_limit"] = limit
            start_date = (datetime.datetime.utcnow() + datetime.timedelta(days=(-30))).strftime("%Y-%m-%d 00:00:00")
            end_date = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
            out_dump = []
            if JWT_AUTHORIZATION.is_authorized_action(cherrypy.request.authorizations, JWT_AUTHORIZATION.SESSIONS_VIEW):
                dump = cherrypy.request.db.getuserAccountDump(user.user_id, start_date, end_date)
                images = cherrypy.request.db.getImages(only_enabled=False)
                for entry in dump:
                    entry = cherrypy.request.db.serializable(entry.jsonDict)
                    for image in images:
                        if str(image.image_id.hex) == entry.get("image_id"):
                            if image.image_src:
                                entry["image_src"] = image.image_src
                            else:
                                break
                        out_dump.append(entry)

                    response["account_dump"] = out_dump
                    response["start_date"] = start_date
                    response["end_date"] = end_date

                return response

        @cherrypy.expose
        @cherrypy.tools.json_in()
        @cherrypy.tools.json_out()
        @Authenticated(requested_actions=[JWT_AUTHORIZATION.COMPANIES_CREATE], read_only=False)
        def create_companyParse error at or near `RETURN_VALUE' instruction at offset 244

        @cherrypy.expose
        @cherrypy.tools.json_in()
        @cherrypy.tools.json_out()
        @Authenticated(requested_actions=[JWT_AUTHORIZATION.COMPANIES_MODIFY], read_only=False)
        def update_company(self):
            response = {}
            event = cherrypy.request.json
            if "target_company" in event:
                target_company = event["target_company"]
                if "company_id" in target_company:
                    company = cherrypy.request.db.getCompany(company_id=(target_company["company_id"]))
                    if company:
                        try:
                            company = cherrypy.request.db.updateCompany(company=company,
                              company_name=(target_company["company_name"]),
                              street=(target_company.get("street")),
                              city=(target_company.get("city")),
                              zip=(target_company.get("zip")),
                              country=(target_company.get("country")))
                            response["company"] = cherrypy.request.db.serializable(company.jsonDict)
                        except Exception as e:
                            try:
                                msg = "Error: (%s)" % e
                                self.logger.error(msg)
                                response["error_message"] = msg
                                cherrypy.response.status = 400
                            finally:
                                e = None
                                del e

                    else:
                        msg = "Invalid Request: Company does not exists by id (%s)" % target_company["company_id"]
                        self.logger.error(msg)
                        response["error_message"] = msg
                        cherrypy.response.status = 400
                else:
                    msg = "Invalid Request: Missing required parameters"
                    self.logger.error(msg)
                    response["error_message"] = msg
                    cherrypy.response.status = 400
            else:
                msg = "Invalid Request: Missing required parameters"
                self.logger.error(msg)
                response["error_message"] = msg
                cherrypy.response.status = 400
            return response

        @cherrypy.expose
        @cherrypy.tools.json_in()
        @cherrypy.tools.json_out()
        @Authenticated(requested_actions=[JWT_AUTHORIZATION.COMPANIES_DELETE], read_only=False)
        def delete_companyParse error at or near `RETURN_VALUE' instruction at offset 186

        @cherrypy.expose
        @cherrypy.tools.json_in()
        @cherrypy.tools.json_out()
        @Authenticated(requested_actions=[JWT_AUTHORIZATION.COMPANIES_VIEW], read_only=True)
        def get_companyParse error at or near `RETURN_VALUE' instruction at offset 192

        @cherrypy.expose
        @cherrypy.tools.json_in()
        @cherrypy.tools.json_out()
        @Authenticated(requested_actions=[JWT_AUTHORIZATION.COMPANIES_VIEW], read_only=True)
        def get_companies(self):
            response = {"companies": []}
            event = cherrypy.request.json
            for company in cherrypy.request.db.getCompanies():
                response["companies"].append(cherrypy.request.db.serializable(company.jsonDict))

            return response

        @cherrypy.expose
        @cherrypy.tools.json_in()
        @cherrypy.tools.json_out()
        @Authenticated(requested_actions=[JWT_AUTHORIZATION.WEBFILTERS_VIEW], read_only=True)
        def get_url_filter_policies(self):
            response = {}
            url_filter_policies = cherrypy.request.db.get_url_filter_policies()
            response["url_filter_policies"] = [cherrypy.request.db.serializable(x.jsonDict) for x in url_filter_policies]
            return response

        @cherrypy.expose
        @cherrypy.tools.json_in()
        @cherrypy.tools.json_out()
        @Authenticated(requested_actions=[JWT_AUTHORIZATION.WEBFILTERS_CREATE], read_only=False)
        def create_url_filter_policy(self):
            response = {}
            event = cherrypy.request.json
            target_url_filter_policy = event.get("target_url_filter_policy")
            if target_url_filter_policy:
                enable_categorization = target_url_filter_policy.get("enable_categorization")
                if enable_categorization:
                    license_helper = LicenseHelper(cherrypy.request.db, self.logger)
                    if not license_helper.is_url_categorization_ok():
                        msg = "Access Denied. URL Categorization is not licensed"
                        self.logger.error(msg)
                        response["error_message"] = msg
                        return response
                    categories = target_url_filter_policy.get("categories")
                    if categories:
                        if type(categories) != dict:
                            msg = "Invalid categories: must be a json dict"
                            self.logger.error(msg)
                            response["error_message"] = msg
                            return response
                        for _default_category in ALL_CATEGORIES.keys():
                            if _default_category not in categories:
                                categories[_default_category] = "inherit"

                    else:
                        for _default_category in ALL_CATEGORIES.keys():
                            if _default_category not in categories:
                                categories[_default_category] = "inherit"

                    for json_prop in ('domain_blacklist', 'domain_whitelist', 'ssl_bypass_domains',
                                      'ssl_bypass_ips'):
                        if json_prop in target_url_filter_policy:
                            if target_url_filter_policy[json_prop] == "":
                                target_url_filter_policy[json_prop] = []
                            target_url_filter_policy[json_prop] = parse_multiline_input(target_url_filter_policy[json_prop])
                            if json_prop == "ssl_bypass_domains":
                                conflicts = validate_overlapping_domains(target_url_filter_policy[json_prop])
                                if not conflicts:
                                    msg = "Error validating SSL Bypass Domains. Overlapping domains detected: %s" % conflicts
                                    self.logger.error(msg)
                                    response["error_message"] = msg
                                    return response
                                if json_prop == "ssl_bypass_ips":
                                    conflicts = IPAddressHelper.validate_overlapping_addresses(target_url_filter_policy[json_prop])
                                    if conflicts:
                                        msg = "Error validating SSL Bypass IPs. %s" % conflicts
                                        self.logger.error(msg)
                                        response["error_message"] = msg
                                        return response
                                safe_search_patterns = target_url_filter_policy.get("safe_search_patterns")

                    if safe_search_patterns:
                        try:
                            safe_search_patterns = validate_safe_search_patterns(safe_search_patterns)
                        except Exception as e:
                            msg = str(e)
                            self.logger.error(msg)
                            response["error_message"] = msg
                            return response

                url_filter_policy = cherrypy.request.db.create_url_filter_policy(filter_policy_name=(target_url_filter_policy.get("filter_policy_name")),
                  filter_policy_descriptions=(target_url_filter_policy.get("filter_policy_descriptions")),
                  categories=categories,
                  domain_blacklist=(target_url_filter_policy.get("domain_blacklist")),
                  domain_whitelist=(target_url_filter_policy.get("domain_whitelist")),
                  deny_by_default=(target_url_filter_policy.get("deny_by_default")),
                  enable_categorization=(target_url_filter_policy.get("enable_categorization")),
                  ssl_bypass_domains=(target_url_filter_policy.get("ssl_bypass_domains")),
                  ssl_bypass_ips=(target_url_filter_policy.get("ssl_bypass_ips")),
                  enable_safe_search=(target_url_filter_policy.get("enable_safe_search")),
                  safe_search_patterns=safe_search_patterns,
                  disable_logging=(target_url_filter_policy.get("disable_logging")))
                self.logger.info("Created Web Filter Policy (%s) - (%s)" % (url_filter_policy.filter_policy_id,
                 url_filter_policy.filter_policy_name))
                response["url_filter_policy"] = cherrypy.request.db.serializable(url_filter_policy.jsonDict)
            else:
                msg = "Invalid Request: Missing required parameters"
                self.logger.error(msg)
                response["error_message"] = msg
            return response

        @cherrypy.expose
        @cherrypy.tools.json_in()
        @cherrypy.tools.json_out()
        @Authenticated(requested_actions=[JWT_AUTHORIZATION.WEBFILTERS_MODIFY], read_only=False)
        def update_url_filter_policy(self):
            response = {}
            event = cherrypy.request.json
            target_url_filter_policy = event.get("target_url_filter_policy")
            if target_url_filter_policy and "filter_policy_id" in target_url_filter_policy:
                filter_policy_id = target_url_filter_policy.get("filter_policy_id")
                if filter_policy_id:
                    try:
                        filter_policy_id = uuid.UUID(filter_policy_id)
                    except:
                        filter_policy_id = None

                    if filter_policy_id:
                        filter_policy = cherrypy.request.db.get_url_filter_policy(filter_policy_id)
                        if filter_policy:
                            enable_categorization = target_url_filter_policy.get("enable_categorization")
                            if enable_categorization:
                                license_helper = LicenseHelper(cherrypy.request.db, self.logger)
                                if not license_helper.is_url_categorization_ok():
                                    msg = "Access Denied. URL Categorization is not licensed"
                                    self.logger.error(msg)
                                    response["error_message"] = msg
                                    return response
                                categories = target_url_filter_policy.get("categories")
                                if categories:
                                    if type(categories) != dict:
                                        msg = "Invalid categories: must be a json dict"
                                        self.logger.error(msg)
                                        response["error_message"] = msg
                                        return response
                                    for _default_category in ALL_CATEGORIES.keys():
                                        if _default_category not in categories:
                                            categories[_default_category] = "inherit"

                                else:
                                    for _default_category in ALL_CATEGORIES.keys():
                                        if _default_category not in categories:
                                            categories[_default_category] = "inherit"

                                for json_prop in ('domain_blacklist', 'domain_whitelist',
                                                  'ssl_bypass_domains', 'ssl_bypass_ips'):
                                    if json_prop in target_url_filter_policy:
                                        if target_url_filter_policy[json_prop] == "":
                                            target_url_filter_policy[json_prop] = []
                                        else:
                                            target_url_filter_policy[json_prop] = parse_multiline_input(target_url_filter_policy[json_prop])
                                        if json_prop == "ssl_bypass_domains":
                                            conflicts = validate_overlapping_domains(target_url_filter_policy[json_prop])
                                            if not conflicts:
                                                msg = "Error validating SSL Bypass Domains. Overlapping domains detected: %s" % conflicts
                                                self.logger.error(msg)
                                                response["error_message"] = msg
                                                return response
                                            if json_prop == "ssl_bypass_ips":
                                                conflicts = IPAddressHelper.validate_overlapping_addresses(target_url_filter_policy[json_prop])
                                                if conflicts:
                                                    msg = "Error validating SSL Bypass IPs. %s" % conflicts
                                                    self.logger.error(msg)
                                                    response["error_message"] = msg
                                                    return response
                                            safe_search_patterns = target_url_filter_policy.get("safe_search_patterns")

                                if safe_search_patterns:
                                    try:
                                        safe_search_patterns = validate_safe_search_patterns(safe_search_patterns)
                                    except Exception as e:
                                        msg = str(e)
                                        self.logger.error(msg)
                                        response["error_message"] = msg
                                        return response

                            updated_url_filter_policy = cherrypy.request.db.update_url_filter_policy(filter_policy,
                              filter_policy_name=(target_url_filter_policy.get("filter_policy_name")),
                              filter_policy_descriptions=(target_url_filter_policy.get("filter_policy_descriptions")),
                              categories=categories,
                              domain_blacklist=(target_url_filter_policy.get("domain_blacklist")),
                              domain_whitelist=(target_url_filter_policy.get("domain_whitelist")),
                              deny_by_default=(target_url_filter_policy.get("deny_by_default")),
                              enable_categorization=(target_url_filter_policy.get("enable_categorization")),
                              ssl_bypass_domains=(target_url_filter_policy.get("ssl_bypass_domains")),
                              ssl_bypass_ips=(target_url_filter_policy.get("ssl_bypass_ips")),
                              enable_safe_search=(target_url_filter_policy.get("enable_safe_search")),
                              safe_search_patterns=safe_search_patterns,
                              disable_logging=(target_url_filter_policy.get("disable_logging")))
                            self.logger.info("Updated Web Filter Policy (%s) - (%s)" % (updated_url_filter_policy.filter_policy_id,
                             updated_url_filter_policy.filter_policy_name))
                            response["url_filter_policy"] = cherrypy.request.db.serializable(updated_url_filter_policy.jsonDict)
                        else:
                            msg = "Invalid Request. filter_policy does not exit by that id"
                            self.logger.error(msg)
                            response["error_message"] = msg
                    else:
                        msg = "Invalid Request. filter_policy_id must be a uuid"
                        self.logger.error(msg)
                        response["error_message"] = msg
                else:
                    msg = "Invalid Request. Missing required parameters"
                    self.logger.error(msg)
                    response["error_message"] = msg
            else:
                msg = "Invalid Request: Missing required parameters"
                self.logger.error(msg)
                response["error_message"] = msg
            return response

        @cherrypy.expose
        @cherrypy.tools.json_in()
        @cherrypy.tools.json_out()
        @Authenticated(requested_actions=[JWT_AUTHORIZATION.WEBFILTERS_DELETE], read_only=False)
        def delete_url_filter_policy(self):
            response = {}
            event = cherrypy.request.json
            filter_policy_id = event.get("filter_policy_id")
            if filter_policy_id:
                filter_policy = cherrypy.request.db.get_url_filter_policy(filter_policy_id)
                if filter_policy:
                    group_settings = cherrypy.request.db.getGroupSettings(name="web_filter_policy", value=filter_policy_id)
                    if group_settings:
                        group_names = [x.group.name for x in group_settings]
                        msg = "Unable to delete filter policy (%s). Policy in use by group(s) (%s)" % (
                         filter_policy.filter_policy_name,
                         group_names)
                        self.logger.error(msg)
                        response["error_message"] = msg
                    elif filter_policy.images:
                        image_names = [x.friendly_name for x in filter_policy.images]
                        msg = "Unable to delete filter policy (%s). Policy in use by image(s) (%s)" % (
                         filter_policy.filter_policy_name,
                         image_names)
                        self.logger.error(msg)
                        response["error_message"] = msg
                    else:
                        cherrypy.request.db.deleteApiConfig(filter_policy)
                        self.logger.info("Deleted filter policy: (%s)" % filter_policy_id)
                else:
                    msg = "Filter policy with id (%s) does not exist" % filter_policy_id
                    self.logger.error(msg)
                    response["error_message"] = msg
            else:
                msg = "Invalid Request. Missing required parameters"
                self.logger.error(msg)
                response["error_message"] = msg
            return response

        @cherrypy.expose
        @cherrypy.tools.json_in()
        @cherrypy.tools.json_out()
        @Authenticated(requested_actions=[JWT_AUTHORIZATION.WEBFILTERS_VIEW], read_only=True)
        def get_all_categories(self):
            _categories = []
            for (k, v) in ALL_CATEGORIES.items():
                _categories.append({'id':k, 
                 'label':v["label"]})

            _categories = sorted(_categories, key=(lambda i: i["label"]))
            return {"categories": _categories}

        @cherrypy.expose
        @cherrypy.tools.json_in()
        @cherrypy.tools.json_out()
        @Authenticated(requested_actions=[JWT_AUTHORIZATION.WEBFILTERS_VIEW], read_only=True)
        def get_safe_search_patterns(self):
            return {"safe_search_patterns": SAFE_SEARCH_PATTERNS}

        @cherrypy.expose
        @cherrypy.tools.json_in()
        @cherrypy.tools.json_out()
        @Authenticated(requested_actions=[JWT_AUTHORIZATION.USERS_VIEW], read_only=True)
        def get_attributes(self):
            return self._get_attributes()

        def _get_attributesParse error at or near `RETURN_VALUE' instruction at offset 230

        @cherrypy.expose
        @cherrypy.tools.json_in()
        @cherrypy.tools.json_out()
        @Authenticated(requested_actions=[JWT_AUTHORIZATION.BRANDINGS_VIEW], read_only=True)
        def get_branding_configs(self):
            response = {}
            branding_configs = cherrypy.request.db.get_branding_configs()
            response["branding_configs"] = [cherrypy.request.db.serializable(x.jsonDict) for x in branding_configs]
            return response

        @cherrypy.expose
        @cherrypy.tools.json_in()
        @cherrypy.tools.json_out()
        @Authenticated(requested_actions=[JWT_AUTHORIZATION.BRANDINGS_DELETE], read_only=False)
        def delete_branding_config(self):
            response = {}
            event = cherrypy.request.json
            branding_config_id = event.get("branding_config_id")
            if branding_config_id:
                branding_config = cherrypy.request.db.get_branding_config(branding_config_id)
                if branding_config:
                    self.logger.info("Deleting Branding Config (%s) : (%s)" % (branding_config.branding_config_id,
                     branding_config.name))
                    cherrypy.request.db.delete_branding_config(branding_config)
                else:
                    msg = "Branding config with id (%s) does not exist" % branding_config_id
                    self.logger.error(msg)
                    response["error_message"] = msg
            else:
                msg = "Invalid Request. Missing required parameters"
                self.logger.error(msg)
                response["error_message"] = msg
            return response

        @cherrypy.expose
        @cherrypy.tools.json_in()
        @cherrypy.tools.json_out()
        @Authenticated(requested_actions=[JWT_AUTHORIZATION.BRANDINGS_CREATE], read_only=False)
        def create_branding_config(self):
            response = {}
            event = cherrypy.request.json
            license_helper = LicenseHelper(cherrypy.request.db, self.logger)
            if license_helper.is_branding_ok():
                target_branding_config = event.get("target_branding_config")
                if target_branding_config:
                    required_parameters = ["name",
                     "hostname",
                     "favicon_logo_url",
                     "header_logo_url",
                     "html_title",
                     "login_caption",
                     "login_logo_url",
                     "login_splash_url",
                     "loading_session_text",
                     "joining_session_text",
                     "destroying_session_text",
                     "launcher_background_url"]
                    ok = True
                    for x in required_parameters:
                        if x not in target_branding_config:
                            ok = False

                    if ok:
                        branding_config = cherrypy.request.db.create_branding_config(name=(target_branding_config.get("name")),
                          favicon_logo_url=(target_branding_config.get("favicon_logo_url")),
                          header_logo_url=(target_branding_config.get("header_logo_url")),
                          html_title=(target_branding_config.get("html_title")),
                          login_caption=(target_branding_config.get("login_caption")),
                          login_logo_url=(target_branding_config.get("login_logo_url")),
                          login_splash_url=(target_branding_config.get("login_splash_url")),
                          loading_session_text=(target_branding_config.get("loading_session_text")),
                          joining_session_text=(target_branding_config.get("joining_session_text")),
                          destroying_session_text=(target_branding_config.get("destroying_session_text")),
                          is_default=(target_branding_config.get("is_default")),
                          hostname=(target_branding_config.get("hostname")),
                          launcher_background_url=(target_branding_config.get("launcher_background_url")))
                        self.logger.info("Created Branding Config (%s) - (%s)" % (branding_config.branding_config_id,
                         branding_config.name))
                        response["branding_config"] = cherrypy.request.db.serializable(branding_config.jsonDict)
                    else:
                        msg = "Invalid Request. Missing required parameters"
                        self.logger.error(msg)
                        response["error_message"] = msg
                else:
                    msg = "Invalid Request. Missing required parameters"
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
        @Authenticated(requested_actions=[JWT_AUTHORIZATION.BRANDINGS_MODIFY], read_only=False)
        def update_branding_config(self):
            response = {}
            event = cherrypy.request.json
            license_helper = LicenseHelper(cherrypy.request.db, self.logger)
            if license_helper.is_branding_ok():
                target_branding_config = event.get("target_branding_config")
                if target_branding_config:
                    branding_config_id = target_branding_config.get("branding_config_id")
                    if branding_config_id:
                        branding_config = cherrypy.request.db.get_branding_config(branding_config_id)
                        if branding_config:
                            updated_branding_config = cherrypy.request.db.update_branding_config(branding_config=branding_config,
                              name=(target_branding_config.get("name")),
                              favicon_logo_url=(target_branding_config.get("favicon_logo_url")),
                              header_logo_url=(target_branding_config.get("header_logo_url")),
                              html_title=(target_branding_config.get("html_title")),
                              login_caption=(target_branding_config.get("login_caption")),
                              login_logo_url=(target_branding_config.get("login_logo_url")),
                              login_splash_url=(target_branding_config.get("login_splash_url")),
                              loading_session_text=(target_branding_config.get("loading_session_text")),
                              joining_session_text=(target_branding_config.get("joining_session_text")),
                              destroying_session_text=(target_branding_config.get("destroying_session_text")),
                              is_default=(target_branding_config.get("is_default")),
                              hostname=(target_branding_config.get("hostname")),
                              launcher_background_url=(target_branding_config.get("launcher_background_url")))
                            self.logger.info("Updated Branding Config (%s) - (%s)" % (updated_branding_config.branding_config_id,
                             updated_branding_config.name))
                            response["branding_config"] = cherrypy.request.db.serializable(branding_config.jsonDict)
                        else:
                            msg = "Branding config with id (%s) does not exist" % branding_config_id
                            self.logger.error(msg)
                            response["error_message"] = msg
                    else:
                        msg = "Invalid Request. Missing required parameters"
                        self.logger.error(msg)
                        response["error_message"] = msg
                else:
                    msg = "Invalid Request. Missing required parameters"
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
        @Authenticated(requested_actions=[JWT_AUTHORIZATION.STAGING_VIEW], read_only=True)
        def get_staging_configs(self):
            response = {}
            staging_configs = cherrypy.request.db.get_staging_configs()
            response["staging_configs"] = [cherrypy.request.db.serializable(x.jsonDict) for x in staging_configs]
            return response

        @cherrypy.expose
        @cherrypy.tools.json_in()
        @cherrypy.tools.json_out()
        @Authenticated(requested_actions=[JWT_AUTHORIZATION.STAGING_VIEW], read_only=True)
        def get_staging_config(self):
            return self._get_staging_config()

        def _get_staging_configParse error at or near `RETURN_VALUE' instruction at offset 198

        @cherrypy.expose
        @cherrypy.tools.json_in()
        @cherrypy.tools.json_out()
        @Authenticated(requested_actions=[JWT_AUTHORIZATION.STAGING_DELETE], read_only=False)
        def delete_staging_config(self):
            return self._delete_staging_config()

        def _delete_staging_configParse error at or near `RETURN_VALUE' instruction at offset 220

        @cherrypy.expose
        @cherrypy.tools.json_in()
        @cherrypy.tools.json_out()
        @Authenticated(requested_actions=[JWT_AUTHORIZATION.STAGING_CREATE], read_only=False)
        def create_staging_config(self):
            return self._create_staging_config()

        def _create_staging_config(self, public=False):
            response = {}
            event = cherrypy.request.json
            license_helper = LicenseHelper(cherrypy.request.db, self.logger)
            if license_helper.is_staging_ok():
                target_staging_config = event.get("target_staging_config")
                if target_staging_config:
                    required_parameters = ["zone_id",
                     "image_id",
                     "num_sessions",
                     "expiration"]
                    ok = True
                    for x in required_parameters:
                        if x not in target_staging_config:
                            ok = False

                    if ok:
                        staging_config = cherrypy.request.db.create_staging_config(zone_id=(target_staging_config.get("zone_id")),
                          server_pool_id=(target_staging_config.get("server_pool_id")),
                          autoscale_config_id=(target_staging_config.get("autoscale_config_id")),
                          image_id=(target_staging_config.get("image_id")),
                          num_sessions=(target_staging_config.get("num_sessions")),
                          expiration=(target_staging_config.get("expiration")),
                          allow_kasm_audio=(target_staging_config.get("allow_kasm_audio")),
                          allow_kasm_uploads=(target_staging_config.get("allow_kasm_uploads")),
                          allow_kasm_downloads=(target_staging_config.get("allow_kasm_downloads")),
                          allow_kasm_clipboard_down=(target_staging_config.get("allow_kasm_clipboard_down")),
                          allow_kasm_clipboard_up=(target_staging_config.get("allow_kasm_clipboard_up")),
                          allow_kasm_microphone=(target_staging_config.get("allow_kasm_microphone")),
                          allow_kasm_gamepad=(target_staging_config.get("allow_kasm_gamepad")),
                          allow_kasm_webcam=(target_staging_config.get("allow_kasm_webcam")),
                          allow_kasm_printing=(target_staging_config.get("allow_kasm_printing")))
                        self.logger.info("Created  Staging Config ID (%s) : Zone (%s) : Image (%s)" % (
                         staging_config.staging_config_id,
                         staging_config.zone_name,
                         staging_config.image_friendly_name))
                        response["staging_config"] = cherrypy.request.db.serializable(staging_config.jsonDict)
                    else:
                        msg = "Invalid Request. Missing required parameters"
                        self.logger.error(msg)
                        response["error_message"] = msg
                        if public:
                            cherrypy.response.status = 400
                else:
                    msg = "Invalid Request. Missing required parameters"
                    self.logger.error(msg)
                    response["error_message"] = msg
                    if public:
                        cherrypy.response.status = 400
            else:
                msg = "Access Denied. This feature is not licensed"
                self.logger.error(msg)
                response["error_message"] = msg
                if public:
                    cherrypy.response.status = 400
            return response

        @cherrypy.expose
        @cherrypy.tools.json_in()
        @cherrypy.tools.json_out()
        @Authenticated(requested_actions=[JWT_AUTHORIZATION.STAGING_MODIFY], read_only=False)
        def update_staging_config(self):
            return self._update_staging_config()

        def _update_staging_config(self, public=False):
            response = {}
            event = cherrypy.request.json
            license_helper = LicenseHelper(cherrypy.request.db, self.logger)
            if license_helper.is_staging_ok():
                target_staging_config = event.get("target_staging_config")
                if target_staging_config:
                    staging_config_id = target_staging_config.get("staging_config_id")
                    if staging_config_id:
                        staging_config = cherrypy.request.db.get_staging_config(staging_config_id)
                        if staging_config:
                            updated_staging_config = cherrypy.request.db.update_staging_config(staging_config=staging_config,
                              zone_id=(target_staging_config.get("zone_id")),
                              server_pool_id=(target_staging_config.get("server_pool_id")),
                              autoscale_config_id=(target_staging_config.get("autoscale_config_id")),
                              image_id=(target_staging_config.get("image_id")),
                              num_sessions=(target_staging_config.get("num_sessions")),
                              expiration=(target_staging_config.get("expiration")),
                              allow_kasm_audio=(target_staging_config.get("allow_kasm_audio")),
                              allow_kasm_uploads=(target_staging_config.get("allow_kasm_uploads")),
                              allow_kasm_downloads=(target_staging_config.get("allow_kasm_downloads")),
                              allow_kasm_clipboard_down=(target_staging_config.get("allow_kasm_clipboard_down")),
                              allow_kasm_clipboard_up=(target_staging_config.get("allow_kasm_clipboard_up")),
                              allow_kasm_microphone=(target_staging_config.get("allow_kasm_microphone")),
                              allow_kasm_gamepad=(target_staging_config.get("allow_kasm_gamepad")),
                              allow_kasm_webcam=(target_staging_config.get("allow_kasm_webcam")),
                              allow_kasm_printing=(target_staging_config.get("allow_kasm_printing")))
                            self.logger.info("Updated Staging Config ID (%s) : Zone (%s) : Image (%s)" % (
                             updated_staging_config.staging_config_id,
                             updated_staging_config.zone_name,
                             updated_staging_config.image_friendly_name))
                            response["staging_config"] = cherrypy.request.db.serializable(updated_staging_config.jsonDict)
                        else:
                            msg = "Staging config with id (%s) does not exist" % staging_config_id
                            self.logger.error(msg)
                            response["error_message"] = msg
                            if public:
                                cherrypy.response.status = 400
                    else:
                        msg = "Invalid Request. Missing required parameters"
                        self.logger.error(msg)
                        response["error_message"] = msg
                        if public:
                            cherrypy.response.status = 400
                else:
                    msg = "Invalid Request. Missing required parameters"
                    self.logger.error(msg)
                    response["error_message"] = msg
                    if public:
                        cherrypy.response.status = 400
            else:
                msg = "Access Denied. This feature is not licensed"
                self.logger.error(msg)
                response["error_message"] = msg
                if public:
                    cherrypy.response.status = 400
            return response

        @cherrypy.expose
        @cherrypy.tools.json_in()
        @cherrypy.tools.json_out()
        @Authenticated(requested_actions=[JWT_AUTHORIZATION.CASTING_VIEW], read_only=True)
        def get_cast_configs(self):
            return self._get_cast_configs()

        def _get_cast_configs(self):
            response = {}
            cast_configs = cherrypy.request.db.get_cast_configs()
            response["cast_configs"] = [cherrypy.request.db.serializable(x.jsonDict) for x in cast_configs]
            return response

        @cherrypy.expose
        @cherrypy.tools.json_in()
        @cherrypy.tools.json_out()
        @Authenticated(requested_actions=[JWT_AUTHORIZATION.CASTING_VIEW], read_only=True)
        def get_cast_config(self):
            return self._get_cast_config()

        def _get_cast_config(self, public=False):
            response = {}
            event = cherrypy.request.json
            cast_config_id = event.get("cast_config_id")
            if cast_config_id:
                cast_config = cherrypy.request.db.get_cast_config(cast_config_id)
                if cast_config:
                    response["cast_config"] = cherrypy.request.db.serializable(cast_config.jsonDict)
                else:
                    msg = "Cast config with id (%s) does not exist" % cast_config_id
                    self.logger.error(msg)
                    response["error_message"] = msg
                    if public:
                        cherrypy.response.status = 400
            else:
                msg = "Invalid Request. Missing required parameters"
                self.logger.error(msg)
                response["error_message"] = msg
                if public:
                    cherrypy.response.status = 400
            return response

        @cherrypy.expose
        @cherrypy.tools.json_in()
        @cherrypy.tools.json_out()
        @Authenticated(requested_actions=[JWT_AUTHORIZATION.CASTING_DELETE], read_only=False)
        def delete_cast_config(self):
            return self._delete_cast_config()

        def _delete_cast_config(self, public=False):
            response = {}
            event = cherrypy.request.json
            cast_config_id = event.get("cast_config_id")
            if cast_config_id:
                cast_config = cherrypy.request.db.get_cast_config(cast_config_id)
                if cast_config:
                    self.logger.info("Deleting Cast Config ID (%s) :Image (%s)" % (
                     cast_config.cast_config_id,
                     cast_config.image_friendly_name))
                    cherrypy.request.db.delete_cast_config(cast_config)
                else:
                    msg = "Cast config with id (%s) does not exist" % cast_config_id
                    self.logger.error(msg)
                    response["error_message"] = msg
                    if public:
                        cherrypy.response.status = 400
            else:
                msg = "Invalid Request. Missing required parameters"
                self.logger.error(msg)
                response["error_message"] = msg
                if public:
                    cherrypy.response.status = 400
            return response

        @cherrypy.expose
        @cherrypy.tools.json_in()
        @cherrypy.tools.json_out()
        @Authenticated(requested_actions=[JWT_AUTHORIZATION.CASTING_CREATE], read_only=False)
        def create_cast_config(self):
            return self._create_cast_config()

        def _create_cast_config(self, public=False):
            response = {}
            event = cherrypy.request.json
            license_helper = LicenseHelper(cherrypy.request.db, self.logger)
            if license_helper.is_casting_ok():
                target_cast_config = event.get("target_cast_config")
                if target_cast_config:
                    required_parameters = ["key"]
                    ok = True
                    for x in required_parameters:
                        if x not in target_cast_config:
                            self.logger.warning("Missing (%s) parameter" % x)
                            ok = False

                    for json_prop in ('allowed_referrers', ):
                        if json_prop in target_cast_config:
                            if target_cast_config[json_prop] == "":
                                target_cast_config[json_prop] = []
                            if type(target_cast_config[json_prop]) != list:
                                target_cast_config[json_prop] = parse_multiline_input(target_cast_config[json_prop])

                    if ok:
                        duplicate_key = cherrypy.request.db.get_cast_config(key=(target_cast_config.get("key")))
                        duplicate_name = cherrypy.request.db.get_cast_config(name=(target_cast_config.get("casting_config_name")))
                        if not duplicate_key or duplicate_name:
                            remote_app_configs = {}
                            if target_cast_config.get("remote_app_configs"):
                                remote_app_configs = json.loads(target_cast_config.get("remote_app_configs"))
                            cast_config = cherrypy.request.db.create_cast_config(image_id=(target_cast_config.get("image_id")),
                              allowed_referrers=(target_cast_config.get("allowed_referrers")),
                              limit_sessions=(target_cast_config.get("limit_sessions")),
                              session_remaining=(target_cast_config.get("session_remaining")),
                              limit_ips=(target_cast_config.get("limit_ips")),
                              ip_request_limit=(target_cast_config.get("ip_request_limit")),
                              ip_request_seconds=(target_cast_config.get("ip_request_seconds")),
                              error_url=(target_cast_config.get("error_url")),
                              enable_sharing=(target_cast_config.get("enable_sharing")),
                              disable_control_panel=(target_cast_config.get("disable_control_panel")),
                              disable_tips=(target_cast_config.get("disable_tips")),
                              disable_fixed_res=(target_cast_config.get("disable_fixed_res")),
                              key=(target_cast_config.get("key")),
                              allow_anonymous=(target_cast_config.get("allow_anonymous")),
                              group_id=(target_cast_config.get("group_id")),
                              require_recaptcha=(target_cast_config.get("require_recaptcha")),
                              kasm_url=(target_cast_config.get("kasm_url")),
                              dynamic_kasm_url=(target_cast_config.get("dynamic_kasm_url")),
                              dynamic_docker_network=(target_cast_config.get("dynamic_docker_network")),
                              allow_resume=(target_cast_config.get("allow_resume")),
                              enforce_client_settings=(target_cast_config.get("enforce_client_settings")),
                              allow_kasm_audio=(target_cast_config.get("allow_kasm_audio")),
                              allow_kasm_uploads=(target_cast_config.get("allow_kasm_uploads")),
                              allow_kasm_downloads=(target_cast_config.get("allow_kasm_downloads")),
                              allow_kasm_clipboard_down=(target_cast_config.get("allow_kasm_clipboard_down")),
                              allow_kasm_clipboard_up=(target_cast_config.get("allow_kasm_clipboard_up")),
                              allow_kasm_microphone=(target_cast_config.get("allow_kasm_microphone")),
                              allow_kasm_sharing=(target_cast_config.get("allow_kasm_sharing")),
                              kasm_audio_default_on=(target_cast_config.get("kasm_audio_default_on")),
                              kasm_ime_mode_default_on=(target_cast_config.get("kasm_ime_mode_default_on")),
                              allow_kasm_gamepad=(target_cast_config.get("allow_kasm_gamepad")),
                              allow_kasm_webcam=(target_cast_config.get("allow_kasm_webcam")),
                              allow_kasm_printing=(target_cast_config.get("allow_kasm_printing")),
                              valid_until=(target_cast_config.get("valid_until")),
                              casting_config_name=(target_cast_config.get("casting_config_name")),
                              remote_app_configs=remote_app_configs)
                            self.logger.info("Created  Cast Config ID (%s) : Image (%s) - Configuration Name (%s)" % (
                             cast_config.cast_config_id,
                             cast_config.image_friendly_name,
                             cast_config.casting_config_name))
                            response["cast_config"] = cherrypy.request.db.serializable(cast_config.jsonDict)
                        else:
                            msg = "A Cast config with existing key (%s) OR configuration name (%s) exists. Key/Configuration Name must be unique" % (target_cast_config.get("key"),
                             target_cast_config.get("casting_config_name"))
                            self.logger.error(msg)
                            response["error_message"] = msg
                            if public:
                                cherrypy.response.status = 400
                    else:
                        msg = "Invalid Request. Missing required parameters"
                        self.logger.error(msg)
                        response["error_message"] = msg
                        if public:
                            cherrypy.response.status = 400
                else:
                    msg = "Invalid Request. Missing required parameters"
                    self.logger.error(msg)
                    response["error_message"] = msg
                    if public:
                        cherrypy.response.status = 400
            else:
                msg = "Access Denied. This feature is not licensed"
                self.logger.error(msg)
                response["error_message"] = msg
                if public:
                    cherrypy.response.status = 400
            return response

        @cherrypy.expose
        @cherrypy.tools.json_in()
        @cherrypy.tools.json_out()
        @Authenticated(requested_actions=[JWT_AUTHORIZATION.CASTING_MODIFY], read_only=False)
        def update_cast_config(self):
            return self._update_cast_config()

        def _update_cast_configParse error at or near `RETURN_VALUE' instruction at offset 1112

        @cherrypy.expose
        @cherrypy.tools.json_in()
        @cherrypy.tools.json_out()
        @Authenticated(requested_actions=[JWT_AUTHORIZATION.AUTH_VIEW], read_only=True)
        def get_oidc_configs(self):
            response = {}
            oidc_configs = cherrypy.request.db.get_oidc_configs()
            response["oidc_configs"] = [cherrypy.request.db.serializable(x.jsonDict) for x in oidc_configs]
            return response

        @cherrypy.expose
        @cherrypy.tools.json_in()
        @cherrypy.tools.json_out()
        @Authenticated(requested_actions=[JWT_AUTHORIZATION.AUTH_CREATE], read_only=False)
        def create_oidc_config(self):
            response = {}
            event = cherrypy.request.json
            license_helper = LicenseHelper(cherrypy.request.db, self.logger)
            if license_helper.is_sso_ok():
                target_oidc_config = event.get("target_oidc_config")
                if target_oidc_config:
                    required_parameters = ["display_name",
                     "client_id",
                     "client_secret",
                     "auth_url",
                     "token_url",
                     "scope",
                     "redirect_url",
                     "user_info_url",
                     "username_attribute"]
                    ok = True
                    for x in required_parameters:
                        if x not in target_oidc_config:
                            self.logger.warning("Missing (%s) parameter" % x)
                            ok = False

                    for json_prop in ('scope', ):
                        if json_prop in target_oidc_config:
                            if target_oidc_config[json_prop] == "":
                                target_oidc_config[json_prop] = []
                            else:
                                target_oidc_config[json_prop] = parse_multiline_input((target_oidc_config[json_prop]),
                                  to_lower=False)

                    if ok:
                        oidc_config = cherrypy.request.db.create_oidc_config(auto_login=(target_oidc_config.get("auto_login")),
                          enabled=(target_oidc_config.get("enabled")),
                          is_default=(target_oidc_config.get("is_default")),
                          hostname=(target_oidc_config.get("hostname")),
                          display_name=(target_oidc_config.get("display_name")),
                          client_id=(target_oidc_config.get("client_id")),
                          client_secret=(target_oidc_config.get("client_secret")),
                          auth_url=(target_oidc_config.get("auth_url")),
                          token_url=(target_oidc_config.get("token_url")),
                          scope=(target_oidc_config.get("scope")),
                          redirect_url=(target_oidc_config.get("redirect_url")),
                          user_info_url=(target_oidc_config.get("user_info_url")),
                          logo_url=(target_oidc_config.get("logo_url")),
                          username_attribute=(target_oidc_config.get("username_attribute")),
                          groups_attribute=(target_oidc_config.get("groups_attribute")),
                          debug=(target_oidc_config.get("debug")))
                        self.logger.info("Created OIDC Config ID (%s) : Name (%s)" % (
                         oidc_config.oidc_id,
                         oidc_config.display_name))
                        response["oidc_config"] = cherrypy.request.db.serializable(oidc_config.jsonDict)
                    else:
                        msg = "Invalid Request. Missing required parameters"
                        self.logger.error(msg)
                        response["error_message"] = msg
                else:
                    msg = "Invalid Request. Missing required parameters"
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
        @Authenticated(requested_actions=[JWT_AUTHORIZATION.AUTH_MODIFY], read_only=False)
        def update_oidc_config(self):
            response = {}
            event = cherrypy.request.json
            license_helper = LicenseHelper(cherrypy.request.db, self.logger)
            if license_helper.is_sso_ok():
                target_oidc_config = event.get("target_oidc_config")
                if target_oidc_config:
                    oidc_id = target_oidc_config.get("oidc_id")
                    if oidc_id:
                        oidc_config = cherrypy.request.db.get_oidc_config(oidc_id)
                        if oidc_config:
                            for json_prop in ('scope', ):
                                if json_prop in target_oidc_config:
                                    if target_oidc_config[json_prop] == "":
                                        target_oidc_config[json_prop] = []
                                    else:
                                        target_oidc_config[json_prop] = parse_multiline_input((target_oidc_config[json_prop]),
                                          to_lower=False)
                                updated_oidc_config = cherrypy.request.db.update_oidc_config(oidc_config=oidc_config,
                                  auto_login=(target_oidc_config.get("auto_login")),
                                  enabled=(target_oidc_config.get("enabled")),
                                  is_default=(target_oidc_config.get("is_default")),
                                  hostname=(target_oidc_config.get("hostname")),
                                  display_name=(target_oidc_config.get("display_name")),
                                  client_id=(target_oidc_config.get("client_id")),
                                  client_secret=(target_oidc_config.get("client_secret")),
                                  auth_url=(target_oidc_config.get("auth_url")),
                                  token_url=(target_oidc_config.get("token_url")),
                                  scope=(target_oidc_config.get("scope")),
                                  redirect_url=(target_oidc_config.get("redirect_url")),
                                  user_info_url=(target_oidc_config.get("user_info_url")),
                                  logo_url=(target_oidc_config.get("logo_url")),
                                  username_attribute=(target_oidc_config.get("username_attribute")),
                                  groups_attribute=(target_oidc_config.get("groups_attribute")),
                                  debug=(target_oidc_config.get("debug")))
                                self.logger.info("Created OIDC Config ID (%s) : Name (%s)" % (
                                 updated_oidc_config.oidc_id,
                                 updated_oidc_config.display_name))
                                response["oidc_config"] = cherrypy.request.db.serializable(updated_oidc_config.jsonDict)

                        else:
                            msg = "OIDC config with id (%s) does not exist" % oidc_id
                            self.logger.error(msg)
                            response["error_message"] = msg
                    else:
                        msg = "Invalid Request. Missing required parameters"
                        self.logger.error(msg)
                        response["error_message"] = msg
                else:
                    msg = "Invalid Request. Missing required parameters"
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
        @Authenticated(requested_actions=[JWT_AUTHORIZATION.AUTH_DELETE], read_only=False)
        def delete_oidc_config(self):
            response = {}
            event = cherrypy.request.json
            oidc_config_id = event.get("oidc_config_id")
            if oidc_config_id:
                oidc_config = cherrypy.request.db.get_oidc_config(oidc_config_id)
                if oidc_config:
                    self.logger.info("Deleting OIDC Config ID (%s) : Name (%s)" % (
                     oidc_config.oidc_id,
                     oidc_config.display_name))
                    cherrypy.request.db.delete_oidc_config(oidc_config)
                else:
                    msg = "OIDC config with id (%s) does not exist" % oidc_config_id
                    self.logger.error(msg)
                    response["error_message"] = msg
            else:
                msg = "Invalid Request. Missing required parameters"
                self.logger.error(msg)
                response["error_message"] = msg
            return response

        @cherrypy.expose
        @cherrypy.tools.json_in()
        @cherrypy.tools.json_out()
        @Authenticated(requested_actions=[JWT_AUTHORIZATION.AUTH_VIEW], read_only=True)
        def get_all_ssos(self):
            SSOConfig = typing.NamedTuple("SSOConfig", id=str, sso_type=str, name=str)
            response = {}
            try:
                sso_configs = []
                ldap_configs = cherrypy.request.db.get_ldap_configs()
                for ldap_config in ldap_configs:
                    sso_configs.append(SSOConfig(id=(str(ldap_config.ldap_id)), sso_type="ldap", name=(ldap_config.name)))

                saml_configs = cherrypy.request.db.get_saml_configs()
                for saml_config in saml_configs:
                    sso_configs.append(SSOConfig(id=(str(saml_config.saml_id)), sso_type="saml", name=(saml_config.display_name)))

                oidc_configs = cherrypy.request.db.get_oidc_configs()
                for oidc_config in oidc_configs:
                    sso_configs.append(SSOConfig(id=(str(oidc_config.oidc_id)), sso_type="oidc", name=(oidc_config.display_name)))

                response["ssos"] = sso_configs
            except Exception:
                msg = "Unable to retrieve all SSO settings"
                self.logger.exception(msg)
                response["error_message"] = msg
            else:
                return response

        @cherrypy.expose
        @cherrypy.tools.json_in()
        @cherrypy.tools.json_out()
        @Authenticated(requested_actions=[JWT_AUTHORIZATION.AUTH_VIEW], read_only=True)
        def get_sso_attribute_mapping_fields(self):
            response = {"fields": (cherrypy.request.db.get_sso_attribute_mapping_fields())}
            return response

        @cherrypy.expose
        @cherrypy.tools.json_in()
        @cherrypy.tools.json_out()
        @Authenticated(requested_actions=[JWT_AUTHORIZATION.AUTH_VIEW], read_only=True)
        def get_sso_attribute_mappings(self):
            response = {}
            event = cherrypy.request.json
            sso_id = event.get("sso_id")
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

                    response["attribute_mappings"] = cherrypy.request.db.serializable(attribute_mappings)
                else:
                    msg = "Invalid Request. SSO id is not valid"
                    self.logger.error(msg)
                    response["error_message"] = msg
                    return response
            else:
                msg = "Invalid Request. Missing required parameters"
                self.logger.error(msg)
                response["error_message"] = msg
            return response

        @cherrypy.expose
        @cherrypy.tools.json_in()
        @cherrypy.tools.json_out()
        @Authenticated(requested_actions=[JWT_AUTHORIZATION.AUTH_MODIFY])
        def add_sso_attribute_mapping(self):
            response = {}
            event = cherrypy.request.json
            sso_mapping = event.get("target_sso_attribute_mapping")
            if sso_mappingand "sso_id" in sso_mapping and "sso_id" in sso_mapping and "user_field" in sso_mapping:
                sso_id = sso_mapping.get("sso_id")
                if cherrypy.request.db.get_ldap_config(sso_id):
                    sso_type = "ldap"
                elif cherrypy.request.db.get_saml_config(sso_id):
                    sso_type = "saml"
                elif cherrypy.request.db.get_oidc_config(sso_id):
                    sso_type = "oidc"
                else:
                    msg = "Invalid Request. SSO id is not valid"
                    self.logger.error(msg)
                    response["error_message"] = msg
                    return response
                sso_attribute_mapping = cherrypy.request.db.create_sso_attribute_mapping(attribute_name=(sso_mapping.get("attribute_name")), user_field=(sso_mapping.get("user_field")),
                  ldap_id=(sso_id if sso_type == "ldap" else None),
                  saml_id=(sso_id if sso_type == "saml" else None),
                  oidc_id=(sso_id if sso_type == "oidc" else None))
                response["sso_attribute_mapping"] = cherrypy.request.db.serializable(sso_attribute_mapping.jsonDict)
            else:
                msg = "Invalid Request. Missing required parameters"
                self.logger.error(msg)
                response["error_message"] = msg
            return response

        @cherrypy.expose
        @cherrypy.tools.json_in()
        @cherrypy.tools.json_out()
        @Authenticated(requested_actions=[JWT_AUTHORIZATION.AUTH_MODIFY])
        def delete_sso_attribute_mapping(self):
            response = {}
            event = cherrypy.request.json
            sso_attribute_id = event.get("sso_attribute_id")
            if sso_attribute_id:
                sso_attribute_mapping = cherrypy.request.db.get_sso_attribute_mapping(sso_attribute_id=sso_attribute_id)
                if sso_attribute_mapping:
                    cherrypy.request.db.delete_sso_attribute_mapping(sso_attribute_mapping=sso_attribute_mapping)
                else:
                    msg = f"SSO attribute mapping with id ({sso_attribute_id}) does not exist"
                    self.logger.error(msg)
                    response["error_message"] = msg
            else:
                msg = "Invalid Request. Missing required parameters"
                self.logger.error(msg)
                response["error_message"] = msg
            return response

        @cherrypy.expose
        @cherrypy.tools.json_in()
        @cherrypy.tools.json_out()
        @Authenticated(requested_actions=[JWT_AUTHORIZATION.AUTH_MODIFY])
        def update_sso_attribute_mappingParse error at or near `RETURN_VALUE' instruction at offset 230

        @cherrypy.expose
        @cherrypy.tools.json_in()
        @cherrypy.tools.json_out()
        @Authenticated(requested_actions=[JWT_AUTHORIZATION.GROUPS_MODIFY, JWT_AUTHORIZATION.GROUPS_MODIFY_IFMEMBER])
        def add_sso_mapping_group(self):
            response = {}
            event = cherrypy.request.json
            sso_mapping = event.get("target_sso_mapping")
            if sso_mapping:
                if not sso_mapping.get("apply_to_all_users") or sso_mapping.get("sso_group_attributes"):
                    msg = "SSO group attributes must be defined if mapping is not assigned to all users"
                    self.logger.error(msg)
                    response["error_message"] = msg
                else:
                    sso_id = sso_mapping.get("sso_id")
                    try:
                        uuid.UUID(sso_id)
                    except ValueError:
                        msg = "Invalid Request. SSO id is not a UUID"
                        self.logger.error(msg)
                        response["error_message"] = msg
                        return response
                    else:
                        if cherrypy.request.db.get_ldap_config(sso_id):
                            sso_type = "ldap"
                        elif cherrypy.request.db.get_saml_config(sso_id):
                            sso_type = "saml"
                        elif cherrypy.request.db.get_oidc_config(sso_id):
                            sso_type = "oidc"
                        else:
                            msg = "Invalid Request. SSO id is not valid"
                            self.logger.error(msg)
                            response["error_message"] = msg
                            return response
                        target_group = cherrypy.request.db.getGroup(group_id=(sso_mapping.get("group_id")))
                    if JWT_AUTHORIZATION.is_user_authorized_action((cherrypy.request.authenticated_user), (cherrypy.request.authorizations), (JWT_AUTHORIZATION.GROUPS_MODIFY), target_group=target_group):
                        group_mapping = cherrypy.request.db.createGroupMapping(group_id=(sso_mapping.get("group_id")), ldap_id=(sso_id if sso_type == "ldap" else None),
                          saml_id=(sso_id if sso_type == "saml" else None),
                          oidc_id=(sso_id if sso_type == "oidc" else None),
                          sso_group_attributes=(sso_mapping.get("sso_group_attributes")),
                          apply_to_all_users=(sso_mapping.get("apply_to_all_users")))
                        response["sso_mapping"] = cherrypy.request.db.serializable(group_mapping.jsonDict)
                    else:
                        self.logger.error(f"User ({cherrypy.request.kasm_user_name}) is not authorized to modify the target group ({target_group.name}).")
                        response["error_message"] = "Unauthorized to modify target group."
                        response["ui_show_error"] = True
                        cherrypy.response.status = 401
            else:
                msg = "Invalid Request. Missing required parameters"
                self.logger.error(msg)
                response["error_message"] = msg
            return response

        @cherrypy.expose
        @cherrypy.tools.json_in()
        @cherrypy.tools.json_out()
        @Authenticated(requested_actions=[JWT_AUTHORIZATION.GROUPS_VIEW, JWT_AUTHORIZATION.GROUPS_VIEW_IFMEMBER, JWT_AUTHORIZATION.GROUPS_VIEW_SYSTEM], read_only=True)
        def get_sso_mappings_group(self):
            response = {}
            event = cherrypy.request.json
            group_id = event.get("group_id")
            if group_id:
                group = cherrypy.request.db.getGroup(group_id=group_id)
                if group:
                    group_mappings = []
                    for group_mapping in group.group_mappings:
                        group_mappings.append(group_mapping.jsonDict)

                    response["group_mappings"] = cherrypy.request.db.serializable(group_mappings)
                else:
                    msg = f"Group with id ({group_id}) does not exist"
                    self.logger.error(msg)
                    response["error_message"] = msg
            else:
                msg = "Invalid Request. Missing required parameters"
                self.logger.error(msg)
                response["error_message"] = msg
            return response

        @cherrypy.expose
        @cherrypy.tools.json_in()
        @cherrypy.tools.json_out()
        @Authenticated(requested_actions=[JWT_AUTHORIZATION.GROUPS_MODIFY, JWT_AUTHORIZATION.GROUPS_MODIFY_IFMEMBER, JWT_AUTHORIZATION.GROUPS_MODIFY_SYSTEM])
        def delete_sso_mapping_group(self):
            response = {}
            event = cherrypy.request.json
            sso_group_id = event.get("sso_group_id")
            if sso_group_id:
                group_mapping = cherrypy.request.db.getGroupMapping(sso_group_id=sso_group_id)
                if group_mapping:
                    cherrypy.request.db.deleteGroupMapping(group_mapping=group_mapping)
                else:
                    msg = f"SSO to group mapping with id ({sso_group_id}) does not exist"
                    self.logger.error(msg)
                    response["error_message"] = msg
            else:
                msg = "Invalid Request. Missing required parameters"
                self.logger.error(msg)
                response["error_message"] = msg
            return response

        @cherrypy.expose
        @cherrypy.tools.json_in()
        @cherrypy.tools.json_out()
        @Authenticated(requested_actions=[JWT_AUTHORIZATION.GROUPS_MODIFY, JWT_AUTHORIZATION.GROUPS_MODIFY_IFMEMBER, JWT_AUTHORIZATION.GROUPS_MODIFY_SYSTEM])
        def update_sso_mapping_group(self):
            response = {}
            event = cherrypy.request.json
            sso_group_mapping = event.get("target_sso_mapping")
            sso_group_id = sso_group_mapping.get("sso_group_id")
            if sso_group_id:
                if not sso_group_mapping.get("apply_to_all_users") or sso_group_mapping.get("sso_group_attributes"):
                    msg = "SSO group attributes must be defined if mapping is not assigned to all users"
                    self.logger.error(msg)
                    response["error_message"] = msg
                else:
                    group_mapping = cherrypy.request.db.getGroupMapping(sso_group_id=(sso_group_mapping.get("sso_group_id")))
                    if group_mapping:
                        cherrypy.request.db.updateGroupMapping(group_mapping=group_mapping, sso_group_attributes=(sso_group_mapping.get("sso_group_attributes")),
                          apply_to_all_users=(sso_group_mapping.get("apply_to_all_users", False)))
                    else:
                        msg = f'SSO to group mapping with id ({sso_group_mapping.get("sso_group_id")}) does not exist'
                        self.logger.error(msg)
                        response["error_message"] = msg
            else:
                msg = "Invalid Request. Missing required parameters"
                self.logger.error(msg)
                response["error_message"] = msg
            return response

        @cherrypy.expose()
        @cherrypy.tools.json_out()
        @JwtAuthenticated(authorizations=[JWT_AUTHORIZATION.SERVER_AGENT])
        def get_server_file_mappings(self):
            file_mappings = {}
            storage_mappings = {}
            storage_mapping_destinations = []
            response = {}
            if cherrypy.request.decoded_jwt and "server_id" in cherrypy.request.decoded_jwt:
                server_id = cherrypy.request.decoded_jwt["server_id"]
                server = cherrypy.request.db.getServer(server_id)
                if server:
                    for image in server.images:
                        for file in image.file_mappings:
                            if file.os_type == OS_TYPES.WINDOWS:
                                priv_key = str.encode(self._db.get_config_setting_value("auth", "api_private_key"))
                                encoded_jwt = generate_jwt_token({"file_map_id": (str(file.file_map_id))}, [JWT_AUTHORIZATION.SERVER_AGENT], priv_key, expires_minutes=10)
                                file_mappings[str(file.file_map_id)] = {'jwt_token':encoded_jwt, 
                                 'destination':file.destination, 
                                 'is_readable':file.is_readable, 
                                 'is_writable':file.is_writable, 
                                 'is_executable':file.is_executable}

                        for storage_mapping in [x for x in image.storage_mappings if x.enabled if x.storage_provider.enabled if x.enabled if x.storage_provider.enabled]:
                            target = storage_mapping.target or storage_mapping.storage_provider.default_target
                            if target in storage_mapping_destinations:
                                target += "_%s" % storage_mapping.storage_mapping_id.hex[:8]
                            storage_mapping_destinations.append(target)
                            (_config, emblem_config) = self.provider_manager.refresh_storage_mapping_config(storage_mapping, False, target)
                            storage_mappings[target] = _config

                    if server.server_pool:
                        for image in server.server_pool.images:
                            for file in image.file_mappings:
                                if file.os_type == OS_TYPES.WINDOWS:
                                    priv_key = str.encode(self._db.get_config_setting_value("auth", "api_private_key"))
                                    encoded_jwt = generate_jwt_token({"file_map_id": (str(file.file_map_id))}, [JWT_AUTHORIZATION.SERVER_AGENT], priv_key, expires_minutes=10)
                                    file_mappings[str(file.file_map_id)] = {'jwt_token':encoded_jwt, 
                                     'destination':file.destination, 
                                     'is_readable':file.is_readable, 
                                     'is_writable':file.is_writable, 
                                     'is_executable':file.is_executable}

                    response["file_mappings"] = file_mappings
                    response["storage_mappings"] = storage_mappings
                else:
                    self.logger.error("Invalid request for server file mappings, server does not exist.")
                    response["error_message"] = "Access Denied!"
            else:
                self.logger.error("Invalid request, JWT token missing server_id.")
                response["error_message"] = "Access Denied!"
            return response

        @cherrypy.expose
        @JwtAuthenticated(authorizations=[JWT_AUTHORIZATION.AGENT, JWT_AUTHORIZATION.SERVER_AGENT])
        def get_file_mapping_contents(self):
            if cherrypy.request.decoded_jwt and "file_map_id" in cherrypy.request.decoded_jwt:
                file_map = cherrypy.request.db.get_file_map(file_map_id=(cherrypy.request.decoded_jwt["file_map_id"]))
                if file_map:
                    cherrypy.response.headers["Content-Type"] = "application/octet-stream"
                    cherrypy.response.status = 200
                    if file_map.file_type == "binary":
                        return base64.b64decode(file_map.content.encode("ascii"))
                    return file_map.content.encode("utf-8")
                else:
                    cherrypy.response.status = 404
                    self.logger.error(f'Attempt to retrieve file mapping ID ({cherrypy.request.decoded_jwt["file_map_id"]}) that does not exist.')
            else:
                cherrypy.response.status = 403
                self.logger.error("Invalid or missing JWT token used in attempt to retrieve file mapping contents.")

        @cherrypy.expose
        @cherrypy.tools.json_in()
        @cherrypy.tools.json_out()
        @Authenticated(requested_actions=[JWT_AUTHORIZATION.GROUPS_VIEW, JWT_AUTHORIZATION.USERS_VIEW, JWT_AUTHORIZATION.IMAGES_VIEW], read_only=True)
        def get_file_mappings(self):
            response = {}
            event = cherrypy.request.json
            image_id = event.get("image_id")
            group_id = event.get("group_id")
            user_id = event.get("user_id")
            kasm_id = event.get("kasm_id")
            file_mappings = cherrypy.request.db.get_file_mappings(group_id=group_id, image_id=image_id, user_id=user_id, kasm_id=kasm_id)
            response["file_mappings"] = []
            for file_map in file_mappings:
                if not not (file_map.image and JWT_AUTHORIZATION.is_authorized_action(cherrypy.request.authorizations, JWT_AUTHORIZATION.IMAGES_VIEW)):
                    if not file_map.group:
                        if not JWT_AUTHORIZATION.is_user_authorized_action((cherrypy.request.authenticated_user), (cherrypy.request.authorizations), (JWT_AUTHORIZATION.GROUPS_VIEW), target_group=(file_map.group)):
                            if file_map.user:
                                if JWT_AUTHORIZATION.is_user_authorized_action((cherrypy.request.authenticated_user), (cherrypy.request.authorizations), (JWT_AUTHORIZATION.USERS_VIEW), target_user=(file_map.user)):
                                    pass
                                file_map_dict = file_map.jsonDict
                                if file_map.file_type == "text":
                                    file_map_dict["content"] = file_map.content
                                response["file_mappings"].append(cherrypy.request.db.serializable(file_map_dict))
                        else:
                            return response

        @cherrypy.expose
        @cherrypy.tools.json_in()
        @cherrypy.tools.json_out()
        @Authenticated(requested_actions=[JWT_AUTHORIZATION.GROUPS_MODIFY, JWT_AUTHORIZATION.GROUPS_MODIFY_IFMEMBER, JWT_AUTHORIZATION.GROUPS_MODIFY_SYSTEM, JWT_AUTHORIZATION.USERS_MODIFY, JWT_AUTHORIZATION.USERS_MODIFY_ADMIN, JWT_AUTHORIZATION.IMAGES_MODIFY])
        def create_file_map(self):
            response = {}
            event = cherrypy.request.json
            target_file_map = event.get("target_file_map")
            if target_file_map:
                image_id = target_file_map.get("image_id")
                group_id = target_file_map.get("group_id")
                user_id = target_file_map.get("user_id")
                is_writable = target_file_map.get("is_writable", False)
                is_readable = target_file_map.get("is_readable", True)
                is_executable = target_file_map.get("is_executable", False)
                file_type = target_file_map.get("file_type", "text")
                name = target_file_map.get("name")
                description = target_file_map.get("description")
                destination = target_file_map.get("destination")
                content = target_file_map.get("content")
                if name:
                    if content:
                        if not image_id:
                            if group_id or user_id:
                                authorized = False
                                if image_id:
                                    if JWT_AUTHORIZATION.is_authorized_action(cherrypy.request.authorizations, JWT_AUTHORIZATION.IMAGES_MODIFY):
                                        authorized = True
                                    if group_id:
                                        group = cherrypy.request.db.getGroup(group_id=group_id)
                                        if group:
                                            if JWT_AUTHORIZATION.is_user_authorized_action((cherrypy.request.authenticated_user), (cherrypy.request.authorizations), (JWT_AUTHORIZATION.GROUPS_MODIFY), target_group=group):
                                                authorized = True
                                            if user_id:
                                                user = cherrypy.request.db.get_user_by_id(user_id)
                                                if user:
                                                    if JWT_AUTHORIZATION.is_user_authorized_action((cherrypy.request.authenticated_user), (cherrypy.request.authorizations), (JWT_AUTHORIZATION.USERS_MODIFY), target_user=user):
                                                        authorized = True
                                                    if not authorized:
                                                        self.logger.error(f"Unauthorized attempt to create a file mapping by user ({cherrypy.request.kasm_user_name}).")
                                                        cherrypy.response.status = 401
                                                        response["ui_show_error"] = True
                                                        response["error_message"] = "Unauthorized Action"
                                                    else:
                                                        file_map = cherrypy.request.db.create_file_map(name=name, description=description, content=content, destination=destination, file_type=file_type,
                                                          is_readable=is_readable,
                                                          is_writable=is_writable,
                                                          is_executable=is_executable,
                                                          user_id=user_id,
                                                          group_id=group_id,
                                                          image_id=image_id)
                                                        response["file_map"] = cherrypy.request.db.serializable(file_map.jsonDict)
                                            self.logger.error("Invalid request, file map must be associated with a group, user, or image.")
                                            response["error_message"] = "Invalid Request"
                                msg = "Invalid Request, missing required fields."
                                self.logger.error(msg)
                                response["error_message"] = msg
                    msg = "Invalid Request. Missing required parameters"
                    self.logger.error(msg)
                    response["error_message"] = msg
                return response

        @cherrypy.expose
        @cherrypy.tools.json_in()
        @cherrypy.tools.json_out()
        @Authenticated(requested_actions=[JWT_AUTHORIZATION.GROUPS_MODIFY, JWT_AUTHORIZATION.GROUPS_MODIFY_IFMEMBER, JWT_AUTHORIZATION.GROUPS_MODIFY_SYSTEM, JWT_AUTHORIZATION.USERS_MODIFY, JWT_AUTHORIZATION.USERS_MODIFY_ADMIN, JWT_AUTHORIZATION.IMAGES_MODIFY])
        def update_file_map(self):
            response = {}
            event = cherrypy.request.json
            target_file_map = event.get("target_file_map")
            if target_file_map:
                file_map_id = target_file_map.get("file_map_id")
                is_writable = target_file_map.get("is_writable", False)
                is_readable = target_file_map.get("is_readable", True)
                is_executable = target_file_map.get("is_executable", False)
                file_type = target_file_map.get("file_type", "text")
                name = target_file_map.get("name")
                description = target_file_map.get("description")
                destination = target_file_map.get("destination")
                content = target_file_map.get("content")
                if file_map_id and name and content:
                    file_map = cherrypy.request.db.get_file_map(file_map_id=file_map_id)
                    if file_map:
                        if not (file_map.image and JWT_AUTHORIZATION.is_authorized_action(cherrypy.request.authorizations, JWT_AUTHORIZATION.IMAGES_MODIFY)):
                            if file_map.group and JWT_AUTHORIZATION.is_user_authorized_action((cherrypy.request.authenticated_user), (cherrypy.request.authorizations), (JWT_AUTHORIZATION.GROUPS_MODIFY), target_group=(file_map.group)) or file_map.user and JWT_AUTHORIZATION.is_user_authorized_action((cherrypy.request.authenticated_user), (cherrypy.request.authorizations), (JWT_AUTHORIZATION.USERS_MODIFY), target_user=(file_map.user)):
                                file_map = cherrypy.request.db.update_file_map(file_map=file_map, name=name, description=description, content=content, destination=destination, file_type=file_type,
                                  is_readable=is_readable,
                                  is_writable=is_writable,
                                  is_executable=is_executable)
                                response["file_map"] = cherrypy.request.db.serializable(file_map.jsonDict)
                            else:
                                self.logger.error(f"User ({cherrypy.request.kasm_user_id}) attempted to modify file mapping ({file_map_id}) but is not authorized.")
                                cherrypy.response.status = 401
                                response["ui_show_error"] = True
                                response["error_message"] = "Unauthorized Request"
                    else:
                        self.logger.error(f"Unable to find referenced file map {file_map_id}")
                        response["error_message"] = "Unable to find referenced file map."
                else:
                    msg = "Invalid Request, missing required fields."
                    self.logger.error(msg)
                    response["error_message"] = msg
            else:
                msg = "Invalid Request. Missing required parameters."
                self.logger.error(msg)
                response["error_message"] = msg
            return response

        @cherrypy.expose
        @cherrypy.tools.json_out()
        @CookieAuthenticated(requested_actions=[JWT_AUTHORIZATION.IMAGES_MODIFY, JWT_AUTHORIZATION.GROUPS_MODIFY, JWT_AUTHORIZATION.GROUPS_MODIFY_IFMEMBER, JWT_AUTHORIZATION.GROUPS_MODIFY_SYSTEM, JWT_AUTHORIZATION.USERS_MODIFY, JWT_AUTHORIZATION.USERS_MODIFY_ADMIN])
        def upload_file_mapping(self, ufile, name, description, destination, file_type='binary', image_id=None, group_id=None, user_id=None, is_writable='false', is_readable='true', is_executable='false', file_map_id=None):
            response = {}
            is_writable = True if is_writable.lower() == "true" else False
            is_readable = True if is_readable.lower() == "true" else False
            is_executable = True if is_executable.lower() == "true" else False
            image_id = None if image_id == "null" else image_id
            group_id = None if group_id == "null" else group_id
            group = None
            target_user_id = None if user_id == "null" else user_id
            target_user = None
            file_map_id = None if file_map_id == "null" else file_map_id
            if group_id:
                group = cherrypy.request.db.getGroup(group_id=group_id)
            if target_user_id:
                target_user = cherrypy.request.db.get_user_by_id(target_user_id)
            if not (image_id and JWT_AUTHORIZATION.is_authorized_action(cherrypy.request.authorizations, JWT_AUTHORIZATION.IMAGES_MODIFY)):
                if group and JWT_AUTHORIZATION.is_user_authorized_action((cherrypy.request.authenticated_user), (cherrypy.request.authorizations), (JWT_AUTHORIZATION.GROUPS_MODIFY), target_group=group) or target_user and JWT_AUTHORIZATION.is_user_authorized_action((cherrypy.request.authenticated_user), (cherrypy.request.authorizations), (JWT_AUTHORIZATION.USERS_MODIFY), target_user=target_user):
                    if file_map_id and type(ufile) == str and ufile == "[object Object]":
                        all_data_b64 = None
                    elif type(ufile) == cherrypy._cpreqbody.Part and hasattr(ufile, "file"):
                        max_size = 5000000
                        size = 0
                        all_data = bytearray()
                        while True:
                            data = ufile.file.read(8192)
                            if not data:
                                break
                            all_data += data
                            size += len(data)
                            if size > max_size:
                                break

                        if size > max_size:
                            msg = f"Upload file mapping failed, size of file greater than limit of {max_size} bytes."
                            self.logger.error(msg)
                            response["error_message"] = msg
                            return response
                        all_data_b64 = base64.b64encode(all_data).decode("ascii")
                    else:
                        msg = "Invalid Request, missing required fields."
                        self.logger.error(msg)
                        response["error_message"] = msg
                        return response
                    if file_map_id:
                        file_map = cherrypy.request.db.get_file_map(file_map_id=file_map_id)
                        if file_map:
                            file_map = cherrypy.request.db.update_file_map(file_map=file_map, name=name, description=description, content=all_data_b64, destination=destination, file_type=file_type,
                              is_readable=is_readable,
                              is_writable=is_writable,
                              is_executable=is_executable)
                        else:
                            self.logger.error(f"Unable to find referenced file map {file_map_id}")
                            response["error_message"] = "Unable to find referenced file map."
                    elif name and description:
                        if image_id or group_id or target_user_id:
                            file_map = cherrypy.request.db.create_file_map(name=name, description=description, content=all_data_b64, destination=destination, file_type=file_type,
                              is_readable=is_readable,
                              is_writable=is_writable,
                              is_executable=is_executable,
                              user_id=target_user_id,
                              group_id=group_id,
                              image_id=image_id)
                            response["file_map"] = cherrypy.request.db.serializable(file_map.jsonDict)
                        else:
                            self.logger.error("Invalid request, file map must be associated with a group, user, or image.")
                            response["error_message"] = "Invalid Request"
                    else:
                        msg = "Invalid Request, missing required fields."
                        self.logger.error(msg)
                        response["error_message"] = msg
                else:
                    self.logger.error(f"User ({cherrypy.request.kasm_user_id}) attempted to modify file mapping ({file_map_id}) but is not authorized.")
                    cherrypy.response.status = 401
                    response["ui_show_error"] = True
                    response["error_message"] = "Unauthorized Request"
                return response

        @cherrypy.expose
        @cherrypy.tools.json_in()
        @cherrypy.tools.json_out()
        @Authenticated(requested_actions=[JWT_AUTHORIZATION.GROUPS_MODIFY, JWT_AUTHORIZATION.GROUPS_MODIFY_IFMEMBER, JWT_AUTHORIZATION.GROUPS_MODIFY_SYSTEM, JWT_AUTHORIZATION.USERS_MODIFY, JWT_AUTHORIZATION.USERS_MODIFY_ADMIN, JWT_AUTHORIZATION.IMAGES_MODIFY])
        def delete_file_map(self):
            response = {}
            event = cherrypy.request.json
            target_file_map = event.get("target_file_map", {})
            file_map_id = target_file_map.get("file_map_id")
            if file_map_id:
                file_map = cherrypy.request.db.get_file_map(file_map_id=file_map_id)
                if file_map:
                    if not (file_map.image and JWT_AUTHORIZATION.is_authorized_action(cherrypy.request.authorizations, JWT_AUTHORIZATION.IMAGES_MODIFY)):
                        if not (file_map.group and JWT_AUTHORIZATION.is_user_authorized_action((cherrypy.request.authenticated_user), (cherrypy.request.authorizations), (JWT_AUTHORIZATION.GROUPS_MODIFY), target_group=(file_map.group))):
                            if not file_map.user or JWT_AUTHORIZATION.is_user_authorized_action((cherrypy.request.authenticated_user), (cherrypy.request.authorizations), (JWT_AUTHORIZATION.USERS_MODIFY), target_user=(file_map.user)):
                                cherrypy.request.db.delete_file_map(file_map=file_map)
                            else:
                                response["error_message"] = "Unauthorized Request"
                                cherrypy.response.status = 401
                                response["ui_show_error"] = True
                                self.logger.error(f"User ({cherrypy.request.kasm_user_name}) attempted to delete a file mapping with improper authorization.")
                else:
                    self.logger.error(f"File mapping with id ({file_map_id}) does not exist")
                    response["error_message"] = "Unable to find referenced file map."
            else:
                msg = "Invalid Request. Missing required parameters"
                self.logger.error(msg)
                response["error_message"] = msg
            return response

        @cherrypy.expose
        @cherrypy.tools.json_in()
        @cherrypy.tools.json_out()
        @Authenticated(requested_actions=[JWT_AUTHORIZATION.CONNECTION_PROXY_VIEW], read_only=True)
        def get_connection_proxies(self):
            response = {}
            connection_proxies = cherrypy.request.db.get_connection_proxies()
            response["connection_proxies"] = [cherrypy.request.db.serializable(x.jsonDict) for x in connection_proxies]
            return response

        @cherrypy.expose
        @cherrypy.tools.json_in()
        @cherrypy.tools.json_out()
        @Authenticated(requested_actions=[JWT_AUTHORIZATION.CONNECTION_PROXY_CREATE])
        def create_connection_proxy(self):
            response = {}
            event = cherrypy.request.json
            target_connection_proxy = event.get("target_connection_proxy")
            if target_connection_proxy:
                connection_proxy = cherrypy.request.db.create_connection_proxy(server_address=(target_connection_proxy.get("server_address")),
                  server_port=(target_connection_proxy.get("server_port")),
                  connection_proxy_type=(target_connection_proxy.get("connection_proxy_type")),
                  auth_token=(target_connection_proxy.get("auth_token")),
                  zone_id=(target_connection_proxy.get("zone_id")))
                response["connection_proxy"] = cherrypy.request.db.serializable(connection_proxy.jsonDict)
            else:
                msg = "Invalid Request. Missing required parameters"
                self.logger.error(msg)
                response["error_message"] = msg
            return response

        @cherrypy.expose
        @cherrypy.tools.json_in()
        @cherrypy.tools.json_out()
        @Authenticated(requested_actions=[JWT_AUTHORIZATION.CONNECTION_PROXY_MODIFY])
        def update_connection_proxy(self):
            response = {}
            event = cherrypy.request.json
            target_connection_proxy = event.get("target_connection_proxy")
            connection_proxy_id = target_connection_proxy.get("connection_proxy_id")
            if connection_proxy_id:
                connection_proxy = cherrypy.request.db.get_connection_proxy(connection_proxy_id)
                if connection_proxy:
                    updated_connection_proxy = cherrypy.request.db.update_connection_proxy(connection_proxy,
                      server_address=(target_connection_proxy.get("server_address")),
                      server_port=(target_connection_proxy.get("server_port")),
                      connection_proxy_type=(target_connection_proxy.get("connection_proxy_type")),
                      auth_token=(target_connection_proxy.get("auth_token")),
                      zone_id=(target_connection_proxy.get("zone_id")))
                    response["connection_proxy"] = cherrypy.request.db.serializable(updated_connection_proxy.jsonDict)
            else:
                msg = "Invalid Request. Missing required parameters"
                self.logger.error(msg)
                response["error_message"] = msg
            return response

        @cherrypy.expose
        @cherrypy.tools.json_in()
        @cherrypy.tools.json_out()
        @Authenticated(requested_actions=[JWT_AUTHORIZATION.CONNECTION_PROXY_DELETE])
        def delete_connection_proxy(self):
            response = {}
            event = cherrypy.request.json
            target_connection_proxy = event.get("target_connection_proxy")
            connection_proxy_id = target_connection_proxy.get("connection_proxy_id")
            if connection_proxy_id:
                connection_proxy = cherrypy.request.db.get_connection_proxy(connection_proxy_id)
                if connection_proxy:
                    cherrypy.request.db.delete_connection_proxy(connection_proxy)
                else:
                    msg = f"Connection Proxy with id ({connection_proxy_id}) does not exist"
                    self.logger.error(msg)
                    response["error_message"] = msg
            else:
                msg = "Invalid Request. Missing required parameters"
                self.logger.error(msg)
                response["error_message"] = msg
            return response

        @cherrypy.tools.json_out()
        @cherrypy.expose
        @CookieAuthenticated(requested_actions=[JWT_AUTHORIZATION.PHYSICAL_TOKENS_CREATE])
        def upload_physical_tokens(self, ufile, zippw):
            response = {}
            upload_filename = ufile.filename
            try:
                with ZipFile(BytesIO(ufile.file.read())) as zfile:
                    tokens = []
                    for zitem in zfile.namelist():
                        zcontent = zfile.open(zitem, mode="r", pwd=(bytes(zippw, "utf-8")))
                        zcontent_text = zcontent.read().decode("UTF-8")
                        m_pattern = re.compile("^(\\S+), *(\\S+)", re.MULTILINE)
                        for m_token in re.finditer(m_pattern, zcontent_text):
                            tokens.append({'serial_number':(m_token.group)(1), 
                             'token_seed':(m_token.group)(2), 
                             'seed_filename':upload_filename})

                    if len(tokens) > 0:
                        cherrypy.request.db.create_physical_tokens(tokens)
            except RuntimeError:
                self.logger.info("Admin attempted to import tokens failed due to invalid password for zip file or unsupported zip format.")
                response["error_message"] = "Invalid password for zip file or unsupported zip file type."
            except IntegrityError:
                self.logger.info("Admin attempted to import tokens that already exist.")
                response["error_message"] = "Import failed, one or more tokens already exist."
            except Exception as ex:
                try:
                    self.logger.error(f"Exception occurred ({type(ex).__name__}) when importing logs: {str(ex)}")
                    response["error_message"] = "Exception occurred when importing tokens, see logs for more details."
                finally:
                    ex = None
                    del ex

            else:
                return response

        @cherrypy.expose
        @cherrypy.tools.json_in()
        @cherrypy.tools.json_out()
        @Authenticated(requested_actions=[JWT_AUTHORIZATION.PHYSICAL_TOKENS_MODIFY], read_only=False)
        def unassign_physical_token(self):
            response = {}
            event = cherrypy.request.json
            if "target_token" in event and "serial_number" in event["target_token"]:
                token = cherrypy.request.db.get_physical_token(event["target_token"]["serial_number"])
                if token:
                    if token.user:
                        token = cherrypy.request.db.unassign_physical_token(token)
                        response["token"] = cherrypy.request.db.serializable(token.jsonDict)
                else:
                    msg = f'Invalid Request. Specified token ({event["target_token"]["serial_number"]}) did not exist.'
                    self.logger.error(msg)
                    response["error_message"] = msg
            else:
                msg = "Invalid Request. Missing required parameters"
                self.logger.error(msg)
                response["error_message"] = msg
            return response

        @cherrypy.expose
        @cherrypy.tools.json_in()
        @cherrypy.tools.json_out()
        @Authenticated(requested_actions=[JWT_AUTHORIZATION.PHYSICAL_TOKENS_MODIFY], read_only=False)
        def assign_physical_token(self):
            response = {}
            event = cherrypy.request.json
            if "target_user" in eventand "user_id" in event["target_user"] and "user_id" in event["target_user"] and "serial_number" in event["target_token"]:
                user = cherrypy.request.db.get_user_by_id(event["target_user"]["user_id"])
                token = cherrypy.request.db.get_physical_token(event["target_token"]["serial_number"])
                if user and token:
                    token = cherrypy.request.db.assign_physical_token(token, user)
                    response["physical_token"] = cherrypy.request.db.serializable(token.jsonDict)
                    self.logger.info(f"Physical token ({token.serial_number}) assigned to user ({user.username}) with seed ({user.secret})")
                else:
                    msg = f'Invalid Request. Specified user ({event["target_user"]["user_id"]}) or token ({event["target_token"]["serial_number"]}) did not exist.'
                    self.logger.error(msg)
                    response["error_message"] = msg
            else:
                msg = "Invalid Request. Missing required parameters"
                self.logger.error(msg)
                response["error_message"] = msg
            return response

        @cherrypy.expose
        @cherrypy.tools.json_in()
        @cherrypy.tools.json_out()
        @Authenticated(requested_actions=[JWT_AUTHORIZATION.PHYSICAL_TOKENS_DELETE], read_only=False)
        def delete_physical_token(self):
            response = {}
            event = cherrypy.request.json
            if "target_token" in event and "serial_number" in event["target_token"]:
                token = cherrypy.request.db.get_physical_token(event["target_token"]["serial_number"])
                if token:
                    username = token.user.username if token.user else ""
                    cherrypy.request.db.delete_physical_token(token)
                    self.logger.info(f'Deleted physical token ({event["target_token"]["serial_number"]}) and unassigned from user ({username}).')
                    response["tokens_deleted"] = 1
                else:
                    msg = f'Delete token failed, unable to find token with serial number {event["target_token"]["serial_number"]}'
                    self.logger.info(msg)
                    response["error_message"] = msg
            elif "target_token" in event and "seed_filename" in event["target_token"]:
                response["tokens_deleted"] = cherrypy.request.db.delete_physical_tokens_by_file(event["target_token"]["seed_filename"])
                self.logger.info(f'Deleted {response["tokens_deleted"]} by filename {event["target_token"]["seed_filename"]}')
            else:
                msg = "Invalid Request. Missing required parameters"
                self.logger.error(msg)
                response["error_message"] = msg
            return response

        @cherrypy.expose
        @cherrypy.tools.json_in()
        @cherrypy.tools.json_out()
        @Authenticated(requested_actions=[JWT_AUTHORIZATION.PHYSICAL_TOKENS_VIEW], read_only=True)
        def get_physical_tokens(self):
            response = {}
            tokens = cherrypy.request.db.get_physical_tokens()
            if tokens:
                response["physical_tokens"] = [cherrypy.request.db.serializable(x.jsonDict) for x in tokens]
            return response

        @cherrypy.expose
        @cherrypy.tools.json_in()
        @cherrypy.tools.json_out()
        @Authenticated(requested_actions=[JWT_AUTHORIZATION.SERVER_POOLS_VIEW], read_only=True)
        def get_server_pools(self):
            response = {"server_pools": []}
            server_pools = cherrypy.request.db.get_server_pools()
            for server_pool in server_pools:
                _sp = cherrypy.request.db.serializable(server_pool.jsonDict)
                _sp["servers"] = []
                for server in server_pool.servers:
                    _sp["servers"].append({'server_id':str(server.server_id), 
                     'hostname':server.hostname, 
                     'friendly_name':server.friendly_name})

                response["server_pools"].append(_sp)

            return response

        @cherrypy.expose
        @cherrypy.tools.json_in()
        @cherrypy.tools.json_out()
        @Authenticated(requested_actions=[JWT_AUTHORIZATION.SERVER_POOLS_CREATE])
        def create_server_pool(self):
            response = {}
            event = cherrypy.request.json
            target_server_pool = event.get("target_server_pool")
            if target_server_pool:
                server_pool = cherrypy.request.db.create_server_pool(server_pool_name=(target_server_pool.get("server_pool_name")),
                  server_pool_type=(target_server_pool.get("server_pool_type")))
                response["server_pool"] = cherrypy.request.db.serializable(server_pool.jsonDict)
            else:
                msg = "Invalid Request. Missing required parameters"
                self.logger.error(msg)
                response["error_message"] = msg
            return response

        @cherrypy.expose
        @cherrypy.tools.json_in()
        @cherrypy.tools.json_out()
        @Authenticated(requested_actions=[JWT_AUTHORIZATION.SERVER_POOLS_MODIFY])
        def update_server_pool(self):
            response = {}
            event = cherrypy.request.json
            target_server_pool = event.get("target_server_pool")
            server_pool_id = target_server_pool.get("server_pool_id")
            if server_pool_id:
                server_pool = cherrypy.request.db.get_server_pool(server_pool_id)
                if server_pool:
                    server_pool = cherrypy.request.db.update_server_pool(server_pool,
                      server_pool_name=(target_server_pool.get("server_pool_name")),
                      server_pool_type=(target_server_pool.get("server_pool_type")))
                    response["server_pool"] = cherrypy.request.db.serializable(server_pool.jsonDict)
                else:
                    msg = f"Server Pool with id ({server_pool_id}) does not exist"
                    self.logger.error(msg)
                    response["error_message"] = msg
            else:
                msg = "Invalid Request. Missing required parameters"
                self.logger.error(msg)
                response["error_message"] = msg
            return response

        @cherrypy.expose
        @cherrypy.tools.json_in()
        @cherrypy.tools.json_out()
        @Authenticated(requested_actions=[JWT_AUTHORIZATION.SERVER_POOLS_DELETE])
        def delete_server_pool(self):
            response = {}
            event = cherrypy.request.json
            target_server_pool = event.get("target_server_pool")
            server_pool_id = target_server_pool.get("server_pool_id")
            if server_pool_id:
                server_pool = cherrypy.request.db.get_server_pool(server_pool_id)
                if server_pool:
                    cherrypy.request.db.delete_server_pool(server_pool)
                else:
                    msg = f"Server Pool with id ({server_pool_id}) does not exist"
                    self.logger.error(msg)
                    response["error_message"] = msg
            else:
                msg = "Invalid Request. Missing required parameters"
                self.logger.error(msg)
                response["error_message"] = msg
            return response

        @cherrypy.expose
        @cherrypy.tools.json_in()
        @cherrypy.tools.json_out()
        @Authenticated(requested_actions=[JWT_AUTHORIZATION.AUTOSCALE_VIEW], read_only=True)
        def get_autoscale_configs(self):
            response = {}
            autoscale_configs = cherrypy.request.db.get_autoscale_configs()
            response["autoscale_configs"] = []
            for auto_scale_config in autoscale_configs:
                asc_dict = cherrypy.request.db.serializable(auto_scale_config.jsonDict)
                if auto_scale_config.vm_provider_config:
                    asc_dict["vm_provider_config"] = {"vm_provider_display_name": (auto_scale_config.vm_provider_config.vm_provider_display_name)}
                response["autoscale_configs"].append(asc_dict)

            return response

        @cherrypy.expose
        @cherrypy.tools.json_in()
        @cherrypy.tools.json_out()
        @Authenticated(requested_actions=[JWT_AUTHORIZATION.AUTOSCALE_CREATE])
        def create_autoscale_configParse error at or near `ROT_TWO' instruction at offset 634

        @cherrypy.expose
        @cherrypy.tools.json_in()
        @cherrypy.tools.json_out()
        @Authenticated(requested_actions=[JWT_AUTHORIZATION.AUTOSCALE_MODIFY])
        def update_autoscale_configParse error at or near `ROT_TWO' instruction at offset 638

        @cherrypy.expose
        @cherrypy.tools.json_in()
        @cherrypy.tools.json_out()
        @Authenticated(requested_actions=[JWT_AUTHORIZATION.AUTOSCALE_DELETE])
        def delete_autoscale_config(self):
            response = {}
            event = cherrypy.request.json
            autoscale_config_id = event.get("autoscale_config_id")
            if autoscale_config_id:
                autoscale_config = cherrypy.request.db.get_autoscale_config(autoscale_config_id)
                if autoscale_config:
                    cherrypy.request.db.delete_autoscale_config(autoscale_config)
                else:
                    msg = f"AutoScale Config with id ({autoscale_config_id}) does not exist"
                    self.logger.error(msg)
                    response["error_message"] = msg
            else:
                msg = "Invalid Request. Missing required parameters"
                self.logger.error(msg)
                response["error_message"] = msg
            return response

        @cherrypy.expose
        @cherrypy.tools.json_in()
        @cherrypy.tools.json_out()
        @Authenticated(requested_actions=[JWT_AUTHORIZATION.AUTOSCALE_SCHEDULE_CREATE])
        def create_schedule(self):
            response = {}
            event = cherrypy.request.json
            target_schedule = event.get("target_schedule", {})
            if target_schedule:
                if target_schedule.get("autoscale_config_id"):
                    try:
                        schedule = cherrypy.request.db.create_schedule(autoscale_config_id=(target_schedule.get("autoscale_config_id")),
                          days_of_the_week=(target_schedule.get("days_of_the_week")),
                          active_start_time=(target_schedule.get("active_start_time")),
                          active_end_time=(target_schedule.get("active_end_time")),
                          timezone=(target_schedule.get("timezone")))
                        response["schedule"] = cherrypy.request.db.serializable(schedule.jsonDict)
                    except ZoneInfoNotFoundError:
                        msg = "Received an invalid timezone value"
                        self.logger.error(msg)
                        response["error_message"] = msg

                else:
                    self.logger.error("Invalid Request. Unknown schedule type.")
                    response["error_message"] = "Invalid Request. Missing required parameters"
            else:
                msg = "Invalid Request. Missing required parameters"
                self.logger.error(msg)
                response["error_message"] = msg
            return response

        @cherrypy.expose
        @cherrypy.tools.json_in()
        @cherrypy.tools.json_out()
        @Authenticated(requested_actions=[JWT_AUTHORIZATION.AUTOSCALE_SCHEDULE_VIEW], read_only=True)
        def get_schedule(self):
            response = {}
            event = cherrypy.request.json
            target_schedule_id = event.get("target_schedule_id")
            if target_schedule_id:
                schedule = cherrypy.request.db.get_schedule(schedule_id=target_schedule_id)
                response["schedule"] = cherrypy.request.db.serializable(schedule.jsonDict)
            else:
                msg = "Invalid Request. Missing required parameters"
                self.logger.error(msg)
                response["error_message"] = msg
            return response

        @cherrypy.expose
        @cherrypy.tools.json_in()
        @cherrypy.tools.json_out()
        @Authenticated(requested_actions=[JWT_AUTHORIZATION.AUTOSCALE_SCHEDULE_VIEW], read_only=True)
        def get_schedules(self):
            response = {}
            event = cherrypy.request.json
            if event.get("target_autoscale_config_id"):
                schedules = cherrypy.request.db.get_schedules(autoscale_config_id=(event.get("target_autoscale_config_id")))
                response["schedules"] = [cherrypy.request.db.serializable(x.jsonDict) for x in schedules]
            else:
                self.logger.error("Invalid Request. Unknown schedule type.")
                response["error_message"] = "Invalid Request. Missing required parameters"
            return response

        @cherrypy.expose
        @cherrypy.tools.json_in()
        @cherrypy.tools.json_out()
        @Authenticated(requested_actions=[JWT_AUTHORIZATION.AUTOSCALE_SCHEDULE_MODIFY])
        def update_schedule(self):
            response = {}
            event = cherrypy.request.json
            target_schedule = event.get("target_schedule", {})
            if target_schedule:
                schedule_id = target_schedule.get("target_schedule_id")
                if schedule_id:
                    schedule = cherrypy.request.db.get_schedule(schedule_id=schedule_id)
                    if schedule:
                        try:
                            schedule = cherrypy.request.db.update_schedule(schedule=schedule,
                              days_of_the_week=(target_schedule.get("days_of_the_week")),
                              active_start_time=(target_schedule.get("active_start_time")),
                              active_end_time=(target_schedule.get("active_end_time")),
                              timezone=(target_schedule.get("timezone")))
                            response["schedule"] = cherrypy.request.db.serializable(schedule.jsonDict)
                        except ZoneInfoNotFoundError:
                            msg = "Received an invalid timezone value"
                            self.logger.error(msg)
                            response["error_message"] = msg

                    else:
                        self.logger.error(f"Unable to find referenced schedule {schedule_id}")
                        response["error_message"] = "Unable to find referenced schedule."
                else:
                    self.logger.error("Invalid Request. Missing schedule id")
                    response["error_message"] = "Invalid Request. Missing required parameters"
            else:
                msg = "Invalid Request. Missing required parameters"
                self.logger.error(msg)
                response["error_message"] = msg
            return response

        @cherrypy.expose
        @cherrypy.tools.json_in()
        @cherrypy.tools.json_out()
        @Authenticated(requested_actions=[JWT_AUTHORIZATION.AUTOSCALE_SCHEDULE_DELETE])
        def delete_schedule(self):
            response = {}
            event = cherrypy.request.json
            target_schedule_id = event.get("target_schedule_id")
            if target_schedule_id:
                schedule = cherrypy.request.db.get_schedule(schedule_id=target_schedule_id)
                if schedule:
                    cherrypy.request.db.delete_schedule(schedule=schedule)
                else:
                    self.logger.error(f"Unable to find referenced schedule {target_schedule_id}")
                    response["error_message"] = "Unable to find referenced schedule."
            else:
                msg = "Invalid Request. Missing required parameters"
                self.logger.error(msg)
                response["error_message"] = msg
            return response

        @cherrypy.expose
        @cherrypy.tools.json_in()
        @cherrypy.tools.json_out()
        @Authenticated(requested_actions=[JWT_AUTHORIZATION.VM_PROVIDER_VIEW], read_only=True)
        def get_vm_provider_configs(self):
            response = {"vm_provider_configs": []}
            response["vm_provider_configs"] += [cherrypy.request.db.serializable(x.jsonDict) for x in cherrypy.request.db.get_vm_provider_configs()]
            return response

        @cherrypy.expose
        @cherrypy.tools.json_in()
        @cherrypy.tools.json_out()
        @Authenticated(requested_actions=[JWT_AUTHORIZATION.VM_PROVIDER_VIEW], read_only=True)
        def get_vm_provider_config(self):
            response = {}
            event = cherrypy.request.json
            target_vm_provider_config = event.get("target_vm_provider_config", {})
            provider_name = target_vm_provider_config.get("vm_provider_name")
            vm_provider_config_id = target_vm_provider_config.get("vm_provider_config_id")
            vm_provider_config = cherrypy.request.db.get_vm_provider_config(vm_provider_config_id=vm_provider_config_id, provider_name=provider_name)
            response["vm_provider_config"] = cherrypy.request.db.serializable(vm_provider_config.jsonDict)
            return response

        @cherrypy.expose
        @cherrypy.tools.json_in()
        @cherrypy.tools.json_out()
        @Authenticated(requested_actions=[JWT_AUTHORIZATION.VM_PROVIDER_CREATE])
        def create_vm_provider_config(self):
            response = {}
            event = cherrypy.request.json
            target_vm_provider_config = event.get("target_vm_provider_config", {})
            provider_name = target_vm_provider_config.get("vm_provider_name")
            if not LicenseHelper(cherrypy.request.db, self.logger).is_auto_scaling_ok():
                msg = "Access Denied. Auto Scaling is not licensed"
                self.logger.error(msg)
                return {"error_message": msg}
            if provider_name:
                try:
                    if provider_name == "azure":
                        response["vm_provider_config"] = self._create_update_azure_provider(target_provider_config=target_vm_provider_config,
                          is_vm=True)
                        return response
                    if provider_name == "aws":
                        response["vm_provider_config"] = self._create_update_aws_provider(target_provider_config=target_vm_provider_config,
                          is_vm=True)
                        return response
                    if provider_name == "digital_ocean":
                        response["vm_provider_config"] = self._create_update_digital_ocean_provider(target_provider_config=target_vm_provider_config,
                          is_vm=True)
                        return response
                    if provider_name == "oci":
                        response["vm_provider_config"] = self._create_update_oci_provider(target_provider_config=target_vm_provider_config,
                          is_vm=True)
                        return response
                    if provider_name == "gcp":
                        response["vm_provider_config"] = self._create_update_gcp_provider(target_provider_config=target_vm_provider_config,
                          is_vm=True)
                        return response
                    if provider_name == "vsphere":
                        response["vm_provider_config"] = self._create_update_vsphere_provider(target_provider_config=target_vm_provider_config,
                          is_vm=True)
                        return response
                    if provider_name == "openstack":
                        response["vm_provider_config"] = self._create_update_openstack_provider(target_provider_config=target_vm_provider_config,
                          is_vm=True)
                        return response
                    msg = f"Provider with name ({provider_name}) does not exist"
                    self.logger.error(msg)
                    response["error_message"] = msg
                except JsonValidationException as e:
                    self.logger.exception(e)
                    response["error_message"] = str(e)
                    return response
                except ValueError as e:
                    self.logger.exception(e)
                    response["error_message"] = str(e)
                    return response

            else:
                msg = "Invalid Request. Missing required parameters"
                self.logger.error(msg)
                response["error_message"] = msg
            return response

        @cherrypy.expose
        @cherrypy.tools.json_in()
        @cherrypy.tools.json_out()
        @Authenticated(requested_actions=[JWT_AUTHORIZATION.VM_PROVIDER_MODIFY])
        def update_vm_provider_config(self):
            response = {}
            event = cherrypy.request.json
            target_vm_provider_config = event.get("target_vm_provider_config")
            vm_provider_config_id = target_vm_provider_config.get("vm_provider_config_id")
            provider_name = target_vm_provider_config.get("vm_provider_name")
            if not LicenseHelper(cherrypy.request.db, self.logger).is_auto_scaling_ok():
                msg = "Access Denied. Auto Scaling is not licensed"
                self.logger.error(msg)
                return {"error_message": msg}
            if vm_provider_config_id and provider_name:
                vm_provider_config = cherrypy.request.db.get_vm_provider_config(vm_provider_config_id=vm_provider_config_id,
                  provider_name=provider_name)
                if vm_provider_config:
                    try:
                        if provider_name == "azure":
                            response["vm_provider_config"] = self._create_update_azure_provider(azure_config=vm_provider_config,
                              target_provider_config=target_vm_provider_config,
                              update=True,
                              is_vm=True)
                            return response
                        if provider_name == "aws":
                            response["vm_provider_config"] = self._create_update_aws_provider(aws_config=vm_provider_config,
                              target_provider_config=target_vm_provider_config,
                              update=True,
                              is_vm=True)
                            return response
                        if provider_name == "digital_ocean":
                            response["vm_provider_config"] = self._create_update_digital_ocean_provider(digital_ocean_config=vm_provider_config,
                              target_provider_config=target_vm_provider_config,
                              update=True,
                              is_vm=True)
                            return response
                        if provider_name == "oci":
                            response["vm_provider_config"] = self._create_update_oci_provider(oci_config=vm_provider_config,
                              target_provider_config=target_vm_provider_config,
                              update=True,
                              is_vm=True)
                            return response
                        if provider_name == "gcp":
                            response["vm_provider_config"] = self._create_update_gcp_provider(gcp_config=vm_provider_config,
                              target_provider_config=target_vm_provider_config,
                              update=True,
                              is_vm=True)
                            return response
                        if provider_name == "vsphere":
                            response["vm_provider_config"] = self._create_update_vsphere_provider(vsphere_config=vm_provider_config,
                              target_provider_config=target_vm_provider_config,
                              update=True,
                              is_vm=True)
                            return response
                        if provider_name == "openstack":
                            response["vm_provider_config"] = self._create_update_openstack_provider(openstack_config=vm_provider_config,
                              target_provider_config=target_vm_provider_config,
                              update=True,
                              is_vm=True)
                            return response
                        msg = f"Provider with name ({provider_name}) does not exist"
                        self.logger.error(msg)
                        response["error_message"] = msg
                    except JsonValidationException as e:
                        self.logger.exception(e)
                        response["error_message"] = str(e)
                        return response
                    except ValueError as e:
                        self.logger.exception(e)
                        response["error_message"] = str(e)
                        return response

                else:
                    msg = f"Provider Config with id ({vm_provider_config_id}) does not exist"
                    self.logger.error(msg)
                    response["error_message"] = msg
                    return response
            else:
                msg = "Invalid Request. Missing required parameters"
                self.logger.error(msg)
                response["error_message"] = msg
            return response

        @staticmethod
        def _create_update_azure_provider(target_provider_config, azure_config=None, update=False, is_vm=False):
            data = process_json_props(data=target_provider_config, dict_props=[
             "azure_image_reference",
             "azure_tags",
             "azure_config_override"],
              list_props=[],
              not_empty_props=[])
            if data.get("azure_authority"):
                if data.get("azure_authority") not in AZURE_AUTHORITY.__members__:
                    raise ValueError(f"Azure Authority must be one of {[str(x) for x in AZURE_AUTHORITY.__members__]}")
                kwargs = {'azure_subscription_id':(data.get)("azure_subscription_id"), 
                 'azure_resource_group':(data.get)("azure_resource_group"), 
                 'azure_tenant_id':(data.get)("azure_tenant_id"), 
                 'azure_client_id':(data.get)("azure_client_id"), 
                 'azure_client_secret':(data.get)("azure_client_secret"), 
                 'azure_region':(data.get)("azure_region"), 
                 'azure_authority':(data.get)("azure_authority")}
                if is_vm:
                    kwargs.update({'config_name':(data.get)("vm_provider_config_name"), 
                     'max_instances':(data.get)("max_instances"), 
                     'azure_vm_size':(data.get)("azure_vm_size"), 
                     'azure_os_disk_type':(data.get)("azure_os_disk_type"), 
                     'azure_image_reference':(data.get)("azure_image_reference"), 
                     'azure_network_sg':(data.get)("azure_network_sg"), 
                     'azure_subnet':(data.get)("azure_subnet"), 
                     'azure_os_disk_size_gb':(data.get)("azure_os_disk_size_gb"), 
                     'azure_tags':(data.get)("azure_tags"), 
                     'azure_os_username':(data.get)("azure_os_username"), 
                     'azure_os_password':(data.get)("azure_os_password"), 
                     'azure_ssh_public_key':(data.get)("azure_ssh_public_key"), 
                     'startup_script':(data.get)("startup_script"), 
                     'azure_config_override':(data.get)("azure_config_override"), 
                     'azure_public_ip':(data.get)("azure_public_ip"), 
                     'azure_is_windows':(data.get)("azure_is_windows")})
                    if update:
                        kwargs["azure_vm_config"] = azure_config
                        provider = (cherrypy.request.db.update_azure_config)(**kwargs)
                    else:
                        provider = (cherrypy.request.db.create_azure_config)(**kwargs)
                else:
                    kwargs.update({"config_name": (data.get("dns_provider_config_name"))})
                    if update:
                        kwargs["azure_dns_config"] = azure_config
                        provider = (cherrypy.request.db.update_azure_dns_config)(**kwargs)
                    else:
                        provider = (cherrypy.request.db.create_azure_dns_config)(**kwargs)
                return cherrypy.request.db.serializable(provider.jsonDict)

        def _create_update_aws_provider(self, target_provider_config, aws_config=None, update=False, is_vm=False):
            data = process_json_props(data=target_provider_config, dict_props=[
             "aws_ec2_custom_tags",
             "aws_ec2_config_override"],
              list_props=[
             "aws_ec2_security_group_ids"],
              not_empty_props=[])
            kwargs = {'aws_access_key_id':(data.get)("aws_access_key_id"), 
             'aws_secret_access_key':(data.get)("aws_secret_access_key")}
            if is_vm:
                ssh_private_key = data.get("aws_ec2_private_key", "").strip()
                ssh_passphrase = data.get("aws_ec2_passphrase", "").strip()
                if ssh_private_key:
                    ssh_passphrase = ssh_passphrase.encode("utf-8") if ssh_passphrase else None
                    backend = default_backend()
                    try:
                        key = backend.load_pem_private_key((ssh_private_key.encode("utf-8")), password=ssh_passphrase, unsafe_skip_rsa_key_validation=False)
                        public_key = key.public_key().public_bytes(encoding=(serialization.Encoding.OpenSSH),
                          format=(serialization.PublicFormat.OpenSSH))
                        data["aws_ec2_private_key"] = ssh_private_key
                        data["aws_ec2_public_key"] = public_key.decode("utf-8")
                    except Exception as e:
                        try:
                            msg = f"Error processing SSH Private Key: ({e})"
                            self.logger.exception(msg)
                            raise e
                        finally:
                            e = None
                            del e

                kwargs.update({'config_name':(data.get)("vm_provider_config_name"), 
                 'max_instances':(data.get)("max_instances"), 
                 'aws_ec2_instance_type':(data.get)("aws_ec2_instance_type"), 
                 'startup_script':(data.get)("startup_script"), 
                 'aws_region':(data.get)("aws_region"), 
                 'aws_ec2_ami_id':(data.get)("aws_ec2_ami_id"), 
                 'aws_ec2_public_key':(data.get)("aws_ec2_public_key"), 
                 'aws_ec2_private_key':(data.get)("aws_ec2_private_key"), 
                 'aws_ec2_security_group_ids':(data.get)("aws_ec2_security_group_ids"), 
                 'aws_ec2_subnet_id':(data.get)("aws_ec2_subnet_id"), 
                 'aws_ec2_iam':(data.get)("aws_ec2_iam"), 
                 'aws_ec2_ebs_volume_type':(data.get)("aws_ec2_ebs_volume_type"), 
                 'aws_ec2_ebs_volume_size_gb':(data.get)("aws_ec2_ebs_volume_size_gb"), 
                 'aws_ec2_custom_tags':(data.get)("aws_ec2_custom_tags"), 
                 'retrieve_password':(data.get)("retrieve_password", False), 
                 'aws_ec2_config_override':(data.get)("aws_ec2_config_override")})
                if update:
                    kwargs["aws_vm_config"] = aws_config
                    provider = (cherrypy.request.db.update_aws_vm_config)(**kwargs)
                else:
                    provider = (cherrypy.request.db.create_aws_vm_config)(**kwargs)
            else:
                kwargs.update({"config_name": (data.get("dns_provider_config_name"))})
                if update:
                    kwargs["aws_dns_config"] = aws_config
                    provider = (cherrypy.request.db.update_aws_dns_config)(**kwargs)
                else:
                    provider = (cherrypy.request.db.create_aws_dns_config)(**kwargs)
            return cherrypy.request.db.serializable(provider.jsonDict)

        @staticmethod
        def _create_update_digital_ocean_provider(target_provider_config, digital_ocean_config=None, update=False, is_vm=False):
            data = process_json_props(data=target_provider_config, dict_props=[], list_props=[], not_empty_props=[])
            kwargs = {"digital_ocean_token": (data.get("digital_ocean_token"))}
            if is_vm:
                kwargs.update({'config_name':(data.get)("vm_provider_config_name"), 
                 'max_instances':(data.get)("max_instances"), 
                 'startup_script':(data.get)("startup_script"), 
                 'region':(data.get)("region"), 
                 'digital_ocean_droplet_image':(data.get)("digital_ocean_droplet_image"), 
                 'digital_ocean_droplet_size':(data.get)("digital_ocean_droplet_size"), 
                 'digital_ocean_tags':(data.get)("digital_ocean_tags"), 
                 'digital_ocean_sshkey_name':(data.get)("digital_ocean_sshkey_name"), 
                 'digital_ocean_firewall_name':(data.get)("digital_ocean_firewall_name")})
                if update:
                    kwargs["digital_ocean_vm_config"] = digital_ocean_config
                    provider = (cherrypy.request.db.update_digital_ocean_vm_config)(**kwargs)
                else:
                    provider = (cherrypy.request.db.create_digital_ocean_vm_config)(**kwargs)
            else:
                kwargs.update({"config_name": (data.get("dns_provider_config_name"))})
                if update:
                    kwargs["digital_ocean_dns_config"] = digital_ocean_config
                    provider = (cherrypy.request.db.update_digital_ocean_dns_config)(**kwargs)
                else:
                    provider = (cherrypy.request.db.create_digital_ocean_dns_config)(**kwargs)
            return cherrypy.request.db.serializable(provider.jsonDict)

        @staticmethod
        def _create_update_oci_provider(target_provider_config, oci_config=None, update=False, is_vm=False):
            data = process_json_props(data=target_provider_config, dict_props=[
             "oci_custom_tags",
             "oci_config_override"],
              list_props=[
             "oci_nsg_ocids",
             "oci_availability_domains"],
              not_empty_props=[])
            kwargs = {'oci_user_ocid':(data.get)("oci_user_ocid"), 
             'oci_private_key':(data.get)("oci_private_key"), 
             'oci_fingerprint':(data.get)("oci_fingerprint"), 
             'oci_tenancy_ocid':(data.get)("oci_tenancy_ocid"), 
             'oci_region':(data.get)("oci_region"), 
             'oci_compartment_ocid':(data.get)("oci_compartment_ocid")}
            if is_vm:
                kwargs.update({'config_name':(data.get)("vm_provider_config_name"), 
                 'max_instances':(data.get)("max_instances"), 
                 'startup_script':(data.get)("startup_script"), 
                 'oci_availability_domains':(data.get)("oci_availability_domains"), 
                 'oci_shape':(data.get)("oci_shape"), 
                 'oci_image_ocid':(data.get)("oci_image_ocid"), 
                 'oci_subnet_ocid':(data.get)("oci_subnet_ocid"), 
                 'oci_ssh_public_key':(data.get)("oci_ssh_public_key"), 
                 'oci_flex_cpus':(data.get)("oci_flex_cpus"), 
                 'oci_flex_memory_gb':(data.get)("oci_flex_memory_gb"), 
                 'oci_boot_volume_gb':(data.get)("oci_boot_volume_gb"), 
                 'oci_custom_tags':(data.get)("oci_custom_tags"), 
                 'oci_config_override':(data.get)("oci_config_override"), 
                 'oci_baseline_ocpu_utilization':(data.get)("oci_baseline_ocpu_utilization"), 
                 'oci_storage_vpus_per_gb':(data.get)("oci_storage_vpus_per_gb"), 
                 'oci_nsg_ocids':(data.get)("oci_nsg_ocids")})
                if update:
                    kwargs["oci_vm_config"] = oci_config
                    provider = (cherrypy.request.db.update_oci_vm_config)(**kwargs)
                else:
                    provider = (cherrypy.request.db.create_oci_vm_config)(**kwargs)
            else:
                kwargs.update({"config_name": (data.get("dns_provider_config_name"))})
                if update:
                    kwargs["oci_dns_config"] = oci_config
                    provider = (cherrypy.request.db.update_oci_dns_config)(**kwargs)
                else:
                    provider = (cherrypy.request.db.create_oci_dns_config)(**kwargs)
            return cherrypy.request.db.serializable(provider.jsonDict)

        @staticmethod
        def _create_update_gcp_provider(target_provider_config, gcp_config=None, update=False, is_vm=False):
            data = process_json_props(data=target_provider_config, dict_props=[
             "gcp_credentials",
             "gcp_custom_labels",
             "gcp_service_account",
             "gcp_config_override"],
              list_props=[
             "gcp_network_tags",
             "gcp_metadata",
             "gcp_guest_accelerators"],
              not_empty_props=[])
            kwargs = {'gcp_credentials':(data.get)("gcp_credentials"), 
             'gcp_project':(data.get)("gcp_project")}
            if is_vm:
                kwargs.update({'config_name':(data.get)("vm_provider_config_name"), 
                 'max_instances':(data.get)("max_instances"), 
                 'startup_script':(data.get)("startup_script"), 
                 'gcp_region':(data.get)("gcp_region"), 
                 'gcp_zone':(data.get)("gcp_zone"), 
                 'gcp_machine_type':(data.get)("gcp_machine_type"), 
                 'gcp_image':(data.get)("gcp_image"), 
                 'gcp_boot_volume_gb':(data.get)("gcp_boot_volume_gb"), 
                 'gcp_cmek':(data.get)("gcp_cmek"), 
                 'gcp_disk_type':(data.get)("gcp_disk_type"), 
                 'gcp_network':(data.get)("gcp_network"), 
                 'gcp_subnetwork':(data.get)("gcp_subnetwork"), 
                 'gcp_public_ip':(data.get)("gcp_public_ip"), 
                 'gcp_network_tags':(data.get)("gcp_network_tags"), 
                 'gcp_custom_labels':(data.get)("gcp_custom_labels"), 
                 'gcp_metadata':(data.get)("gcp_metadata"), 
                 'gcp_service_account':(data.get)("gcp_service_account"), 
                 'gcp_guest_accelerators':(data.get)("gcp_guest_accelerators"), 
                 'gcp_config_override':(data.get)("gcp_config_override")})
                if update:
                    kwargs["gcp_vm_config"] = gcp_config
                    provider = (cherrypy.request.db.update_gcp_vm_config)(**kwargs)
                else:
                    provider = (cherrypy.request.db.create_gcp_vm_config)(**kwargs)
            else:
                kwargs.update({"config_name": (data.get("dns_provider_config_name"))})
                if update:
                    kwargs["gcp_dns_config"] = gcp_config
                    provider = (cherrypy.request.db.update_gcp_dns_config)(**kwargs)
                else:
                    provider = (cherrypy.request.db.create_gcp_dns_config)(**kwargs)
            return cherrypy.request.db.serializable(provider.jsonDict)

        @staticmethod
        def _create_update_vsphere_provider(target_provider_config, vsphere_config=None, update=False, is_vm=True):
            data = process_json_props(data=target_provider_config, dict_props=[], list_props=[], not_empty_props=[])
            kwargs = dict()
            if is_vm:
                kwargs.update({'config_name':(data.get)("vm_provider_config_name"), 
                 'max_instances':(data.get)("max_instances"), 
                 'vsphere_vcenter_address':(data.get)("vsphere_vcenter_address"), 
                 'vsphere_vcenter_port':(data.get)("vsphere_vcenter_port"), 
                 'vsphere_vcenter_username':(data.get)("vsphere_vcenter_username"), 
                 'vsphere_vcenter_password':(data.get)("vsphere_vcenter_password"), 
                 'vsphere_template_name':(data.get)("vsphere_template_name"), 
                 'vsphere_datacenter_name':(data.get)("vsphere_datacenter_name"), 
                 'vsphere_vm_folder':(data.get)("vsphere_vm_folder"), 
                 'vsphere_datastore':(data.get)("vsphere_datastore"), 
                 'vsphere_cluster_name':(data.get)("vsphere_cluster_name"), 
                 'vsphere_resource_pool':(data.get)("vsphere_resource_pool"), 
                 'vsphere_datastore_cluster_name':(data.get)("vsphere_datastore_cluster_name"), 
                 'startup_script':(data.get)("startup_script"), 
                 'vsphere_os_username':(data.get)("vsphere_os_username"), 
                 'vsphere_os_password':(data.get)("vsphere_os_password"), 
                 'vsphere_cpus':(data.get)("vsphere_cpus"), 
                 'vsphere_memoryMB':(data.get)("vsphere_memoryMB"), 
                 'vsphere_installed_OS_type':(data.get)("vsphere_installed_OS_type")})
                if update:
                    kwargs["vsphere_vm_config"] = vsphere_config
                    provider = (cherrypy.request.db.update_vsphere_vm_config)(**kwargs)
                else:
                    provider = (cherrypy.request.db.create_vsphere_vm_config)(**kwargs)
            else:
                raise Exception("_create_update_vsphere_provider called with is_vm=False, vsphere provider does not support DNS")
            return cherrypy.request.db.serializable(provider.jsonDict)

        @staticmethod
        def _create_update_openstack_provider(target_provider_config, openstack_config=None, update=False, is_vm=True):
            data = process_json_props(data=target_provider_config, dict_props=[
             "openstack_config_override",
             "openstack_metadata"],
              list_props=[
             "openstack_security_groups"],
              not_empty_props=[])
            kwargs = dict()
            if is_vm:
                kwargs.update({'config_name':(data.get)("vm_provider_config_name"), 
                 'max_instances':(data.get)("max_instances"), 
                 'openstack_keystone_endpoint':(data.get)("openstack_keystone_endpoint"), 
                 'openstack_nova_endpoint':(data.get)("openstack_nova_endpoint"), 
                 'openstack_nova_version':(data.get)("openstack_nova_version"), 
                 'openstack_glance_endpoint':(data.get)("openstack_glance_endpoint"), 
                 'openstack_glance_version':(data.get)("openstack_glance_version"), 
                 'openstack_cinder_endpoint':(data.get)("openstack_cinder_endpoint"), 
                 'openstack_cinder_version':(data.get)("openstack_cinder_version"), 
                 'openstack_project_name':(data.get)("openstack_project_name"), 
                 'openstack_project_domain_name':(data.get)("openstack_project_domain_name"), 
                 'openstack_user_domain_name':(data.get)("openstack_user_domain_name"), 
                 'openstack_auth_method':(data.get)("openstack_auth_method"), 
                 'openstack_username':(data.get)("openstack_username"), 
                 'openstack_password':(data.get)("openstack_password"), 
                 'openstack_application_credential_id':(data.get)("openstack_application_credential_id"), 
                 'openstack_application_credential_secret':(data.get)("openstack_application_credential_secret"), 
                 'openstack_metadata':(data.get)("openstack_metadata"), 
                 'openstack_image_id':(data.get)("openstack_image_id"), 
                 'openstack_flavor':(data.get)("openstack_flavor"), 
                 'openstack_create_volume':(data.get)("openstack_create_volume"), 
                 'openstack_volume_size_gb':(data.get)("openstack_volume_size_gb"), 
                 'openstack_volume_type':(data.get)("openstack_volume_type"), 
                 'startup_script':(data.get)("startup_script"), 
                 'openstack_security_groups':(data.get)("openstack_security_groups"), 
                 'openstack_network_id':(data.get)("openstack_network_id"), 
                 'openstack_key_name':(data.get)("openstack_key_name"), 
                 'openstack_availability_zone':(data.get)("openstack_availability_zone"), 
                 'openstack_config_override':(data.get)("openstack_config_override")})
                if update:
                    kwargs["openstack_vm_config"] = openstack_config
                    provider = (cherrypy.request.db.update_openstack_vm_config)(**kwargs)
                else:
                    provider = (cherrypy.request.db.create_openstack_vm_config)(**kwargs)
            else:
                raise Exception("_create_update_openstack_provider called with is_vm=False, vsphere provider does not support DNS")
            return cherrypy.request.db.serializable(provider.jsonDict)

        @cherrypy.expose
        @cherrypy.tools.json_in()
        @cherrypy.tools.json_out()
        @Authenticated(requested_actions=[JWT_AUTHORIZATION.VM_PROVIDER_DELETE])
        def delete_vm_provider_config(self):
            response = {}
            event = cherrypy.request.json
            target_vm_provider_config = event.get("target_vm_provider_config", {})
            vm_provider_config_id = target_vm_provider_config.get("vm_provider_config_id")
            provider_name = target_vm_provider_config.get("vm_provider_name")
            if vm_provider_config_id and provider_name:
                vm_provider_config = cherrypy.request.db.get_vm_provider_config(vm_provider_config_id=vm_provider_config_id,
                  provider_name=provider_name)
                if vm_provider_config:
                    cherrypy.request.db.delete_vm_provider_config(vm_provider_config)
                else:
                    msg = f"Unable to find provider ID {vm_provider_config_id}"
                    self.logger.error(msg)
                    response["error_message"] = msg
                    return response
            else:
                msg = "Invalid Request. Missing required parameters"
                self.logger.error(msg)
                response["error_message"] = msg
            return response

        @cherrypy.expose
        @cherrypy.tools.json_in()
        @cherrypy.tools.json_out()
        @Authenticated(requested_actions=[JWT_AUTHORIZATION.DNS_PROVIDERS_VIEW], read_only=True)
        def get_dns_provider_configs(self):
            response = {"dns_provider_configs": []}
            response["dns_provider_configs"] += [cherrypy.request.db.serializable(x.jsonDict) for x in cherrypy.request.db.get_dns_provider_configs()]
            return response

        @cherrypy.expose
        @cherrypy.tools.json_in()
        @cherrypy.tools.json_out()
        @Authenticated(requested_actions=[JWT_AUTHORIZATION.DNS_PROVIDERS_VIEW], read_only=True)
        def get_dns_provider_config(self):
            response = {}
            event = cherrypy.request.json
            target_dns_provider_config = event.get("target_dns_provider_config", {})
            provider_name = target_dns_provider_config.get("dns_provider_name")
            dns_provider_config_id = target_dns_provider_config.get("dns_provider_config_id")
            dns_provider_config = cherrypy.request.db.get_dns_provider_config(dns_provider_config_id=dns_provider_config_id, provider_name=provider_name)
            response["dns_provider_config"] = cherrypy.request.db.serializable(dns_provider_config.jsonDict)
            return response

        @cherrypy.expose
        @cherrypy.tools.json_in()
        @cherrypy.tools.json_out()
        @Authenticated(requested_actions=[JWT_AUTHORIZATION.DNS_PROVIDERS_DELETE])
        def delete_dns_provider_config(self):
            response = {}
            event = cherrypy.request.json
            target_dns_provider_config = event.get("target_dns_provider_config", {})
            dns_provider_config_id = target_dns_provider_config.get("dns_provider_config_id")
            dns_provider_name = target_dns_provider_config.get("dns_provider_name")
            if dns_provider_config_id and dns_provider_name:
                dns_provider_config = cherrypy.request.db.get_dns_provider_config(dns_provider_config_id=dns_provider_config_id,
                  provider_name=dns_provider_name)
                if dns_provider_config:
                    cherrypy.request.db.delete_dns_provider_config(dns_provider_config)
                else:
                    msg = f"Unable to find provider ID {dns_provider_config_id}"
                    self.logger.error(msg)
                    response["error_message"] = msg
                    return response
            else:
                msg = "Invalid Request. Missing required parameters"
                self.logger.error(msg)
                response["error_message"] = msg
            return response

        @cherrypy.expose
        @cherrypy.tools.json_in()
        @cherrypy.tools.json_out()
        @Authenticated(requested_actions=[JWT_AUTHORIZATION.DNS_PROVIDERS_CREATE])
        def create_dns_provider_config(self):
            response = {}
            event = cherrypy.request.json
            target_dns_provider_config = event.get("target_dns_provider_config", {})
            dns_provider_name = target_dns_provider_config.get("dns_provider_name")
            if not LicenseHelper(cherrypy.request.db, self.logger).is_auto_scaling_ok():
                msg = "Access Denied. Auto Scaling is not licensed"
                self.logger.error(msg)
                return {"error_message": msg}
            if dns_provider_name:
                if dns_provider_name == "azure":
                    response["dns_provider_config"] = self._create_update_azure_provider(target_provider_config=target_dns_provider_config,
                      is_vm=False)
                    return response
                if dns_provider_name == "aws":
                    response["dns_provider_config"] = self._create_update_aws_provider(target_provider_config=target_dns_provider_config,
                      is_vm=False)
                    return response
                if dns_provider_name == "digital_ocean":
                    response["dns_provider_config"] = self._create_update_digital_ocean_provider(target_provider_config=target_dns_provider_config,
                      is_vm=False)
                    return response
                if dns_provider_name == "oci":
                    response["dns_provider_config"] = self._create_update_oci_provider(target_provider_config=target_dns_provider_config,
                      is_vm=False)
                    return response
                if dns_provider_name == "gcp":
                    response["dns_provider_config"] = self._create_update_gcp_provider(target_provider_config=target_dns_provider_config,
                      is_vm=False)
                    return response
                msg = f"Provider with name ({dns_provider_name}) does not exist"
                self.logger.error(msg)
                response["error_message"] = msg
            else:
                msg = "Invalid Request. Missing required parameters"
                self.logger.error(msg)
                response["error_message"] = msg
            return response

        @cherrypy.expose
        @cherrypy.tools.json_in()
        @cherrypy.tools.json_out()
        @Authenticated(requested_actions=[JWT_AUTHORIZATION.DNS_PROVIDERS_MODIFY])
        def update_dns_provider_config(self):
            response = {}
            event = cherrypy.request.json
            target_dns_provider_config = event.get("target_dns_provider_config")
            dns_provider_config_id = target_dns_provider_config.get("dns_provider_config_id")
            dns_provider_name = target_dns_provider_config.get("dns_provider_name")
            if not LicenseHelper(cherrypy.request.db, self.logger).is_auto_scaling_ok():
                msg = "Access Denied. Auto Scaling is not licensed"
                self.logger.error(msg)
                return {"error_message": msg}
            if dns_provider_config_id and dns_provider_name:
                dns_provider_config = cherrypy.request.db.get_dns_provider_config(dns_provider_config_id, dns_provider_name)
                if dns_provider_config:
                    try:
                        if dns_provider_name == "azure":
                            response["dns_provider_config"] = self._create_update_azure_provider(azure_config=dns_provider_config,
                              target_provider_config=target_dns_provider_config,
                              update=True,
                              is_vm=False)
                            return response
                        if dns_provider_name == "aws":
                            response["dns_provider_config"] = self._create_update_aws_provider(aws_config=dns_provider_config,
                              target_provider_config=target_dns_provider_config,
                              update=True,
                              is_vm=False)
                            return response
                        if dns_provider_name == "digital_ocean":
                            response["dns_provider_config"] = self._create_update_digital_ocean_provider(digital_ocean_config=dns_provider_config,
                              target_provider_config=target_dns_provider_config,
                              update=True,
                              is_vm=False)
                            return response
                        if dns_provider_name == "oci":
                            response["dns_provider_config"] = self._create_update_oci_provider(oci_config=dns_provider_config,
                              target_provider_config=target_dns_provider_config,
                              update=True,
                              is_vm=False)
                            return response
                        if dns_provider_name == "gcp":
                            response["dns_provider_config"] = self._create_update_gcp_provider(gcp_config=dns_provider_config,
                              target_provider_config=target_dns_provider_config,
                              update=True,
                              is_vm=False)
                            return response
                        msg = f"Provider with name ({dns_provider_name}) does not exist"
                        self.logger.error(msg)
                        response["error_message"] = msg
                    except JsonValidationException as e:
                        self.logger.exception(e)
                        response["error_message"] = str(e)
                        return response

                else:
                    msg = f"DNS provider config with id ({dns_provider_config_id}) does not exist"
                    self.logger.error(msg)
                    response["error_message"] = msg
                    return response
            else:
                msg = "Invalid Request. Missing required parameters"
                self.logger.error(msg)
                response["error_message"] = msg
            return response

        @cherrypy.expose
        @cherrypy.tools.json_in()
        @cherrypy.tools.json_out()
        @Authenticated(requested_actions=[JWT_AUTHORIZATION.SYSTEM_EXPORT_DATA], read_only=True)
        def export_data(self):
            event = cherrypy.request.json
            response = {}
            key = event.get("export_key", "").strip()
            tables = event.get("tables")
            if key:
                export_data = cherrypy.request.db.export_data(tables=tables)
                zip_buffer = io.BytesIO()
                with pyzipper.AESZipFile(zip_buffer, mode="w", compression=(pyzipper.ZIP_LZMA), encryption=(pyzipper.WZ_AES)) as zf:
                    zf.setpassword(str(key).encode("utf-8"))
                    yaml_file = io.StringIO(yaml.dump(export_data))
                    zf.writestr("export_data.yaml", yaml_file.getvalue().encode("utf-8"))
                encoded_zip = base64.b64encode(zip_buffer.getvalue()).decode("utf-8")
                response["data"] = encoded_zip
            else:
                msg = "Invalid Request. Missing required parameters"
                self.logger.error(msg)
                response["error_message"] = msg
            return response

        @cherrypy.expose
        @cherrypy.tools.json_in()
        @cherrypy.tools.json_out()
        @Authenticated(requested_actions=[JWT_AUTHORIZATION.SYSTEM_EXPORT_DATA], read_only=True)
        def export_schema(self):
            event = cherrypy.request.json
            response = cherrypy.request.db.export_schema(tables=(event.get("tables")))
            return {"schema": (yaml.dump(response))}

        @cherrypy.expose
        @cherrypy.tools.json_in()
        @cherrypy.tools.json_out()
        @Authenticated(requested_actions=[JWT_AUTHORIZATION.SYSTEM_IMPORT_DATA])
        def import_data(self):
            event = cherrypy.request.json
            response = {}
            import_data = event.get("import_data")
            import_format = event.get("import_format")
            import_key = event.get("import_key")
            sanity_test = event.get("sanity_test")
            if import_data and import_format:
                if import_format == "yaml":
                    import_data = yaml.safe_load(import_data)
                elif import_format == "zip":
                    import_data = base64.b64decode(import_data)
                    zip_buffer = io.BytesIO(import_data)
                    try:
                        with pyzipper.AESZipFile(zip_buffer, mode="r", compression=(pyzipper.ZIP_LZMA), encryption=(pyzipper.WZ_AES)) as zf:
                            if import_key:
                                zf.setpassword(import_key.encode("utf-8"))
                            import_data = zf.read("export_data.yaml")
                            import_data = yaml.safe_load(import_data)
                    except Exception as e:
                        msg = "Error processing zip file: %s" % e
                        self.logger.error(msg)
                        response["error_message"] = msg
                        return response

                alembic_version = cherrypy.request.db.getAlembicVersion()
                import_alembic_version = import_data.get("alembic_version")
                if alembic_version == import_alembic_version:
                    if sanity_test:
                        errors = cherrypy.request.db.import_data_sanity_test(import_data=import_data)
                        if errors:
                            self.logger.error("Failed Sanity Import: %s" % errors)
                            response["error_message"] = errors
                            return response
                    del import_data["alembic_version"]
                    response = cherrypy.request.db.import_data(import_data=import_data, replace=(event.get("replace", True)))
                    self.logger.info("Completed Data Import")
                else:
                    msg = "Invalid alembic version. Expecting (%s) Got (%s)" % (alembic_version, import_alembic_version)
                    self.logger.error(msg)
                    response["error_message"] = msg
            else:
                msg = "Invalid Request. Missing required parameters"
                self.logger.error(msg)
                response["error_message"] = msg
            return response

        @cherrypy.tools.json_in()
        @cherrypy.tools.json_out()
        @cherrypy.expose
        @Unauthenticated()
        def register_component(self, token=None):
            response = {}
            event = cherrypy.request.json
            target_component = event.get("target_component")
            target_token = event.get("registration_token")
            target_type = target_component.get("type").lower()
            if token is None:
                token = event.get("token")
            authorized = False
            registration_token = self._db.get_config_setting_value("auth", "registration_token")
            if target_token and registration_token and registration_token == target_token:
                authorized = True
            elif not (token and len(token.split(".")) == 3):
                if not target_token or len(target_token.split(".")) == 3:
                    token = token if token else target_token
                    pub_cert = str.encode(self._db.get_config_setting_value("auth", "api_public_cert"))
                    decoded_jwt = jwt.decode(token, pub_cert, algorithm="RS256")
                    if "authorizations" in decoded_jwt:
                        for authorization in decoded_jwt["authorizations"]:
                            if JWT_AUTHORIZATION.is_authorized(authorization, [JWT_AUTHORIZATION.SERVER_AGENT]):
                                if not not target_type == "server_agent":
                                    pass
                                if JWT_AUTHORIZATION.is_authorized(authorization, [JWT_AUTHORIZATION.GUAC]):
                                    if target_type == "connection_proxy":
                                        pass
                                    authorized = True

                    if not authorized:
                        self.logger.error(f"Invalid JWT token utilized on register_component: {decoded_jwt}")
                elif token and target_type == "connection_proxy" and "id" in target_component:
                    component_id = target_component.get("id")
                    connection_proxy = cherrypy.request.db.get_connection_proxy(component_id)
                    if connection_proxy:
                        if connection_proxy.auth_token == token:
                            authorized = True
                        else:
                            self.logger.error(f"Invalid auth token for connection_proxy ({component_id}).")
                    else:
                        self.logger.error(f"Connection Proxy by id ({component_id}) not found to look up auth_token.")
                else:
                    self.logger.error("Unable to find valid registration token, auth token, or JWT")
            if target_component and "type" in target_component:
                if authorized:
                    if target_type == "connection_proxy":
                        connection_proxy = None
                        component_id = target_component.get("id")
                        zone_id = target_component.get("zone_id")
                        zone_name = target_component.get("zone_name")
                        server_address = target_component.get("server_address")
                        if component_id:
                            connection_proxy = cherrypy.request.db.get_connection_proxy(connection_proxy_id=component_id)
                        if not zone_id or zone_name:
                            zone = cherrypy.request.db.getZone(zone_name=zone_name)
                            if zone:
                                zone_id = zone.zone_id
                            else:
                                self.logger.warning(f"Zone ({zone_name}) does not exist! Creating Zone.")
                                zone = cherrypy.request.db.createZone(zone_name=zone_name)
                                zone_id = zone.zone_id
                        else:
                            zones = cherrypy.request.db.getZones()
                            if len(zones) == 1:
                                zone_id = zones[0].zone_id
                        if not server_address:
                            if "X-Forwarded-For" in cherrypy.request.headers:
                                server_address = cherrypy.request.headers["X-Forwarded-For"]
                            else:
                                server_address = cherrypy.request.remote.ip
                        server_port = target_component["server_port"] if "server_port" in target_component else 443
                        connection_proxy_type = target_component["connection_proxy_type"] if "connection_proxy_type" in target_component else "GUAC"
                        if connection_proxy:
                            cherrypy.request.db.update_connection_proxy(connection_proxy=connection_proxy,
                              server_address=server_address,
                              server_port=server_port,
                              connection_proxy_type=connection_proxy_type,
                              zone_id=zone_id,
                              auth_token=None)
                        elif not zone_id or connection_proxy is None:
                            msg = "Component registration failed, a Zone ID was not provided and more than one zone exists."
                            self.logger.error(msg)
                            response["error_message"] = msg
                        else:
                            connection_proxy = cherrypy.request.db.create_connection_proxy(server_address=server_address,
                              server_port=server_port,
                              connection_proxy_type=connection_proxy_type,
                              zone_id=zone_id,
                              connection_proxy_id=component_id,
                              auth_token=None)
                        if connection_proxy:
                            response["connection_proxy"] = cherrypy.request.db.serializable(connection_proxy.jsonDict)
                            response["connection_proxy"]["public_jwt_cert"] = self._db.get_config_setting_value("auth", "api_public_cert")
                            priv_key = str.encode(cherrypy.request.db.get_config_setting("auth", "api_private_key").value)
                            response["connection_proxy"]["auth_token"] = generate_jwt_token({"connection_proxy_id": (str(connection_proxy.connection_proxy_id))},
                              [
                             JWT_AUTHORIZATION.GUAC],
                              priv_key,
                              expires_days=365)
                    elif target_type == "server_agent":
                        server_id = target_component.get("id")
                        service_status = target_component.get("service_status")
                        server = cherrypy.request.db.getServer(server_id)
                        if server:
                            if server.agent_installed:
                                if server.operational_status not in (SERVER_OPERATIONAL_STATUS.DESTROYING,):
                                    old_status = server.operational_status
                                    server = cherrypy.request.db.update_server(server, operational_status=(SERVER_OPERATIONAL_STATUS.RUNNING.value))
                                    self.logger.debug(f"Agent has checked on on Server ({server_id}), status changed from ({old_status}) to (running)")
                                    response["operational_status"] = SERVER_OPERATIONAL_STATUS.RUNNING.value
                                    server_agent = {}
                                    priv_key = str.encode(self._db.get_config_setting_value("auth", "api_private_key"))
                                    server_agent["agent_jwt_token"] = generate_jwt_token({"server_id": server_id}, [JWT_AUTHORIZATION.SERVER_AGENT], priv_key, expires_days=1095)
                                    if "auto_configure" in target_component:
                                        if target_component["auto_configure"]:
                                            if "hostname" in target_component:
                                                hostname = target_component["hostname"] if target_component["hostname"] else server_id
                                                server_agent["public_jwt_cert"] = self._db.get_config_setting_value("auth", "api_public_cert")
                                                cert_and_key = generate_ssl_certs(hostname, days=3650)
                                                server_agent["server_cert"] = cert_and_key[1]
                                                server_agent["server_key"] = cert_and_key[0]
                                                server_agent["multi_user"] = False if server.max_simultaneous_sessions <= 1 else True
                                                if server.connection_username:
                                                    server_agent["user_sso"] = True if ("{sso_username}" in server.connection_username) or (server.connection_username == "{sso_create_user}") else False
                                                if old_status == SERVER_OPERATIONAL_STATUS.RUNNING.value:
                                                    if service_status:
                                                        if service_status == "running":
                                                            for kasm in server.kasms:
                                                                if kasm.operational_status in (SESSION_OPERATIONAL_STATUS.REQUESTED.value,
                                                                 SESSION_OPERATIONAL_STATUS.PROVISIONING.value,
                                                                 SESSION_OPERATIONAL_STATUS.ASSIGNED.value,
                                                                 SESSION_OPERATIONAL_STATUS.STARTING.value):
                                                                    self.logger.info(f"Server ({server.server_id}) has checked in, launching session ({kasm.kasm_id}) with current status of {kasm.operational_status}")
                                                                    self.provider_manager.get_session_from_server(image=(kasm.image),
                                                                      server=server,
                                                                      user=(kasm.user),
                                                                      user_ip=None,
                                                                      cast_config=(kasm.cast_config),
                                                                      user_language=None,
                                                                      user_timezone=None,
                                                                      queued_kasm=kasm)

                                                        response["server_agent"] = server_agent
                                                if server.agent_installed:
                                                    msg = f"Attempt to register a server agent for a server ({server_id}), which is being destroyed."
                                                    self.logger.info(msg)
                                                    response["error_message"] = "Access Denied!"
                                                else:
                                                    msg = f"Attempt to register a server agent for a server ({server_id}) that is not supposed to have an agent installed."
                                                    self.logger.error(msg)
                                                    response["error_message"] = "Access Denied!"
                                    msg = f"Attempt to register a server agent for a non-existing server ({server_id})"
                                    self.logger.error(msg)
                                    response["error_message"] = "Access Denied!"
                        msg = f"Attempt to register an invalid component ({target_type})."
                        self.logger.error(msg)
                        response["error_message"] = "Access Denied!"
                else:
                    msg = "Unauthorized attempt to register a component."
                    self.logger.error(msg)
                    response["error_message"] = "Access Denied!"
            else:
                msg = f"Invalid Request. Missing required parameters: {event}"
                self.logger.error(msg)
                response["error_message"] = "Access Denied!"
            return response

        def available_architectures(self):
            arch_normalizer = {'aarch64':"arm64", 
             'amd64':"amd64", 
             'x86_64':"amd64"}
            archs = []
            servers = self._get_servers()
            if "servers" in servers:
                for server in servers["servers"]:
                    if isinstance(server["docker_info"], dict):
                        arch = arch_normalizer.get(server["docker_info"].get("Architecture"))
                        if arch not in archs:
                            archs.append(arch)

                return archs

        def addSlash(self, path):
            if not path.endswith("/"):
                path += "/"
            return path

        @cherrypy.expose
        @cherrypy.tools.json_in()
        @cherrypy.tools.json_out()
        @Authenticated(requested_actions=[JWT_AUTHORIZATION.REGISTRIES_VIEW], read_only=True)
        def get_registries(self):
            response = {'registries':[],  'architectures':[]}
            refresh = False
            archs = self.available_architectures()
            response["architectures"] = archs
            registries = cherrypy.request.db.get_registries()
            for (i, _registry) in enumerate(registries):
                if not _registry.config:
                    registry_url = self.addSlash(_registry.registry_url)
                    try:
                        update_registry = self._create_registry(registry_url, True, _registry.registry_id)
                        if "error_message" in update_registry:
                            raise Exception(update_registry["error_message"])
                        refresh = True
                    except Exception as e:
                        try:
                            response["error_message"] = "There was a problem importing a registry"
                            del registries[i]
                            self.logger.error(registry_url + " - " + str(e))
                        finally:
                            e = None
                            del e

            if refresh:
                registries = cherrypy.request.db.get_registries()
            for _registry in registries:
                registry_url = self.addSlash(_registry.registry_url)
                registry = {}
                registry["registry_id"] = _registry.registry_id
                registry["registry_url"] = registry_url
                registry["do_auto_update"] = _registry.do_auto_update
                registry["schema_version"] = _registry.schema_version
                registry["is_verified"] = _registry.is_verified
                registry["workspaces"] = _registry.workspaces
                config = _registry.config
                del config["workspaces"]
                registry["config"] = config
                response["registries"].append(registry)

            response = cherrypy.request.db.serializable(response)
            return response

        @cherrypy.expose
        @cherrypy.tools.json_in()
        @cherrypy.tools.json_out()
        @Authenticated(requested_actions=[JWT_AUTHORIZATION.REGISTRIES_CREATE], read_only=False)
        def create_registry(self):
            response = {}
            event = cherrypy.request.json
            if "registry" in event:
                return self._create_registry(self.addSlash(event["registry"]))
            msg = "Invalid Request. Missing required parameters"
            self.logger.error(msg)
            response["error_message"] = msg
            return response

        def _create_registry(self, registry_url, update=False, registry_id=None):
            valid_schema = "1.0"
            current_schema = ""
            response = {}
            try:
                versions = urllib.request.urlopen((registry_url + "versions.txt"), cafile=(certifi.where()))
            except urllib.error.HTTPError as e:
                response["error_message"] = "This registry does not appear to have a valid schema list"
                return response
            except (urllib.error.URLError, ValueError) as e:
                response["error_message"] = "A valid url needs to be entered"
                return response
            else:
                for version in versions.read().decode("utf-8").splitlines():
                    if version == valid_schema:
                        current_schema = version
                        break

                if current_schema != valid_schema:
                    response["error_message"] = "This registry does not appear to have a compatible schema version available"
                    return response
                with urllib.request.urlopen((registry_url + current_schema + "/list.json"), cafile=(certifi.where())) as url:
                    data = json.load(url)
                    if all((k in data for k in ('name', 'icon', 'description', 'list_url',
                                                'workspaces'))):
                        if registry_id:
                            alreadyexists = cherrypy.request.db.get_registry(registry_id)
                        else:
                            alreadyexists = cherrypy.request.db.get_registry_by_url(data["list_url"])
                        if not alreadyexists:
                            try:
                                new_registry = cherrypy.request.db.create_registry(schema_version=current_schema,
                                  config=data)
                                response["registry"] = cherrypy.request.db.serializable(new_registry.jsonDict)
                            except Exception as e:
                                try:
                                    response["error_message"] = str(e)
                                finally:
                                    e = None
                                    del e

                        elif update:
                            try:
                                update = {}
                                update["config"] = data
                                update["registry_url"] = data["list_url"]
                                update_registry = cherrypy.request.db.update_registry(registry_id=(alreadyexists.registry_id),
                                  update=update)
                                response["registry"] = cherrypy.request.db.serializable(update_registry.jsonDict)
                            except Exception as e:
                                try:
                                    response["error_message"] = str(e)
                                    self.logger.error(e)
                                finally:
                                    e = None
                                    del e

                        else:
                            response["error_message"] = "This Registry has already been installed."
                    else:
                        response["error_message"] = "This does not look like a valid registry."
            return response

        @cherrypy.expose
        @cherrypy.tools.json_in()
        @cherrypy.tools.json_out()
        @Authenticated(requested_actions=[JWT_AUTHORIZATION.REGISTRIES_MODIFY], read_only=False)
        def update_registry(self):
            response = {}
            event = cherrypy.request.json
            if "registry_id" in event:
                try:
                    registry = cherrypy.request.db.get_registry(event["registry_id"])
                    try:
                        update_registry = self._create_registry(registry.registry_url, True)
                        response["registry"] = update_registry
                    except Exception as e:
                        try:
                            response["error_message"] = "There was a problem updating the registry"
                            self.logger.error(e)
                        finally:
                            e = None
                            del e

                except Exception as e:
                    try:
                        response["error_message"] = "There was a problem finding the registry " + event["registry_id"]
                    finally:
                        e = None
                        del e

            else:
                response["error_message"] = "Missing Registry ID"
            return response

        @cherrypy.expose
        @cherrypy.tools.json_in()
        @cherrypy.tools.json_out()
        @Authenticated(requested_actions=[JWT_AUTHORIZATION.REGISTRIES_MODIFY], read_only=False)
        def registry_auto_updates(self):
            response = {}
            event = cherrypy.request.json
            if "registry_id" in event and "auto_updates" in event:
                try:
                    registry = cherrypy.request.db.get_registry(event["registry_id"])
                    try:
                        update = {}
                        update["do_auto_update"] = event["auto_updates"]
                        update_registry = cherrypy.request.db.update_registry(registry_id=(registry.registry_id),
                          update=update)
                        response["registry"] = cherrypy.request.db.serializable(update_registry.jsonDict)
                    except Exception as e:
                        try:
                            response["error_message"] = "There was a problem updating the registry"
                            self.logger.error(e)
                        finally:
                            e = None
                            del e

                except Exception as e:
                    try:
                        response["error_message"] = "There was a problem finding the registry " + event["registry_id"]
                    finally:
                        e = None
                        del e

            else:
                response["error_message"] = "Missing Registry ID"
            return response

        @cherrypy.expose
        @cherrypy.tools.json_in()
        @cherrypy.tools.json_out()
        @Authenticated(requested_actions=[JWT_AUTHORIZATION.REGISTRIES_DELETE], read_only=False)
        def delete_registry(self):
            response = {}
            event = cherrypy.request.json
            if "registry_id" in event:
                self._delete_registry(event["registry_id"])
            else:
                response["error_message"] = "Missing Registry ID"
            return response

        def _delete_registry(self, registry_id):
            api = cherrypy.request.db.get_registry(registry_id)
            cherrypy.request.db.delete_registry(api)

        @cherrypy.expose
        @cherrypy.tools.json_in()
        @cherrypy.tools.json_out()
        @Authenticated(requested_actions=[JWT_AUTHORIZATION.STORAGE_PROVIDERS_VIEW], read_only=True)
        def get_storage_providers(self):
            response = {}
            storage_providers = cherrypy.request.db.get_storage_providers()
            response["storage_providers"] = [cherrypy.request.db.serializable(x.jsonDict) for x in storage_providers]
            return response

        @cherrypy.expose
        @cherrypy.tools.json_in()
        @cherrypy.tools.json_out()
        @Authenticated(requested_actions=[JWT_AUTHORIZATION.STORAGE_PROVIDERS_CREATE])
        def create_storage_provider(self):
            response = {}
            event = cherrypy.request.json
            target_storage_provider = event.get("target_storage_provider", {})
            storage_provider_type = target_storage_provider.get("storage_provider_type")
            if target_storage_provider and storage_provider_type:
                try:
                    STORAGE_PROVIDER_TYPES(storage_provider_type)
                except ValueError:
                    msg = "Invalid storage_provider_type (%s)" % storage_provider_type
                    self.logger.error(msg)
                    response["error_message"] = msg
                    return response
                else:
                    for json_prop in ('scope', ):
                        if json_prop in target_storage_provider:
                            if target_storage_provider[json_prop] == "":
                                target_storage_provider[json_prop] = []
                            else:
                                target_storage_provider[json_prop] = parse_multiline_input((target_storage_provider[json_prop]),
                                  to_lower=False)
                        target_storage_provider = process_json_props(data=target_storage_provider, dict_props=[
                         "auth_url_options",
                         "volume_config",
                         "mount_config"],
                          list_props=[
                         "scope"],
                          not_empty_props=[])
                        valid = False
                        error_message = False

                if storage_provider_type == STORAGE_PROVIDER_TYPES.NEXTCLOUD.value:
                    (valid, error_message) = Nextcloud.validate_storage_provider(target_storage_provider)
                elif storage_provider_type == STORAGE_PROVIDER_TYPES.GOOGLE_DRIVE.value:
                    (valid, error_message) = GoogleDrive.validate_storage_provider(target_storage_provider)
                elif storage_provider_type == STORAGE_PROVIDER_TYPES.ONEDRIVE.value:
                    (valid, error_message) = OneDrive.validate_storage_provider(target_storage_provider)
                elif storage_provider_type == STORAGE_PROVIDER_TYPES.DROPBOX.value:
                    (valid, error_message) = Dropbox.validate_storage_provider(target_storage_provider)
                elif storage_provider_type == STORAGE_PROVIDER_TYPES.S3.value:
                    (valid, error_message) = S3.validate_storage_provider(target_storage_provider)
                elif storage_provider_type == STORAGE_PROVIDER_TYPES.CUSTOM.value:
                    (valid, error_message) = CustomStorageProvider.validate_storage_provider(target_storage_provider)
                else:
                    self.logger.error("No validation routine defined for storage_provider_type: %s" % storage_provider_type)
                if valid:
                    storage_provider = cherrypy.request.db.create_storage_provider(name=(target_storage_provider.get("name")),
                      storage_provider_type=(target_storage_provider.get("storage_provider_type")),
                      client_id=(target_storage_provider.get("client_id")),
                      client_secret=(target_storage_provider.get("client_secret")),
                      auth_url=(target_storage_provider.get("auth_url")),
                      token_url=(target_storage_provider.get("token_url")),
                      webdav_url=(target_storage_provider.get("webdav_url")),
                      scope=(target_storage_provider.get("scope")),
                      redirect_url=(target_storage_provider.get("redirect_url")),
                      auth_url_options=(target_storage_provider.get("auth_url_options")),
                      volume_config=(target_storage_provider.get("volume_config")),
                      mount_config=(target_storage_provider.get("mount_config")),
                      root_drive_url=(target_storage_provider.get("root_drive_url")),
                      default_target=(target_storage_provider.get("default_target")),
                      enabled=(target_storage_provider.get("enabled")))
                    response["storage_provider"] = cherrypy.request.db.serializable(storage_provider.jsonDict)
                    self.logger.info(("Successfully created storage_provider_id (%s)" % storage_provider.storage_provider_id),
                      extra={"storage_provider_id": (storage_provider.storage_provider_id)})
                else:
                    msg = "Invalid Request. %s" % error_message
                    self.logger.error(msg)
                    response["error_message"] = msg
            else:
                msg = "Invalid Request. Missing required parameters"
                self.logger.error(msg)
                response["error_message"] = msg
            return response

        @cherrypy.expose
        @cherrypy.tools.json_in()
        @cherrypy.tools.json_out()
        @Authenticated(requested_actions=[JWT_AUTHORIZATION.STORAGE_PROVIDERS_MODIFY])
        def update_storage_provider(self):
            response = {}
            event = cherrypy.request.json
            target_storage_provider = event.get("target_storage_provider", {})
            storage_provider_id = target_storage_provider.get("storage_provider_id")
            storage_provider_type = target_storage_provider.get("storage_provider_type")
            if storage_provider_id:
                storage_provider = cherrypy.request.db.get_storage_provider(storage_provider_id=storage_provider_id)
                if storage_provider:
                    for json_prop in ('scope', ):
                        if json_prop in target_storage_provider:
                            if target_storage_provider[json_prop] == "":
                                target_storage_provider[json_prop] = []
                            else:
                                target_storage_provider[json_prop] = parse_multiline_input((target_storage_provider[json_prop]),
                                  to_lower=False)
                        data = process_json_props(data=target_storage_provider, dict_props=[
                         "auth_url_options",
                         "volume_config",
                         "mount_config"],
                          list_props=[
                         "scope"],
                          not_empty_props=[])

                    if target_storage_provider:
                        storage_provider = cherrypy.request.db.update_storage_provider(storage_provider=storage_provider,
                          storage_provider_type=(target_storage_provider.get("storage_provider_type")),
                          client_id=(target_storage_provider.get("client_id")),
                          client_secret=(target_storage_provider.get("client_secret")),
                          auth_url=(target_storage_provider.get("auth_url")),
                          token_url=(target_storage_provider.get("token_url")),
                          webdav_url=(target_storage_provider.get("webdav_url")),
                          scope=(data.get("scope")),
                          redirect_url=(target_storage_provider.get("redirect_url")),
                          auth_url_options=(data.get("auth_url_options")),
                          volume_config=(data.get("volume_config")),
                          mount_config=(data.get("mount_config")),
                          root_drive_url=(target_storage_provider.get("root_drive_url")),
                          default_target=(target_storage_provider.get("default_target")),
                          enabled=(target_storage_provider.get("enabled")))
                        response["storage_provider"] = cherrypy.request.db.serializable(storage_provider.jsonDict)
                        self.logger.info(("Successfully updated storage_provider_id (%s)" % storage_provider.storage_provider_id),
                          extra={"storage_provider_id": (storage_provider.storage_provider_id)})
                else:
                    msg = "No storage provider found with id (%s)" % storage_provider_id
                    self.logger.error(msg)
                    response["error_message"] = msg
            else:
                msg = "Invalid Request. Missing required parameters"
                self.logger.error(msg)
                response["error_message"] = msg
            return response

        @cherrypy.expose
        @cherrypy.tools.json_in()
        @cherrypy.tools.json_out()
        @Authenticated(requested_actions=[JWT_AUTHORIZATION.STORAGE_PROVIDERS_DELETE])
        def delete_storage_provider(self):
            response = {}
            event = cherrypy.request.json
            target_storage_provider = event.get("target_storage_provider", {})
            storage_provider_id = target_storage_provider.get("storage_provider_id")
            if storage_provider_id:
                storage_provider = cherrypy.request.db.get_storage_provider(storage_provider_id=storage_provider_id)
                if storage_provider:
                    cherrypy.request.db.delete_storage_provider(storage_provider)
                    self.logger.info(("Successfully deleted storage_provider_id (%s)" % storage_provider_id),
                      extra={"storage_provider_id": storage_provider_id})
                else:
                    msg = "No storage provider with id (%s) found" % storage_provider_id
                    self.logger.error(msg)
                    response["error_message"] = msg
            else:
                msg = "Invalid Request. Missing required parameters"
                self.logger.error(msg)
                response["error_message"] = msg
            return response

        @cherrypy.expose
        @cherrypy.tools.json_in()
        @cherrypy.tools.json_out()
        @Authenticated(requested_actions=[JWT_AUTHORIZATION.GLOBAL_ADMIN], read_only=True)
        def get_permissions(self):
            response = {}
            response["permissions"] = []
            for permission in JWT_AUTHORIZATION:
                if int(permission) >= 100:
                    response["permissions"].append({'name':str(permission), 
                     'permission_id':int(permission), 
                     'friendly_name':(permission.get_friendly_name)(), 
                     'description':permission.description})
                return response

        @cherrypy.expose
        @cherrypy.tools.json_in()
        @cherrypy.tools.json_out()
        @Authenticated(requested_actions=[JWT_AUTHORIZATION.GLOBAL_ADMIN], read_only=False)
        def add_permissions_group(self):
            return self._add_permissions_group()

        def _add_permissions_group(self, replace=False):
            response = {}
            event = cherrypy.request.json
            target_group = event.get("target_group")
            target_api_config = event.get("target_api_config")
            target_permissions = event.get("target_permissions")
            failed_permissions_applied = 0
            if target_permissions:
                for permission_id in target_permissions:
                    if not JWT_AUTHORIZATION.is_valid_value(permission_id):
                        msg = f"The specified permission id ({permission_id}) is invalid."
                        self.logger.error(msg)
                        response["error_message"] = msg
                        cherrypy.response.status = 400
                        return response

                if target_groupand "group_id" in target_group and "group_id" in target_group and target_permissions:
                    group = cherrypy.request.db.getGroup(target_group["group_id"])
                    if group is not None:
                        if replace:
                            for current_permission in group.permissions:
                                cherrypy.request.db.delete_group_permission(current_permission)

                            response["permissions"] = []
                            for permission_id in target_permissions:
                                permission = JWT_AUTHORIZATION(permission_id)
                                if not group.has_permission(permission):
                                    gp = cherrypy.request.db.create_group_permission(permission, group_id=(group.group_id))
                                    response["permissions"].append(cherrypy.request.db.serializable(gp.jsonDict))
                                else:
                                    failed_permissions_applied += 1
                                    self.logger.info(f'The group ({target_group["group_id"]}) already has the permission ({permission}).')

                    else:
                        msg = "The specified group does not exist."
                        self.logger.error(msg)
                        response["error_message"] = msg
                        cherrypy.response.status = 400
                elif target_api_config and "api_id" in target_api_config and target_permissions:
                    api = cherrypy.request.db.getApiConfig(target_api_config["api_id"])
                    if api:
                        if replace:
                            for current_permission in api.permissions:
                                cherrypy.request.db.delete_group_permission(current_permission)

                            response["permissions"] = []
                            for permission_id in target_permissions:
                                permission = JWT_AUTHORIZATION(permission_id)
                                if not api.has_permission(permission):
                                    gp = cherrypy.request.db.create_group_permission(permission, api_id=(api.api_id))
                                    response["permissions"].append(cherrypy.request.db.serializable(gp.jsonDict))
                                else:
                                    failed_permissions_applied += 1
                                    self.logger.info(f'The API Config ({target_api_config["api_id"]}) already has the permission ({permission}).')

                    else:
                        msg = f'The specified API config ({target_api_config["api_id"]}) does not exist.'
                        self.logger.error(msg)
                        response["error_message"] = msg
                        cherrypy.response.status = 400
                else:
                    msg = "Invalid request, missing required value."
                    self.logger.error(msg)
                    response["error_message"] = msg
                    cherrypy.response.status = 400
                if failed_permissions_applied > 0:
                    response["error_message"] = f"{len(target_permissions) - failed_permissions_applied} permissions added, {failed_permissions_applied} already part of the group."
                return response

        @cherrypy.expose
        @cherrypy.tools.json_in()
        @cherrypy.tools.json_out()
        @Authenticated(requested_actions=[JWT_AUTHORIZATION.GLOBAL_ADMIN], read_only=False)
        def replace_permissions_group(self):
            return self._add_permissions_group(True)

        @cherrypy.expose
        @cherrypy.tools.json_in()
        @cherrypy.tools.json_out()
        @Authenticated(requested_actions=[JWT_AUTHORIZATION.GLOBAL_ADMIN], read_only=False)
        def remove_permissions_group(self):
            response = {}
            event = cherrypy.request.json
            group_permission_id = event.get("group_permission_id")
            if group_permission_id:
                gp = cherrypy.request.db.get_group_permission(group_permission_id)
                if gp:
                    gp = cherrypy.request.db.delete_group_permission(gp)
                else:
                    msg = "The specified permission does not exist."
                    self.logger.error(msg)
                    response["error_message"] = msg
                    cherrypy.response.status = 400
            else:
                msg = "Invalid request, missing required value."
                self.logger.error(msg)
                response["error_message"] = msg
                cherrypy.response.status = 400
            return response

        @cherrypy.expose
        @cherrypy.tools.json_in()
        @cherrypy.tools.json_out()
        @Authenticated(requested_actions=[JWT_AUTHORIZATION.GLOBAL_ADMIN], read_only=True)
        def get_permissions_group(self):
            response = {}
            event = cherrypy.request.json
            target_group = event.get("target_group")
            target_api_config = event.get("target_api_config")
            if target_group and "group_id" in target_group and target_group["group_id"] != "":
                group = cherrypy.request.db.getGroup(target_group["group_id"])
                if group is not None:
                    response["permissions"] = [cherrypy.request.db.serializable(x.jsonDict) for x in group.permissions if x.permission]
            elif target_api_config:
                if "api_id" in target_api_config:
                    api = cherrypy.request.db.getApiConfig(target_api_config["api_id"])
                    if api is not None:
                        response["permissions"] = [cherrypy.request.db.serializable(x.jsonDict) for x in api.permissions if x.permission]
            return response

        @cherrypy.expose
        @cherrypy.tools.json_out()
        @cherrypy.tools.json_in()
        @Authenticated(requested_actions=[JWT_AUTHORIZATION.SESSION_RECORDINGS_VIEW], read_only=True)
        def get_session_recording(self):
            return self._get_session_recordings()

        def _get_session_recordings(self, public=False):
            response = {}
            object_storage = None
            event = cherrypy.request.json
            target_kasm_id = event.get("target_kasm_id")
            preauth_download_link = event.get("preauth_download_link", False)
            page = event.get("page", 1)
            pages = 1
            per_page = 5
            total_duration = 0
            total = 0
            if preauth_download_link:
                object_storage_key = cherrypy.request.db.get_config_setting_value("session_recording", "recording_object_storage_key")
                object_storage_secret = cherrypy.request.db.get_config_setting_value("session_recording", "recording_object_storage_secret")
                if object_storage_key and object_storage_secret:
                    credentials = {'aws_access_key_id':object_storage_key, 
                     'aws_secret_access_key':object_storage_secret}
                    object_storage = AwsObjectStorageProvider(cherrypy.request.db, self.logger, credentials)
                else:
                    self.logger.error("Request for session recording download url failed, Object Storage credentials are not configured on the server settings.")
                    response["error_message"] = "Invalid Request. Missing required settings"
                    if public:
                        cherrypy.response.status = 400
                    return response
            if target_kasm_id:
                accounting = cherrypy.request.db.getAccounting(kasm_id=target_kasm_id)
                if accounting is None:
                    msg = "Invalid Kasm ID"
                    self.logger.error(msg)
                    response["error_message"] = msg
                    if public:
                        cherrypy.response.status = 400
                    return response
                response["session_recordings"] = []
                session_recordings_sorted = deepcopy(accounting.session_recordings)
                session_recordings_sorted.sort(key=(lambda x: list(os.path.split(urlparse(x.session_recording_url).path))[-1].rsplit(".", 2)[-2]))
                total = len(session_recordings_sorted)
                pages = math.ceil(total / per_page)
                for session_recording in session_recordings_sorted:
                    total_duration += session_recording.session_recording_metadata["duration"]

                session_recordings_sorted_paged = []
                for i in range(0, total, per_page):
                    session_recordings_sorted_paged.append(session_recordings_sorted[i:i + per_page])

                for session_recording in session_recordings_sorted_paged[page - 1]:
                    session_dict = session_recording.jsonDict
                    if preauth_download_link:
                        try:
                            session_dict["session_recording_download_url"] = object_storage.request_download_file(session_recording.session_recording_url)
                        except Exception as error:
                            try:
                                session_dict["session_recording_download_url"] = "error"
                            finally:
                                error = None
                                del error

                        else:
                            response["session_recordings"].append(cherrypy.request.db.serializable(session_dict))

                self.logger.info((create_session_recording_request_log(cherrypy.request, [accounting])), extra={'metric_name':"sessions.session_history.request_session_recordings", 
                 'username':cherrypy.request.authenticated_user.username if (cherrypy.request.authenticated_user) else None, 
                 'api_key_id':cherrypy.request.api_key_id if (hasattr(cherrypy.request, "api_key_id")) else None, 
                 'number_of_accountings_requested':1, 
                 'total_cloud_urls_requested':len(response["session_recordings"]) if preauth_download_link else 0})
            else:
                msg = "Invalid Request. Missing required parameters"
                self.logger.error(msg)
                response["error_message"] = msg
                if public:
                    cherrypy.response.status = 400
            response["items"] = total
            response["page"] = page
            response["per_page"] = per_page
            response["total_duration"] = total_duration
            return response

        @cherrypy.expose
        @cherrypy.tools.json_out()
        @cherrypy.tools.json_in()
        @Authenticated(requested_actions=[JWT_AUTHORIZATION.SESSION_RECORDINGS_VIEW], read_only=True)
        def get_sessions_recordings(self):
            return self._get_sessions_recordings()

        def _get_sessions_recordings(self, public=False):
            response = {}
            object_storage = None
            event = cherrypy.request.json
            target_kasm_ids = event.get("target_kasm_ids", [])
            preauth_download_link = event.get("preauth_download_link", False)
            if preauth_download_link:
                object_storage_key = cherrypy.request.db.get_config_setting_value("session_recording", "recording_object_storage_key")
                object_storage_secret = cherrypy.request.db.get_config_setting_value("session_recording", "recording_object_storage_secret")
                if object_storage_key and object_storage_secret:
                    credentials = {'aws_access_key_id':object_storage_key, 
                     'aws_secret_access_key':object_storage_secret}
                    object_storage = AwsObjectStorageProvider(cherrypy.request.db, self.logger, credentials)
                else:
                    self.logger.error("Request for session recording download url failed, Object Storage credentials are not configured on the server settings.")
                    response["error_message"] = "Invalid Request. Missing required settings"
                    if public:
                        cherrypy.response.status = 400
                    return response
            if target_kasm_ids:
                accountings = cherrypy.request.db.getAccountings(kasm_ids=target_kasm_ids)
                response["kasm_sessions"] = {}
                cloud_storage_links = 0
                for account in accountings:
                    response["kasm_sessions"].setdefault(str(account.kasm_id), {})["session_recordings"] = []
                    session_recordings_sorted = deepcopy(account.session_recordings)
                    session_recordings_sorted.sort(key=(lambda x: list(os.path.split(urlparse(x.session_recording_url).path))[-1].rsplit(".", 2)[-2]))
                    for session_recording in session_recordings_sorted:
                        session_dict = session_recording.jsonDict
                        if preauth_download_link:
                            try:
                                session_dict["session_recording_download_url"] = object_storage.request_download_file(session_recording.session_recording_url)
                            except Exception as error:
                                try:
                                    session_dict["session_recording_download_url"] = "error"
                                finally:
                                    error = None
                                    del error

                            else:
                                cloud_storage_links += 1
                            response["kasm_sessions"][str(account.kasm_id)]["session_recordings"].append(cherrypy.request.db.serializable(session_dict))

                self.logger.info((create_session_recording_request_log(cherrypy.request, accountings)), extra={'metric_name':"sessions.session_history.request_session_recordings", 
                 'username':cherrypy.request.authenticated_user.username if (cherrypy.request.authenticated_user) else None, 
                 'api_key_id':cherrypy.request.api_key_id if (hasattr(cherrypy.request, "api_key_id")) else None, 
                 'number_of_accountings_requested':len(accountings), 
                 'total_cloud_urls_requested':cloud_storage_links})
            else:
                msg = "Invalid Request. Missing required parameters"
                self.logger.error(msg)
                response["error_message"] = msg
                if public:
                    cherrypy.response.status = 400
            return response

        @cherrypy.expose
        @cherrypy.tools.json_in()
        @cherrypy.tools.json_out()
        @Authenticated(requested_actions=[JWT_AUTHORIZATION.SESSIONS_VIEW], read_only=True)
        def get_session_history(self):
            response = {}
            event = cherrypy.request.json
            preauth_download_link = event.get("preauth_download_link", False)
            filters = event.get("filters", [])
            or_filters = event.get("or_filters", [])
            object_storage = None
            if preauth_download_link:
                if JWT_AUTHORIZATION.is_authorized_action(cherrypy.request.authorizations, JWT_AUTHORIZATION.SESSION_RECORDINGS_VIEW):
                    object_storage_key = cherrypy.request.db.get_config_setting_value("session_recording", "recording_object_storage_key")
                    object_storage_secret = cherrypy.request.db.get_config_setting_value("session_recording", "recording_object_storage_secret")
                    if object_storage_key:
                        if object_storage_secret:
                            credentials = {'aws_access_key_id':object_storage_key, 
                             'aws_secret_access_key':object_storage_secret}
                            object_storage = AwsObjectStorageProvider(cherrypy.request.db, self.logger, credentials)
                        error_message = ""
                        for filter_ in [*filters]:
                            if filter_["id"] == "kasm_id":
                                try:
                                    uuid.UUID(filter_["value"])
                                except ValueError:
                                    error_message = "Invalid kasm ID"
                                else:
                                    if filter_["id"] == "cast_config_id":
                                        try:
                                            uuid.UUID(filter_["value"])
                                        except ValueError:
                                            error_message = "Invalid cast config ID"
                                        else:
                                            if filter_["id"] == "staging_config_id":
                                                try:
                                                    uuid.UUID(filter_["value"])
                                                except ValueError:
                                                    error_message = "Invalid staging config ID"
                                                else:
                                                    if filter_["id"] == "created_date":
                                                        if not isinstance(filter_["value"], dict):
                                                            error_message = "Created date filter is not a dict"
                                                        if isinstance(filter_["value"], dict):
                                                            if "from" not in filter_["value"].keys() or "to" not in filter_["value"].keys():
                                                                error_message = "Invalid created date ranges"
                                                        if not filter_["id"] == "destroyed_date":
                                                            if not isinstance(filter_["value"], dict):
                                                                error_message = "Destroyed date filter is not a dict"
                                                        if isinstance(filter_["value"], dict):
                                                            if "from" not in filter_["value"].keys() or "to" not in filter_["value"].keys():
                                                                error_message = "Invalid destroyed date ranges"
                                                            if error_message:
                                                                response["error_message"] = error_message
                                                                return response
                                    updated_or_filters = []

                        for filter_ in [
                         *or_filters]:
                            if filter_["id"] in ('kasm_id', 'cast_config_id', 'staging_config_id',
                                                 'zone_name'):
                                try:
                                    uuid.UUID(filter_["value"])
                                except ValueError:
                                    while True:
                                        pass

                                else:
                                    updated_or_filters.append(filter_)

                        accountings = cherrypy.request.db.getAccountings(page=(event["page"] if "page" in event else None), page_size=(event["page_size"] if "page_size" in event else None),
                          filters=filters,
                          or_filters=updated_or_filters,
                          sort_by=(event["sort_by"] if "sort_by" in event else None),
                          sort_direction=(event["sort_direction"] if "sort_direction" in event else "desc"))
                        accountings_count = cherrypy.request.db.getAccountingsCount(filters=filters, or_filters=updated_or_filters)
                        sessions = []
                        cloud_storage_links = 0
                        if accountings:
                            for accounting in accountings:
                                recordings = []
                                if JWT_AUTHORIZATION.is_authorized_action(cherrypy.request.authorizations, JWT_AUTHORIZATION.SESSION_RECORDINGS_VIEW):
                                    session_recordings_sorted = deepcopy(accounting.session_recordings)
                                    session_recordings_sorted.sort(key=(lambda x: list(os.path.split(urlparse(x.session_recording_url).path))[-1].rsplit(".", 2)[-2]))
                                    for recording in session_recordings_sorted:
                                        recording_dict = recording.jsonDict
                                        if object_storage:
                                            if preauth_download_link:
                                                recording_dict["session_recording_download_url"] = object_storage.request_download_file(recording.session_recording_url)
                                                cloud_storage_links += 1
                                            recordings.append(cherrypy.request.db.serializable(recording_dict))
                                        session = cherrypy.request.db.serializable(accounting.jsonDict)

                                    if recordings:
                                        session["session_recordings"] = recordings
                                    sessions.append(session)

                    if JWT_AUTHORIZATION.is_authorized_action(cherrypy.request.authorizations, JWT_AUTHORIZATION.SESSION_RECORDINGS_VIEW):
                        if object_storage:
                            if preauth_download_link:
                                self.logger.info((create_session_recording_request_log(cherrypy.request, accountings)), extra={'metric_name':"sessions.session_history.request_session_recordings", 
                                 'username':cherrypy.request.authenticated_user.username if (cherrypy.request.authenticated_user) else None, 
                                 'api_key_id':cherrypy.request.api_key_id if (hasattr(cherrypy.request, "api_key_id")) else None, 
                                 'number_of_accountings_requested':len(accountings), 
                                 'total_cloud_urls_requested':cloud_storage_links})
            response["sessions"] = cherrypy.request.db.serializable(sessions)
            response["total"] = accountings_count
            if "page" in event:
                response["page"] = event["page"] if event["page"] >= 0 else 0
                return response

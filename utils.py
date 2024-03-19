# decompyle3 version 3.9.1
# Python bytecode version base 3.8.0 (3413)
# Decompiled from: Python 3.8.18 (default, Aug 25 2023, 13:20:30) 
# [GCC 11.4.0]
# Embedded file name: utils.py
import hashlib, hmac, ipaddress, json, logging, logging.config, re, threading, time
from datetime import datetime, timedelta, date
import cherrypy, jwt, requests, simplejson, stripe
from cachetools.func import ttl_cache
from dateutil.relativedelta import relativedelta as relativedelta
from data.enums import SESSION_OPERATIONAL_STATUS, JWT_AUTHORIZATION, SKU
from data.data_utils import is_sanitized

class ConnectionError(Exception):
    pass


class JsonValidationException(Exception):
    pass


class RequestContextFilter(logging.Filter):

    def filter(self, record):
        properties = [
         "kasm_user_name","kasm_user_id","kasm_id","kasm_image_name","kasm_image_friendly_name","api_key",
         "path_info", "query_string", "api_key_id", "api_key_name", "is_api"]
        for x in properties:
            val = getattr(cherrypy.request, x, None)
            if val:
                setattr(record, x, val)
            client_ip = getattr(cherrypy.request, "authenticated_user_ip", None)

        if client_ip:
            client_ip = client_ip.split(",")[0].strip()
            record.request_ip = client_ip
        else:
            if "X-Forwarded-For" in cherrypy.request.headers:
                ip = cherrypy.request.headers["X-Forwarded-For"]
            else:
                ip = cherrypy.request.remote.ip
            record.request_ip = ip
        if "User-Agent" in cherrypy.request.headers:
            record.user_agent = cherrypy.request.headers["User-Agent"]
        return True


def is_valid_email_address(address):
    return re.match("^([a-zA-Z0-9_\\-\\.\\+]+)@((\\[[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.)|(([a-zA-Z0-9\\-]+\\.)+))([a-zA-Z]{2,4}|[0-9]{1,3}|local)(\\]?)$", address, re.M | re.I)


@ttl_cache(maxsize=2000, ttl=30)
def validate_api_key(api_key, api_key_secret, update_last_used):
    return cherrypy.request.db.validateApiKey(api_key, api_key_secret, update_last_used)


@ttl_cache(maxsize=2000, ttl=10)
def validate_session_token_ex(token, username):
    return cherrypy.request.db.validateSessionToken(token, username)


@ttl_cache(maxsize=2000, ttl=600)
def is_developer_api_licensed(logger):
    license_helper = LicenseHelper(cherrypy.request.db, logger)
    return license_helper.is_developer_api_ok()


class Unauthenticated(object):

    def __call__(self, func, *args, **kwargs):
        fname = func.__name__

        def wrapper(self, token=None, *params, **kwargs):
            cherrypy.request.authorizations = []
            cherrypy.request.authenticated_user = None
            cherrypy.request.session_token_id = None
            cherrypy.request.kasm_user_id = None
            cherrypy.request.kasm_user_name = None
            cherrypy.request.kasm = None
            cherrypy.request.impersonated = False
            cherrypy.request.internal = False
            if "X-Forwarded-For" in cherrypy.request.headers:
                cherrypy.request.clientip = cherrypy.request.headers["X-Forwarded-For"]
            else:
                cherrypy.request.clientip = cherrypy.request.remote.ip
            self.logger.debug(f"Unauthenticated user made authorized API call to ({fname}) from IP address ({cherrypy.request.clientip}).")
            if token:
                return func(self, *params, token=token, **kwargs)
            return func(self)

        return wrapper


class Authenticated(object):

    def __init__(self, requested_actions=None, kasm=False, read_only=False, pass_unauthenticated=False):
        if requested_actions is None:
            requested_actions = []
        self.requested_actions = requested_actions
        self.kasm = kasm
        self.read_only = read_only
        self.pass_unauthenticated = pass_unauthenticated

    def __call__(self, func, *args, **kwargs):
        func._requested_actions = self.requested_actions
        func._kasm = self.kasm
        func._read_only = self.read_only
        func._pass_unauthenticated = self.pass_unauthenticated

        def new_func(self):
            event = cherrypy.request.json
            cherrypy.request.is_api = False
            username = event.get("username")
            token = event.get("token")
            kasm_id = event.get("kasm_id")
            api_key = cherrypy.request.headers.get("api-key")
            if not api_key:
                api_key = event.get("api_key")
            api_key_secret = cherrypy.request.headers.get("api-key-secret")
            if not api_key_secret:
                api_key_secret = event.get("api_key_secret")
            response = dict()
            if "X-Forwarded-For" in cherrypy.request.headers:
                cherrypy.request.clientip = cherrypy.request.headers["X-Forwarded-For"]
            else:
                cherrypy.request.clientip = cherrypy.request.remote.ip
            ip = cherrypy.request.clientip
            cherrypy.request.authorizations = []
            cherrypy.request.authenticated_user = None
            cherrypy.request.session_token_id = None
            cherrypy.request.kasm_user_id = None
            cherrypy.request.kasm_user_name = None
            cherrypy.request.authenticated_user_ip = ip
            cherrypy.request.kasm = None
            cherrypy.request.impersonated = False
            cherrypy.request.internal = False
            if api_key:
                if api_key_secret:
                    if is_developer_api_licensed(self.logger):
                        api = cherrypy.request.db.getApiConfigByKey(api_key)
                        api_key_valid = validate_api_key(api_key, api_key_secret, update_last_used=True)
                        if api and api_key_valid:
                            cherrypy.request.is_api = True
                            cherrypy.request.api_key_name = api.name
                            cherrypy.request.api_key_id = api.api_id
                            cherrypy.request.authorizations = api.get_authorizations()
                            if func._read_only is False:
                                if api.read_only:
                                    response["error_message"] = "Unauthorized"
                                    self.logger.warning("Read-Only API Key (%s) attempted access to non Read-Only API (%s) at (%s)" % (
                                     api_key, func.__name__, ip))
                                    cherrypy.response.status = 401
                                    return response
                                if "user_id" in event:
                                    if JWT_AUTHORIZATION.is_authorized_action(cherrypy.request.authorizations, JWT_AUTHORIZATION.USERS_AUTH_SESSION):
                                        user = cherrypy.request.db.get_user_by_id(event["user_id"])
                                        if user:
                                            cherrypy.request.authenticated_user = user
                                            cherrypy.request.kasm_user_id = str(user.user_id)
                                            cherrypy.request.kasm_user_name = user.username
                                        else:
                                            msg = "Invalid user_id (%s)" % event["user_id"]
                                            self.logger.error(msg)
                                            response["error_message"] = msg
                                            cherrypy.response.status = 400
                                            return response
                                    else:
                                        msg = f"API Key ({api.name}) is not authorized to impersonate a user."
                                        self.logger.error(msg)
                                        response["error_message"] = msg
                                        cherrypy.response.status = 401
                                        return response
                                if "kasm_id" in event:
                                    kasm = cherrypy.request.db.getKasm(kasm_id)
                                    if kasm:
                                        cherrypy.request.authenticated_kasm = kasm
                                    else:
                                        msg = "Invalid kasm_id (%s)" % event["kasm_id"]
                                        self.logger.error(msg)
                                        response["error_message"] = msg
                                        cherrypy.response.status = 400
                                        return response
                                if JWT_AUTHORIZATION.any_authorized_actions(cherrypy.request.authorizations, func._requested_actions):
                                    self.logger.debug("Successfully authenticated request (%s) for API (%s) at (%s) for user (%s)" % (
                                     func.__name__, api_key, ip, cherrypy.request.kasm_user_name))
                                    return func(self)
                                self.logger.error(f"API Key ({api.name}) attempted to call ({func.__name__}) with improper authorization.")
                                response["error_message"] = "Unauthorized"
                                cherrypy.response.status = 401
                                return response
                        else:
                            if api and api.expires < datetime.utcnow():
                                self.logger.warning(f"API Key ({api.name}) has expired.")
                                response["error_message"] = "Access has expired"
                                cherrypy.response.status = 401
                            else:
                                cherrypy.response.status = 403
                                response["error_message"] = "Access Denied"
                                self.logger.warning("Invalid Api Key/Secret for (%s) at (%s) for request (%s)" % (
                                 api_key, ip, func.__name__))
                            return response
                    else:
                        self.logger.error("Developer Api is configured but not licensed")
                        response["error_message"] = "Access Denied. This feature is not licensed"
                        cherrypy.response.status = 403
                        return response
                if func._kasm:
                    if kasm_id:
                        kasm = cherrypy.request.db.getKasm(kasm_id)
                        if kasm:
                            username = ""
                            if kasm.user:
                                user = cherrypy.request.db.getUser(kasm.user.username)
                                cherrypy.request.authenticated_user = user
                                cherrypy.request.kasm_user_id = str(user.user_id)
                                cherrypy.request.kasm_user_name = user.username
                                username = user.username
                            cherrypy.request.authenticated_kasm = kasm
                            self.logger.debug("Successfully authenticated request (%s) for user (%s) at (%s)" % (
                             func.__name__, username, ip))
                            return func(self)
                        self.logger.error("Invalid kasm_id (%s) from (%s) for request (%s)" % (
                         kasm_id, ip, func.__name__))
                        response["error"] = "Access Denied"
                        cherrypy.response.status = 403
                    else:
                        self.logger.warning("Authenticated request missing required kasm_id from (%s)" % ip)
                        response["error"] = "Access Denied"
                        cherrypy.response.status = 403
                elif username and token:
                    is_valid_token = False
                    try:
                        pub_cert = str.encode(cherrypy.request.db.get_config_setting_value_cached("auth", "api_public_cert"))
                        decoded_jwt = jwt.decode(token, pub_cert, algorithm="RS256")
                        session_token_id = decoded_jwt["session_token_id"]
                        if func._read_only:
                            is_valid_token = validate_session_token_ex(session_token_id, event["username"])
                        else:
                            is_valid_token = cherrypy.request.db.validateSessionToken(session_token_id, event["username"])
                    except jwt.exceptions.ExpiredSignatureError as ex:
                        self.logger.warn(f"Expired JWT token used for authenticated request: {ex}")
                        response["error_message"] = "Access Denied"
                        cherrypy.response.status = 403
                        return response
                    except jwt.exceptions.DecodeError as ex:
                        self.logger.warn(f"Invalid JWT token used for authenticated request: {ex}")
                        response["error_message"] = "Access Denied"
                        cherrypy.response.status = 403
                        return response

                    if is_valid_token:
                        user = cherrypy.request.db.getUser(username)
                        if user is not None:
                            cherrypy.request.authenticated_user = user
                            cherrypy.request.session_token_id = session_token_id
                            for authorization in decoded_jwt["authorizations"]:
                                cherrypy.request.authorizations.append(JWT_AUTHORIZATION(authorization))

                            cherrypy.request.kasm_user_id = str(user.user_id)
                            cherrypy.request.kasm_user_name = user.username
                            if user.locked:
                                self.logger.warning("User (%s) is locked out. Rejecting Request" % username)
                                response["error_message"] = "Access Denied"
                                cherrypy.response.status = 403
                            elif user.disabled:
                                self.logger.warning("User (%s) is disabled. Rejecting Request" % username)
                                response["error_message"] = "Access Denied"
                                cherrypy.response.status = 403
                            elif JWT_AUTHORIZATION.any_authorized_actions(cherrypy.request.authorizations, func._requested_actions):
                                if user.plan_id and not JWT_AUTHORIZATION.any_admin_action(func._requested_actions):
                                    if user.plan_end_date > datetime.utcnow():
                                        stripe.api_key = cherrypy.request.db.get_config_setting_value("subscription", "stripe_private_key")
                                        sub = stripe.Subscription.retrieve(user.subscription_id)
                                        if sub["status"] == "active":
                                            self.logger.debug("Successfully authenticated request (%s) for user (%s) at (%s)" % (
                                             func.__name__, username, ip))
                                            return func(self)
                                        self.logger.warning("User %s Subscription has ended." % user.username)
                                        return func(self)
                                    else:
                                        self.logger.debug("Successfully authenticated request (%s) for user (%s) at (%s)" % (
                                         func.__name__, username, ip))
                                        return func(self)
                                else:
                                    self.logger.debug("Successfully authenticated request (%s) for user (%s) at (%s)" % (
                                     func.__name__, username, ip))
                                    return func(self)
                            else:
                                self.logger.error(f"User ({username}) attempted to call ({func.__name__}) with improper authorization.")
                                response["error_message"] = "Unauthorized"
                                response["ui_show_error"] = not (JWT_AUTHORIZATION.is_readonly_actions(func._requested_actions) and func._read_only)
                                cherrypy.response.status = 401
                        else:
                            self.logger.warning("Invalid username (%s) at (%s) for request (%s)" % (
                             username, ip, func.__name__))
                            response["error_message"] = "Access Denied"
                            cherrypy.response.status = 403
                    else:
                        self.logger.warning("Invalid token (%s) for user (%s) at (%s) for request (%s)" % (
                         token, username, ip, func.__name__))
                        response["error_message"] = "Access Denied"
                        cherrypy.response.status = 403
                else:
                    if func._pass_unauthenticated:
                        return func(self)
                    self.logger.warning("Authenticated request missing required username or token values from (%s)" % ip)
                    response["error_message"] = "Invalid Request"
                    cherrypy.response.status = 400
                return response

        return new_func


class JwtAuthenticated:

    def __init__(self, authorizations):
        self.authorizations = authorizations

    def __call__(self, func, *args, **kwargs):
        func._authorizations = self.authorizations

        def wrapper(self, token=None):
            response = {}
            authorized = False
            if token is None:
                token = cherrypy.request.json.get("token")
            if token:
                try:
                    pub_cert = str.encode(cherrypy.request.db.get_config_setting_value_cached("auth", "api_public_cert"))
                    cherrypy.request.decoded_jwt = jwt.decode(token, pub_cert, algorithm="RS256")
                    authorized = False
                    if "authorizations" in cherrypy.request.decoded_jwt:
                        for authorization in cherrypy.request.decoded_jwt["authorizations"]:
                            if JWT_AUTHORIZATION.is_authorized(authorization, func._authorizations):
                                authorized = True

                    if authorized:
                        response = func(self, *args, **kwargs)
                    else:
                        self.logger.error(f"JWT token did not contain required authorization: {cherrypy.request.decoded_jwt} to call ({func.__name__})")
                        cherrypy.request.decoded_jwt = None
                        response["error_message"] = "Unauthorized Action"
                        cherrypy.response.status = 401
                        return response
                except jwt.exceptions.DecodeError:
                    self.logger.error("Error decoding JWT token")
                    response["error_message"] = "Access Denied."
                    cherrypy.response.status = 403
                    return response
                except jwt.exceptions.ExpiredSignatureError:
                    self.logger.error("Error, expired JWT token")
                    response["error_message"] = "Access Denied."
                    cherrypy.response.status = 403
                    return response

            else:
                self.logger.warning(f"JWT token missing from request to {func.__name__}")
                response["error_message"] = "JWT token missing from request"
            return response

        return wrapper


class CookieAuthenticated(object):

    def __init__(self, requested_actions=None):
        if requested_actions is None:
            requested_actions = []
        self.requested_actions = requested_actions

    def __call__(self, func, *args, **kwargs):
        func._requested_actions = self.requested_actions

        def wrapper(self, **params):
            response = {}
            if "X-Forwarded-For" in cherrypy.request.headers:
                cherrypy.request.clientip = cherrypy.request.headers["X-Forwarded-For"]
            else:
                cherrypy.request.clientip = cherrypy.request.remote.ip
            ip = cherrypy.request.clientip
            username = cherrypy.request.cookie.get("username")
            token = cherrypy.request.cookie.get("session_token")
            session_token_id = None
            if username:
                if token:
                    username = username.value
                    token = token.value
                    try:
                        pub_cert = str.encode(cherrypy.request.db.get_config_setting_value_cached("auth", "api_public_cert"))
                        decoded_jwt = jwt.decode(token, pub_cert, algorithm="RS256")
                        session_token_id = decoded_jwt["session_token_id"]
                    except jwt.exceptions.ExpiredSignatureError as ex:
                        self.logger.warn(f"Expired JWT token used for authenticated request: {ex}")
                        response["error_message"] = "Access Denied"
                        cherrypy.response.status = 403
                        return response
                    except jwt.exceptions.DecodeError as ex:
                        self.logger.warn(f"Invalid JWT token used for authenticated request: {ex}")
                        response["error_message"] = "Access Denied"
                        cherrypy.response.status = 403
                        return response
                    else:
                        cherrypy.request.authorizations = []
                        cherrypy.request.authenticated_user = None
                        cherrypy.request.session_token_id = None
                        cherrypy.request.kasm_user_id = None
                        cherrypy.request.kasm_user_name = None
                        cherrypy.request.authenticated_user_ip = ip
                        cherrypy.request.kasm = None
                        cherrypy.request.impersonated = False
                        cherrypy.request.internal = False
                        for authorization in decoded_jwt["authorizations"]:
                            cherrypy.request.authorizations.append(JWT_AUTHORIZATION(authorization))

                        if "kasm_id" in decoded_jwt:
                            kasm_id = decoded_jwt["kasm_id"]
                            cherrypy.request.kasm = cherrypy.request.db.getKasm(kasm_id)
                            if cherrypy.request.kasm:
                                if str(cherrypy.request.kasm.api_token) == session_token_id:
                                    if "impersonate_user" in decoded_jwt:
                                        if decoded_jwt["impersonate_user"]:
                                            cherrypy.request.authenticated_user = cherrypy.request.kasm.user
                                            cherrypy.request.user_id = cherrypy.request.kasm.user.user_id
                                            cherrypy.request.user_name = cherrypy.request.kasm.user.username
                                            cherrypy.request.impersonated = True
                                            cherrypy.request.internal = True
                                        cherrypy.request.session_token_id = session_token_id
                                        return func(self, **params)
                                    if not cherrypy.request.kasm:
                                        self.logger.warning(f"Cookie authentication attempt with invalid kasm_id ({kasm_id})")
                                        cherrypy.response.status = 401
                                        return response
                                    self.logger.error(f"Cookie authentication attempt to kasm session ({kasm_id}) with an invalid token.")
                                    cherrypy.response.status = 401
                                    return response
                            if validate_session_token_ex(session_token_id, username):
                                if JWT_AUTHORIZATION.any_authorized_actions(cherrypy.request.authorizations, func._requested_actions):
                                    user = cherrypy.request.db.getUser(username)
                                    if user is not None:
                                        cherrypy.request.authenticated_user = user
                                        cherrypy.request.session_token_id = session_token_id
                                        cherrypy.request.kasm_user_id = str(user.user_id)
                                        cherrypy.request.kasm_user_name = user.username
                                        if user.locked:
                                            self.logger.warning("User (%s) is locked out. Rejecting Request" % username)
                                            cherrypy.response.status = 401
                                            response["error_message"] = "Access Denied"
                                        elif user.disabled:
                                            self.logger.warning("User (%s) is disabled. Rejecting Request" % username)
                                            cherrypy.response.status = 401
                                            response["error_message"] = "Access Denied"
                                        else:
                                            return func(self, **params)
                                    else:
                                        self.logger.error(f"User ({username}) not found.")
                                        response["error_message"] = "Access Denied."
                                        cherrypy.response.status = 401
                                        return response
                                else:
                                    self.logger.error(f"User ({username}) not authorized for action {func._requested_actions}")
                                    response["error_message"] = "Access Denied."
                                    cherrypy.response.status = 401
                                    return response
                            else:
                                self.logger.error("Error, invalid authentication cookies")
                                response["error_message"] = "Access Denied."
                                cherrypy.response.status = 403
                                return response
                    self.logger.error("Error, missing authenticate cookies")
                    response["error_message"] = "Access Denied."
                    cherrypy.response.status = 403
                    return response
                return response

        return wrapper


def func_timing(func):

    def wrapper_function(self, *args, **kwargs):
        t1 = time.time()
        result = func(self, *args, **kwargs)
        seconds = time.time() - t1
        if hasattr(self, "logger"):
            module = func.__module__ if hasattr(func, "__module__") else None
            name = func.__name__ if hasattr(func, "__name__") else None
            self.logger.debug(("Function (%s.%s) executed in (%s) seconds" % (module, name, seconds)), extra={
              'metric_name': "timing.function",
              'timing.module_name': module,
              'timing.function_name': name,
              'timing.seconds': seconds})
        return result

    return wrapper_function


def getRequestJson(request):
    cl = request.headers["Content-Length"]
    rawbody = request.body.read(int(cl))
    body = simplejson.loads(rawbody)
    return body


def validate_volume_config(config):
    ret = None
    required_keys = ["bind", "mode", "uid", "gid"]
    valid_modes = ["rw", "ro"]
    for (k, v) in config.items():
        if not set(required_keys).issubset(set(v.keys())):
            return "Config %s is missing one or more required options %s" % (k, set(required_keys) - set(v.keys()))
        else:
            if not isinstance(v["uid"], int):
                return "uid must be an integer"
            if not isinstance(v["gid"], int):
                return "gid must be an integer"
            if v["mode"] not in valid_modes:
                return "mode must be either %s" % valid_modes
            timeout = v.get("timeout")
        if not timeout != None:
            if not not isinstance(timeout, float):
                if not isinstance(timeout, int):
                    return "timeout must be an number"
                if timeout <= 0:
                    return "timeout must be greater than 0"
                required = v.get("required")
                if not required != None:
                    if not isinstance(required, bool):
                        return "required must be a bool"
                    return ret


def validate_launch_config(config):
    required_launch_form_keys = {
      'key': str,
      'label': str,
      'value': str,
      'allow_saving': bool,
      'placeholder': str,
      'required': bool,
      'help': str,
      'input_type': str,
      'options': list,
      'validator_regex': str,
      'validator_regex_description': str,
      'display_if': list}
    if config:
        if "file_mapping" in config:
            if "destination" not in config["file_mapping"]:
                return "Missing destination in file_mapping section"
        else:
            return "Missing file_mapping section"
        if "launch_form" in config:
            launch_form = config["launch_form"]
            if type(launch_form) == list:
                for form_item in launch_form:
                    for (k, form_type) in required_launch_form_keys.items():
                        if k in form_item:
                            if form_item[k] and type(form_item[k]) != form_type:
                                return "%s is not of type %s" % (k, form_type)
                            else:
                                return "Required property %s is not in launch_form item : %s" % (k, form_item)

            else:
                return "launch_form must be a list"
        else:
            return "Missing launch_form section"


def generate_jwt_token(data, authorizations, private_key, expires_minutes=None, expires_hours=None, expires_days=None):
    exp_date = None
    if expires_minutes:
        exp_date = datetime.utcnow() + timedelta(minutes=(int(expires_minutes)))
    elif expires_hours:
        exp_date = datetime.utcnow() + timedelta(hours=(int(expires_hours)))
    elif expires_days:
        exp_date = datetime.utcnow() + timedelta(days=(int(expires_days)))
    else:
        raise ValueError("JWT token requires an expiration to be defined.")
    data["exp"] = exp_date
    if not (authorizations and isinstance(authorizations, list)):
        raise ValueError("JWT token requires authorization.")
    data["authorizations"] = []
    for authorization in authorizations:
        data["authorizations"].append(int(authorization.value))

    return jwt.encode(data, private_key, algorithm="RS256").decode("UTF-8")


def generate_guac_client_secret(installation_id, user_id):
    installation_id_bytes = installation_id.replace("-", "").encode("ascii")
    user_id_bytes = user_id.replace("-", "").encode("ascii")
    secret_bytes = installation_id_bytes + user_id_bytes
    secret_hashed = hashlib.sha256()
    secret_hashed.update(secret_bytes)
    return secret_hashed.hexdigest()


def passwordComplexityCheck(password, min_len=8, require_lower=True, require_upper=True, require_special=True, require_numbers=True):
    if password is None:
        password = ""
    length_error = len(password) < min_len
    digit_error = require_numbers and re.search("\\d", password) is None
    uppercase_error = require_upper and re.search("[A-Z]", password) is None
    lowercase_error = require_lower and re.search("[a-z]", password) is None
    symbol_error = require_special and re.search('[ !#@$%&\'()*+,-./[\\\\\\]^_`{|}~"]', password) is None
    message = ""
    if digit_error:
        message = "Your password must contain at least one number."
    elif length_error:
        message = "Your password must be at least {} characters long".format(min_len)
    elif symbol_error:
        message = "Your password must contain at least one special character."
    elif lowercase_error:
        message = "Your password must contain at least one lower case character."
    elif uppercase_error:
        message = "Your password must contain at least one upper case character."
    response = not length_error and not digit_error and not uppercase_error and {'status':(not lowercase_error) and (not symbol_error),  'message':message}
    return response


class EffectiveLicense:

    def __init__(self, limit, license_type, licensed, features, license_sku):
        self.limit = limit
        self.license_type = license_type
        self.license_sku = license_sku
        self.licensed = licensed
        self.features = features

    def dump(self):
        return {'limit':self.limit, 
         'license_type':self.license_type, 
         'license_sku':self.license_sku, 
         'licensed':self.licensed, 
         'features':self.features}


PER_NAMED_USER = "Per Named User"
PER_CONCURRENT_KASM = "Per Concurrent Kasm"
DEFAULT_FEATURES = [
 "session_staging",
 "session_casting",
 "log_forwarding",
 "developer_api",
 "inject_ssh_keys",
 "saml",
 "ldap",
 "sso",
 "allow_kasm_sharing",
 "login_banner",
 "usage_limit"]
DEFAULT_EFFECTIVE_LICENSE = EffectiveLicense(limit=5, license_type=PER_CONCURRENT_KASM, licensed=False, features=DEFAULT_FEATURES, license_sku=(SKU.STANDARD.value))

class LicenseHelper:

    def __init__(self, db, logger):
        self.db = db
        self.logger = logger
        self.effective_license = self.get_effective_license()

    def get_effective_license(self):
        limit = 0
        license_type = None
        license_sku = None
        features = set()
        for license in self.db.getLicenses():
            if license.is_verified:
                license_type = license.license_type
                license_sku = license.sku
                limit += license.limit
            if license.is_legacy:
                for default_feature in DEFAULT_FEATURES:
                    features.add(default_feature)

                for (feature_name, enabled) in license.features.items():
                    if enabled:
                        features.add(feature_name)

        if limit and license_type:
            res = EffectiveLicense(limit, license_type, True, list(features), license_sku)
        else:
            res = DEFAULT_EFFECTIVE_LICENSE
        return res

    def is_licensed(self):
        return self.effective_license.limit and self.effective_license.license_type

    def is_per_named_user(self):
        return self.effective_license.license_type == PER_NAMED_USER

    def is_per_named_user_ok(self, with_user_added=False):
        if not self.is_licensed():
            return False
        if self.is_per_named_user():
            remaining_users = self.remaining_per_named_user()
            if not with_user_added:
                return remaining_users >= 0
            return remaining_users > 0
        else:
            return True

    def is_branding_ok(self):
        return "branding" in self.effective_license.features

    def is_auto_scaling_ok(self):
        return "auto_scaling" in self.effective_license.features

    def is_url_categorization_ok(self):
        return "url_categorization" in self.effective_license.features

    def is_casting_ok(self):
        return "session_casting" in self.effective_license.features

    def is_staging_ok(self):
        return "session_staging" in self.effective_license.features

    def is_developer_api_ok(self):
        return "developer_api" in self.effective_license.features

    def is_sso_ok(self):
        return "saml" in self.effective_license.features or "oidc" in self.effective_license.features or "ldap" in self.effective_license.features or "sso" in self.effective_license.features

    def is_inject_ssh_keys_ok(self):
        return "inject_ssh_keys" in self.effective_license.features

    def is_allow_kasm_sharing_ok(self):
        return "inject_ssh_keys" in self.effective_license.features

    def is_usage_limit_ok(self):
        return "usage_limit" in self.effective_license.features

    def is_login_banner_ok(self):
        return "login_banner" in self.effective_license.features

    def is_log_forwarding_ok(self):
        return "log_forwarding" in self.effective_license.features

    def is_session_recording_ok(self):
        feature_ok = "session_recording" in self.effective_license.features
        if not feature_ok:
            feature_ok = self.effective_license.license_sku == SKU.ENTERPRISE
        return feature_ok

    def remaining_per_named_user(self):
        if self.is_per_named_user():
            users = self.db.getUsers()
            res = self.effective_license.limit - len(users)
            self.logger.debug("License Check: Current Users (%s) , License Limit (%s) , Remaining (%s)" % (
             len(users),
             self.effective_license.limit,
             res))
            return res
        raise Exception("This license is not per named user")

    def is_per_concurrent_kasm(self):
        return self.effective_license.license_type == PER_CONCURRENT_KASM

    def is_per_concurrent_kasm_ok(self):
        # return True # uncomment to bypass
        if not self.is_licensed():
            return False
        if self.is_per_concurrent_kasm():
            remaining_kasms = self.remaining_per_concurrent_kasms()
            return remaining_kasms > 0
        return True

    def remaining_per_concurrent_kasms(self):
        # return 999999 # uncomment to bypass
        if self.is_per_concurrent_kasm():
            kasms = self.db.get_kasms(operational_status=(SESSION_OPERATIONAL_STATUS.RUNNING.value))
            res = self.effective_license.limit - len(kasms)
            self.logger.debug("License Check: Current Kasms (%s) , License Limit (%s) , Remaining (%s)" % (
             len(kasms),
             self.effective_license.limit,
             res))
            return res
        raise Exception("This license is not per named user")

    def get_limit_remaining(self):
        # return 999999 # uncomment to bypass
        if self.is_per_concurrent_kasm():
            return self.remaining_per_concurrent_kasms()
        return self.remaining_per_named_user()


def check_usage(user):
    (used_hours, hours, dates) = get_hours(user)
    if used_hours is not None:
        if hours - used_hours <= 0:
            return False
        return True


def get_usage(user):
    override_ttl = 60
    (used_hours, hours, dates) = get_hours(user, override_ttl)
    return (
     used_hours, dates)


usage_cache = {}
usage_lock = threading.Lock()

def get_hours(user, override_ttl=None):

    def get_user_hours():
        hour_count = cherrypy.request.db.getUserAccountSummary(user.user_id, dates["start_date"], dates["end_date"])
        max_kasms = user.get_setting_value("max_kasms_per_user", 2)
        ttl = get_ttl(hour_count, max_kasms)
        usage_lock.acquire()
        try:
            usage_cache[(user.user_id, dates["start_date"])] = [
             hour_count, datetime.utcnow(), ttl]
        finally:
            usage_lock.release()

        return hour_count

    def get_group_hours():
        user_ids = cherrypy.request.db.getGroup(group_id).get_user_ids()
        hour_count = cherrypy.request.db.getGroupAccountsSummary(group_id, dates["start_date"], dates["end_date"], user_ids)
        ttl = get_ttl(hour_count, len(user_ids))
        usage_lock.acquire()
        try:
            usage_cache[(group_id, dates["start_date"])] = [
             hour_count, datetime.utcnow(), ttl]
        finally:
            usage_lock.release()

        return hour_count

    def get_ttl(hour_count, _max=None):
        percent_used = hour_count / hours
        if percent_used < 0.5:
            ttl = hours * 0.05 * 3600
        elif percent_used < 0.85:
            ttl = hours * 0.01 * 3600
        else:
            ttl = 60
        if _max is not None:
            return ttl / _max
        if ttl > 60:
            return ttl
        return 60

    limit = user.get_setting_value("usage_limit", False)
    if limit:
        usage_type = limit["type"]
        interval = limit["interval"]
        hours = limit["hours"]
        dates = get_interval(interval)
        if usage_type == "per_user":
            if (
             user.user_id, dates["start_date"]) in usage_cache:
                cached = usage_cache[(user.user_id, dates["start_date"])]
                actual_ttl = override_ttl if override_ttl is not None else cached[2]
                if (datetime.utcnow() - cached[1]).total_seconds() < actual_ttl:
                    used_hours = cached[0]
                else:
                    used_hours = get_user_hours()
            else:
                used_hours = get_user_hours()
        else:
            group_id = user.get_setting_group_id("usage_limit")
            if (group_id, dates["start_date"]) in usage_cache:
                cached = usage_cache[(group_id, dates["start_date"])]
                actual_ttl = override_ttl if override_ttl is not None else cached[2]
                if (datetime.utcnow() - cached[1]).total_seconds() < actual_ttl:
                    used_hours = cached[0]
                else:
                    used_hours = get_group_hours()
            else:
                used_hours = get_group_hours()
        return (
         used_hours, hours, dates)
    return (None, None, None)


def validate_usage_limit(config):
    ret = None
    required_keys = {"type", "interval", "hours"}
    valid_type = ["per_user", "per_group"]
    valid_interval = ["daily", "weekly", "monthly", "total"]
    if not required_keys.issubset(set(config.keys())):
        return "Usage Limitis missing one or more required options %s" % (set(required_keys) - set(config.keys()))
    if config["type"] not in valid_type:
        return "type must be either %s" % valid_type
    if config["interval"] not in valid_interval:
        return "type must be either %s" % valid_interval
    hours = config.get("hours")
    if hours is not None:
        if not isinstance(hours, float):
            if not isinstance(hours, int):
                return "hours must be a number"
        if hours <= 0:
            return "hours must be greater than 0"
        return ret


def get_interval(interval):
    if interval == "monthly":
        start_date = datetime.utcnow().replace(day=1).strftime("%Y-%m-%d 00:00:00")
        end_date = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        next_start_date = (datetime.utcnow() + relativedelta(months=1, day=1)).strftime("%Y-%m-%d 00:00:00")
    elif interval == "weekly":
        today = datetime.utcnow()
        s = today - timedelta(days=(today.isoweekday()))
        start_date = s.strftime("%Y-%m-%d 00:00:00")
        end_date = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        next_start_date = (s + timedelta(weeks=1)).strftime("%Y-%m-%d 00:00:00")
    elif interval == "daily":
        s = datetime.utcnow()
        start_date = s.strftime("%Y-%m-%d 00:00:00")
        end_date = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        next_start_date = (s + timedelta(days=1)).strftime("%Y-%m-%d 00:00:00")
    else:
        start_date = date.min.strftime("%Y-%m-%d %H:%M:%S")
        end_date = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        next_start_date = date.min.strftime("%Y-%m-%d %H:%M:%S")
    response = {'start_date':start_date, 
     'end_date':end_date, 
     'next_start_date':next_start_date}
    return response


def update_hubspot_contact_by_email(api_key, email, data, logger):
    url = "https://api.hubapi.com/contacts/v1/contact/email/{email}/profile?hapikey={api_key}".format(api_key=api_key, email=email)
    headers = {}
    headers["Content-Type"] = "application/json"
    _data = json.dumps(data)
    logger.info("Sending hubspot url (%s) with data (%s)" % (url, data))
    r = requests.post(data=_data, url=url, headers=headers)
    return r


def generate_hmac(value, key):
    _hash = hmac.new(key,
      value,
      digestmod=(hashlib.sha256)).hexdigest()
    return _hash


def validate_overlapping_domains(domains):
    wildcard_domains = [x for x in domains if x.startswith(".")]
    conflicts = []
    for domain in domains:
        for wd in wildcard_domains:
            if wd == domain:
                continue
            else:
                if ("." + domain).endswith(wd):
                    conflicts.append("{} : {}".format(domain, wd))

        return conflicts


class IPAddressHelper:

    @staticmethod
    def convert_ipstr_long(ip_address):
        ip = ipaddress.ip_address(ip_address)
        return int(ip)

    @staticmethod
    def convert_long_ipstr(long_ip_address):
        ip = ipaddress.ip_address(long_ip_address)
        return str(ip)

    @staticmethod
    def parse_range(ip_address_range):
        ip_range_long = [
         0, 0]
        ip_address_range = ip_address_range.replace(" ", "")
        if re.match("^(\\d{1,3}\\.){3}\\d{1,3}(/(\\d{1,2}|(\\d{1,3}\\.){3}\\d{1,3}))?$", ip_address_range):
            ip = ipaddress.ip_network(ip_address_range)
            ip_range_long[0] = int(ip.network_address)
            ip_range_long[1] = int(ip.broadcast_address)
        elif re.match("^(\\d{1,3}\\.){3}\\d{1,3}-(\\d{1,3}\\.){3}\\d{1,3}$", ip_address_range):
            ipadds = ip_address_range.split("-")
            ip_range_long[0] = int(ipaddress.ip_address(ipadds[0]))
            ip_range_long[1] = int(ipaddress.ip_address(ipadds[1]))
        else:
            raise Exception("Invalid IP range format")
        if ip_range_long[0] > ip_range_long[1]:
            raise Exception("Invalid IP range")
        return ip_range_long

    @staticmethod
    def validate_ranges(ranges):
        for ip_range in ranges.split(","):
            IPAddressHelper.parse_range(ip_range)

    @staticmethod
    def get_next_ip(ip_range, exclusion_ranges, used_ips, is_range_subnet=True):
        ip_range_int = IPAddressHelper.parse_range(ip_range)
        if is_range_subnet:
            ip_range_int[0] = ip_range_int[0] + 2
            ip_range_int[1] = ip_range_int[1] - 1
        exclusion_ranges_arr = exclusion_ranges.replace(" ", "").split(",")
        for (i, s) in enumerate(exclusion_ranges_arr):
            exclusion_ranges_arr[i] = IPAddressHelper.parse_range(s)

        for (i, s) in enumerate(used_ips):
            used_ips[i] = int(ipaddress.ip_address(s))

        next_ip_int = 0
        for i in range(ip_range_int[0], ip_range_int[1], 1):
            if i not in used_ips:
                is_excluded = False
                for exclusion_range in exclusion_ranges_arr:
                    if i >= exclusion_range[0]:
                        if i <= exclusion_range[1]:
                            is_excluded = True
                            break

                if is_excluded == False:
                    next_ip_int = ipaddress.ip_address(i)
                    break

        if next_ip_int == 0:
            raise Exception("No available IP address available in range {0}".format(ip_range))
        return str(ipaddress.ip_address(next_ip_int))

    @staticmethod
    def validate_overlapping_addresses(addresses):
        errors = []
        network_objects = []
        for x in addresses:
            try:
                o = ipaddress.IPv4Network(x, strict=False)
                o.string_entry = x
                network_objects.append(o)
            except ipaddress.AddressValueError:
                errors.append("%s is not a valid IPv4 Address/Network" % x)

        for (index, a) in enumerate(network_objects):
            for b in network_objects[index + 1:]:
                if a.overlaps(b):
                    errors.append("%s overlaps %s" % (a.string_entry, b.string_entry))

            return errors


def validate_safe_search_patterns(patterns):
    try:
        patterns = json.loads(patterns)
    except Exception as e:
        try:
            raise Exception("Safe Search Patterns must be JSON: (%s)" % e)
        finally:
            e = None
            del e

    else:
        if type(patterns) != list:
            raise Exception("Safe Search Patterns must be a JSON list")
        else:
            keys = [
             "match", "name", "replace"]
        for pattern in patterns:
            if type(pattern) != dict:
                raise Exception("Each pattern in the list must be a dict: %s" % str(pattern))
            else:
                for k in keys:
                    if k not in pattern:
                        raise Exception("Missing key '%s' in pattern: %s" % (k, pattern))
                    if type(pattern[k]) != str:
                        raise Exception("Key '%s' must be a string: %s" % (k, pattern[k]))

                return patterns


def parse_multiline_input(input, to_lower=True):
    out = input.split("\n")
    out = list(dict.fromkeys(out))
    out = [x.strip() for x in out]
    if to_lower:
        out = [x.lower() for x in out]
    out = [x for x in out if x]
    return out


def validate_recaptcha(value, site, private_key):
    response = {'status':False, 
     'error_message':""}
    params = {'secret':private_key,  'response':value}
    res = requests.get(site, params=params, verify=True)
    res = res.json()
    if "success" in res and res["success"] == True:
        response["status"] = True
    elif "error-codes" in res:
        response["error_message"] = "Error in reCAPTCHA request: {0}".format(res["error-codes"])
    else:
        response["error_message"] = "Unknown reCAPTCHA error"
    return response


def process_json_props(list_props, dict_props, not_empty_props, data):
    ret = data.copy()
    for json_prop in dict_props + list_props:
        if json_prop in ret:
            if ret[json_prop] == "":
                if json_prop in list_props:
                    ret[json_prop] = []
                else:
                    ret[json_prop] = {}
            elif is_sanitized(ret[json_prop]):
                del ret[json_prop]
            else:
                try:
                    if type(ret[json_prop]) == str:
                        ret[json_prop] = json.loads(ret[json_prop])
                    if json_prop in list_props:
type(ret[json_prop]) != listValueError"%s is not JSON list" % json_prop                    elif type(ret[json_prop]) != dict:
                        raise ValueError("%s is not JSON dictionary" % json_prop)
                    if json_prop in not_empty_props:
                        if not json_prop:
                            raise ValueError("%s cannot be empty" % json_prop)
                except ValueError as e:
                    try:
                        msg = str(e)
                        raise JsonValidationException(msg)
                    finally:
                        e = None
                        del e

                except Exception as e:
                    try:
                        msg = "Invalid json format for %s" % json_prop
                        raise JsonValidationException(msg)
                    finally:
                        e = None
                        del e

        return ret


def is_healthy(url, timeout=5, verify=False):
    ret = False
    try:
        headers = {"Content-Type": "application/json"}
        r = requests.get(url=url, headers=headers, verify=verify, timeout=timeout)
        ret = r.ok
        if ret:
            logging.debug("Endpoint (%s) is healthy" % url)
        else:
            logging.error("Endpoint (%s) is not healthy" % url)
    except Exception as e:
        try:
            logging.exception("Endpoint (%s) is not healthy: %s" % (url, e))
        finally:
            e = None
            del e

    else:
        return ret


def parse_docker_image(docker_image_str):
    parts = docker_image_str.split(":")
    repository = parts[0]
    tag = parts[1] if len(parts) > 1 else "latest"
    if "/" in repository:
        (registry, repository) = repository.split("/", 1)
    else:
        registry = None
    return (
     registry, repository, tag)


def provider_manager_thread_pool_wrapper(func, *args, **kwargs):
    try:
        result = func(*args, **kwargs)
        func.__self__.db.thread_safe_session.remove()
    except:
        func.__self__.db.thread_safe_session.remove()
        raise
    else:
        return result


def object_storage_variable_substitution(path: str, account) -> str:
    s = {'kasm_id':account.kasm_id,  'user_id':account.user_id,  'username':account.user_name,  'image_id':account.image_id,  'image_friendly_name':account.image_friendly_name, 
     'created_timestamp':account.created_date,  'created_date':(account.created_date.date)(),  'start_timestamp':account.start_date, 
     'start_date':(account.start_date.date)(),  'current_epoch':int(round(time.time() * 1000))}
    return (path.format)(**s)


def create_session_recording_request_log(request, accountings: list):
    if len(accountings) > 1:
        kasm_ids = " ".join([str(x.kasm_id) for x in accountings])
    elif len(accountings) == 1:
        kasm_ids = accountings[0].kasm_id
    else:
        raise ValueError("accounts list must include at least one account")
    if hasattr(request, "api_key_name") and request.api_key_name is not None:
        if request.authenticated_user is not None:
            user = f"API key: {request.api_key_name} with user: {request.authenticated_user.username}"
        else:
            user = f"API key: {request.api_key_name}"
    elif request.authenticated_user is not None:
        user = f"User: {request.authenticated_user.username}"
    else:
        raise Exception(f"Missing authentication information to create session_recording log message for session(s): {kasm_ids}")
    return f"{user} has requested cloud storage links for session(s) {kasm_ids} recordings"

# okay decompiling bytecode/utils.pyc

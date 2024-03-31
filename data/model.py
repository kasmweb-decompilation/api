# decompyle3 version 3.9.1
# Python bytecode version base 3.8.0 (3413)
# Decompiled from: Python 3.10.12 (main, Nov 20 2023, 15:14:05) [GCC 11.4.0]
# Embedded file name: data/model.py

import os, jwt, base64, json, datetime, sqlalchemy, sys, inspect, hashlib, copy, re, logging
try:
    from zoneinfo import ZoneInfo
except ImportError:
    from backports.zoneinfo import ZoneInfo
else:
    try:
        from .enums import AZURE_AUTHORITY, SERVER_POOL_TYPE, IMAGE_TYPE, CONNECTION_TYPE, SERVER_TYPE, CPU_ALLOCATION_METHOD, SESSION_OPERATIONAL_STATUS, STORAGE_PROVIDER_TYPES, OS_TYPES, JWT_AUTHORIZATION
        from .data_utils import sanitize_username
    except ImportError:
        from enums import AZURE_AUTHORITY, SERVER_POOL_TYPE, IMAGE_TYPE, CONNECTION_TYPE, SERVER_TYPE, CPU_ALLOCATION_METHOD, SESSION_OPERATIONAL_STATUS, STORAGE_PROVIDER_TYPES, OS_TYPES, JWT_AUTHORIZATION
        from data_utils import sanitize_username
    else:
        from sqlalchemy import Column, Integer, BigInteger, String, TIMESTAMP, Boolean, VARCHAR, ForeignKey, Text, JSON, Float, Numeric, UniqueConstraint, asc, desc, TypeDecorator, select, CheckConstraint, Time, func
        from sqlalchemy.dialects.postgresql.json import JSONB
        from sqlalchemy.ext.declarative import declarative_base
        from sqlalchemy.ext.hybrid import hybrid_property
        from sqlalchemy.orm import relationship, validates, object_session, reconstructor
        from sqlalchemy.dialects.postgresql import UUID
        from sqlalchemy_utils import EncryptedType
        from sqlalchemy_utils.types.encrypted.encrypted_type import AesEngine, StringEncryptedType
        from sqlalchemy.sql import expression
        from sqlalchemy.ext.compiler import compiles
        from sqlalchemy.types import DateTime
        from sqlalchemy.ext.mutable import MutableDict
        from sqlalchemy_json import mutable_json_type

        class utcnow(expression.FunctionElement):
            type = DateTime()
            inherit_cache = True


        @compiles(utcnow, "postgresql")
        def pg_utcnow(element, compiler, **kw):
            return "TIMEZONE('utc', CURRENT_TIMESTAMP)"


        class AddLogger:

            @reconstructor
            def add_logger(self):
                self.logger = logging.getLogger("database_models")
                if "manager_api_server" in logging.root.manager.loggerDict.keys():
                    for handler in logging.root.manager.loggerDict["manager_api_server"].handlers:
                        if handler.__class__.__name__ == "QueueHandler":
                            if handler.log_handler.__class__.__name__ == "KasmLogHandler":
                                self.logger.addHandler(handler)

                elif "client_api_server" in logging.root.manager.loggerDict.keys():
                    for handler in logging.root.manager.loggerDict["client_api_server"].handlers:
                        if handler.__class__.__name__ == "QueueHandler":
                            if handler.log_handler.__class__.__name__ == "KasmLogHandler":
                                self.logger.addHandler(handler)

                elif "admin_api_server" in logging.root.manager.loggerDict.keys():
                    for handler in logging.root.manager.loggerDict["admin_api_server"].handlers:
                        if handler.__class__.__name__ == "QueueHandler":
                            if handler.log_handler.__class__.__name__ == "KasmLogHandler":
                                self.logger.addHandler(handler)


        Base = declarative_base(cls=AddLogger)

        def get_key():
            installation_id = os.getenv("INSTALLATION_ID")
            if installation_id:
                return installation_id + "sENXf4f5J!P4kguy@3"
            raise Exception("Missing INSTALLATION_ID environment variable")


        def sanitized_string():
            return "**********"


        class EncryptedJSONType(TypeDecorator):
            impl = String

            def __init__(self, *args, **kwargs):
                (super(EncryptedJSONType, self).__init__)(*args, **kwargs)

            def process_bind_param(self, value, dialect):
                if value is not None:
                    value = json.dumps(value)
                return value

            def process_result_value(self, value, dialect):
                if value is not None:
                    value = json.loads(value)
                return value


        class Jsonable:

            def __init__(self, *args, **kwargs):
                self.fields = args
                self.sanitize = []
                if "sanitize" in kwargs:
                    self.sanitize = kwargs["sanitize"]

            def sanitize(self, v):
                pass

            def __call__(self, cls):
                cls._jsonFields = self.fields
                cls._sanitize = self.sanitize

                def sanitize(k, v):
                    if k in cls._sanitize:
                        if v:
                            return sanitized_string()
                        return v
                    return v

                def toDict(self):
                    d = {}
                    for f in self.__class__._jsonFields:
                        v = self.__getattribute__(f)
                        if isinstance(v, list):
                            d[f] = [e.jsonDict if hasattr(e.__class__, "_jsonFields") else e for e in v]
                        else:
                            d[f] = v.jsonDict if hasattr(v.__class__, "_jsonFields") else sanitize(f, v)

                    return d

                cls.toDict = toDict

                def toDictUnsanitized(self):
                    d = {}
                    for f in self.__class__._jsonFields:
                        v = self.__getattribute__(f)
                        if isinstance(v, list):
                            d[f] = [e.jsonDictUnsanitized if hasattr(e.__class__, "_jsonFields") else e for e in v]
                        else:
                            d[f] = v.jsonDictUnsanitized if hasattr(v.__class__, "_jsonFields") else v

                    return d

                cls.toDictUnsanitized = toDictUnsanitized
                oGetter = cls.__getattribute__

                def getter(self, key):
                    if key == "jsonDict":
                        return self.toDict()
                    if key == "jsonDictUnsanitized":
                        return self.toDictUnsanitized()
                    return oGetter(self, key)

                cls.__getattribute__ = getter
                return cls


        @Jsonable("setting_id", "name", "value", "category", "services_restart", "description", "value_type", "title")
        class ConfigSetting(Base):
            __tablename__ = "settings"
            setting_id = Column(UUID(as_uuid=True), primary_key=True,
              server_default=(sqlalchemy.text("uuid_generate_v4()")))
            name = Column(VARCHAR(255))
            title = Column(VARCHAR(255))
            value = Column(StringEncryptedType(String, get_key, AesEngine, "pkcs5"))
            value_type = Column(String)
            category = Column(VARCHAR(255))
            services_restart = Column(VARCHAR(255))
            description = Column(Text)
            sanitize = Column(Boolean, default=False, server_default=(sqlalchemy.sql.expression.literal(False)), nullable=False)

            def getValueBool(self):
                return self.value is not None and self.value.lower() in ('yes', 'true',
                                                                         't', '1',
                                                                         'True')

            @property
            def sanitized_value(self):
                if self.sanitize:
                    if self.value:
                        return sanitized_string()
                    return self.value


        @Jsonable("user_id", "username", "locked", "failed_pw_attempts", "session_date", "plan_start_date", "plan_end_date", "plan_id", "anonymous", "first_name", "last_name", "phone", "organization", "notes", "saml_id", "oidc_id", "subscription_id", "company_id", "company", "program_id", "disabled", "created", "password_set_date", "city", "state", "country", "email", "custom_attribute_1", "custom_attribute_2", "custom_attribute_3")
        class User(Base):
            __tablename__ = "users"
            created = Column(TIMESTAMP, nullable=False)
            user_id = Column("user_id", UUID(as_uuid=True), primary_key=True,
              server_default=(sqlalchemy.text("uuid_generate_v4()")))
            username = Column((VARCHAR(255)), index=True, unique=True)
            email_confirm_token = Column(VARCHAR(64))
            email_pw_reset_request_date = Column(TIMESTAMP)
            locked = Column(Boolean, default=False)
            anonymous = Column(Boolean, default=False)
            failed_pw_attempts = Column(Integer, default=0)
            pw_hash = Column(VARCHAR(128))
            salt = Column(VARCHAR(64))
            plan_id = Column(VARCHAR(64))
            subscription_id = Column(VARCHAR(64))
            plan_start_date = Column(TIMESTAMP)
            plan_end_date = Column(TIMESTAMP)
            stripe_id = Column(VARCHAR(64))
            kasms = relationship("Kasm", back_populates="user", passive_deletes=True)
            groups = relationship("UserGroup", back_populates="user", passive_deletes=True)
            first_name = Column(VARCHAR(64))
            last_name = Column(VARCHAR(64))
            phone = Column(VARCHAR(64))
            organization = Column(VARCHAR(64))
            notes = Column(Text)
            realm = Column((VARCHAR(64)), default="local")
            saml_id = Column("saml_id", UUID(as_uuid=True), ForeignKey("saml_config.saml_id", onupdate="CASCADE", ondelete="CASCADE"), index=True)
            oidc_id = Column("oidc_id", UUID(as_uuid=True), ForeignKey("oidc_configs.oidc_id", onupdate="CASCADE", ondelete="CASCADE"),
              index=True)
            secret = Column(VARCHAR(32))
            set_two_factor = Column(Boolean, default=False)
            user_attributes = relationship("UserAttributes", back_populates="user", passive_deletes=True)
            company_id = Column("company_id", UUID(as_uuid=True), ForeignKey("companies.company_id", onupdate="CASCADE", ondelete="SET NULL"), index=True)
            company = relationship("Company", back_populates="users")
            program_id = Column(String)
            disabled = Column(Boolean, default=False, server_default=(sqlalchemy.sql.expression.literal(False)), nullable=False)
            session_tokens = relationship("SessionToken", back_populates="user", passive_deletes=True)
            session_permissions = relationship("SessionPermission", back_populates="user", passive_deletes=True)
            session_history = relationship("Accounting", primaryjoin="foreign(User.user_id) == remote(Accounting.user_id)",
              order_by="Accounting.start_date.desc()",
              uselist=True)
            file_mappings = relationship("FileMap", back_populates="user", passive_deletes=True)
            storage_mappings = relationship("StorageMapping", back_populates="user", passive_deletes=True)
            sso_ep = Column((EncryptedType(String, get_key, AesEngine, "pkcs5")), nullable=True)
            city = Column(String)
            state = Column(String)
            country = Column(String)
            email = Column(String)
            custom_attribute_1 = Column(String)
            custom_attribute_2 = Column(String)
            custom_attribute_3 = Column(String)
            tokens = relationship("PhysicalToken", back_populates="user", passive_deletes=True)
            password_set_date = Column(TIMESTAMP)
            webauthn_credentials = relationship("WebauthnCredential", back_populates="user", passive_deletes=True)

            def is_password_expired(self):
                max_days = self.get_setting_value("password_expires", 0)
                if not self.password_set_date:
                    return True
                if max_days > 0:
                    diff = datetime.datetime.utcnow() - self.password_set_date
                    if max_days - diff.days < 0:
                        return True
                    return False

            @hybrid_property
            def last_session(self):
                if len(self.session_history):
                    return self.session_history[0].start_date

            @last_session.expression
            def last_session(cls):
                return select([Accounting.start_date]).where(Accounting.user_id == cls.user_id).limit(1).as_scalar()

            @property
            def has_subscription(self):
                return self.subscription_id

            @property
            def has_plan(self):
                return self.plan_id

            def get_group_permissions(self):
                group_permissions = []
                for user_group in self.groups:
                    for group_permission in user_group.group.permissions:
                        group_permissions.append(group_permission)

                return group_permissions

            def get_authorizations(self):
                permissions = []
                for user_group in self.groups:
                    for group_permission in user_group.group.permissions:
                        perm = group_permission.permission
                        if perm:
                            if perm not in permissions:
                                permissions.append(perm)
                        return JWT_AUTHORIZATION.summarize_authorizations(permissions)

            @property
            def set_webauthn(self):
                if len(self.webauthn_credentials) > 0:
                    return True
                return False

            def get_valid_session_token(self):
                for token in self.session_tokens:
                    if not token.is_expired:
                        return token

            def get_setting_value(self, name, default=None):
                pri = 4096
                val = None
                for user_group in self.groups:
                    for group_setting in user_group.group.settings:
                        if name == group_setting.name:
                            if user_group.group.priority < pri:
                                pri = user_group.group.priority
                                val = group_setting.casted_value

                if val is None:
                    if default is not None:
                        return default
                    return val

            def get_setting_values(self, name):
                settings = []
                self.groups.sort(key=(lambda x: x.group.priority))
                for user_group in self.groups:
                    for group_setting in user_group.group.settings:
                        if name == group_setting.name:
                            if group_setting.value_type == "json":
                                settings.append(json.loads(group_setting.value))
                            elif group_setting.value_type == "usage_limit":
                                settings.append(json.loads(group_setting.value))
                            elif group_setting.value_type == "float":
                                settings.append(float(group_setting.value))
                            elif group_setting.value_type == "int":
                                settings.append(int(group_setting.value))
                            else:
                                if group_setting.value:
                                    if group_setting.value_type == "bool":
                                        settings.append(group_setting.value.lower == "true")
                                    settings.append(group_setting.value)
                        return settings

            def get_setting_group_id(self, name):
                pri = 4096
                val = None
                for user_group in self.groups:
                    for group_setting in user_group.group.settings:
                        if name == group_setting.name:
                            if user_group.group.priority < pri:
                                pri = user_group.group.priority
                                val = user_group.group.group_id
                        return val

            def get_groups(self):
                groups = []
                for user_group in self.groups:
                    groups.append({'name':(user_group.group).name, 
                     'group_id':(user_group.group).group_id})

                return groups

            def none_system_group_ids(self):
                groups = []
                for user_group in self.groups:
                    if not user_group.group.is_system == False:
                        if "group_assignment_label" in user_group.group.group_metadata:
                            groups.append(user_group.group.group_id)
                        return groups

            def get_group_ids(self):
                groups = []
                for user_group in self.groups:
                    groups.append(user_group.group.group_id)

                return groups

            def get_images(self, only_enabled=True):
                images = []
                for ug in self.groups:
                    for gi in ug.group.images:
                        if not any((x.image_id == gi.image.image_id for x in images)):
                            if only_enabled:
                                if not gi.image.enabled:
                                    images.append(gi.image)
                                images.append(gi.image)

                    return images

            def is_any_sso_images(self):
                for image in self.get_images():
                    if not image.is_server:
                        if not image.server:
                            if image.server.connection_username and "{sso_username}" in image.server.connection_username or image.server.connection_password == "{sso_cred}":
                                return True
                            if not image.is_server_pool:
                                if not image.server_pool:
                                    for server in image.server_pool.servers:
                                        if server.is_desktop:
                                            if server.connection_username:
                                                if not not "{sso_username}" in server.connection_username:
                                                    pass
                                                if server.connection_password == "{sso_cred}":
                                                    pass
                                                return True

                                    for autoscale_config in image.server_pool.autoscale_configs:
                                        if autoscale_config.connection_username:
                                            if not not "{sso_username}" in autoscale_config.connection_username:
                                                pass
                                            if autoscale_config.connection_password == "{sso_cred}":
                                                pass
                                            return True

                                    return False

            def get_program_data(self):
                program_data = {}
                self.groups.sort(key=(lambda x: x.group.priority))
                for user_group in self.groups:
                    if user_group.group.program_data:
                        program_data = user_group.group.program_data
                        break
                    return program_data


        @Jsonable("user_group_id", "user_id", "group_id")
        class UserGroup(Base):
            __tablename__ = "user_groups"
            user_group_id = Column("user_group_id", UUID(as_uuid=True), primary_key=True,
              server_default=(sqlalchemy.text("uuid_generate_v4()")))
            user_id = Column("user_id", UUID(as_uuid=True), ForeignKey("users.user_id", onupdate="CASCADE", ondelete="CASCADE"), index=True)
            group_id = Column(UUID(as_uuid=True), ForeignKey("groups.group_id", onupdate="CASCADE", ondelete="CASCADE"), index=True)
            user = relationship("User", back_populates="groups")
            group = relationship("Group", back_populates="users")


        @Jsonable("user_attributes_id", "name", "value", "user_id", "toggle_control_panel", "ssh_public_key", "chat_sfx", "theme", "preferred_language", "preferred_timezone")
        class UserAttributes(Base):
            __tablename__ = "user_attributes"
            user_attributes_id = Column("user_attributes_id", UUID(as_uuid=True), primary_key=True,
              server_default=(sqlalchemy.text("uuid_generate_v4()")))
            default_image = Column("default_image", UUID(as_uuid=True), ForeignKey("images.image_id", onupdate="CASCADE", ondelete="CASCADE"), index=True,
              default=None)
            image = relationship("Image", backref="images")
            show_tips = Column(Boolean, default=False, server_default=(sqlalchemy.sql.expression.literal(False)), nullable=False)
            user_login_to_kasm = Column(Boolean, default=None, nullable=True)
            toggle_control_panel = Column(Boolean, default=False, server_default=(sqlalchemy.sql.expression.literal(False)), nullable=False)
            chat_sfx = Column(Boolean, default=True, server_default=(sqlalchemy.sql.expression.literal(True)), nullable=False)
            theme = Column(String, default="Auto", server_default="Auto", nullable=False)
            ssh_public_key = Column(String, nullable=False)
            ssh_private_key = Column((EncryptedType(String, get_key, AesEngine, "pkcs5")), nullable=False)
            user_id = Column("user_id", UUID(as_uuid=True), ForeignKey("users.user_id", onupdate="CASCADE", ondelete="CASCADE"), index=True)
            user = relationship("User", back_populates="user_attributes")
            preferred_language = Column(String, nullable=False, server_default="Auto", default="Auto")
            preferred_timezone = Column(String, nullable=False, server_default="Auto", default="Auto")


        @Jsonable("group_image_id", "group_id", "image_id", "image_name", "group_name", "image_friendly_name", "image_src")
        class GroupImage(Base):
            __tablename__ = "group_images"
            group_image_id = Column("group_image_id", UUID(as_uuid=True), primary_key=True,
              server_default=(sqlalchemy.text("uuid_generate_v4()")))
            group_id = Column("group_id", UUID(as_uuid=True), ForeignKey("groups.group_id", onupdate="CASCADE", ondelete="CASCADE"), index=True)
            image_id = Column("image_id", UUID(as_uuid=True), ForeignKey("images.image_id", onupdate="CASCADE", ondelete="CASCADE"), index=True)
            group = relationship("Group", back_populates="images")
            image = relationship("Image", back_populates="groups")

            @property
            def image_name(self):
                if self.image:
                    return self.image.name

            @property
            def image_friendly_name(self):
                if self.image:
                    return self.image.friendly_name

            @property
            def image_src(self):
                if self.image:
                    return self.image.image_src

            @property
            def group_name(self):
                if self.group:
                    return self.group.name


        @Jsonable("group_id", "name", "is_system", "description", "priority", "program_data", "group_metadata")
        class Group(Base):
            __tablename__ = "groups"
            group_id = Column("group_id", UUID(as_uuid=True), primary_key=True,
              server_default=(sqlalchemy.text("uuid_generate_v4()")))
            name = Column(VARCHAR(1024))
            is_system = Column(Boolean, default=False)
            description = Column(String)
            priority = Column(Integer, default=4095)
            users = relationship("UserGroup", back_populates="group", passive_deletes=True, lazy="dynamic")
            settings = relationship("GroupSetting", back_populates="group", passive_deletes=True)
            images = relationship("GroupImage", back_populates="group", passive_deletes=True)
            program_data = Column(JSONB, default={})
            group_metadata = Column(JSONB, default={}, server_default="{}", nullable=False)
            cast_configs = relationship("CastConfig", back_populates="group", passive_deletes=True)
            group_mappings = relationship("SSOToGroupMapping", back_populates="group", passive_deletes=True)
            file_mappings = relationship("FileMap", back_populates="group", passive_deletes=True)
            storage_mappings = relationship("StorageMapping", back_populates="group", passive_deletes=True)
            permissions = relationship("GroupPermission", back_populates="group", passive_deletes=True)

            def get_users(self, page=None, page_size=None, filters=[], sort_by=None, sort_direction="desc"):
                response = {}
                q = self.users.join(User)
                for filter in filters:
                    name = filter["id"]
                    value = filter["value"]
                    if not value:
                        pass
                    else:
                        if name == "name":
                            q = q.filter(User.username.contains(value))
                        user_total = q.count()

                if sort_by:
                    if sort_direction:
                        if sort_direction == "desc":
                            q = q.order_by(desc(User.username))
                        else:
                            q = q.order_by(asc(User.username))
                    if page is not None:
                        if page_size:
                            q = q.offset(page * page_size).limit(page_size)
                        users = []
                        for user_group in q.all():
                            users.append({'name':(user_group.user).username, 
                             'user_id':(user_group.user).user_id})

                    response["users"] = users
                    response["total"] = user_total
                    return response

            def get_user_ids(self):
                user_ids = []
                for user_group in self.users:
                    user_ids.append(user_group.user.user_id)

                return user_ids

            def has_permission(self, permission):
                for perm in self.permissions:
                    if perm.permission == permission:
                        return True
                    return False


        @Jsonable("group_setting_id", "name", "value", "value_type", "description", "group_id")
        class GroupSetting(Base):
            __tablename__ = "group_settings"
            group_setting_id = Column("group_setting_id", UUID(as_uuid=True), primary_key=True,
              server_default=(sqlalchemy.text("uuid_generate_v4()")))
            name = Column(VARCHAR(255))
            value = Column(String)
            value_type = Column((VARCHAR(48)), default="string")
            description = Column(String)
            group_id = Column("group_id", UUID(as_uuid=True), ForeignKey("groups.group_id", onupdate="CASCADE", ondelete="CASCADE"), index=True)
            group = relationship("Group", back_populates="settings")

            @property
            def casted_value(self):
                val = self.value
                if self.value_type == "json":
                    val = json.loads(val) if val else {}
                elif self.value_type == "usage_limit":
                    val = json.loads(val) if val else {}
                elif self.value_type == "float":
                    val = float(val)
                elif self.value_type == "int":
                    val = int(val)
                elif val:
                    if self.value_type == "bool":
                        val = val.lower() == "true"
                return val


        @Jsonable("company_id", "company_name", "street", "city", "zip", "country", "created")
        class Company(Base):
            __tablename__ = "companies"
            company_id = Column("company_id", UUID(as_uuid=True), primary_key=True,
              server_default=(sqlalchemy.text("uuid_generate_v4()")))
            company_name = Column(String, index=True, nullable=False, unique=True)
            street = Column(String, index=True)
            city = Column(String, index=True)
            zip = Column(String, index=True)
            country = Column(String, index=True)
            created = Column(TIMESTAMP, nullable=False)
            users = relationship("User", back_populates="company", passive_deletes=True)


        @Jsonable("server_id", "created", "server_type", "agent_version", "container_limit", "cores", "docker_images", "hostname",
          "instance_id", "last_reported", "memory", "operational_status", "provider", "docker_info",
          "memory_stats", "disk_stats", "network_interfaces", "cpu_percent", "last_reported_elapsed", "cores_override",
          "memory_override", "manager_id", "manager", "core_calculations", "memory_calculations", "public_ip",
          "enabled", "prune_images_mode", "gpus", "gpu_info", "gpu_percent", "gpu_memory_used_percent", "gpu_temp",
          "gpus_override", "connection_type", "connection_info", "max_simultaneous_sessions", "zone_id", "server_pool_id",
          "server_pool_name", "zone_name", "friendly_name", "is_autoscaled", "connection_username", "connection_password",
          "connection_port", "connection_private_key", "use_user_private_key", "connection_passphrase", "agent_installed",
          sanitize=[
         "connection_password", "connection_private_key", "connection_passphrase"])
        class Server(Base):
            __tablename__ = "servers"
            server_id = Column("server_id", UUID(as_uuid=True), primary_key=True,
              server_default=(sqlalchemy.text("uuid_generate_v4()")))
            friendly_name = Column(String)
            created = Column(TIMESTAMP, server_default=(utcnow()), nullable=False)
            server_type = Column((VARCHAR(100)), server_default="host", nullable=False)
            agent_version = Column(String)
            container_limit = Column(Integer, default=0)
            docker_containers = Column(JSON, default={}, nullable=False)
            docker_networks = Column(JSON, default={}, nullable=False)
            docker_images = Column(JSON, default={}, nullable=False)
            docker_info = Column(JSON, default={})
            cores = Column(Integer, default=0)
            cores_override = Column(Integer, default=0)
            gpus_override = Column(Integer, default=0)
            cpu_percent = Column(Float, default=0)
            gpu_percent = Column(JSON, default={})
            gpu_memory_used_percent = Column(JSON, default={})
            gpu_temp = Column(JSON, default={})
            hostname = Column(VARCHAR(255))
            port = Column(Integer)
            host_token = Column(VARCHAR(64))
            instance_id = Column(VARCHAR(100))
            last_reported = Column("last_reported", TIMESTAMP)
            memory = Column(BigInteger, default=0)
            memory_override = Column(BigInteger, default=0)
            memory_stats = Column(JSON, default={})
            disk_stats = Column(JSON, default={})
            network_interfaces = Column(JSON, default={})
            operational_status = Column("operational_status", VARCHAR(48))
            provider = Column(VARCHAR(100))
            kasms = relationship("Kasm", back_populates="server", passive_deletes=True)
            images = relationship("Image", back_populates="server", passive_deletes=True)
            manager_id = Column("manager_id", UUID(as_uuid=True), ForeignKey("managers.manager_id", onupdate="CASCADE",
              ondelete="SET NULL"),
              index=True)
            manager = relationship("Manager", back_populates="servers")
            public_ip = Column(String)
            enabled = Column(Boolean, default=True, nullable=False)
            prune_images_mode = Column(String, default="Normal", nullable=False, server_default="Normal")
            connection_type = Column(String, default=(CONNECTION_TYPE.KASMVNC.value), server_default=(CONNECTION_TYPE.KASMVNC.value),
              nullable=False)
            connection_port = Column(Integer)
            connection_info = Column((StringEncryptedType(EncryptedJSONType, get_key, AesEngine, "pkcs5")), default={}, nullable=False)
            connection_username = Column(String)
            connection_password = Column(StringEncryptedType(String, get_key, AesEngine, "pkcs5"))
            connection_private_key = Column(StringEncryptedType(String, get_key, AesEngine, "pkcs5"))
            connection_passphrase = Column(StringEncryptedType(String, get_key, AesEngine, "pkcs5"))
            use_user_private_key = Column(Boolean, default=True, nullable=False)
            server_pool = relationship("ServerPool", back_populates="servers")
            server_pool_id = Column("server_pool_id", UUID(as_uuid=True), ForeignKey("server_pools.server_pool_id", onupdate="CASCADE",
              ondelete="SET NULL"),
              index=True)
            tags = Column(JSON, default=[], server_default="[]", nullable=False)
            zone = relationship("Zone", back_populates="servers")
            zone_id = Column("zone_id", UUID(as_uuid=True), ForeignKey("zones.zone_id", onupdate="CASCADE",
              ondelete="SET NULL"),
              index=True)
            autoscale_config = relationship("AutoScaleConfig", back_populates="servers")
            autoscale_config_id = Column("autoscale_config_id", UUID(as_uuid=True), ForeignKey("autoscale_configs.autoscale_config_id", onupdate="CASCADE",
              ondelete="SET NULL"),
              index=True)
            max_simultaneous_sessions = Column(Integer, server_default="1", default=1, nullable=False)
            reusable = Column(Boolean, nullable=False, default=False, server_default="false")
            agent_installed = Column(Boolean, nullable=False, default=False, server_default="false")

            @property
            def has_gpu(self):
                return "Runtimes" in self.docker_info and "nvidia" in self.docker_info["Runtimes"] and "GPUs" in self.docker_info and len(self.docker_info["GPUs"]) > 0

            @property
            def gpus(self):
                if self.has_gpu:
                    return len(self.docker_info["GPUs"])
                return 0

            @property
            def gpu_info(self):
                if self.docker_info:
                    if "GPUs" in self.docker_info:
                        return self.docker_info["GPUs"]
                    return {}

            @property
            def last_reported_elapsed(self):
                if self.last_reported:
                    return str(datetime.datetime.utcnow() - self.last_reported).split(".")[:-1][0]

            @property
            def core_calculations(self):
                if self.cores_override:
                    max_cores = self.cores_override
                else:
                    max_cores = self.cores
                cores_used = 0
                for k in self.kasms:
                    if k.operational_status in (SESSION_OPERATIONAL_STATUS.RUNNING.value, SESSION_OPERATIONAL_STATUS.STARTING.value):
                        cores_used += k.cores
                    percentage = 0

                if cores_used:
                    if max_cores:
                        percentage = cores_used / max_cores * 100
                    return {'percentage':percentage, 
                     'used':cores_used,  'max':max_cores}

            @property
            def memory_calculations(self):
                if self.memory_override:
                    max_memory = self.memory_override
                else:
                    max_memory = self.memory
                memory_used = 0
                for k in self.kasms:
                    if k.operational_status in (SESSION_OPERATIONAL_STATUS.RUNNING.value, SESSION_OPERATIONAL_STATUS.STARTING.value):
                        memory_used += k.memory
                    percentage = 0

                if memory_used:
                    if max_memory:
                        percentage = memory_used / max_memory * 100
                    return {'percentage':percentage, 
                     'used':memory_used,  'max':max_memory}

            @property
            def is_ssh(self):
                if self.connection_type == CONNECTION_TYPE.SSH.value:
                    return True
                return False

            @property
            def is_vnc(self):
                if self.connection_type == CONNECTION_TYPE.VNC.value:
                    return True
                return False

            @property
            def is_rdp(self):
                if self.connection_type == CONNECTION_TYPE.RDP.value:
                    return True
                return False

            @property
            def is_kasmvnc(self):
                if self.connection_type == CONNECTION_TYPE.KASMVNC.value:
                    return True
                return False

            @property
            def is_container_host(self):
                if self.server_type == SERVER_TYPE.HOST.value:
                    return True
                return False

            @property
            def is_desktop(self):
                if self.server_type == SERVER_TYPE.DESKTOP.value:
                    return True
                return False

            @property
            def is_autoscaled(self):
                if self.autoscale_config_id:
                    return True
                return False

            @property
            def zone_name(self):
                if self.zone:
                    return self.zone.zone_name

            @property
            def is_sso(self):
                return "{sso_username}" in self.connection_username or "{sso_create_user}" in self.connection_username

            @property
            def server_pool_name(self):
                if self.server_pool:
                    return self.server_pool.server_pool_name

            @property
            def os_type(self):
                if self.agent_installed:
                    return OS_TYPES.WINDOWS
                return OS_TYPES.LINUX

            def available_resources(self, host_overhead_memory=0, host_overhead_cores=0, session_operational_status_filter=None):
                cores = self.cores_override if self.cores_override > 0 else self.cores
                cores -= host_overhead_cores
                memory = self.memory_override if self.memory_override > 0 else self.memory
                memory -= host_overhead_memory
                gpus = self.gpus_override if self.gpus_override > 0 else self.gpus
                for kasm in self.kasms:
                    if session_operational_status_filter:
                        if kasm.operational_status in session_operational_status_filter:
                            pass
                        cores -= kasm.cores
                        memory -= kasm.memory
                        gpus -= kasm.gpus
                    return {'memory':memory, 
                     'cores':cores,  'gpus':gpus}

            @property
            def is_reusable(self):
                if self.is_autoscaled:
                    return self.reusable
                return True

            def get_connection_username(self, user):
                if self.connection_username:
                    if "{sso_username}" in self.connection_username:
                        if "@" in self.connection_username:
                            user_fqn = user.username.split("@")
                            conn_user_fqn = self.connection_username.split("@")
                            return f"{user_fqn[0]}@{conn_user_fqn[1]}"
                        return self.connection_username.replace("{sso_username}", user.username)
                    else:
                        if "{sso_create_user}" in self.connection_username:
                            return self.connection_username.replace("{sso_create_user}", sanitize_username(user))
                        return self.connection_username

            def is_user_multi_session_allowed(self, user):
                if self.is_container_host or self.is_ssh:
                    return True
                for kasm in user.kasms:
                    if not kasm.server:
                        if kasm.server.server_id == self.server_id:
                            return False
                        return True


        @Jsonable("image_id", "cores", "description", "docker_registry", "docker_token", "docker_user", "enabled",
          "friendly_name", "hash", "memory", "name", "x_res", "y_res", "imageAttributes", "restrict_to_network",
          "restrict_network_names", "restrict_to_server", "server_id", "persistent_profile_config", "volume_mappings",
          "run_config", "image_src", "available", "exec_config", "restrict_to_zone", "zone_id", "zone_name",
          "persistent_profile_path", "filter_policy_id", "filter_policy_name", "filter_policy_force_disabled",
          "session_time_limit", "categories", "default_category", "allow_network_selection",
          "require_gpu", "gpu_count", "hidden", "notes", "image_type",
          "server_pool_id", "link_url", "cpu_allocation_method", "uncompressed_size_mb", "launch_config", sanitize=[
         "docker_token"])
        class Image(Base):
            __tablename__ = "images"
            image_id = Column("image_id", UUID(as_uuid=True), primary_key=True,
              server_default=(sqlalchemy.text("uuid_generate_v4()")))
            cores = Column(Float, default=1)
            description = Column(String)
            docker_registry = Column(String)
            docker_token = Column(StringEncryptedType(VARCHAR(8192), get_key, AesEngine, "pkcs5"))
            docker_user = Column(VARCHAR(255))
            image_src = Column(VARCHAR(255))
            enabled = Column(Boolean, default=True)
            available = Column(Boolean, default=False)
            friendly_name = Column(VARCHAR(255))
            hash = Column(VARCHAR(255))
            memory = Column(BigInteger, default=768000000)
            name = Column((VARCHAR(255)), nullable=True)
            x_res = Column(Integer, default=800)
            y_res = Column(Integer, default=600)
            imageAttributes = relationship("ImageAttribute", back_populates="image", passive_deletes=True)
            kasms = relationship("Kasm", back_populates="image")
            groups = relationship("GroupImage", back_populates="image", passive_deletes=True)
            run_config = Column(JSON, default={}, nullable=False)
            volume_mappings = Column(JSON, default={}, nullable=False)
            persistent_profile_path = Column(String)
            restrict_to_network = Column(Boolean, default=False)
            restrict_network_names = Column(JSON, default=[], server_default="[]", nullable=False)
            allow_network_selection = Column(Boolean, default=False, server_default=(sqlalchemy.sql.expression.literal(False)), nullable=False)
            restrict_to_server = Column(Boolean, default=False)
            server_id = Column("server_id", UUID(as_uuid=True), ForeignKey("servers.server_id", onupdate="CASCADE", ondelete="SET NULL"),
              index=True)
            exec_config = Column(JSON, default={}, nullable=False)
            server = relationship("Server", back_populates="images")
            restrict_to_zone = Column(Boolean, default=False)
            zone_id = Column("zone_id", UUID(as_uuid=True), ForeignKey("zones.zone_id", onupdate="CASCADE", ondelete="SET NULL"),
              index=True)
            zone = relationship("Zone", back_populates="images")
            staging_configs = relationship("StagingConfig", back_populates="image", passive_deletes=True)
            filter_policy_id = Column("filter_policy_id", UUID(as_uuid=True), ForeignKey("filter_policies.filter_policy_id", onupdate="CASCADE", ondelete="SET NULL"),
              index=True)
            filter_policy = relationship("FilterPolicy", back_populates="images")
            filter_policy_force_disabled = Column(Boolean, default=False, server_default=(sqlalchemy.sql.expression.literal(False)), nullable=False)
            cast_configs = relationship("CastConfig", back_populates="image", passive_deletes=True)
            session_time_limit = Column(Integer)
            categories = Column(JSON, default=[], nullable=False)
            require_gpu = Column(Boolean, default=False, server_default=(sqlalchemy.sql.expression.literal(False)), nullable=False)
            gpu_count = Column(Integer, default=0, server_default="0", nullable=False)
            hidden = Column(Boolean, nullable=False, default=False, server_default="false")
            notes = Column(String)
            file_mappings = relationship("FileMap", back_populates="image", passive_deletes=True)
            storage_mappings = relationship("StorageMapping", back_populates="image", passive_deletes=True)
            image_type = Column(String, server_default=(IMAGE_TYPE.CONTAINER.value), nullable=False)
            server_pool_id = Column("server_pool_id", UUID(as_uuid=True), ForeignKey("server_pools.server_pool_id", onupdate="CASCADE", ondelete="SET NULL"),
              index=True)
            server_pool = relationship("ServerPool", back_populates="images")
            link_url = Column(String)
            cpu_allocation_method = Column(String, nullable=False, default=(CPU_ALLOCATION_METHOD.INHERIT.value), server_default=(CPU_ALLOCATION_METHOD.INHERIT.value))
            uncompressed_size_mb = Column(Integer, nullable=False, default=0, server_default="0")
            launch_config = Column(JSON, default={}, server_default="{}", nullable=False)
            _default_persistent_profile_config = {
              'mode': "rw",
              'bind': "/home/kasm-user",
              'required': True,
              'gid': 1000,
              'uid': 1000}

            @property
            def memory_gb(self):
                return self.memory / 1000000000

            @property
            def memory_mb(self):
                return self.memory / 1000000

            @property
            def persistent_profile_config(self):
                ret = {}
                if self.persistent_profile_path:
                    ret = {(self.persistent_profile_path): (self._default_persistent_profile_config)}
                return ret

            @property
            def gpus(self):
                return self.gpu_count

            @property
            def zone_name(self):
                if self.zone:
                    return self.zone.zone_name

            @property
            def filter_policy_name(self):
                if self.filter_policy:
                    return self.filter_policy.filter_policy_name

            def get_port_map(self):
                port_map = dict()
                for attr in self.imageAttributes:
                    if attr.category == "port_map":
                        port_map[attr.name] = {"container_port": (attr.value)}

                if port_map:
                    return port_map
                return self.default_image_port_map

            def is_user_authorized(self, user):
                return any((self.image_id == x.image_id for x in user.get_images()))

            def get_persistent_profile_permissions(self, user):
                if self.persistent_profile_config:
                    if user.get_setting_value("allow_persistent_profile", False):
                        return [
                         "Enabled", "Disabled", "Reset"]
                    return []

            @property
            def default_category(self):
                if self.categories:
                    if len(self.categories) >= 1:
                        return self.categories[0]
                    return ""

            @property
            def is_container(self):
                if self.image_type == IMAGE_TYPE.CONTAINER.value:
                    return True
                return False

            @property
            def is_server(self):
                if self.image_type == IMAGE_TYPE.SERVER.value:
                    return True
                return False

            @property
            def is_server_pool(self):
                if self.image_type == IMAGE_TYPE.SERVER_POOL.value:
                    return True
                return False

            @property
            def default_image_port_map(self):
                return {'vnc':{"container_port": "6901/tcp/https/basic_multi"}, 
                 'audio':{"container_port": "4901/tcp/https/basic"}, 
                 'uploads':{"container_port": "4902/tcp/https/basic"}, 
                 'audio_input':{"container_port": "4903/tcp/https/basic"}, 
                 'gamepad':{"container_port": "4904/tcp/https/basic"}, 
                 'webcam':{"container_port": "4905/tcp/https/basic"}}

            def is_valid_launch_selections(self, launch_selections):
                validation_errors = []
                validated_selections = {}
                validator_classes = {"string": int}
                if self.launch_config:
                    launch_form = self.launch_config.get("launch_form")
                    if launch_form:
                        if type(launch_form) == list:
                            for form_item in launch_form:
                                if type(form_item) == dict:
                                    if "key" in form_item:
                                        key = form_item["key"]
                                        if form_item["key"] in launch_selections:
                                            value = launch_selections[key]
                                            self.logger.info("launch_selection (%s:%s) needs to be validated" % (key, value))
                                            validator_regex = form_item.get("validator_regex")
                                            if validator_regex and value is not None:
                                                match = re.match(validator_regex, value)
                                                if match:
                                                    validated_selections[key] = value
                                                else:
                                                    validation_errors.append("Launch Selection (%s) did not pass validation: (%s)" % (form_item.get("label"),
                                                     form_item.get("validator_regex_description")))
                                            else:
                                                validated_selections[key] = value

                    return (
                     validated_selections, validation_errors)

            def has_minimum_launch_selections(self, launch_selections):
                if self.launch_config:
                    launch_form = self.launch_config.get("launch_form")
                    if launch_form:
                        if type(launch_form) == list:
                            for form_item in launch_form:
                                if type(form_item) == dict:
                                    if "key" in form_item:
                                        key = form_item["key"]
                                        required = False
                                        if "required" in form_item:
                                            if form_item["display_if"] is None:
                                                required = form_item["required"]
                                            if required:
                                                if form_item["key"] not in launch_selections:
                                                    return False

                    return True

            def get_launch_config_file_mapping_properties(self):
                default_properties = {
                  'destination': "/tmp/launch_selections.json",
                  'is_readable': True,
                  'is_writeable': False,
                  'is_executable': False}
                if self.launch_config:
                    if type(self.launch_config) == dict:
                        if "file_mapping" in self.launch_config:
                            for x in ('destination', 'is_readable', 'is_writeable',
                                      'is_executable'):
                                if x in self.launch_config["file_mapping"]:
                                    default_properties[x] = self.launch_config["file_mapping"][x]

                    return default_properties


        @Jsonable("attr_id", "name", "category", "value", "image_id")
        class ImageAttribute(Base):
            __tablename__ = "image_attributes"
            attr_id = Column("attr_id", UUID(as_uuid=True), primary_key=True,
              server_default=(sqlalchemy.text("uuid_generate_v4()")))
            name = Column(VARCHAR(255))
            category = Column(VARCHAR(48))
            value = Column(VARCHAR(255))
            image_id = Column("image_id", UUID(as_uuid=True), ForeignKey("images.image_id", onupdate="CASCADE", ondelete="CASCADE"))
            image = relationship("Image", back_populates="imageAttributes")


        @Jsonable("kasm_id", "container_id", "cores", "hostname", "keepalive_date", "share_id", "expiration_date", "memory", "operational_status", "operational_message", "operational_progress", "server_id", "start_date", "created_date", "user_id", "image_id", "container_ip", "is_persistent_profile", "persistent_profile_mode", "image_src", "docker_network")
        class Kasm(Base):
            __tablename__ = "kasms"
            kasm_id = Column("kasm_id", UUID(as_uuid=True), primary_key=True,
              server_default=(sqlalchemy.text("uuid_generate_v4()")))
            container_id = Column("container_id", VARCHAR(255))
            cores = Column(Float, default=0)
            gpus = Column(Integer, default=0)
            hostname = Column(VARCHAR(255))
            keepalive_date = Column(TIMESTAMP, nullable=False)
            expiration_date = Column(TIMESTAMP, nullable=False)
            memory = Column(BigInteger, default=0)
            container_ip = Column(String)
            operational_status = Column("operational_status", VARCHAR(48))
            operational_message = Column(String)
            operational_progress = Column(Integer, default=0)
            connection_proxy = relationship("ConnectionProxy", back_populates="kasms")
            connection_proxy_id = Column("connection_proxy_id", ForeignKey("connection_proxies.connection_proxy_id", onupdate="CASCADE", ondelete="SET NULL"),
              index=True, nullable=True)
            server_id = Column("server_id", UUID(as_uuid=True), ForeignKey("servers.server_id", onupdate="CASCADE", ondelete="CASCADE"), index=True)
            start_date = Column(TIMESTAMP)
            created_date = Column(TIMESTAMP, nullable=False)
            token = Column(VARCHAR(48))
            view_only_token = Column(VARCHAR(48))
            api_token = Column(VARCHAR(48))
            user_id = Column("user_id", UUID(as_uuid=True), ForeignKey("users.user_id", onupdate="CASCADE", ondelete="CASCADE"), index=True)
            user = relationship("User", back_populates="kasms")
            server = relationship("Server", back_populates="kasms")
            image_id = Column("image_id", UUID(as_uuid=True), ForeignKey("images.image_id"))
            image = relationship("Image", back_populates="kasms")
            share_id = Column(VARCHAR(48))
            kasm_attributes = relationship("KasmAttribute", back_populates="kasm", passive_deletes=True)
            is_standby = Column(Boolean, nullable=False, default=False, server_default="false")
            staging_config = relationship("StagingConfig", back_populates="kasms")
            staging_config_id = Column("staging_config_id", UUID(as_uuid=True), ForeignKey("staging_configs.staging_config_id", onupdate="CASCADE", ondelete="SET NULL"),
              index=True, nullable=True)
            cast_config = relationship("CastConfig", back_populates="kasms")
            cast_config_id = Column("cast_config_id", UUID(as_uuid=True), ForeignKey("cast_configs.cast_config_id", onupdate="CASCADE", ondelete="SET NULL"),
              index=True, nullable=True)
            autoscale_config = relationship("AutoScaleConfig", back_populates="kasms")
            autoscale_config_id = Column("autoscale_config_id", UUID(as_uuid=True), ForeignKey("autoscale_configs.autoscale_config_id", onupdate="CASCADE", ondelete="SET NULL"),
              index=True, nullable=True)
            docker_network = Column(String)
            docker_environment = Column(JSON, server_default="{}", default={}, nullable=False)
            session_permissions = relationship("SessionPermission", back_populates="kasm", passive_deletes=True)
            connection_info = Column((StringEncryptedType(EncryptedJSONType, get_key, AesEngine, "pkcs5")), default={}, nullable=True)
            queued_tasks = Column(mutable_json_type(dbtype=JSONB, nested=True), server_default="[]", default=[])
            connection_credential = Column(StringEncryptedType(VARCHAR(255), get_key, AesEngine, "pkcs5"))
            file_mappings = relationship("FileMap", back_populates="kasm", passive_deletes=True)

            def set_operational_status(self, value):
                if isinstance(value, str):
                    value = SESSION_OPERATIONAL_STATUS.validate(value)
                if isinstance(value, SESSION_OPERATIONAL_STATUS):
                    self.operational_status = value.value
                else:
                    raise ValueError("Invalid operational status {value}.")
                return value

            def get_operational_status(self):
                return SESSION_OPERATIONAL_STATUS.validate(self.operational_status)

            def get_port_map(self):
                port_map = dict()
                for attr in self.kasm_attributes:
                    if attr.category == "port_map":
                        port_map[attr.name] = {'path':attr.value,  'port':self.server.port if (self.image.is_container) else (self.get_service_port(attr.name)), 
                         'authorization':None if (self.image.is_container) else (self.get_service_basic_auth(attr.name)), 
                         'username':None if (self.image.is_container) else (self.server.connection_info.get("port_map", {}).get(attr.name, {}).get("username"))}
                    return port_map

            @property
            def is_persistent_profile(self):
                for attr in self.kasm_attributes:
                    if not attr.name == "persistent_profile_mode":
                        if attr.value in ('Reset', 'Enabled'):
                            return True
                        return False

            @property
            def persistent_profile_mode(self):
                for attr in self.kasm_attributes:
                    if attr.name == "persistent_profile_mode":
                        return attr.value

            @property
            def persistent_profile_path(self):
                for attr in self.kasm_attributes:
                    if attr.name == "persistent_profile_path":
                        return attr.value

            @property
            def connection_type(self):
                ret = None
                if self.container_id:
                    ret = CONNECTION_TYPE.KASMVNC.value
                else:
                    ret = self.server.connection_type
                return ret

            def get_service_basic_auth(self, service):
                ret = None
                if service == "vnc":
                    if self.server.connection_username:
                        if self.server.connection_password:
                            creds = "%s:%s" % (self.server.connection_username, self.server.connection_password)
                            creds = base64.b64encode(creds.encode("ascii")).decode("ascii")
                            ret = "Basic %s" % creds
                    return ret

            def get_service_port(self, service):
                ret = None
                if service == "vnc":
                    if self.server.connection_type == CONNECTION_TYPE.KASMVNC.value:
                        ret = self.server.connection_port
                    return ret

            def getAttribute(self, name):
                selected_attribute = None
                for attr in self.kasm_attributes:
                    if attr.name == name:
                        selected_attribute = attr
                    return selected_attribute


        @Jsonable("attr_id", "name", "category", "value", "kasm_id")
        class KasmAttribute(Base):
            __tablename__ = "kasm_attributes"
            attr_id = Column("attr_id", UUID(as_uuid=True), primary_key=True,
              server_default=(sqlalchemy.text("uuid_generate_v4()")))
            name = Column(VARCHAR(255))
            category = Column(VARCHAR(48))
            value = Column(VARCHAR(255))
            kasm_id = Column("kasm_id", UUID(as_uuid=True), ForeignKey("kasms.kasm_id", onupdate="CASCADE", ondelete="CASCADE"), index=True)
            kasm = relationship("Kasm", back_populates="kasm_attributes")


        @Jsonable("emailaddress", "enable", "type")
        class Newsletter(Base):
            __tablename__ = "newsletters"
            emailaddress = Column((VARCHAR(255)), primary_key=True)
            enabled = Column(Boolean, default=True)
            type = Column(VARCHAR(64))


        class Log(Base):
            __tablename__ = "logs"
            log_id = Column("log_id", UUID(as_uuid=True), primary_key=True,
              server_default=(sqlalchemy.text("uuid_generate_v4()")))
            ingest_date = Column(TIMESTAMP, nullable=False, index=True)
            host = Column((VARCHAR(255)), index=True)
            data = Column(JSONB)
            metric_name = Column((VARCHAR(255)), index=True)
            kasm_user_name = Column((VARCHAR(255)), index=True)
            levelname = Column((VARCHAR(20)), index=True)
            disk_stats = Column(Numeric(precision=9, scale=2))
            memory_stats = Column(Numeric(precision=9, scale=2))
            cpu_percent = Column(Numeric(precision=9, scale=2))
            server_id = Column((VARCHAR(64)), index=True)
            gpu_percent = Column(Numeric(precision=9, scale=2))
            gpu_memory = Column(Numeric(precision=9, scale=2))
            gpu_temp = Column(Numeric(precision=9, scale=2))


        @Jsonable("ldap_id", "name", "enabled", "url", "auto_create_app_user", "email_attribute", "search_base",
          "search_filter", "search_subtree", "service_account_dn", "group_membership_filter", "service_account_password",
          "username_domain_match", sanitize=["service_account_password"])
        class LDAPConfig(Base):
            __tablename__ = "ldap_configs"
            ldap_id = Column("ldap_id", UUID(as_uuid=True), primary_key=True,
              server_default=(sqlalchemy.text("uuid_generate_v4()")))
            name = Column((VARCHAR(255)), nullable=False)
            enabled = Column(Boolean, default=False, nullable=False)
            url = Column((VARCHAR(255)), nullable=False)
            auto_create_app_user = Column(Boolean, default=True, nullable=False)
            email_attribute = Column(VARCHAR(255))
            search_base = Column((VARCHAR(255)), nullable=False)
            search_filter = Column((VARCHAR(255)), nullable=False)
            search_subtree = Column(Boolean, default=True, nullable=False)
            service_account_dn = Column(VARCHAR(255))
            service_account_password = Column(StringEncryptedType(VARCHAR(255), get_key, AesEngine, "pkcs5"))
            connection_timeout = Column(Integer, default=5, nullable=False)
            group_membership_filter = Column((VARCHAR(255)), nullable=False)
            username_domain_match = Column(String)
            group_mappings = relationship("SSOToGroupMapping", back_populates="ldap_config", passive_deletes=True)
            autoscale_configs = relationship("AutoScaleConfig", back_populates="ldap_config", passive_deletes=True)
            user_attribute_mappings = relationship("SSOAttributeToUserFieldMapping", back_populates="ldap_config", passive_deletes=True)


        @Jsonable("saml_id", "strict", "debug", "adfs", "enabled", "auto_login", "is_default", "hostname", "display_name", "group_attribute", "sp_entity_id", "sp_acs_url",
          "sp_slo_url", "sp_name_id", "sp_x509_cert", "sp_private_key", "idp_entity_id", "idp_sso_url", "idp_slo_url",
          "idp_x509_cert", "want_attribute_statement", "name_id_encrypted", "authn_request_signed", "logout_request_signed",
          "logout_response_signed", "sign_metadata", "want_messages_signed", "want_assertions_signed",
          "want_name_id", "want_name_id_encrypted", "want_assertions_encrypted", "signature_algorithm",
          "digest_algorithm", "logo_url", sanitize=[
         "sp_x509_cert", "sp_private_key", "idp_x509_cert"])
        class SAMLConfig(Base):
            __tablename__ = "saml_config"
            saml_id = Column("saml_id", UUID(as_uuid=True), primary_key=True,
              server_default=(sqlalchemy.text("uuid_generate_v4()")))
            strict = Column(Boolean, default=True, nullable=False)
            debug = Column(Boolean, default=False, nullable=False)
            auto_login = Column(Boolean, default=False, nullable=False)
            enabled = Column(Boolean, default=False, nullable=False)
            adfs = Column(Boolean, default=False, nullable=False)
            group_attribute = Column((VARCHAR(255)), nullable=True)
            is_default = Column(Boolean, default=False, nullable=False)
            hostname = Column((VARCHAR(255)), nullable=True)
            display_name = Column((VARCHAR(255)), nullable=True)
            sp_entity_id = Column((VARCHAR(255)), nullable=True)
            sp_acs_url = Column((VARCHAR(255)), nullable=True)
            sp_slo_url = Column((VARCHAR(255)), nullable=True)
            sp_name_id = Column((VARCHAR(255)), nullable=True)
            sp_x509_cert = Column((StringEncryptedType(Text, get_key, AesEngine, "pkcs5")), nullable=True)
            sp_private_key = Column((StringEncryptedType(Text, get_key, AesEngine, "pkcs5")), nullable=True)
            idp_entity_id = Column((VARCHAR(255)), nullable=True)
            idp_sso_url = Column((VARCHAR(255)), nullable=True)
            idp_slo_url = Column((VARCHAR(255)), nullable=True)
            idp_x509_cert = Column((StringEncryptedType(Text, get_key, AesEngine, "pkcs5")), nullable=True)
            want_attribute_statement = Column(Boolean, default=True, nullable=False)
            name_id_encrypted = Column(Boolean, default=False, nullable=False)
            authn_request_signed = Column(Boolean, default=False, nullable=False)
            logout_request_signed = Column(Boolean, default=False, nullable=False)
            logout_response_signed = Column(Boolean, default=False, nullable=False)
            sign_metadata = Column(Boolean, default=False, nullable=False)
            want_messages_signed = Column(Boolean, default=False, nullable=False)
            want_assertions_signed = Column(Boolean, default=False, nullable=False)
            want_name_id = Column(Boolean, default=True, nullable=False)
            want_name_id_encrypted = Column(Boolean, default=False, nullable=False)
            want_assertions_encrypted = Column(Boolean, default=False, nullable=False)
            signature_algorithm = Column(Text, nullable=True)
            digest_algorithm = Column(Text, nullable=True)
            logo_url = Column(String, nullable=True)
            group_mappings = relationship("SSOToGroupMapping", back_populates="saml_config", passive_deletes=True)
            user_attribute_mappings = relationship("SSOAttributeToUserFieldMapping", back_populates="saml_config", passive_deletes=True)


        @Jsonable("installation_id", "update_information")
        class Installation(Base):
            __tablename__ = "installation"
            installation_id = Column("installation_id", UUID(as_uuid=True), primary_key=True,
              server_default=(sqlalchemy.text("uuid_generate_v4()")))
            update_information = Column(JSON, default={}, nullable=True)


        public_key = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4W4YZgXW9Fpa6bs/NsnP\nQEjM5c0IQpE2BJkg/EbASPeF/HeZapfUpgvtBxlNNx2Ej4nzOMHRVrycatJts3hX\nozZqx2C3ajCXez3s99Mgq+geZ+Fdn/AK/aBzgjoP44BrgafL5fcXMPv/pThqLwtq\nwLdiRZeqRSWY1l79fvC0GGj6yk7qkT7ezWcCERtZEo8siPqIPn/nhXYQipP0CoxN\nJyvONrZZFWUkOiO0rDturLqcadxiLdYwIG/iCjmaJe5sZw1+mb/ePYBgEqyQfei9\nkD6Eg17H2cn7kk9L9b8uy40m3okz0KOJSSgsUQMfoVhNc2dyyCtSxpX2GV3BiJvi\nwQIDAQAB\n-----END PUBLIC KEY-----"

        @Jsonable("license_id", "expiration", "issued_at", "issued_to", "limit", "is_verified", "license_type", "features", "sku")
        class License(Base):
            __tablename__ = "licenses"
            license_id = Column("license_id", UUID(as_uuid=True), primary_key=True,
              server_default=(sqlalchemy.text("uuid_generate_v4()")))
            license_key = Column(Text, nullable=False)

            @validates("license_key")
            def validate_license_key(self, key, license_key):
                _data = self.verify_license_key(license_key)
                for x in ('exp', 'iat', 'issued_to', 'license_type', 'installation_id',
                          'limit', 'sku', 'features'):
                    pass

                return license_key

            @property
            def decoded_license_data(self):
                res = {}
                if self.license_key:
                    res = jwt.decode((self.license_key), public_key, algorithm="RS256", audience="urn:kasm", verify=False)
                return res

            @property
            def expiration(self):
                res = None
                if self.decoded_license_data:
                    if self.decoded_license_data.get("exp"):
                        res = datetime.datetime.utcfromtimestamp(self.decoded_license_data.get("exp"))
                    return res

            @property
            def issued_at(self):
                res = None
                if self.decoded_license_data:
                    if self.decoded_license_data.get("iat"):
                        res = datetime.datetime.utcfromtimestamp(self.decoded_license_data.get("iat"))
                    return res

            @property
            def issued_to(self):
                res = None
                if self.decoded_license_data:
                    res = self.decoded_license_data.get("issued_to")
                return res

            @property
            def issued_to(self):
                res = None
                if self.decoded_license_data:
                    res = self.decoded_license_data.get("issued_to")
                return res

            @property
            def installation_id(self):
                res = None
                if self.decoded_license_data:
                    res = self.decoded_license_data.get("installation_id")
                return res

            @property
            def license_type(self):
                res = None
                if self.decoded_license_data:
                    res = self.decoded_license_data.get("license_type")
                return res

            @property
            def limit(self):
                res = None
                if self.decoded_license_data:
                    if self.decoded_license_data.get("limit"):
                        res = int(self.decoded_license_data.get("limit"))
                    return res

            @property
            def is_verified(self):
                res = False
                if self.license_key:
                    try:
                        d = self.verify_license_key(self.license_key)
                        res = True
                    except jwt.exceptions.ExpiredSignatureError as e:
                        try:
                            return False
                        finally:
                            e = None
                            del e

                    return res

            @property
            def features(self):
                res = None
                if self.decoded_license_data:
                    if self.decoded_license_data.get("features"):
                        res = self.decoded_license_data.get("features")
                    return res

            @property
            def sku(self):
                res = None
                if self.decoded_license_data:
                    if self.decoded_license_data.get("sku"):
                        res = self.decoded_license_data.get("sku")
                    return res

            @property
            def is_legacy(self):
                return not self.sku

            @staticmethod
            def verify_license_key(license_key):
                try:
                    data = jwt.decode(license_key, public_key, algorithm="RS256", audience="urn:kasm")
                except jwt.exceptions.DecodeError as e:
                    try:
                        e.args = ('Invalid key format', )
                        raise
                    finally:
                        e = None
                        del e

                except jwt.exceptions.ExpiredSignatureError as e2:
                    try:
                        e2.args = ('Signature has expired', )
                        raise
                    finally:
                        e2 = None
                        del e2

                else:
                    return data


        @Jsonable("manager_id", "manager_version", "manager_hostname", "first_reported", "last_reported", "last_reported_elapsed", "last_reported_seconds", "zone_id", "zone_name", "is_primary")
        class Manager(Base):
            __tablename__ = "managers"
            manager_id = Column("manager_id", UUID(as_uuid=True), primary_key=True,
              server_default=(sqlalchemy.text("uuid_generate_v4()")))
            manager_version = Column(String)
            manager_hostname = Column(String)
            first_reported = Column("first_reported", TIMESTAMP)
            last_reported = Column("last_reported", TIMESTAMP)
            servers = relationship("Server", back_populates="manager")
            zone_id = Column("zone_id", UUID(as_uuid=True), ForeignKey("zones.zone_id", onupdate="CASCADE", ondelete="SET NULL"),
              index=True, nullable=False)
            zone = relationship("Zone", back_populates="managers", foreign_keys=[zone_id])

            @property
            def last_reported_elapsed(self):
                if self.last_reported:
                    return str(datetime.datetime.utcnow() - self.last_reported).split(".")[:-1][0]

            @property
            def last_reported_seconds(self):
                if self.last_reported:
                    return (datetime.datetime.utcnow() - self.last_reported).total_seconds()

            @property
            def zone_name(self):
                if self.zone:
                    return self.zone.zone_name

            @property
            def is_primary(self):
                if self.zone:
                    return self.zone.primary_manager_id == self.manager_id


        @Jsonable("zone_id", "zone_name", "primary_manager_id", "primary_manager", "managers", "allow_origin_domain", "upstream_auth_address", "proxy_connections", "proxy_hostname", "proxy_path", "proxy_port", "load_strategy", "prioritize_static_agents", "search_alternate_zones")
        class Zone(Base):
            __tablename__ = "zones"
            zone_id = Column("zone_id", UUID(as_uuid=True), primary_key=True, server_default=(sqlalchemy.text("uuid_generate_v4()")))
            zone_name = Column(String, unique=True, nullable=False)
            load_strategy = Column(String, nullable=False, default="least_load", server_default="least_load")
            prioritize_static_agents = Column(Boolean, nullable=False, default=True, server_default="true")
            search_alternate_zones = Column(Boolean, nullable=False, default=True, server_default="true")
            allow_origin_domain = Column(String, nullable=False, default="$request_host$")
            upstream_auth_address = Column(String, nullable=False, default="$request_host$")
            proxy_connections = Column(Boolean, nullable=False, default=True)
            proxy_hostname = Column(String, nullable=False, default="$request_host$")
            proxy_path = Column(String, nullable=False, default="desktop")
            proxy_port = Column(Integer, nullable=False, default=443)
            primary_manager_id = Column("primary_manager_id", UUID(as_uuid=True), ForeignKey("managers.manager_id", onupdate="CASCADE", ondelete="SET NULL"),
              unique=True, index=True)
            primary_manager = relationship("Manager", foreign_keys=[primary_manager_id])
            managers = relationship("Manager", passive_deletes=True, foreign_keys="Manager.zone_id")
            servers = relationship("Server", passive_deletes=True, foreign_keys="Server.zone_id")
            images = relationship("Image", back_populates="zone", passive_deletes=True)
            staging_configs = relationship("StagingConfig", back_populates="zone", passive_deletes=True)
            connection_proxies = relationship("ConnectionProxy", passive_deletes=True, foreign_keys="ConnectionProxy.zone_id")
            autoscale_configs = relationship("AutoScaleConfig", passive_deletes=True, foreign_keys="AutoScaleConfig.zone_id")

            def get_zone_servers(self):
                servers = []
                for manager in self.managers:
                    servers = servers + manager.servers

                return servers

            def get_zone_kasms(self):
                kasms = []
                for server in self.get_zone_servers():
                    kasms = kasms + server.kasms

                return kasms


        @Jsonable("api_id", "name", "api_key", "enabled", "read_only", "created", "last_used", "expires")
        class Api(Base):
            __tablename__ = "api_configs"
            api_id = Column("api_id", UUID(as_uuid=True), primary_key=True, server_default=(sqlalchemy.text("uuid_generate_v4()")))
            name = Column(String, unique=True, nullable=False)
            api_key = Column((VARCHAR(12)), nullable=False)
            api_key_secret_hash = Column((VARCHAR(128)), nullable=False)
            salt = Column((VARCHAR(64)), nullable=False)
            enabled = Column(Boolean, default=False)
            read_only = Column(Boolean, default=False)
            created = Column(TIMESTAMP, nullable=False)
            last_used = Column(TIMESTAMP)
            expires = Column(TIMESTAMP)
            permissions = relationship("GroupPermission", back_populates="api_config", passive_deletes=True)

            def has_permission(self, permission):
                for perm in self.permissions:
                    if perm.permission == permission:
                        return True
                    return False

            def get_authorizations(self):
                permissions = []
                for group_permission in self.permissions:
                    perm = group_permission.permission
                    if not perm:
                        if perm not in permissions:
                            permissions.append(perm)
                        return JWT_AUTHORIZATION.summarize_authorizations(permissions)


        @Jsonable("account_id", "kasm_id", "user_id", "user_name", "image_id", "image_name", "image_src", "image_friendly_name", "start_date", "created_date", "destroyed_date", "destroy_reason", "group_ids", "usage_hours", "cast_config_id")
        class Accounting(Base):
            __tablename__ = "accounting"
            account_id = Column("account_id", UUID(as_uuid=True), primary_key=True, server_default=(sqlalchemy.text("uuid_generate_v4()")))
            kasm_id = Column(UUID(as_uuid=True))
            user_id = Column(UUID(as_uuid=True))
            user_name = Column(VARCHAR(255))
            image_id = Column(UUID(as_uuid=True))
            image_name = Column(String)
            image_src = Column(String)
            image_friendly_name = Column(String)
            start_date = Column(TIMESTAMP)
            created_date = Column(TIMESTAMP)
            destroyed_date = Column(TIMESTAMP)
            destroy_reason = Column(VARCHAR(32))
            group_ids = Column(JSONB)
            usage_hours = Column(Float)
            user_ip = Column(String)
            cast_config_id = Column(UUID(as_uuid=True))
            staging_config_id = Column(UUID(as_uuid=True))
            zone_id = Column(UUID(as_uuid=True))
            zone_name = Column(String)
            server_id = Column(UUID(as_uuid=True))
            server_hostname = Column(String)
            docker_network = Column(String)
            session_recordings = relationship("SessionRecording", back_populates="accounting", passive_deletes=True)
            is_queued = Column(Boolean, default=False, server_default="false", nullable=True)

            @property
            def is_cast(self):
                if self.cast_config_id:
                    return True
                return False

            @property
            def is_staged(self):
                if self.staging_config_id:
                    return True
                return False

            @property
            def is_assigned(self):
                if self.user_id:
                    return True
                return False

            @property
            def unassigned_time(self):
                if self.created_date:
                    if self.start_date:
                        return (self.start_date - self.created_date).total_seconds()
                    if self.destroyed_date:
                        return (self.destroyed_date - self.created_date).total_seconds()
                    return 0


        @Jsonable("recording_id", "account_id", "session_recording_url", "session_recording_metadata")
        class SessionRecording(Base):
            __tablename__ = "session_recordings"
            recording_id = Column("recording_id", UUID(as_uuid=True), primary_key=True,
              server_default=(sqlalchemy.text("uuid_generate_v4()")))
            account_id = Column("account_id", UUID(as_uuid=True), ForeignKey("accounting.account_id", onupdate="CASCADE", ondelete="CASCADE"), index=True)
            accounting = relationship("Accounting", back_populates="session_recordings")
            session_recording_url = Column(String, nullable=True)
            session_recording_metadata = Column(JSONB, default={})


        @Jsonable("cart_id", "stripe_id", "user_id", "plan_name")
        class Cart(Base):
            __tablename__ = "cart"
            cart_id = Column("cart_id", UUID(as_uuid=True), primary_key=True,
              server_default=(sqlalchemy.text("uuid_generate_v4()")))
            plan_name = Column(VARCHAR(64))
            stripe_id = Column(VARCHAR(64))
            user_id = Column(UUID(as_uuid=True))
            completed = Column(Boolean, default=False)


        class Domain(Base):
            __tablename__ = "domains"
            domain_id = Column("domain_id", UUID(as_uuid=True), primary_key=True, server_default=(sqlalchemy.text("uuid_generate_v4()")))
            domain_name = Column(String, nullable=False, index=True, unique=True)
            categories = Column(JSONB, default={}, nullable=False, index=True)
            is_system = Column(Boolean, nullable=False, default=False)
            requested = Column(Integer, nullable=False, default=0, server_default="0")
            created = Column(TIMESTAMP, nullable=False, index=True)
            updated = Column(TIMESTAMP, nullable=False, index=True)


        @Jsonable("filter_policy_id", "filter_policy_name", "filter_policy_descriptions", "categories", "domain_blacklist", "domain_whitelist", "deny_by_default", "enable_categorization", "ssl_bypass_domains", "ssl_bypass_ips", "enable_safe_search", "safe_search_patterns", "disable_logging")
        class FilterPolicy(Base):
            __tablename__ = "filter_policies"
            filter_policy_id = Column("filter_policy_id", UUID(as_uuid=True), primary_key=True, server_default=(sqlalchemy.text("uuid_generate_v4()")))
            filter_policy_name = Column(String)
            filter_policy_descriptions = Column(String)
            deny_by_default = Column(Boolean, default=False, nullable=False)
            enable_categorization = Column(Boolean, default=False, nullable=False)
            categories = Column(JSON, default={}, nullable=False)
            domain_blacklist = Column(JSON, default=[], nullable=False)
            domain_whitelist = Column(JSON, default=[], nullable=False)
            ssl_bypass_domains = Column(JSON, default=[], nullable=False)
            ssl_bypass_ips = Column(JSON, default=[], nullable=False)
            enable_safe_search = Column(Boolean, default=False, nullable=False)
            safe_search_patterns = Column(JSON, default=[], nullable=False)
            disable_logging = Column(Boolean, default=False, server_default="false", nullable=True)
            images = relationship("Image", back_populates="filter_policy", passive_deletes=True)

            @property
            def redirect_url(self):
                return "http://access_denied/"

            def get_allow_categories(self, default_allow):
                allow_categories = []
                deny_categories = []
                for (k, v) in self.categories.items():
                    if v == "allow":
                        allow_categories.append(k)
                    elif v == "inherit":
                        if default_allow:
                            allow_categories.append(k)
                        else:
                            deny_categories.append(k)
                    else:
                        deny_categories.append(k)

                return (set(allow_categories), set(deny_categories))


        @Jsonable("branding_config_id", "name", "favicon_logo_url", "header_logo_url", "html_title", "login_caption", "login_logo_url", "loading_session_text", "joining_session_text", "destroying_session_text", "hostname", "is_default", "login_splash_url", "launcher_background_url")
        class BrandingConfig(Base):
            __tablename__ = "branding_configs"
            branding_config_id = Column("branding_config_id", UUID(as_uuid=True), primary_key=True, server_default=(sqlalchemy.text("uuid_generate_v4()")))
            name = Column(String, nullable=False)
            favicon_logo_url = Column(String, nullable=False)
            header_logo_url = Column(String, nullable=False)
            html_title = Column(String, nullable=False)
            login_caption = Column(String, nullable=False)
            login_logo_url = Column(String, nullable=False)
            login_splash_url = Column(String, nullable=False)
            loading_session_text = Column(String, nullable=False)
            joining_session_text = Column(String, nullable=False)
            destroying_session_text = Column(String, nullable=False)
            is_default = Column(Boolean, default=False, server_default=(sqlalchemy.sql.expression.literal(False)), nullable=False)
            hostname = Column(String, nullable=False)
            launcher_background_url = Column(String, server_default="img/backgrounds/background1.jpg", nullable=False)

            @staticmethod
            def get_internal_branding_config():
                return {
                  'name': "Internal",
                  'favicon_logo_url': "/img/favicon.png",
                  'header_logo_url': "/img/headerlogo.svg",
                  'html_title': "Kasm Workspaces",
                  'login_caption': "The Container Streaming Platform®",
                  'login_logo_url': "/img/logo.svg",
                  'login_splash_url': "/img/login_splash.jpg",
                  'loading_session_text': "Creating a secure connection...",
                  'joining_session_text': "Creating a secure connection...",
                  'destroying_session_text': "Destroying session...",
                  'is_default': True,
                  'hostname': "*"}


        @Jsonable("staging_config_id", "zone_id", "zone_name", "image_id", "image_friendly_name", "num_sessions", "num_current_sessions", "expiration", "allow_kasm_audio", "allow_kasm_uploads", "allow_kasm_downloads", "allow_kasm_clipboard_down", "allow_kasm_clipboard_up", "allow_kasm_microphone", "allow_kasm_gamepad", "allow_kasm_webcam", "allow_kasm_printing", "server_pool_id", "server_pool_name", "autoscale_config_id", "autoscale_config_name")
        class StagingConfig(Base):
            __tablename__ = "staging_configs"
            staging_config_id = Column("staging_config_id", UUID(as_uuid=True), primary_key=True, server_default=(sqlalchemy.text("uuid_generate_v4()")))
            zone_id = Column("zone_id", UUID(as_uuid=True), ForeignKey("zones.zone_id", onupdate="CASCADE", ondelete="CASCADE"),
              index=True, nullable=False)
            zone = relationship("Zone", back_populates="staging_configs")
            server_pool_id = Column("server_pool_id", UUID(as_uuid=True), ForeignKey("server_pools.server_pool_id", onupdate="CASCADE", ondelete="CASCADE"),
              index=True, nullable=True)
            server_pool = relationship("ServerPool", back_populates="staging_configs", foreign_keys=[server_pool_id])
            autoscale_config_id = Column("autoscale_config_id", UUID(as_uuid=True), ForeignKey("autoscale_configs.autoscale_config_id", onupdate="CASCADE", ondelete="CASCADE"),
              index=True, nullable=True)
            autoscale_config = relationship("AutoScaleConfig", back_populates="staging_configs", foreign_keys=[autoscale_config_id])
            image_id = Column("image_id", UUID(as_uuid=True), ForeignKey("images.image_id", onupdate="CASCADE", ondelete="CASCADE"),
              index=True, nullable=False)
            image = relationship("Image", back_populates="staging_configs")
            num_sessions = Column(Integer, nullable=False)
            kasms = relationship("Kasm", back_populates="staging_config")
            expiration = Column(Float, nullable=False)
            allow_kasm_audio = Column(Boolean, server_default=(sqlalchemy.sql.expression.literal(False)), default=False, nullable=False)
            allow_kasm_uploads = Column(Boolean, server_default=(sqlalchemy.sql.expression.literal(False)), default=False, nullable=False)
            allow_kasm_downloads = Column(Boolean, server_default=(sqlalchemy.sql.expression.literal(False)), default=False, nullable=False)
            allow_kasm_clipboard_down = Column(Boolean, server_default=(sqlalchemy.sql.expression.literal(False)), default=False, nullable=False)
            allow_kasm_clipboard_up = Column(Boolean, server_default=(sqlalchemy.sql.expression.literal(False)), default=False, nullable=False)
            allow_kasm_microphone = Column(Boolean, server_default=(sqlalchemy.sql.expression.literal(False)), default=False, nullable=False)
            allow_kasm_gamepad = Column(Boolean, server_default=(sqlalchemy.sql.expression.literal(False)), default=False, nullable=False)
            allow_kasm_webcam = Column(Boolean, server_default=(sqlalchemy.sql.expression.literal(False)), default=False, nullable=False)
            allow_kasm_printing = Column(Boolean, server_default=(sqlalchemy.sql.expression.literal(False)), default=False, nullable=False)
            __table_args__ = (UniqueConstraint("zone_id", "image_id", name="_zone_id_image_id_uc"),)

            @property
            def zone_name(self):
                if self.zone:
                    return self.zone.zone_name

            @property
            def server_pool_name(self):
                if self.server_pool:
                    return self.server_pool.server_pool_name

            @property
            def autoscale_config_name(self):
                if self.autoscale_config:
                    return self.autoscale_config.autoscale_config_name

            @property
            def image_friendly_name(self):
                if self.image:
                    return self.image.friendly_name

            @property
            def num_current_sessions(self):
                return len([x for x in self.kasms if x.is_standby])

            @property
            def client_settings(self):
                client_settings = {'allow_kasm_audio':self.allow_kasm_audio, 
                 'allow_kasm_uploads':self.allow_kasm_uploads, 
                 'allow_kasm_downloads':self.allow_kasm_downloads, 
                 'allow_kasm_clipboard_down':self.allow_kasm_clipboard_down, 
                 'allow_kasm_clipboard_up':self.allow_kasm_clipboard_up, 
                 'allow_kasm_microphone':self.allow_kasm_microphone, 
                 'allow_kasm_gamepad':self.allow_kasm_gamepad, 
                 'allow_kasm_webcam':self.allow_kasm_webcam, 
                 'allow_kasm_printing':self.allow_kasm_printing}
                return client_settings


        @Jsonable("session_token_id", "session_date")
        class SessionToken(Base):
            __tablename__ = "session_tokens"
            session_token_id = Column("session_token_id", UUID(as_uuid=True), primary_key=True, server_default=(sqlalchemy.text("uuid_generate_v4()")))
            session_date = Column(TIMESTAMP, nullable=False)
            session_expiration_date = Column(TIMESTAMP, nullable=True)
            user_id = Column("user_id", UUID(as_uuid=True), ForeignKey("users.user_id", onupdate="CASCADE", ondelete="CASCADE"), index=True)
            user = relationship("User", back_populates="session_tokens")

            @property
            def is_expired(self):
                if self.session_expiration_date:
                    return datetime.datetime.utcnow() > self.session_expiration_date
                return False

            def generate_jwt(self, private_key, max_session_life, authorizations_filter=None):
                authorizations = []
                for authorization in self.get_authorizations():
                    if not authorizations_filter is None:
                        if authorization in authorizations_filter:
                            pass
                    authorizations.append(int(authorization))

                data = {'session_token_id':str(self.session_token_id),  'authorizations':authorizations}
                data["exp"] = datetime.datetime.utcnow() + datetime.timedelta(seconds=max_session_life)
                return jwt.encode(data, private_key, algorithm="RS256").decode("UTF-8")

            def get_authorizations(self):
                return self.user.get_authorizations()

            def expires_at(self, max_session_life):
                if self.session_expiration_date:
                    return self.session_expiration_date
                return self.session_date + datetime.timedelta(seconds=max_session_life)

            def output(self, max_session_life):
                return {'session_token':(self.session_token_id).hex, 
                 'session_token_date':str(self.session_date), 
                 'expires_at':str(self.expires_at(max_session_life))}


        @Jsonable("cast_config_id", "image_id", "image_friendly_name", "allowed_referrers", "limit_sessions", "session_remaining", "limit_ips", "ip_request_limit", "ip_request_seconds", "error_url", "enable_sharing", "disable_control_panel", "disable_tips", "disable_fixed_res", "key", "allow_anonymous", "group_id", "require_recaptcha", "group_name", "kasm_url", "dynamic_kasm_url", "dynamic_docker_network", "allow_resume", "enforce_client_settings", "allow_kasm_audio", "allow_kasm_uploads", "allow_kasm_downloads", "allow_kasm_downloads", "allow_kasm_clipboard_down", "allow_kasm_clipboard_up", "allow_kasm_microphone", "valid_until", "allow_kasm_sharing", "kasm_audio_default_on", "kasm_ime_mode_default_on", "allow_kasm_gamepad", "allow_kasm_webcam", "allow_kasm_printing", "casting_config_name", "remote_app_configs")
        class CastConfig(Base):
            __tablename__ = "cast_configs"
            cast_config_id = Column("cast_config_id", UUID(as_uuid=True), primary_key=True, server_default=(sqlalchemy.text("uuid_generate_v4()")))
            image_id = Column("image_id", UUID(as_uuid=True), ForeignKey("images.image_id", onupdate="CASCADE", ondelete="CASCADE"),
              index=True, nullable=False)
            image = relationship("Image", back_populates="cast_configs")
            allowed_referrers = Column(JSON, default=[], nullable=False)
            limit_sessions = Column(Boolean, default=False, server_default=(sqlalchemy.sql.expression.literal(False)), nullable=False)
            session_remaining = Column(Integer, nullable=False, default=0)
            limit_ips = Column(Boolean, default=False, server_default=(sqlalchemy.sql.expression.literal(False)), nullable=False)
            ip_request_limit = Column(Integer, nullable=False, default=0)
            ip_request_seconds = Column(Integer, nullable=False, default=0)
            error_url = Column(String, nullable=True)
            enable_sharing = Column(Boolean, default=False, server_default=(sqlalchemy.sql.expression.literal(False)), nullable=False)
            disable_control_panel = Column(Boolean, default=False, server_default=(sqlalchemy.sql.expression.literal(False)), nullable=False)
            disable_tips = Column(Boolean, default=False, server_default=(sqlalchemy.sql.expression.literal(False)), nullable=False)
            disable_fixed_res = Column(Boolean, default=False, server_default=(sqlalchemy.sql.expression.literal(False)), nullable=False)
            key = Column(String, nullable=False, unique=True)
            allow_anonymous = Column(Boolean, default=False, server_default=(sqlalchemy.sql.expression.literal(False)), nullable=False)
            group_id = Column(UUID(as_uuid=True), ForeignKey("groups.group_id", onupdate="CASCADE", ondelete="CASCADE"), index=True)
            group = relationship("Group", back_populates="cast_configs")
            require_recaptcha = Column(Boolean, default=False, server_default=(sqlalchemy.sql.expression.literal(False)), nullable=False)
            kasm_url = Column(String)
            dynamic_kasm_url = Column(Boolean, default=False, server_default=(sqlalchemy.sql.expression.literal(False)), nullable=False)
            dynamic_docker_network = Column(Boolean, default=False, server_default=(sqlalchemy.sql.expression.literal(False)), nullable=False)
            allow_resume = Column(Boolean, default=True, server_default=(sqlalchemy.sql.expression.literal(True)), nullable=False)
            enforce_client_settings = Column(Boolean, default=False, server_default=(sqlalchemy.sql.expression.literal(False)), nullable=False)
            allow_kasm_audio = Column(Boolean, server_default=(sqlalchemy.sql.expression.literal(False)), default=False, nullable=False)
            allow_kasm_uploads = Column(Boolean, server_default=(sqlalchemy.sql.expression.literal(False)), default=False, nullable=False)
            allow_kasm_downloads = Column(Boolean, server_default=(sqlalchemy.sql.expression.literal(False)), default=False, nullable=False)
            allow_kasm_clipboard_down = Column(Boolean, server_default=(sqlalchemy.sql.expression.literal(False)), default=False, nullable=False)
            allow_kasm_clipboard_up = Column(Boolean, server_default=(sqlalchemy.sql.expression.literal(False)), default=False, nullable=False)
            allow_kasm_microphone = Column(Boolean, server_default=(sqlalchemy.sql.expression.literal(False)), default=False, nullable=False)
            allow_kasm_sharing = Column(Boolean, server_default=(sqlalchemy.sql.expression.literal(False)), default=False, nullable=False)
            kasm_audio_default_on = Column(Boolean, server_default=(sqlalchemy.sql.expression.literal(False)), default=False, nullable=False)
            kasm_ime_mode_default_on = Column(Boolean, server_default=(sqlalchemy.sql.expression.literal(False)), default=False, nullable=False)
            allow_kasm_gamepad = Column(Boolean, server_default=(sqlalchemy.sql.expression.literal(False)), default=False, nullable=False)
            allow_kasm_webcam = Column(Boolean, server_default=(sqlalchemy.sql.expression.literal(False)), default=False, nullable=False)
            allow_kasm_printing = Column(Boolean, server_default=(sqlalchemy.sql.expression.literal(False)), default=False, nullable=False)
            casting_config_name = Column(String, nullable=False, unique=True)
            valid_until = Column(TIMESTAMP)
            kasms = relationship("Kasm", back_populates="cast_config")
            remote_app_configs = Column(JSON, default={}, nullable=True)

            @property
            def image_friendly_name(self):
                if self.image:
                    return self.image.friendly_name

            @property
            def group_name(self):
                if self.group:
                    return self.group.name

            @property
            def client_settings(self):
                client_settings = {'allow_kasm_audio':self.allow_kasm_audio, 
                 'allow_kasm_uploads':self.allow_kasm_uploads, 
                 'allow_kasm_downloads':self.allow_kasm_downloads, 
                 'allow_kasm_clipboard_down':self.allow_kasm_clipboard_down, 
                 'allow_kasm_clipboard_up':self.allow_kasm_clipboard_up, 
                 'allow_kasm_microphone':self.allow_kasm_microphone, 
                 'allow_kasm_sharing':self.allow_kasm_sharing, 
                 'allow_kasm_gamepad':self.allow_kasm_gamepad, 
                 'allow_kasm_webcam':self.allow_kasm_webcam, 
                 'allow_kasm_printing':self.allow_kasm_printing, 
                 'kasm_audio_default_on':self.kasm_audio_default_on, 
                 'kasm_ime_mode_default_on':self.kasm_ime_mode_default_on}
                return client_settings

            def generate_connection_info(self, url_params):
                conn_info = {}
                if self.remote_app_configs:
                    if "remote_app_name" in self.remote_app_configs:
                        conn_info = {"guac": {"settings": {"remote-app": (self.remote_app_configs["remote_app_name"])}}}
                        if "args" in self.remote_app_configs:
                            argument_string = ""
                            for arg in self.remote_app_configs["args"]:
                                if "argument_name" in arg:
                                    argument_string += f'{arg["argument_name"]} '
                                if "value" in arg:
                                    argument_string += f'{arg["value"]} '
                                if "url_param_name" in arg and arg["url_param_name"]:
                                    if not url_params:
                                        if not arg["url_param_name"] in url_params:
                                            value = url_params[arg["url_param_name"]]
                                            if "value_pattern" in arg:
                                                if re.search(arg["value_pattern"], value) is None:
                                                    raise ValueError("URL parameter value did not match value pattern.")
                                            argument_string += f"{value} "
                                else:
                                    if "url_param_name" in arg:
                                        if arg["url_param_name"]:
                                            if "required" in arg:
                                                if arg["required"]:
                                                    raise ValueError("URL missing required parameter.")
                                                conn_info["guac"]["settings"]["remote-app-args"] = argument_string

                    return conn_info

            def validate(self):
                if self.remote_app_configs:
                    if "remote_app_name" in self.remote_app_configs:
                        if "args" in self.remote_app_configs["remote_app_name"]:
                            for arg in self.remote_app_configs["remote_app_name"]["args"]:
                                if "value" in arg:
                                    if "url_param_name" in arg or "value_pattern" in arg:
                                        raise ValueError("Invalid RemoteApp configuration, value defined with url_param_name or value_pattern.")
                                    if "value" not in arg:
                                        if "url_param_name" not in arg:
                                            raise ValueError("Invalid RemoteApp configuration, a value or url_param_name must be defined for each argument.")
                                    if "required" in arg:
                                        if type(arg["required"]) is not bool:
                                            raise ValueError("Invalid RemoteApp configuration, required field should be a bool.")
                                        if "value_pattern" in arg:
                                            try:
                                                re.compile(arg["value_pattern"])
                                            except re.error:
                                                raise ValueError("Invalid RemoteApp configuration, value_pattern is not a valid regular expression.")

                    else:
                        raise ValueError("Invalid Remote App Configuration")


        @Jsonable("session_permission_id", "kasm_id", "user_id", "access", "vnc_username", "username", sanitize=[
         "vnc_password"])
        class SessionPermission(Base):
            __tablename__ = "session_permissions"
            session_permission_id = Column("session_permission_id", UUID(as_uuid=True), primary_key=True,
              server_default=(sqlalchemy.text("uuid_generate_v4()")))
            kasm_id = Column("kasm_id", UUID(as_uuid=True), ForeignKey("kasms.kasm_id", onupdate="CASCADE", ondelete="CASCADE"), index=True,
              nullable=False)
            kasm = relationship("Kasm", back_populates="session_permissions")
            user_id = Column("user_id", UUID(as_uuid=True), ForeignKey("users.user_id", onupdate="CASCADE", ondelete="CASCADE"), index=True,
              nullable=False)
            user = relationship("User", back_populates="session_permissions")
            access = Column(String, nullable=False)
            vnc_username = Column(String, nullable=False)
            vnc_password = Column((EncryptedType(String, get_key, AesEngine, "pkcs5")), nullable=False)
            __table_args__ = (UniqueConstraint("kasm_id", "user_id", name="_kasm_id_user_id_uc"),)

            @property
            def username(self):
                return self.user.username


        @Jsonable("auto_login", "enabled", "is_default", "hostname", "display_name", "oidc_id", "client_id", "auth_url", "token_url",
          "scope", "redirect_url", "user_info_url", "client_secret", "logo_url", "username_attribute", "groups_attribute",
          "debug", sanitize=["client_secret"])
        class OIDCConfig(Base):
            __tablename__ = "oidc_configs"
            oidc_id = Column("oidc_id", UUID(as_uuid=True), primary_key=True, server_default=(sqlalchemy.text("uuid_generate_v4()")))
            auto_login = Column(Boolean, default=False, nullable=False)
            enabled = Column(Boolean, default=False, nullable=False)
            is_default = Column(Boolean, default=False, nullable=False)
            hostname = Column(String, nullable=True)
            display_name = Column(String, nullable=False)
            client_id = Column(String, nullable=False)
            client_secret = Column((EncryptedType(String, get_key, AesEngine, "pkcs5")), nullable=False)
            auth_url = Column(String, nullable=False)
            token_url = Column(String, nullable=False)
            scope = Column(JSON, default=[], server_default="[]", nullable=False)
            redirect_url = Column(String, nullable=False)
            user_info_url = Column(String, nullable=False)
            logo_url = Column(String, nullable=True)
            username_attribute = Column(String, nullable=False)
            groups_attribute = Column(String, nullable=True)
            debug = Column(Boolean, default=False, nullable=False)
            group_mappings = relationship("SSOToGroupMapping", back_populates="oidc_config", passive_deletes=True)
            user_attribute_mappings = relationship("SSOAttributeToUserFieldMapping", back_populates="oidc_config", passive_deletes=True)


        @Jsonable("sso_attribute_id", "ldap_id", "saml_id", "oidc_id", "attribute_name", "user_field")
        class SSOAttributeToUserFieldMapping(Base):
            __tablename__ = "sso_attribute_userfield_mapping"
            sso_attribute_id = Column("sso_attribute_id", UUID(as_uuid=True), primary_key=True,
              server_default=(sqlalchemy.text("uuid_generate_v4()")))
            ldap_id = Column("ldap_id", UUID(as_uuid=True), ForeignKey("ldap_configs.ldap_id", onupdate="CASCADE", ondelete="CASCADE"), index=True)
            saml_id = Column("saml_id", UUID(as_uuid=True), ForeignKey("saml_config.saml_id", onupdate="CASCADE", ondelete="CASCADE"), index=True)
            oidc_id = Column("oidc_id", UUID(as_uuid=True), ForeignKey("oidc_configs.oidc_id", onupdate="CASCADE", ondelete="CASCADE"), index=True)
            ldap_config = relationship("LDAPConfig", back_populates="user_attribute_mappings")
            saml_config = relationship("SAMLConfig", back_populates="user_attribute_mappings")
            oidc_config = relationship("OIDCConfig", back_populates="user_attribute_mappings")
            attribute_name = Column(String)
            user_field = Column(String)

            def process_attributes(self, user, attributes):
                value = None
                if self.attribute_name in attributes:
                    value = str(attributes[self.attribute_name][0]) if isinstance(attributes[self.attribute_name], list) else str(attributes[self.attribute_name])
                self.apply(user, value)
                return value

            def apply(self, user, value):
                if user is None or not isinstance(user, User):
                    raise ValueError("Invalid User passed.")
                if self.user_field == "First Name":
                    user.first_name = value
                elif self.user_field == "Last Name":
                    user.last_name = value
                elif self.user_field == "Phone":
                    user.phone = value
                elif self.user_field == "Organization":
                    user.organization = value
                elif self.user_field == "Notes":
                    user.notes = value
                elif self.user_field == "City":
                    user.city = value
                elif self.user_field == "State":
                    user.state = value
                elif self.user_field == "Country":
                    user.country = value
                elif self.user_field == "Email":
                    user.email = value
                elif self.user_field == "Custom Attribute 1":
                    user.custom_attribute_1 = value
                elif self.user_field == "Custom Attribute 2":
                    user.custom_attribute_2 = value
                elif self.user_field == "Custom Attribute 3":
                    user.custom_attribute_3 = value
                else:
                    return False
                return True

            @staticmethod
            def user_fields():
                return [
                 "First Name","Last Name","Phone","Organization","Notes","City","State","Country","Email","Custom Attribute 1","Custom Attribute 2","Custom Attribute 3"]


        @Jsonable("sso_group_id", "ldap_id", "saml_id", "oidc_id", "group_id", "sso_group_attributes", "apply_to_all_users", "sso_name", "sso_type")
        class SSOToGroupMapping(Base):
            __tablename__ = "sso_to_group_mapping"
            sso_group_id = Column("sso_group_id", UUID(as_uuid=True), primary_key=True,
              server_default=(sqlalchemy.text("uuid_generate_v4()")))
            ldap_id = Column("ldap_id", UUID(as_uuid=True), ForeignKey("ldap_configs.ldap_id", onupdate="CASCADE", ondelete="CASCADE"), index=True)
            saml_id = Column("saml_id", UUID(as_uuid=True), ForeignKey("saml_config.saml_id", onupdate="CASCADE", ondelete="CASCADE"), index=True)
            oidc_id = Column("oidc_id", UUID(as_uuid=True), ForeignKey("oidc_configs.oidc_id", onupdate="CASCADE", ondelete="CASCADE"), index=True)
            group_id = Column(UUID(as_uuid=True), ForeignKey("groups.group_id", onupdate="CASCADE", ondelete="CASCADE"), index=True, nullable=False)
            sso_group_attributes = Column(String)
            apply_to_all_users = Column(Boolean, default=False, server_default=(sqlalchemy.sql.expression.literal(False)), nullable=False)
            ldap_config = relationship("LDAPConfig", back_populates="group_mappings")
            saml_config = relationship("SAMLConfig", back_populates="group_mappings")
            oidc_config = relationship("OIDCConfig", back_populates="group_mappings")
            group = relationship("Group", back_populates="group_mappings")

            @property
            def sso_name(self):
                if self.ldap_id:
                    return self.ldap_config.name
                if self.saml_id:
                    return self.saml_config.display_name
                if self.oidc_id:
                    return self.oidc_config.display_name
                raise Exception("No SSO specified")

            @property
            def sso_type(self):
                if self.ldap_id:
                    return "ldap"
                if self.saml_id:
                    return "saml"
                if self.oidc_id:
                    return "oidc"
                raise Exception("No SSO specified")

            @property
            def sso_id(self):
                if self.ldap_id:
                    return self.ldap_id
                if self.saml_id:
                    return self.saml_id
                if self.oidc_id:
                    return self.oidc_id
                raise Exception("No SSO specified")


        @Jsonable("file_map_id", "created", "user_id", "group_id", "image_id", "kasm_id", "name", "description", "destination", "file_type", "is_readable", "is_writable", "is_executable")
        class FileMap(Base):
            __tablename__ = "file_mappings"
            file_map_id = Column("file_map_id", UUID(as_uuid=True), primary_key=True,
              server_default=(sqlalchemy.text("uuid_generate_v4()")))
            created = Column(TIMESTAMP, nullable=False)
            user_id = Column("user_id", UUID(as_uuid=True), ForeignKey("users.user_id", onupdate="CASCADE", ondelete="CASCADE"), index=True)
            image_id = Column("image_id", UUID(as_uuid=True), ForeignKey("images.image_id", onupdate="CASCADE", ondelete="CASCADE"), index=True)
            group_id = Column("group_id", UUID(as_uuid=True), ForeignKey("groups.group_id", onupdate="CASCADE", ondelete="CASCADE"), index=True)
            kasm_id = Column("kasm_id", UUID(as_uuid=True), ForeignKey("kasms.kasm_id", onupdate="CASCADE", ondelete="CASCADE"), index=True)
            user = relationship("User", back_populates="file_mappings")
            image = relationship("Image", back_populates="file_mappings")
            group = relationship("Group", back_populates="file_mappings")
            kasm = relationship("Kasm", back_populates="file_mappings")
            name = Column(String, nullable=False)
            description = Column(String, nullable=True)
            destination = Column(String, nullable=False)
            file_type = Column(String, nullable=False)
            is_readable = Column(Boolean, default=False, server_default=(sqlalchemy.sql.expression.literal(False)), nullable=False)
            is_writable = Column(Boolean, default=False, server_default=(sqlalchemy.sql.expression.literal(False)), nullable=False)
            is_executable = Column(Boolean, default=False, server_default=(sqlalchemy.sql.expression.literal(False)), nullable=False)
            content = Column((EncryptedType(String, get_key, AesEngine, "pkcs5")), nullable=False)

            @property
            def os_type(self):
                if self.destination:
                    if not self.destination.startswith("/"):
                        return OS_TYPES.WINDOWS
                    return OS_TYPES.LINUX


        @Jsonable("storage_mapping_id", "name", "config", "enabled", "user_id", "group_id", "image_id", "storage_provider_id", "read_only",
          "target", "storage_provider_type", "webdav_user", "webdav_pass", "s3_access_key_id", "s3_secret_access_key",
          "oauth_token", "s3_bucket", sanitize=[
         "webdav_pass", "s3_secret_access_key", "oauth_token"])
        class StorageMapping(Base):
            __tablename__ = "storage_mappings"
            storage_mapping_id = Column("storage_mapping_id", UUID(as_uuid=True), primary_key=True,
              server_default=(sqlalchemy.text("uuid_generate_v4()")))
            name = Column(String, nullable=False)
            config = Column((StringEncryptedType(EncryptedJSONType, get_key, AesEngine, "pkcs5")), default={}, nullable=False)
            user_id = Column("user_id", UUID(as_uuid=True), ForeignKey("users.user_id", onupdate="CASCADE", ondelete="CASCADE"), index=True)
            image_id = Column("image_id", UUID(as_uuid=True), ForeignKey("images.image_id", onupdate="CASCADE", ondelete="CASCADE"), index=True)
            group_id = Column("group_id", UUID(as_uuid=True), ForeignKey("groups.group_id", onupdate="CASCADE", ondelete="CASCADE"), index=True)
            storage_provider_id = Column("storage_provider_id", UUID(as_uuid=True), ForeignKey("storage_providers.storage_provider_id", onupdate="CASCADE", ondelete="CASCADE"), index=True, nullable=False)
            user = relationship("User", back_populates="storage_mappings")
            image = relationship("Image", back_populates="storage_mappings")
            group = relationship("Group", back_populates="storage_mappings")
            storage_provider = relationship("StorageProvider", back_populates="storage_mappings")
            enabled = Column(Boolean, default=False, server_default=(sqlalchemy.sql.expression.literal(False)), nullable=False)
            target = Column(String, nullable=True)
            read_only = Column(Boolean, default=False, server_default=(sqlalchemy.sql.expression.literal(False)), nullable=False)
            s3_access_key_id = Column(String, nullable=True)
            s3_secret_access_key = Column((EncryptedType(String, get_key, AesEngine, "pkcs5")), nullable=True)
            s3_bucket = Column(String, nullable=True)
            webdav_user = Column(String, nullable=True)
            webdav_pass = Column((EncryptedType(String, get_key, AesEngine, "pkcs5")), nullable=True)
            oauth_token = Column((StringEncryptedType(EncryptedJSONType, get_key, AesEngine, "pkcs5")), default={}, nullable=False)

            @property
            def storage_provider_type(self):
                return self.storage_provider.storage_provider_type

            __table_args__ = (
             CheckConstraint("(user_id IS NOT NULL)::int + (group_id IS NOT NULL)::int + (image_id IS NOT NULL)::int = 1", name="storage_mappings_check"),)


        @Jsonable("name", "storage_provider_id", "storage_provider_type", "client_id", "client_secret", "auth_url", "token_url", "webdav_url",
          "scope", "redirect_url", "auth_url_options", "volume_config", "mount_config", "root_drive_url", "default_target",
          "enabled", sanitize=[
         "client_secret"])
        class StorageProvider(Base):
            __tablename__ = "storage_providers"
            storage_provider_id = Column("storage_provider_id", UUID(as_uuid=True), primary_key=True,
              server_default=(sqlalchemy.text("uuid_generate_v4()")))
            storage_provider_type = Column("storage_provider_type", String, nullable=False, server_default=(STORAGE_PROVIDER_TYPES.OTHER.value), default=(STORAGE_PROVIDER_TYPES.OTHER.value))
            name = Column(String, nullable=False)
            client_id = Column(String, nullable=True)
            client_secret = Column((EncryptedType(String, get_key, AesEngine, "pkcs5")), nullable=True)
            auth_url = Column(String, nullable=True)
            token_url = Column(String, nullable=True)
            webdav_url = Column(String, nullable=True)
            scope = Column(JSON, default=[], server_default="[]", nullable=False)
            redirect_url = Column(String, nullable=True)
            auth_url_options = Column(JSON, default={}, server_default="{}", nullable=False)
            volume_config = Column(JSON, default={}, server_default="{}", nullable=False)
            mount_config = Column(JSON, default={}, server_default="{}", nullable=False)
            root_drive_url = Column(String, nullable=True)
            default_target = Column(String, nullable=False)
            enabled = Column(Boolean, default=False, server_default=(sqlalchemy.sql.expression.literal(False)), nullable=False)
            storage_mappings = relationship("StorageMapping", back_populates="storage_provider", passive_deletes=True)

            @property
            def target(self):
                if self.config:
                    if "mount_config" in self.config:
                        return self.config["mount_config"].get("target")

            @property
            def is_read_only(self):
                if self.config:
                    if "mount_config" in self.config:
                        return self.config["mount_config"].get("read_only")


        @Jsonable("connection_proxy_id", "connection_proxy_type", "server_address", "server_port", "first_reported", "last_reported",
          "last_reported_elapsed", "last_reported_seconds", "zone_id", "zone_name", "auth_token", sanitize=["auth_token"])
        class ConnectionProxy(Base):
            __tablename__ = "connection_proxies"
            connection_proxy_id = Column("connection_proxy_id", UUID(as_uuid=True), primary_key=True,
              server_default=(sqlalchemy.text("uuid_generate_v4()")))
            connection_proxy_type = Column(String, nullable=False)
            auth_token = Column(StringEncryptedType(String, get_key, AesEngine, "pkcs5"))
            server_port = Column(Integer, nullable=False)
            server_address = Column(String, nullable=False)
            first_reported = Column("first_reported", TIMESTAMP)
            last_reported = Column("last_reported", TIMESTAMP)
            zone_id = Column("zone_id", UUID(as_uuid=True), ForeignKey("zones.zone_id", onupdate="CASCADE", ondelete="SET NULL"),
              index=True, nullable=False)
            zone = relationship("Zone", back_populates="connection_proxies", foreign_keys=[zone_id])
            kasms = relationship("Kasm", back_populates="connection_proxy", passive_deletes=True)

            @property
            def last_reported_elapsed(self):
                if self.last_reported:
                    return str(datetime.datetime.utcnow() - self.last_reported).split(".")[:-1][0]

            @property
            def last_reported_seconds(self):
                if self.last_reported:
                    return (datetime.datetime.utcnow() - self.last_reported).total_seconds()

            @property
            def zone_name(self):
                if self.zone:
                    return self.zone.zone_name


        @Jsonable("server_pool_id", "server_pool_name", "server_pool_type", "servers", "images", "autoscale_configs")
        class ServerPool(Base):
            __tablename__ = "server_pools"
            server_pool_id = Column("server_pool_id", UUID(as_uuid=True), primary_key=True,
              server_default=(sqlalchemy.text("uuid_generate_v4()")))
            server_pool_name = Column(String, nullable=False)
            server_pool_type = Column(String, server_default=(SERVER_POOL_TYPE.DOCKER_AGENT.value), nullable=False)
            servers = relationship("Server", back_populates="server_pool")
            images = relationship("Image", back_populates="server_pool")
            autoscale_configs = relationship("AutoScaleConfig", back_populates="server_pool")
            staging_configs = relationship("StagingConfig", back_populates="server_pool")


        @Jsonable("autoscale_config_id", "enabled", "autoscale_config_name", "autoscale_type", "standby_cores", "standby_memory_mb",
          "standby_gpus", "downscale_backoff", "last_provision", "request_downscale_at",
          "register_dns", "base_domain_name", "nginx_cert", "nginx_key", "agent_cores_override", "agent_memory_override_gb",
          "agent_gpus_override",
          "aws_config_id", "aws_config", "azure_config_id", "azure_config", "vm_provider_config", "azure_dns_config",
          "azure_dns_config_id", "openstack_vm_config_id", "openstack_config", "zone_id",
          "zone_name", "connection_type",
          "connection_info", "connection_port", "connection_username", "connection_password", "reusable",
          "hooks", "minimum_pool_standby_sessions", "server_pool_id",
          "vm_provider_config_id", "max_simultaneous_sessions_per_server", "dns_provider_config_id",
          "ldap_id", "ad_create_machine_record", "ad_recursive_machine_record_cleanup", "ad_computer_container_dn",
          "connection_private_key", "use_user_private_key", "connection_passphrase", "agent_installed",
          "require_checkin", "aggressive_scaling", sanitize=[
         "nginx_cert","nginx_key","connection_password","connection_private_key","connection_passphrase"])
        class AutoScaleConfig(Base):
            __tablename__ = "autoscale_configs"
            autoscale_config_id = Column("autoscale_config_id", UUID(as_uuid=True), primary_key=True,
              server_default=(sqlalchemy.text("uuid_generate_v4()")))
            enabled = Column(Boolean, server_default="false", default=False, nullable=False)
            autoscale_config_name = Column(String, nullable=False)
            autoscale_type = Column(String, nullable=False)
            standby_cores = Column(Integer, nullable=False, default=0, server_default="0")
            standby_memory_mb = Column(Integer, nullable=False, default=0, server_default="0")
            standby_gpus = Column(Integer, nullable=False, default=0, server_default="0")
            downscale_backoff = Column(Integer, nullable=False, default=0, server_default="0")
            last_provision = Column(TIMESTAMP, nullable=False)
            request_downscale_at = Column(TIMESTAMP, nullable=False)
            register_dns = Column(Boolean, default=False)
            base_domain_name = Column(String)
            nginx_cert = Column((StringEncryptedType(String, get_key, AesEngine, "pkcs5")), nullable=False, default="")
            nginx_key = Column((StringEncryptedType(String, get_key, AesEngine, "pkcs5")), nullable=False, default="")
            agent_cores_override = Column(Integer)
            agent_memory_override_gb = Column(Float)
            agent_gpus_override = Column(Integer)
            schedules = relationship("Schedule", back_populates="autoscale_config", passive_deletes=True)
            connection_type = Column(String, default=(CONNECTION_TYPE.KASMVNC.value), server_default=(CONNECTION_TYPE.KASMVNC.value),
              nullable=False)
            connection_info = Column((StringEncryptedType(EncryptedJSONType, get_key, AesEngine, "pkcs5")), default={}, nullable=False)
            connection_port = Column(Integer)
            connection_username = Column(String)
            connection_password = Column(StringEncryptedType(String, get_key, AesEngine, "pkcs5"))
            connection_private_key = Column(StringEncryptedType(String, get_key, AesEngine, "pkcs5"))
            connection_passphrase = Column(StringEncryptedType(String, get_key, AesEngine, "pkcs5"))
            use_user_private_key = Column(Boolean, server_default="true", default=True, nullable=False)
            agent_installed = Column(Boolean, nullable=False, default=False, server_default="false")
            require_checkin = Column(Boolean, nullable=False, default=False, server_default="false")
            reusable = Column(Boolean, nullable=False, server_default="false", default=False)
            hooks = Column(JSON, default={}, server_default="{}", nullable=False)
            minimum_pool_standby_sessions = Column(Integer, default=0, server_default="0", nullable=False)
            max_simultaneous_sessions_per_server = Column(Integer, default=1, server_default="1", nullable=False)
            aggressive_scaling = Column(Boolean, nullable=False, default=False, server_default="false")
            ldap_id = Column("ldap_id", UUID(as_uuid=True), ForeignKey("ldap_configs.ldap_id", onupdate="CASCADE", ondelete="CASCADE"), index=True)
            ldap_config = relationship("LDAPConfig", back_populates="autoscale_configs")
            ad_create_machine_record = Column(Boolean, default=False)
            ad_recursive_machine_record_cleanup = Column(Boolean, default=False)
            ad_computer_container_dn = Column(String)
            azure_config_id = Column("azure_config_id", UUID(as_uuid=True), ForeignKey("azure_configs.azure_config_id", onupdate="CASCADE", ondelete="SET NULL"),
              index=True, nullable=True)
            azure_config = relationship("AzureVMConfig", back_populates="autoscale_configs", foreign_keys=[azure_config_id])
            azure_dns_config_id = Column("azure_dns_config_id", UUID(as_uuid=True), ForeignKey("azure_dns_configs.azure_dns_config_id", onupdate="CASCADE", ondelete="SET NULL"),
              index=True, nullable=True)
            azure_dns_config = relationship("AzureDNSConfig", back_populates="autoscale_configs", foreign_keys=[azure_dns_config_id])
            aws_config_id = Column("aws_config_id", UUID(as_uuid=True), ForeignKey("aws_configs.aws_config_id", onupdate="CASCADE", ondelete="SET NULL"),
              index=True, nullable=True)
            aws_config = relationship("AwsVMConfig", back_populates="autoscale_configs", foreign_keys=[aws_config_id])
            aws_dns_config_id = Column("aws_dns_config_id", UUID(as_uuid=True), ForeignKey("aws_dns_configs.config_id", onupdate="CASCADE", ondelete="SET NULL"),
              index=True, nullable=True)
            aws_dns_config = relationship("AwsDNSConfig", back_populates="autoscale_configs", foreign_keys=[aws_dns_config_id])
            digital_ocean_vm_config_id = Column("digital_ocean_vm_config_id", UUID(as_uuid=True), ForeignKey("digital_ocean_vm_configs.config_id", onupdate="CASCADE", ondelete="SET NULL"),
              index=True, nullable=True)
            digital_ocean_config = relationship("DigitalOceanVMConfig", back_populates="autoscale_configs", foreign_keys=[digital_ocean_vm_config_id])
            digital_ocean_dns_config_id = Column("digital_ocean_dns_config_id", UUID(as_uuid=True), ForeignKey("digital_ocean_dns_configs.config_id", onupdate="CASCADE", ondelete="SET NULL"),
              index=True, nullable=True)
            digital_ocean_dns_config = relationship("DigitalOceanDNSConfig", back_populates="autoscale_configs", foreign_keys=[digital_ocean_dns_config_id])
            oci_vm_config_id = Column("oci_vm_config_id", UUID(as_uuid=True), ForeignKey("oci_vm_configs.config_id", onupdate="CASCADE", ondelete="SET NULL"),
              index=True, nullable=True)
            oci_config = relationship("OracleVMConfig", back_populates="autoscale_configs", foreign_keys=[oci_vm_config_id])
            oci_dns_config_id = Column("oci_dns_config_id", UUID(as_uuid=True), ForeignKey("oci_dns_configs.config_id", onupdate="CASCADE", ondelete="SET NULL"),
              index=True, nullable=True)
            oci_dns_config = relationship("OracleDNSConfig", back_populates="autoscale_configs", foreign_keys=[oci_dns_config_id])
            gcp_vm_config_id = Column("gcp_vm_config_id", UUID(as_uuid=True), ForeignKey("gcp_vm_configs.config_id", onupdate="CASCADE", ondelete="SET NULL"),
              index=True, nullable=True)
            gcp_config = relationship("GcpVMConfig", back_populates="autoscale_configs", foreign_keys=[gcp_vm_config_id])
            gcp_dns_config_id = Column("gcp_dns_config_id", UUID(as_uuid=True), ForeignKey("gcp_dns_configs.config_id", onupdate="CASCADE", ondelete="SET NULL"),
              index=True, nullable=True)
            gcp_dns_config = relationship("GcpDNSConfig", back_populates="autoscale_configs", foreign_keys=[gcp_dns_config_id])
            vsphere_vm_config_id = Column("vsphere_vm_config_id", UUID(as_uuid=True), ForeignKey("vsphere_vm_configs.config_id", onupdate="CASCADE", ondelete="SET NULL"),
              index=True, nullable=True)
            vsphere_config = relationship("VsphereVMConfig", back_populates="autoscale_configs", foreign_keys=[vsphere_vm_config_id])
            openstack_vm_config_id = Column("openstack_vm_config_id", UUID(as_uuid=True), ForeignKey("openstack_vm_configs.config_id", onupdate="CASCADE", ondelete="SET NULL"),
              index=True, nullable=True)
            openstack_config = relationship("OpenStackVMConfig", back_populates="autoscale_configs", foreign_keys=[openstack_vm_config_id])
            server_pool_id = Column("server_pool_id", UUID(as_uuid=True), ForeignKey("server_pools.server_pool_id", onupdate="CASCADE", ondelete="SET NULL"),
              index=True, nullable=True)
            server_pool = relationship("ServerPool", back_populates="autoscale_configs", foreign_keys=[server_pool_id])
            servers = relationship("Server", passive_deletes=True, foreign_keys="Server.autoscale_config_id")
            staging_configs = relationship("StagingConfig", passive_deletes=True, foreign_keys="StagingConfig.autoscale_config_id")
            kasms = relationship("Kasm", passive_deletes=True, foreign_keys="Kasm.autoscale_config_id")
            zone_id = Column("zone_id", UUID(as_uuid=True), ForeignKey("zones.zone_id", onupdate="CASCADE", ondelete="SET NULL"),
              index=True, nullable=False)
            zone = relationship("Zone", back_populates="autoscale_configs", foreign_keys=[zone_id])

            @property
            def vm_provider_config(self):
                if self.aws_config_id:
                    return self.aws_config
                if self.azure_config_id:
                    return self.azure_config
                if self.digital_ocean_vm_config_id:
                    return self.digital_ocean_config
                if self.oci_vm_config_id:
                    return self.oci_config
                if self.gcp_vm_config_id:
                    return self.gcp_config
                if self.vsphere_vm_config_id:
                    return self.vsphere_config
                if self.openstack_vm_config_id:
                    return self.openstack_config

            @property
            def vm_provider_config_id(self):
                if self.vm_provider_config:
                    return self.vm_provider_config.vm_provider_config_id

            @property
            def dns_provider_config(self):
                if self.azure_dns_config_id:
                    return self.azure_dns_config
                if self.aws_dns_config_id:
                    return self.aws_dns_config
                if self.digital_ocean_dns_config_id:
                    return self.digital_ocean_dns_config
                if self.oci_dns_config_id:
                    return self.oci_dns_config
                if self.gcp_dns_config_id:
                    return self.gcp_dns_config

            @property
            def dns_provider_config_id(self):
                if self.dns_provider_config:
                    return self.dns_provider_config.dns_provider_config_id

            @property
            def is_azure(self):
                if self.azure_config:
                    return True
                return False

            @property
            def is_aws(self):
                if self.aws_config:
                    return True
                return False

            @property
            def is_digital_ocean(self):
                if self.digital_ocean_config:
                    return True
                return False

            @property
            def is_oci(self):
                if self.oci_config:
                    return True
                return False

            @property
            def is_gcp(self):
                if self.gcp_config:
                    return True
                return False

            @property
            def is_vsphere(self):
                if self.vsphere_config:
                    return True
                return False

            @property
            def is_desktop_pool(self):
                if self.server_pool_id:
                    if self.server_pool.server_pool_type == SERVER_POOL_TYPE.SERVER.value:
                        return True
                    return False

            @property
            def is_agent_pool(self):
                if self.server_pool_id:
                    if self.server_pool.server_pool_type == SERVER_POOL_TYPE.DOCKER_AGENT.value:
                        return True
                    return False

            @property
            def zone_name(self):
                if self.zone:
                    return self.zone.zone_name

            @property
            def is_active(self):
                is_active = False
                if self.schedules:
                    for schedule in self.schedules:
                        if schedule.is_active():
                            is_active = True
                            break

                else:
                    is_active = True
                return is_active

            def desired_staged_resources(self, only_remaining=False):
                desired_cores = 0
                desired_memory = 0
                desired_gpus = 0
                unmet_cores = 0
                unmet_memory = 0
                unmet_gpus = 0
                if self.staging_configs:
                    for staging_config in self.staging_configs:
                        if staging_config.num_sessions > 0:
                            multiplier = staging_config.num_sessions
                            if only_remaining:
                                multiplier = multiplier - staging_config.num_current_sessions
                                if self.agent_cores_override >= staging_config.image.cores and self.agent_gpus_override >= staging_config.image.gpus and self.agent_memory_override_gb >= staging_config.image.memory_gb:
                                    desired_cores += staging_config.image.cores * multiplier
                                    desired_memory += staging_config.image.memory * multiplier
                                    desired_gpus += staging_config.image.gpus * multiplier
                                else:
                                    unmet_cores = max(max(0, staging_config.image.cores - self.agent_cores_override), unmet_cores)
                                    unmet_memory = max(max(0, staging_config.image.memory - self.agent_memory_override_gb), unmet_memory)
                                    unmet_gpus = max(max(0, staging_config.image.gpus - self.agent_gpus_override), unmet_gpus)
                            else:
                                desired_cores += staging_config.image.cores * multiplier
                                desired_memory += staging_config.image.memory * multiplier
                                desired_gpus += staging_config.image.gpus * multiplier

                    return {
                      'memory': desired_memory, 'cores': desired_cores, 'gpus': desired_gpus, 'unmet_cores': unmet_cores, 'unmet_memory': unmet_memory, 'unmet_gpus': unmet_gpus}


        @Jsonable("schedule_id", "autoscale_config_id", "days_of_the_week", "active_start_time", "active_end_time", "timezone")
        class Schedule(Base):
            __tablename__ = "schedules"
            schedule_id = Column("schedule_id", UUID(as_uuid=True), primary_key=True,
              server_default=(sqlalchemy.text("uuid_generate_v4()")))
            autoscale_config_id = Column("autoscale_config_id", UUID(as_uuid=True), ForeignKey("autoscale_configs.autoscale_config_id", onupdate="CASCADE", ondelete="CASCADE"), index=True)
            autoscale_config = relationship("AutoScaleConfig", back_populates="schedules")
            days_of_the_week = Column(JSON, server_default="[]", default=[], nullable=False)
            active_start_time = Column(Time, nullable=False)
            active_end_time = Column(Time, nullable=False)
            timezone = Column((String(44)), nullable=False)

            def is_active(self, timestamp: datetime.datetime=None) -> bool:
                if not timestamp:
                    timestamp = object_session(self).execute(select([func.current_timestamp().op("AT TIME ZONE")("UTC")])).first()[0]
                local_zone_info = ZoneInfo(self.timezone)
                timestamp = timestamp.astimezone(local_zone_info)
                timestamp = timestamp.replace(second=0, microsecond=0, tzinfo=None)
                self.logger.debug(f"Using {timestamp} as the current time to check if schedule {self.schedule_id} is active")
                day_of_the_week = timestamp.isoweekday()
                current_time = timestamp.timetz()
                start_time = self.active_start_time.replace(second=0, microsecond=0)
                end_time = self.active_end_time.replace(second=0, microsecond=0)
                if day_of_the_week in self.days_of_the_week:
                    self.logger.debug(f"Schedule {self.schedule_id} has {day_of_the_week} is it's active days.")
                    if start_time < end_time:
                        return start_time <= current_time <= end_time
                    return current_time >= start_time
                elif day_of_the_week - 1 in self.days_of_the_week:
                    self.logger.debug(f"Schedule {self.schedule_id} has {day_of_the_week - 1} is it's active days. Checking for active times cross midnight.")
                    if start_time > end_time:
                        return current_time <= end_time
                return False


        @Jsonable("azure_config_id", "vm_provider_name", "vm_provider_display_name", "config_name",
          "max_instances", "azure_subscription_id", "azure_resource_group", "azure_tenant_id", "azure_client_id",
          "azure_client_secret", "azure_region", "azure_vm_size", "azure_os_disk_type", "azure_image_reference",
          "azure_network_sg", "azure_subnet", "azure_os_disk_size_gb", "azure_tags", "azure_os_username",
          "azure_os_password", "azure_ssh_public_key", "startup_script", "azure_config_override", "azure_public_ip",
          "azure_authority", "azure_is_windows", "vm_provider_config_name", "vm_provider_config_id", sanitize=[
         "azure_client_secret", "azure_os_password"])
        class AzureVMConfig(Base):
            __tablename__ = "azure_configs"
            azure_config_id = Column("azure_config_id", UUID(as_uuid=True), primary_key=True,
              server_default=(sqlalchemy.text("uuid_generate_v4()")))
            config_name = Column(String, nullable=False)
            autoscale_configs = relationship("AutoScaleConfig", passive_deletes=True, foreign_keys="AutoScaleConfig.azure_config_id")
            max_instances = Column(Integer, nullable=False)
            azure_subscription_id = Column(String, nullable=False)
            azure_resource_group = Column(String, nullable=False)
            azure_tenant_id = Column(String, nullable=False)
            azure_client_id = Column(String, nullable=False)
            azure_client_secret = Column((StringEncryptedType(String, get_key, AesEngine, "pkcs5")), nullable=False)
            azure_region = Column(String, nullable=False)
            azure_vm_size = Column(String, nullable=False)
            azure_os_disk_type = Column(String, nullable=False)
            azure_image_reference = Column(JSON, server_default="{}", default={}, nullable=False)
            azure_network_sg = Column(String, nullable=False)
            azure_subnet = Column(String, nullable=False)
            azure_os_disk_size_gb = Column(Integer, nullable=False)
            azure_tags = Column(JSON, server_default="{}", default={}, nullable=False)
            azure_os_username = Column(String, nullable=False)
            azure_os_password = Column((StringEncryptedType(String, get_key, AesEngine, "pkcs5")), nullable=False)
            azure_ssh_public_key = Column(String, nullable=True)
            startup_script = Column(String, nullable=True)
            azure_config_override = Column(JSON, server_default="{}", default={}, nullable=False)
            azure_public_ip = Column(Boolean, server_default="false", default=False)
            azure_authority = Column(String, server_default=(AZURE_AUTHORITY.AZURE_PUBLIC_CLOUD.value), default=(AZURE_AUTHORITY.AZURE_PUBLIC_CLOUD.value),
              nullable=False)
            azure_is_windows = Column(Boolean, default=False)

            @property
            def vm_provider_display_name(self):
                return "Azure"

            @property
            def vm_provider_name(self):
                return "azure"

            @property
            def vm_provider_config_name(self):
                return self.config_name

            @property
            def vm_provider_config_id(self):
                return self.azure_config_id


        @Jsonable("azure_dns_config_id", "dns_provider_name", "dns_provider_display_name", "config_name",
          "azure_subscription_id", "azure_resource_group", "azure_tenant_id", "azure_client_id",
          "azure_client_secret", "azure_region", "dns_provider_config_name", "dns_provider_config_id", "azure_authority",
          sanitize=[
         "azure_client_secret"])
        class AzureDNSConfig(Base):
            __tablename__ = "azure_dns_configs"
            azure_dns_config_id = Column("azure_dns_config_id", UUID(as_uuid=True), primary_key=True,
              server_default=(sqlalchemy.text("uuid_generate_v4()")))
            config_name = Column(String, nullable=False)
            autoscale_configs = relationship("AutoScaleConfig", passive_deletes=True, foreign_keys="AutoScaleConfig.azure_dns_config_id")
            azure_subscription_id = Column(String, nullable=False)
            azure_resource_group = Column(String, nullable=False)
            azure_tenant_id = Column(String, nullable=False)
            azure_client_id = Column(String, nullable=False)
            azure_client_secret = Column((StringEncryptedType(String, get_key, AesEngine, "pkcs5")), nullable=False)
            azure_region = Column(String, nullable=False)
            azure_authority = Column(String, server_default=(AZURE_AUTHORITY.AZURE_PUBLIC_CLOUD.value), default=(AZURE_AUTHORITY.AZURE_PUBLIC_CLOUD.value),
              nullable=False)

            @property
            def dns_provider_display_name(self):
                return "Azure"

            @property
            def dns_provider_name(self):
                return "azure"

            @property
            def dns_provider_config_name(self):
                return self.config_name

            @property
            def dns_provider_config_id(self):
                return self.azure_dns_config_id


        @Jsonable("aws_config_id", "config_name", "aws_ec2_instance_type", "aws_region", "aws_access_key_id", "aws_secret_access_key", "aws_ec2_ami_id", "aws_ec2_instance_type",
          "max_instances", "aws_ec2_security_group_ids", "aws_ec2_subnet_id", "startup_script", "aws_ec2_iam", "aws_ec2_ebs_volume_type",
          "aws_ec2_ebs_volume_size_gb", "aws_ec2_custom_tags", "retrieve_password", "vm_provider_display_name",
          "vm_provider_name", "vm_provider_config_name", "vm_provider_config_id", "aws_ec2_config_override", sanitize=[
         "aws_secret_access_key"])
        class AwsVMConfig(Base):
            __tablename__ = "aws_configs"
            aws_config_id = Column("aws_config_id", UUID(as_uuid=True), primary_key=True,
              server_default=(sqlalchemy.text("uuid_generate_v4()")))
            config_name = Column(String, nullable=False)
            aws_ec2_instance_type = Column(String, nullable=False)
            aws_region = Column(String)
            aws_access_key_id = Column(String)
            aws_secret_access_key = Column(StringEncryptedType(String, get_key, AesEngine, "pkcs5"))
            aws_ec2_ami_id = Column(String)
            max_instances = Column(Integer)
            aws_ec2_security_group_ids = Column(JSON, server_default="[]", default=[], nullable=False)
            aws_ec2_subnet_id = Column(String)
            startup_script = Column(String)
            aws_ec2_iam = Column(String)
            aws_ec2_ebs_volume_type = Column(String)
            aws_ec2_ebs_volume_size_gb = Column(Integer)
            aws_ec2_private_key = Column((EncryptedType(String, get_key, AesEngine, "pkcs5")), nullable=False)
            aws_ec2_public_key = Column(String, nullable=False)
            aws_ec2_custom_tags = Column(JSON, server_default="{}", default={}, nullable=False)
            retrieve_password = Column(Boolean, server_default="false", default=False)
            autoscale_configs = relationship("AutoScaleConfig", passive_deletes=True, foreign_keys="AutoScaleConfig.aws_config_id")
            aws_ec2_config_override = Column(JSON, server_default="{}", default={}, nullable=False)

            @property
            def vm_provider_display_name(self):
                return "Amazon Web Services"

            @property
            def vm_provider_name(self):
                return "aws"

            @property
            def vm_provider_config_name(self):
                return self.config_name

            @property
            def vm_provider_config_id(self):
                return self.aws_config_id


        @Jsonable("config_id", "config_name", "aws_access_key_id", "aws_secret_access_key", "dns_provider_display_name",
          "dns_provider_name", "dns_provider_config_name", "dns_provider_config_id", sanitize=[
         "aws_secret_access_key"])
        class AwsDNSConfig(Base):
            __tablename__ = "aws_dns_configs"
            config_id = Column("config_id", UUID(as_uuid=True), primary_key=True,
              server_default=(sqlalchemy.text("uuid_generate_v4()")))
            config_name = Column(String, nullable=False)
            aws_access_key_id = Column(String)
            aws_secret_access_key = Column(StringEncryptedType(String, get_key, AesEngine, "pkcs5"))
            autoscale_configs = relationship("AutoScaleConfig", passive_deletes=True, foreign_keys="AutoScaleConfig.aws_dns_config_id")

            @property
            def dns_provider_display_name(self):
                return "Amazon Web Services"

            @property
            def dns_provider_name(self):
                return "aws"

            @property
            def dns_provider_config_name(self):
                return self.config_name

            @property
            def dns_provider_config_id(self):
                return self.config_id


        @Jsonable("config_id", "config_name", "max_instances", "digital_ocean_token", "region", "digital_ocean_droplet_image", "digital_ocean_droplet_size",
          "digital_ocean_tags", "digital_ocean_sshkey_name", "digital_ocean_firewall_name", "startup_script", "vm_provider_display_name",
          "vm_provider_name", "vm_provider_config_name", "vm_provider_config_id", sanitize=[
         "digital_ocean_token"])
        class DigitalOceanVMConfig(Base):
            __tablename__ = "digital_ocean_vm_configs"
            config_id = Column("config_id", UUID(as_uuid=True), primary_key=True,
              server_default=(sqlalchemy.text("uuid_generate_v4()")))
            config_name = Column(String, nullable=False)
            max_instances = Column(Integer)
            digital_ocean_token = Column(StringEncryptedType(String, get_key, AesEngine, "pkcs5"))
            region = Column(String)
            digital_ocean_droplet_image = Column(String)
            digital_ocean_droplet_size = Column(String)
            digital_ocean_tags = Column(String)
            digital_ocean_sshkey_name = Column(String)
            digital_ocean_firewall_name = Column(String)
            startup_script = Column(String)
            autoscale_configs = relationship("AutoScaleConfig", passive_deletes=True, foreign_keys="AutoScaleConfig.digital_ocean_vm_config_id")

            @property
            def vm_provider_display_name(self):
                return "Digital Ocean"

            @property
            def vm_provider_name(self):
                return "digital_ocean"

            @property
            def vm_provider_config_name(self):
                return self.config_name

            @property
            def vm_provider_config_id(self):
                return self.config_id


        @Jsonable("config_id", "config_name", "digital_ocean_token", "dns_provider_display_name",
          "dns_provider_name", "dns_provider_config_name", "dns_provider_config_id", sanitize=[
         "digital_ocean_token"])
        class DigitalOceanDNSConfig(Base):
            __tablename__ = "digital_ocean_dns_configs"
            config_id = Column("config_id", UUID(as_uuid=True), primary_key=True,
              server_default=(sqlalchemy.text("uuid_generate_v4()")))
            config_name = Column(String, nullable=False)
            digital_ocean_token = Column(StringEncryptedType(String, get_key, AesEngine, "pkcs5"))
            autoscale_configs = relationship("AutoScaleConfig", passive_deletes=True, foreign_keys="AutoScaleConfig.digital_ocean_dns_config_id")

            @property
            def dns_provider_display_name(self):
                return "Digital Ocean"

            @property
            def dns_provider_name(self):
                return "digital_ocean"

            @property
            def dns_provider_config_name(self):
                return self.config_name

            @property
            def dns_provider_config_id(self):
                return self.config_id


        @Jsonable("config_id", "config_name", "max_instances", "oci_fingerprint", "oci_tenancy_ocid", "oci_region", "oci_compartment_ocid", "oci_availability_domains",
          "oci_shape", "oci_image_ocid", "oci_subnet_ocid", "oci_ssh_public_key", "startup_script", "oci_user_ocid", "oci_private_key",
          "oci_flex_cpus", "oci_flex_memory_gb", "oci_boot_volume_gb", "oci_custom_tags", "vm_provider_display_name",
          "vm_provider_name", "vm_provider_config_name", "vm_provider_config_id", "oci_baseline_ocpu_utilization",
          "oci_config_override", "oci_storage_vpus_per_gb", "oci_nsg_ocids", sanitize=[
         "oci_private_key"])
        class OracleVMConfig(Base):
            __tablename__ = "oci_vm_configs"
            config_id = Column("config_id", UUID(as_uuid=True), primary_key=True,
              server_default=(sqlalchemy.text("uuid_generate_v4()")))
            config_name = Column(String, nullable=False)
            max_instances = Column(Integer)
            oci_fingerprint = Column(String)
            oci_tenancy_ocid = Column(String)
            oci_region = Column(String)
            oci_compartment_ocid = Column(String)
            oci_shape = Column(String)
            oci_image_ocid = Column(String)
            oci_subnet_ocid = Column(String)
            oci_ssh_public_key = Column(String)
            startup_script = Column(String)
            oci_user_ocid = Column(String)
            oci_private_key = Column(StringEncryptedType(String, get_key, AesEngine, "pkcs5"))
            oci_flex_cpus = Column(Integer)
            oci_flex_memory_gb = Column(Integer)
            oci_boot_volume_gb = Column(Integer)
            oci_custom_tags = Column(JSON, server_default="{}", default={}, nullable=False)
            oci_config_override = Column(JSON, server_default="{}", default={}, nullable=False)
            oci_baseline_ocpu_utilization = Column(String)
            oci_storage_vpus_per_gb = Column(Integer)
            oci_nsg_ocids = Column(JSON, server_default="[]", default=[], nullable=False)
            oci_availability_domains = Column(JSON, server_default="[]", default=[], nullable=False)
            autoscale_configs = relationship("AutoScaleConfig", passive_deletes=True, foreign_keys="AutoScaleConfig.oci_vm_config_id")

            @property
            def vm_provider_display_name(self):
                return "Oracle Cloud Infrastructure"

            @property
            def vm_provider_name(self):
                return "oci"

            @property
            def vm_provider_config_name(self):
                return self.config_name

            @property
            def vm_provider_config_id(self):
                return self.config_id


        @Jsonable("config_id", "config_name", "oci_user_ocid", "oci_private_key", "oci_fingerprint", "oci_tenancy_ocid", "oci_region", "oci_compartment_ocid", "dns_provider_display_name",
          "dns_provider_name", "dns_provider_config_name", "dns_provider_config_id", sanitize=[
         "oci_private_key"])
        class OracleDNSConfig(Base):
            __tablename__ = "oci_dns_configs"
            config_id = Column("config_id", UUID(as_uuid=True), primary_key=True,
              server_default=(sqlalchemy.text("uuid_generate_v4()")))
            config_name = Column(String, nullable=False)
            oci_user_ocid = Column(String)
            oci_private_key = Column(StringEncryptedType(String, get_key, AesEngine, "pkcs5"))
            oci_fingerprint = Column(String)
            oci_tenancy_ocid = Column(String)
            oci_region = Column(String)
            oci_compartment_ocid = Column(String)
            autoscale_configs = relationship("AutoScaleConfig", passive_deletes=True, foreign_keys="AutoScaleConfig.oci_dns_config_id")

            @property
            def dns_provider_display_name(self):
                return "Oracle Cloud Infrastructure"

            @property
            def dns_provider_name(self):
                return "oci"

            @property
            def dns_provider_config_name(self):
                return self.config_name

            @property
            def dns_provider_config_id(self):
                return self.config_id


        @Jsonable("config_id", "config_name", "max_instances", "gcp_project", "gcp_region", "gcp_zone", "gcp_machine_type", "gcp_image", "startup_script", "gcp_boot_volume_gb",
          "gcp_cmek", "gcp_disk_type", "gcp_network", "gcp_subnetwork", "gcp_public_ip", "gcp_network_tags", "gcp_custom_labels",
          "gcp_credentials", "gcp_metadata", "gcp_service_account", "gcp_guest_accelerators", "gcp_config_override", "vm_provider_display_name",
          "vm_provider_name", "vm_provider_config_name", "vm_provider_config_id", sanitize=[
         "gcp_credentials"])
        class GcpVMConfig(Base):
            __tablename__ = "gcp_vm_configs"
            config_id = Column("config_id", UUID(as_uuid=True), primary_key=True,
              server_default=(sqlalchemy.text("uuid_generate_v4()")))
            config_name = Column(String, nullable=False)
            max_instances = Column(Integer)
            gcp_project = Column(String)
            gcp_region = Column(String)
            gcp_zone = Column(String)
            gcp_machine_type = Column(String)
            gcp_image = Column(String)
            startup_script = Column(String)
            gcp_boot_volume_gb = Column(Integer)
            gcp_cmek = Column(String)
            gcp_disk_type = Column(String)
            gcp_network = Column(String)
            gcp_subnetwork = Column(String)
            gcp_public_ip = Column(Boolean, default=False)
            gcp_network_tags = Column(JSON, server_default="[]", default=[], nullable=False)
            gcp_custom_labels = Column(JSON, server_default="{}", default={}, nullable=False)
            gcp_credentials = Column((StringEncryptedType(EncryptedJSONType, get_key, AesEngine, "pkcs5")), default={}, nullable=False)
            gcp_metadata = Column(JSON, server_default="[]", default=[], nullable=False)
            gcp_service_account = Column(JSON, server_default="{}", default={}, nullable=False)
            gcp_guest_accelerators = Column(JSON, server_default="[]", default=[], nullable=False)
            gcp_config_override = Column(JSON, server_default="{}", default={}, nullable=False)
            autoscale_configs = relationship("AutoScaleConfig", passive_deletes=True, foreign_keys="AutoScaleConfig.gcp_vm_config_id")

            @property
            def vm_provider_display_name(self):
                return "Google Cloud Platform"

            @property
            def vm_provider_name(self):
                return "gcp"

            @property
            def vm_provider_config_name(self):
                return self.config_name

            @property
            def vm_provider_config_id(self):
                return self.config_id


        @Jsonable("config_id", "config_name", "gcp_credentials", "gcp_project", "dns_provider_display_name",
          "dns_provider_name", "dns_provider_config_name", "dns_provider_config_id", sanitize=[
         "gcp_credentials"])
        class GcpDNSConfig(Base):
            __tablename__ = "gcp_dns_configs"
            config_id = Column("config_id", UUID(as_uuid=True), primary_key=True,
              server_default=(sqlalchemy.text("uuid_generate_v4()")))
            config_name = Column(String, nullable=False)
            gcp_credentials = Column((StringEncryptedType(EncryptedJSONType, get_key, AesEngine, "pkcs5")), default={}, nullable=False)
            gcp_project = Column(String)
            autoscale_configs = relationship("AutoScaleConfig", passive_deletes=True, foreign_keys="AutoScaleConfig.gcp_dns_config_id")

            @property
            def dns_provider_display_name(self):
                return "Google Cloud Platform"

            @property
            def dns_provider_name(self):
                return "gcp"

            @property
            def dns_provider_config_name(self):
                return self.config_name

            @property
            def dns_provider_config_id(self):
                return self.config_id


        @Jsonable("config_id", "vm_provider_name", "vm_provider_display_name", "vm_provider_config_name", "vm_provider_config_id", "config_name",
          "max_instances", "vsphere_vcenter_address", "vsphere_vcenter_port", "vsphere_vcenter_username", "vsphere_vcenter_password",
          "vsphere_template_name", "vsphere_datacenter_name", "vsphere_vm_folder", "vsphere_datastore", "vsphere_cluster_name",
          "vsphere_resource_pool", "vsphere_datastore_cluster_name", "startup_script", "vsphere_os_username", "vsphere_os_password",
          "vsphere_cpus", "vsphere_memoryMB", "vsphere_installed_OS_type", sanitize=[
         "vsphere_vcenter_password", "vsphere_os_password"])
        class VsphereVMConfig(Base):
            __tablename__ = "vsphere_vm_configs"
            config_id = Column("config_id", UUID(as_uuid=True), primary_key=True,
              server_default=(sqlalchemy.text("uuid_generate_v4()")))
            config_name = Column(String, nullable=False)
            autoscale_configs = relationship("AutoScaleConfig", passive_deletes=True, foreign_keys="AutoScaleConfig.vsphere_vm_config_id")
            max_instances = Column(Integer, nullable=False)
            vsphere_vcenter_address = Column(String, nullable=False)
            vsphere_vcenter_port = Column(Integer, nullable=False)
            vsphere_vcenter_username = Column(String, nullable=False)
            vsphere_vcenter_password = Column(String, nullable=False)
            vsphere_template_name = Column(String, nullable=False)
            vsphere_datacenter_name = Column(String, nullable=False)
            vsphere_vm_folder = Column(String, nullable=True)
            vsphere_datastore = Column(String, nullable=True)
            vsphere_cluster_name = Column(String, nullable=True)
            vsphere_resource_pool = Column(String, nullable=True)
            vsphere_datastore_cluster_name = Column(String, nullable=True)
            startup_script = Column(String, nullable=True)
            vsphere_os_username = Column(String, nullable=False)
            vsphere_os_password = Column((StringEncryptedType(String, get_key, AesEngine, "pkcs5")), nullable=False)
            vsphere_cpus = Column(Integer, nullable=True)
            vsphere_memoryMB = Column(Integer, nullable=True)
            vsphere_installed_OS_type = Column(String, nullable=False)

            @property
            def vm_provider_display_name(self):
                return "VMWare VSphere"

            @property
            def vm_provider_name(self):
                return "vsphere"

            @property
            def vm_provider_config_name(self):
                return self.config_name

            @property
            def vm_provider_config_id(self):
                return self.config_id


        @Jsonable("config_id", "vm_provider_name", "vm_provider_display_name", "vm_provider_config_name", "vm_provider_config_id", "config_name",
          "max_instances", "openstack_keystone_endpoint", "openstack_nova_endpoint", "openstack_nova_version", "openstack_glance_endpoint",
          "openstack_glance_version", "openstack_cinder_endpoint", "openstack_cinder_version", "openstack_project_name",
          "openstack_project_domain_name", "openstack_user_domain_name", "openstack_auth_method", "openstack_username",
          "openstack_password", "openstack_application_credential_id", "openstack_application_credential_secret", "openstack_metadata",
          "openstack_image_id", "openstack_flavor", "openstack_create_volume", "openstack_volume_size_gb", "openstack_volume_type",
          "openstack_security_groups", "openstack_network_id", "openstack_key_name", "openstack_availability_zone", "startup_script",
          "openstack_config_override", sanitize=["openstack_password", "openstack_application_credential_secret"])
        class OpenStackVMConfig(Base):
            __tablename__ = "openstack_vm_configs"
            config_id = Column("config_id", UUID(as_uuid=True), primary_key=True,
              server_default=(sqlalchemy.text("uuid_generate_v4()")))
            config_name = Column(String, nullable=False)
            autoscale_configs = relationship("AutoScaleConfig", passive_deletes=True, foreign_keys="AutoScaleConfig.openstack_vm_config_id")
            max_instances = Column(Integer, nullable=False)
            openstack_keystone_endpoint = Column(String, nullable=False)
            openstack_nova_endpoint = Column(String, nullable=False)
            openstack_nova_version = Column(String, nullable=False)
            openstack_glance_endpoint = Column(String, nullable=False)
            openstack_glance_version = Column(String, nullable=False)
            openstack_cinder_endpoint = Column(String, nullable=False)
            openstack_cinder_version = Column(String, nullable=False)
            openstack_project_name = Column(String, nullable=False)
            openstack_project_domain_name = Column(String, nullable=True)
            openstack_user_domain_name = Column(String, nullable=True)
            openstack_auth_method = Column(String, nullable=False)
            openstack_username = Column(String, nullable=True)
            openstack_password = Column((StringEncryptedType(String, get_key, AesEngine, "pkcs5")), nullable=True)
            openstack_application_credential_id = Column(String, nullable=True)
            openstack_application_credential_secret = Column((StringEncryptedType(String, get_key, AesEngine, "pkcs5")), nullable=True)
            openstack_metadata = Column(JSON, server_default="{}", default={}, nullable=False)
            openstack_image_id = Column(String, nullable=False)
            openstack_flavor = Column(String, nullable=False)
            openstack_create_volume = Column(Boolean, default=False, nullable=False)
            openstack_volume_size_gb = Column(Integer, nullable=True)
            openstack_volume_type = Column(String, nullable=True)
            startup_script = Column(String, nullable=True)
            openstack_security_groups = Column(JSON, server_default="[]", default=[], nullable=False)
            openstack_network_id = Column(String, nullable=False)
            openstack_key_name = Column(String, nullable=True)
            openstack_availability_zone = Column(String, nullable=False)
            openstack_config_override = Column(JSON, server_default="{}", default={}, nullable=False)

            @property
            def vm_provider_display_name(self):
                return "OpenStack"

            @property
            def vm_provider_name(self):
                return "openstack"

            @property
            def vm_provider_config_name(self):
                return self.config_name

            @property
            def vm_provider_config_id(self):
                return self.config_id


        @Jsonable("token_id", "serial_number", "seed_filename", "created", "user_id", "username")
        class PhysicalToken(Base):
            __tablename__ = "physical_tokens"
            token_id = Column("token_id", UUID(as_uuid=True), primary_key=True, server_default=(sqlalchemy.text("uuid_generate_v4()")))
            serial_number = Column(String, nullable=False, unique=True)
            token_seed = Column((EncryptedType(String, get_key, AesEngine, "pkcs5")), nullable=False)
            seed_filename = Column(String, nullable=True)
            created = Column(TIMESTAMP, nullable=False)
            user_id = Column("user_id", UUID(as_uuid=True), ForeignKey("users.user_id", onupdate="CASCADE", ondelete="CASCADE"), index=True)
            user = relationship("User", back_populates="tokens")

            @property
            def username(self):
                if self.user:
                    return self.user.username
                return ""


        registry_public_key = "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAETOKk2I/V9CUk8zfZdHY3tRGReCD6\nIVjb+qW612w2UGbt+abRfh1aHW1EH4wuDM+zEmcE4ER7ycUxxL77FphXvg==\n-----END PUBLIC KEY-----"

        @Jsonable("registry_id", "config", "do_auto_update", "registry_url", "workspaces", "schema_version", "is_verified")
        class Registry(Base):
            __tablename__ = "registries"
            registry_id = Column("registry_id", UUID(as_uuid=True), primary_key=True, server_default=(sqlalchemy.text("uuid_generate_v4()")))
            config = Column(JSONB)
            do_auto_update = Column(Boolean, default=False)
            registry_url = Column((VARCHAR(255)), index=True, unique=True)
            schema_version = Column(VARCHAR(255))

            @property
            def workspaces(self):
                if self.config:
                    workspaces = self.config["workspaces"]
                    return workspaces
                return ""

            @property
            def is_verifiedParse error at or near `POP_EXCEPT' instruction at offset 158


        @Jsonable("webauthn_credential_id", "authenticator_credential_id", "public_key", "sign_count", "created", "user_id", "username")
        class WebauthnCredential(Base):
            __tablename__ = "webauthn_credentials"
            webauthn_credential_id = Column("webauthn_credential_id", UUID(as_uuid=True), primary_key=True, server_default=(sqlalchemy.text("uuid_generate_v4()")))
            authenticator_credential_id = Column((VARCHAR(255)), nullable=False, index=True)
            public_key = Column(VARCHAR(255))
            sign_count = Column(Integer, nullable=True)
            created = Column(TIMESTAMP, nullable=False)
            user = relationship("User", back_populates="webauthn_credentials")
            user_id = Column("user_id", UUID(as_uuid=True), ForeignKey("users.user_id", onupdate="CASCADE", ondelete="CASCADE"), index=True)

            @property
            def username(self):
                if self.user:
                    return self.user.username
                return ""


        @Jsonable("webauthn_request_id", "challenge", "created")
        class WebauthnRequest(Base):
            __tablename__ = "webauthn_requests"
            webauthn_request_id = Column("webauthn_request_id", UUID(as_uuid=True), primary_key=True, server_default=(sqlalchemy.text("uuid_generate_v4()")))
            challenge = Column((VARCHAR(255)), nullable=False)
            created = Column(TIMESTAMP, nullable=False)


        @Jsonable("group_permission_id", "group_id", "permission_name", "permission_description", "permission_id")
        class GroupPermission(Base):
            __tablename__ = "group_permissions"
            group_permission_id = Column("group_permission_id", UUID(as_uuid=True), primary_key=True,
              server_default=(sqlalchemy.text("uuid_generate_v4()")))
            permission_id = Column(Integer, nullable=False)
            group_id = Column("group_id", UUID(as_uuid=True), ForeignKey("groups.group_id", onupdate="CASCADE", ondelete="CASCADE"), index=True)
            group = relationship("Group", back_populates="permissions")
            api_id = Column("api_id", ForeignKey("api_configs.api_id", onupdate="CASCADE", ondelete="CASCADE"), index=True)
            api_config = relationship("Api", back_populates="permissions")

            @property
            def permission(self):
                if JWT_AUTHORIZATION.is_valid_value(self.permission_id):
                    return JWT_AUTHORIZATION(self.permission_id)
                return

            @property
            def permission_name(self):
                return self.permission.get_friendly_name()

            @property
            def permission_description(self):
                return self.permission.description


        class Model:

            def create_schema(self, engine):
                Base.metadata.create_all(engine)


        MODEL_CLASSES = {}
        current_module = sys.modules[__name__]
        for (name, obj) in inspect.getmembers(sys.modules[__name__]):
            if inspect.isclass(obj):
                if hasattr(obj, "__tablename__"):
                    MODEL_CLASSES[obj.__tablename__] = obj
                MODEL_CLASS_ORDER = [
                 "installation",
                 "companies",
                 "licenses",
                 "settings",
                 "filter_policies",
                 "groups",
                 "group_settings",
                 "saml_config",
                 "ldap_configs",
                 "saml_config",
                 "oidc_configs",
                 "sso_attribute_userfield_mapping",
                 "sso_to_group_mapping",
                 "users",
                 "user_groups",
                 "session_tokens",
                 "zones",
                 "managers",
                 "azure_configs",
                 "azure_dns_configs",
                 "aws_configs",
                 "aws_dns_configs",
                 "digital_ocean_vm_configs",
                 "digital_ocean_dns_configs",
                 "oci_vm_configs",
                 "oci_dns_configs",
                 "gcp_vm_configs",
                 "gcp_dns_configs",
                 "vsphere_vm_configs",
                 "openstack_vm_configs",
                 "server_pools",
                 "autoscale_configs",
                 "servers",
                 "images",
                 "user_attributes",
                 "image_attributes",
                 "group_images",
                 "connection_proxies",
                 "staging_configs",
                 "branding_configs",
                 "api_configs",
                 "cast_configs",
                 "kasms",
                 "kasm_attributes",
                 "session_permissions",
                 "accounting",
                 "session_recordings",
                 "api_configs",
                 "aws_configs",
                 "azure_configs",
                 "cart",
                 "companies",
                 "domains",
                 "logs",
                 "newsletters",
                 "physical_tokens",
                 "registries",
                 "file_mappings",
                 "storage_providers",
                 "storage_mappings",
                 "schedules",
                 "webauthn_credentials",
                 "webauthn_requests",
                 "group_permissions"]
                missing_orders = [x for x in MODEL_CLASSES.keys() if x not in MODEL_CLASS_ORDER]

        if missing_orders:
            raise AssertionError("Missing one or more definitions in MODEL_CLASS_ORDER: %s" % missing_orders)
        extra_class_order = [x for x in MODEL_CLASS_ORDER if x not in MODEL_CLASSES]
        if extra_class_order:
            raise AssertionError("Excess definition detected in MODEL_CLASS_ORDER: %s" % extra_class_order)
        IMPORT_EXPORT_IGNORE = ["logs","installation","licenses","cart","newsletters"]

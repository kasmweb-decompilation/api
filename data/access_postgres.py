# Decompiled with PyLingual (https://pylingual.io)
# Internal filename: data/access_postgres.py
# Bytecode version: 3.8.0rc1+ (3413)
# Source timestamp: 1970-01-01 00:00:00 UTC (0)

import os
import typing
import uuid
import select
import hashlib
import datetime
import threading
import logging
import logging.config
import random
import string
try:
    from zoneinfo import ZoneInfo
except ImportError:
    from backports.zoneinfo import ZoneInfo
from data.access_base import DataAccessBase
from data.lookup_tables import CLIENT_SETTINGS, VALID_CLIENT_SETTINGS_BY_TYPE
from sqlalchemy import create_engine, text, MetaData, func, case, nullslast
from data.report import Report
from data.keygen import generate_ssh_keys
from data.enums import CONNECTION_TYPE, SESSION_OPERATIONAL_STATUS, JWT_AUTHORIZATION
from data.exceptions import UniqueConstraintViolation
from data.data_utils import is_sanitized
from data.model import MODEL_CLASSES, MODEL_CLASS_ORDER, IMPORT_EXPORT_IGNORE, User, Image, Kasm, Server, ImageAttribute, UserAttributes, Model, ConfigSetting, Newsletter, GroupSetting, Group, UserGroup, GroupImage, LDAPConfig, SAMLConfig, Installation, License, Manager, Zone, KasmAttribute, Log, Api, Accounting, Company, Domain, FilterPolicy, Cart, BrandingConfig, SessionToken, StagingConfig, CastConfig, SessionPermission, OIDCConfig, SSOToGroupMapping, ConnectionProxy, ServerPool, AzureVMConfig, AzureDNSConfig, AutoScaleConfig, AwsVMConfig, AwsDNSConfig, DigitalOceanVMConfig, DigitalOceanDNSConfig, OracleVMConfig, OracleDNSConfig, GcpVMConfig, GcpDNSConfig, VsphereVMConfig, PhysicalToken, SSOAttributeToUserFieldMapping, FileMap, Registry, StorageMapping, StorageProvider, Schedule, WebauthnCredential, WebauthnRequest, SessionRecording, GroupPermission, OpenStackVMConfig
from sqlalchemy.orm import sessionmaker, scoped_session
from sqlalchemy.exc import SQLAlchemyError, IntegrityError
from sqlalchemy.sql.expression import true, or_
from decimal import Decimal
from cachetools.func import ttl_cache
logging.basicConfig()
logging.getLogger('sqlalchemy').setLevel(logging.WARNING)

class DataAccessPostgres(DataAccessBase):
    DEFAULT_USER_GROUP_ID = '68d557ac-4cac-42cc-a9f3-1c7c853de0f3'
    db_engine = None
    db_session_factory = None

    def __init__(self, config=None):
        if DataAccessPostgres.db_engine is None:
            DataAccessPostgres.engine = create_engine(self.get_url(config), pool_pre_ping=True, pool_size=config['database']['pool_size'], max_overflow=config['database']['max_overflow'])
            DataAccessPostgres.session_factory = sessionmaker(bind=DataAccessPostgres.engine)
            DataAccessPostgres.thread_safe_session = scoped_session(DataAccessPostgres.session_factory)
        try:
            installation_id = str(self.getInstallation().installation_id)
            os.environ['INSTALLATION_ID'] = installation_id
        except SQLAlchemyError:
            pass
        self.config_lock = threading.Lock()
        if self.engine.dialect.has_table(self.engine, 'settings'):
            self._reloadConfigs()
            t = threading.Thread(target=self._notifyListener)
            t.setDaemon(True)
            t.start()
        else:  # inserted
            self._config = {}

    def export_schema(self, tables):
        out = {'alembic_version': self.getAlembicVersion()}
        session = self.session()
        if not tables:
            tables = [table for table in MODEL_CLASSES.keys()]
        try:
            for table in [table for table in tables if table not in IMPORT_EXPORT_IGNORE]:
                obj = MODEL_CLASSES[table]
                _o = {}
                for col in obj.__table__.columns:
                    try:
                        _type = str(col.type)
                    except Exception as e:
                        _type = str(col.type.__class__.__name__)
                    _required = None
                    if col.nullable:
                        _required = False
                    else:  # inserted
                        if col.default or col.server_default:
                            _required = False
                        else:  # inserted
                            _required = True
                    _d = {'type': _type, 'required': _required}
                    if col.foreign_keys:
                        _d['foreign_key'] = ','.join([y.target_fullname for y in col.foreign_keys])
                    _o[str(col.name)] = _d
                out[str(table)] = _o
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex
        return out

    def import_data_sanity_test(self, import_data):
        errors = []
        for table, obj in MODEL_CLASSES.items():
            if table in IMPORT_EXPORT_IGNORE:
                continue
            if table not in import_data:
                errors.append('Import data missing table %s' % table)
            else:  # inserted
                if len(import_data[table]) == 0:
                    errors.append('Import data missing records for table %s' % table)
                else:  # inserted
                    required_or_fk = []
                    for col in obj.__table__.columns:
                        _required = None
                        if col.nullable:
                            _required = False
                        else:  # inserted
                            if col.default or col.server_default:
                                _required = False
                            else:  # inserted
                                _required = True
                        if _required or col.foreign_keys:
                            required_or_fk.append(col.name)
                    required_or_fk_checked = required_or_fk.copy()
                    for record in import_data[table]:
                        for r in required_or_fk:
                            if record.get(r) is not None and r in required_or_fk_checked:
                                required_or_fk_checked.remove(r)
                    if required_or_fk_checked:
                        errors.append('Import data for table (%s) didnt include required or fk field %s' % (table, required_or_fk_checked))
        return errors

    def import_data(self, import_data, replace=True):
        out = {}
        session = self.session()
        try:
            if replace:
                for table in reversed(MODEL_CLASS_ORDER):
                    if table in IMPORT_EXPORT_IGNORE:
                        continue
                    _obj = MODEL_CLASSES[table]
                    existing_records = session.query(_obj).all()
                    for r in existing_records:
                        session.delete(r)
                        session.flush()
            tables_todo = import_data.keys()
            for table in [table for table in MODEL_CLASS_ORDER if table not in IMPORT_EXPORT_IGNORE]:
                if table in tables_todo:
                    data = import_data.pop(table)
                    for record in data:
                        if table == 'zones' and 'primary_manager_id' in record:
                            record['primary_manager_id'] = None
                        obj = MODEL_CLASSES[table]
                        instance = obj(**record)
                        session.add(instance)
                        session.flush()
            session.commit()
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex
        return out

    def export_data(self, tables):
        out = {'alembic_version': self.getAlembicVersion()}
        session = self.session()
        if not tables:
            tables = [table for table in MODEL_CLASSES.keys()]
        try:
            for table in [table for table in tables if table not in IMPORT_EXPORT_IGNORE]:
                obj = MODEL_CLASSES[table]
                columns = [col.name for col in obj.__table__.columns]
                records = session.query(obj).all()
                _records = []
                for record in records:
                    _r = {k: v for k, v in record.__dict__.items() if k in columns}
                    _records.append(self.serializable(_r))
                out[table] = _records
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex
        return out

    @staticmethod
    def get_url(config):
        dbname = config['database']['name']
        dbpassword = config['database']['password']
        dbuser = config['database']['username']
        dbhost = config['database']['host']
        dbport = int(config['database']['port'])
        if 'ssl' in config['database'] and config['database']['ssl']:
            return 'postgresql://{0}:{1}@{2}:{3}/{4}?sslmode=require'.format(dbuser, dbpassword, dbhost, dbport, dbname)
        return 'postgresql://{0}:{1}@{2}:{3}/{4}'.format(dbuser, dbpassword, dbhost, dbport, dbname)

    def session(self):
        return DataAccessPostgres.thread_safe_session()

    def _notifyListener(self):
        conn = self.engine.connect()
        conn.execute(text('LISTEN settings_updated;').execution_options(autocommit=True))
        while threading.main_thread().is_alive():
            if select.select([conn.connection], [], [], 5) == ([], [], []):
                continue
            logging.info('Settings update notification received')
            conn.connection.poll()
            while conn.connection.notifies:
                notify = conn.connection.notifies.pop()
                if notify.channel == 'settings_update':
                    self._reloadConfigs()
                    break

    def _reloadConfigs(self):
        self.config_lock.acquire()
        self._config = {}
        session = self.session()
        try:
            settings = session.query(ConfigSetting).all()
        except SQLAlchemyError as ex:
            print(ex)
            session.rollback()
        for setting in settings:
            if setting.category not in self._config:
                self._config[setting.category] = {}
            session.expunge(setting)
            self._config[setting.category][setting.name] = setting
        self.config_lock.release()

    @property
    def config(self):
        return self._config

    def get_config_settings(self, sanitize=False):
        session = self.session()
        try:
            settings = session.query(ConfigSetting).all()
            if sanitize:
                for x in settings:
                    x.value = x.sanitized_value
            return settings
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex

    def update_config_setting(self, settings_id, value):
        self.config_lock.acquire()
        session = self.session()
        try:
            setting = session.query(ConfigSetting).filter(ConfigSetting.setting_id == settings_id).one()
            setting.value = value
            session.commit()
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex
        finally:  # inserted
            self.config_lock.release()

    def get_config_setting_by_id(self, settings_id):
        session = self.session()
        try:
            return session.query(ConfigSetting).filter(ConfigSetting.setting_id == settings_id).one()
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex

    def get_config_setting(self, category, name):
        session = self.session()
        try:
            return session.query(ConfigSetting).filter(ConfigSetting.name == name).filter(ConfigSetting.category == category).one_or_none()
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex

    @ttl_cache(maxsize=500, ttl=10)
    def get_config_setting_bool(self, category, name, default):
        value = self.get_config_setting(category, name)
        return value.getValueBool() if value else default

    @ttl_cache(maxsize=500, ttl=10)
    def get_config_setting_value(self, category, name):
        session = self.session()
        try:
            config_setting = session.query(ConfigSetting).filter(ConfigSetting.name == name).filter(ConfigSetting.category == category).one_or_none()
            return config_setting.value if config_setting else None
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex

    @ttl_cache(maxsize=100, ttl=300)
    def get_config_setting_value_cached(self, category, name):
        session = self.session()
        try:
            config_setting = session.query(ConfigSetting).filter(ConfigSetting.name == name).filter(ConfigSetting.category == category).one_or_none()
            return config_setting.value if config_setting else None
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex

    def get_kasms(self, user=None, operational_status=None):
        k = None
        session = self.session()
        try:
            query = session.query(Kasm)
            if user:
                query = query.filter(Kasm.user_id == user.user_id)
            if operational_status:
                query = query.filter(Kasm.operational_status == operational_status)
            k = query.all()
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex
        return k

    def remove_session_token(self, session_token_id):
        session_token = self.getSessionToken(session_token_id)
        if session_token:
            self.delete_session_token(session_token)

    def delete_session_token(self, session_token):
        self._delete(session_token)

    def remove_expired_session_tokens(self, user):
        max_session_life = int(self.config['auth']['session_lifetime'].value)
        for session_token in user.session_tokens:
            if session_token.is_expired:
                self.delete_session_token(session_token)
            else:  # inserted
                if Decimal(datetime.datetime.utcnow().timestamp()) - Decimal(session_token.session_date.timestamp()) > max_session_life:
                    self.delete_session_token(session_token)

    def remove_all_session_tokens(self, user):
        for session_token in user.session_tokens:
            self.delete_session_token(session_token)

    def getSessionToken(self, session_token_id):
        session = self.session()
        try:
            return session.query(SessionToken).filter(SessionToken.session_token_id == session_token_id).first()
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex

    def createSessionToken(self, user):
        session = self.session()
        try:
            session_token = SessionToken(user_id=user.user_id, session_date=datetime.datetime.utcnow())
            session.add(session_token)
            session.commit()
            return session_token
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex

    def updateSessionToken(self, session_token_id):
        session_token = self.getSessionToken(session_token_id)
        if session_token is not None:
            session_token.session_date = datetime.datetime.utcnow()
            self.updateToken(session_token)
            return session_token

    def replaceSessionToken(self, session_token_id, user, session_token_grace_period=30):
        session_token = self.getSessionToken(session_token_id)
        session_token.session_expiration_date = datetime.datetime.utcnow() + datetime.timedelta(seconds=session_token_grace_period)
        self.updateToken(session_token)
        self.remove_expired_session_tokens(user)
        session_token = self.createSessionToken(user)
        return session_token

    def updateToken(self, session_token):
        self._save()

    def validateSessionToken(self, token, username=None):
        max_session_life = int(self.get_config_setting_value_cached('auth', 'session_lifetime'))
        session = self.session()
        try:
            if username is None:
                session_token = session.query(SessionToken).filter(SessionToken.session_token_id == token).first()
            else:  # inserted
                session_token = session.query(SessionToken).join(User, User.user_id == SessionToken.user_id).filter(SessionToken.session_token_id == token).filter(User.username == username).first()
            if session_token is not None:
                if session_token.is_expired:
                    return False
                return Decimal(datetime.datetime.utcnow().timestamp()) - Decimal(session_token.session_date.timestamp()) < max_session_life
            return False
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex

    def setConfigSetting(self, category, name, title, value, value_type, services_restart=None, description=None, sanitize=False):
        self.config_lock.acquire()
        session = self.session()
        try:
            conf = session.query(ConfigSetting).filter(ConfigSetting.name == name).filter(ConfigSetting.category == category).first()
            if conf is None:
                conf = ConfigSetting(name=name, value=value, title=title, value_type=value_type, services_restart=services_restart, category=category, description=description, sanitize=sanitize)
                session.add(conf)
            else:  # inserted
                conf.value = value
                conf.services_restart = services_restart
            session.commit()
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex
        finally:  # inserted
            self.config_lock.release()
        return conf

    def getImage(self, image_id):
        session = self.session()
        try:
            return session.query(Image).filter(Image.image_id == image_id).first()
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex

    def clone_image(self, image):
        _image = image.__dict__.copy()
        _image.pop('image_id')
        _image.pop('_sa_instance_state')
        _image.pop('logger')
        new_image = Image(**_image)
        return new_image

    def image_on_agent(self, image_name):
        session = self.session()
        try:
            for server in session.query(Server).filter(Server.server_type == 'host').all():
                if isinstance(server.docker_images, dict):
                    for k, v in server.docker_images.items():
                        for tag in v.get('tags', []):
                            if tag == image_name:
                                return True
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex
        return False

    def create_update_image(self, image_id=None, image_name=None, cores=None, description=None, docker_registry=None, docker_token=None, docker_user=None, enabled=None, friendly_name=None, hash=None, memory=None, name=None, x_res=None, y_res=None, run_config=None, restrict_to_network=None, restrict_network_names=None, restrict_to_server=None, server_id=None, persistent_profile_path=None, volume_mappings=None, image_src=None, exec_config=None, restrict_to_zone=None, zone_id=None, filter_policy_id=None, filter_policy_force_disabled=None, session_time_limit=None, categories=None, allow_network_selection=None, require_gpu=None, gpu_count=None, hidden=None, notes=None, image_type=None, server_pool_id=None, link_url=None, cpu_allocation_method=None, uncompressed_size_mb=None, launch_config=None):
        if image_id:
            image = self.getImage(image_id)
        else:  # inserted
            image = Image()
        image.docker_registry = docker_registry
        image.docker_user = docker_user
        if image_name:
            image.image_name = image_name[:255]
        if cores:
            image.cores = float(cores)
        if description:
            image.description = description
        if not docker_token or not is_sanitized(docker_token):
            image.docker_token = docker_token[:8192]
        else:  # inserted
            image.docker_token = docker_token
        if enabled:
            image.enabled = True
        else:  # inserted
            if enabled == False:
                image.enabled = False
        if friendly_name:
            image.friendly_name = friendly_name[:255]
        if image_src:
            image.image_src = image_src[:255]
        if hash:
            image.hash = hash[:255]
        else:  # inserted
            image.hash = hash
        if memory:
            image.memory = int(memory)
        if name:
            _name = name[:255]
            if _name!= image.name:
                image.available = self.image_on_agent(_name)
                image.name = _name
        if x_res:
            image.x_res = int(x_res)
        if y_res:
            image.y_res = int(y_res)
        if run_config or run_config == {}:
            image.run_config = run_config
        if exec_config or exec_config == {}:
            image.exec_config = exec_config
        if launch_config or launch_config == {}:
            image.launch_config = launch_config
        if volume_mappings or volume_mappings == {}:
            image.volume_mappings = volume_mappings
        if categories or categories == []:
            image.categories = categories
        if restrict_to_network:
            image.restrict_to_network = True
        else:  # inserted
            if restrict_to_network == False:
                image.restrict_to_network = False
        if restrict_to_server:
            image.restrict_to_server = True
        else:  # inserted
            if restrict_to_server == False:
                image.restrict_to_server = False
        if server_id:
            image.server_id = server_id
        else:  # inserted
            image.server_id = None
        if server_pool_id:
            image.server_pool_id = server_pool_id
        if restrict_to_zone:
            image.restrict_to_zone = True
        else:  # inserted
            if restrict_to_zone == False:
                image.restrict_to_zone = False
        if zone_id:
            image.zone_id = zone_id
        if not filter_policy_id!= None or filter_policy_id == '':
            image.filter_policy_id = None
        else:  # inserted
            image.filter_policy_id = filter_policy_id
        if filter_policy_force_disabled!= None:
            image.filter_policy_force_disabled = filter_policy_force_disabled
        if restrict_network_names or restrict_network_names == []:
            image.restrict_network_names = restrict_network_names
        if allow_network_selection!= None:
            image.allow_network_selection = allow_network_selection
        if session_time_limit!= None:
            if session_time_limit == '':
                image.session_time_limit = None
            else:  # inserted
                image.session_time_limit = session_time_limit
        if gpu_count!= None:
            image.gpu_count = gpu_count
        else:  # inserted
            image.gpu_count = 0
        if hidden:
            image.hidden = True
        else:  # inserted
            image.hidden = False
        if notes:
            image.notes = notes
        if image_type:
            image.image_type = image_type
        if link_url:
            image.link_url = link_url
        if cpu_allocation_method:
            image.cpu_allocation_method = cpu_allocation_method
        if uncompressed_size_mb is not None:
            image.uncompressed_size_mb = uncompressed_size_mb
        image.persistent_profile_path = persistent_profile_path
        image.persistent_profile_path = f'{image.persistent_profile_path}/' if image.persistent_profile_path and image.persistent_profile_path.startswith('s3://') and (not image.persistent_profile_path.endswith('/')) else f'{image.persistent_profile_path}/'
        if not image_id:
            image = self.createImage(image)
        else:  # inserted
            session = self.session()
        else:  # inserted
            pass
            except SQLAlchemyError as ex: session.rollback() as ex:
                pass  # postinserted
            else:  # inserted
                ex = None
            else:  # inserted
                pass
        return image

    def delete_image(self, image):
        self._delete(image)

    def createImage(self, image, install=False):
        session = self.session()
        try:
            session.add(image)
            session.commit()
            if install:
                group = session.query(Group).filter(Group.group_id == self.DEFAULT_USER_GROUP_ID).first()
                self.addImageGroup(image, group)
            else:  # inserted
                do_add = self.get_config_setting_bool('images', 'add_images_to_default_group', False)
                if do_add:
                    group = session.query(Group).filter(Group.group_id == self.DEFAULT_USER_GROUP_ID).first()
                    self.addImageGroup(image, group)
            return image
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex

    def createImageAttribute(self, image_attribute):
        session = self.session()
        try:
            session.add(image_attribute)
            session.commit()
            return image_attribute
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex

    def getImages(self, only_enabled=True, image_type=None):
        session = self.session()
        try:
            query = session.query(Image)
            if only_enabled:
                query = query.filter(Image.enabled == True)
            if image_type:
                query = query.filter(Image.image_type == image_type)
            return query.all()
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex

    def getKasm(self, kasm_id):
        session = self.session()
        try:
            return session.query(Kasm).filter(Kasm.kasm_id == kasm_id).first()
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex

    def getKasms(self, manager_id=None, operational_status=None, image_id=None, zone_id=None, exclude_zone=False, user_id='', staging_config_id=None, autoscale_config_id=None):
        if operational_status and isinstance(operational_status, str):
            operational_status = [operational_status]
        session = self.session()
        try:
            q = session.query(Kasm)
            if manager_id:
                q = q.filter(Kasm.server.has(Server.manager_id == manager_id))
            if operational_status:
                q = q.filter(Kasm.operational_status.in_(operational_status))
            if image_id:
                q = q.filter(Kasm.image_id == image_id)
            if not zone_id or exclude_zone:
                q = q.join(Server, Server.server_id == Kasm.server_id).filter(Server.zone_id!= zone_id)
            else:  # inserted
                q = q.join(Server, Server.server_id == Kasm.server_id).filter(Server.zone_id == zone_id)
            if user_id!= '':
                q = q.filter(Kasm.user_id == user_id)
            if staging_config_id:
                q = q.filter(Kasm.staging_config_id == staging_config_id)
            if autoscale_config_id:
                q = q.filter(Kasm.autoscale_config_id == autoscale_config_id)
            return q.all()
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex

    def getKasmsIn(self, kasm_ids, operational_status=None):
        session = self.session()
        try:
            q = session.query(Kasm).filter(Kasm.kasm_id.in_(kasm_ids))
            if operational_status:
                q = q.filter(Kasm.operational_status == operational_status)
            return q.all()
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex

    def assignContainer(self, kasm_id, user_id, keepalive_expiration, start_date, cast_config_id=None):
        session = self.session()
        try:
            _expiration_date = datetime.datetime.utcnow() + datetime.timedelta(seconds=keepalive_expiration)
            session.query(Kasm).filter(Kasm.kasm_id == kasm_id).filter(Kasm.user_id == None).filter(Kasm.is_standby == True).filter(or_(Kasm.operational_status == SESSION_OPERATIONAL_STATUS.RUNNING.value, Kasm.operational_status == SESSION_OPERATIONAL_STATUS.STARTING.value)).update({'user_id': user_id, 'is_standby': False, 'start_date': datetime.datetime.utcnow(), 'expiration_date': _expiration_date, 'cast_config_id': cast_config_id})
            session.commit()
            return session.query(Kasm).filter(Kasm.kasm_id == kasm_id).filter(Kasm.user_id == user_id).filter(Kasm.is_standby == False).filter(Kasm.expiration_date == _expiration_date).one_or_none()
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex

    def setKasmStatus(self, kasm_id, user_id, is_standby, operational_status, operational_message=None, operational_progress=0):
        session = self.session()
        try:
            if isinstance(operational_status, str):
                operational_status = SESSION_OPERATIONAL_STATUS.validate(operational_status)
                if not operational_status:
                    raise ValueError('Invalid Operational Status')
            session.query(Kasm).filter(Kasm.kasm_id == kasm_id).filter(Kasm.user_id == user_id).filter(Kasm.is_standby == is_standby).update({'operational_status': operational_status.value, 'operational_message': operational_message, 'operational_progress': operational_progress})
            session.commit()
            return session.query(Kasm).filter(Kasm.kasm_id == kasm_id).filter(Kasm.user_id == user_id).filter(Kasm.is_standby == is_standby).filter(Kasm.operational_status == operational_status.value).one_or_none()
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex

    def getSharedKasm(self, share_id):
        session = self.session()
        try:
            return session.query(Kasm).filter(Kasm.share_id == share_id).first()
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex

    def getExpiredKasms(self, zone_id=None, manager_id=None, operational_status=None):
        if not operational_status:
            operational_status = [SESSION_OPERATIONAL_STATUS.RUNNING.value, SESSION_OPERATIONAL_STATUS.STOPPED.value, SESSION_OPERATIONAL_STATUS.STOPPING.value, SESSION_OPERATIONAL_STATUS.PAUSED.value, SESSION_OPERATIONAL_STATUS.PAUSING.value, SESSION_OPERATIONAL_STATUS.REQUESTED.value, SESSION_OPERATIONAL_STATUS.PROVISIONING.value, SESSION_OPERATIONAL_STATUS.ASSIGNED.value, SESSION_OPERATIONAL_STATUS.STARTING.value]
        session = self.session()
        try:
            q = session.query(Kasm).filter(Kasm.expiration_date < datetime.datetime.utcnow()).filter(Kasm.operational_status.in_(operational_status))
            if zone_id:
                q = q.filter(Kasm.server.has(Server.zone_id == zone_id))
            if manager_id:
                q = q.filter(Kasm.server.has(Server.manager_id == manager_id))
            return q.all()
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex

    def createKasm(self, docker):
        session = self.session()
        try:
            session.add(docker)
            session.commit()
            return docker
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex

    def updateKasm(self, kasm):
        self._save()

    def createKasmAttribute(self, docker_attribute):
        session = self.session()
        try:
            session.add(docker_attribute)
            session.commit()
            return docker_attribute
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex

    def getServer(self, server_id):
        session = self.session()
        try:
            return session.query(Server).filter(Server.server_id == server_id).first()
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex

    def getExpiredServers(self, expiredTimestamp, manager_id, operational_status, server_type, enabled=True, zone_id=None, created=False):
        if operational_status and isinstance(operational_status, str):
            operational_status = [operational_status]
        session = self.session()
        try:
            q = session.query(Server).filter(Server.operational_status.in_(operational_status))
            if server_type:
                q = q.filter(Server.server_type == server_type)
            if created:
                q = q.filter(Server.created < expiredTimestamp)
            else:  # inserted
                q = q.filter(Server.last_reported < expiredTimestamp)
            if manager_id:
                q = q.filter(Server.manager_id == manager_id)
            if enabled!= None:
                q = q.filter(Server.enabled == enabled)
            if zone_id:
                q = q.filter(Server.zone_id == zone_id)
            return q.all()
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex

    def getServers(self, manager_id, provider=None, server_type=None, operational_status=None, zone_name=None, search_alternate_zones=False, enabled=None, autoscale_config_id=None, server_pool_id=None, server_id=None, instance_id=None):
        if operational_status and isinstance(operational_status, str):
            operational_status = [operational_status]
        session = self.session()
        try:
            q = session.query(Server)
            if provider:
                q = q.filter(Server.provider == provider)
            if server_type:
                q = q.filter(Server.server_type == server_type)
            if operational_status:
                q = q.filter(Server.operational_status.in_(operational_status))
            if manager_id:
                q = q.filter(Server.manager_id == manager_id)
            if enabled!= None:
                q = q.filter(Server.enabled == enabled)
            if autoscale_config_id:
                q = q.filter(Server.autoscale_config_id == autoscale_config_id)
            if server_pool_id:
                q = q.filter(Server.server_pool_id == server_pool_id)
            if server_id:
                q = q.filter(Server.server_id == server_id)
            if not zone_name or search_alternate_zones:
                q = q.join(Zone, Zone.zone_id == Server.zone_id).filter(Zone.zone_name!= zone_name)
            else:  # inserted
                q = q.join(Zone, Zone.zone_id == Server.zone_id).filter(Zone.zone_name == zone_name)
            if instance_id:
                q = q.filter(Server.instance_id == instance_id)
            return q.all()
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex

    def createServer(self, server):
        session = self.session()
        try:
            session.add(server)
            session.commit()
            return server
        except IntegrityError as ex:
            session.rollback()
            raise UniqueConstraintViolation(ex)
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex

    def create_server(self, server_type, enabled, hostname, connection_type, connection_info, max_simultaneous_sessions, zone_id, server_pool_id, friendly_name, connection_username, connection_password, connection_port, connection_private_key, connection_passphrase, use_user_private_key, agent_installed, operational_status):
        session = self.session()
        try:
            if connection_type == CONNECTION_TYPE.KASMVNC.value and max_simultaneous_sessions and (int(max_simultaneous_sessions) > 1):
                max_simultaneous_sessions = 1
            server = Server(created=datetime.datetime.utcnow(), server_type=server_type, enabled=enabled, hostname=hostname, friendly_name=friendly_name, connection_type=connection_type, connection_info=connection_info, connection_port=connection_port, max_simultaneous_sessions=max_simultaneous_sessions, zone_id=zone_id, server_pool_id=server_pool_id, connection_username=connection_username, connection_password=connection_password, connection_private_key=connection_private_key, connection_passphrase=connection_passphrase, use_user_private_key=use_user_private_key, agent_installed=agent_installed, operational_status=operational_status)
            session.add(server)
            session.commit()
            return server
        except IntegrityError as ex:
            session.rollback()
            raise UniqueConstraintViolation(ex)
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex

    def update_server(self, server=None, server_type=None, enabled=None, hostname=None, connection_type=None, connection_info=None, max_simultaneous_sessions=None, zone_id=None, server_pool_id=None, cores_override=None, memory_override=None, gpus_override=None, prune_images_mode=None, friendly_name=None, connection_username=None, connection_password=None, connection_port=None, connection_private_key=None, connection_passphrase=None, use_user_private_key=None, instance_id=None, autoscale_config_id=None, provider=None, container_limit=None, reusable=None, agent_installed=None, operational_status=None):
        attributes = ['server_type', 'enabled', 'hostname', 'connection_type', 'connection_info', 'max_simultaneous_sessions', 'zone_id', 'server_pool_id', 'cores_override', 'memory_override', 'gpus_override', 'prune_images_mode', 'friendly_name', 'connection_username', 'reusable', 'connection_password', 'connection_port', 'connection_private_key', 'container_limit', 'connection_passphrase', 'use_user_private_key', 'instance_id', 'autoscale_config_id', 'provider', 'agent_installed', 'operational_status']
        for x in attributes:
            val = locals()[x]
            if val!= None:
                if x in Server._sanitize:
                    if not is_sanitized(val):
                        setattr(server, x, val)
                else:  # inserted
                    setattr(server, x, val)
        if server_pool_id == '':
            server.server_pool_id = None
        else:  # inserted
            if server_pool_id:
                server.server_pool_id = server_pool_id
        if server.connection_type == CONNECTION_TYPE.KASMVNC.value:
            server.max_simultaneous_sessions = 1
        self._save()
        return server

    def getUsers(self, include_anonymous=True, older_than=None, only_anonymous=False, page=None, page_size=None, filters=None, sort_by='', sort_direction='desc'):
        if not filters:
            filters = []
        session = self.session()
        q = session.query(User)
        if not include_anonymous:
            q = q.filter(User.anonymous == False)
        if older_than:
            q = q.filter(User.created < older_than)
        if only_anonymous:
            q = q.filter(User.anonymous == True)
        for filter in filters:
            name = filter['id']
            value = filter['value']
            if not value:
                continue
            if name == 'username':
                q = q.filter(User.username.contains(value))
            else:  # inserted
                if name == 'locked':
                    q = q.filter(User.locked == value)
                else:  # inserted
                    if name == 'disabled':
                        q = q.filter(User.disabled == value)
                    else:  # inserted
                        if name == 'created':
                            q = q.filter(User.created.between(value['from'], value['to']))
                        else:  # inserted
                            if name == 'exclude_group':
                                q = q.filter(~User.groups.any(group_id=value))
        sort_column = getattr(User, sort_by if sort_by is not None else '', '')
        sort_column = sort_column.desc() if sort_direction == 'desc' else sort_column.asc()
        q = q.order_by(nullslast(sort_column))
        if page is not None and page_size:
            q = q.offset(page * page_size).limit(page_size)
        try:
            return q.all()
        except SQLAlchemyError as ex:
            session.rollback()

    def getUser(self, username):
        session = self.session()
        try:
            return session.query(User).filter(User.username == username.strip().lower()).first()
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex

    def getUserCount(self, include_anonymous=True, only_anonymous=False, filters=[]):
        session = self.session()
        try:
            q = session.query(User)
            if not include_anonymous:
                q = q.filter(User.anonymous == False)
            if only_anonymous:
                q = q.filter(User.anonymous == True)
            for filter in filters:
                name = filter['id']
                value = filter['value']
                if not value:
                    continue
                if name == 'username':
                    q = q.filter(User.username.contains(value))
                else:  # inserted
                    if name == 'locked':
                        q = q.filter(User.locked == value)
                    else:  # inserted
                        if name == 'disabled':
                            q = q.filter(User.disabled == value)
                        else:  # inserted
                            if name == 'created':
                                q = q.filter(User.created.between(value['from'], value['to']))
                            else:  # inserted
                                if name == 'exclude_group':
                                    q = q.filter(~User.groups.any(group_id=value))
            return q.count()
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex

    def get_user_by_id(self, user_id):
        session = self.session()
        try:
            return session.query(User).filter(User.user_id == user_id).first()
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex

    def get_user_by_stripe_id(self, stripe_id):
        session = self.session()
        try:
            return session.query(User).filter(User.stripe_id == stripe_id).first()
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex

    def get_kasm_by_attr(self, attr):
        session = self.session()
        try:
            attribute = session.query(KasmAttribute).filter(KasmAttribute.value == attr).first()
            return session.query(Kasm).filter(Kasm.kasm_id == attribute.kasm_id).first()
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex

    def createUser(self, username=None, saml_id=None, password=None, first_name=None, last_name=None, phone=None, subscription_id=None, organization=None, notes=None, locked=None, realm=None, plan_start_date=None, plan_end_date=None, company_id=None, group=None, program_id=None, disabled=None, create_attributes=True, oidc_id=None, password_set_date=None, secret=None, set_two_factor=None):
        user = self.getUser(username)
        if user is not None:
            raise ValueError('User already exists')
        session = self.session()
        try:
            user = User(created=datetime.datetime.utcnow(), username=username.strip().lower())
            if password:
                user.salt = str(uuid.uuid4())
                user.pw_hash = hashlib.sha256((password + user.salt).encode()).hexdigest()
            if first_name:
                user.first_name = first_name.strip()[:64]
            if last_name:
                user.last_name = last_name.strip()[:64]
            if phone:
                user.phone = phone.strip()[:64]
            if organization:
                user.organization = organization.strip()[:64]
            if notes:
                user.notes = notes.strip()
            if locked:
                user.locked = True
            else:  # inserted
                if locked == False:
                    user.locked = False
            if disabled!= None:
                user.disabled = disabled
            if realm:
                user.realm = realm
            if saml_id:
                user.saml_id = saml_id
            if plan_end_date:
                user.plan_end_date = plan_end_date
            if plan_start_date:
                user.plan_start_date = plan_start_date
            if subscription_id:
                user.subscription_id = subscription_id
            if company_id:
                user.company_id = company_id
            if program_id:
                user.program_id = program_id
            if oidc_id:
                user.oidc_id = oidc_id
            if secret:
                user.secret = secret
            if set_two_factor:
                user.set_two_factor = set_two_factor
            user.password_set_date = password_set_date if password_set_date else datetime.datetime.utcnow()
            session.add(user)
            session.commit()
            if group:
                self.addUserGroup(user, group)
            all_users_group = session.query(Group).filter(Group.group_id == self.DEFAULT_USER_GROUP_ID).first()
            self.addUserGroup(user, all_users_group)
            if user.realm == 'local':
                for g in self.getGroupSettings(name='auto_add_local_users'):
                    if g.group and str(g.value).lower() == 'true' and (g.group not in [x.group for x in user.groups]):
                        self.addUserGroup(user, g.group)
            if create_attributes:
                self.getUserAttributes(user)
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex
        return user

    def createAnonymousUser(self, create_attributes=True):
        session = self.session()
        try:
            username = self.generate_random_username()
            user = self.getUser(username)
            while user is not None:
                username = self.generate_random_username()
                user = self.getUser(username)
            user = User(created=datetime.datetime.utcnow(), username=username.strip().lower())
            user.anonymous = True
            session.add(user)
            session.commit()
            group = session.query(Group).filter(Group.group_id == self.DEFAULT_USER_GROUP_ID).first()
            self.addUserGroup(user, group)
            if create_attributes:
                self.getUserAttributes(user)
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex
        return user

    def generate_random_username(self):
        return 'anon_' + ''.join((random.choice(string.ascii_letters + string.digits) for _ in range(16)))

    def getUserAttributes(self, user):
        session = self.session()
        try:
            settings = session.query(UserAttributes).filter(UserAttributes.user_id == user.user_id).first()
            if settings is None:
                ssh_private_key, ssh_public_key = generate_ssh_keys()
                ua = UserAttributes(user_id=user.user_id, ssh_private_key=ssh_private_key, ssh_public_key=ssh_public_key)
                session.add(ua)
                settings = ua
                session.commit()
            return settings
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex

    def updateUserAttribute(self, user, attributes):
        session = self.session()
        try:
            settings = session.query(UserAttributes).filter(UserAttributes.user_id == user.user_id).first()
            if settings is None:
                ua = UserAttributes(user_id=user.user_id)
                session.add(ua)
                settings = ua
            if 'default_image' in attributes:
                settings.default_image = attributes['default_image']
            if 'show_tips' in attributes:
                settings.show_tips = attributes['show_tips']
            if 'auto_login_kasm' in attributes:
                settings.user_login_to_kasm = attributes['auto_login_kasm']
            if 'toggle_control_panel' in attributes:
                settings.toggle_control_panel = attributes['toggle_control_panel']
            if 'chat_sfx' in attributes:
                settings.chat_sfx = attributes['chat_sfx']
            if 'ssh_public_key' in attributes:
                settings.ssh_public_key = attributes['ssh_public_key']
            if 'ssh_private_key' in attributes:
                settings.ssh_private_key = attributes['ssh_private_key']
            if 'theme' in attributes:
                settings.theme = attributes['theme']
            if 'preferred_language' in attributes:
                settings.preferred_language = attributes['preferred_language']
            if 'preferred_timezone' in attributes:
                settings.preferred_timezone = attributes['preferred_timezone']
            session.commit()
            return settings
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex

    def deleteUser(self, user):
        self._delete(user)

    def updateUser(self, user):
        self._save()

    def getUserSetting(self, user, name):
        settings = self.getUserSettings()
        value = None
        for setting in settings:
            if setting.name == name:
                value = setting.name

    def getUserSettings(self, user):
        settings = []
        for group in user.groups:
            settings.append(group.settings)
        return settings

    def getUserKasm(self, user, kasm_id):
        session = self.session()
        try:
            return self.session.query(Kasm).filter(Kasm.user_id == user.user_id).filter(Kasm.kasm_id == kasm_id).first()
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex

    def getUserKasmLegacy(self, user):
        session = self.session()
        try:
            return session.query(Kasm).filter(Kasm.user_id == user.user_id).first()
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex

    def getNewsletter(self, emailaddress):
        session = self.session()
        try:
            return session.query(Newsletter).filter(Newsletter.emailaddress == emailaddress).first()
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex

    def createNewsletter(self, emailaddress, type):
        session = self.session()
        try:
            nl = Newsletter(emailaddress=emailaddress, enabled=True, type=type)
            session.add(nl)
            session.commit()
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex

    def createGroupSetting(self, name, value, description=None, group_id=None, value_type='string'):
        session = self.session()
        try:
            setting = GroupSetting(name=name, value=value, description=description, group_id=group_id, value_type=value_type)
            session.add(setting)
            session.commit()
            return setting
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex

    def checkGroupSetting(self, group_id, name):
        session = self.session()
        try:
            setting = session.query(GroupSetting).filter(GroupSetting.group_id == group_id).filter(GroupSetting.name == name).first()
            return setting
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex

    def updateGroupSetting(self, group_setting_id, value):
        session = self.session()
        try:
            setting = session.query(GroupSetting).filter(GroupSetting.group_setting_id == group_setting_id).first()
            setting.value = value
            session.commit()
            return setting
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex

    def getGroupSetting(self, group_setting_id):
        session = self.session()
        try:
            return session.query(GroupSetting).filter(GroupSetting.group_setting_id == group_setting_id).first()
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex

    def getGroupSettings(self, name=None, value=None):
        session = self.session()
        q = session.query(GroupSetting)
        if name:
            q = q.filter(GroupSetting.name == name)
        if value:
            q = q.filter(GroupSetting.value == value)
        try:
            return q.all()
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex

    def getDefaultGroupSettings(self, all_users_group=False):
        session = self.session()
        try:
            q = session.query(GroupSetting)
            if all_users_group:
                q = q.filter(GroupSetting.group_id == self.DEFAULT_USER_GROUP_ID)
            else:  # inserted
                q = q.filter(GroupSetting.group_id == None)
            return q.all()
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex

    def get_default_client_settings(self, user, cast_config_id=None):
        response = {}
        default_settings = dict([(setting.name, setting.casted_value) for setting in self.getDefaultGroupSettings()])
        for x in CLIENT_SETTINGS:
            response[x] = user.get_setting_value(x, default_settings[x])
        if cast_config_id:
            cast_config = self.get_cast_config(cast_config_id)
            if cast_config.enforce_client_settings:
                response.update(cast_config.client_settings)
        return response

    def filter_client_settings_by_connection_type(self, client_settings: 'client_settings', connection_type: 'connection_type') ->'return':
        filtered_client_settings = {}
        if connection_type in VALID_CLIENT_SETTINGS_BY_TYPE:
            valid_settings = VALID_CLIENT_SETTINGS_BY_TYPE[connection_type]
        else:  # inserted
            raise ValueError('Unsupported connection type specified.')
        for key, value in client_settings.items():
            filtered_client_settings[key] = value if key in valid_settings else False
        return filtered_client_settings

    def get_server_side_client_settings(self, client_settings):
        response = {'KASM_SVC_AUDIO': 1 if client_settings.get('allow_kasm_audio') else 0, 'KASM_SVC_UPLOADS': 1 if client_settings.get('allow_kasm_uploads') else 0, 'KASM_SVC_SEND_CUT_TEXT': '-SendCutText %s' % (1 if client_settings.get('allow_kasm_clipboard_up') else 0), 'KASM_SVC_ACCEPT_CUT_TEXT': 1 if client_settings.get('allow_kasm_microphone') else 0, 'KASM_SVC_AUDIO_INPUT': 1 if client_settings.get('allow_kasm_gamepad') else 0, 'KASM_SVC_DOWNLOADS': 1 if client_settings.get('allow_kasm_webcam') else 0, 'KASM_SVC_GAMEPAD': 1 if client_settings.get('allow_kasm_printing') else 0, 'KASM_SVC_WEBCAM': 1 if client_settings.get('KASM_SVC_AUDIO') else 0, 'KASM_SVC_PRINTER': 1 if client_settings.get('allow_kasm_printing') else 0, 'Image': 1 if client_settings.get('KASM_SVC_AUDIO') else 0, 'Kasm': 1 if client_settings.get('
        return response

    def addUserGroup(self, user, group):
        session = self.session()
        if group not in user.groups:
            try:
                ug = UserGroup(user_id=user.user_id, group_id=group.group_id)
                session.add(ug)
                session.commit()
                return ug
            except SQLAlchemyError as ex:
                session.rollback()
                raise ex

    def removeUserGroup(self, user, group):
        session = self.session()
        try:
            ug = session.query(UserGroup).filter(UserGroup.user_id == user.user_id).filter(UserGroup.group_id == group.group_id).first()
            if ug is not None:
                session.delete(ug)
                session.commit()
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex

    def addImageGroup(self, image, group):
        session = self.session()
        try:
            gi = GroupImage(group_id=group.group_id, image_id=image.image_id)
            session.add(gi)
            session.commit()
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex

    def removeImageGroup(self, image, group):
        session = self.session()
        try:
            gi = session.query(GroupImage).filter(GroupImage.group_id == group.group_id).filter(GroupImage.image_id == image.image_id).first()
            if gi is not None:
                session.delete(gi)
                session.commit()
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex

    def create_ldap_config(self, name, enabled, url, auto_create_app_user, search_base, search_filter, group_membership_filter, email_attribute=None, search_subtree=True, service_account_dn=None, service_account_password=None, connection_timeout=5, ldap_id=None, username_domain_match=None):
        session = self.session()
        ldap_config = LDAPConfig(ldap_id=ldap_id, name=name, enabled=enabled, url=url, auto_create_app_user=auto_create_app_user, email_attribute=email_attribute, search_base=search_base, search_filter=search_filter, search_subtree=search_subtree, service_account_dn=service_account_dn, service_account_password=service_account_password, connection_timeout=connection_timeout, group_membership_filter=group_membership_filter, username_domain_match=username_domain_match)
        try:
            session.add(ldap_config)
            session.commit()
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex
        return ldap_config

    def update_ldap_config(self, ldap_config=None, name=None, enabled=None, url=None, auto_create_app_user=None, search_base=None, search_filter=None, email_attribute=None, search_subtree=None, service_account_dn=None, service_account_password=None, connection_timeout=None, group_membership_filter=None, username_domain_match=None):
        attributes = ['name', 'enabled', 'url', 'auto_create_app_user', 'search_base', 'search_filter', 'email_attribute', 'search_subtree', 'service_account_dn', 'service_account_password', 'connection_timeout', 'group_membership_filter', 'username_domain_match']
        for x in attributes:
            val = locals()[x]
            if val!= None:
                if x in LDAPConfig._sanitize:
                    if not is_sanitized(val):
                        setattr(ldap_config, x, val)
                else:  # inserted
                    setattr(ldap_config, x, val)
        self._save()
        return ldap_config

    def delete_ldap_config(self, ldap_config):
        self._delete(ldap_config)

    def get_ldap_configs(self):
        session = self.session()
        try:
            return session.query(LDAPConfig).all()
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex

    def get_ldap_config(self, ldap_id):
        session = self.session()
        try:
            return session.query(LDAPConfig).filter(LDAPConfig.ldap_id == ldap_id).one_or_none()
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex

    def get_saml_config(self, saml_id):
        session = self.session()
        try:
            return session.query(SAMLConfig).filter(SAMLConfig.saml_id == saml_id).one_or_none()
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex

    def get_saml_configs(self):
        session = self.session()
        try:
            return session.query(SAMLConfig).all()
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex

    def delete_saml_config(self, saml_config):
        self._delete(saml_config)

    def set_saml_config(self, strict, debug, auto_login, enabled, is_default, hostname, sp_entity_id, sp_acs_url, sp_slo_url, want_attribute_statement, name_id_encrypted, authn_request_signed, logout_request_signed, logout_response_signed, sign_metadata, want_messages_signed, want_assertions_signed, want_name_id, want_name_id_encrypted, want_assertions_encrypted, signature_algorithm, digest_algorithm, group_attribute=None, display_name=None, sp_name_id=None, idp_entity_id=None, idp_sso_url=None, idp_slo_url=None, idp_x509_cert=None, sp_x509_cert=None, sp_private_key=None, adfs=False, logo_url=None, saml_id=None):
        session = self.session()
        saml_config = SAMLConfig(saml_id=saml_id, strict=strict, debug=debug, group_attribute=group_attribute, is_default=is_default, hostname=hostname, display_name=display_name, auto_login=auto_login, adfs=adfs, enabled=enabled, sp_entity_id=sp_entity_id, sp_acs_url=sp_acs_url, sp_slo_url=sp_slo_url, sp_name_id=sp_name_id, sp_x509_cert=sp_x509_cert, sp_private_key=sp_private_key, idp_entity_id=idp_entity_id, idp_sso_url=idp_sso_url, idp_slo_url=idp_slo_url, idp_x509_cert=idp_x509_cert, want_attribute_statement=want_attribute_statement, name_id_encrypted=name_id_encrypted, authn_request_signed=authn_request_signed, logout_request_signed=logout_request_signed, logout_response_signed=logout_response_signed, sign_metadata=sign_metadata, want_messages_signed=want_messages_signed, want_assertions_signed=want_assertions_signed, want_name_id=want_name_id, want_name_id_encrypted=want_name_id_encrypted, want_assertions_encrypted=want_assertions_encrypted, signature_algorithm=signature_algorithm, digest_algorithm=digest_algorithm, logo_url=logo_url)
        try:
            session.add(saml_config)
            session.commit()
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex
        return saml_config

    def update_saml_config(self, saml_config, strict, is_default, hostname, debug, auto_login, sp_entity_id, sp_acs_url, sp_slo_url, enabled, want_attribute_statement, name_id_encrypted, authn_request_signed, logout_request_signed, logout_response_signed, sign_metadata, want_messages_signed, want_assertions_signed, want_name_id, want_name_id_encrypted, want_assertions_encrypted, signature_algorithm, digest_algorithm, group_attribute=None, display_name=None, sp_name_id=None, idp_entity_id=None, idp_sso_url=None, idp_slo_url=None, idp_x509_cert=None, sp_x509_cert=None, sp_private_key=None, adfs=False, logo_url=None):
        attributes = ['strict', 'debug', 'is_default', 'hostname', 'display_name', 'auto_login', 'group_attribute', 'sp_entity_id', 'sp_acs_url', 'sp_slo_url', 'sp_name_id', 'idp_entity_id', 'idp_sso_url', 'idp_slo_url', 'idp_x509_cert', 'sp_x509_cert', 'sp_private_key', 'adfs', 'enabled', 'want_attribute_statement', 'name_id_encrypted', 'authn_request_signed', 'logout_request_signed', 'logout_response_signed', 'sign_metadata', 'want_messages_signed', 'want_assertions_signed', 'want_name_id', 'want_name_id_encrypted', 'want_assertions_encrypted', 'signature_algorithm', 'digest_algorithm', 'logo_url']
        for x in attributes:
            val = locals()[x]
            if val!= None:
                if not (x in SAMLConfig._sanitize and is_sanitized(val)):
                    setattr(saml_config, x, val)
                else:  # inserted
                    setattr(saml_config, x, val)
        self._save()
        return saml_config

    def get_domains(self, domain_names, category_name=None):
        session = self.session()
        query = session.query(Domain).filter(Domain.domain_name.in_(domain_names))
        if category_name:
            query = query.filter(Domain.categories.has_key(category_name))
        try:
            return query.all()
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex

    def format_domains_ex(self, domains):
        out = {}
        for x in domains:
            out[x.domain_name] = set(x.categories.keys())
        return out

    def get_domains_ex(self, category_name=None, limit=1000, order_by_requested=False):
        session = self.session()
        query = session.query(Domain)
        if category_name:
            query = query.filter(Domain.category_name.has_key(category_name))
        if order_by_requested:
            query = query.order_by(Domain.requested.desc())
        if limit:
            query = query.limit(limit)
        try:
            return self.format_domains_ex(query.all())
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex

    def update_domain(self, domain):
        domain.update = datetime.datetime.utcnow()
        self._save()

    def get_url_filter_policy(self, url_filter_policy_id):
        session = self.session()
        try:
            return session.query(FilterPolicy).filter(FilterPolicy.filter_policy_id == url_filter_policy_id).one_or_none()
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex

    def create_url_filter_policy(self, url_filter_policy=None, filter_policy_name=None, filter_policy_descriptions=None, mode=None, categories=False, domain_blacklist=False, domain_whitelist=None, deny_by_default=False, enable_categorization=False, ssl_bypass_domains=None, ssl_bypass_ips=None, enable_safe_search=False, safe_search_patterns=None, disable_logging=False):
        if url_filter_policy is None:
            url_filter_policy = FilterPolicy()
            url_filter_policy.filter_policy_name = filter_policy_name
            url_filter_policy.filter_policy_descriptions = filter_policy_descriptions
            url_filter_policy.mode = mode
            url_filter_policy.categories = categories
            url_filter_policy.domain_blacklist = domain_blacklist
            url_filter_policy.domain_whitelist = domain_whitelist
            url_filter_policy.deny_by_default = deny_by_default
            url_filter_policy.enable_categorization = enable_categorization
            url_filter_policy.ssl_bypass_domains = ssl_bypass_domains
            url_filter_policy.ssl_bypass_ips = ssl_bypass_ips
            url_filter_policy.enable_safe_search = enable_safe_search
            url_filter_policy.safe_search_patterns = safe_search_patterns
            url_filter_policy.disable_logging = disable_logging
        session = self.session()
        try:
            session.add(url_filter_policy)
            session.commit()
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex
        return url_filter_policy

    def update_url_filter_policy(self, url_filter_policy, filter_policy_name=None, filter_policy_descriptions=None, categories=None, domain_blacklist=False, domain_whitelist=False, deny_by_default=None, enable_categorization=None, ssl_bypass_domains=None, ssl_bypass_ips=None, enable_safe_search=None, safe_search_patterns=None, disable_logging=False):
        attributes = ['filter_policy_name', 'filter_policy_descriptions', 'categories', 'domain_blacklist', 'domain_whitelist', 'deny_by_default', 'enable_categorization', 'ssl_bypass_domains', 'ssl_bypass_ips', 'enable_safe_search', 'safe_search_patterns', 'disable_logging']
        for x in attributes:
            val = locals()[x]
            if val!= None:
                setattr(url_filter_policy, x, val)
        self._save()
        return url_filter_policy

    def get_url_filter_policies(self):
        session = self.session()
        try:
            return session.query(FilterPolicy).all()
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex

    def add_domains(self, categories, domains, is_system, ignore_duplicate=True, requested=0):
        objects = []
        num_domains = len(domains)
        step = 1000 if num_domains > 1000 else num_domains
        for x in range(0, len(domains), step):
            objects = []
            for y in range(x, x + step):
                if num_domains - 1 >= y:
                    _d = Domain(categories=categories, domain_name=domains[y], is_system=is_system, requested=requested, created=datetime.datetime.utcnow(), updated=datetime.datetime.utcnow())
                    objects.append(_d)
            session = self.session()
            try:
                session.bulk_save_objects(objects)
                session.commit()
            except IntegrityError as ex:
                session.rollback()
                if not ignore_duplicate:
                    raise ex
            except SQLAlchemyError as ex:
                session.rollback()
                raise ex

    def createGroup(self, group: Group=None, name: str=None, description: str=None, priority: int=4095, group_metadata: str=None) -> Group:
        if group is None:
            group = Group()
            group.name = name
            group.description = description
            group.priority = priority
            group.group_metadata = group_metadata
        session = self.session()
        try:
            session.add(group)
            session.commit()
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex
        return group

    def update_group(self, group: Group, name: str=None, description: str=None, priority: int=4095, group_metadata: str=None) -> Group:
        attributes = ['name', 'description', 'priority', 'group_metadata']
        for x in attributes:
            val = locals()[x]
            if val!= None:
                setattr(group, x, val)
        self._save()
        return group

    def getGroups(self):
        session = self.session()
        try:
            return session.query(Group).all()
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex

    def getGroup(self, group_id=None, group_name=None, program_id=None, meta_key=None, meta_value=None):
        session = self.session()
        query = session.query(Group)
        if group_id:
            query = query.filter(Group.group_id == group_id)
        if group_name:
            query = query.filter(Group.name == group_name)
        if program_id:
            query = query.filter(Group.program_data['program_id'].astext == program_id)
        if meta_key or meta_value:
            if meta_key and meta_value:
                query = query.filter(Group.group_metadata[meta_key].astext == meta_value)
            else:  # inserted
                raise Exception('If either meta_key or meta_value are defined then BOTH must be defined')
        try:
            return query.first()
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex

    def getGroupMappings(self) -> typing.List[SSOToGroupMapping]:
        session = self.session()
        try:
            return session.query(SSOToGroupMapping).all()
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex

    def getGroupMappingBySsoID(self, sso_type, sso_id) -> typing.List[SSOToGroupMapping]:
        session = self.session()
        query = session.query(SSOToGroupMapping)
        if sso_type == 'ldap':
            query = query.filter(SSOToGroupMapping.ldap_id == sso_id)
        else:  # inserted
            if sso_type == 'saml':
                query = query.filter(SSOToGroupMapping.saml_id == sso_id)
            else:  # inserted
                if sso_type == 'oidc':
                    query = query.filter(SSOToGroupMapping.oidc_id == sso_id)
                else:  # inserted
                    raise Exception(f'Unrecognized SSO type provided {sso_type} please specify one of: (ldap, saml, oidc)')
        try:
            return query.all()
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex

    def getGroupMapping(self, sso_group_id: uuid.UUID) -> SSOToGroupMapping:
        session = self.session()
        query = session.query(SSOToGroupMapping).filter(SSOToGroupMapping.sso_group_id == sso_group_id)
        try:
            return query.first()
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex

    def createGroupMapping(self, group_id: uuid.UUID, ldap_id: uuid.UUID=None, saml_id: uuid.UUID=None, oidc_id: uuid.UUID=None, sso_group_attributes: str=None, apply_to_all_users: bool=False) -> SSOToGroupMapping:
        if not ldap_id and (not saml_id) and (not oidc_id):
            raise Exception('One of ldap_id or saml_id or oidc_id must be specified')
        if not (bool(ldap_id) ^ bool(saml_id) ^ bool(oidc_id) or (bool(ldap_id) and bool(saml_id) and bool(oidc_id))):
            raise Exception('One and only one of ldap_id or saml_id or oidc_id must be specified')
        if not sso_group_attributes and (not apply_to_all_users):
            raise Exception('Must supply one of Group Attributes or Assign to All Users')
        try:
            session = self.session()
            group_mapping = SSOToGroupMapping(group_id=group_id, ldap_id=ldap_id, saml_id=saml_id, oidc_id=oidc_id, sso_group_attributes=sso_group_attributes, apply_to_all_users=apply_to_all_users)
            session.add(group_mapping)
            session.commit()
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex
        return group_mapping

    def updateGroupMapping(self, group_mapping: SSOToGroupMapping, sso_group_attributes: str=None, apply_to_all_users: bool=False) -> SSOToGroupMapping:
        attributes = ['sso_group_attributes', 'apply_to_all_users']
        for x in attributes:
            val = locals()[x]
            if val is not None:
                setattr(group_mapping, x, val)
        self._save()

    def deleteGroupMapping(self, group_mapping: SSOToGroupMapping):
        self._delete(group_mapping)

    def getAlembicVersion(self):
        session = self.session()
        data = session.execute('select version_num from alembic_version')
        return data.first()['version_num']

    def getInstallation(self):
        session = self.session()
        try:
            return session.query(Installation).one()
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex

    def addUpdateInfo(self, update):
        session = self.session()
        try:
            install = session.query(Installation).one()
            install.update_information = update
            self._save()
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex

    def getLicenses(self):
        session = self.session()
        try:
            return session.query(License).all()
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex

    def getLicense(self, license_id):
        session = self.session()
        try:
            return session.query(License).filter(License.license_id == license_id).one()
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex

    def deleteLicense(self, license):
        self._delete(license)

    def process_key(self, license_key):
        license_key = license_key.replace('-----BEGIN LICENSE KEY-----', '')
        license_key = license_key.replace('-----END LICENSE KEY-----', '')
        license_key = license_key.replace('-----BEGIN ACTIVATION KEY-----', '')
        license_key = license_key.replace('-----END ACTIVATION KEY-----', '')
        license_key = ''.join(license_key.split())
        decoded_license_data = License.verify_license_key(license_key)
        return (license_key, decoded_license_data)

    def addLicense(self, license_key):
        session = self.session()
        license_key, decoded_license_data = self.process_key(license_key)
        duplicate = session.query(License).filter(License.license_key == license_key).all()
        if duplicate:
            raise Exception('License already registered.')
        decoded_installation_id = decoded_license_data.get('installation_id')
        if not decoded_installation_id:
            raise Exception('Missing installation_id')
        installation_id = str(self.getInstallation().installation_id)
        if decoded_installation_id!= installation_id:
            raise Exception('License invalid for this installation')
        license_type = decoded_license_data.get('license_type')
        other_types = [x for x in session.query(License).all() if x.license_type!= license_type]
        if other_types:
            raise Exception('Error applying license type (%s). Only one license type may be registered at once.' % license_type)
        sku = decoded_license_data.get('sku')
        other_skus = [x for x in session.query(License).all() if x.sku!= sku]
        if other_skus:
            raise Exception('Error applying license sku (%s). Only one license sku may be registered at once.' % sku)
        license = License(license_key=license_key)
        try:
            session.add(license)
            session.commit()
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex
        return license

    def createInstallation(self, installation):
        session = self.session()
        try:
            session.add(installation)
            session.commit()
            return installation
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex

    def getManager(self, manager_id):
        session = self.session()
        try:
            return session.query(Manager).filter(Manager.manager_id == manager_id).one_or_none()
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex

    def getManagers(self, zone_name=None):
        session = self.session()
        try:
            q = session.query(Manager)
            if zone_name:
                q = q.join(Zone, Zone.zone_id == Manager.zone_id).filter(Zone.zone_name == zone_name)
            return q.all()
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex

    def createManager(self, manager_id, manager_version, manager_hostname, zone_id):
        session = self.session()
        manager = Manager(manager_id=manager_id, manager_version=manager_version, zone_id=zone_id, manager_hostname=manager_hostname, first_reported=datetime.datetime.utcnow(), last_reported=datetime.datetime.utcnow())
        try:
            session.add(manager)
            session.commit()
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex
        return manager

    def updateManager(self, manager):
        self._save()

    def deleteManager(self, manager):
        self._delete(manager)

    def setPrimaryManager(self, zone_id, manager_id):
        session = self.session()
        try:
            for zone in session.query(Zone).filter(Zone.primary_manager_id == manager_id).filter(Zone.zone_id!= zone_id).all():
                zone.primary_manager_id = None
                session.add(zone)
            zone = session.query(Zone).filter(Zone.zone_id == zone_id).one()
            zone.primary_manager_id = manager_id
            session.add(zone)
            session.commit()
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex
        return zone

    def getZone(self, zone_name):
        session = self.session()
        try:
            return session.query(Zone).filter(Zone.zone_name == zone_name).first()
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex

    def getZoneById(self, zone_id):
        session = self.session()
        try:
            return session.query(Zone).filter(Zone.zone_id == zone_id).first()
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex

    def getZones(self):
        session = self.session()
        try:
            q = session.query(Zone)
            return q.all()
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex

    def updateZone(self, zone=None, zone_name=None, allow_origin_domain=None, upstream_auth_address=None, proxy_connections=None, proxy_hostname=None, proxy_path=None, proxy_port=None, load_strategy=None, prioritize_static_agents=None, search_alternate_zones=None):
        attributes = ['zone_name', 'allow_origin_domain', 'upstream_auth_address', 'proxy_connections', 'proxy_hostname', 'proxy_path', 'proxy_port', 'load_strategy', 'prioritize_static_agents', 'search_alternate_zones']
        for x in attributes:
            val = locals()[x]
            if val is not None:
                if x in Zone._sanitize:
                    if not is_sanitized(val):
                        setattr(zone, x, val)
                else:  # inserted
                    setattr(zone, x, val)
        self._save()
        return zone

    def createZone(self, zone=None, zone_name=None, allow_origin_domain=None, upstream_auth_address=None, proxy_connections=None, proxy_hostname=None, proxy_path=None, proxy_port=None, load_strategy=None, prioritize_static_agents=None, search_alternate_zones=None):
        if zone is None:
            zone = Zone()
            zone.zone_name = zone_name
            zone.allow_origin_domain = allow_origin_domain
            zone.upstream_auth_address = upstream_auth_address
            zone.proxy_connections = proxy_connections
            zone.proxy_hostname = proxy_hostname
            zone.proxy_path = proxy_path
            zone.proxy_port = proxy_port
            zone.load_strategy = load_strategy
            zone.prioritize_static_agents = prioritize_static_agents
            zone.search_alternate_zones = search_alternate_zones
        session = self.session()
        try:
            session.add(zone)
            session.commit()
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex
        return zone

    def deleteZone(self, zone):
        self._delete(zone)

    def update_autoscale_last_provision(self, autoscale_config_id):
        session = self.session()
        try:
            session.query(AutoScaleConfig).filter(AutoScaleConfig.autoscale_config_id == autoscale_config_id).update({'last_provision': datetime.datetime.utcnow()})
            session.commit()
            return
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex

    def update_autoscale_request_downscale_at(self, autoscale_config_id, _datetime):
        session = self.session()
        try:
            session.query(AutoScaleConfig).filter(AutoScaleConfig.autoscale_config_id == autoscale_config_id).update({'request_downscale_at': _datetime})
            session.commit()
            return
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex

    def getGroupAccountsSummary(self, group_id, start_date, end_date, user_ids):
        session = self.session()
        try:
            act_s_date = case([(Accounting.start_date < start_date, start_date)], else_=Accounting.start_date)
            act_e_date = case([(Accounting.destroyed_date > end_date, end_date)], else_=Accounting.destroyed_date)
            old_kasms = session.query(func.extract('epoch', func.sum(act_e_date - act_s_date))).filter(Accounting.group_ids.op('?')(group_id.hex)).filter(Accounting.destroyed_date >= start_date).filter(Accounting.start_date <= end_date).scalar()
            kasm_s_date = case([(Kasm.start_date < start_date, start_date)], else_=Kasm.start_date)
            kasm_e_date = datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
            kasm_e_date = kasm_e_date if kasm_e_date < end_date else end_date
            live_kasms = session.query(func.extract('epoch', func.sum(kasm_e_date - kasm_s_date))).filter(Kasm.user_id.in_(user_ids)).scalar()
            if live_kasms is not None:
                live_kasms = live_kasms / 3600
            else:  # inserted
                live_kasms = 0
            if old_kasms is not None:
                old_kasms = old_kasms / 3600
            else:  # inserted
                old_kasms = 0
            return old_kasms + live_kasms
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex

    def getUserAccountSummary(self, user_id, start_date, end_date):
        session = self.session()
        try:
            act_s_date = case([(Accounting.start_date < start_date, start_date)], else_=Accounting.start_date)
            act_e_date = case([(Accounting.destroyed_date > end_date, end_date)], else_=Accounting.destroyed_date)
            old_kasms = session.query(func.extract('epoch', func.sum(act_e_date - act_s_date))).filter(Accounting.user_id == user_id).filter(Accounting.destroyed_date >= start_date).filter(Accounting.start_date <= end_date).scalar()
            kasm_s_date = case([(Kasm.start_date < start_date, start_date)], else_=Kasm.start_date)
            kasm_e_date = datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
            kasm_e_date = kasm_e_date if kasm_e_date < end_date else end_date
            live_kasms = session.query(func.extract('epoch', func.sum(kasm_e_date - kasm_s_date))).filter(Kasm.user_id == user_id).scalar()
            if live_kasms is not None:
                live_kasms = live_kasms / 3600
            else:  # inserted
                live_kasms = 0
            if old_kasms is not None:
                old_kasms = old_kasms / 3600
            else:  # inserted
                old_kasms = 0
            return old_kasms + live_kasms
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex

    def getuserAccountDump(self, user_id, start_date, end_date):
        session = self.session()
        try:
            return session.query(Accounting).filter(Accounting.user_id == user_id).filter(Accounting.destroyed_date >= start_date).filter(Accounting.start_date <= end_date).all()
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex

    def getAccounting(self, kasm_id):
        session = self.session()
        try:
            return session.query(Accounting).filter(Accounting.kasm_id == kasm_id).one_or_none()
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex

    def getAccountings(self, cast_config_id=None, user_ip=None, after=None, server_id=None, kasm_ids=None, page=None, page_size=None, filters=None, or_filters=None, sort_by='', sort_direction='desc'):
        if not filters:
            filters = []
        if not or_filters:
            or_filters = []
        session = self.session()
        try:
            q = session.query(Accounting)
            if cast_config_id:
                q = q.filter(Accounting.cast_config_id == cast_config_id)
            if user_ip:
                q = q.filter(Accounting.user_ip == user_ip)
            if after:
                q = q.filter(Accounting.start_date >= after)
            if server_id:
                q = q.filter(Accounting.server_id == server_id)
            if kasm_ids:
                q = q.filter(Accounting.kasm_id.in_(kasm_ids))
            for filter_ in filters:
                name = filter_['id']
                value = filter_['value']
                if not value:
                    continue
                if name == 'username' or name == 'user_name':
                    q = q.filter(func.lower(Accounting.user_name).contains(value.lower(), autoescape=True))
                else:  # inserted
                    if name == 'kasm_id':
                        q = q.filter(Accounting.kasm_id == value)
                    else:  # inserted
                        if name == 'image_friendly_name':
                            @q.filter
                            q = func.lower(Accounting.image_friendly_name).contains(value.lower(), autoescape=True)
                        else:  # inserted
                            if name == 'image_name':
                                q = q.filter(func.lower(Accounting.image_name).contains(value.lower(), autoescape=True))
                            else:  # inserted
                                if name == 'user_ip':
                                    q = q.filter(func.lower(Accounting.user_ip).contains(value.lower(), autoescape=True))
                                else:  # inserted
                                    if name == 'cast_config_id':
                                        q = q.filter(Accounting.cast_config_id == value)
                                    else:  # inserted
                                        if name == 'staging_config_id':
                                            q = q.filter(Accounting.staging_config_id == value)
                                        else:  # inserted
                                            if name == 'zone_name':
                                                q = q.filter(func.lower(Accounting.zone_name).contains(value.lower(), autoescape=True))
                                            else:  # inserted
                                                if name == 'created_date':
                                                    q = q.filter(Accounting.created_date.between(value['from'], value['to']))
                                                else:  # inserted
                                                    if name == 'destroyed_date':
                                                        q = q.filter(Accounting.destroyed_date.between(value['from'], value['to']))
            filter_array = []
            for filter_ in or_filters:
                name = filter_['id']
                value = filter_['value']
                if not value:
                    continue
                if name == 'image_friendly_name':
                    filter_array.append(func.lower(Accounting.image_friendly_name).contains(value.lower(), autoescape=True))
                else:  # inserted
                    if name == 'username' or name == 'user_name':
                        filter_array.append(func.lower(Accounting.user_name).contains(value.lower(), autoescape=True))
                    else:  # inserted
                        if name == 'kasm_id':
                            filter_array.append(Accounting.kasm_id == value)
                        else:  # inserted
                            if name == 'image_name':
                                filter_array.append(func.lower(Accounting.image_name).contains(value.lower(), autoescape=True))
                            else:  # inserted
                                if name == 'user_ip':
                                    filter_array.append(func.lower(Accounting.user_ip).contains(value.lower(), autoescape=True))
                                else:  # inserted
                                    if name == 'cast_config_id':
                                        filter_array.append(Accounting.cast_config_id == value)
                                    else:  # inserted
                                        if name == 'staging_config_id':
                                            filter_array.append(Accounting.staging_config_id == value)
                                        else:  # inserted
                                            if name == 'zone_name':
                                                filter_array.append(func.lower(Accounting.zone_name).contains(value.lower(), autoescape=True))
            if or_filters and filter_array:
                q = q.filter(or_(*filter_array))
            if getattr(Accounting, sort_by is not None):
                sort_by = sort_by
            else:  # inserted
                @''
            sort_column = sort_column.desc() if sort_column and (not sort_direction == 'desc') else ''
            else:  # inserted
                @sort_column.asc()
            q = sort_column(q.order_by(nullslast(sort_column)))
            q = q.offset(page * page_size).limit(page_size) if page is not None and page_size else None
            return q.all()
        except SQLAlchemyError as ex:
            session.rollback()
        else:  # inserted
            ex = None
        else:  # inserted
            pass
        return None

    def getAccountingsCount(self, filters=None, or_filters=None):
        if not filters:
            filters = []
        if not or_filters:
            or_filters = []
        session = self.session()
        try:
            q = session.query(Accounting)
            for filter_ in filters:
                name = filter_['id']
                value = filter_['value']
                if not value:
                    continue
                if name == 'username' or name == 'user_name':
                    q = q.filter(func.lower(Accounting.user_name).contains(value.lower(), autoescape=True))
                else:  # inserted
                    if name == 'kasm_id':
                        q = q.filter(Accounting.kasm_id == value)
                    else:  # inserted
                        if name == 'image_friendly_name':
                            q = q.filter(func.lower(Accounting.image_friendly_name).contains(value.lower(), autoescape=True))
                        else:  # inserted
                            if name == 'image_name':
                                q = q.filter(func.lower(Accounting.image_name).contains(value.lower(), autoescape=True))
                            else:  # inserted
                                if name == 'user_ip':
                                    q = q.filter(func.lower(Accounting.user_ip).contains(value.lower(), autoescape=True))
                                else:  # inserted
                                    if name == 'cast_config_id':
                                        q = q.filter(Accounting.cast_config_id == value)
                                    else:  # inserted
                                        if name == 'staging_config_id':
                                            q = q.filter(Accounting.staging_config_id == value)
                                        else:  # inserted
                                            if name == 'zone_name':
                                                q = q.filter(func.lower(Accounting.zone_name).contains(value.lower(), autoescape=True))
                                            else:  # inserted
                                                if name == 'created_date':
                                                    q = q.filter(Accounting.created_date.between(value['from'], value['to']))
                                                else:  # inserted
                                                    if name == 'destroyed_date':
                                                        q = q.filter(Accounting.destroyed_date.between(value['from'], value['to']))
            filter_array = []
            for filter_ in or_filters:
                name = filter_['id']
                value = filter_['value']
                if not value:
                    continue
                if name == 'image_friendly_name':
                    filter_array.append(func.lower(Accounting.image_friendly_name).contains(value.lower(), autoescape=True))
                else:  # inserted
                    if name == 'username' or name == 'user_name':
                        filter_array.append(func.lower(Accounting.user_name).contains(value.lower(), autoescape=True))
                    else:  # inserted
                        if name == 'kasm_id':
                            filter_array.append(Accounting.kasm_id == value)
                        else:  # inserted
                            if name == 'image_name':
                                filter_array.append(func.lower(Accounting.image_name).contains(value.lower(), autoescape=True))
                            else:  # inserted
                                if name == 'user_ip':
                                    filter_array.append(func.lower(Accounting.user_ip).contains(value.lower(), autoescape=True))
                                else:  # inserted
                                    if name == 'cast_config_id':
                                        filter_array.append(Accounting.cast_config_id == value)
                                    else:  # inserted
                                        filter_array.append(Accounting.staging_config_id == value) if name == 'staging_config_id' else filter_array.append(Accounting.staging_config_id == value)
                                    else:  # inserted
                                        filter_array.append(func.lower(Accounting.zone_name).contains(value.lower(), autoescape=True)) if name == 'zone_name' else filter_array.append(func.lower(Accounting.zone_name).contains(MetaData.lower(), autoescape=True))
                    continue
            if or_filters and filter_array and q.filter('ZoneInfo'):
                q = or_(filter_array)
            return q.count()
        except SQLAlchemyError as ex: session.rollback() as ex:
            pass  # postinserted
        else:  # inserted
            ex = None
            return None

    def createAccounting(self, kasm_id, user_id, user_name, image_id, image_name, image_src, image_friendly_name, start_date, created_date, destroyed_date, destroy_reason, group_ids, usage_hours, user_ip, cast_config_id, staging_config_id, zone_id, zone_name, server_id, server_hostname, docker_network, is_queued):
        account = Accounting(kasm_id=kasm_id, user_id=user_id, user_name=user_name, image_id=image_id, image_name=image_name, image_src=image_src, image_friendly_name=image_friendly_name, start_date=start_date, created_date=created_date, destroyed_date=destroyed_date, destroy_reason=destroy_reason, group_ids=group_ids, usage_hours=usage_hours, user_ip=user_ip, cast_config_id=cast_config_id, staging_config_id=staging_config_id, zone_id=zone_id, zone_name=zone_name, server_id=server_id, server_hostname=server_hostname, docker_network=docker_network, is_queued=is_queued)
        session = self.session()
        try:
            session.add(account)
            session.commit()
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex
        return account

    def updateAccounting(self, accounting, user_id=None, user_name=None, start_date=None, destroyed_date=None, destroy_reason=None, usage_hours=None, user_ip=None, cast_config_id=None, server_id=None, server_hostname=None, is_queued=None):
        attributes = ['user_id', 'user_name', 'start_date', 'destroyed_date', 'destroy_reason', 'usage_hours', 'user_ip', 'cast_config_id', 'server_id', 'server_hostname', 'is_queued']
        for x in attributes:
            val = locals()[x]
            if val!= None:
                setattr(accounting, x, val)
        self._save()
        return accounting

    def addSessionRecording(self, account_id: str, session_recording_url: str, session_recording_metadata: dict) -> SessionRecording:
        recording = SessionRecording(account_id=account_id, session_recording_url=session_recording_url, session_recording_metadata=session_recording_metadata)
        session = self.session()
        try:
            session.add(recording)
            session.commit()
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex
        return recording

    def getSessionRecording(self, recording_id: str=None, session_recording_url: str=None) -> SessionRecording:
        session = self.session()
        try:
            q = session.query(SessionRecording)
            if recording_id:
                q = q.filter(SessionRecording.recording_id == recording_id)
            if session_recording_url:
                q = q.filter(SessionRecording.session_recording_url == session_recording_url)
            return q.one_or_none()
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex

    def getSessionRecordings(self, account_id: str) -> typing.List[SessionRecording]:
        session = self.session()
        try:
            q = session.query(SessionRecording)
            if account_id:
                q = q.filter(SessionRecording.account_id == account_id)
            return q.all()
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex

    def updateSessionRecording(self, session_recording, session_recording_url=None, session_recording_metadata=None):
        attributes = ['session_recording_url', 'session_recording_metadata']
        for x in attributes:
            val = locals()[x]
            if val is not None:
                setattr(session_recording, x, val)
        self._save()
        return session_recording

    def createCart(self, plan_name, user_id, stripe_id=None, completed=None):
        cart = Cart(plan_name=plan_name, user_id=user_id, stripe_id=stripe_id, completed=completed)
        session = self.session()
        try:
            session.add(cart)
            session.commit()
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex
        return cart

    def updateCart(self, cart, plan_name=None, user_id=None, stripe_id=None, completed=None):
        attributes = ['plan_name', 'user_id', 'stripe_id', 'completed']
        for x in attributes:
            val = locals()[x]
            if val!= None:
                setattr(cart, x, val)
        self._save()
        return cart

    def getCart(self, cart_id):
        session = self.session()
        try:
            return session.query(Cart).filter(Cart.cart_id == cart_id).first()
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex

    def getReport(self, name):
        return Report.get_report(name)

    def execute_native_query(self, query):
        session = self.session()
        try:
            result = session.execute(text(query))
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex
        return result

    def clean_logs(self, log_retention_date, debug_retention_date):
        log_retention = self.get_config_setting_value('logging', 'log_retention')
        log_retention = int(log_retention) if log_retention is not None else 7
        debug_retention = self.get_config_setting_value('logging', 'debug_retention')
        debug_retention = int(debug_retention) if debug_retention is not None else 4
        self.execute_native_query(f'\n        DELETE FROM logs\n        WHERE\n            (\n                (select extract(epoch from max(ingest_date) - min(ingest_date))/3600 FROM logs)>((({log_retention}) * 24) + 1)\n                OR\n                (select extract(epoch from max(ingest_date) - min(ingest_date))/60 FROM logs WHERE levelname = \'DEBUG\')>(({debug_retention}) * 60 + 14)\n            )\n            AND\n        log_id IN\n        (\n        SELECT\n            log_id\n        FROM logs\n        WHERE\n            ingest_date < (SELECT now() - {log_retention} * INTERVAL \'1 DAY\') OR\n            (\n                ingest_date < (SELECT now() - {debug_retention} * INTERVAL \'1 HOUR\') AND\n                levelname = \'DEBUG\'\n            )\n        LIMIT 700000\n        FOR UPDATE SKIP LOCKED\n        );\n        ')

    def createLogs(self, logs):
        try:
            DataAccessPostgres.engine.execute(Log.__table__.insert(), *logs)
        except SQLAlchemyError as ex:
            raise ex

    def getApiConfigs(self):
        session = self.session()
        try:
            return session.query(Api).all()
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex

    def getApiConfig(self, api_id):
        session = self.session()
        try:
            return session.query(Api).filter(Api.api_id == api_id).first()
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex

    def getApiConfigByKey(self, api_key):
        session = self.session()
        try:
            return session.query(Api).filter(Api.api_key == api_key).first()
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex

    def getApiName(self, api_name):
        session = self.session()
        try:
            return session.query(Api).filter(Api.name == api_name).first()
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex

    def createApiConfig(self, name, api_key, api_key_secret, enabled=False, read_only=False, expires=None):
        session = self.session()
        salt = str(uuid.uuid4())
        _hash = hashlib.sha256((api_key_secret + salt).encode()).hexdigest()
        api = Api(name=name, api_key=api_key, salt=salt, api_key_secret_hash=_hash, enabled=enabled, read_only=read_only, created=datetime.datetime.utcnow(), expires=expires)
        try:
            session.add(api)
            session.commit()
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex
        return api

    def updateApiConfig(self, name=None, api_id=None, enabled=None, read_only=None, expires=None):
        session = self.session()
        try:
            if api_id:
                api = session.query(Api).filter(Api.api_id == api_id).first()
                if api:
                    if name:
                        api.name = name[:255]
                    if enabled:
                        api.enabled = True
                    else:  # inserted
                        if enabled == False:
                            api.enabled = False
                    if read_only:
                        api.read_only = True
                    else:  # inserted
                        if read_only == False:
                            api.read_only = False
                    api.expires = expires
                    session.commit()
                    return api
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex

    def deleteApiConfig(self, api_config):
        self._delete(api_config)

    def validateApiKey(self, api_key, api_key_secret, update_last_used=False):
        session = self.session()
        try:
            api = session.query(Api).filter(Api.api_key == api_key).first()
            if api and api.enabled:
                _hash = hashlib.sha256(api_key_secret.encode() + api.salt.encode()).hexdigest()
                if not _hash == api.api_key_secret_hash or update_last_used:
                    api.last_used = datetime.datetime.utcnow()
                    session.commit()
                    return api.expires is None or api.expires > datetime.datetime.now()
            return False
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex

    def getCompany(self, company_name=None, company_id=None):
        session = self.session()
        query = session.query(Company)
        if company_name:
            query = query.filter(Company.company_name == company_name)
        if company_id:
            query = query.filter(Company.company_id == company_id)
        try:
            return query.first()
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex

    def createCompany(self, company_name, street=None, city=None, zip=None, country=None):
        session = self.session()
        try:
            company = Company()
            company.company_name = company_name
            company.street = street
            company.city = city
            company.zip = zip
            company.country = country
            company.created = datetime.datetime.utcnow()
            session.add(company)
            session.commit()
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex
        return company

    def updateCompany(self, company, company_name=None, street=None, city=None, zip=None, country=None):
        attributes = ['company_name', 'street', 'city', 'zip', 'country']
        for x in attributes:
            val = locals()[x]
            if val!= None:
                setattr(company, x, val)
        self._save()
        return company

    def getCompanies(self):
        session = self.session()
        try:
            q = session.query(Company)
            return q.all()
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex

    def deleteCompany(self, company):
        self._delete(company)

    def get_effective_branding_config(self, hostname):
        hostname = hostname.strip().lower()
        session = self.session()
        try:
            res = session.query(BrandingConfig).filter(BrandingConfig.hostname == hostname).one_or_none()
            if not res:
                res = session.query(BrandingConfig).filter(BrandingConfig.is_default == True).one_or_none()
            return res
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex

    def get_internal_branding_config(self):
        branding = BrandingConfig.get_internal_branding_config()
        branding['launcher_background_url'] = self.get_config_setting_value('theme', 'launcher_background_url')
        return branding

    def get_branding_configs(self):
        session = self.session()
        try:
            return session.query(BrandingConfig).all()
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex

    def get_branding_config(self, branding_config_id):
        session = self.session()
        try:
            return session.query(BrandingConfig).filter(BrandingConfig.branding_config_id == branding_config_id).first()
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex

    def delete_branding_config(self, branding_config):
        self._delete(branding_config)

    def create_branding_config(self, name, favicon_logo_url, header_logo_url, html_title, login_caption, login_logo_url, loading_session_text, joining_session_text, destroying_session_text, is_default, hostname, login_splash_url, launcher_background_url):
        session = self.session()
        try:
            if is_default:
                for branding_config in session.query(BrandingConfig).all():
                    branding_config.is_default = False
                    session.add(branding_config)
            branding_config = BrandingConfig(name=name, favicon_logo_url=favicon_logo_url, header_logo_url=header_logo_url, html_title=html_title, login_caption=login_caption, login_logo_url=login_logo_url, login_splash_url=login_splash_url, loading_session_text=loading_session_text, joining_session_text=joining_session_text, destroying_session_text=destroying_session_text, is_default=is_default, hostname=hostname, launcher_background_url=launcher_background_url)
            session.add(branding_config)
            session.commit()
            return branding_config
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex

    def update_branding_config(self, branding_config=None, name=None, favicon_logo_url=None, header_logo_url=None, html_title=None, login_caption=None, login_logo_url=None, loading_session_text=None, joining_session_text=None, destroying_session_text=None, is_default=None, hostname=None, login_splash_url=None, launcher_background_url=None):
        attributes = ['name', 'favicon_logo_url', 'header_logo_url', 'html_title', 'login_caption', 'login_logo_url', 'loading_session_text', 'joining_session_text', 'destroying_session_text', 'is_default', 'hostname', 'login_splash_url', 'launcher_background_url']
        for x in attributes:
            val = locals()[x]
            if val!= None:
                setattr(branding_config, x, val)
        if is_default:
            session = self.session()
            try:
                for branding_config in session.query(BrandingConfig).filter(BrandingConfig.branding_config_id!= branding_config.branding_config_id).all():
                    branding_config.is_default = False
                    session.add(branding_config)
            except SQLAlchemyError as ex:
                session.rollback()
                raise ex
        self._save()
        return branding_config

    def hasFilterWithCategorization(self):
        session = self.session()
        try:
            if session.query(FilterPolicy).filter(FilterPolicy.enable_categorization == true()).first() is None:
                return False
            return True
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex

    def get_staging_config(self, staging_config_id):
        session = self.session()
        try:
            return session.query(StagingConfig).filter(StagingConfig.staging_config_id == staging_config_id).first()
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex

    def get_staging_configs(self, zone_id=None):
        session = self.session()
        try:
            q = session.query(StagingConfig)
            if zone_id:
                q = q.filter(StagingConfig.zone_id == zone_id)
            return q.all()
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex

    def create_staging_config(self, zone_id, server_pool_id, autoscale_config_id, image_id, num_sessions, expiration, allow_kasm_audio, allow_kasm_uploads, allow_kasm_downloads, allow_kasm_clipboard_down, allow_kasm_clipboard_up, allow_kasm_microphone, allow_kasm_gamepad, allow_kasm_webcam, allow_kasm_printing):
        session = self.session()
        try:
            staging_config = StagingConfig(zone_id=zone_id, server_pool_id=server_pool_id, autoscale_config_id=autoscale_config_id, image_id=image_id, num_sessions=num_sessions, expiration=expiration, allow_kasm_audio=allow_kasm_audio, allow_kasm_uploads=allow_kasm_uploads, allow_kasm_downloads=allow_kasm_downloads, allow_kasm_clipboard_down=allow_kasm_clipboard_down, allow_kasm_clipboard_up=allow_kasm_clipboard_up, allow_kasm_microphone=allow_kasm_microphone, allow_kasm_gamepad=allow_kasm_gamepad, allow_kasm_webcam=allow_kasm_webcam, allow_kasm_printing=allow_kasm_printing)
            session.add(staging_config)
            session.commit()
            return staging_config
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex

    def update_staging_config(self, staging_config, zone_id, server_pool_id, autoscale_config_id, image_id, num_sessions, expiration, allow_kasm_audio, allow_kasm_uploads, allow_kasm_downloads, allow_kasm_clipboard_down, allow_kasm_clipboard_up, allow_kasm_microphone, allow_kasm_gamepad, allow_kasm_webcam, allow_kasm_printing):
        attributes = ['zone_id', 'image_id', 'num_sessions', 'expiration', 'allow_kasm_audio', 'allow_kasm_uploads', 'allow_kasm_downloads', 'allow_kasm_clipboard_down', 'allow_kasm_clipboard_up', 'allow_kasm_microphone', 'allow_kasm_gamepad', 'allow_kasm_webcam', 'allow_kasm_printing']
        for x in attributes:
            val = locals()[x]
            if val!= None:
                setattr(staging_config, x, val)
        staging_config.server_pool_id = server_pool_id
        staging_config.autoscale_config_id = autoscale_config_id
        self._save()
        return staging_config

    def delete_staging_config(self, staging_config):
        self._delete(staging_config)

    def get_cast_config(self, cast_config_id=None, key=None, name=None):
        session = self.session()
        try:
            q = session.query(CastConfig)
            if cast_config_id:
                q = q.filter(CastConfig.cast_config_id == cast_config_id)
            if key:
                q = q.filter(CastConfig.key == key)
            if name:
                q = q.filter(CastConfig.casting_config_name == name)
            return q.one_or_none()
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex

    def get_cast_configs(self):
        session = self.session()
        try:
            return session.query(CastConfig).all()
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex

    def create_cast_config(self, image_id, allowed_referrers, limit_sessions, session_remaining, limit_ips, ip_request_limit, ip_request_seconds, error_url, enable_sharing, disable_control_panel, disable_tips, disable_fixed_res, key, allow_anonymous, group_id, require_recaptcha, kasm_url, dynamic_kasm_url, dynamic_docker_network, allow_resume, enforce_client_settings, allow_kasm_audio, allow_kasm_uploads, allow_kasm_downloads, allow_kasm_clipboard_down, allow_kasm_clipboard_up, allow_kasm_microphone, allow_kasm_sharing, kasm_audio_default_on, kasm_ime_mode_default_on, allow_kasm_gamepad, allow_kasm_webcam, allow_kasm_printing, valid_until, casting_config_name, remote_app_configs):
        if remote_app_configs is None:
            remote_app_configs = {}
        session = self.session()
        try:
            cast_config = CastConfig(image_id=image_id, allowed_referrers=allowed_referrers, limit_sessions=limit_sessions, session_remaining=session_remaining, limit_ips=limit_ips, ip_request_limit=ip_request_limit, ip_request_seconds=ip_request_seconds, error_url=error_url, enable_sharing=enable_sharing, disable_control_panel=disable_control_panel, disable_tips=disable_tips, disable_fixed_res=disable_fixed_res, key=key, allow_anonymous=allow_anonymous, group_id=group_id, require_recaptcha=require_recaptcha, kasm_url=kasm_url, dynamic_kasm_url=dynamic_kasm_url, dynamic_docker_network=dynamic_docker_network, allow_resume=allow_resume, enforce_client_settings=enforce_client_settings, allow_kasm_audio=allow_kasm_audio, allow_kasm_uploads=allow_kasm_uploads, allow_kasm_downloads=allow_kasm_downloads, allow_kasm_clipboard_down=allow_kasm_clipboard_down, allow_kasm_clipboard_up=allow_kasm_clipboard_up, allow_kasm_microphone=allow_kasm_microphone, allow_kasm_sharing=allow_kasm_sharing, kasm_audio_default_on=kasm_audio_default_on, kasm_ime_mode_default_on=kasm_ime_mode_default_on, allow_kasm_gamepad=allow_kasm_gamepad, allow_kasm_webcam=allow_kasm_webcam, allow_kasm_printing=allow_kasm_printing, valid_until=valid_until, casting_config_name=casting_config_name, remote_app_configs=remote_app_configs)
            cast_config.validate()
            session.add(cast_config)
            session.commit()
            return cast_config
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex

    def update_cast_config(self, cast_config=None, image_id=None, allowed_referrers=None, limit_sessions=None, session_remaining=None, limit_ips=None, ip_request_limit=None, ip_request_seconds=None, error_url=None, enable_sharing=None, disable_control_panel=None, disable_tips=None, disable_fixed_res=None, key=None, allow_anonymous=None, group_id=None, require_recaptcha=None, kasm_url=None, dynamic_kasm_url=None, dynamic_docker_network=None, allow_resume=None, enforce_client_settings=None, allow_kasm_audio=None, allow_kasm_uploads=None, allow_kasm_downloads=None, allow_kasm_clipboard_down=None, allow_kasm_clipboard_up=None, allow_kasm_microphone=None, allow_kasm_sharing=None, kasm_audio_default_on=None, kasm_ime_mode_default_on=None, allow_kasm_gamepad=None, allow_kasm_webcam=None, allow_kasm_printing=None, valid_until=None, casting_config_name=None, remote_app_configs=None):
        attributes = ['image_id', 'allowed_referrers', 'limit_sessions', 'session_remaining', 'limit_ips', 'ip_request_limit', 'ip_request_seconds', 'error_url', 'enable_sharing', 'disable_control_panel', 'disable_tips', 'disable_fixed_res', 'key', 'allow_anonymous', 'group_id', 'require_recaptcha', 'kasm_url', 'dynamic_kasm_url', 'dynamic_docker_network', 'allow_resume', 'enforce_client_settings', 'allow_kasm_audio', 'allow_kasm_uploads', 'allow_kasm_downloads', 'allow_kasm_clipboard_down', 'allow_kasm_clipboard_up', 'allow_kasm_microphone', 'allow_kasm_sharing', 'kasm_audio_default_on', 'kasm_ime_mode_default_on', 'allow_kasm_gamepad', 'allow_kasm_webcam', 'valid_until', 'allow_kasm_printing', 'casting_config_name', 'remote_app_configs']
        for x in attributes:
            val = locals()[x]
            if val!= None:
                setattr(cast_config, x, val)
        self._save()
        return cast_config

    def decrement_cast_session_limit(self, cast_config):
        session = self.session()
        try:
            session.query(CastConfig).filter(CastConfig.cast_config_id == cast_config.cast_config_id).update({'session_remaining': CastConfig.session_remaining - 1})
            session.commit()
            return
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex

    def delete_cast_config(self, cast_config):
        self._delete(cast_config)

    def create_file_map(self, name, description, content, destination, file_type='text', is_readable=True, is_writable=False, is_executable=False, user_id=None, group_id=None, image_id=None, kasm_id=None):
        session = self.session()
        try:
            file_map = FileMap(created=datetime.datetime.utcnow(), user_id=user_id, group_id=group_id, image_id=image_id, kasm_id=kasm_id, name=name, description=description, file_type=file_type, content=content, destination=destination, is_readable=is_readable, is_writable=is_writable, is_executable=is_executable)
            session.add(file_map)
            session.commit()
            return file_map
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex

    def get_file_map(self, file_map_id):
        session = self.session()
        try:
            q = session.query(FileMap)
            q = q.filter(FileMap.file_map_id == file_map_id)
            return q.one_or_none()
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex

    def get_file_mappings(self, group_id=None, image_id=None, user_id=None, kasm_id=None, name=None):
        session = self.session()
        try:
            q = session.query(FileMap)
            if group_id:
                q = q.filter(FileMap.group_id == group_id)
            if image_id:
                q = q.filter(FileMap.image_id == image_id)
            if user_id:
                q = q.filter(FileMap.user_id == user_id)
            if kasm_id:
                q = q.filter(FileMap.kasm_id == kasm_id)
            if name:
                q = q.filter(FileMap.name == name)
            return q.all()
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex

    def get_orphaned_file_mappings(self, created_before):
        session = self.session()
        try:
            q = session.query(FileMap).filter(FileMap.group_id == None).filter(FileMap.image_id == None).filter(FileMap.user_id == None).filter(FileMap.kasm_id == None).filter(FileMap.created <= created_before)
            return q.all()
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex

    def update_file_map(self, file_map, name=None, description=None, content=None, destination=None, file_type=None, is_readable=None, is_writable=None, is_executable=None, user_id=None, group_id=None, image_id=None, kasm_id=None):
        attributes = ['name', 'description', 'content', 'destination', 'file_type', 'is_readable', 'is_writable', 'is_executable', 'user_id', 'group_id', 'image_id', 'kasm_id']
        for x in attributes:
            val = locals()[x]
            if val is not None:
                setattr(file_map, x, val)
        self._save()
        return file_map

    def delete_file_map(self, file_map):
        self._delete(file_map)

    def get_session_permission(self, session_permission_id=None, kasm_id=None, user_id=None):
        session = self.session()
        try:
            q = session.query(SessionPermission)
            if session_permission_id:
                q = q.filter(SessionPermission.session_permission_id == session_permission_id)
            if kasm_id:
                q = q.filter(SessionPermission.kasm_id == kasm_id)
            if user_id:
                q = q.filter(SessionPermission.user_id == user_id)
            return q.one_or_none()
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex

    def get_session_permissions(self, session_permission_id=None, kasm_id=None, user_id=None):
        session = self.session()
        try:
            q = session.query(SessionPermission)
            if session_permission_id:
                q = q.filter(SessionPermission.session_permission_id == session_permission_id)
            if kasm_id:
                q = q.filter(SessionPermission.kasm_id == kasm_id)
            if user_id:
                q = q.filter(SessionPermission.user_id == user_id)
            return q.all()
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex

    def create_session_permission(self, kasm_id, user_id, access, vnc_username=None, vnc_password=None):
        session = self.session()
        try:
            session_permissions = SessionPermission(kasm_id=kasm_id, user_id=user_id, access=access, vnc_username=vnc_username if vnc_username else uuid.uuid4().hex[0:15], vnc_password=vnc_password if vnc_password else uuid.uuid4().hex)
            session.add(session_permissions)
            session.commit()
            return session_permissions
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex

    def update_session_permission(self, session_permission, access):
        session_permission.access = access
        self._save()
        return session_permission

    def delete_session_permissions(self, session_permissions):
        self._bulk_delete(session_permissions)

    def get_sso_attribute_mapping_fields(self):
        return SSOAttributeToUserFieldMapping.user_fields()

    def get_sso_attribute_mapping(self, sso_attribute_id):
        session = self.session()
        try:
            q = session.query(SSOAttributeToUserFieldMapping)
            q = q.filter(SSOAttributeToUserFieldMapping.sso_attribute_id == sso_attribute_id)
            return q.one_or_none()
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex

    def delete_sso_attribute_mapping(self, sso_attribute_mapping):
        self._delete(sso_attribute_mapping)

    def update_sso_attribute_mapping(self, sso_attribute_mapping, attribute_name=None, user_field=None):
        attributes = ['attribute_name', 'user_field']
        for x in attributes:
            val = locals()[x]
            if val is not None:
                setattr(sso_attribute_mapping, x, val)
        self._save()
        return sso_attribute_mapping

    def create_physical_tokens(self, tokens):
        session = self.session()
        try:
            for t in tokens:
                token = PhysicalToken(serial_number=t['serial_number'], seed_filename=t['seed_filename'], token_seed=t['token_seed'], created=datetime.datetime.utcnow())
                session.add(token)
            session.commit()
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex

    def create_sso_attribute_mapping(self, attribute_name, user_field, oidc_id=None, saml_id=None, ldap_id=None):
        session = self.session()
        try:
            sso_attribute_mapping = SSOAttributeToUserFieldMapping(attribute_name=attribute_name, user_field=user_field, oidc_id=oidc_id, saml_id=saml_id, ldap_id=ldap_id)
            session.add(sso_attribute_mapping)
            session.commit()
            return sso_attribute_mapping
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex

    def create_physical_token(self, serial_number, seed_filename, token_seed, token_id=None):
        session = self.session()
        try:
            token = PhysicalToken(serial_number=serial_number, seed_filename=seed_filename, token_seed=token_seed, created=datetime.datetime.utcnow(), token_id=token_id)
            session.add(token)
            session.commit()
            return token
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex

    def clear_user_physical_tokens(self, user):
        for token in user.tokens:
            token.user = None
        user.set_two_factor = False
        user.secret = None
        self._save()
        return user

    def unassign_physical_token(self, token):
        if token and token.user:
            token.user.set_two_factor = False
            token.user.secret = None
            token.user = None
        self._save()
        return token

    def assign_physical_token(self, token, user):
        if token.user and token.user == user:
            return token
        if token.user:
            self.unassign_physical_token(token)
        self.clear_user_physical_tokens(user)
        user.set_two_factor = True
        user.secret = token.token_seed
        token.user = user
        self._save()
        return token

    def get_physical_tokens(self):
        session = self.session()
        try:
            return session.query(PhysicalToken).all()
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex

    def get_physical_token(self, serial_number):
        session = self.session()
        try:
            return session.query(PhysicalToken).filter(PhysicalToken.serial_number == serial_number).one_or_none()
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex

    def delete_physical_tokens_by_file(self, seed_filename):
        session = self.session()
        deleted = 0
        try:
            tokens = session.query(PhysicalToken).filter(PhysicalToken.seed_filename == seed_filename).all()
            for token in tokens:
                self.unassign_physical_token(token)
            deleted = len(tokens)
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex
        self._bulk_delete(tokens)
        return deleted

    def delete_physical_token(self, token):
        self.unassign_physical_token(token)
        self._delete(token)

    def get_oidc_config(self, oidc_id):
        session = self.session()
        try:
            return session.query(OIDCConfig).filter(OIDCConfig.oidc_id == oidc_id).one_or_none()
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex

    def get_oidc_configs(self):
        session = self.session()
        try:
            return session.query(OIDCConfig).all()
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex

    def delete_oidc_config(self, oidc_config):
        self._delete(oidc_config)

    def create_oidc_config(self, auto_login, enabled, is_default, hostname, display_name, client_id, client_secret, auth_url, token_url, scope, redirect_url, user_info_url, logo_url, username_attribute, groups_attribute, debug, oidc_id=None):
        session = self.session()
        try:
            oidc_config = OIDCConfig(oidc_id=oidc_id, auto_login=auto_login, enabled=enabled, is_default=is_default, hostname=hostname, display_name=display_name, client_id=client_id, client_secret=client_secret, auth_url=auth_url, token_url=token_url, scope=scope, redirect_url=redirect_url, user_info_url=user_info_url, logo_url=logo_url, username_attribute=username_attribute, groups_attribute=groups_attribute, debug=debug)
            session.add(oidc_config)
            session.commit()
            return oidc_config
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex

    def update_oidc_config(self, oidc_config=None, auto_login=None, enabled=None, is_default=None, hostname=None, display_name=None, client_id=None, client_secret=None, auth_url=None, token_url=None, scope=None, redirect_url=None, user_info_url=None, logo_url=None, username_attribute=None, groups_attribute=None, debug=None):
        attributes = ['auto_login', 'enabled', 'is_default', 'hostname', 'display_name', 'client_id', 'client_secret', 'auth_url', 'token_url', 'scope', 'redirect_url', 'user_info_url', 'logo_url', 'username_attribute', 'groups_attribute', 'debug']
        for x in attributes:
            val = locals()[x]
            if val!= None:
                if not (x in OIDCConfig._sanitize and is_sanitized(val)):
                    setattr(oidc_config, x, val)
                else:  # inserted
                    setattr(oidc_config, x, val)
        self._save()
        return oidc_config

    def get_connection_proxies(self, zone_id=None, connection_proxy_type=None):
        session = self.session()
        try:
            q = session.query(ConnectionProxy)
            if zone_id:
                q = q.filter(ConnectionProxy.zone_id == zone_id)
            if connection_proxy_type:
                q = q.filter(ConnectionProxy.connection_proxy_type == connection_proxy_type)
            return q.all()
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex

    def get_connection_proxy(self, connection_proxy_id):
        session = self.session()
        try:
            return session.query(ConnectionProxy).filter(ConnectionProxy.connection_proxy_id == connection_proxy_id).one_or_none()
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex

    def create_connection_proxy(self, server_address, server_port, connection_proxy_type, auth_token, zone_id, connection_proxy_id=None):
        session = self.session()
        try:
            connection_proxy = ConnectionProxy(connection_proxy_id=connection_proxy_id, server_address=server_address, server_port=server_port, connection_proxy_type=connection_proxy_type, auth_token=auth_token, zone_id=zone_id)
            session.add(connection_proxy)
            session.commit()
            return connection_proxy
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex

    def update_connection_proxy(self, connection_proxy, server_address=None, server_port=None, connection_proxy_type=None, auth_token=None, zone_id=None):
        attributes = ['server_address', 'server_port', 'connection_proxy_type', 'auth_token', 'zone_id']
        for x in attributes:
            val = locals()[x]
            if val!= None:
                if not (x in ConnectionProxy._sanitize and is_sanitized(val)):
                    setattr(connection_proxy, x, val)
                else:  # inserted
                    setattr(connection_proxy, x, val)
        self._save()
        return connection_proxy

    def delete_connection_proxy(self, connection_proxy):
        self._delete(connection_proxy)

    def get_server_pools(self):
        session = self.session()
        try:
            return session.query(ServerPool).all()
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex

    def get_server_pool(self, server_pool_id):
        session = self.session()
        try:
            return session.query(ServerPool).filter(ServerPool.server_pool_id == server_pool_id).one_or_none()
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex

    def delete_server_pool(self, server_pool):
        self._delete(server_pool)

    def create_server_pool(self, server_pool_name, server_pool_type, server_pool_id=None):
        session = self.session()
        try:
            server_pool = ServerPool(server_pool_id=server_pool_id, server_pool_name=server_pool_name, server_pool_type=server_pool_type)
            session.add(server_pool)
            session.commit()
            return server_pool
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex

    def update_server_pool(self, server_pool, server_pool_name=None, server_pool_type=None):
        attributes = ['server_pool_name', 'server_pool_type']
        for x in attributes:
            val = locals()[x]
            if val!= None:
                if not (x in ServerPool._sanitize and is_sanitized(val)):
                    setattr(server_pool, x, val)
                else:  # inserted
                    setattr(server_pool, x, val)
        self._save()
        return server_pool

    def create_azure_config(self, config_name, max_instances, azure_subscription_id, azure_resource_group, azure_tenant_id, azure_client_id, azure_client_secret, azure_region, azure_vm_size, azure_os_disk_type, azure_image_reference, azure_network_sg, azure_subnet, azure_os_disk_size_gb, azure_tags, azure_os_username, azure_os_password, azure_ssh_public_key, startup_script, azure_config_override, azure_public_ip, azure_authority, azure_is_windows, azure_config_id=None):
        session = self.session()
        try:
            azure_config = AzureVMConfig(azure_config_id=azure_config_id, config_name=config_name, max_instances=max_instances, azure_subscription_id=azure_subscription_id, azure_resource_group=azure_resource_group, azure_tenant_id=azure_tenant_id, azure_client_id=azure_client_id, azure_client_secret=azure_client_secret, azure_region=azure_region, azure_vm_size=azure_vm_size, azure_os_disk_type=azure_os_disk_type, azure_image_reference=azure_image_reference, azure_network_sg=azure_network_sg, azure_subnet=azure_subnet, azure_os_disk_size_gb=azure_os_disk_size_gb, azure_tags=azure_tags, azure_os_username=azure_os_username, azure_os_password=azure_os_password, azure_ssh_public_key=azure_ssh_public_key, startup_script=startup_script, azure_config_override=azure_config_override, azure_public_ip=azure_public_ip, azure_authority=azure_authority, azure_is_windows=azure_is_windows)
            session.add(azure_config)
            session.commit()
            return azure_config
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex

    def update_azure_config(self, azure_vm_config=None, config_name=None, max_instances=None, azure_subscription_id=None, azure_resource_group=None, azure_tenant_id=None, azure_client_id=None, azure_client_secret=None, azure_region=None, azure_vm_size=None, azure_os_disk_type=None, azure_image_reference=None, azure_network_sg=None, azure_subnet=None, azure_os_disk_size_gb=None, azure_tags=None, azure_os_username=None, azure_os_password=None, azure_ssh_public_key=None, startup_script=None, azure_config_override=None, azure_public_ip=None, azure_authority=None, azure_is_windows=None):
        attributes = ['config_name', 'max_instances', 'azure_subscription_id', 'azure_resource_group', 'azure_tenant_id', 'azure_client_id', 'azure_client_secret', 'azure_region', 'azure_vm_size', 'azure_os_disk_type', 'azure_image_reference', 'azure_network_sg', 'azure_subnet', 'azure_os_disk_size_gb', 'azure_os_disk_size_gb', 'azure_tags', 'azure_os_username', 'azure_os_password', 'azure_ssh_public_key', 'startup_script', 'azure_config_override', 'azure_public_ip', 'azure_authority', 'azure_is_windows']
        for x in attributes:
            val = locals()[x]
            if val!= None:
                if not (x in AzureVMConfig._sanitize and is_sanitized(val)):
                    setattr(azure_vm_config, x, val)
                else:  # inserted
                    setattr(azure_vm_config, x, val)
        self._save()
        return azure_vm_config

    def create_aws_vm_config(self, config_name, max_instances, aws_ec2_instance_type, aws_region, aws_access_key_id, aws_secret_access_key, aws_ec2_ami_id, aws_ec2_public_key, aws_ec2_private_key, aws_ec2_security_group_ids, aws_ec2_subnet_id, startup_script, aws_ec2_iam, aws_ec2_ebs_volume_type, aws_ec2_ebs_volume_size_gb, aws_ec2_custom_tags, retrieve_password, aws_ec2_config_override, aws_config_id=None):
        session = self.session()
        try:
            aws_vm_config = AwsVMConfig(aws_config_id=aws_config_id, config_name=config_name, max_instances=max_instances, aws_ec2_instance_type=aws_ec2_instance_type, aws_region=aws_region, aws_access_key_id=aws_access_key_id, aws_secret_access_key=aws_secret_access_key, aws_ec2_ami_id=aws_ec2_ami_id, aws_ec2_public_key=aws_ec2_public_key, aws_ec2_private_key=aws_ec2_private_key, aws_ec2_security_group_ids=aws_ec2_security_group_ids, aws_ec2_subnet_id=aws_ec2_subnet_id, startup_script=startup_script, aws_ec2_iam=aws_ec2_iam, aws_ec2_ebs_volume_type=aws_ec2_ebs_volume_type, aws_ec2_ebs_volume_size_gb=aws_ec2_ebs_volume_size_gb, aws_ec2_custom_tags=aws_ec2_custom_tags, retrieve_password=retrieve_password, aws_ec2_config_override=aws_ec2_config_override)
            session.add(aws_vm_config)
            session.commit()
            return aws_vm_config
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex

    def update_aws_vm_config(self, aws_vm_config=None, config_name=None, max_instances=None, aws_ec2_instance_type=None, aws_region=None, aws_access_key_id=None, aws_secret_access_key=None, aws_ec2_ami_id=None, aws_ec2_public_key=None, aws_ec2_private_key=None, aws_ec2_security_group_ids=None, aws_ec2_subnet_id=None, startup_script=None, aws_ec2_iam=None, aws_ec2_ebs_volume_type=None, aws_ec2_ebs_volume_size_gb=None, aws_ec2_custom_tags=None, retrieve_password=None, aws_ec2_config_override=None):
        attributes = ['config_name', 'max_instances', 'aws_ec2_instance_type', 'aws_region', 'aws_access_key_id', 'aws_secret_access_key', 'aws_ec2_ami_id', 'aws_ec2_instance_type', 'aws_ec2_public_key', 'aws_ec2_private_key', 'aws_ec2_security_group_ids', 'aws_ec2_subnet_id', 'startup_script', 'aws_ec2_iam', 'aws_ec2_ebs_volume_type', 'aws_ec2_ebs_volume_size_gb', 'aws_ec2_custom_tags', 'retrieve_password', 'aws_ec2_config_override']
        for x in attributes:
            val = locals()[x]
            if val is not None:
                if not (x in AwsVMConfig._sanitize and is_sanitized(val)):
                    setattr(aws_vm_config, x, val)
                else:  # inserted
                    setattr(aws_vm_config, x, val)
        self._save()
        return aws_vm_config

    def create_digital_ocean_vm_config(self, config_name, max_instances, digital_ocean_token, region, digital_ocean_droplet_image, digital_ocean_droplet_size, digital_ocean_tags, digital_ocean_sshkey_name, digital_ocean_firewall_name, startup_script, config_id=None):
        session = self.session()
        try:
            digital_ocean_vm_config = DigitalOceanVMConfig(config_id=config_id, config_name=config_name, max_instances=max_instances, digital_ocean_token=digital_ocean_token, region=region, digital_ocean_droplet_image=digital_ocean_droplet_image, digital_ocean_droplet_size=digital_ocean_droplet_size, digital_ocean_tags=digital_ocean_tags, digital_ocean_sshkey_name=digital_ocean_sshkey_name, digital_ocean_firewall_name=digital_ocean_firewall_name, startup_script=startup_script)
            session.add(digital_ocean_vm_config)
            session.commit()
            return digital_ocean_vm_config
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex

    def update_digital_ocean_vm_config(self, digital_ocean_vm_config, config_name=None, max_instances=None, digital_ocean_token=None, region=None, digital_ocean_droplet_image=None, digital_ocean_droplet_size=None, digital_ocean_tags=None, digital_ocean_sshkey_name=None, digital_ocean_firewall_name=None, startup_script=None):
        attributes = ['config_name', 'max_instances', 'digital_ocean_token', 'region', 'digital_ocean_droplet_image', 'digital_ocean_droplet_size', 'digital_ocean_tags', 'digital_ocean_sshkey_name', 'digital_ocean_firewall_name', 'startup_script']
        for x in attributes:
            val = locals()[x]
            if val is not None:
                if not (x in DigitalOceanVMConfig._sanitize and is_sanitized(val)):
                    setattr(digital_ocean_vm_config, x, val)
                else:  # inserted
                    setattr(digital_ocean_vm_config, x, val)
        self._save()
        return digital_ocean_vm_config

    def create_oci_vm_config(self, config_name, max_instances, oci_fingerprint, oci_tenancy_ocid, oci_region, oci_compartment_ocid, oci_availability_domains, oci_shape, oci_image_ocid, oci_subnet_ocid, oci_ssh_public_key, startup_script, oci_user_ocid, oci_private_key, oci_flex_cpus, oci_flex_memory_gb, oci_boot_volume_gb, oci_custom_tags, oci_config_override, oci_baseline_ocpu_utilization, oci_storage_vpus_per_gb, oci_nsg_ocids, config_id=None):
        session = self.session()
        try:
            oci_vm_config = OracleVMConfig(config_id=config_id, config_name=config_name, max_instances=max_instances, oci_fingerprint=oci_fingerprint, oci_tenancy_ocid=oci_tenancy_ocid, oci_region=oci_region, oci_compartment_ocid=oci_compartment_ocid, oci_availability_domains=oci_availability_domains, oci_shape=oci_shape, oci_image_ocid=oci_image_ocid, oci_subnet_ocid=oci_subnet_ocid, oci_ssh_public_key=oci_ssh_public_key, startup_script=startup_script, oci_user_ocid=oci_user_ocid, oci_private_key=oci_private_key, oci_flex_cpus=oci_flex_cpus, oci_flex_memory_gb=oci_flex_memory_gb, oci_boot_volume_gb=oci_boot_volume_gb, oci_custom_tags=oci_custom_tags, oci_config_override=oci_config_override, oci_baseline_ocpu_utilization=oci_baseline_ocpu_utilization, oci_storage_vpus_per_gb=oci_storage_vpus_per_gb, oci_nsg_ocids=oci_nsg_ocids)
            session.add(oci_vm_config)
            session.commit()
            return oci_vm_config
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex

    def update_oci_vm_config(self, oci_vm_config=None, config_name=None, max_instances=None, oci_fingerprint=None, oci_tenancy_ocid=None, oci_region=None, oci_compartment_ocid=None, oci_availability_domains=None, oci_shape=None, oci_image_ocid=None, oci_subnet_ocid=None, oci_ssh_public_key=None, startup_script=None, oci_user_ocid=None, oci_private_key=None, oci_flex_cpus=None, oci_flex_memory_gb=None, oci_boot_volume_gb=None, oci_custom_tags=None, oci_config_override=None, oci_baseline_ocpu_utilization=None, oci_storage_vpus_per_gb=None, oci_nsg_ocids=None):
        attributes = ['config_name', 'max_instances', 'oci_fingerprint', 'oci_tenancy_ocid', 'oci_region', 'oci_compartment_ocid', 'oci_availability_domains', 'oci_shape', 'oci_image_ocid', 'oci_subnet_ocid', 'oci_ssh_public_key', 'startup_script', 'oci_user_ocid', 'oci_private_key', 'oci_flex_cpus', 'oci_flex_memory_gb', 'oci_boot_volume_gb', 'oci_custom_tags', 'oci_config_override', 'oci_baseline_ocpu_utilization', 'oci_storage_vpus_per_gb', 'oci_nsg_ocids']
        for x in attributes:
            val = locals()[x]
            if val is not None:
                if not (x in OracleVMConfig._sanitize and is_sanitized(val)):
                    setattr(oci_vm_config, x, val)
                else:  # inserted
                    setattr(oci_vm_config, x, val)
        self._save()
        return oci_vm_config

    def create_gcp_vm_config(self, config_name, max_instances, gcp_project, gcp_region, gcp_zone, gcp_machine_type, gcp_image, startup_script, gcp_boot_volume_gb, gcp_cmek, gcp_disk_type, gcp_network, gcp_subnetwork, gcp_public_ip, gcp_network_tags, gcp_custom_labels, gcp_credentials, gcp_metadata, gcp_service_account, gcp_guest_accelerators, gcp_config_override, config_id=None):
        session = self.session()
        try:
            gcp_vm_config = GcpVMConfig(config_id=config_id, config_name=config_name, max_instances=max_instances, gcp_project=gcp_project, gcp_region=gcp_region, gcp_zone=gcp_zone, gcp_machine_type=gcp_machine_type, gcp_image=gcp_image, startup_script=startup_script, gcp_boot_volume_gb=gcp_boot_volume_gb, gcp_cmek=gcp_cmek, gcp_disk_type=gcp_disk_type, gcp_network=gcp_network, gcp_subnetwork=gcp_subnetwork, gcp_public_ip=gcp_public_ip, gcp_network_tags=gcp_network_tags, gcp_custom_labels=gcp_custom_labels, gcp_credentials=gcp_credentials, gcp_metadata=gcp_metadata, gcp_service_account=gcp_service_account, gcp_guest_accelerators=gcp_guest_accelerators, gcp_config_override=gcp_config_override)
            session.add(gcp_vm_config)
            session.commit()
            return gcp_vm_config
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex

    def update_gcp_vm_config(self, gcp_vm_config=None, config_name=None, max_instances=None, gcp_project=None, gcp_region=None, gcp_zone=None, gcp_machine_type=None, gcp_image=None, startup_script=None, gcp_boot_volume_gb=None, gcp_cmek=None, gcp_disk_type=None, gcp_network=None, gcp_subnetwork=None, gcp_public_ip=None, gcp_network_tags=None, gcp_custom_labels=None, gcp_credentials=None, gcp_metadata=None, gcp_service_account=None, gcp_guest_accelerators=None, gcp_config_override=None):
        attributes = ['config_name', 'max_instances', 'gcp_project', 'gcp_region', 'gcp_zone', 'gcp_machine_type', 'gcp_image', 'startup_script', 'gcp_boot_volume_gb', 'gcp_cmek', 'gcp_disk_type', 'gcp_network', 'gcp_subnetwork', 'gcp_public_ip', 'gcp_network_tags', 'gcp_custom_labels', 'gcp_credentials', 'gcp_metadata', 'gcp_service_account', 'gcp_guest_accelerators', 'gcp_config_override']
        for x in attributes:
            val = locals()[x]
            if val is not None:
                if not (x in GcpVMConfig._sanitize and is_sanitized(val)):
                    setattr(gcp_vm_config, x, val)
                else:  # inserted
                    setattr(gcp_vm_config, x, val)
        self._save()
        return gcp_vm_config

    def create_vsphere_vm_config(self, config_name, max_instances, vsphere_vcenter_address, vsphere_vcenter_port, vsphere_vcenter_username, vsphere_vcenter_password, vsphere_template_name, vsphere_datacenter_name, vsphere_vm_folder, vsphere_datastore, vsphere_cluster_name, vsphere_resource_pool, vsphere_datastore_cluster_name, startup_script, vsphere_os_username, vsphere_os_password, vsphere_cpus, vsphere_memoryMB, vsphere_installed_OS_type, config_id=None):
        session = self.session()
        try:
            vsphere_vm_config = VsphereVMConfig(config_id=config_id, config_name=config_name, max_instances=max_instances, vsphere_vcenter_address=vsphere_vcenter_address, vsphere_vcenter_port=vsphere_vcenter_port, vsphere_vcenter_username=vsphere_vcenter_username, vsphere_vcenter_password=vsphere_vcenter_password, vsphere_template_name=vsphere_template_name, vsphere_datacenter_name=vsphere_datacenter_name, vsphere_vm_folder=vsphere_vm_folder, vsphere_datastore=vsphere_datastore, vsphere_cluster_name=vsphere_cluster_name, vsphere_resource_pool=vsphere_resource_pool, vsphere_datastore_cluster_name=vsphere_datastore_cluster_name, startup_script=startup_script, vsphere_os_username=vsphere_os_username, vsphere_os_password=vsphere_os_password, vsphere_cpus=vsphere_cpus, vsphere_memoryMB=vsphere_memoryMB, vsphere_installed_OS_type=vsphere_installed_OS_type)
            session.add(vsphere_vm_config)
            session.commit()
            return vsphere_vm_config
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex

    def update_vsphere_vm_config(self, vsphere_vm_config=None, config_name=None, max_instances=None, vsphere_vcenter_address=None, vsphere_vcenter_port=None, vsphere_vcenter_username=None, vsphere_vcenter_password=None, vsphere_template_name=None, vsphere_datacenter_name=None, vsphere_vm_folder=None, vsphere_datastore=None, vsphere_cluster_name=None, vsphere_resource_pool=None, vsphere_datastore_cluster_name=None, startup_script=None, vsphere_os_username=None, vsphere_os_password=None, vsphere_cpus=None, vsphere_memoryMB=None, vsphere_installed_OS_type=None):
        attributes = ['config_name', 'max_instances', 'vsphere_vcenter_address', 'vsphere_vcenter_port', 'vsphere_vcenter_username', 'vsphere_vcenter_password', 'vsphere_template_name', 'vsphere_datacenter_name', 'vsphere_vm_folder', 'vsphere_datastore', 'vsphere_cluster_name', 'vsphere_resource_pool', 'vsphere_datastore_cluster_name', 'startup_script', 'vsphere_os_username', 'vsphere_os_password', 'vsphere_cpus', 'vsphere_memoryMB', 'vsphere_installed_OS_type']
        for x in attributes:
            val = locals()[x]
            if val is not None:
                if not (x in VsphereVMConfig._sanitize and is_sanitized(val)):
                    setattr(vsphere_vm_config, x, val)
                else:  # inserted
                    setattr(vsphere_vm_config, x, val)
        self._save()
        return vsphere_vm_config

    def create_openstack_vm_config(self, config_name, max_instances, openstack_keystone_endpoint, openstack_nova_endpoint, openstack_nova_version, openstack_glance_endpoint, openstack_glance_version, openstack_cinder_endpoint, openstack_cinder_version, openstack_project_name, openstack_project_domain_name, openstack_auth_method, openstack_user_domain_name, openstack_username, openstack_password, openstack_application_credential_id, openstack_application_credential_secret, openstack_metadata, openstack_image_id, openstack_flavor, openstack_create_volume, openstack_volume_size_gb, openstack_volume_type, startup_script, openstack_security_groups, openstack_network_id, openstack_key_name, openstack_availability_zone, openstack_config_override, config_id=None):
        session = self.session()
        try:
            openstack_vm_config = OpenStackVMConfig(config_id=config_id, config_name=config_name, max_instances=max_instances, openstack_keystone_endpoint=openstack_keystone_endpoint, openstack_nova_endpoint=openstack_nova_endpoint, openstack_nova_version=openstack_nova_version, openstack_glance_endpoint=openstack_glance_endpoint, openstack_glance_version=openstack_glance_version, openstack_cinder_endpoint=openstack_cinder_endpoint, openstack_cinder_version=openstack_cinder_version, openstack_project_name=openstack_project_name, openstack_project_domain_name=openstack_project_domain_name, openstack_user_domain_name=openstack_user_domain_name, openstack_auth_method=openstack_auth_method, openstack_username=openstack_username, openstack_password=openstack_password, openstack_application_credential_id=openstack_application_credential_id, openstack_application_credential_secret=openstack_application_credential_secret, openstack_image_id=openstack_image_id, openstack_metadata=openstack_metadata, openstack_flavor=openstack_flavor, openstack_create_volume=openstack_create_volume, openstack_volume_size_gb=openstack_volume_size_gb, openstack_volume_type=openstack_volume_type, openstack_security_groups=openstack_security_groups, startup_script=startup_script, openstack_network_id=openstack_network_id, openstack_key_name=openstack_key_name, openstack_availability_zone=openstack_availability_zone, openstack_config_override=openstack_config_override)
            session.add(openstack_vm_config)
            session.commit()
            return openstack_vm_config
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex

    def update_openstack_vm_config(self, openstack_vm_config=None, config_name=None, max_instances=None, openstack_keystone_endpoint=None, openstack_nova_endpoint=None, openstack_nova_version=None, openstack_glance_endpoint=None, openstack_glance_version=None, openstack_cinder_endpoint=None, openstack_cinder_version=None, openstack_project_name=None, openstack_project_domain_name=None, openstack_user_domain_name=None, openstack_auth_method=None, openstack_username=None, openstack_password=None, openstack_application_credential_id=None, openstack_application_credential_secret=None, openstack_image_id=None, openstack_metadata=None, openstack_flavor=None, openstack_create_volume=None, openstack_volume_size_gb=None, openstack_volume_type=None, openstack_security_groups=None, startup_script=None, openstack_network_id=None, openstack_key_name=None, openstack_availability_zone=None, openstack_config_override=None):
        attributes = ['config_name', 'max_instances', 'openstack_keystone_endpoint', 'openstack_nova_endpoint', 'openstack_nova_version', 'openstack_glance_endpoint', 'openstack_glance_version', 'openstack_cinder_endpoint', 'openstack_cinder_version', 'openstack_project_name', 'openstack_project_domain_name', 'openstack_user_domain_name', 'openstack_auth_method', 'openstack_username', 'openstack_password', 'openstack_application_credential_id', 'openstack_application_credential_secret', 'openstack_image_id', 'openstack_metadata', 'openstack_flavor', 'openstack_create_volume', 'openstack_volume_size_gb', 'openstack_volume_type', 'openstack_security_groups', 'startup_script', 'openstack_network_id', 'openstack_key_name', 'openstack_availability_zone', 'openstack_config_override']
        for x in attributes:
            val = locals()[x]
            if val is not None:
                if not (x in OpenStackVMConfig._sanitize and is_sanitized(val)):
                    setattr(openstack_vm_config, x, val)
                else:  # inserted
                    setattr(openstack_vm_config, x, val)
        self._save()
        return openstack_vm_config

    def get_vm_provider_configs(self, azure=True, aws=True, digital_ocean=True, oci=True, gcp=True, vsphere=True, openstack=True):
        session = self.session()
        ret = []
        try:
            if azure:
                ret += session.query(AzureVMConfig).all()
            if aws:
                ret += session.query(AwsVMConfig).all()
            if digital_ocean:
                ret += session.query(DigitalOceanVMConfig).all()
            if oci:
                ret += session.query(OracleVMConfig).all()
            if gcp:
                ret += session.query(GcpVMConfig).all()
            if vsphere:
                ret += session.query(VsphereVMConfig).all()
            if openstack:
                ret += session.query(OpenStackVMConfig).all()
            return ret
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex

    def get_vm_provider_config(self, vm_provider_config_id, provider_name):
        session = self.session()
        ret = None
        try:
            if provider_name == 'azure':
                ret = session.query(AzureVMConfig).filter(AzureVMConfig.azure_config_id == vm_provider_config_id).one_or_none()
            else:  # inserted
                if provider_name == 'aws':
                    ret = session.query(AwsVMConfig).filter(AwsVMConfig.aws_config_id == vm_provider_config_id).one_or_none()
                else:  # inserted
                    if provider_name == 'digital_ocean':
                        ret = session.query(DigitalOceanVMConfig).filter(DigitalOceanVMConfig.config_id == vm_provider_config_id).one_or_none()
                    else:  # inserted
                        if provider_name == 'oci':
                            ret = session.query(OracleVMConfig).filter(OracleVMConfig.config_id == vm_provider_config_id).one_or_none()
                        else:  # inserted
                            if provider_name == 'gcp':
                                ret = session.query(GcpVMConfig).filter(GcpVMConfig.config_id == vm_provider_config_id).one_or_none()
                            else:  # inserted
                                if provider_name == 'vsphere':
                                    ret = session.query(VsphereVMConfig).filter(VsphereVMConfig.config_id == vm_provider_config_id).one_or_none()
                                else:  # inserted
                                    if provider_name == 'openstack':
                                        ret = session.query(OpenStackVMConfig).filter(OpenStackVMConfig.config_id == vm_provider_config_id).one_or_none()
                                    else:  # inserted
                                        raise NotImplementedError('Provider %s not recognized' % provider_name)
            return ret
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex

    def get_azure_vm_configs(self):
        session = self.session()
        try:
            return session.query(AzureVMConfig).all()
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex

    def get_azure_vm_config(self, azure_config_id):
        session = self.session()
        try:
            return session.query(AzureVMConfig).filter(AzureVMConfig.azure_config_id == azure_config_id).one_or_none()
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex

    def get_aws_vm_configs(self):
        session = self.session()
        try:
            return session.query(AwsVMConfig).all()
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex

    def get_aws_vm_config(self, aws_config_id):
        session = self.session()
        try:
            return session.query(AwsVMConfig).filter(AwsVMConfig.aws_config_id == aws_config_id).one_or_none()
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex

    def get_digital_ocean_vm_configs(self):
        session = self.session()
        try:
            return session.query(DigitalOceanVMConfig).all()
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex

    def get_digital_ocean_vm_config(self, config_id):
        session = self.session()
        try:
            return session.query(DigitalOceanVMConfig).filter(DigitalOceanVMConfig.config_id == config_id).one_or_none()
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex

    def get_oci_vm_configs(self):
        session = self.session()
        try:
            return session.query(OracleVMConfig).all()
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex

    def get_oci_vm_config(self, config_id):
        session = self.session()
        try:
            return session.query(OracleVMConfig).filter(OracleVMConfig.config_id == config_id).one_or_none()
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex

    def get_gcp_vm_configs(self):
        session = self.session()
        try:
            return session.query(GcpVMConfig).all()
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex

    def get_gcp_vm_config(self, config_id):
        session = self.session()
        try:
            return session.query(GcpVMConfig).filter(GcpVMConfig.config_id == config_id).one_or_none()
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex

    def get_vsphere_vm_configs(self):
        session = self.session()
        try:
            return session.query(VsphereVMConfig).all()
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex

    def get_vsphere_vm_config(self, config_id):
        session = self.session()
        try:
            return session.query(VsphereVMConfig).filter(VsphereVMConfig.config_id == config_id).one_or_none()
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex

    def get_openstack_vm_configs(self):
        session = self.session()
        try:
            return session.query(OpenStackVMConfig).all()
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex

    def get_openstack_vm_config(self, config_id):
        session = self.session()
        try:
            return session.query(OpenStackVMConfig).filter(OpenStackVMConfig.config_id == config_id).one_or_none()
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex

    def get_dns_provider_configs(self, azure=True, aws=True, digital_ocean=True, oci=True, gcp=True):
        session = self.session()
        ret = []
        try:
            if azure:
                ret += session.query(AzureDNSConfig).all()
            if aws:
                ret += session.query(AwsDNSConfig).all()
            if digital_ocean:
                ret += session.query(DigitalOceanDNSConfig).all()
            if oci:
                ret += session.query(OracleDNSConfig).all()
            if gcp:
                ret += session.query(GcpDNSConfig).all()
            return ret
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex

    def get_dns_provider_config(self, dns_provider_config_id, provider_name):
        session = self.session()
        ret = None
        try:
            if provider_name == 'azure':
                ret = session.query(AzureDNSConfig).filter(AzureDNSConfig.azure_dns_config_id == dns_provider_config_id).one_or_none()
            else:  # inserted
                if provider_name == 'aws':
                    ret = session.query(AwsDNSConfig).filter(AwsDNSConfig.config_id == dns_provider_config_id).one_or_none()
                else:  # inserted
                    if provider_name == 'digital_ocean':
                        ret = session.query(DigitalOceanDNSConfig).filter(DigitalOceanDNSConfig.config_id == dns_provider_config_id).one_or_none()
                    else:  # inserted
                        if provider_name == 'oci':
                            ret = session.query(OracleDNSConfig).filter(OracleDNSConfig.config_id == dns_provider_config_id).one_or_none()
                        else:  # inserted
                            if provider_name == 'gcp':
                                ret = session.query(GcpDNSConfig).filter(GcpDNSConfig.config_id == dns_provider_config_id).one_or_none()
                            else:  # inserted
                                raise NotImplementedError('Provider %s not recognized' % provider_name)
            return ret
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex

    def create_azure_dns_config(self, config_name, azure_subscription_id, azure_resource_group, azure_tenant_id, azure_client_id, azure_client_secret, azure_region, azure_authority, azure_dns_config_id=None):
        session = self.session()
        try:
            azure_dns_config = AzureDNSConfig(azure_dns_config_id=azure_dns_config_id, config_name=config_name, azure_subscription_id=azure_subscription_id, azure_resource_group=azure_resource_group, azure_tenant_id=azure_tenant_id, azure_client_id=azure_client_id, azure_client_secret=azure_client_secret, azure_region=azure_region, azure_authority=azure_authority)
            session.add(azure_dns_config)
            session.commit()
            return azure_dns_config
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex

    def update_azure_dns_config(self, azure_dns_config, config_name=None, azure_subscription_id=None, azure_resource_group=None, azure_tenant_id=None, azure_client_id=None, azure_client_secret=None, azure_region=None, azure_authority=None):
        attributes = ['config_name', 'azure_subscription_id', 'azure_resource_group', 'azure_tenant_id', 'azure_client_id', 'azure_client_secret', 'azure_region', 'azure_authority']
        for x in attributes:
            val = locals()[x]
            if val!= None:
                if x in AzureDNSConfig._sanitize:
                    if not is_sanitized(val):
                        setattr(azure_dns_config, x, val)
                else:  # inserted
                    setattr(azure_dns_config, x, val)
        self._save()
        return azure_dns_config

    def create_aws_dns_config(self, config_name, aws_access_key_id, aws_secret_access_key, config_id=None):
        session = self.session()
        try:
            aws_dns_config = AwsDNSConfig(config_id=config_id, config_name=config_name, aws_access_key_id=aws_access_key_id, aws_secret_access_key=aws_secret_access_key)
            session.add(aws_dns_config)
            session.commit()
            return aws_dns_config
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex

    def update_aws_dns_config(self, aws_dns_config, config_name=None, aws_access_key_id=None, aws_secret_access_key=None):
        attributes = ['config_name', 'aws_access_key_id', 'aws_secret_access_key']
        for x in attributes:
            val = locals()[x]
            if val is not None:
                if not (x in AwsDNSConfig._sanitize and is_sanitized(val)):
                    setattr(aws_dns_config, x, val)
                else:  # inserted
                    setattr(aws_dns_config, x, val)
        self._save()
        return aws_dns_config

    def create_digital_ocean_dns_config(self, config_name, digital_ocean_token, config_id=None):
        session = self.session()
        try:
            digital_ocean_dns_config = DigitalOceanDNSConfig(config_id=config_id, config_name=config_name, digital_ocean_token=digital_ocean_token)
            session.add(digital_ocean_dns_config)
            session.commit()
            return digital_ocean_dns_config
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex

    def update_digital_ocean_dns_config(self, digital_ocean_dns_config, config_name=None, digital_ocean_token=None):
        attributes = ['config_name', 'digital_ocean_token']
        for x in attributes:
            val = locals()[x]
            if val is not None:
                if not (x in DigitalOceanDNSConfig._sanitize and is_sanitized(val)):
                    setattr(digital_ocean_dns_config, x, val)
                else:  # inserted
                    setattr(digital_ocean_dns_config, x, val)
        self._save()
        return digital_ocean_dns_config

    def create_oci_dns_config(self, config_name, oci_user_ocid, oci_private_key, oci_fingerprint, oci_tenancy_ocid, oci_region, oci_compartment_ocid, config_id=None):
        session = self.session()
        try:
            oci_dns_config = OracleDNSConfig(config_id=config_id, config_name=config_name, oci_user_ocid=oci_user_ocid, oci_private_key=oci_private_key, oci_fingerprint=oci_fingerprint, oci_tenancy_ocid=oci_tenancy_ocid, oci_region=oci_region, oci_compartment_ocid=oci_compartment_ocid)
            session.add(oci_dns_config)
            session.commit()
            return oci_dns_config
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex

    def update_oci_dns_config(self, oci_dns_config, config_name=None, oci_user_ocid=None, oci_private_key=None, oci_fingerprint=None, oci_tenancy_ocid=None, oci_region=None, oci_compartment_ocid=None):
        attributes = ['config_name', 'oci_user_ocid', 'oci_private_key', 'oci_fingerprint', 'oci_tenancy_ocid', 'oci_region', 'oci_compartment_ocid']
        for x in attributes:
            val = locals()[x]
            if val is not None:
                if x in OracleDNSConfig._sanitize:
                    if not is_sanitized(val):
                        setattr(oci_dns_config, x, val)
                else:  # inserted
                    setattr(oci_dns_config, x, val)
        self._save()
        return oci_dns_config

    def create_gcp_dns_config(self, config_name, gcp_credentials, gcp_project, config_id=None):
        session = self.session()
        try:
            gcp_dns_config = GcpDNSConfig(config_id=config_id, config_name=config_name, gcp_credentials=gcp_credentials, gcp_project=gcp_project)
            session.add(gcp_dns_config)
            session.commit()
            return gcp_dns_config
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex

    def update_gcp_dns_config(self, gcp_dns_config, config_name=None, gcp_credentials=None, gcp_project=None):
        attributes = ['config_name', 'gcp_credentials', 'gcp_project']
        for x in attributes:
            val = locals()[x]
            if val is not None:
                if x in GcpDNSConfig._sanitize:
                    if not is_sanitized(val):
                        setattr(gcp_dns_config, x, val)
                else:  # inserted
                    setattr(gcp_dns_config, x, val)
        self._save()
        return gcp_dns_config

    def get_azure_dns_configs(self):
        session = self.session()
        try:
            return session.query(AzureDNSConfig).all()
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex

    def get_azure_dns_config(self, azure_dns_config_id):
        session = self.session()
        try:
            return session.query(AzureDNSConfig).filter(AzureDNSConfig.azure_dns_config_id == azure_dns_config_id).one_or_none()
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex

    def get_aws_dns_configs(self):
        session = self.session()
        try:
            return session.query(AwsDNSConfig).all()
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex

    def get_aws_dns_config(self, config_id):
        session = self.session()
        try:
            return session.query(AwsDNSConfig).filter(AwsDNSConfig.config_id == config_id).one_or_none()
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex

    def get_digital_ocean_dns_configs(self):
        session = self.session()
        try:
            return session.query(DigitalOceanDNSConfig).all()
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex

    def get_digital_ocean_dns_config(self, config_id):
        session = self.session()
        try:
            return session.query(DigitalOceanDNSConfig).filter(DigitalOceanDNSConfig.config_id == config_id).one_or_none()
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex

    def get_oci_dns_configs(self):
        session = self.session()
        try:
            return session.query(OracleDNSConfig).all()
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex

    def get_oci_dns_config(self, config_id):
        session = self.session()
        try:
            return session.query(OracleDNSConfig).filter(OracleDNSConfig.config_id == config_id).one_or_none()
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex
                session = self.session()
                try:
                    return session.query(GcpDNSConfig).all()
                except SQLAlchemyError as ex:
                    session.rollback()
                    raise ex
                        session = self.session()
                        try:
                            return session.query(GcpDNSConfig).filter(GcpDNSConfig.config_id == config_id).one_or_none()
                        except SQLAlchemyError as ex:
                            session.rollback()
                            raise ex
                                self._delete(vm_provider_config)
                                    self._delete(dns_provider_config)

    def get_autoscale_config(self, server_pool_id=None, zone_id=None, enabled=None, autoscale_type=None):
        session = self.session()
        try:
            q = session.query(AutoScaleConfig)
            if server_pool_id:
                q = q.filter(AutoScaleConfig.server_pool_id == server_pool_id)
            if zone_id:
                q = q.filter(AutoScaleConfig.zone_id == zone_id)
            if enabled is not None:
                q = q.filter(AutoScaleConfig.enabled == enabled)
            if autoscale_type:
                q = q.filter(AutoScaleConfig.autoscale_type == autoscale_type)
            return q.all()
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex
                session = self.session()
                try:
                    return session.query(AutoScaleConfig).filter(AutoScaleConfig.autoscale_config_id == autoscale_config_id).one_or_none()
                except SQLAlchemyError as ex:
                    session.rollback()
                    raise ex

    def create_autoscale_config(self, autoscale_config=None, aggressive_scaling=False):
        session = self.session()
        try:
            if connection_type == CONNECTION_TYPE.KASMVNC.value and max_simultaneous_sessions_per_server and (int(max_simultaneous_sessions_per_server) > 1):
                max_simultaneous_sessions_per_server = 1
            downscale_backoff = AutoScaleConfig(autoscale_config_id=autoscale_config_id, autoscale_config_name=autoscale_config_name, autoscale_type=autoscale_type, enabled=enabled, standby_cores=standby_cores, standby_memory_mb=standby_memory_mb, standby_gpus=standby_gpus, downscale_backoff=downscale_backoff, last_provision=datetime.datetime.fromtimestamp(0), request_downscale_at=datetime.datetime.fromtimestamp(0), register_dns=register_dns, base_domain_name=base_domain_name, nginx_cert=nginx_cert, nginx_key=nginx_key, agent_cores_override=agent_cores_override, agent_memory_override_gb=agent_memory_override_gb, agent_gpus_override=agent_gpus_override, aws_config_id=aws_config_id, aws_dns_config_id=aws_dns_config_id, azure_config_id=azure_config_id, azure_dns_config_id=azure_dns_config_id, digital_ocean_vm_config_id=digital_ocean_vm_config_id, digital_ocean_dns_config_id=digital_ocean_dns_config_id, openstack_vm_config_id=openstack_vm_config_id, oci_vm_config_id=oci_vm_config_id, oci_dns_config_id=oci_dns_config_id, gcp_vm_config_id=gcp_vm_config_id, gcp_dns_config_id=gcp_dns_config_id, vsphere_vm_config_id=vsphere_vm_config_id, zone_id=zone_id, server_pool_id=server_pool_id, connection_type=connection_type, connection_info=connection_info, connection_port=connection_port, connection_username=connection_username, connection_password=connection_password, connection_private_key=connection_private_key, use_user_private_key=use_user_private_key, connection_passphrase=connection_passphrase, reusable=reusable, hooks=hooks, minimum_pool_standby_sessions=minimum_pool_standby_sessions, max_simultaneous_sessions_per_server=max_simultaneous_sessions_per_server, ldap_id=ldap_id, ad_create_machine_record=ad_create_machine_record, ad_recursive_machine_record_cleanup=ad_recursive_machine_record_cleanup, ad_computer_container_dn=ad_computer_container_dn, agent_installed=agent_installed, require_checkin
            session.add(autoscale_config)
            session.commit()
            return autoscale_config
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex
                attributes = ['enabled', 'autoscale_config_name', 'autoscale_type', 'standby_cores', 'standby_memory_mb', 'standby_gpus', 'downscale_backoff', 'register_dns', 'base_domain_name', 'nginx_cert', 'nginx_key', 'agent_cores_override', 'agent_memory_override_gb', 'agent_gpus_override', 'connection_type', 'connection_info', 'connection_port', 'connection_username', 'connection_password', 'reusable', 'hooks', 'minimum_pool_standby_sessions', 'max_simultaneous_sessions_per_server', 'zone_id', 'ldap_id', 'ad_create_machine_record', 'ad_recursive_machine_record_cleanup', 'ad_computer_container_dn', 'connection_password', 'connection_private_key', 'connection_passphrase', 'use_user_private_key', 'agent_installed', 'require_checkin', 'aggressive_scaling']
                for x in attributes:
                    val = locals()[x]
                    if val is not None:
                        if not (x in AutoScaleConfig._sanitize and is_sanitized(val)):
                            setattr(autocale_config, x, val)
                        else:  # inserted
                            setattr(autocale_config, x, val)
                autocale_config.azure_config_id = azure_config_id
                autocale_config.azure_dns_config_id = azure_dns_config_id
                autocale_config.aws_config_id = aws_config_id
                autocale_config.aws_dns_config_id = aws_dns_config_id
                autocale_config.digital_ocean_vm_config_id = digital_ocean_vm_config_id
                autocale_config.digital_ocean_dns_config_id = digital_ocean_dns_config_id
                autocale_config.oci_vm_config_id = oci_vm_config_id
                autocale_config.oci_dns_config_id = oci_dns_config_id
                autocale_config.gcp_vm_config_id = gcp_vm_config_id
                autocale_config.gcp_dns_config_id = gcp_dns_config_id
                autocale_config.vsphere_vm_config_id = vsphere_vm_config_id
                autocale_config.openstack_vm_config_id = openstack_vm_config_id
                autocale_config.server_pool_id = server_pool_id
                if autocale_config.connection_type == CONNECTION_TYPE.KASMVNC.value or autocale_config.connection_type == CONNECTION_TYPE.VNC.value:
                    autocale_config.max_simultaneous_sessions_per_server = 1
                self._save()
                return autocale_config
                    self._delete(autoscale_config)

    def create_schedule(self, autoscale_config_id: datetime.time, days_of_the_week: str, active_start_time: datetime.time, active_end_time: datetime.time, timezone: str):
        session = self.session()
        ZoneInfo(timezone)
        schedule = Schedule(autoscale_config_id=autoscale_config_id, days_of_the_week=days_of_the_week, active_start_time=active_start_time, active_end_time=active_end_time, timezone=timezone)
        try:
            session.add(schedule)
            session.commit()
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex
        return schedule

    def get_schedules(self, autoscale_config_id: str=None):
        session = self.session()
        try:
            q = session.query(Schedule)
            if autoscale_config_id:
                q = q.filter(Schedule.autoscale_config_id == autoscale_config_id)
            return q.all()
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex

    def get_schedule(self, schedule_id: str=None, autoscale_config_id: str=None):
        session = self.session()
        try:
            q = session.query(Schedule)
            if schedule_id:
                q = q.filter(Schedule.schedule_id == schedule_id)
            if autoscale_config_id:
                q = q.filter(Schedule.autoscale_config_id == autoscale_config_id)
            return q.one_or_none()
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex

    def update_schedule(self, schedule: Schedule, days_of_the_week: typing.List=None, active_start_time: datetime.time=None, active_end_time: datetime.time=None, timezone: str=None):
        attributes = ['days_of_the_week', 'active_start_time', 'active_end_time', 'timezone']
        if timezone:
            ZoneInfo(timezone)
        for x in attributes:
            val = locals()[x]
            if val is not None:
                if not (x in Schedule._sanitize and is_sanitized(val)):
                    setattr(schedule, x, val)
                else:  # inserted
                    setattr(schedule, x, val)
        self._save()
        return schedule

    def delete_schedule(self, schedule: Schedule):
        self._delete(schedule)

    def create_storage_mapping(self, name, storage_provider_id, enabled, config=None, user_id=None, image_id=None, group_id=None, target=None, read_only=None, s3_access_key_id=None, s3_bucket=None, s3_secret_access_key=None, webdav_user=None, webdav_pass=None, oauth_token=None):
        session = self.session()
        storage_mapping = StorageMapping(name=name, storage_provider_id=storage_provider_id, config=config, enabled=enabled, user_id=user_id, image_id=image_id, group_id=group_id, target=target, read_only=read_only, s3_access_key_id=s3_access_key_id, s3_secret_access_key=s3_secret_access_key, s3_bucket=s3_bucket, webdav_user=webdav_user, webdav_pass=webdav_pass, oauth_token=oauth_token)
        try:
            session.add(storage_mapping)
            session.commit()
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex
        return storage_mapping

    def get_storage_mappings(self, storage_mapping_id=None, user_id=None, group_id=None, image_id=None):
        session = self.session()
        try:
            q = session.query(StorageMapping)
            if storage_mapping_id:
                q = q.filter(StorageMapping.storage_mapping_id == storage_mapping_id)
            if user_id:
                q = q.filter(StorageMapping.user_id == user_id)
            if group_id:
                q = q.filter(StorageMapping.group_id == group_id)
            if image_id:
                q = q.filter(StorageMapping.image_id == image_id)
            return q.all()
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex

    def update_storage_mapping(self, storage_mapping, name=None, storage_provider_id=None, config=None, enabled=None, user_id=None, group_id=None, image_id=None, target=None, read_only=None, s3_access_key_id=None, s3_secret_access_key=None, s3_bucket=None, webdav_user=None, webdav_pass=None, oauth_token=None):
        session = self.session()
        try:
            q = session.query(StorageMapping)
            if storage_mapping_id:
                q = q.filter(StorageMapping.storage_mapping_id == storage_mapping_id)
            if user_id:
                q = q.filter(StorageMapping.user_id == user_id)
            if group_id:
                q = q.filter(StorageMapping.group_id == group_id)
            if image_id:
                q = q.filter(StorageMapping.image_id == image_id)
            return q.one_or_none()
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex
                attributes = ['name', 'storage_provider_id', 'config', 'enabled', 'user_id', 'group_id', 'image_id', 'target', 'read_only', 's3_access_key_id', 's3_secret_access_key', 's3_bucket', 'webdav_user', 'webdav_pass', 'oauth_token']
                for x in attributes:
                    val = locals()[x]
                    if val is not None:
                        if not (x in StorageMapping._sanitize and is_sanitized(val)):
                            setattr(storage_mapping, x, val)
                        else:  # inserted
                            setattr(storage_mapping, x, val)
                self._save()
                return storage_mapping
                    self._delete(storage_mapping)

    def get_storage_provider(self, storage_provider_id=None, storage_provider_type=None, enabled=None):
        session = self.session()
        try:
            q = session.query(StorageProvider)
            if storage_provider_id:
                q = q.filter(StorageProvider.storage_provider_id == storage_provider_id)
            if storage_provider_type:
                q = q.filter(StorageProvider.storage_provider_type == storage_provider_type)
            if enabled is not None:
                q = q.filter(StorageProvider.enabled == enabled)
            return q.one_or_none()
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex

    def update_storage_provider(self, storage_provider, name, storage_provider_type=None, client_id=None, client_secret=None, auth_url=None, token_url=None, webdav_url=None, scope=None, redirect_url=None, auth_url_options=None, volume_config=None, mount_config=None, root_drive_url=None, default_target=None, enabled=None):
        session = self.session()
        try:
            q = session.query(StorageProvider)
            if storage_provider_id:
                q = q.filter(StorageProvider.storage_provider_id == storage_provider_id)
            if storage_provider_type:
                q = q.filter(StorageProvider.storage_provider_type == storage_provider_type)
            if enabled is not None:
                q = q.filter(StorageProvider.enabled == enabled)
            return q.all()
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex
                session = self.session()
                storage_provider = StorageProvider(name=name, storage_provider_type=storage_provider_type, client_id=client_id, client_secret=client_secret, auth_url=auth_url, token_url=token_url, webdav_url=webdav_url, scope=scope, redirect_url=redirect_url, auth_url_options=auth_url_options, volume_config=volume_config, mount_config=mount_config, root_drive_url=root_drive_url, default_target=default_target, enabled=enabled)
                try:
                    session.add(storage_provider)
                    session.commit()
                except SQLAlchemyError as ex:
                    session.rollback()
                    raise ex
                return storage_provider
                    attributes = ['name', 'storage_provider_type', 'client_id', 'client_secret', 'auth_url', 'token_url', 'webdav_url', 'scope', 'redirect_url', 'auth_url_options', 'volume_config', 'mount_config', 'root_drive_url', 'default_target', 'enabled']
                    for x in attributes:
                        val = locals()[x]
                        if val is not None:
                            if x in StorageProvider._sanitize:
                                if not is_sanitized(val):
                                    setattr(storage_provider, x, val)
                            else:  # inserted
                                setattr(storage_provider, x, val)
                    self._save()
                    return storage_provider
                        self._delete(storage_provider)

    def create_group_permission(self, permission, group_id=None, api_id=None):
        session = self.session()
        try:
            gp = GroupPermission(permission_id=int(permission), group_id=group_id, api_id=api_id)
            session.add(gp)
            session.commit()
            return gp
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex
                self._delete(group_permission)
                    session = self.session()
                    try:
                        q = session.query(GroupPermission).filter(GroupPermission.group_permission_id == group_permission_id)
                        return q.one_or_none()
                    except SQLAlchemyError as ex:
                        session.rollback()
                        raise ex
                            meta = MetaData(bind=self.engine)
                            meta.reflect()
                            meta.drop_all()
                                model = Model()
                                model.create_schema(self.engine)
                                conn = self.engine.connect()
                                conn.execute(text('\n            DROP VIEW IF EXISTS getLogs;\n            '))
                                conn.execute(text('\n            CREATE VIEW getLogs as\n            SELECT \n                logs.host,\n                logs.ingest_date,\n                logs.data->>\'application\' AS application,\n                (logs.data ->> \'levelname\'::text) AS levelname,\n                    CASE\n                        WHEN ((logs.data ->> \'message\'::text) ~~ \'Successfully authenticated request (%\'::text) THEN \"substring\"((logs.data ->> \'message\'::text), \'\\(([^\\s\\)]+)\\)\'::text)\n                        ELSE (logs.data ->> \'funcName\'::text)\n                    END AS funcname,\n                (logs.data ->> \'request_ip\'::text) AS request_ip,\n                (logs.data ->> \'kasm_user_name\'::text) AS kasm_user_name,\n                (logs.data ->> \'kasm_user_id\'::text) AS kasm_user_id,\n                (logs.data ->> \'msecs\'::text) AS msec,\n                coalesce((logs.data->>\'message\'), (logs.data ->> \'msg\'::text)) AS message,\n                logs.data->>\'exc_info\' AS traceback,\n                to_char(logs.ingest_date, \'YYYYMMDD\'::text) AS log_day,\n                to_char(logs.ingest_date, \'YYYYMMDDHH24\'::text) AS log_hour,\n                to_char(logs.ingest_date, \'YYYYMMDDHH24MI\'::text) AS log_minute\n            FROM logs\n            WHERE (logs.data ? \'levelname\'::text);\n            '))
                                conn.execute(text('\n            DROP TRIGGER IF EXISTS settings_updated_trigger on settings;\n            DROP FUNCTION IF EXISTS notify_trigger();\n        '))
                                conn.execute(text('\n            CREATE FUNCTION notify_trigger() RETURNS trigger AS $$\n            BEGIN\n                PERFORM pg_notify(\'settings_updated\', \'\');\n                RETURN NEW;\n            END;\n            $$ LANGUAGE plpgsql;\n            '))
                                conn.execute(text('\n          CREATE TRIGGER settings_updated_trigger \n          AFTER UPDATE ON settings\n          FOR EACH ROW\n          EXECUTE PROCEDURE notify_trigger();'))
                                    session = self.session()
                                    try:
                                        session.delete(object)
                                        session.commit()
                                    except SQLAlchemyError as ex:
                                        session.rollback()
                                        raise ex
                                            session = self.session()
                                            try:
                                                for x in objects:
                                                    session.delete(x)
                                                session.commit()
                                            except SQLAlchemyError as ex:
                                                session.rollback()
                                                raise ex
                                                    session = self.session()
                                                    try:
                                                        session.commit()
                                                    except SQLAlchemyError as ex:
                                                        session.rollback()
                                                        raise ex
                                                            session = self.session()
                                                            try:
                                                                return session.query(Registry).all()
                                                            except SQLAlchemyError as ex:
                                                                session.rollback()
                                                                raise ex

    def update_registry(self, config, schema_version=None, do_auto_update=False):
        session = self.session()
        try:
            registry = Registry(config=config, registry_url=config['list_url'], do_auto_update=do_auto_update, schema_version=schema_version)
            session.add(registry)
            session.commit()
            return registry
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex
                session = self.session()
                try:
                    session.query(Registry).filter(Registry.registry_id == registry_id).update(update)
                    session.commit()
                    return session.query(Registry).filter(Registry.registry_id == registry_id).one_or_none()
                except SQLAlchemyError as ex:
                    session.rollback()
                    raise ex

    def seed_registry(self, registry_url, config=None, do_auto_update=False, schema_version=None):
        session = self.session()
        try:
            registry = Registry(config=config, do_auto_update=do_auto_update, registry_url=registry_url, schema_version=schema_version)
            session.add(registry)
            session.commit()
            return registry
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex
                session = self.session()
                try:
                    return session.query(Registry).filter(Registry.registry_id == registry_id).one_or_none()
                except SQLAlchemyError as ex:
                    session.rollback()
                    raise ex
                        session = self.session()
                        try:
                            return session.query(Registry).filter(Registry.registry_url == registry_url).one_or_none()
                        except SQLAlchemyError as ex:
                            session.rollback()
                            raise ex
                                self._delete(registry)
    for <mask_9> in (None, None):
        pass  # postinserted
    def create_webauthn_credential(self, user_id, authenticator_credential_id, public_key, sign_count, webauthn_credential_id):
        session = self.session()
        try:
            credential = WebauthnCredential(created=datetime.datetime.utcnow(), user_id=user_id, authenticator_credential_id=authenticator_credential_id, public_key=public_key, sign_count=sign_count, webauthn_credential_id=webauthn_credential_id)
            session.add(credential)
            session.commit()
            return credential
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex

    def get_webauthn_credential_by_authenticator_credential_id(self, authenticator_credential_id):
        session = self.session()
        try:
            return session.query(WebauthnCredential).filter(WebauthnCredential.authenticator_credential_id == authenticator_credential_id).one_or_none()
        except SQLAlchemyError as ex:
            session.rollback()
            raise ex
                session = self.session()
                try:
                    session.query(WebauthnCredential).filter(WebauthnCredential.user_id == user_id).delete(synchronize_session=False)
                    session.commit()
                except SQLAlchemyError as ex:
                    session.rollback()
                    raise ex
                        session = self.session()
                        try:
                            request = WebauthnRequest(webauthn_request_id=request_id, challenge=challenge, created=datetime.datetime.utcnow())
                            session.add(request)
                            session.commit()
                            return request
                        except SQLAlchemyError as ex:
                            session.rollback()
                            raise ex
                                session = self.session()
                                max_request_life = int(self.config['auth']['webauthn_request_lifetime'].value)
                                try:
                                    request = session.query(WebauthnRequest).filter(WebauthnRequest.webauthn_request_id == request_id).one_or_none()
                                    if request:
                                        session.delete(request)
                                        session.commit()
                                except SQLAlchemyError as ex:
                                    session.rollback()
                                    raise ex
                                if not request or Decimal(datetime.datetime.utcnow().timestamp()) - Decimal(request.created.timestamp()) > max_request_life:
                                    return False
                                return request
                                    session = self.session()
                                    max_request_life = int(self.config['auth']['webauthn_request_lifetime'].value)
                                    expired_time = datetime.datetime.utcnow() - datetime.timedelta(seconds=max_request_life)
                                    try:
                                        request = session.query(WebauthnRequest).filter(WebauthnRequest.created < expired_time).delete(synchronize_session=False)
                                        session.commit()
                                        return request
                                    except SQLAlchemyError as ex:
                                        session.rollback()
                                        raise ex
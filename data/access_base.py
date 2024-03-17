# decompyle3 version 3.9.1
# Python bytecode version base 3.8.0 (3413)
# Decompiled from: Python 3.10.12 (main, Nov 20 2023, 15:14:05) [GCC 11.4.0]
# Embedded file name: data/access_base.py
import abc, json, uuid, datetime
from logging import Logger
from sqlalchemy import select, func
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm.collections import InstrumentedList
from data.model import ImageAttribute, GroupImage, GroupSetting, UserGroup, FilterPolicy
from decimal import Decimal

class CustomEncoder(json.JSONEncoder):

    def default(self, obj):
        if isinstance(obj, uuid.UUID):
            return obj.hex
        if isinstance(obj, InstrumentedList):
            return [x for x in obj]
        if isinstance(obj, datetime.datetime):
            return str(obj)
        if isinstance(obj, datetime.time):
            return obj.isoformat()
        if isinstance(obj, ImageAttribute):
            return {'name':obj.name,  'category':obj.category,  'value':obj.value}
        if isinstance(obj, Decimal):
            return float(obj)
        if isinstance(obj, Logger):
            return f"Logger class {Logger.__class__.__name__} is not JSON serializable"
        if isinstance(obj, FilterPolicy):
            return obj.jsonDict
        return json.JSONEncoder.default(self, obj)


class DataAccessBase(object):
    __metaclass__ = abc.ABCMeta

    @abc.abstractmethod
    def __init__(self, config):
        pass

    @abc.abstractmethod
    def __del__(self):
        pass

    @abc.abstractmethod
    def new_db_session(self):
        pass

    @property
    @abc.abstractmethod
    def config(self):
        pass

    @abc.abstractmethod
    def get_config_settings(self, category, name):
        pass

    @abc.abstractmethod
    def setConfigSetting(self, service, name, value, value_type, services_restart=None, description=None):
        pass

    @abc.abstractmethod
    def createGroupSetting(self, name, value, description=None, group_id=None, value_type='string'):
        pass

    @abc.abstractmethod
    def updateGroupSetting(self, group_setting_id, value):
        pass

    @abc.abstractmethod
    def checkGroupSetting(self, group_id, name):
        pass

    @abc.abstractmethod
    def getDefaultGroupSettings(self):
        pass

    @abc.abstractmethod
    def getGroupSetting(self, group_setting_id):
        pass

    @abc.abstractmethod
    def deleteGroupSetting(self, groupsetting):
        self._delete(groupsetting)

    @abc.abstractmethod
    def addUserGroup(self, user, group):
        pass

    @abc.abstractmethod
    def removeUserGroup(self, user, group):
        pass

    @abc.abstractmethod
    def addImageGroup(self, image, group):
        pass

    @abc.abstractmethod
    def removeImageGroup(self, image, group):
        pass

    @abc.abstractmethod
    def createGroup(self, group):
        pass

    @abc.abstractmethod
    def getGroups(self):
        pass

    @abc.abstractmethod
    def getGroup(self, group_ip):
        pass

    def delete_group(self, group):
        self._delete(group)

    @abc.abstractmethod
    def getImage(self, image_id):
        pass

    @abc.abstractmethod
    def createImage(self, image, install=False):
        pass

    @abc.abstractmethod
    def updateImage(self, image):
        self._save()

    @abc.abstractmethod
    def deleteImage(self, image):
        self._delete(image)

    @abc.abstractmethod
    def getImages(self, enabled=True):
        pass

    @abc.abstractmethod
    def getKasm(self, kasm_id):
        pass

    @abc.abstractmethod
    def createKasm(self, docker):
        pass

    def deleteKasm(self, docker):
        self._delete(docker)

    @abc.abstractmethod
    def updateKasm(self, docker):
        self._save()

    @abc.abstractmethod
    def getExpiredKasms(self, zone_id, manager_id):
        pass

    @abc.abstractmethod
    def getServer(self, server_id):
        pass

    @abc.abstractmethod
    def createServer(self, server):
        pass

    def getServers(self, manager_id, provider=None, server_type=None, operational_status=None):
        pass

    @abc.abstractmethod
    def getExpiredServers(self, expiredTimestamp, manager_id, operational_status='running', server_type='host'):
        pass

    @abc.abstractmethod
    def updateServer(self, server):
        self._save()

    @abc.abstractmethod
    def deleteServer(self, server):
        self._delete(server)

    @abc.abstractmethod
    def getUser(self, username):
        pass

    @abc.abstractmethod
    def getUsers(self, page=0, page_size=None, username=None):
        pass

    @abc.abstractmethod
    def getUserSettings(self, user):
        pass

    @abc.abstractmethod
    def updateUser(self, user):
        self._save()

    @abc.abstractmethod
    def createUser(self, username, pw):
        pass

    @abc.abstractmethod
    def deleteUser(self, user):
        self._delete(user)

    @abc.abstractmethod
    def createImageAttribute(self, image_attribute):
        pass

    @abc.abstractmethod
    def deleteImageAttribute(self, image_attribute):
        self._delete(image_attribute)

    @abc.abstractmethod
    def updateImageAttribute(self, image_attribute):
        self._save()

    @abc.abstractmethod
    def getUserKasm(self, user, kasm_id):
        pass

    @abc.abstractmethod
    def getNewsletter(self, emailaddress):
        pass

    @abc.abstractmethod
    def createNewsletter(self, emailaddress, type):
        pass

    @abc.abstractmethod
    def updateNewsletter(self, newsletter):
        self._save()

    @abc.abstractmethod
    def get_saml_config(self):
        pass

    @abc.abstractmethod
    def set_saml_config(self, SAMLconfig):
        pass

    @abc.abstractmethod
    def update_saml_config(self):
        pass

    @abc.abstractmethod
    def createLogs(self, logs):
        pass

    @abc.abstractmethod
    def getReport(self, reportid=None, name=None):
        pass

    @abc.abstractmethod
    def dropSchema(self):
        pass

    @abc.abstractmethod
    def createSchema(self):
        pass

    @abc.abstractmethod
    def execute_native_query(self, query):
        pass

    @abc.abstractmethod
    def clean_logs(self, log_retention_date, debug_retention_date):
        pass

    @abc.abstractmethod
    def escape_string(self, s):
        if not isinstance(s, str):
            raise TypeError("%r must be a str or unicode" % (s,))
        s = s.replace("'", "''")
        s = s.replace("\\", "\\\\")
        return s

    @abc.abstractmethod
    def _delete(self, object):
        pass

    @abc.abstractmethod
    def _save(self):
        pass

    @classmethod
    def serializable(cls, obj, clear_private_objects=True, skip_fields=[]):
        if type(obj) == dict and clear_private_objects:
            new_obj = {}
            for (k, v) in obj.items():
                if clear_private_objects:
                    if not k.startswith("_"):
                        pass
                    if k not in skip_fields:
                        new_obj[k] = v

        else:
            new_obj = obj
        return json.loads(json.dumps(new_obj, cls=CustomEncoder))

    def get_current_time(self):
        session = self.session()
        try:
            result = session.execute(select([func.current_timestamp().op("AT TIME ZONE")("UTC")])).first()[0]
        except SQLAlchemyError as ex:
            try:
                session.rollback()
                raise ex
            finally:
                ex = None
                del ex

        else:
            return result

# okay decompiling ../bytecode/data/access_base.pyc

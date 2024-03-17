# decompyle3 version 3.9.1
# Python bytecode version base 3.8.0 (3413)
# Decompiled from: Python 3.10.12 (main, Nov 20 2023, 15:14:05) [GCC 11.4.0]
# Embedded file name: data/enums.py
from strenum import StrEnum
import enum

class AZURE_AUTHORITY(StrEnum):
    AZURE_PUBLIC_CLOUD = "AZURE_PUBLIC_CLOUD"
    AZURE_GOVERNMENT = "AZURE_GOVERNMENT"
    AZURE_CHINA = "AZURE_CHINA"
    AZURE_GERMANY = "AZURE_GERMANY"


class SERVER_TYPE(StrEnum):
    HOST = "host"
    DESKTOP = "Desktop"


class SERVER_POOL_TYPE(StrEnum):
    DOCKER_AGENT = "Docker Agent"
    SERVER = "Server Pool"


class IMAGE_TYPE(StrEnum):
    CONTAINER = "Container"
    SERVER = "Server"
    SERVER_POOL = "Server Pool"


class CONNECTION_TYPE(StrEnum):
    KASMVNC = "KasmVNC"
    RDP = "RDP"
    VNC = "VNC"
    SSH = "SSH"


class CONNECTION_PROXY_TYPE(StrEnum):
    GUAC = "GUAC"


class CPU_ALLOCATION_METHOD(StrEnum):
    INHERIT = "Inherit"
    QUOTAS = "Quotas"
    SHARES = "Shares"


class SERVER_OPERATIONAL_STATUS(StrEnum):
    RUNNING = "running"
    DELETE_PENDING = "delete_pending"
    DESTROYING = "destroying"
    MISSING = "missing"
    STARTING = "starting"
    DEAD = "dead"

    def validate(value):
        if not value:
            return False
        for status in SERVER_OPERATIONAL_STATUS:
            if status.value == value.lower():
                return status
            return False


class SESSION_OPERATIONAL_STATUS(StrEnum):
    RUNNING = "running"
    DELETE_PENDING = "delete_pending"
    ADMIN_DELETE_PENDING = "admin_delete_pending"
    USER_DELETE_PENDING = "user_delete_pending"
    DESTROYING = "destroying"
    STOPPED = "stopped"
    PAUSED = "paused"
    SAVING = "saving"
    STARTING = "starting"
    DELETING = "deleting"
    REQUESTED = "requested"
    PROVISIONING = "provisioning"
    ASSIGNED = "assigned"
    STOPPING = "stopping"
    PAUSING = "pausing"

    def validate(value):
        if not value:
            return False
        for status in SESSION_OPERATIONAL_STATUS:
            if status.value == value.lower():
                return status
            return False


class JWT_AUTHORIZATION(enum.Enum):
    KASM_SESSION = (50, 'Base permissions allowed for a Kasm session (API calls made by a session container).')
    AGENT = (60, 'Base permissions allowed for a Kasm Agent.')
    SERVER_AGENT = (70, 'Base permissions allowed for a Server agent service.')
    GUAC = (80, 'Base permissions allowed for a Kasm Guac.')
    USER = (100, 'Default level of permissions for normal users.')
    GLOBAL_ADMIN = (200, 'Global Administrator with all permissions.')
    USERS_VIEW = (300, 'View users and user information.')
    USERS_MODIFY = (301, 'Modify existing users.')
    USERS_CREATE = (302, 'Create new users.')
    USERS_DELETE = (303, 'Delete existing users.')
    USERS_MODIFY_ADMIN = (351, 'Modify users with root admin permissions.')
    USERS_AUTH_SESSION = (352, 'Login and logout on behalf of another user.')
    GROUPS_VIEW = (400, 'View groups, group members, and group settings.')
    GROUPS_MODIFY = (401, 'Modify group members and settings.')
    GROUPS_CREATE = (402, 'Create new groups.')
    GROUPS_DELETE = (403, 'Delete existing groups.')
    GROUPS_VIEW_IFMEMBER = (420, 'View groups you are a member of, excluding system groups.')
    GROUPS_MODIFY_IFMEMBER = (421, 'Modify groups you are a member of, with the exception of group permissions and excluding system groups.')
    GROUPS_VIEW_SYSTEM = (440, 'View groups, group members and group settings of system defined groups.')
    GROUPS_MODIFY_SYSTEM = (441, 'Modify group members and settings of system groups.')
    GROUPS_DELETE_SYSTEM = (443, 'Delete a system group.')
    AGENTS_VIEW = (500, 'View agents and agent settings.')
    AGENTS_MODIFY = (501, 'Modify agent settings.')
    AGENTS_CREATE = (502, 'Create agents.')
    AGENTS_DELETE = (503, 'Delete existing agents.')
    STAGING_VIEW = (600, 'View staging list and stage configuration settings.')
    STAGING_MODIFY = (601, 'Modify existing staging settings.')
    STAGING_CREATE = (602, 'Create new staging configurations.')
    STAGING_DELETE = (603, 'Delete existing staging configurations.')
    CASTING_VIEW = (700, 'View casting list and casting configuration settings.')
    CASTING_MODIFY = (701, 'Modify existing casting settings.')
    CASTING_CREATE = (702, 'Create new casting configurations.')
    CASTING_DELETE = (703, 'Delete existing casting configurations.')
    SESSIONS_VIEW = (800, 'View all user sessions.')
    SESSIONS_MODIFY = (801, 'Perform modifications to a session of another user.')
    SESSIONS_DELETE = (803, 'Delete the session of another user.')
    SESSION_RECORDINGS_VIEW = (850, 'View all user session recordings')
    IMAGES_VIEW = (900, 'View images')
    IMAGES_MODIFY = (901, 'Modify image configurations.')
    IMAGES_CREATE = (902, 'Create new images.')
    IMAGES_DELETE = (903, 'Delete existing images.')
    IMAGES_MODIFY_RESOURCES = (904, 'Modify image resource settings, such as CPU and Memory settings.')
    DEVAPI_VIEW = (1000, 'View developer API list.')
    DEVAPI_MODIFY = (1001, 'Modify developer API configurations.')
    DEVAPI_CREATE = (1002, 'Create a new developer API key.')
    DEVAPI_DELETE = (1003, 'Delete an existing developer API key.')
    WEBFILTERS_VIEW = (1100, 'View webfilters')
    WEBFILTERS_MODIFY = (1101, 'Modify existing webfilters')
    WEBFILTERS_CREATE = (1102, 'Create a new webfilter.')
    WEBFILTERS_DELETE = (1103, 'Delete an existing webfilter')
    BRANDINGS_VIEW = (1200, 'View branding configurations.')
    BRANDINGS_MODIFY = (1201, 'Modify existing branding configurations.')
    BRANDINGS_CREATE = (1202, 'Create new branding configurations.')
    BRANDINGS_DELETE = (1203, 'Delete existing branding configurations.')
    SETTINGS_VIEW = (1300, 'View global settings.')
    SETTINGS_MODIFY = (1301, 'Modify global settings.')
    SETTINGS_MODIFY_AUTH = (1302, 'Modify global settings in the authentication category.')
    SETTINGS_MODIFY_CAST = (1303, 'Modify global settings in the casting category.')
    SETTINGS_MODIFY_IMAGES = (1304, 'Modify global settings in the images category.')
    SETTINGS_MODIFY_LICENSE = (1305, 'Modify global settings in the license category.')
    SETTINGS_MODIFY_LOGGING = (1306, 'Modify global settings in the logging category.')
    SETTINGS_MODIFY_MANAGER = (1307, 'Modify global settings in the manager category.')
    SETTINGS_MODIFY_SCALE = (1308, 'Modify global settings in the scale category.')
    SETTINGS_MODIFY_SUBSCRIPTION = (1309, 'Modify global settings in the subscription category.')
    SETTINGS_MODIFY_FILTER = (1310, 'Modify global settings in the filter category.')
    SETTINGS_MODIFY_STORAGE = (1311, 'Modify global settings in the storage category.')
    SETTINGS_MODIFY_CONNECTIONS = (1312, 'Modify global settings in the connections category.')
    SETTINGS_MODIFY_THEME = (1313, 'Modify global settings in the theme category.')
    AUTH_VIEW = (1400, 'View LDAP/OIDC/SAML configurations.')
    AUTH_MODIFY = (1401, 'Modify LDAP/OIDC/SAML configurations.')
    AUTH_CREATE = (1402, 'Create LDAP/OIDC/SAML configurations.')
    AUTH_DELETE = (1403, 'Delete LDAP/OIDC/SAML configurations.')
    LICENSES_VIEW = (1500, 'View licenses.')
    LICENSES_CREATE = (1502, 'Add new licenses.')
    LICENSES_DELETE = (1503, 'Delete licenses.')
    SYSTEM_VIEW = (1600, 'View system information.')
    SYSTEM_EXPORT_SCHEMA = (1604, 'Export system schema.')
    SYSTEM_IMPORT_DATA = (1605, 'Import system data.')
    SYSTEM_EXPORT_DATA = (1606, 'Export system data.')
    REPORTS_VIEW = (1700, 'View system reports.')
    MANAGERS_VIEW = (1800, 'View the managers.')
    MANAGERS_MODIFY = (1801, 'Modify existing managers.')
    MANAGERS_CREATE = (1802, 'Create a new manager.')
    MANAGERS_DELETE = (1803, 'Delete existing managers.')
    ZONES_VIEW = (1900, 'View Zones and Zone settings.')
    ZONES_MODIFY = (1901, 'Modify Zone settings.')
    ZONES_CREATE = (1902, 'Create new Zones.')
    ZONES_DELETE = (1903, 'Delete existing Zones.')
    COMPANIES_VIEW = (2000, 'View companies.')
    COMPANIES_MODIFY = (2001, 'Modify existing company.')
    COMPANIES_CREATE = (2002, 'Create a new company.')
    COMPANIES_DELETE = (2003, 'Delete an existing company.')
    CONNECTION_PROXY_VIEW = (2100, 'View connection proxies.')
    CONNECTION_PROXY_MODIFY = (2101, 'Modify connection proxies.')
    CONNECTION_PROXY_CREATE = (2102, 'Create a connection proxy.')
    CONNECTION_PROXY_DELETE = (2103, 'Delete an existing connection proxy.')
    PHYSICAL_TOKENS_VIEW = (2200, 'View physical 2FA tokens.')
    PHYSICAL_TOKENS_MODIFY = (2201, 'Assign/Unassign physical 2FA tokens.')
    PHYSICAL_TOKENS_CREATE = (2202, 'Import or create physical 2FA tokens.')
    PHYSICAL_TOKENS_DELETE = (2203, 'Delete a physical 2FA token.')
    SERVERS_VIEW = (2300, 'View servers.')
    SERVERS_MODIFY = (2301, 'Modify existing servers.')
    SERVERS_CREATE = (2302, 'Create new servers.')
    SERVERS_DELETE = (2303, 'Delete servers.')
    SERVER_POOLS_VIEW = (2400, 'View server pools.')
    SERVER_POOLS_MODIFY = (2401, 'Modify server pools.')
    SERVER_POOLS_CREATE = (2402, 'Create a new server pool.')
    SERVER_POOLS_DELETE = (2403, 'Delete a server pool.')
    AUTOSCALE_VIEW = (2500, 'View auto scale configurations.')
    AUTOSCALE_MODIFY = (2501, 'Modify an existing auto scale configuration.')
    AUTOSCALE_CREATE = (2502, 'Create a new auto scale configuration.')
    AUTOSCALE_DELETE = (2503, 'Delete auto scale configurations.')
    VM_PROVIDER_VIEW = (2600, 'View VM Provider configurations.')
    VM_PROVIDER_MODIFY = (2601, 'Modify VM Provider configurations.')
    VM_PROVIDER_CREATE = (2602, 'Create new VM Provider configurations.')
    VM_PROVIDER_DELETE = (2603, 'Delete VM Provider configurations.')
    AUTOSCALE_SCHEDULE_VIEW = (2700, 'View an auto scale schedule.')
    AUTOSCALE_SCHEDULE_MODIFY = (2701, 'Modify an auto scale schedule.')
    AUTOSCALE_SCHEDULE_CREATE = (2702, 'Create an auto scale schedule.')
    AUTOSCALE_SCHEDULE_DELETE = (2703, 'Delete an auto scale schedule.')
    DNS_PROVIDERS_VIEW = (2800, 'View DNS provider configurations.')
    DNS_PROVIDERS_MODIFY = (2801, 'Modify DNS provider configurations.')
    DNS_PROVIDERS_CREATE = (2802, 'Create new DNS Provider configurations.')
    DNS_PROVIDERS_DELETE = (2803, 'Delete DNS Provider configurations.')
    REGISTRIES_VIEW = (2900, 'View Workspace Registries.')
    REGISTRIES_MODIFY = (2901, 'Modify existing Workspace Registries.')
    REGISTRIES_CREATE = (2902, 'Add new Workspace Registries')
    REGISTRIES_DELETE = (2903, 'Delete a Workspace Registry')
    STORAGE_PROVIDERS_VIEW = (3000, 'View Storage Providers.')
    STORAGE_PROVIDERS_MODIFY = (3001, 'Modify existing Storage Providers.')
    STORAGE_PROVIDERS_CREATE = (3002, 'Create new Storage Providers.')
    STORAGE_PROVIDERS_DELETE = (3003, 'Delete an existing Storage Provider.')

    def __new__(cls, value, name):
        member = object.__new__(cls)
        member._value_ = value
        member.description = name
        return member

    def __int__(self):
        return self.value

    def get_friendly_name(self):
        return " ".join((x.capitalize() or "_" for x in str(self).lower().replace("jwt_authorization.", "").split("_")))

    @staticmethod
    def is_valid_value(value: int):
        values = [authorization.value for authorization in JWT_AUTHORIZATION]
        return value in values

    @staticmethod
    def is_readonly_action(action):
        i = int(action)
        if i < 201:
            return False
        if action in (JWT_AUTHORIZATION.GROUPS_VIEW_IFMEMBER, JWT_AUTHORIZATION.GROUPS_VIEW_SYSTEM):
            return True
        return i % 100 == 0

    @staticmethod
    def is_readonly_actions(actions):
        for action in actions:
            if not JWT_AUTHORIZATION.is_readonly_action(action):
                return False
            return True

    @staticmethod
    def get_authorized_views(user_authorizations):
        views = {'user_dashboard':(JWT_AUTHORIZATION.is_authorized_action)(user_authorizations, JWT_AUTHORIZATION.USER), 
         'admin_dashboard':False, 
         'reports':(JWT_AUTHORIZATION.is_authorized_action)(user_authorizations, JWT_AUTHORIZATION.REPORTS_VIEW), 
         'logging':(JWT_AUTHORIZATION.is_authorized_action)(user_authorizations, JWT_AUTHORIZATION.REPORTS_VIEW), 
         'users':(JWT_AUTHORIZATION.is_authorized_action)(user_authorizations, JWT_AUTHORIZATION.USERS_VIEW), 
         'groups':(JWT_AUTHORIZATION.any_authorized_actions)(user_authorizations, [JWT_AUTHORIZATION.GROUPS_VIEW, JWT_AUTHORIZATION.GROUPS_VIEW_IFMEMBER]), 
         'agents':(JWT_AUTHORIZATION.is_authorized_action)(user_authorizations, JWT_AUTHORIZATION.AGENTS_VIEW), 
         'managers':(JWT_AUTHORIZATION.is_authorized_action)(user_authorizations, JWT_AUTHORIZATION.MANAGERS_VIEW), 
         'zones':(JWT_AUTHORIZATION.is_authorized_action)(user_authorizations, JWT_AUTHORIZATION.ZONES_VIEW), 
         'staging':(JWT_AUTHORIZATION.all_authorized_actions)(user_authorizations, [JWT_AUTHORIZATION.STAGING_VIEW]), 
         'casting':(JWT_AUTHORIZATION.all_authorized_actions)(user_authorizations, [JWT_AUTHORIZATION.CASTING_VIEW]), 
         'sessions':(JWT_AUTHORIZATION.is_authorized_action)(user_authorizations, JWT_AUTHORIZATION.SESSIONS_VIEW), 
         'images':(JWT_AUTHORIZATION.is_authorized_action)(user_authorizations, JWT_AUTHORIZATION.IMAGES_VIEW), 
         'image_resources':(JWT_AUTHORIZATION.is_authorized_action)(user_authorizations, JWT_AUTHORIZATION.IMAGES_MODIFY_RESOURCES), 
         'devapi':(JWT_AUTHORIZATION.is_authorized_action)(user_authorizations, JWT_AUTHORIZATION.DEVAPI_VIEW), 
         'branding':(JWT_AUTHORIZATION.is_authorized_action)(user_authorizations, JWT_AUTHORIZATION.BRANDINGS_VIEW), 
         'settings':(JWT_AUTHORIZATION.is_authorized_action)(user_authorizations, JWT_AUTHORIZATION.SETTINGS_VIEW), 
         'auth':(JWT_AUTHORIZATION.is_authorized_action)(user_authorizations, JWT_AUTHORIZATION.AUTH_VIEW), 
         'system':(JWT_AUTHORIZATION.is_authorized_action)(user_authorizations, JWT_AUTHORIZATION.SYSTEM_VIEW), 
         'system_config':(JWT_AUTHORIZATION.any_authorized_actions)(user_authorizations, [JWT_AUTHORIZATION.SYSTEM_VIEW, JWT_AUTHORIZATION.SYSTEM_EXPORT_DATA, JWT_AUTHORIZATION.SYSTEM_EXPORT_SCHEMA, JWT_AUTHORIZATION.SYSTEM_IMPORT_DATA]), 
         'license':(JWT_AUTHORIZATION.all_authorized_actions)(user_authorizations, [JWT_AUTHORIZATION.LICENSES_VIEW, JWT_AUTHORIZATION.SYSTEM_VIEW]), 
         'companies':(JWT_AUTHORIZATION.is_authorized_action)(user_authorizations, JWT_AUTHORIZATION.COMPANIES_VIEW), 
         'webfilter':(JWT_AUTHORIZATION.is_authorized_action)(user_authorizations, JWT_AUTHORIZATION.WEBFILTERS_VIEW), 
         'group_permissions':(JWT_AUTHORIZATION.is_authorized_action)(user_authorizations, JWT_AUTHORIZATION.GLOBAL_ADMIN), 
         'physical_tokens':(JWT_AUTHORIZATION.is_authorized_action)(user_authorizations, JWT_AUTHORIZATION.PHYSICAL_TOKENS_VIEW), 
         'registries':(JWT_AUTHORIZATION.all_authorized_actions)(user_authorizations, [JWT_AUTHORIZATION.REGISTRIES_VIEW, JWT_AUTHORIZATION.AGENTS_VIEW, JWT_AUTHORIZATION.SYSTEM_VIEW, JWT_AUTHORIZATION.IMAGES_VIEW]), 
         'pools':(JWT_AUTHORIZATION.is_authorized_action)(user_authorizations, JWT_AUTHORIZATION.SERVER_POOLS_VIEW), 
         'servers':(JWT_AUTHORIZATION.is_authorized_action)(user_authorizations, JWT_AUTHORIZATION.SERVERS_VIEW), 
         'autoscale':(JWT_AUTHORIZATION.all_authorized_actions)(user_authorizations, [JWT_AUTHORIZATION.AUTOSCALE_VIEW, JWT_AUTHORIZATION.SERVER_POOLS_VIEW]), 
         'autoscale_schedule':(JWT_AUTHORIZATION.all_authorized_actions)(user_authorizations, [JWT_AUTHORIZATION.AUTOSCALE_SCHEDULE_VIEW, JWT_AUTHORIZATION.SERVER_POOLS_VIEW]), 
         'dns_providers':(JWT_AUTHORIZATION.all_authorized_actions)(user_authorizations, [JWT_AUTHORIZATION.DNS_PROVIDERS_VIEW, JWT_AUTHORIZATION.SERVER_POOLS_VIEW]), 
         'storage_providers':(JWT_AUTHORIZATION.is_authorized_action)(user_authorizations, JWT_AUTHORIZATION.STORAGE_PROVIDERS_VIEW), 
         'connection_proxies':(JWT_AUTHORIZATION.is_authorized_action)(user_authorizations, JWT_AUTHORIZATION.CONNECTION_PROXY_VIEW), 
         'vm_providers':(JWT_AUTHORIZATION.all_authorized_actions)(user_authorizations, [JWT_AUTHORIZATION.VM_PROVIDER_VIEW, JWT_AUTHORIZATION.SERVER_POOLS_VIEW, JWT_AUTHORIZATION.AUTOSCALE_VIEW])}
        admin_dashboard = False
        for (k, v) in views.items():
            if not k != "user_dashboard":
                if v:
                    admin_dashboard = True
                views["admin_dashboard"] = admin_dashboard
                return views

    @staticmethod
    def summarize_authorizations(user_authorizations):
        authorizations = []
        if JWT_AUTHORIZATION.USER in user_authorizations:
            authorizations.append(JWT_AUTHORIZATION.USER)
        if JWT_AUTHORIZATION.GLOBAL_ADMIN in user_authorizations:
            authorizations.append(JWT_AUTHORIZATION.GLOBAL_ADMIN)
            return authorizations
        for authorization in user_authorizations:
            if authorization not in authorizations:
                authorizations.append(authorization)
            return authorizations

    @staticmethod
    def any_admin_action(requested_actions):
        for action in requested_actions:
            if int(action) >= 200:
                return True
            return False

    @staticmethod
    def is_authorized(authorization_provided_int, authorizations_needed):
        for enum_auth in JWT_AUTHORIZATION:
            if enum_auth.value == authorization_provided_int:
                return enum_auth in authorizations_needed
            return False

    @staticmethod
    def is_user_authorized_action(user, user_authorizations, requested_action, target_user=None, target_group=None, target_setting=None):
        if JWT_AUTHORIZATION.GLOBAL_ADMIN in user_authorizations:
            return True
        if_member_allowed_view = False
        if_member_allowed_modify = False
        if target_group:
            if user:
                for group in user.groups:
                    if group.group_id == target_group.group_id:
                        if_member_allowed_view = JWT_AUTHORIZATION.GROUPS_VIEW_IFMEMBER in user_authorizations
                        if_member_allowed_modify = JWT_AUTHORIZATION.GROUPS_MODIFY_IFMEMBER in user_authorizations

            if requested_action == JWT_AUTHORIZATION.GROUPS_MODIFY:
                if target_group:
                    if target_group.is_system:
                        return (JWT_AUTHORIZATION.GROUPS_MODIFY_SYSTEM in user_authorizations) and ((JWT_AUTHORIZATION.GROUPS_MODIFY in user_authorizations) or if_member_allowed_modify)
                    return JWT_AUTHORIZATION.GROUPS_MODIFY in user_authorizations or if_member_allowed_modify
                else:
                    return False
            elif requested_action == JWT_AUTHORIZATION.GROUPS_VIEW:
                if target_group:
                    if target_group.is_system:
                        return (JWT_AUTHORIZATION.GROUPS_VIEW_SYSTEM in user_authorizations) and ((JWT_AUTHORIZATION.GROUPS_VIEW in user_authorizations) or if_member_allowed_view)
                    return JWT_AUTHORIZATION.GROUPS_VIEW in user_authorizations or if_member_allowed_view
                else:
                    return False
            elif requested_action == JWT_AUTHORIZATION.USERS_MODIFY:
                if target_user:
                    if JWT_AUTHORIZATION.GLOBAL_ADMIN in target_user.get_authorizations():
                        return JWT_AUTHORIZATION.USERS_MODIFY_ADMIN in user_authorizations
                    return JWT_AUTHORIZATION.USERS_MODIFY in user_authorizations
                else:
                    return False
            elif requested_action == JWT_AUTHORIZATION.USERS_DELETE:
                if target_user:
                    if JWT_AUTHORIZATION.GLOBAL_ADMIN in target_user.get_authorizations():
                        return JWT_AUTHORIZATION.USERS_MODIFY_ADMIN in user_authorizations and JWT_AUTHORIZATION.USERS_DELETE in user_authorizations
                    return JWT_AUTHORIZATION.USERS_DELETE in user_authorizations
                else:
                    return False
            elif requested_action == JWT_AUTHORIZATION.SETTINGS_MODIFY:
                if JWT_AUTHORIZATION.SETTINGS_MODIFY in user_authorizations:
                    return True
                if target_setting:
                    if target_setting.category == "auth":
                        return JWT_AUTHORIZATION.SETTINGS_MODIFY_AUTH in user_authorizations
                    if target_setting.category == "connections":
                        return JWT_AUTHORIZATION.SETTINGS_MODIFY_CONNECTIONS in user_authorizations
                    if target_setting.category == "images":
                        return JWT_AUTHORIZATION.SETTINGS_MODIFY_IMAGES in user_authorizations
                    if target_setting.category == "licensing":
                        return JWT_AUTHORIZATION.SETTINGS_MODIFY_LICENSE in user_authorizations
                    if target_setting.category == "logging":
                        return JWT_AUTHORIZATION.SETTINGS_MODIFY_LOGGING in user_authorizations
                    if target_setting.category == "manager":
                        return JWT_AUTHORIZATION.SETTINGS_MODIFY_MANAGER in user_authorizations
                    if target_setting.category == "scale":
                        return JWT_AUTHORIZATION.SETTINGS_MODIFY_SCALE in user_authorizations
                    if target_setting.category == "storage":
                        return JWT_AUTHORIZATION.SETTINGS_MODIFY_STORAGE in user_authorizations
                    if target_setting.category == "theme":
                        return JWT_AUTHORIZATION.SETTINGS_MODIFY_THEME in user_authorizations
                    if target_setting.category == "web_filter":
                        return JWT_AUTHORIZATION.SETTINGS_MODIFY_FILTER in user_authorizations
                    return False
            return JWT_AUTHORIZATION.is_authorized_action(user_authorizations, requested_action)

    @staticmethod
    def is_authorized_action(user_authorizations, requested_action):
        if requested_action in user_authorizations:
            return True
        if int(requested_action) < 200:
            return False
        if JWT_AUTHORIZATION.GLOBAL_ADMIN in user_authorizations:
            return True
        return False

    @staticmethod
    def any_authorized_actions(user_authorizations, requested_actions):
        for action in requested_actions:
            if JWT_AUTHORIZATION.is_authorized_action(user_authorizations, action):
                return True
            return False

    @staticmethod
    def all_authorized_actions(user_authorizations, requested_actions):
        if JWT_AUTHORIZATION.GLOBAL_ADMIN in user_authorizations:
            return True
        for action in requested_actions:
            if action not in user_authorizations:
                return False
            return True


class STORAGE_PROVIDER_TYPES(StrEnum):
    OTHER = "Other"
    GOOGLE_DRIVE = "Google Drive"
    ONEDRIVE = "OneDrive"
    DROPBOX = "Dropbox"
    S3 = "S3"
    NEXTCLOUD = "Nextcloud"
    CUSTOM = "Custom"


class OS_TYPES(StrEnum):
    LINUX = "Linux"
    WINDOWS = "Windows"


class LANGUAGES(StrEnum):
    Afar0_Djibouti = "aa_DJ.UTF-8"
    Afar0_Eritrea = "aa_ER.UTF-8"
    Afar0_Ethiopia = "aa_ET.UTF-8"
    Afrikaans0_South_Africa = "af_ZA.UTF-8"
    Amharic0_Ethiopia = "am_ET.UTF-8"
    Aragonese0_Spain = "an_ES.UTF-8"
    Arabic0_United_Arab_Emirates = "ar_AE.UTF-8"
    Arabic0_Bahrain = "ar_BH.UTF-8"
    Arabic0_Algeria = "ar_DZ.UTF-8"
    Arabic0_Egypt = "ar_EG.UTF-8"
    Arabic0_India = "ar_IN.UTF-8"
    Arabic0_Iraq = "ar_IQ.UTF-8"
    Arabic0_Jordan = "ar_JO.UTF-8"
    Arabic0_Kuwait = "ar_KW.UTF-8"
    Arabic0_Lebanon = "ar_LB.UTF-8"
    Arabic0_Libyan_Arab_Jamahiriya = "ar_LY.UTF-8"
    Arabic0_Morocco = "ar_MA.UTF-8"
    Arabic0_Oman = "ar_OM.UTF-8"
    Arabic0_Qatar = "ar_QA.UTF-8"
    Arabic0_Saudi_Arabia = "ar_SA.UTF-8"
    Arabic0_Sudan = "ar_SD.UTF-8"
    Arabic0_Syrian_Arab_Republic = "ar_SY.UTF-8"
    Arabic0_Tunisia = "ar_TN.UTF-8"
    Arabic0_Yemen = "ar_YE.UTF-8"
    Assamese0_India = "as_IN.UTF-8"
    Asturian0_Spain = "ast_ES.UTF-8"
    Southern_Aymara0_Peru = "ayc_PE.UTF-8"
    Azerbaijani0_Azerbaijan = "az_AZ.UTF-8"
    Belarusian0_Belarus = "be_BY.UTF-8"
    Bemba0_Zambia = "bem_ZM.UTF-8"
    Berber0_Algeria = "ber_DZ.UTF-8"
    Berber0_Morocco = "ber_MA.UTF-8"
    Bulgarian0_Bulgaria = "bg_BG.UTF-8"
    Bhojpuri0_India = "bho_IN.UTF-8"
    Bengali0_Bangladesh = "bn_BD.UTF-8"
    Bengali0_India = "bn_IN.UTF-8"
    Tibetan0_China = "bo_CN.UTF-8"
    Tibetan0_India = "bo_IN.UTF-8"
    Breton0_France = "br_FR.UTF-8"
    Bodo0_India = "brx_IN.UTF-8"
    Bosnian0_Bosnia_and_Herzegovina = "bs_BA.UTF-8"
    Bilin0_Eritrea = "byn_ER.UTF-8"
    Catalan0_Andorra = "ca_AD.UTF-8"
    Catalan0_Spain = "ca_ES.UTF-8"
    Catalan0_France = "ca_FR.UTF-8"
    Catalan0_Italy = "ca_IT.UTF-8"
    Crimean_Tatar0_Ukraine = "crh_UA.UTF-8"
    Kashubian0_Poland = "csb_PL.UTF-8"
    Czech0_Czechia = "cs_CZ.UTF-8"
    Chuvash0_Russian_Federation = "cv_RU.UTF-8"
    Welsh0_United_Kingdom = "cy_GB.UTF-8"
    Danish0_Denmark = "da_DK.UTF-8"
    German0_Austria = "de_AT.UTF-8"
    German0_Belgium = "de_BE.UTF-8"
    German0_Switzerland = "de_CH.UTF-8"
    German0_Germany = "de_DE.UTF-8"
    German0_Luxembourg = "de_LU.UTF-8"
    Dogri0_India = "doi_IN.UTF-8"
    Dhivehi0_Maldives = "dv_MV.UTF-8"
    Dzongkha0_Bhutan = "dz_BT.UTF-8"
    Modern_Greek0_Cyprus = "el_CY.UTF-8"
    Modern_Greek0_Greece = "el_GR.UTF-8"
    English0_Antigua_and_Barbuda = "en_AG.UTF-8"
    English0_Australia = "en_AU.UTF-8"
    English0_Botswana = "en_BW.UTF-8"
    English0_Canada = "en_CA.UTF-8"
    English0_Denmark = "en_DK.UTF-8"
    English0_United_Kingdom = "en_GB.UTF-8"
    English0_Hong_Kong = "en_HK.UTF-8"
    English0_Ireland = "en_IE.UTF-8"
    English0_India = "en_IN.UTF-8"
    English0_Nigeria = "en_NG.UTF-8"
    English0_New_Zealand = "en_NZ.UTF-8"
    English0_Philippines = "en_PH.UTF-8"
    English0_Singapore = "en_SG.UTF-8"
    English0_United_States_of_America = "en_US.UTF-8"
    English0_South_Africa = "en_ZA.UTF-8"
    English0_Zambia = "en_ZM.UTF-8"
    English0_Zimbabwe = "en_ZW.UTF-8"
    Spanish0_Argentina = "es_AR.UTF-8"
    Spanish0_Bolivia = "es_BO.UTF-8"
    Spanish0_Chile = "es_CL.UTF-8"
    Spanish0_Colombia = "es_CO.UTF-8"
    Spanish0_Costa_Rica = "es_CR.UTF-8"
    Spanish0_Cuba = "es_CU.UTF-8"
    Spanish0_Dominican_Republic = "es_DO.UTF-8"
    Spanish0_Ecuador = "es_EC.UTF-8"
    Spanish0_Spain = "es_ES.UTF-8"
    Spanish0_Guatemala = "es_GT.UTF-8"
    Spanish0_Honduras = "es_HN.UTF-8"
    Spanish0_Mexico = "es_MX.UTF-8"
    Spanish0_Nicaragua = "es_NI.UTF-8"
    Spanish0_Panama = "es_PA.UTF-8"
    Spanish0_Peru = "es_PE.UTF-8"
    Spanish0_Puerto_Rico = "es_PR.UTF-8"
    Spanish0_Paraguay = "es_PY.UTF-8"
    Spanish0_El_Salvador = "es_SV.UTF-8"
    Spanish0_United_States_of_America = "es_US.UTF-8"
    Spanish0_Uruguay = "es_UY.UTF-8"
    Spanish0_Venezuela = "es_VE.UTF-8"
    Estonian0_Estonia = "et_EE.UTF-8"
    Basque0_Spain = "eu_ES.UTF-8"
    Persian0_Iran = "fa_IR.UTF-8"
    Fulah0_Senegal = "ff_SN.UTF-8"
    Finnish0_Finland = "fi_FI.UTF-8"
    Filipino0_Philippines = "fil_PH.UTF-8"
    Faroese0_Faroe_Islands = "fo_FO.UTF-8"
    French0_Belgium = "fr_BE.UTF-8"
    French0_Canada = "fr_CA.UTF-8"
    French0_Switzerland = "fr_CH.UTF-8"
    French0_France = "fr_FR.UTF-8"
    French0_Luxembourg = "fr_LU.UTF-8"
    Friulian0_Italy = "fur_IT.UTF-8"
    Western_Frisian0_Germany = "fy_DE.UTF-8"
    Western_Frisian0_Neatherlands = "fy_NL.UTF-8"
    Irish0_Ireland = "ga_IE.UTF-8"
    Scottish_Gaelic0_United_Kingdom = "gd_GB.UTF-8"
    Geez0_Eritrea = "gez_ER.UTF-8"
    Geez0_Ethiopia = "gez_ET.UTF-8"
    Galician0_Spain = "gl_ES.UTF-8"
    Gujarati0_India = "gu_IN.UTF-8"
    Manx0_United_Kingdom = "gv_GB.UTF-8"
    Hausa0_Nigeria = "ha_NG.UTF-8"
    Hebrew0_Israel = "he_IL.UTF-8"
    Hindi0_India = "hi_IN.UTF-8"
    Chhattisgarhi0_India = "hne_IN.UTF-8"
    Croatian0_Croatia = "hr_HR.UTF-8"
    Upper_Sorbian0_Germany = "hsb_DE.UTF-8"
    Haitian0_Haiti = "ht_HT.UTF-8"
    Hungarian0_Hungary = "hu_HU.UTF-8"
    Armenian0_Armenia = "hy_AM.UTF-8"
    Interlingua0_France = "ia_FR.UTF-8"
    Indonesian0_Indonesia = "id_ID.UTF-8"
    Igbo0_Nigeria = "ig_NG.UTF-8"
    Inupiaq0_Canada = "ik_CA.UTF-8"
    Icelandic0_Iceland = "is_IS.UTF-8"
    Italian0_Switzerland = "it_CH.UTF-8"
    Italian0_Italy = "it_IT.UTF-8"
    Inuktitut0_Canada = "iu_CA.UTF-8"
    Japanese0_Japan = "ja_JP.UTF-8"
    Georgian0_Georgia = "ka_GE.UTF-8"
    Kazakh0_Kazakhstan = "kk_KZ.UTF-8"
    Kalaallisut0_Greenland = "kl_GL.UTF-8"
    Central_Khmer0_Cambodia = "km_KH.UTF-8"
    Kannada0_India = "kn_IN.UTF-8"
    Konkani0_India = "kok_IN.UTF-8"
    Korean0_Republic_of_Korea = "ko_KR.UTF-8"
    Kashmiri0_India = "ks_IN.UTF-8"
    Kurdish0_Turkey = "ku_TR.UTF-8"
    Cornish0_United_Kingdom = "kw_GB.UTF-8"
    Kirghiz0_Kyrgyzstan = "ky_KG.UTF-8"
    Luxembourgish0_Luxembourg = "lb_LU.UTF-8"
    Ganda0_Uganda = "lg_UG.UTF-8"
    Limburgan0_Belgium = "li_BE.UTF-8"
    Ligurian0_Italy = "lij_IT.UTF-8"
    Limburgan0_Netherlands = "li_NL.UTF-8"
    Lao0_Lao_Peoples_Democratic_Republic = "lo_LA.UTF-8"
    Lithuanian0_Lithuania = "lt_LT.UTF-8"
    Latvian0_Latvia = "lv_LV.UTF-8"
    Magahi0_India = "mag_IN.UTF-8"
    Maithili0_India = "mai_IN.UTF-8"
    Malagasy0_Madagascar = "mg_MG.UTF-8"
    Eastern_Mari0_Russian_Federation = "mhr_RU.UTF-8"
    Maori0_New_Zealand = "mi_NZ.UTF-8"
    Macedonian0_Macedonia = "mk_MK.UTF-8"
    Malayalam0_India = "ml_IN.UTF-8"
    Manipuri0_India = "mni_IN.UTF-8"
    Mongolian0_Mongolia = "mn_MN.UTF-8"
    Marathi0_India = "mr_IN.UTF-8"
    Malay0_Malaysia = "ms_MY.UTF-8"
    Maltese0_Malta = "mt_MT.UTF-8"
    Burmese0_Myanmar = "my_MM.UTF-8"
    Norwegian_Bokmal0_Norway = "nb_NO.UTF-8"
    Low_German0_Germany = "nds_DE.UTF-8"
    Low_German0_Netherlands = "nds_NL.UTF-8"
    Nepali0_Nepal = "ne_NP.UTF-8"
    Central_Nahuatl0_Mexico = "nhn_MX.UTF-8"
    Niuean0_Niue = "niu_NU.UTF-8"
    Niuean0_New_Zealand = "niu_NZ.UTF-8"
    Dutch0_Aruba = "nl_AW.UTF-8"
    Dutch0_Belgium = "nl_BE.UTF-8"
    Dutch0_Netherlands = "nl_NL.UTF-8"
    Norwegian_Nynorsk0_Norway = "nn_NO.UTF-8"
    South_Ndebele0_South_Africa = "nr_ZA.UTF-8"
    Pedi0_South_Africa = "nso_ZA.UTF-8"
    Occitan0_France = "oc_FR.UTF-8"
    Oromo0_Ethiopia = "om_ET.UTF-8"
    Oromo0_Kenya = "om_KE.UTF-8"
    Oriya0_India = "or_IN.UTF-8"
    Ossetian0_Russian_Federation = "os_RU.UTF-8"
    Panjabi0_India = "pa_IN.UTF-8"
    Panjabi0_Pakistan = "pa_PK.UTF-8"
    Polish0_Poland = "pl_PL.UTF-8"
    Pushto0_Afghanistan = "ps_AF.UTF-8"
    Portuguese0_Brazil = "pt_BR.UTF-8"
    Portuguese0_Portugal = "pt_PT.UTF-8"
    Romanian0_Romania = "ro_RO.UTF-8"
    Russian0_Russian_Federation = "ru_RU.UTF-8"
    Russian0_Ukraine = "ru_UA.UTF-8"
    Kinyarwanda0_Rwanda = "rw_RW.UTF-8"
    Sanskirt0_India = "sa_IN.UTF-8"
    Santali0_India = "sat_IN.UTF-8"
    Sardinian0_Italy = "sc_IT.UTF-8"
    Sindhi0_India = "sd_IN.UTF-8"
    Northern_Sami0_Norway = "se_NO.UTF-8"
    Shuswap0_Canada = "shs_CA.UTF-8"
    Sidamo0_Ethiopia = "sid_ET.UTF-8"
    Sinhala0_Sri_Lanka = "si_LK.UTF-8"
    Slovak0_Slovakia = "sk_SK.UTF-8"
    Slovenian0_Slovenia = "sl_SI.UTF-8"
    Somali0_Djibouti = "so_DJ.UTF-8"
    Somali0_Ethiopia = "so_ET.UTF-8"
    Somali0_Kenya = "so_KE.UTF-8"
    Somali0_Somalia = "so_SO.UTF-8"
    Albanian0_Albania = "sq_AL.UTF-8"
    Albanian0_Macedonia = "sq_MK.UTF-8"
    Serbian0_Montenegro = "sr_ME.UTF-8"
    Serbian0_Serbia = "sr_RS.UTF-8"
    Swati0_South_Africa = "ss_ZA.UTF-8"
    Southern_Sotho0_South_Africa = "st_ZA.UTF-8"
    Swedish0_Finland = "sv_FI.UTF-8"
    Swedish0_Sweden = "sv_SE.UTF-8"
    Swahili0_Kenya = "sw_KE.UTF-8"
    Swahili0_Tanzania = "sw_TZ.UTF-8"
    Silesian0_Poland = "szl_PL.UTF-8"
    Tamil0_India = "ta_IN.UTF-8"
    Tamil0_Sri_Lanka = "ta_LK.UTF-8"
    Telugu0_India = "te_IN.UTF-8"
    Tajik0_Tajikistan = "tg_TJ.UTF-8"
    Thai0_Thailand = "th_TH.UTF-8"
    Tigrinya0_Eritrea = "ti_ER.UTF-8"
    Tigrinya0_Ethiopia = "ti_ET.UTF-8"
    Tigre0_Eritrea = "tig_ER.UTF-8"
    Turkmen0_Turkmenistan = "tk_TM.UTF-8"
    Tagalog0_Philippines = "tl_PH.UTF-8"
    Tswana0_South_Africa = "tn_ZA.UTF-8"
    Turkish0_Cyprus = "tr_CY.UTF-8"
    Turkish0_Turkey = "tr_TR.UTF-8"
    Tsonga0_South_Africa = "ts_ZA.UTF-8"
    Tatar0_Russian_Federation = "tt_RU.UTF-8"
    Uighur0_China = "ug_CN.UTF-8"
    Ukrainian0_Ukraine = "uk_UA.UTF-8"
    Unami0_United_States_of_America = "unm_US.UTF-8"
    Urdu0_India = "ur_IN.UTF-8"
    Urdu0_Pakistan = "ur_PK.UTF-8"
    Uzbek0_Uzbekistan = "uz_UZ.UTF-8"
    Venda0_South_Africa = "ve_ZA.UTF-8"
    Vietnamese0_Viet_Nam = "vi_VN.UTF-8"
    Walloon0_Belgium = "wa_BE.UTF-8"
    Walser0_Switzerland = "wae_CH.UTF-8"
    Wolaytta0_Ethiopia = "wal_ET.UTF-8"
    Wolof0_Senegal = "wo_SN.UTF-8"
    Xhosa0_South_Africa = "xh_ZA.UTF-8"
    Yiddish0_United_States_of_America = "yi_US.UTF-8"
    Yoruba0_Nigeria = "yo_NG.UTF-8"
    Yue_Chinese0_Hong_Kong = "yue_HK.UTF-8"
    Chinese0_China = "zh_CN.UTF-8"
    Chinese0_Hong_Kong = "zh_HK.UTF-8"
    Chinese0_Singapore = "zh_SG.UTF-8"
    Chinese0_Taiwan = "zh_TW.UTF-8"
    Zulu0_South_Africa = "zu_ZA.UTF-8"


class TIMEZONES(StrEnum):
    UTCplus00___00 = "Etc/UTC"
    UTCplus01___00_Europe__Andorra = "Europe/Andorra"
    UTCplus04___00_Asia__Dubai = "Asia/Dubai"
    UTCplus04___30_Asia__Kabul = "Asia/Kabul"
    UTCplus01___00_Europe__Tirane = "Europe/Tirane"
    UTCplus04___00_Asia__Yerevan = "Asia/Yerevan"
    UTCplus11___00_Antarctica__Casey = "Antarctica/Casey"
    UTCplus07___00_Antarctica__Davis = "Antarctica/Davis"
    UTCplus10___00_Antarctica__DumontDUrville = "Antarctica/DumontDUrville"
    UTCplus05___00_Antarctica__Mawson = "Antarctica/Mawson"
    UTCminus03___00_Antarctica__Palmer = "Antarctica/Palmer"
    UTCminus03___00_Antarctica__Rothera = "Antarctica/Rothera"
    UTCplus03___00_Antarctica__Syowa = "Antarctica/Syowa"
    UTCplus00___00_Antarctica__Troll = "Antarctica/Troll"
    UTCplus06___00_Antarctica__Vostok = "Antarctica/Vostok"
    UTCminus03___00_America__Argentina__Buenos_Aires = "America/Argentina/Buenos_Aires"
    UTCminus03___00_America__Argentina__Cordoba = "America/Argentina/Cordoba"
    UTCminus03___00_America__Argentina__Salta = "America/Argentina/Salta"
    UTCminus03___00_America__Argentina__Jujuy = "America/Argentina/Jujuy"
    UTCminus03___00_America__Argentina__Tucuman = "America/Argentina/Tucuman"
    UTCminus03___00_America__Argentina__Catamarca = "America/Argentina/Catamarca"
    UTCminus03___00_America__Argentina__La_Rioja = "America/Argentina/La_Rioja"
    UTCminus03___00_America__Argentina__San_Juan = "America/Argentina/San_Juan"
    UTCminus03___00_America__Argentina__Mendoza = "America/Argentina/Mendoza"
    UTCminus03___00_America__Argentina__San_Luis = "America/Argentina/San_Luis"
    UTCminus03___00_America__Argentina__Rio_Gallegos = "America/Argentina/Rio_Gallegos"
    UTCminus03___00_America__Argentina__Ushuaia = "America/Argentina/Ushuaia"
    UTCminus11___00_Pacific__Pago_Pago = "Pacific/Pago_Pago"
    UTCplus01___00_Europe__Vienna = "Europe/Vienna"
    UTCplus10___30_Australia__Lord_Howe = "Australia/Lord_Howe"
    UTCplus10___00_Antarctica__Macquarie = "Antarctica/Macquarie"
    UTCplus10___00_Australia__Hobart = "Australia/Hobart"
    UTCplus10___00_Australia__Melbourne = "Australia/Melbourne"
    UTCplus10___00_Australia__Sydney = "Australia/Sydney"
    UTCplus09___30_Australia__Broken_Hill = "Australia/Broken_Hill"
    UTCplus10___00_Australia__Brisbane = "Australia/Brisbane"
    UTCplus10___00_Australia__Lindeman = "Australia/Lindeman"
    UTCplus09___30_Australia__Adelaide = "Australia/Adelaide"
    UTCplus09___30_Australia__Darwin = "Australia/Darwin"
    UTCplus08___00_Australia__Perth = "Australia/Perth"
    UTCplus08___45_Australia__Eucla = "Australia/Eucla"
    UTCplus04___00_Asia__Baku = "Asia/Baku"
    UTCminus04___00_America__Barbados = "America/Barbados"
    UTCplus06___00_Asia__Dhaka = "Asia/Dhaka"
    UTCplus01___00_Europe__Brussels = "Europe/Brussels"
    UTCplus02___00_Europe__Sofia = "Europe/Sofia"
    UTCminus04___00_Atlantic__Bermuda = "Atlantic/Bermuda"
    UTCplus08___00_Asia__Brunei = "Asia/Brunei"
    UTCminus04___00_America__La_Paz = "America/La_Paz"
    UTCminus02___00_America__Noronha = "America/Noronha"
    UTCminus03___00_America__Belem = "America/Belem"
    UTCminus03___00_America__Fortaleza = "America/Fortaleza"
    UTCminus03___00_America__Recife = "America/Recife"
    UTCminus03___00_America__Araguaina = "America/Araguaina"
    UTCminus03___00_America__Maceio = "America/Maceio"
    UTCminus03___00_America__Bahia = "America/Bahia"
    UTCminus03___00_America__Sao_Paulo = "America/Sao_Paulo"
    UTCminus04___00_America__Campo_Grande = "America/Campo_Grande"
    UTCminus04___00_America__Cuiaba = "America/Cuiaba"
    UTCminus03___00_America__Santarem = "America/Santarem"
    UTCminus04___00_America__Porto_Velho = "America/Porto_Velho"
    UTCminus04___00_America__Boa_Vista = "America/Boa_Vista"
    UTCminus04___00_America__Manaus = "America/Manaus"
    UTCminus05___00_America__Eirunepe = "America/Eirunepe"
    UTCminus05___00_America__Rio_Branco = "America/Rio_Branco"
    UTCminus05___00_America__Nassau = "America/Nassau"
    UTCplus06___00_Asia__Thimphu = "Asia/Thimphu"
    UTCplus03___00_Europe__Minsk = "Europe/Minsk"
    UTCminus06___00_America__Belize = "America/Belize"
    UTCminus03___30_America__St_Johns = "America/St_Johns"
    UTCminus04___00_America__Halifax = "America/Halifax"
    UTCminus04___00_America__Glace_Bay = "America/Glace_Bay"
    UTCminus04___00_America__Moncton = "America/Moncton"
    UTCminus04___00_America__Goose_Bay = "America/Goose_Bay"
    UTCminus04___00_America__Blanc_Sablon = "America/Blanc-Sablon"
    UTCminus05___00_America__Toronto = "America/Toronto"
    UTCminus05___00_America__Nipigon = "America/Nipigon"
    UTCminus05___00_America__Thunder_Bay = "America/Thunder_Bay"
    UTCminus05___00_America__Iqaluit = "America/Iqaluit"
    UTCminus05___00_America__Pangnirtung = "America/Pangnirtung"
    UTCminus05___00_America__Atikokan = "America/Atikokan"
    UTCminus06___00_America__Winnipeg = "America/Winnipeg"
    UTCminus06___00_America__Rainy_River = "America/Rainy_River"
    UTCminus06___00_America__Resolute = "America/Resolute"
    UTCminus06___00_America__Rankin_Inlet = "America/Rankin_Inlet"
    UTCminus06___00_America__Regina = "America/Regina"
    UTCminus06___00_America__Swift_Current = "America/Swift_Current"
    UTCminus07___00_America__Edmonton = "America/Edmonton"
    UTCminus07___00_America__Cambridge_Bay = "America/Cambridge_Bay"
    UTCminus07___00_America__Yellowknife = "America/Yellowknife"
    UTCminus07___00_America__Inuvik = "America/Inuvik"
    UTCminus07___00_America__Creston = "America/Creston"
    UTCminus07___00_America__Dawson_Creek = "America/Dawson_Creek"
    UTCminus07___00_America__Fort_Nelson = "America/Fort_Nelson"
    UTCminus07___00_America__Whitehorse = "America/Whitehorse"
    UTCminus07___00_America__Dawson = "America/Dawson"
    UTCminus08___00_America__Vancouver = "America/Vancouver"
    UTCplus06___30_Indian__Cocos = "Indian/Cocos"
    UTCplus01___00_Europe__Zurich = "Europe/Zurich"
    UTCplus00___00_Africa__Abidjan = "Africa/Abidjan"
    UTCminus10___00_Pacific__Rarotonga = "Pacific/Rarotonga"
    UTCminus04___00_America__Santiago = "America/Santiago"
    UTCminus03___00_America__Punta_Arenas = "America/Punta_Arenas"
    UTCminus06___00_Pacific__Easter = "Pacific/Easter"
    UTCplus08___00_Asia__Shanghai = "Asia/Shanghai"
    UTCplus06___00_Asia__Urumqi = "Asia/Urumqi"
    UTCminus05___00_America__Bogota = "America/Bogota"
    UTCminus06___00_America__Costa_Rica = "America/Costa_Rica"
    UTCminus05___00_America__Havana = "America/Havana"
    UTCminus01___00_Atlantic__Cape_Verde = "Atlantic/Cape_Verde"
    UTCminus04___00_America__Curacao = "America/Curacao"
    UTCplus07___00_Indian__Christmas = "Indian/Christmas"
    UTCplus02___00_Asia__Nicosia = "Asia/Nicosia"
    UTCplus02___00_Asia__Famagusta = "Asia/Famagusta"
    UTCplus01___00_Europe__Prague = "Europe/Prague"
    UTCplus01___00_Europe__Berlin = "Europe/Berlin"
    UTCplus01___00_Europe__Copenhagen = "Europe/Copenhagen"
    UTCminus04___00_America__Santo_Domingo = "America/Santo_Domingo"
    UTCplus01___00_Africa__Algiers = "Africa/Algiers"
    UTCminus05___00_America__Guayaquil = "America/Guayaquil"
    UTCminus06___00_Pacific__Galapagos = "Pacific/Galapagos"
    UTCplus02___00_Europe__Tallinn = "Europe/Tallinn"
    UTCplus02___00_Africa__Cairo = "Africa/Cairo"
    UTCplus01___00_Africa__El_Aaiun = "Africa/El_Aaiun"
    UTCplus01___00_Europe__Madrid = "Europe/Madrid"
    UTCplus01___00_Africa__Ceuta = "Africa/Ceuta"
    UTCplus00___00_Atlantic__Canary = "Atlantic/Canary"
    UTCplus02___00_Europe__Helsinki = "Europe/Helsinki"
    UTCplus12___00_Pacific__Fiji = "Pacific/Fiji"
    UTCminus03___00_Atlantic__Stanley = "Atlantic/Stanley"
    UTCplus10___00_Pacific__Chuuk = "Pacific/Chuuk"
    UTCplus11___00_Pacific__Pohnpei = "Pacific/Pohnpei"
    UTCplus11___00_Pacific__Kosrae = "Pacific/Kosrae"
    UTCplus00___00_Atlantic__Faroe = "Atlantic/Faroe"
    UTCplus01___00_Europe__Paris = "Europe/Paris"
    UTCplus00___00_Europe__London = "Europe/London"
    UTCplus04___00_Asia__Tbilisi = "Asia/Tbilisi"
    UTCminus03___00_America__Cayenne = "America/Cayenne"
    UTCplus00___00_Africa__Accra = "Africa/Accra"
    UTCplus01___00_Europe__Gibraltar = "Europe/Gibraltar"
    UTCminus02___00_America__Nuuk = "America/Nuuk"
    UTCplus00___00_America__Danmarkshavn = "America/Danmarkshavn"
    UTCminus01___00_America__Scoresbysund = "America/Scoresbysund"
    UTCminus04___00_America__Thule = "America/Thule"
    UTCplus02___00_Europe__Athens = "Europe/Athens"
    UTCminus02___00_Atlantic__South_Georgia = "Atlantic/South_Georgia"
    UTCminus06___00_America__Guatemala = "America/Guatemala"
    UTCplus10___00_Pacific__Guam = "Pacific/Guam"
    UTCplus00___00_Africa__Bissau = "Africa/Bissau"
    UTCminus04___00_America__Guyana = "America/Guyana"
    UTCplus08___00_Asia__Hong_Kong = "Asia/Hong_Kong"
    UTCminus06___00_America__Tegucigalpa = "America/Tegucigalpa"
    UTCminus05___00_America__Port_au_Prince = "America/Port-au-Prince"
    UTCplus01___00_Europe__Budapest = "Europe/Budapest"
    UTCplus07___00_Asia__Jakarta = "Asia/Jakarta"
    UTCplus07___00_Asia__Pontianak = "Asia/Pontianak"
    UTCplus08___00_Asia__Makassar = "Asia/Makassar"
    UTCplus09___00_Asia__Jayapura = "Asia/Jayapura"
    UTCplus01___00_Europe__Dublin = "Europe/Dublin"
    UTCplus02___00_Asia__Jerusalem = "Asia/Jerusalem"
    UTCplus05___30_Asia__Kolkata = "Asia/Kolkata"
    UTCplus06___00_Indian__Chagos = "Indian/Chagos"
    UTCplus03___00_Asia__Baghdad = "Asia/Baghdad"
    UTCplus03___30_Asia__Tehran = "Asia/Tehran"
    UTCplus00___00_Atlantic__Reykjavik = "Atlantic/Reykjavik"
    UTCplus01___00_Europe__Rome = "Europe/Rome"
    UTCminus05___00_America__Jamaica = "America/Jamaica"
    UTCplus03___00_Asia__Amman = "Asia/Amman"
    UTCplus09___00_Asia__Tokyo = "Asia/Tokyo"
    UTCplus03___00_Africa__Nairobi = "Africa/Nairobi"
    UTCplus06___00_Asia__Bishkek = "Asia/Bishkek"
    UTCplus12___00_Pacific__Tarawa = "Pacific/Tarawa"
    UTCplus13___00_Pacific__Enderbury = "Pacific/Enderbury"
    UTCplus14___00_Pacific__Kiritimati = "Pacific/Kiritimati"
    UTCplus09___00_Asia__Pyongyang = "Asia/Pyongyang"
    UTCplus09___00_Asia__Seoul = "Asia/Seoul"
    UTCplus06___00_Asia__Almaty = "Asia/Almaty"
    UTCplus05___00_Asia__Qyzylorda = "Asia/Qyzylorda"
    UTCplus06___00_Asia__Qostanay = "Asia/Qostanay"
    UTCplus05___00_Asia__Aqtobe = "Asia/Aqtobe"
    UTCplus05___00_Asia__Aqtau = "Asia/Aqtau"
    UTCplus05___00_Asia__Atyrau = "Asia/Atyrau"
    UTCplus05___00_Asia__Oral = "Asia/Oral"
    UTCplus02___00_Asia__Beirut = "Asia/Beirut"
    UTCplus05___30_Asia__Colombo = "Asia/Colombo"
    UTCplus00___00_Africa__Monrovia = "Africa/Monrovia"
    UTCplus02___00_Europe__Vilnius = "Europe/Vilnius"
    UTCplus01___00_Europe__Luxembourg = "Europe/Luxembourg"
    UTCplus02___00_Europe__Riga = "Europe/Riga"
    UTCplus02___00_Africa__Tripoli = "Africa/Tripoli"
    UTCplus01___00_Africa__Casablanca = "Africa/Casablanca"
    UTCplus01___00_Europe__Monaco = "Europe/Monaco"
    UTCplus02___00_Europe__Chisinau = "Europe/Chisinau"
    UTCplus12___00_Pacific__Majuro = "Pacific/Majuro"
    UTCplus12___00_Pacific__Kwajalein = "Pacific/Kwajalein"
    UTCplus06___30_Asia__Yangon = "Asia/Yangon"
    UTCplus08___00_Asia__Ulaanbaatar = "Asia/Ulaanbaatar"
    UTCplus07___00_Asia__Hovd = "Asia/Hovd"
    UTCplus08___00_Asia__Choibalsan = "Asia/Choibalsan"
    UTCplus08___00_Asia__Macau = "Asia/Macau"
    UTCminus04___00_America__Martinique = "America/Martinique"
    UTCplus01___00_Europe__Malta = "Europe/Malta"
    UTCplus04___00_Indian__Mauritius = "Indian/Mauritius"
    UTCplus05___00_Indian__Maldives = "Indian/Maldives"
    UTCminus06___00_America__Mexico_City = "America/Mexico_City"
    UTCminus05___00_America__Cancun = "America/Cancun"
    UTCminus06___00_America__Merida = "America/Merida"
    UTCminus06___00_America__Monterrey = "America/Monterrey"
    UTCminus06___00_America__Matamoros = "America/Matamoros"
    UTCminus07___00_America__Mazatlan = "America/Mazatlan"
    UTCminus06___00_America__Chihuahua = "America/Chihuahua"
    UTCminus06___00_America__Ojinaga = "America/Ojinaga"
    UTCminus07___00_America__Hermosillo = "America/Hermosillo"
    UTCminus08___00_America__Tijuana = "America/Tijuana"
    UTCminus06___00_America__Bahia_Banderas = "America/Bahia_Banderas"
    UTCplus08___00_Asia__Kuala_Lumpur = "Asia/Kuala_Lumpur"
    UTCplus08___00_Asia__Kuching = "Asia/Kuching"
    UTCplus02___00_Africa__Maputo = "Africa/Maputo"
    UTCplus02___00_Africa__Windhoek = "Africa/Windhoek"
    UTCplus11___00_Pacific__Noumea = "Pacific/Noumea"
    UTCplus11___00_Pacific__Norfolk = "Pacific/Norfolk"
    UTCplus01___00_Africa__Lagos = "Africa/Lagos"
    UTCminus06___00_America__Managua = "America/Managua"
    UTCplus01___00_Europe__Amsterdam = "Europe/Amsterdam"
    UTCplus01___00_Europe__Oslo = "Europe/Oslo"
    UTCplus05___45_Asia__Kathmandu = "Asia/Kathmandu"
    UTCplus12___00_Pacific__Nauru = "Pacific/Nauru"
    UTCminus11___00_Pacific__Niue = "Pacific/Niue"
    UTCplus12___00_Pacific__Auckland = "Pacific/Auckland"
    UTCplus12___45_Pacific__Chatham = "Pacific/Chatham"
    UTCminus05___00_America__Panama = "America/Panama"
    UTCminus05___00_America__Lima = "America/Lima"
    UTCminus10___00_Pacific__Tahiti = "Pacific/Tahiti"
    UTCminus09___30_Pacific__Marquesas = "Pacific/Marquesas"
    UTCminus09___00_Pacific__Gambier = "Pacific/Gambier"
    UTCplus10___00_Pacific__Port_Moresby = "Pacific/Port_Moresby"
    UTCplus11___00_Pacific__Bougainville = "Pacific/Bougainville"
    UTCplus08___00_Asia__Manila = "Asia/Manila"
    UTCplus05___00_Asia__Karachi = "Asia/Karachi"
    UTCplus01___00_Europe__Warsaw = "Europe/Warsaw"
    UTCminus03___00_America__Miquelon = "America/Miquelon"
    UTCminus08___00_Pacific__Pitcairn = "Pacific/Pitcairn"
    UTCminus04___00_America__Puerto_Rico = "America/Puerto_Rico"
    UTCplus02___00_Asia__Gaza = "Asia/Gaza"
    UTCplus02___00_Asia__Hebron = "Asia/Hebron"
    UTCplus00___00_Europe__Lisbon = "Europe/Lisbon"
    UTCplus00___00_Atlantic__Madeira = "Atlantic/Madeira"
    UTCminus01___00_Atlantic__Azores = "Atlantic/Azores"
    UTCplus09___00_Pacific__Palau = "Pacific/Palau"
    UTCminus04___00_America__Asuncion = "America/Asuncion"
    UTCplus03___00_Asia__Qatar = "Asia/Qatar"
    UTCplus04___00_Indian__Reunion = "Indian/Reunion"
    UTCplus02___00_Europe__Bucharest = "Europe/Bucharest"
    UTCplus01___00_Europe__Belgrade = "Europe/Belgrade"
    UTCplus02___00_Europe__Kaliningrad = "Europe/Kaliningrad"
    UTCplus03___00_Europe__Moscow = "Europe/Moscow"
    UTCplus03___00_Europe__Simferopol = "Europe/Simferopol"
    UTCplus03___00_Europe__Kirov = "Europe/Kirov"
    UTCplus03___00_Europe__Volgograd = "Europe/Volgograd"
    UTCplus04___00_Europe__Astrakhan = "Europe/Astrakhan"
    UTCplus04___00_Europe__Saratov = "Europe/Saratov"
    UTCplus04___00_Europe__Ulyanovsk = "Europe/Ulyanovsk"
    UTCplus04___00_Europe__Samara = "Europe/Samara"
    UTCplus05___00_Asia__Yekaterinburg = "Asia/Yekaterinburg"
    UTCplus06___00_Asia__Omsk = "Asia/Omsk"
    UTCplus07___00_Asia__Novosibirsk = "Asia/Novosibirsk"
    UTCplus07___00_Asia__Barnaul = "Asia/Barnaul"
    UTCplus07___00_Asia__Tomsk = "Asia/Tomsk"
    UTCplus07___00_Asia__Novokuznetsk = "Asia/Novokuznetsk"
    UTCplus07___00_Asia__Krasnoyarsk = "Asia/Krasnoyarsk"
    UTCplus08___00_Asia__Irkutsk = "Asia/Irkutsk"
    UTCplus09___00_Asia__Chita = "Asia/Chita"
    UTCplus09___00_Asia__Yakutsk = "Asia/Yakutsk"
    UTCplus09___00_Asia__Khandyga = "Asia/Khandyga"
    UTCplus10___00_Asia__Vladivostok = "Asia/Vladivostok"
    UTCplus10___00_Asia__Ust_Nera = "Asia/Ust-Nera"
    UTCplus11___00_Asia__Magadan = "Asia/Magadan"
    UTCplus11___00_Asia__Sakhalin = "Asia/Sakhalin"
    UTCplus11___00_Asia__Srednekolymsk = "Asia/Srednekolymsk"
    UTCplus12___00_Asia__Kamchatka = "Asia/Kamchatka"
    UTCplus12___00_Asia__Anadyr = "Asia/Anadyr"
    UTCplus03___00_Asia__Riyadh = "Asia/Riyadh"
    UTCplus11___00_Pacific__Guadalcanal = "Pacific/Guadalcanal"
    UTCplus04___00_Indian__Mahe = "Indian/Mahe"
    UTCplus02___00_Africa__Khartoum = "Africa/Khartoum"
    UTCplus01___00_Europe__Stockholm = "Europe/Stockholm"
    UTCplus08___00_Asia__Singapore = "Asia/Singapore"
    UTCminus03___00_America__Paramaribo = "America/Paramaribo"
    UTCplus02___00_Africa__Juba = "Africa/Juba"
    UTCplus00___00_Africa__Sao_Tome = "Africa/Sao_Tome"
    UTCminus06___00_America__El_Salvador = "America/El_Salvador"
    UTCplus03___00_Asia__Damascus = "Asia/Damascus"
    UTCminus05___00_America__Grand_Turk = "America/Grand_Turk"
    UTCplus01___00_Africa__Ndjamena = "Africa/Ndjamena"
    UTCplus05___00_Indian__Kerguelen = "Indian/Kerguelen"
    UTCplus07___00_Asia__Bangkok = "Asia/Bangkok"
    UTCplus05___00_Asia__Dushanbe = "Asia/Dushanbe"
    UTCplus13___00_Pacific__Fakaofo = "Pacific/Fakaofo"
    UTCplus09___00_Asia__Dili = "Asia/Dili"
    UTCplus05___00_Asia__Ashgabat = "Asia/Ashgabat"
    UTCplus01___00_Africa__Tunis = "Africa/Tunis"
    UTCplus13___00_Pacific__Tongatapu = "Pacific/Tongatapu"
    UTCplus03___00_Europe__Istanbul = "Europe/Istanbul"
    UTCminus04___00_America__Port_of_Spain = "America/Port_of_Spain"
    UTCplus13___00_Pacific__Funafuti = "Pacific/Funafuti"
    UTCplus08___00_Asia__Taipei = "Asia/Taipei"
    UTCplus02___00_Europe__Kiev = "Europe/Kiev"
    UTCplus02___00_Europe__Uzhgorod = "Europe/Uzhgorod"
    UTCplus02___00_Europe__Zaporozhye = "Europe/Zaporozhye"
    UTCplus12___00_Pacific__Wake = "Pacific/Wake"
    UTCminus05___00_America__New_York = "America/New_York"
    UTCminus05___00_America__Detroit = "America/Detroit"
    UTCminus05___00_America__Kentucky__Louisville = "America/Kentucky/Louisville"
    UTCminus05___00_America__Kentucky__Monticello = "America/Kentucky/Monticello"
    UTCminus05___00_America__Indiana__Indianapolis = "America/Indiana/Indianapolis"
    UTCminus05___00_America__Indiana__Vincennes = "America/Indiana/Vincennes"
    UTCminus05___00_America__Indiana__Winamac = "America/Indiana/Winamac"
    UTCminus05___00_America__Indiana__Marengo = "America/Indiana/Marengo"
    UTCminus05___00_America__Indiana__Petersburg = "America/Indiana/Petersburg"
    UTCminus05___00_America__Indiana__Vevay = "America/Indiana/Vevay"
    UTCminus06___00_America__Chicago = "America/Chicago"
    UTCminus06___00_America__Indiana__Tell_City = "America/Indiana/Tell_City"
    UTCminus06___00_America__Indiana__Knox = "America/Indiana/Knox"
    UTCminus06___00_America__Menominee = "America/Menominee"
    UTCminus06___00_America__North_Dakota__Center = "America/North_Dakota/Center"
    UTCminus06___00_America__North_Dakota__New_Salem = "America/North_Dakota/New_Salem"
    UTCminus06___00_America__North_Dakota__Beulah = "America/North_Dakota/Beulah"
    UTCminus07___00_America__Denver = "America/Denver"
    UTCminus07___00_America__Boise = "America/Boise"
    UTCminus07___00_America__Phoenix = "America/Phoenix"
    UTCminus08___00_America__Los_Angeles = "America/Los_Angeles"
    UTCminus09___00_America__Anchorage = "America/Anchorage"
    UTCminus09___00_America__Juneau = "America/Juneau"
    UTCminus09___00_America__Sitka = "America/Sitka"
    UTCminus09___00_America__Metlakatla = "America/Metlakatla"
    UTCminus09___00_America__Yakutat = "America/Yakutat"
    UTCminus09___00_America__Nome = "America/Nome"
    UTCminus10___00_America__Adak = "America/Adak"
    UTCminus10___00_Pacific__Honolulu = "Pacific/Honolulu"
    UTCminus03___00_America__Montevideo = "America/Montevideo"
    UTCplus05___00_Asia__Samarkand = "Asia/Samarkand"
    UTCplus05___00_Asia__Tashkent = "Asia/Tashkent"
    UTCminus04___00_America__Caracas = "America/Caracas"
    UTCplus07___00_Asia__Ho_Chi_Minh = "Asia/Ho_Chi_Minh"
    UTCplus11___00_Pacific__Efate = "Pacific/Efate"
    UTCplus12___00_Pacific__Wallis = "Pacific/Wallis"
    UTCplus13___00_Pacific__Apia = "Pacific/Apia"
    UTCplus02___00_Africa__Johannesburg = "Africa/Johannesburg"


class SKU(StrEnum):
    STANDARD = "Standard"
    PROFESSIONAL = "Professional"
    ENTERPRISE = "Enterprise"

# okay decompiling ../bytecode/data/enums.pyc

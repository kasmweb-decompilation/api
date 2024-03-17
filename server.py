# decompyle3 version 3.9.1
# Python bytecode version base 3.8.0 (3413)
# Decompiled from: Python 3.10.12 (main, Nov 20 2023, 15:14:05) [GCC 11.4.0]
# Embedded file name: server.py
import argparse, ipaddress, logging.config, os, re, sys, time, cherrypy, yaml
from alembic import command
from alembic.config import Config
from cherrypy import _cperror
from sqlalchemy import create_engine
from data.access_postgres import DataAccessPostgres
from data.data_access_factory import DataAccessFactory
from data.database_session_tool import DatabaseSessionTool
from log.handlers import KasmLogHandler

def get_db_session(config):
    db = DataAccessFactory.createSession(config["database"]["type"], config)
    db.execute_native_query("SELECT 1;")
    return db


def database_connectivity_test(config):
    create_engine((DataAccessPostgres.get_url(config)), pool_pre_ping=True)


@cherrypy.tools.register("on_start_resource")
def header_sanitizer():
    hostname_valid = False
    candidate_hostname = cherrypy.request.headers.get("HOST")
    if ":" in candidate_hostname:
        (candidate_host, candidate_port) = candidate_hostname.split(":")
        try:
            if int(candidate_port) <= 0 or int(candidate_port) >= 65535:
                raise ValueError("Value outside valid port range.")
        except ValueError as er:
            try:
                logger.error(f"Host header {candidate_hostname} does not have a valid port number:{candidate_port}.")
                raise cherrypy.HTTPError(400)
            finally:
                er = None
                del er

    else:
        candidate_host = candidate_hostname
    try:
        ipaddress.ip_address(candidate_host)
        hostname_valid = True
    except ValueError:
        pass
    else:
        if not hostname_valid:
            try:
                normalized_host = candidate_host.encode("idna").decode()
            except UnicodeError as er:
                try:
                    logger.warning(f"Received unicode error trying to decode punycode hostname {candidate_host}: {er}.")
                    normalized_host = candidate_host
                finally:
                    er = None
                    del er

            else:
                if len(normalized_host) <= 255:
                    normalized_host = normalized_host.rstrip(".")
                    allowed = re.compile("(?!-)[A-Z0-9-_]{1,63}(?<!-)$", re.IGNORECASE)
                    hostname_valid = all((allowed.match(hostname_piece) for hostname_piece in normalized_host.split(".")))
                    if not hostname_valid:
                        logger.warning(f"Hostname {candidate_hostname} failed regular expression validation.")
                else:
                    logger.warning(f"Hostname {candidate_hostname} exceeds valid hostname length.")
            if not hostname_valid:
                logger.error(f"Hostname is not a valid hostname {candidate_hostname}.")
                raise cherrypy.HTTPError(400)


def generic_error_message(status, message, traceback, version):
    try:
        logger.exception(message)
    except Exception:
        pass
    else:
        return f"An error has occurred {status} - see logs for details"


def error_page_404(status, message, traceback, version):
    try:
        logger.warning(message)
    except Exception:
        pass
    else:
        return f"An error has occurred {status} - see logs for details"


def generic_error_response():
    logger.error("Unhandled exception occurred", exc_info=(_cperror.format_exc()))
    cherrypy.response.status = 500
    cherrypy.response.body = [
     b'<html><body>An unhandled exception occurred check logs for details<body><html>']


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--cfg", dest="cfg", required=True, help="Path to app config", default="app.config.yaml")
    parser.add_argument("--autoreload", dest="autoreload", action="store_true", help="Set server to auto reload code")
    parser.add_argument("--enable-client-api", dest="enable_client_api", action="store_true", help="Enable Client API")
    parser.add_argument("--enable-admin-api", dest="enable_admin_api", action="store_true", help="Enable Admin API")
    parser.add_argument("--enable-filter-api", dest="enable_filter_api", action="store_true", help="Enable Filter API")
    parser.add_argument("--enable-public-api", dest="enable_public_api", action="store_true", help="Enable Public API")
    parser.add_argument("--enable-subscriptions-api", dest="enable_subscription_api", action="store_true", help="Enable Subscriptions API")
    parser.add_argument("--port", dest="port", default=8080)
    parser.add_argument("--initialize-database", dest="initialize_database", action="store_true", help="Initialize the database")
    parser.add_argument("--upgrade-database", dest="upgrade_database", action="store_true", help="Upgrade the database")
    parser.add_argument("--db-port-override", dest="db_port_override", help="Override the database port from the config")
    parser.add_argument("--db-host-override", dest="db_host_override", help="Override the database host from the config")
    parser.add_argument("--alembic-config", dest="alembic_config", default="/alembic.ini", help="Override the database host from the config")
    parser.add_argument("--seed-file", dest="seed_file", required=False, help="Path to databse configuration seed file")
    parser.add_argument("--populate-production", dest="populate_production",
      help="Populate data for populate_production",
      action="store_true",
      default=False)
    parser.add_argument("--activation-key-file", dest="activation_key_file",
      help="File for license activation key")
    args = parser.parse_args()
    if not os.path.exists(args.cfg):
        raise Exception("Unable to find config %s" % args.cfg)
    app_config = yaml.safe_load(open(args.cfg))
    if args.db_port_override:
        app_config["database"]["port"] = int(args.db_port_override)
    if args.db_host_override:
        app_config["database"]["host"] = args.db_host_override
    logging.config.dictConfig(app_config["logging"]["api_server"])
    logger = logging.getLogger()
    max_retries = 10
    connected = False
    logger.info("Performing Database Connectivity Test")
    for x in range(0, max_retries):
        try:
            connected = True
            break
        except Exception as e:
            try:
                logger.exception("Unable to initialize database connection. %s" % e)
                time.sleep(5)
            finally:
                e = None
                del e

    if not connected:
        logger.error("Max Connection Attempts Exceeded. Exiting")
        sys.exit(1)
    if args.initialize_database or args.upgrade_database or args.populate_production:
        temp_config = "/tmp/.temp.api.app.config.yaml"
        with open(temp_config, "w") as f:
            f.write(yaml.dump(app_config))
            x_arg = "kasm_config=" + temp_config
            alembic_config = args.alembic_config
            alembic_cfg = Config(alembic_config)
            alembic_cfg.cmd_opts = argparse.Namespace()
            setattr(alembic_cfg.cmd_opts, "x", [])
            alembic_cfg.cmd_opts.x.append(x_arg)
        postgres = None
        if args.initialize_database:
            logger.info("Initializing Postgres Database")
            import initialize_postgres_db
            postgres = initialize_postgres_db.Postgres(app_config)
            postgres.drop_schema()
            postgres.create_schema()
            installation_id = postgres.create_installation_id()
            os.environ["INSTALLATION_ID"] = str(installation_id)
            logger.info("Stamping Database with revision")
            os.chdir(os.path.dirname(alembic_config))
            command.stamp(alembic_cfg, "head")
        if args.populate_production:
            if not os.path.exists(args.seed_file):
                raise Exception("Unable to find seed file %s" % args.seed_file)
            with open((args.seed_file), mode="r", encoding="utf-8") as file:
                seed_data = yaml.safe_load(file)
            if not postgres:
                import initialize_postgres_db
                postgres = initialize_postgres_db.Postgres(app_config)
            postgres.populate_production(seed_data)
        elif args.upgrade_database:
            logger.info("Upgrading Postgres Database")
            command.upgrade(alembic_cfg, "head")
        if args.initialize_database or args.populate_production or args.upgrade_database:
            logger.info("Complete")
            sys.exit(0)
        os.remove(temp_config)
    if args.activation_key_file:
        if not os.path.exists(args.activation_key_file):
            raise Exception("Unable to find license key file %s" % args.activation_key_file)
        with open(args.activation_key_file, "r") as file:
            license_content = file.read().replace("\n", "")
        import initial_activate
        activate = initial_activate.InitialActivate(app_config, logger)
        logger.info("Activating license key")
        activate.activate(license_content)
        sys.exit(0)
    db = get_db_session(app_config)
    if "server" in app_config:
        log_hostname = app_config["server"]["server_hostname"] if "server_hostname" in app_config["server"] else None
        kl = KasmLogHandler.create_cached_kasmloghandler(application="kasm_api", db=db, hostname=log_hostname)
        logger.info("Added Log Handler")
        logger.addHandler(kl)
        path = os.path.dirname(os.path.realpath(__file__))
        config = {"/": {'log.screen':False, 
               'tools.db.on':True, 
               'tools.header_sanitizer.on':True}}
        if os.getenv("KASM_DISABLE_HEADER_SANITIZATION", "false").lower() == "true":
            config["/"]["tools.header_sanitizer.on"] = False
        port = int(args.port)
        if not args.autoreload:
            cherrypy.config.update({"global": {"environment": "production"}})
        cherrypy.config.update({'server.socket_host':"0.0.0.0",  'server.socket_port':port})
        if app_config.get("server", {}).get("sanitize_errors", True):
            cherrypy.config.update({'error_page.default':generic_error_message,  'request.error_response':generic_error_response, 
             'error_page.404':error_page_404})
        if args.enable_admin_api:
            from admin_api import AdminApi
            cherrypy.tree.mount(AdminApi(app_config), "/api/admin", config)
        if args.enable_filter_api:
            from filter_api import FilterApi
            cherrypy.tree.mount(FilterApi(app_config), "/api/filter", config)
        subscription_settings = [x for x in db.get_config_settings() if x.category == "subscription"]
        if subscription_settings:
            logger.info("Subscription settings detected")
        if args.enable_subscription_api or subscription_settings:
            from subscription_api import SubscriptionApi
            cherrypy.tree.mount(SubscriptionApi(app_config), "/api/subscriptions", config)
        if args.enable_client_api:
            from client_api import ClientApi
            cherrypy.tree.mount(ClientApi(app_config), "/api", config)
        if args.enable_public_api:
            from public_api import PublicAPI
            cherrypy.tree.mount(PublicAPI(app_config), "/api/public", config)
        cherrypy.tools.db = DatabaseSessionTool(app_config)
        cherrypy.engine.start()
        cherrypy.engine.block()

# okay decompiling bytecode/server.pyc

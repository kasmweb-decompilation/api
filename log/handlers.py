# decompyle3 version 3.9.1
# Python bytecode version base 3.8.0 (3413)
# Decompiled from: Python 3.10.12 (main, Nov 20 2023, 15:14:05) [GCC 11.4.0]
# Embedded file name: log/handlers.py
import urllib.request, ssl, socket, logging, queue
from pythonjsonlogger import jsonlogger
import json, datetime, threading
from logging.handlers import QueueHandler, QueueListener
from logging import StreamHandler

class KasmLogHandler(StreamHandler):
    HTTP_CACHE_SIZE = 20
    DB_CACHE_SIZE = 50
    MAX_CACHE_SECONDS = 120

    def __init__(self, application, db=None, config=None, hostname=None):
        StreamHandler.__init__(self)
        self.db = db
        self.config = config
        self.log_format = "standard"
        self.server_id = None
        self.minimize_local_logging = False
        if db is None and config is None:
            raise ValueError("KasmLogHandler initialized with null database and configuration values")
        elif config is not None:
            if "manager" not in config or "hostnames" not in config["manager"] or len(config["manager"]["hostnames"]) == 0:
                raise ValueError("Invalid configuration file.")
        self.update_config()
        self.http_cache = []
        self.http_cache_last_flush = datetime.datetime.now()
        self.db_log_cache = []
        self.db_log_cache_last_flush = datetime.datetime.now()
        self.setFormatter(jsonlogger.JsonFormatter(fmt="%(asctime) %(name) %(processName) %(filename)  %(funcName) %(levelname) %(lineno) %(module) %(threadName) %(message)", timestamp=True))
        if hostname is None:
            self.hostname = socket.gethostname()
        else:
            self.hostname = hostname
        self.application = application

    def update_config(self, config=None):
        if self.db is not None:
            self.log_protocol = self.db.get_config_setting_value("logging", "log_protocol").lower()
            self.log_port = self.db.get_config_setting_value("logging", "log_port")
            self.log_host = self.db.get_config_setting_value("logging", "log_host")
            self.hec_token = self.db.get_config_setting_value("logging", "hec_token")
            self.http_method = self.db.get_config_setting_value("logging", "http_method").lower()
            self.https_insecure = self.db.get_config_setting_bool("logging", "https_insecure", True)
            self.splunk_endpoint = self.db.get_config_setting_value("logging", "url_endpoint")
            self.minimize_local_logging = self.db.get_config_setting_bool("logging", "minimize_local_logging", False)
            self.log_retention = int(self.db.get_config_setting_value("logging", "log_retention"))
            self.debug_retention = int(self.db.get_config_setting_value("logging", "debug_retention"))
            if self.log_protocol == "splunk":
                self.log_format = "splunk"
                self.log_protocol = "https"
            if self.log_host == "":
                self.log_protocol = "internal"
            if self.config is not None:
                if config is not None:
                    if "manager" not in self.config or "hostnames" not in self.config["manager"] or len(self.config["manager"]["hostnames"]) == 0:
                        raise ValueError("Invalid configuration file.")
                    if self.server_id == config["agent"]["server_id"]:
                        if self.hec_token == (config["manager"]["token"] if "token" in config["manager"] else "None"):
                            if self.log_port == (config["manager"]["public_port"] if "public_port" in config["manager"] else "443"):
                                if self.log_host == config["manager"]["hostnames"][0]:
                                    return
                            self.config = config
                        self.log_host = self.config["manager"]["hostnames"][0]
                        self.log_protocol = "https"
                        self.log_port = self.config["manager"]["public_port"] if "public_port" in self.config["manager"] else "443"
                        self.http_method = "post"
                        self.hec_token = self.config["manager"]["token"] if "token" in self.config["manager"] else "None"
                        self.https_insecure = True
                        self.splunk_endpoint = self.config.get("log_path", "/manager_api/api/v1/log")
                        if "agent" in self.config:
                            if "server_id" in self.config["agent"]:
                                self.server_id = self.config["agent"]["server_id"]
            if self.log_protocol == "https":
                if self.log_port == 0 or self.log_port is None:
                    raise ValueError("Invalid log port")
                self.destination = "https://{0}:{1}{2}".format(self.log_host, self.log_port, self.splunk_endpoint)
                self.request = urllib.request.Request((self.destination), method=(self.http_method.upper()))
                self.request.add_header("Content-Type", "application/json")
                self.request.add_header("Authorization", "Splunk {0}".format(self.hec_token))
                self.insecure_context = ssl.create_default_context()
                self.insecure_context.check_hostname = False
                self.insecure_context.verify_mode = not self.https_insecure

    @staticmethod
    def create_cached_kasmloghandler(application, db=None, config=None, hostname=None):
        qu = queue.Queue(100)
        qu_handler = QueueHandler(qu)
        kl = KasmLogHandler(application=application, db=db, config=config, hostname=hostname)
        qu_listener = QueueListener(qu, kl)
        qu_listener.start()
        qu_handler.log_handler = kl
        return qu_handler

    def emit_http(self, log_dict):
        if self.log_format == "standard":
            log_dict["ingest_date"] = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
            log_dict["host"] = self.hostname
            self.http_cache.append(log_dict)
        elif self.log_format == "splunk":
            slog = {'event':log_dict, 
             'time':(datetime.datetime.utcnow().timestamp)(),  'host':self.hostname}
            self.http_cache.append(slog)
        t_d = datetime.datetime.now() - self.http_cache_last_flush
        lock = threading.Lock()
        lock.acquire()
        if len(self.http_cache) > KasmLogHandler.HTTP_CACHE_SIZE or t_d.total_seconds() > KasmLogHandler.MAX_CACHE_SECONDS:
            msg = ""
            if self.log_format == "standard":
                msg = json.dumps(self.http_cache)
            elif self.log_format == "splunk":
                for log in self.http_cache:
                    msg += json.dumps(log) + " "

            try:
                b_msg = msg.encode("utf-8")
                self.request.add_header("Content-Length", len(b_msg))
                if not self.https_insecure:
                    response = urllib.request.urlopen((self.request), data=b_msg, timeout=3)
                else:
                    response = urllib.request.urlopen((self.request), data=b_msg, timeout=3, context=(self.insecure_context))
                if response.status > 299:
                    print("HTTP Logging failed: Invalid response code ", response.status)
            except Exception as ex:
                try:
                    print(ex)
                finally:
                    ex = None
                    del ex

            else:
                self.http_cache_last_flush = datetime.datetime.now()
                self.http_cache.clear()
            lock.release()

    def emit_db(self, log_dict, forwarded=False):
        if self.log_retention == 0:
            return
        if self.minimize_local_logging:
            if "application" in log_dict:
                if log_dict["application"] == "kasm_squid_adapter":
                    return
                if forwarded and "host" in log_dict and "ingest_date" in log_dict:
                    log = {'host':(log_dict.pop)("host", self.hostname), 
                     'ingest_date':(log_dict.pop)("ingest_date", datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")),  'data':log_dict}
                else:
                    log = {'host':self.hostname, 
                     'data':log_dict}
                    log["ingest_date"] = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
                t_d = datetime.datetime.now() - self.db_log_cache_last_flush
                log["metric_name"] = log_dict.get("metric_name")
                log["kasm_user_name"] = log_dict.get("kasm_user_name")
                log["levelname"] = log_dict.get("levelname")
                log["disk_stats"] = None
                log["memory_stats"] = None
                log["cpu_percent"] = None
                log["server_id"] = None
                log["gpu_percent"] = None
                log["gpu_memory"] = None
                log["gpu_temp"] = None
                if self.debug_retention == 0:
                    if log["levelname"] == "DEBUG":
                        return
                    if "heartbeat" in log_dict:
                        hb = log_dict["heartbeat"]
                        if "disk_stats" in hb:
                            log["disk_stats"] = hb["disk_stats"].get("percent")
                        if "memory_stats" in hb:
                            log["memory_stats"] = hb["memory_stats"].get("percent")
                        log["cpu_percent"] = hb.get("cpu_percent")
                        log["server_id"] = hb.get("server_id")
                        if "docker_info" in hb:
                            if "GPUs" in hb["docker_info"]:
                                gpu_max_cpu = 0
                                gpu_max_mem = 0
                                gpu_max_temp = 0
                                for gpu in hb["docker_info"]["GPUs"].values():
                                    if "gpu_utilization" in gpu:
                                        gpu_max_cpu = gpu["gpu_utilization"] if gpu["gpu_utilization"] > gpu_max_cpu else gpu_max_cpu
                                        if "memory_used" in gpu:
                                            if "memory_total" in gpu:
                                                mem_percent_used = gpu["memory_used"] / gpu["memory_total"] * 100 if gpu["memory_total"] > 0 else 0
                                                gpu_max_mem = mem_percent_used if mem_percent_used > gpu_max_mem else gpu_max_mem
                                                if "gpu_tempurature" in gpu:
                                                    gpu_max_temp = gpu["gpu_tempurature"] if gpu["gpu_tempurature"] > gpu_max_temp else gpu_max_temp
                                                log["gpu_percent"] = gpu_max_cpu
                                                log["gpu_memory"] = gpu_max_mem
                                                log["gpu_temp"] = gpu_max_temp

            lock = threading.Lock()
            lock.acquire()
            self.db_log_cache.append(log)
            if len(self.db_log_cache) > KasmLogHandler.DB_CACHE_SIZE or t_d.total_seconds() > KasmLogHandler.MAX_CACHE_SECONDS:
                try:
                    try:
                        self.db.createLogs(self.db_log_cache)
                    except Exception as ex:
                        try:
                            print(ex)
                        finally:
                            ex = None
                            del ex

                finally:
                    self.db_log_cache.clear()
                    self.db_log_cache_last_flush = datetime.datetime.now()

        lock.release()

    def emit(self, record):
        if hasattr(record, "_json"):
            if self.db is not None:
                log = json.loads(record.msg)
                if self.db is not None:
                    self.emit_db(log, forwarded=True)
                if self.log_protocol == "https":
                    self.emit_http(log)
        else:
            if not hasattr(record, "application"):
                record.application = self.application
            else:
                print(record.application)
            msg = self.format(record)
            log_json = json.loads(msg)
            if self.server_id is not None:
                log_json["server_id"] = self.server_id
            if self.db is not None:
                self.emit_db(log_json)
            if self.log_protocol == "https":
                self.emit_http(log_json)


class InternalLogFilter(logging.Filter):

    def filter(self, record):
        return not hasattr(record, "_json")


class ExternalLogFilter(logging.Filter):

    def __init__(self, application=None):
        self.application = application

    def filter(self, record):
        if not hasattr(record, "_json"):
            return False
        if self.application is None:
            return True
        log = json.loads(record.msg)
        return "application" in log and log["application"] == self.application

# okay decompiling ../bytecode/log/handlers.pyc

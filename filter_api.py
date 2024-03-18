# decompyle3 version 3.9.1
# Python bytecode version base 3.8.0 (3413)
# Decompiled from: Python 3.10.12 (main, Nov 20 2023, 15:14:05) [GCC 11.4.0]
# Embedded file name: filter_api.py
import cherrypy, logging.config
from urllib.parse import urlparse
from data.data_access_factory import DataAccessFactory
from filtering.webroot import WebRoot
from utils import Unauthenticated
from data.categories import ALL_CATEGORIES, WEBROOT_CATEGORIES

class FilterApi(object):

    def __init__(self, config):
        self.config = config
        self._db = DataAccessFactory.createSession(config["database"]["type"], config)
        self._db = DataAccessFactory.createSession(config["database"]["type"], config)
        self.logger = logging.getLogger("filter_api_server")
        self.logger.info("%s initialized" % self.__class__.__name__)
        consumer_key = self._db.get_config_setting_value("webroot", "consumer_key")
        consumer_secret = self._db.get_config_setting_value("webroot", "consumer_secret")
        self.web_root = WebRoot(consumer_key, consumer_secret, self.logger)

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    @Unauthenticated()
    def web_url_check(self):
        event = cherrypy.request.json
        response = {}
        if "url" in event and "installation_id" in event:
            url = event["url"]
            installation_id = event["installation_id"]
            domain = urlparse(url).netloc.split(":")[0]
            domain_split = domain.split(".")
            if domain:
                self.logger.debug(("Received web_url_check from (%s) for (%s)" % (installation_id, url)), extra={'installation_id':installation_id, 
                 'url':url, 
                 'domain':domain})
                search_domains = [
                 domain]
                if len(domain_split) >= 3:
                    for x in range(2, len(domain_split)):
                        _d = ".".join(domain_split[x * -1:])
                        search_domains.append(_d)

                domains = cherrypy.request.db.get_domains(search_domains)
                domain_categories = {}
                if domains:
                    for x in domains:
                        x.requested += 1
                        try:
                            cherrypy.request.db.update_domain(x)
                        except Exception as e:
                            try:
                                self.logger.error("Exception updated requested value for domain (%s) : (%s)" % (x.domain_name, e))
                            finally:
                                e = None
                                del e

                        else:
                            domain_categories[x.domain_name] = x.categories

                else:
                    try:
                        uri, data = self.web_root.get_categories(domain)
                    except Exception as e:
                        self.logger.exception("Error during webroot request for url (%s) : (%s)" % (domain, e))
                        return response
                    else:
                        categories = {}
                        for x in data:
                            category_string = "cat_id_" + x
                            webroot_category = WEBROOT_CATEGORIES.get(category_string)["label"]
                            if webroot_category:
                                categories[category_string] = webroot_category
                            else:
                                self.logger.error("Unknown webroot category id (%s)" % category_string)
                                categories["cat_id_0"] = WEBROOT_CATEGORIES.get("cat_id_0")["label"]

                        domain_categories[uri] = categories
                        self.logger.debug("Adding new url categorization. Url (%s) Categories (%s)" % (url, categories))
                        cherrypy.request.db.add_domains(categories, [uri], True, requested=1)
                response["domains"] = domain_categories
            else:
                msg = "Invalid URL (%s)" % url
                self.logger.error(msg)
                response["error_message"] = msg
        else:
            msg = "Invalid Request. Missing parameters"
            self.logger.error(msg)
            response["error_message"] = msg
        return response

    def get_url_db(self):
        out_domains = {}
        response = {}
        domains = cherrypy.request.db.get_domains_ex(limit=100000, order_by_requested=True)
        for (k, v) in domains.items():
            out_domains[k] = list(v)

        response["domains"] = out_domains
        return response

# okay decompiling bytecode/filter_api.pyc

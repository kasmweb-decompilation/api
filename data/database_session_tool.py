# decompyle3 version 3.9.1
# Python bytecode version base 3.8.0 (3413)
# Decompiled from: Python 3.10.12 (main, Nov 20 2023, 15:14:05) [GCC 11.4.0]
# Embedded file name: data/database_session_tool.py
import cherrypy
from data.data_access_factory import DataAccessFactory

class DatabaseSessionTool(cherrypy.Tool):

    def __init__(self, config):
        cherrypy.Tool.__init__(self, "before_handler", (self.initialize),
          priority=95)
        self._db = DataAccessFactory.createSession(config["database"]["type"], config)

    def _setup(self):
        cherrypy.Tool._setup(self)
        cherrypy.request.hooks.attach("before_finalize", (self.cleanup),
          priority=5)

    def initialize(self):
        cherrypy.request.db = self._db

    def cleanup(self):
        self._db.session().rollback()
        self._db.session().close()
        self._db.thread_safe_session.remove()

# okay decompiling ../bytecode/data/database_session_tool.pyc

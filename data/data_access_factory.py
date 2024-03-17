# decompyle3 version 3.9.1
# Python bytecode version base 3.8.0 (3413)
# Decompiled from: Python 3.10.12 (main, Nov 20 2023, 15:14:05) [GCC 11.4.0]
# Embedded file name: data/data_access_factory.py
from data.access_postgres import DataAccessPostgres
import logging
logging.basicConfig()
pool_status_logger = logging.getLogger("sqlalchemy.pool.status")

class DataAccessFactory:
    database = None

    @staticmethod
    def createSession(type, config):
        if DataAccessFactory.database is not None:
            pool_status_logger.info(f"In createSession: {DataAccessFactory.database.engine.pool.status()}")
            return DataAccessFactory.database
        if type == "postgres":
            DataAccessFactory.database = DataAccessPostgres(config)
            pool_status_logger.info(f"In createSession: {DataAccessFactory.database.engine.pool.status()}")
            return DataAccessFactory.database
        raise ValueError("Data Access type not supported")

# okay decompiling ../bytecode/data/data_access_factory.pyc

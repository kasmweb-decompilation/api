# Source Generated with Decompyle++
# File: server.pyc (Python 3.8)

import argparse
import ipaddress
import logging.config as logging
import os
import re
import sys
import time
import cherrypy
import yaml
from alembic import command
from alembic.config import Config
from cherrypy import _cperror
from sqlalchemy import create_engine
from data.access_postgres import DataAccessPostgres
from data.data_access_factory import DataAccessFactory
from data.database_session_tool import DatabaseSessionTool
from log.handlers import KasmLogHandler

def get_db_session(config):
    db = DataAccessFactory.createSession(config['database']['type'], config)
    db.execute_native_query('SELECT 1;')
    return db


def database_connectivity_test(config):
    create_engine(DataAccessPostgres.get_url(config), True, **('pool_pre_ping',))


def header_sanitizer():
    hostname_valid = False
    candidate_hostname = cherrypy.request.headers.get('HOST')
# WARNING: Decompyle incomplete

header_sanitizer = cherrypy.tools.register('on_start_resource')(header_sanitizer)

def generic_error_message(status = None, message = None, traceback = None, version = {
    'status': str,
    'message': str,
    'traceback': str,
    'version': str,
    'return': str }):
    
    try:
        logger.exception(message)
    finally:
        pass
    except Exception:
        pass
    

    return f'''An error has occurred {status} - see logs for details'''


def error_page_404(status = None, message = None, traceback = None, version = {
    'status': str,
    'message': str,
    'traceback': str,
    'version': str,
    'return': str }):
    
    try:
        logger.warning(message)
    finally:
        pass
    except Exception:
        pass
    

    return f'''An error has occurred {status} - see logs for details'''


def generic_error_response():
    logger.error('Unhandled exception occurred', _cperror.format_exc(), **('exc_info',))
    cherrypy.response.status = 500
    cherrypy.response.body = [
        b'<html><body>An unhandled exception occurred check logs for details<body><html>']

# WARNING: Decompyle incomplete

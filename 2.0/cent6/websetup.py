import os
import sys
import signal
import logging
import getpass

import cracklib
import pylons.test

from sqlalchemy.sql import text
from sqlalchemy.exc import ProgrammingError

from baruwa.model.accounts import User
from baruwa.model.settings import Server, ConfigSettings
from baruwa.lib.regex import ADDRESS_RE
from baruwa.model.meta import Session, Base
from baruwa.config.environment import load_environment

log = logging.getLogger(__name__)

class TimeoutException(Exception): 
    pass


def setup_app(command, conf, variables):
    """Place any commands to setup baruwa here"""
    # Don't reload the app if it was loaded under the testing environment
    if not pylons.test.pylonsapp:
        load_environment(conf.global_conf, conf.local_conf)

    # Create the tables if they don't already exist
    print '-' * 100
    log.info("Creating tables")
    Base.metadata.create_all(bind=Session.bind)
    basepath = os.path.dirname(os.path.dirname(__file__))
    # Create the custom functions
    print '-' * 100
    log.info("Creating custom functions")
    sqlfile = os.path.join(basepath,
                        'baruwa',
                        'config',
                        'sql',
                        'functions.sql')
    if os.path.exists(sqlfile):
        with open(sqlfile, 'r') as handle:
            sql = handle.read()
            try:
                conn = Session.connection()
                conn.execute(text(sql))
                Session.commit()
            except ProgrammingError:
                Session.rollback()
    defaultserver = Session.query(Server)\
                    .filter(Server.hostname == 'default')\
                    .all()
    # Create the Mailscanner SQL config views
    print '-' * 100
    log.info("Populating initial sql")
    sqlfile = os.path.join(basepath,
                        'baruwa',
                        'config',
                        'sql',
                        'integration.sql')
    if os.path.exists(sqlfile):
        with open(sqlfile, 'r') as handle:
            sql = handle.read()
        for sqlcmd in sql.split(';'):
            if sqlcmd:
                try:
                    sqlcmd = "%s;" % sqlcmd
                    Session.execute(text(sqlcmd))
                    Session.commit()
                except ProgrammingError:
                    Session.rollback()
    if not defaultserver:
        log.info("Creating the default settings node")
        dfls = Server('default', True)
        Session.add(dfls)
        confserial = ConfigSettings('confserialnumber',
                                    'ConfSerialNumber',
                                    0)
        confserial.value = 1
        confserial.server_id = 1
        Session.add(confserial)
        Session.commit()
        log.info("Default settings node created !")
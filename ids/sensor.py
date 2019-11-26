import time
import sys
import os
import logging
import codecs
from netaddr import CIDR, IP
from signal import signal, SIGINT, SIGQUIT
from datetime import datetime, timedelta
from database import create_packet, create_connection

database = "./detector.db"
conn = create_connection(database)
c = conn.cursor()

def signal_handler(signal, frame):
    """ TODO: Write doc block """
    print('Exiting!')
    sys.exit(0)

signal(SIGINT, signal_handler)
signal(SIGQUIT, signal_handler)

class Sensor(object):

    def __init__(self, config=None):
        """ Constructor
        """
        logging.basicConfig(
            filename='sensor.log',
            level=logging.DEBUG, 
            format= '[%(asctime)s] {%(pathname)s:%(lineno)d} %(levelname)s - %(message)s',
            datefmt='%m/%d/%Y %I:%M:%S %p'
        )
        self.logger = logging.getLogger(__name__)
        self.logger.info("Starting up sensor thread")
        global conn, c

    def IPinSubnet(ip, net):
        if IP(ip) in CIDR(net):
            return True
        else:
            return False

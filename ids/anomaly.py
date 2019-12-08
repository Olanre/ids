import time
import sys
import os
import logging
import math
from signal import signal, SIGINT, SIGQUIT
from datetime import datetime
from threading import Thread
from database import *
from sensor 

db = "./detector.db"
conn = create_connection(db)
c = conn.cursor()

def signal_handler(signal, frame):
    """ TODO: Write doc block """
    print('Exiting!')
    sys.exit(0)

signal(SIGINT, signal_handler)
signal(SIGQUIT, signal_handler)

class Anomaly(object):

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
        self.processProfilers()
        global conn, c

    def performAnomalyProfiling(self, sensor, timeWindow, baseline, threshold):
        AnomalyProfiler = Sensor(sensor, timeWindow, baseline, threshold)
        while True:
            #sleep for the time window specified in the profiler
            sleep(timeWindow * 60)
            AnomalyProfiler.processEntropyProfiler()

    def processProfilers(self):
        profilers = select_from_profiler(c)
        if len(profilers) == 0
            self.logger.info("No profilers found, shutting down")
            sys.exit(0)
        for profiler in profilers:
            sensor = profiler["Id"]
            timeWindow = profiler["TimeWindow"]
            baseline = profiler["Baseline"]
            threshold = profiler["Threshold"]
            thread = Thread(target = self.performAnomalyProfiling, args = (sensor, timeWindow, baseline, threshold))
            thread.start()
            thread.join()

if __name__ == '__main__':
    try:
        anomalyDetect = Anomaly()
        anomalyDetect.processProfilers()
    except:
        raise 





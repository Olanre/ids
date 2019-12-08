import time
import sys
import os
import logging
import time
from signal import signal, SIGINT, SIGQUIT
from datetime import datetime
from threading import Thread
import database
from sensor import *

db = "./detector.db"
conn = database.create_connection(db)
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
            filename='anomaly.log',
            level=logging.DEBUG, 
            format= '[%(asctime)s] {%(pathname)s:%(lineno)d} %(levelname)s - %(message)s',
            datefmt='%m/%d/%Y %I:%M:%S %p'
        )
        self.logger = logging.getLogger(__name__)
        self.logger.info("Starting up sensor thread")
        self.processProfilers()
        global conn, c

    def performAnomalyProfiling(self, name, sensorId, timeWindow, baseline, threshold):
        AnomalyProfiler = Sensor(name, sensorId, timeWindow, baseline, threshold)
        sleepTime = timeWindow * 60
        while True:
            #sleep for the time window specified in the profiler
            self.logger.info("The profiler {} - {} will now sleep for {} seconds".format(name, sensorId, sleepTime))
            time.sleep(sleepTime)
            AnomalyProfiler.processEntropyProfiler()

    def processProfilers(self):
        thread_list = []
        profilers = database.select_from_profiler(c)
        if len(profilers) == 0:
            self.logger.info("No profilers found, shutting down")
            sys.exit(0)
        self.logger.debug("Retrieved results from the db of size as: {}".format((len(profilers))))
        for profiler in profilers:
            name = profiler["SensorName"]
            sensorId = profiler["Id"]
            timeWindow = profiler["TimeWindow"]
            baseline = profiler["Baseline"]
            threshold = profiler["Threshold"]
            self.logger.info("Starting up new profiler with name:{} id:{} timeWindow:{} baseline:{} threshold:{} ".format(name, sensorId, timeWindow, baseline, threshold))
            thread = Thread(target = self.performAnomalyProfiling, args = (name, sensorId, timeWindow, baseline, threshold))
            thread_list.append(thread)
    
        # from the main-thread, starts child threads
        for thread in thread_list:
            thread.start()
        # main-thread 'sleeping' in join-method, waiting for child-thread to finish 
        for thread in thread_list:
            thread.join()
            
if __name__ == '__main__':
    try:
        anomalyDetect = Anomaly()
    except:
        raise 





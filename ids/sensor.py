import time
import sys
import os
import logging
import codecs
import math
from signal import signal, SIGINT, SIGQUIT
from datetime import datetime
import database
from random import randrange


db = "./detector.db"
conn = database.create_connection(db)
c = conn.cursor()

def signal_handler(signal, frame):
    """ TODO: Write doc block """
    print('Exiting!')
    sys.exit(0)

signal(SIGINT, signal_handler)
signal(SIGQUIT, signal_handler)

class Sensor(object):
    sensorId = 0
    baseline = ""
    threshold = ""
    timeWindow = ""
    name=""

    def __init__(self, name, sensorid, timeWindow, baseline, threshold):
        """ Constructor
        """
        fname = "sensor-" + str(sensorid) + ".log"
        logging.basicConfig(
            filename=fname,
            level=logging.DEBUG, 
            format= '[%(asctime)s] {%(pathname)s:%(lineno)d} %(levelname)s - %(message)s',
            datefmt='%m/%d/%Y %I:%M:%S %p'
        )
        self.logger = logging.getLogger(__name__)
        self.logger.info("Starting up sensor object")
        self.name = name
        self.sensorId = sensorid
        self.timeWindow = timeWindow
        self.baseline = baseline
        self.threshold = threshold
        global conn, c

###################################################        Some Helper Functions            ###########################################################

    def logVals(self, xvalues):
        self.logger.debug("Computed the xvalues to get the entropy from as:  {}".format(xvalues))

    def logRows(self, rows):
        self.logger.debug("Retrieved results from the db of size as: {}".format((len(rows))))


###################################################  Processing and Calculation Algorithm for Entropy  ###########################################################
    def processRows(self, rows, index, total):
        xvalues = []
        self.logRows(rows)
        if len(rows) == 0:
            return 0
        for row in rows:
            xvalues.append( row[index])
        self.logVals(xvalues)
        #get shannon entropy
        return self._calculateEntropy(xvalues, total)
    
    def _calculateEntropy(self, xvalues, total):
        sign = -1
        entropy = 0.0
        if len(xvalues) == 0:
            return 0
        for x in xvalues:
            if x == 0:
                entropy += 0
                continue
            probability_x = x/total
            entropy += sign * (probability_x * math.log(probability_x, 2))
        self.logger.debug("Calculated entropy as: {}".format(entropy))
        #calculateNormalizedEntropy
        normalizedEntropy =  (entropy/ math.log(len(xvalues) , 2))
        self.logger.debug("Calculated normalized entropy as:  {}".format(normalizedEntropy))
        return normalizedEntropy


###################################################  Getting Address Entropy Values ###########################################################

    def _calculateAddressSrcBytesEntropy(self, total, startid, endid):
        xvalues = []
        #now get the number of bytes with xi as the source address
        rows = database.select_source_address_bytes_in_id_range(c, startid, endid)
        return self.processRows(rows, "SumBytes", total)

    def _calculateAddressDstBytesEntropy(self, total, startid, endid):
        xvalues = []
        #now get the number of bytes with xi as the destination address
        rows = database.select_destination_address_bytes_in_id_range(c, startid, endid)
        return self.processRows(rows, "SumBytes", total)

    def _calculateAddressSrcPacketsEntropy(self, total, startid, endid):
        xvalues = []
        #now get the number of packets with xi as the source address
        rows = database.select_source_address_packets_in_id_range(c, startid, endid)
        return self.processRows(rows, "Count", total)


    def _calculateAddressDstPacketsEntropy(self, total, startid, endid):
        xvalues = []
        #now get the number of packets with xi as the destination address
        rows = database.select_destination_address_packets_in_id_range(c, startid, endid)
        return self.processRows(rows, "Count", total)



###################################################  Getting Port Entropy Values ###########################################################

    def _calculatePortSrcBytesEntropy(self, total, startid, endid):
        xvalues = []
        #now get the number of bytes with xi as the source port
        rows = database.select_source_port_bytes_in_id_range(c, startid, endid)
        return self.processRows(rows, "SumBytes", total)


    def _calculatePortDstBytesEntropy(self, total, startid, endid):
        xvalues = []
        #now get the number of bytes with xi as the destination port
        rows = database.select_destination_port_bytes_in_id_range(c, startid, endid)
        return self.processRows(rows, "SumBytes", total)


    def _calculatePortSrcPacketsEntropy(self, total, startid, endid):
        xvalues = []
        #now get the number of packets with xi as the source port
        rows = database.select_source_port_packets_in_id_range(c, startid, endid)
        return self.processRows(rows, "Count", total)

    def _calculatePortDstPacketsEntropy(self, total, startid, endid):
        xvalues = []
        #now get the number of packers with xi as the destination port
        rows = database.select_destination_port_packets_in_id_range(c, startid, endid)
        return self.processRows(rows, "Count", total)
    

###################################################  Getting Degrees Entropy Values ###########################################################

    def _calculateInDegreesEntropy(self, total, startid, endid):
        xvalues = []
        #now get the number of hosts with in degrees xi 
        rows = database.select_in_degrees_in_id_range(c, startid, endid)
        return self.processRows(rows, "Count", total)

    def _calculateOutDegreesEntropy(self, total, startid, endid):
        xvalues = []
        #now get the number of hosts with in degrees xi 
        rows = database.select_out_degrees_in_id_range(c, startid, endid)
        return self.processRows(rows, "Count", total)

###################################################  Getting Latest Packet Id Recorded In DB ###########################################################

    def processLastPacketFromEntropyTable(self, rows):
        if len(rows) == 0:
            return 0
        else:
            return rows[0]["LastPacket"]

    #for Address Entropy
    def getLatestEntropyAddress(self):
        rows = database.select_latest_address_entropy(c, self.sensorId)
        return self.processLastPacketFromEntropyTable(rows)

    #for Ports
    def getLatestEntropyPort(self):
        rows = database.select_latest_port_entropy(c, self.sensorId)
        return self.processLastPacketFromEntropyTable(rows)

    #for Degree
    def getLatestEntropyDegree(self):
        rows = database.select_latest_degree_entropy(c, self.sensorId)
        return self.processLastPacketFromEntropyTable(rows)

    #get the newest packet recorded
    def getLastPacket(self):
        self.logger.debug("Getting the last packet recorded in the database")
        #get the last packet recoded
        rows = database.select_latest_packet(c)
        self.logger.debug("Got the last packet recorded in the database")
        if len(rows) == 0:
            return 0
        else:
            return rows[0]["PacketId"]

    #get the curren time in timestamp format
    def getCurrentTimeStamp(self):
        # current date and time
        now = datetime.now()
        timestamp = datetime.timestamp(now)
        self.logger.debug("Saving the current timestamp = {}".format(timestamp))
        return timestamp
        

###################################################  Process the three Entropy Features ###########################################################
    def _processAddressEntropy(self, firstPacketId, lastPacketId):
        self.logger.debug("Processing address entropy")

        total_bytes = 1
        total_packets = 1
        self.logger.debug("Looking at packets from packet Id {}".format(firstPacketId))
        
        #first get the total bytes
        total_bytes_rows = database.select_total_bytes_in_id_range(c, firstPacketId, lastPacketId)
        if len(total_bytes_rows) > 0:
            total_bytes = total_bytes_rows[0]["TotalBytes"]
        self.logger.debug("Total bytes sent and received in this window is: {}".format(total_bytes))

        #now get the total packets
        total_packets_rows = database.select_total_packets_in_id_range(c, firstPacketId, lastPacketId)
        if len(total_packets_rows) > 0:
            total_packets = total_packets_rows[0]["TotalPackets"]
        self.logger.debug("Total packets sent and received in this window is: {}".format(total_packets))

        #calculate the entropy values
        srcBytesEntropy = self._calculateAddressSrcBytesEntropy(total_bytes, firstPacketId, lastPacketId)
        dstBytesEntropy = self._calculateAddressDstBytesEntropy(total_bytes, firstPacketId, lastPacketId)
        srcPacketEntropy = self._calculateAddressSrcPacketsEntropy(total_packets, firstPacketId, lastPacketId)
        dstPacketEntropy = self._calculateAddressDstPacketsEntropy(total_packets, firstPacketId, lastPacketId)

        #get the current timestamp 
        theTime = self.getCurrentTimeStamp()

        #create the different objects for holding entropy data, one to be returned and the other to be stored
        entropyPackage = [firstPacketId, srcBytesEntropy, dstBytesEntropy, srcPacketEntropy, dstPacketEntropy]
        data = [self.sensorId, theTime , firstPacketId, lastPacketId, srcPacketEntropy, dstPacketEntropy, srcBytesEntropy, dstBytesEntropy ]
        
        self.logger.debug("Saving address entropy data as: {}".format(data))
        database.create_port_entropy(c, data)
        
        return entropyPackage


    def _processPortEntropy(self, firstPacketId, lastPacketId):
        self.logger.debug("Processing port entropy")

        total_bytes = 1
        total_packets = 1
        self.logger.debug("Looking at packets from packet Id: {}".format(firstPacketId))
        
        #first get the total bytes
        total_bytes_rows = database.select_total_bytes_in_id_range(c, firstPacketId, lastPacketId)
        if len(total_bytes_rows) > 0:
            total_bytes = total_bytes_rows[0]["TotalBytes"]
        self.logger.debug("Total bytes sent and received in this window is: {}".format(total_bytes))

        #now get the total packets
        total_packets_rows = database.select_total_packets_in_id_range(c, firstPacketId, lastPacketId)
        if len(total_packets_rows) > 0:
            total_packets = total_packets_rows[0]["TotalPackets"]
        self.logger.debug("Total packets sent and received in this window is: {}".format(total_packets))
        
        #calculate the entropy values
        srcBytesEntropy = self._calculatePortSrcBytesEntropy(total_bytes, firstPacketId, lastPacketId)
        dstBytesEntropy = self._calculatePortDstBytesEntropy(total_bytes, firstPacketId, lastPacketId)
        srcPacketEntropy = self._calculatePortSrcPacketsEntropy(total_packets, firstPacketId, lastPacketId)
        dstPacketEntropy = self._calculatePortDstPacketsEntropy(total_packets, firstPacketId, lastPacketId)

        #get the current timestamp 
        theTime = self.getCurrentTimeStamp()

        #create the different objects for holding entropy data, one to be returned and the other to be stored
        entropyPackage = [firstPacketId, srcBytesEntropy, dstBytesEntropy, srcPacketEntropy, dstPacketEntropy]
        data = [self.sensorId, theTime , firstPacketId, lastPacketId, srcPacketEntropy, dstPacketEntropy, srcBytesEntropy, dstBytesEntropy ]
        
        self.logger.debug("Saving port entropy data as: {}".format(data))
        database.create_port_entropy(c, data)
        
        return entropyPackage

    def _processDegreeEntropy(self, firstPacketId,  lastPacketId):
        self.logger.debug("Processing degree entropy")

        distinct_sources = 1
        distinct_dests = 1
        self.logger.debug("Looking at packets from packet Id: {}".format(firstPacketId))
        
        #first get the total bytes
        distinct_source_rows = database.select_total_distinct_source_hosts_in_id_range(c, firstPacketId, lastPacketId)
        if len(distinct_source_rows) > 0:
            distinct_sources = distinct_source_rows[0]["Count"]
        self.logger.debug("Total source hosts in this window is: {}".format(distinct_sources))

        #now get the total packets
        distinct_dest_rows = database.select_total_distinct_dest_hosts_in_id_range(c, firstPacketId, lastPacketId)
        if len(distinct_dest_rows) > 0:
            distinct_dests = distinct_dest_rows[0]["Count"]
        self.logger.debug("Total destination hosts in this window is: {}".format(distinct_dests))
       
        #calculate the entropy values
        inDegreeEntropy = self._calculateInDegreesEntropy(distinct_sources, firstPacketId, lastPacketId)
        outDegreeEntropy = self._calculateOutDegreesEntropy(distinct_dests, firstPacketId, lastPacketId)

        #get the current timestamp 
        theTime = self.getCurrentTimeStamp()
        #create the different objects for holding entropy data, one to be returned and the other to be stored
        entropyPackage = [firstPacketId, inDegreeEntropy, outDegreeEntropy]
        data = [self.sensorId, theTime , firstPacketId, lastPacketId, inDegreeEntropy, outDegreeEntropy]
        
        self.logger.debug("Saving degree entropy data as: {}".format(data))
        database.create_degree_entropy(c, data)

        return entropyPackage
    
###################################################  Perform Alerting and Responses ###########################################################

    #Check to see if ANY of the entropies in the list has crossed the threshold deviation from upper or lower baseline
    def _checkTriggerCrossed(self, entropyValues):
        upperTriggerThreshold = self.baseline + self.threshold
        lowerTriggerThreshold = self.baseline - self.threshold
        self.logger.debug("Upper and lower baseline are:  {} for upper  and :  {} for lower ".format(upperTriggerThreshold, lowerTriggerThreshold))

        trigger = False
        for i in range(1, len(entropyValues)):
            if entropyValues[i] >= upperTriggerThreshold or entropyValues[i] <= lowerTriggerThreshold:
                self.logger.debug("Trigger detection on entropy value: {} ".format(entropyValues[i]))

                trigger = True
                break
        return trigger

    #generate a new bulk reports on for a given packet interval and sensor
    def _generateReportsOn(self, firstPacketId, lastPacktid):
        all_packets_ids = database.select_packetids_in_id_range(c, firstPacketId, lastPacktid )
        bulk_insert = []
        for packet_id_row in all_packets_ids:
            entry = (self.sensorId, packet_id_row["PacketId"])
            bulk_insert.append(entry)
        self.logger.debug("Building bulk import for data of length: {}".format(bulk_insert))
        database.create_bulk_alert_entry(c, bulk_insert)

    #generate a new response for the current time
    def _generateResponse(self, theTime):
        response_data = [randrange(1000), self.sensorId, self.threshold, self.timeWindow, theTime]
        self.logger.debug("Generating response with data: {}".format(response_data))
        database.create_response_entry(c, response_data )

    #process the result of the entropy profilers and determine whether an alert needs to be generated
    def processEntropyProfiler(self):
        self.logger.debug("Processing Anomaly Entropy Profile.")

        #draw a line in the sand and get the latest packet to be used for computation
        lastPacketId = self.getLastPacket()
        self.logger.debug("Got last packetId as: {}".format(lastPacketId))
       
        #get the last entropy row we accounted for so we can begin the count in this interval
        firstPacketAddressId = self.getLatestEntropyAddress()
        firstPacketPortId = self.getLatestEntropyPort()
        firstPacketDegreeId = self.getLatestEntropyDegree()
        #process each entropy feature
        entropies = []
        entropies.append(self._processAddressEntropy(firstPacketAddressId, lastPacketId))
        self.logger.debug(" Finsihed address Entropy")

        entropies.append(self._processPortEntropy(firstPacketPortId, lastPacketId))
        self.logger.debug(" Finsihed port Entropy")

        entropies.append(self._processDegreeEntropy(firstPacketDegreeId, lastPacketId))
        self.logger.debug(" Finsihed degree Entropy")

        self.logger.debug("Processing all entropy values {}".format(entropies))
        #for the entropy values obtained, determine whether the sensor could generate an alert
        for entropyData in entropies:
            self.logger.debug("Checking is entropy data value {} should trigger an alert ".format(entropyData))
            trigger = self._checkTriggerCrossed( entropyData)
            if trigger:
                self.logger.debug("Triggering on the sensor: {}".format(self.sensorId))
                #get the current timestamp 
                theTime = self.getCurrentTimeStamp()
                firstPacketId = entropyData[0]
                self._generateReportsOn(firstPacketId, lastPacketId)
                self._generateResponse( theTime)

if __name__ == '__main__':
    try:
        sensorTest = Sensor("QRadar-Content", 5, 2, 0.5, 0.3)
        sensorTest.processEntropyProfiler()
    except:
        raise 

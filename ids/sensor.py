import time
import sys
import os
import logging
import codecs
import math
from netaddr import CIDR, IP
from signal import signal, SIGINT, SIGQUIT
from datetime import datetime
from database import *
from random import randrange


db = "./detector.db"
conn = create_connection(db)
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

    def __init__(self, sensorid, timeWindow, baseline, threshold):
        """ Constructor
        """
        logging.basicConfig(
            filename='sensor.log',
            level=logging.DEBUG, 
            format= '[%(asctime)s] {%(pathname)s:%(lineno)d} %(levelname)s - %(message)s',
            datefmt='%m/%d/%Y %I:%M:%S %p'
        )
        self.logger = logging.getLogger(__name__)
        self.logger.info("Starting up sensor object")
        self.sensorId = sensorid
        self.timeWindow = timeWindow
        self.baseline = baseline
        self.threshold = threshold
        global conn, c

###################################################        Some Helper Functions            ###########################################################

    def IPinSubnet(self, ip, net):
        if IP(ip) in CIDR(net):
            return True
        else:
            return False

    def logVals(self, xvalues):
        self.logger.debug("Computed the xvalues to get the entropy from as: " + xvalues)

    def logRows(self, rows):
        self.logger.debug("Retrieved results from the db of size" + str(len(rows)))


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
            probability_x = x/total
            entropy += sign * (probability_x * math.log(probability_x, 2))
        self.logger.debug("Calculated entropy as " + str(entropy))
        #calculateNormalizedEntropy
        normalizedEntropy =  (entropy/ math.log(len(xvalues) , 2))
        self.logger.debug("Calculated normalized entropy as " + str(normalizedEntropy))
        return normalizedEntropy


###################################################  Getting Address Entropy Values ###########################################################

    def _calculateAddressSrcBytesEntropy(self, total, startid, endid):
        xvalues = []
        #now get the number of bytes with xi as the source address
        rows = select_source_address_bytes_in_id_range(c, startid, endid)
        return self.processRows(rows, "SumBytes", total)

    def _calculateAddressDstBytesEntropy(self, total, startid, endid):
        xvalues = []
        #now get the number of bytes with xi as the destination address
        rows = select_destination_address_bytes_in_id_range(c, startid, endid)
        return self.processRows(rows, "SumBytes", total)

    def _calculateAddressSrcPacketsEntropy(self, total, startid, endid):
        xvalues = []
        #now get the number of packets with xi as the source address
        rows = select_source_address_packets_in_id_range(c, startid, endid)
        return self.processRows(rows, "Count", total)


    def _calculateAddressDstPacketsEntropy(self, total, startid, endid):
        xvalues = []
        #now get the number of packets with xi as the destination address
        rows = select_destination_address_packets_in_id_range(c, startid, endid)
        return self.processRows(rows, "Count", total)



###################################################  Getting Port Entropy Values ###########################################################

    def _calculatePortSrcBytesEntropy(self, total, startid, endid):
        xvalues = []
        #now get the number of bytes with xi as the source port
        rows = select_source_port_bytes_in_id_range(c, startid, endid)
        return self.processRows(rows, "SumBytes", total)


    def _calculatePortDstBytesEntropy(self, total, startid, endid):
        xvalues = []
        #now get the number of bytes with xi as the destination port
        rows = select_destination_port_bytes_in_id_range(c, startid, endid)
        return self.processRows(rows, "SumBytes", total)


    def _calculatePortSrcPacketsEntropy(self, total, startid, endid):
        xvalues = []
        #now get the number of packets with xi as the source port
        rows = select_source_port_packets_in_id_range(c, startid, endid)
        return self.processRows(rows, "Count", total)

    def _calculatePortDstPacketsEntropy(self, total, startid, endid):
        xvalues = []
        #now get the number of packers with xi as the destination port
        rows = select_destination_port_packets_in_id_range(c, startid, endid)
        return self.processRows(rows, "Count", total)
    

###################################################  Getting Degrees Entropy Values ###########################################################

    def _calculateInDegreesEntropy(self, total, startid, endid):
        xvalues = []
        #now get the number of hosts with in degrees xi 
        rows = select_in_degrees_in_id_range(c, startid, endid)
        return self.processRows(rows, "Count", total)

    def _calculateOutDegreesEntropy(self, total, startid, endid):
        xvalues = []
        #now get the number of hosts with in degrees xi 
        rows = select_out_degrees_in_id_range(c, startid, endid)
        return self.processRows(rows, "Count", total)

###################################################  Getting Latest Packet Id Recorded In DB ###########################################################

    def processLastPacketFromEntropyTable(self, row):
        if len(row) == 0:
            return 0
        else:
            return row["LastPacket"]

    #for Address Entropy
    def getLatestEntropyAddress(self):
        row = select_latest_address_entropy(c, self.sensorId)
        self.processLastPacketFromEntropyTable(row)

    #for Ports
    def getLatestEntropyPort(self):
        row = select_latest_port_entropy(c, self.sensorId)
        self.processLastPacketFromEntropyTable(row)

    #for Degree
    def getLatestEntropyDegree(self):
        row = select_latest_degree_entropy(c, self.sensorId)
        self.processLastPacketFromEntropyTable(row)

    #get the newest packet recorded
    def getLastPacket(self):
        #get the last packet recoded
        row = select_latest_packet(c)
        if len(row) == 0:
            return 0
        else:
            return row["PacketId"]

    #get the curren time in timestamp format
    def getCurrentTimeStamp(self):
        # current date and time
        now = datetime.now()
        timestamp = datetime.timestamp(now)
        self.logger.debug("Saving the current timestamp =", timestamp)
        return timestamp
        

###################################################  Process the three Entropy Features ###########################################################
    def _processAddressEntropy(self, lastPacketId):
        #get the last entropy row we accounted for so we can begin the count in this interval
        firstPacketId = self.getLatestEntropyAddress()
        self.logger.debug("Looking at packets from packet Id" + str(firstPacketId))
        
        #first get the total bytes
        total_bytes_rows = select_total_bytes_in_id_range(x, firstPacketId, lastPacketId)
        if len(total_bytes_rows) == 0:
            total_bytes = 1
        else:
            total_bytes = total_bytes_rows[0]["TotalBytes"]
        self.logger.debug("Total bytes sent and received in this window is: " + str(total_bytes))

        #now get the total packets
        total_packets_rows = select_total_packets_in_id_range(x, firstPacketId, lastPacketId)
        if len(total_packets_rows) == 0:
            total_packets = 1
        else:
            total_packets = total_packets_rows[0]["TotalPackets"]
        self.logger.debug("Total packets sent and received in this window is: " + str(total_packets))

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
        
        self.logger.debug("Saving address entropy data as: " + data)
        create_port_entropy(c, data)
        
        return entropyPackage


    def _processPortEntropy(self, lastPacketId):
        #get the last entropy row we accounted for so we can begin the count in this interval
        firstPacketId = self.getLatestEntropyPort()
        self.logger.debug("Looking at packets from packet Id" + str(firstPacketId))
        
        #first get the total bytes
        total_bytes_rows = select_total_bytes_in_id_range(x, firstPacketId, lastPacketId)
        if len(total_bytes_rows) == 0:
            total_bytes = 1
        else:
            total_bytes = total_bytes_rows[0]["TotalBytes"]
        self.logger.debug("Total bytes sent and received in this window is: " + str(total_bytes))

        #now get the total packets
        total_packets_rows = select_total_packets_in_id_range(x, firstPacketId, lastPacketId)
        if len(total_packets_rows) == 0:
            total_packets = 1
        else:
            total_packets = total_packets_rows[0]["TotalPackets"]
        self.logger.debug("Total packets sent and received in this window is: " + str(total_packets))
        
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
        
        self.logger.debug("Saving address entropy data as: " + data)
        create_port_entropy(c, data)
        
        return entropyPackage

    def _processDegreeEntropy(self, lastPacketId):
        #get the last entropy row we accounted for so we can begin the count in this interval
        firstPacketId = self.getLatestEntropyDegree()
        self.logger.debug("Looking at packets from packet Id" + str(firstPacketId))
        
        #first get the total bytes
        distinct_source_rows = select_total_distinct_source_hosts_in_id_range(x, firstPacketId, lastPacketId)
        if len(distinct_source_rows) == 0:
            distinct_sources = 1
        else:
            distinct_sources = distinct_source_rows[0]["Count"]
        self.logger.debug("Total bytes sent and received in this window is: " + str(distinct_sources))

        #now get the total packets
        distinct_dest_rows = select_total_distinct_dest_hosts_in_id_range(x, firstPacketId, lastPacketId)
        if len(distinct_dest_rows) == 0:
            distinct_dests = 1
        else:
            distinct_dests = distinct_dest_rows[0]["Count"]
        self.logger.debug("Total packets sent and received in this window is: " + str(distinct_dests))
       
        #calculate the entropy values
        inDegreeEntropy = self._calculateInDegreesEntropy(distinct_sources, firstPacketId, lastPacketId)
        outDegreeEntropy = self._calculateOutDegreesEntropy(distinct_dests, firstPacketId, lastPacketId)

        #get the current timestamp 
        theTime = self.getCurrentTimeStamp()
        #create the different objects for holding entropy data, one to be returned and the other to be stored
        entropyPackage = [firstPacketId, inDegreeEntropy, outDegreeEntropy]
        data = [self.sensorId, theTime , firstPacketId, lastPacketId, inDegreeEntropy, outDegreeEntropy]
        
        self.logger.debug("Saving address entropy data as: " + data)
        create_degree_entropy(c, data)

        return entropyPackage
    
###################################################  Perform Alerting and Responses ###########################################################

    #Check to see if ANY of the entropies in the list has crossed the threshold deviation from upper or lower baseline
    def _checkTriggerCrossed(self, entropyValues):
        upperTriggerThreshold = self.baseline + self.threshold
        lowerTriggerThreshold = self.baseline - self.threshold
        self.logger.debug("Upper and lower baseline are: %s for upper %s for lower " % (upperTriggerThreshold, lowerTriggerThreshold))

        trigger = False
        for i in range(1, len(entropyValues)):
            if entropyValues[i] >= upperTriggerThreshold or entropyValues[i] <= lowerTriggerThreshold:
                self.logger.debug("Trigger detection on entropy value " + str(entropyValues[i]))

                trigger = True
                break
        return trigger

    #generate a new bulk reports on for a given packet interval and sensor
    def _generateReportsOn(self, firstPacketId, lastPacktid):
        all_packets_ids = select_packetids_in_id_range(c, firstPacketId, lastPacktid )
        bulk_insert = []
        for packet_id_row in all_packets_ids:
            entry = [self.sensorId, packet_id]
            bulk_insert.append(entry)
        self.logger.debug("Building bulk import for data of length: " + len(bulk_insert))
        create_bulk_alert_entry(c, bulk_insert)

    #generate a new response for the current time
    def _generateResponse(self, theTime):
        response_data = [randrange(1000), sensor, self.threshold, self.timeWindow, theTime]
        self.logger.debug("Generating response with data: " + response_data)
        create_response_entry(c, response_data )

    #process the result of the entropy profilers and determine whether an alert needs to be generated
    def processEntropyProfiler(self):

        #draw a line in the sand and get the latest packet to be used for computation
        lastPacketId = self.getLastPacket()

        #process each entropy feature
        entropies = []
        entropies.append(self._processAddressEntropy(lastPacketId))
        entropies.append(self._processPortEntropy(lastPacketId))
        entropies.append(self._processDegreeEntropy(lastPacketId))

        #for the entropy values obtained, determine whether the sensor could generate an alert
        for entropyData in entropies:
            trigger = self._checkTriggerCrossed( entropyData)
            if trigger:
                self.logger.debug("Triggering on the sensor " + str(self.sensorId))
                #get the current timestamp 
                theTime = self.getCurrentTimeStamp()
                firstPacketId = entropyData[0]
                self._generateReportsOn(firstPacketId, lastPacketId)
                self._generateResponse( theTime)









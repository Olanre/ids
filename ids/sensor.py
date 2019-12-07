import time
import sys
import os
import logging
import codecs
import math
from netaddr import CIDR, IP
from signal import signal, SIGINT, SIGQUIT
from database import *

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

    def IPinSubnet(self, ip, net):
        if IP(ip) in CIDR(net):
            return True
        else:
            return False

###################################################  Calculation Algorithm for Entropy  ###########################################################

    def calculateEntropy(self, xvalues, total):
        sign = -1
        entropy = 0.0
        for x in xvalues:
            probability_x = x/total
            entropy += sign * (probability_x * math.log(probability_x, 2))
        self.logger.debug("Calculated entropy as " + str(entropy))
        #calculateNormalizedEntropy
        normalizedEntropy =  (entropy/ math.log(len(xvalues) , 2))
        self.logger.debug("Calculated normalized entropy as " + str(normalizedEntropy))
        return normalizedEntropy


###################################################  Getting Address Entropy Values ###########################################################

    def calculateAddressSrcBytesEntropy(self, total, startid, endid):
        xvalues = []
        #now get the number of bytes with xi as the source address
        rows = select_source_address_bytes_in_id_range(c, startid, endid)
        for row in rows:
            xvalues.append( row["SumBytes"])
        #get shannon entropy
        return self.calculateEntropy(xvalues, total)

    def calculateAddressDstBytesEntropy(self, total, startid, endid):
        xvalues = []
        #now get the number of bytes with xi as the source address
        rows = select_destination_address_bytes_in_id_range(c, startid, endid)
        for row in rows:
            xvalues.append( row["SumBytes"])
        #get shannon entropy
        return self.calculateEntropy(xvalues, total)

    def calculateAddressSrcPacketsEntropy(self, total, startid, endid):
        xvalues = []
        #now get the number of bytes with xi as the source address
        rows = select_source_address_packets_in_id_range(c, startid, endid)
        for row in rows:
            xvalues.append( row["Count"])
        #get shannon entropy
        return self.calculateEntropy(xvalues, total)

    def calculateAddressDstPacketsEntropy(self, total, startid, endid):
        xvalues = []
        #now get the number of bytes with xi as the source address
        rows = select_destination_address_packets_in_id_range(c, startid, endid)
        for row in rows:
            xvalues.append( row["Count"])
        #get shannon entropy
        return self.calculateEntropy(xvalues, total)
    

###################################################  Getting Latest Packet Id Recorded In DB ###########################################################

    #for Address
    def getLastAddress(self):
        row = select_latest_address_entropy(c)
        if len(row) == 0:
            return 0
        else:
            return row["LastPacket"]

    #for Ports

    def getLastPort(self):
        row = select_latest_port_entropy(c)
        if len(row) == 0:
            return 0
        else:
            return row["LastPacket"]


    #for Degree
    def getLastDegree(self):
        row = select_latest_degree_entropy(c)
        if len(row) == 0:
            return 0
        else:
            return row["LastPacket"]


    def getLastPacket(self):
        #get the last packet recoded
        row = select_latest_packet(c)
        if len(row) == 0:
            return 0
        else:
            return row["PacketId"]

    def processAddressEntropy(self):
        #draw a line in the sand and get the latest packet to be used for computation
        lastPacketId = self.getLastPacket()

        #get the last entropy row we accounted for so we can begin the count in this interval
        firstPacketId = self.getLastAddress()
        self.logger.debug("Looking at packets from packet Id" + str(firstPacketId))
        
        #first get the total bytes
        total_bytes_rows = select_total_bytes_in_id_range(x, firstPacketId, lastPacketId)
        total_bytes = total_bytes_rows[0]["TotalBytes"]
        self.logger.debug("Total bytes sent and received in this window is: " + str(total_bytes))

        #now get the total packets
        total_packets_rows = select_total_packets_in_id_range(x, firstPacketId, lastPacketId)
        total_packets = total_packets_rows[0]["TotalPackets"]
        self.logger.debug("Total packets sent and received in this window is: " + str(total_packets))

        srcBytesEntropy = self.calculateAddressSrcBytesEntropy(total_bytes, firstPacketId, lastPacketId)
        dstBytesEntropy = self.calculateAddressDstBytesEntropy(total_bytes, firstPacketId, lastPacketId)
        srcPacketEntropy = self.calculateAddressSrcPacketsEntropy(total_packets, firstPacketId, lastPacketId)
        srcDstEntropy = self.calculateAddressDstPacketsEntropy(total_packets, firstPacketId, lastPacketId)


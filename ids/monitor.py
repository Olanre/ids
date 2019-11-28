import pyshark
import gc
import time
import sys
import os
import logging
import codecs
#from netaddr import CIDR, IP
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

class Monitor(object):

    def __init__(self, config=None):
        """ Constructor
        """
        logging.basicConfig(
            filename='monitor.log',
            level=logging.DEBUG, 
            format= '[%(asctime)s] {%(pathname)s:%(lineno)d} %(levelname)s - %(message)s',
            datefmt='%m/%d/%Y %I:%M:%S %p'
        )
        self.logger = logging.getLogger(__name__)
        self.logger.info("Starting up traffic monitor thread")
        self.config = {'timeout': 100,
                        'interface': 'localhost',
                        'output_file': 'monitor.pcap',
                        'packet_count': 5
                        }
        global conn, c
    
    def get_dst(self, pkt):
        if 'ip' in pkt:
            return pkt.ip.dst
        elif 'ipv6' in pkt:
            return pkt.ipv6.dst
        else:
            return ''

    def get_src(self, pkt):
        if 'ip' in pkt:
            return pkt.ip.src
        elif 'ipv6' in pkt:
            return pkt.ipv6.src
        else:
            return ''

    def get_len(self, pkt):
        if 'ip' in pkt:
            return pkt.ip.len
        else:
            return 0

    def get_ttl(self, pkt):
        if 'ip' in pkt:
            return pkt.ip.ttl
        else:
            return 0

    def get_flags(self, pkt):
        if 'tcp' in pkt:
            return pkt.tcp.flags
        else:
            return ''

    def get_highest_layer(self, pkt):
        return pkt.highest_layer

    def store_callback(self, pkt):
        self.logger.debug("Recieved Packet ")
        #print(pkt)
        layers = pkt.layers
        print(layers)
        TTL = self.get_ttl(pkt)
        DestinationAddr = self.get_dst(pkt)
        Length = self.get_len(pkt)
        SourceAddr = self.get_src(pkt)

        TotalLength = pkt.length if pkt.length else 0

        #EthernetProtocol = pkt.eth.type if 'ETH' in pkt and 'TYPE' in pkt.eth else ''
        EthernetProtocol = ''
        EthernetSrcAddr = pkt.eth.src if 'ETH' in pkt else ''
        EthernetDstAddr = pkt.eth.dst if 'ETH' in pkt else ''

        FrameType = pkt.frame_info.protocols if pkt.frame_info else ''
        FrameNumber = pkt.frame_info.number if pkt.frame_info else 0
        FrameLength = pkt.frame_info.cap_len if pkt.frame_info else 0


        ArrivalTime = pkt.sniff_timestamp if pkt.sniff_timestamp else 0
        InterfaceId = pkt.interface_captured if pkt.interface_captured else ''

        Protocol =  self.get_highest_layer(pkt)

        DstPort = pkt.tcp.dstport if 'tcp' in pkt else 0
        SrcPort = pkt.tcp.srcport if 'tcp' in pkt else 0
        Flags = self.get_flags(pkt)
        RawData = str(pkt.get_raw_packet())
        data = [TTL, DestinationAddr, Protocol, TotalLength, SourceAddr, EthernetProtocol,
        EthernetSrcAddr, EthernetDstAddr, FrameLength, FrameType, FrameNumber, ArrivalTime,
        InterfaceId, Length, DstPort, SrcPort, Flags, RawData]
        create_packet(c,data)


    def collect(self):
        #capture = pyshark.LiveCapture(interface='eth0', output_file='monitor.pcap' )
        capture = pyshark.FileCapture('/app/pcap/small.pcap', use_json=True, include_raw=True)
        capture.set_debug()
        capture.apply_on_packets(self.store_callback, timeout=60)




if __name__ == '__main__':
    try:
        monitor = Monitor()
        monitor.collect()
    except:
        raise 

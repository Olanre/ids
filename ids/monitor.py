import pyshark
import gc
import time
import sys
import os
import logging
from signal import signal, SIGINT, SIGQUIT
from datetime import datetime, timedelta
from database import create_packet


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
        self.logger = logging.basicConfig(
            filename='monitor.log',
            level=logging.DEBUG, 
            format= '[%(asctime)s] {%(pathname)s:%(lineno)d} %(levelname)s - %(message)s',
            datefmt='%m/%d/%Y %I:%M:%S %p'
        )
        self.logger.info("Starting up traffic monitor thread")
        self.config = {'timeout': 100,
                        'interface': 'localhost',
                        'output_file': 'monitor.pcap',
                        'packet_count': 5
                        }
    
    def store_callback(pkt):
        self.logger.debug("Recieved Packet ")
        layers = pkt.layers
        TTL = pkt.ip.ttl if pkt.ip in layers else 0
        DestinationAddr = pkt.ip.dst if pkt.ip in layers else ''
        Protocol =  pkt.transport_layer
        TotalLength = pkt.captured_length
        SourceAddr = pkt.ip.src if pkt.ip in layers else ''
        EthernetProtocol = pkt.eth.proto if pkt.eth in layers else ''
        EthernetSrcAddr = pkt.eth.src if pkt.eth in layers else ''
        EthernetDstAddr = pkt.eth.dst if pkt.eth in layers else ''
        FrameLength = pkt.frame_info.cap_length if pkt.frame_info in layers else 0
        FrameType = pkt.frame_info.protocols if pkt.frame_info in layers else ''
        FrameNumber = pkt.frame_info.number if pkt.frame_info in layers else 0
        ArrivalTime = pkt.sniff_timestamp
        InterfaceId = pkt.interface_captured
        Length = pkt.ip.len if pkt.ip in layers else 0
        DstPort = pkt[pkt.transport_layer].dstport
        SrcPort = pkt[pkt.transport_layer].srcport
        Flags = pkt.ip.flags if pkt.ip in layers else ''
        
        data = [TTL, DestinationAddr, Protocol, TotalLength, SourceAddr, EthernetProtocol,
        EthernetSrcAddr, EthernetDstAddr, FrameLength, FrameType, FrameNumber, ArrivalTime,
        InterfaceId, Length, DstPort, SrcPort, Flags ]
        self.logger.debug("Storing packet data %s " % (listToString(data)))

        create_packet(data)


    def poll(self, id):
        capture = pyshark.LiveCapture(interface=self.config['interface'], 
                                    output_file=self.config['output_file'] )
        capture.apply_on_packets(store_callback, timeout=self.config['timeout'])




if __name__ == '__main__':
    try:
        monitor = Monitor()
        monitor.collect()
    except Exception, e:
        print e
        sys.exit(0)

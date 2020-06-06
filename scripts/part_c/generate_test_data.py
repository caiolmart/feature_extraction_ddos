import pandas as pd
from datetime import datetime, timedelta
import logging
import os
from scapy.utils import rdpcap
from scapy.layers.inet import IP, UDP, TCP

from anubisflow import AnubisFG


logging.basicConfig(filename='logs/part_c/generate_test_data.log', 
                    format='%(asctime)s %(message)s', 
                    level=logging.DEBUG)
logging.info('Starting program.')

pcap_dir = 'data/raw/pcap/03-11'
pcap_files = os.listdir(pcap_dir)
pcap_files = [x for x in pcap_files if not '.zip' in x]
pcap_files = sorted(pcap_files, key=lambda x: int(x.split('_')[-1]))

afg = AnubisFG(only_twotuple=True)

outfile = f'data/interim/part_c/test_flows.csv'
f = open(outfile,'w')
idx = 0
for pcap_file in pcap_files:
    logging.info(f'memory_twotup has {len(afg.memory_twotup)} flows.')
    logging.info(f'Output file has {idx} rows.')
    logging.info(f'Reading pcap {pcap_file}')
    capture = rdpcap(f'{pcap_dir}/{pcap_file}')

    for packet in capture:
        afg.update(packet)
        key = (packet[IP].src, packet[IP].dst)
        mem = afg.memory_twotup[key]
        n_packets = sum(mem.fwd_pkt_protocol_counter.values()) + \
                    sum(mem.bck_pkt_protocol_counter.values())
        if n_packets % 100 == 0:
            ftrs = afg.generate_features(key)
            f.write(f'{key};{afg.lst_timestamp};')
            f.write(';'.join([str(x) for x in ftrs]))
            f.write('\n')
            idx += 1
            if n_packets == 5e4:
                del afg.memory_twotup[key]
    capture.close()
f.close()

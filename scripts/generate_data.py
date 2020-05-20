import pandas as pd
from datetime import datetime, timedelta
from pyshark.packet.fields import LayerFieldsContainer
import pyshark
import gc

from anubisflow import AnubisFG

pcap_num = 0
capture = pyshark.FileCapture('data/raw/pcap/01-12/SAT-01-12-2018_0', 
                              keep_packets=False)

files = [
    'DrDoS_DNS.csv',
    'DrDoS_LDAP.csv',
    'DrDoS_MSSQL.csv',
    'DrDoS_NetBIOS.csv',
    'DrDoS_SNMP.csv',
    'DrDoS_SSDP.csv',
    'DrDoS_UDP.csv',
]
afg = AnubisFG()

for filename in files:
    print(f'memory_twotup has {len(afg.memory_twotup)} flows.')
    print(f'memory_fivetup has {len(afg.memory_fivetup)} flows.')
    print(f'Reading data {filename}.')
    data = pd.read_csv(f'data/raw/csv/01-12/{filename}')
    data.columns = [x.strip() for x in data.columns]
    print(f'Data has shape {data.shape}')

    cols = [
        'Source IP',
        'Source Port',
        'Destination IP',
        'Destination Port',
        'Protocol',
        'Timestamp',
        'Flow Duration',
        'Label',
    ]
    data = data[cols]
    gc.collect()

    print('Preparing timestamps.')
    data['timestamp'] = data['Timestamp'].apply(lambda x: datetime.strptime(x, '%Y-%m-%d %H:%M:%S.%f'))
    data['lst_timestamp'] = data.apply(lambda x: x['timestamp'] + timedelta(microseconds=x['Flow Duration']), axis=1)

    protocols = {
        0 : 'HOPOPT',
        1 : 'ICMP',
        2 : 'IGMP',
        3 : 'GGP',
        4 : 'IPv4',
        5 : 'ST',
        6 : 'TCP',
        7 : 'CBT',
        8 : 'EGP',
        9 : 'IGP',
        10 : 'BBN-RCC-MON',
        11 : 'NVP-II',
        12 : 'PUP',
        13 : 'ARGUS',
        14 : 'EMCON',
        15 : 'XNET',
        16 : 'CHAOS',
        17 : 'UDP',
    }
    print('Preparing flow keys.')
    data['flow_key'] = data.apply(lambda x: (LayerFieldsContainer(x['Source IP']),
                                            LayerFieldsContainer(x['Source Port']),
                                            LayerFieldsContainer(x['Destination IP']),
                                            LayerFieldsContainer(x['Destination Port']),
                                            protocols[x['Protocol']]), axis=1)

    drop_cols = [
        'Source IP',
        'Source Port',
        'Destination IP',
        'Destination Port',
        'Protocol',
        'timestamp',
        'Timestamp',
        'Flow Duration',
    ]
    for col in drop_cols:
        del data[col]
    gc.collect()
    print('Sorting by lst_timestamp.')
    data.columns = [x.lower() for x in data.columns]
    data = data.sort_values('lst_timestamp')

    print('Flows done.')

    print('Reading pcap and generating features.')

    outfile = f'data/interim/flow_features_{filename}'
    f = open(outfile,'w')

    idx = 0
    len_data = data.shape[0]
    ts = data.iloc[idx, 1].to_pydatetime()
    key = data.iloc[idx, 2]
    label = data.iloc[idx, 0]
    while idx < len_data:
        try:
            # Try to get packet in this capture.
            packet = capture.next()
        except:
            # Get next pcap file
            pcap_num += 1
            capture.close()
            print(f'Reading pcap {pcap_num}')
            capture = pyshark.FileCapture(f'data/raw/pcap/01-12/SAT-01-12-2018_0{pcap_num}', 
                                        keep_packets=False)
            packet = capture.next()
        afg.update(packet)
        while afg.lst_timestamp >= ts:
            ftrs = afg.generate_features(key)
            f.write(f'{key};{ts};{label};')
            f.write(';'.join([str(x) for x in ftrs]))
            f.write('\n')
            idx += 1
            if idx < len_data:
                ts = data.iloc[idx, 1].to_pydatetime()
                key = data.iloc[idx, 2]
                label = data.iloc[idx, 0]
            else:
                break
    f.close()
    print('Done')
capture.close()

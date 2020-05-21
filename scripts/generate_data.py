import pandas as pd
from datetime import datetime, timedelta
from pyshark.packet.fields import LayerFieldsContainer
import pyshark
import gc

from anubisflow import AnubisFG

pcap_num = 0
capture = pyshark.FileCapture('data/raw/pcap/01-12/SAT-01-12-2018_0', 
                              keep_packets=False)

protocols = {
    0 : 'HOPOPT',
    1 : 'ICMP',
    2 : 'IGMP',
    3 : 'GGP',
    4 : 'IP',
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
    18 : 'MUX',
    19 : 'DCN-MEAS',
    20 : 'HMP',
    21 : 'PRM',
    22 : 'XNS-IDP',
    23 : 'TRUNK-1',
    24 : 'TRUNK-2',
    25 : 'LEAF-1',
    26 : 'LEAF-2',
    27 : 'RDP',
    28 : 'IRTP',
    29 : 'ISO-TP4',
    30 : 'NETBLT',
    31 : 'MFE-NSP',
    32 : 'MERIT-INP',
    33 : 'DCCP',
    34 : '3PC',
    35 : 'IDPR',
    36 : 'XTP',
    37 : 'DDP',
    38 : 'IDPR-CMTP',
    39 : 'TP++',
    40 : 'IL',
    41 : 'IP',
    42 : 'SDRP',
    43 : 'IPv6-Route',
    44 : 'IPv6-Frag',
    45 : 'IDRP',
    46 : 'RSVP',
    47 : 'GRE',
    48 : 'DSR',
    49 : 'BNA',
    50 : 'ESP',
    51 : 'AH',
    52 : 'I-NLSP',
    53 : 'SWIPE',
    54 : 'NARP',
    55 : 'MOBILE',
    56 : 'TLSP',
    57 : 'SKIP',
    58 : 'IPv6-ICMP',
    59 : 'IPv6-NoNxt',
    60 : 'IPv6-Opts',
    61 : 'any',
    62 : 'CFTP',
    63 : 'any',
    64 : 'SAT-EXPAK',
    65 : 'KRYPTOLAN',
    66 : 'RVD',
    67 : 'IPPC',
    68 : 'any',
    69 : 'SAT-MON',
    70 : 'VISA',
    71 : 'IPCV',
    72 : 'CPNX',
    73 : 'CPHB',
    74 : 'WSN',
    75 : 'PVP',
    76 : 'BR-SAT-MON',
    77 : 'SUN-ND',
    78 : 'WB-MON',
    79 : 'WB-EXPAK',
    80 : 'ISO-IP',
    81 : 'VMTP',
    82 : 'SECURE-VMTP',
    83 : 'VINES',
    84 : 'TTP',
    85 : 'NSFNET-IGP',
    86 : 'DGP',
    87 : 'TCF',
    88 : 'EIGRP',
    89 : 'OSPFIGP',
    90 : 'Sprite-RPC',
    91 : 'LARP',
    92 : 'MTP',
    93 : 'AX.25',
    94 : 'IPIP',
    95 : 'MICP',
    96 : 'SCC-SP',
    97 : 'ETHERIP',
    98 : 'ENCAP',
    99 : 'any',
    100 : 'GMTP',
    101 : 'IFMP',
    102 : 'PNNI',
    103 : 'PIM',
    104 : 'ARIS',
    105 : 'SCPS',
    106 : 'QNX',
    107 : 'AN',
    108 : 'IPComp',
    109 : 'SNP',
    110 : 'Compaq-Peer',
    111 : 'IPX-in-IP',
    112 : 'VRRP',
    113 : 'PGM',
    114 : 'any',
    115 : 'L2TP',
    116 : 'DDX',
    117 : 'IATP',
    118 : 'STP',
    119 : 'SRP',
    120 : 'UTI',
    121 : 'SMP',
    122 : 'SM',
    123 : 'PTP',
    124 : 'ISIS',
    125 : 'FIRE',
    126 : 'CRTP',
    127 : 'CRUDP',
    128 : 'SSCOPMCE',
    129 : 'IPLT',
    130 : 'SPS',
    131 : 'PIPE',
    132 : 'SCTP',
    133 : 'FC',
    134 : 'RSVP-E2E-IGNORE',
    135 : 'Mobility',
    136 : 'UDPLite',
    137 : 'MPLS-in-IP',
    138 : 'manet',
    139 : 'HIP',
    140 : 'Shim6',
    141 : 'WESP',
    142 : 'ROHC',
    143 : 'Ethernet',
}

files = [
    'DrDoS_NTP.csv',
    #'DrDoS_DNS.csv',
    #'DrDoS_LDAP.csv',
    #'DrDoS_MSSQL.csv',
    #'DrDoS_NetBIOS.csv',
    #'DrDoS_SNMP.csv',
    #'DrDoS_SSDP.csv',
    #'DrDoS_UDP.csv',
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
    data['timestamp'] = data['Timestamp'].apply(lambda x: datetime.strptime(x, '%Y-%m-%d %H:%M:%S.%f') + timedelta(hours=2))
    data['lst_timestamp'] = data.apply(lambda x: x['timestamp'] + timedelta(microseconds=x['Flow Duration']), axis=1)

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
    while True:
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
        if afg.lst_timestamp >= ts:
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

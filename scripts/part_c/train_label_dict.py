import pandas as pd
from collections import defaultdict
from datetime import datetime, timedelta
import pickle

files = [
    'DrDoS_NTP.csv',
    'DrDoS_DNS.csv',
    'DrDoS_LDAP.csv',
    'DrDoS_MSSQL.csv',
    'DrDoS_NetBIOS.csv',
    'DrDoS_SNMP.csv',
    'DrDoS_SSDP.csv',
    'DrDoS_UDP.csv',
    'UDPLag.csv',
    'Syn.csv',
    'TFTP.csv',
]

label_dict = defaultdict(dict)
for file in files:
    print(f'Reading {file}')
    data = pd.read_csv(f'data/raw/csv/01-12/{file}')
    data.columns = [x.strip() for x in data.columns]
    print(f'Preparing timestamps')
    data['timestamp'] = data['Timestamp'].apply(lambda x: datetime.strptime(x, '%Y-%m-%d %H:%M:%S.%f') + timedelta(hours=4))
    print(data.shape)
    data.head()
    print(f'Grouping data')
    group = data.groupby(['Source IP', 'Destination IP', 'Label']).agg({'Timestamp': 'max'}).reset_index()
    print(f'Inserting into dictionary')
    for index, row in group.iterrows():
        label_dict[(row['Source IP'][0], row['Destination IP'][0])][row['Label'][0]] = row['Timestamp'][0]
    del data
    del group
    print('Done\n')

with open('data/interim/part_c/train_label_dict.pkl', 'wb') as filename:
    pickle.dump(label_dict, filename)
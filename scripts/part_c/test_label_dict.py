import pandas as pd
from collections import defaultdict
from datetime import datetime, timedelta
import pickle

files = [
    'Portmap.csv',
    'NetBIOS.csv',
    'LDAP.csv',
    'MSSQL.csv',
    'UDP.csv',
    'UDPLag.csv',
    'Syn.csv',
]

label_dict = defaultdict(dict)
for file in files:
    print(f'Reading {file}')
    data = pd.read_csv(f'data/raw/csv/03-11/{file}')
    data.columns = [x.strip() for x in data.columns]
    print(f'Preparing timestamps')
    data['timestamp'] = data['Timestamp'].apply(lambda x: datetime.strptime(x, '%Y-%m-%d %H:%M:%S.%f') + timedelta(hours=3))
    print(data.shape)
    data.head()
    print(f'Grouping data')
    group = data.groupby(['Source IP', 'Destination IP', 'Label']).agg({'timestamp': 'max'}).reset_index()
    print(f'Inserting into dictionary')
    for index, row in group.iterrows():
        label_dict[(row['Source IP'], row['Destination IP'])][row['Label']] = row['timestamp']
    del data
    del group
    print('Done\n')

with open('data/interim/part_c/test_label_dict.pkl', 'wb') as filename:
    pickle.dump(label_dict, filename)
# -*- coding: utf-8 -*-
"""
Spyder Editor

This is a temporary script file.
"""

import sqlite3

PATH="data/WiGLE_Backup.db"
net = "network"
loc = "location"

con = sqlite3.connect(PATH)
cur=con.cursor()


query = "DELETE FROM {} WHERE type != ? and type != ?".format(net)
cur.execute(query, ('W', 'B'))

query = "select count(*) from {}".format(net)
print("The number of WiFi and Bluethooth data is",cur.execute(query).fetchone()[0])

query = "select bssid from {}".format(net)
cur.execute(query)

rts=cur.fetchall()
rt_str=[]
for rt in rts:
    # transfer all the rt(tuple) into string
    #print(rt)
    s = ','.join(rt)
    rt_str.append(s)


#cur.execute('''CREATE TABLE vendor (mac TEXT,Registry TEXT,Assignment TEXT,OrganizationName TEXT,OrganizationAddress TEXT)''')

import pandas as pd

# Load the Excel file
df_L = pd.read_excel('data/ieeeMac/macL.xlsx')
df_M = pd.read_excel('data/ieeeMac/macM.xlsx')
df_S = pd.read_excel('data/ieeeMac/macS.xlsx')


i3e = pd.concat([df_L, df_M, df_S], axis=0, ignore_index=True)

# Create a list to store the matched data
matches = []

for string in rt_str:
    
    search_column = 'Assignment'
    
    # Find the row that matches the string in the specified column
    matching_row = i3e.loc[i3e[search_column] == string[0:8].replace(":","")]
    #print(string[0:8].replace(":",""))
    # 将匹配的结果写入数据库
    if not matching_row.empty:
        if matching_row['Registry']=='MA-M':
            matching_row = i3e.loc[i3e[search_column] == string[0:9].replace(":","")]
        elif matching_row['Registry']=='MA-S':
            matching_row = i3e.loc[i3e[search_column] == string[0:10].replace(":","")]
        if not matching_row.empty:
            matches.append({'mac':string,'Registry':matching_row['Registry'],'Assignment':matching_row['Assignment'],'OrganizationName':matching_row['OrganizationName'],'OrganizationAddress':matching_row['OrganizationAddress']})
        
            
        for index, row in matching_row:
            # 以适当的方式将数据插入到数据库表中
            cur.execute("INSERT INTO table (mac,Registry,Assignment,OrganizationName,OrganizationAddress) VALUES (?, ?,?,?,?)", (string,row['Registry'], row['Assignment'],row['OrganizationName'],row['OrganizationAddress']))
            

# Output the matched data to a new Excel file
matched_df = pd.DataFrame(matches)
#matched_df.to_excel('matched_data.xlsx', index=False)

import sqlite3
import pandas as pd
import matplotlib.pyplot as plt

PATH="data/WiGLE_Backup.db"
net = "network"
loc = "location"
WiWiFi="wigle_wifi"
WiBL="wigle_blue"
cve0="cve_basic"
cve1="cve_metrics_2"
cve2="cve_metrics_3"
cve3="cve_weaknesses"


con=sqlite3.connect(PATH)
cur=con.cursor()

sql="""
        select capabilities, count(*)
        from (
            select capabilities from network where type!='W'
            UNION ALL
            SELECT capabilities from wigle_blue
        ) 
        GROUP by capabilities
    """
df=pd.read_sql_query(sql, con)
print("There are {} types of capabilities\n".format(df.shape[0]),df)
con.close()

#df['capabilities']=df['capabilities'].replace([";10", "', '10']","', '12']"],'')

df['capabilities']=df['capabilities'].str.replace(";10",'')
df['capabilities']=df['capabilities'].str.replace("', '10']",'')
df['capabilities']=df['capabilities'].str.replace("\['",'')
df['capabilities']=df['capabilities'].str.replace("', '12']",'')
df['capabilities']=df['capabilities'].str.replace("']",'')

print(df)


mask = df['capabilities'].str.contains('null|Uncategorized|Misc|\[]')

# add new column 'c' with value 'c' for rows containing 'n' in column 'A'
df.loc[mask, 'capabilities'] = 'Uncategorized'

# group by column 'c' and compute the sum of corresponding values in column 'D'
result = df.groupby('capabilities')

# print result
print(result)
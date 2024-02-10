# -*- coding: utf-8 -*-
"""
Spyder Editor

This is a temporary script file.
"""
import re
import sqlite3
import pandas as pd

PATHS = ["data/ieeeMac/macL.txt", "data/ieeeMac/macM.txt", "data/ieeeMac/macS.txt"]
PATH_DB = "data/WiGLE_Backup.db"

con = sqlite3.connect(PATH_DB)
cur = con.cursor()

cur.execute("DELETE FROM i3e")

flag = False

pd_list = []
OrganizationAddress = ""
for PATH in PATHS:
    with open(PATH, 'r', encoding='UTF-8') as f:
        # Read the contents of the file
        Registry = PATH.split("/")[2].split(".")[0]
        for line in f:
            # Do something with the line
            # print(line)

            if "(hex)" in line:
                Assignment = line.split(" ")[0].replace("-","")
            if "(base 16)" in line:
                flag = True
                OrganizationAddress = ''
                if Registry=="macS":
                    Assignment+=line[0:2]
                elif Registry=="macM":
                    Assignment+=line[0]
                OrganizationName = line.split("\t")[2]
                continue
            if line == '\n':
                flag = False
                if OrganizationAddress != "":
                    if Registry=="macL":
                        Assignment = Assignment[0:2]+":"+Assignment[2:4]+":"+Assignment[4:6]
                    elif Registry=="macM":
                        Assignment = Assignment[0:2] + ":" + Assignment[2:4] + ":" + Assignment[4:6]+":"+Assignment[6:7]
                    else:
                        Assignment = Assignment[0:2] + ":" + Assignment[2:4] + ":" + Assignment[4:6] + ":" + Assignment[6:8]
                    pd_list.append(
                        {'Registry': Registry, 'Assignment': Assignment, 'OrganizationName': OrganizationName,
                         'OrganizationAddress': OrganizationAddress})
                    cur.execute(
                        "INSERT INTO  i3e (Registry,Assignment,OrganizationName,OrganizationAddress) VALUES (?,?,?,?)",
                        (Registry, Assignment, OrganizationName, OrganizationAddress))

                continue
            else:
                if flag == True:
                    match = re.search(r'[^\s].*?\n', line)
                    if match == None:
                        continue
                    OrganizationAddress += match.group(0)
con.commit()
con.close()
#matched_df = pd.DataFrame(pd_list)

import requests
import sqlite3
import threading
import json
import pandas as pd

URL_open = "https://www.opencve.io/api/vendors/{}/cve?page={}"
auth = ('YingliDuan', 'ocveLXRdyl844')

header = {"Authorization": "token user:679c2955085b46e48155b84f4c878844",}
URL="https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={}"
URL_keyword="https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={}"

PATH="E:/workplace\jupyter/vulnerability/data/WiGLE_Backup - Copy (2).db"
cve0="cve_basic"
cve1="cve_metrics_2"
cve2="cve_metrics_3"
cve3="cve_weaknesses"

import time


def insertDB(theme, results, keywords):
    con = sqlite3.connect(PATH)
    c = con.cursor()
    print("----insert vulnerabilities into database----")
    print("******** {},{}********".format(theme, keywords))
    print(results)
    # data_es=results['vulnerabilities']
    data_es = results
    # print(data_es)
    i_b = 0
    i_m = 0
    i_w = 0
    for data in data_es:
        for des in data.get('cve').get("descriptions"):
            i_b += 1
            # print(des)
            c.execute('''INSERT OR IGNORE INTO cve_basic (id, published, lastModified, vulnStatus, description_value,keywords)
                  VALUES (?, ?, ?, ?, ?, ?)''',
                      (data.get('cve').get('id'),
                       data.get('cve').get('published'),
                       data.get('cve').get('lastModified'),
                       data.get('cve').get('vulnStatus'),
                       des.get('value'),
                       keywords,
                       ))

        cvsses = list(data.get('cve').get("metrics").keys())
        if cvsses is not None:
            for cvss in cvsses:
                items = data.get('cve').get('metrics').get(cvss)
                if "cvssMetricV2" in cvss:
                    for item in items:
                        i_m += 1
                        c.execute('''INSERT OR IGNORE INTO cve_metrics_2 (id, cvss_type,type, cvssVersion, vectorString, accessVector, accessComplexity,
                              authentication, confidentialityImpact, integrityImpact, availabilityImpact, baseScore, baseSeverity,
                              exploitabilityScore, impactScore, acInsufInfo, obtainAllPrivilege, obtainUserPrivilege, obtainOtherPrivilege,
                              userInteractionRequired)
                              VALUES (?, ?, ?, ?,  ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,?,?)''',
                                  (data.get('cve').get('id'),
                                   cvss,
                                   item.get('type'),
                                   item.get('cvssData').get('version'),
                                   item.get('cvssData').get('vectorString'),
                                   item.get('cvssData').get('accessVector'),
                                   item.get('cvssData').get('accessComplexity'),
                                   item.get('cvssData').get('authentication'),
                                   item.get('cvssData').get('confidentialityImpact'),
                                   item.get('cvssData').get('integrityImpact'),
                                   item.get('cvssData').get('availabilityImpact'),
                                   item.get('cvssData').get('baseScore'),
                                   item.get('baseSeverity'),
                                   item.get('exploitabilityScore'),
                                   item.get('impactScore'),
                                   item.get('acInsufInfo'),
                                   item.get('obtainAllPrivilege'),
                                   item.get('obtainUserPrivilege'),
                                   item.get('obtainOtherPrivilege'),
                                   item.get('userInteractionRequired')))
                if "cvssMetricV3" in cvss:
                    for item in items:
                        i_m += 1
                        c.execute('''INSERT OR IGNORE INTO cve_metrics_3 (id, cvss_type, type, cvssVersion, vectorString, attackVector, attackComplexity,
                                  privilegesRequired, userInteraction, scope, confidentialityImpact, integrityImpact, availabilityImpact, baseScore, baseSeverity,
                                  exploitabilityScore, impactScore)
                                  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                                  (data.get('cve').get('id'),
                                   cvss,
                                   item.get('type'),
                                   item.get('cvssData').get('version'),
                                   item.get('cvssData').get('vectorString'),
                                   item.get('cvssData').get('attackVector'),
                                   item.get('cvssData').get('attackComplexity'),
                                   item.get('cvssData').get('privilegesRequired'),
                                   item.get('cvssData').get('userInteraction'),
                                   item.get('cvssData').get('scope'),
                                   item.get('cvssData').get('confidentialityImpact'),
                                   item.get('cvssData').get('integrityImpact'),
                                   item.get('cvssData').get('availabilityImpact'),
                                   item.get('cvssData').get('baseScore'),
                                   item.get('cvssData').get('baseSeverity'),
                                   item.get('exploitabilityScore'),
                                   item.get('impactScore')))
        weaknesses = data.get('cve').get('weaknesses')
        if weaknesses is not None:
            for weak in weaknesses:
                for value in weak['description']:
                    i_w += 1
                    # (data.get('cve').get('id'),weak.get('type'),value)
                    # print(data.get('cve').get('id'),weak.get('type'),value)

                    c.execute('''INSERT OR IGNORE INTO cve_weaknesses (id,type,description_value) VALUES(?,?,?)''',
                              (data.get('cve').get('id'), weak.get('type'), value.get("value")))

    con.commit()
    con.close()
    print("cve_basic:", i_b)
    print("cve_metrics:", i_m)
    print("cve_weaknesses:", i_w)
    print("---- DONE {}----".format(keywords))


def collect_load_CVE(cve_dict, title, url):
    con = sqlite3.connect(PATH)
    cur = con.cursor()
    sql = "select * from {} ".format(cve0)
    cve_rt = pd.read_sql_query(sql, con)
    con.close()

    results_types = dict.fromkeys(cve_dict)
    flag = False

    for rt in results_types:
        cves = cve_dict[rt]
        cves_rt = []
        for cve in cves:

            #             if rt=='acer':
            #                 flag=True
            flag = True
            if cve in cve_rt['id'].values:
                flag = False
            if flag == True:
                url_n = url.format(cve)

                print(url_n)
                response = requests.get(url_n)
                # print(response.json())
                if response.status_code == 200:
                    cves_rt.append(response.json()['vulnerabilities'][0])
                print(response.status_code)
                time.sleep(6)
        print("UPLODING")
        insertDB(title, cves_rt, rt)


# A ratelimit of 1000 requests per hour and per user is applied on OpenCVE.io.
cves = {}


def collect_cve_id(vendors):
    request_times = 0

    con = sqlite3.connect(PATH)
    cur = con.cursor()
    vendor_flag = False
    for vendor in vendors:
        print(vendor, "-")
        page = 1
        flag = True

        if vendor == 'emerson':
        #     vendor_flag = True
        # if vendor_flag == False:
        #     continue

            sql = "select * from {} where keywords='{}'".format(cve0, vendor)
            rt = cur.execute(sql).fetchall()
            print(vendor, len(rt))
            if len(rt) != 0:
                print("vendor {} found".format(vendor))
                #continue

            vendor_data = []
            while flag:
                time.sleep(2)
                if flag == True:
                    url = URL_open.format(vendor, page)
                    print(url)
                    response = requests.get(url, auth=auth)
                    print(response.status_code)
                    page += 1
                    if response.status_code == 200:
                        # Success! Do something with the response data
                        data = response.json()
                        vendor_data = vendor_data + data
                        if len(data) < 20:
                            flag = False

                        print("length of this response:", len(data))
                    else:
                        flag = False
                        print(f"Request failed with status code {response.status_code}")
                    if response.status_code == 429:
                        cves[vendor] = [ids['id'] for ids in vendor_data]
                        print("To much data in this hour")
                        con.close()
                        return cves
            cves[vendor] = [ids['id'] for ids in vendor_data]
    con.close()
    return cves


ULW_P = ["EUROPE", "BEIJING", "SHENZHEN", "AMERICA", "SICHUAN", "HUI", "ZHOU", "Hong", "KONG", "SHANGHAI", "ASIA", "CH",
         "USA", "BELGIUM",
         "ZHUHAI", "GUANGZHOU"]  # useless word-place
ULW_S = ["COMPUTER", "SYSTEMS", "CO", "LTD", "LIMITED", "CORPORATION", "CORP", "COMMUNCATIONS", "COMMUNICATION",
         "COMMUNICATIONS", "ELECTRONIC", "ELECTRONICS",
         "NETWORK", "INC", "LLC", "COMPANY", "INTERNATIONAL", "WIRELESS", "DATA", "MEDICAL", "AG", "Electric",
         "NETWORKING", "ELECTRIC",
         "SRO", "BV", "SYS", "INDUSTRIALS", "INDUSTRIAL", "DEVICE", "DEVICES", "COMM", "TECHNOLOGY", "TECHNOLOGIES",
         "TECH", "COLTD", "A/S", "DELIVERY", "NV",
         "NETWORKS", "APPLICATIONS", "OF", "APS", "GROUP", "IND", "DEVELOPMENT", "AS", "AB", "OY", "IOT", "INNOTEK",
         "GMBH", "AUDIOVISUELLES",
         "MARKETING", "UND", "COMPUTERSYSTEME", "MACHINE", "ELECTRO", "MECHANICS", "MOBILE", "SOFTWARE", "DIGITAL",
         "TECHLTD", "INFORMATION",
         "AUTOMOTIVE", "CORPORATE", "ENTERPRISE", "LABORATORY", "LABORATORIES"]  # useless word-suffix


def clean_name(vendors, cur):
    vens = []
    vendors = list(vendors)

    for vendor in vendors:
        rt = vendor[0].replace(",", "").replace(".", "").replace("\n", "").replace("，", "").replace("'", "")
        rt_s = rt.split(" ")
        if rt_s[0] == "Harman/Becker":
            name = ["Harman"]
        elif rt_s[0] == "Nokia":
            name = ["Nokia"]
        else:
            name = [r for r in rt_s if
                    r.upper() not in ULW_P and r.upper() not in ULW_S and "(" not in r and ")" not in r]
        # print(name)
        if len(name) != 0:
            sql = "select * from {} where keywords='{}'".format(cve0, name[0].lower())
            # if len(cur.execute(sql).fetchall())==0 and name[0]!='':
            if name[0] != '':
                vens.append(name[0].lower())
    return vens

con = sqlite3.connect(PATH)
cur = con.cursor()
sql="""SELECT DISTINCT vendor.OrganizationName
        FROM vendor
        JOIN (
            SELECT bssid as netid
            FROM network 
            WHERE type = 'B' or type = 'E'
            UNION ALL 
            SELECT netid
            FROM wigle_blue
        ) AS network_blue
        WHERE network_blue.netid = vendor.mac
        GROUP BY vendor.OrganizationName
        """
rts_BT=cur.execute(sql).fetchall()
print("******Results of BT*******\n",len(rts_BT),rts_BT)
rts_BT=list(set(clean_name(rts_BT,cur)))
print("********CLEANED NAME*********\n",len(rts_BT),rts_BT)

sql="""select distinct keywords
        from cve_basic
"""
rts=cur.execute(sql).fetchall()
print("keywords in possesed vulunerabilities:",len(rts))
rts_BT_1=[]
for r in rts_BT:
    if r in rts:
        continue
    rts_BT_1.append(r)
print("********FILTER*********\n",len(rts_BT_1),rts_BT_1)

con.close()

cveIDs_BT=collect_cve_id(rts_BT_1)

collect_load_CVE(cveIDs_BT,"BT Vendors",url=URL)
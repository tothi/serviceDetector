#!/usr/bin/env python3
#
# convert csv config to json format
#
# csv format:
#
# product_name;service;service_name;optional description
# product_name;pipe;named_pipe_path;optional comma separated exe list
#
# csv example:
#
# Bitdefender;service;bdredline_agent;Bitdefender Agent RedLine Service
# Bitdefender;pipe;local\\msgbus\\antitracker.low\\*;bdagent.exe
#

import sys
import csv, json

if len(sys.argv) != 3:
    print("usage: {} csv_input json_output".format(sys.argv[0]))
    exit(1)

j = {}
j['products'] = {}

with open(sys.argv[1], newline='') as csvfile:
    s = csv.reader(csvfile, delimiter=';')
    for r in s:
        try:
            d = r[3]
        except:
            d = ""
        if r[0] not in j['products'].keys():
            j['products'][r[0]] = {"name": r[0], "services": [], "pipes": []}
        if r[1] == "service":
            t = {"name":r[2], "description":d}
        elif r[1] == "pipe":
            t = {"name":r[2], "processes":d.split(",")}
        j['products'][r[0]][r[1]+"s"].append(t)

j2 = {}
j2['products'] = []
for p in j['products']:
    j2['products'].append(j['products'][p])

with open(sys.argv[2], "w") as jsonfile:
    json.dump(j2, jsonfile, indent = 2)


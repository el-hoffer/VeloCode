#!/usr/bin/env python3

import os
import scriptvars
import requests
import json
import csv
from geopy.distance import geodesic as GD

token = "Token %s" %(os.environ['VCO_Token'])
headers = {"Content-Type": "application/json", "Authorization": token}
vco_url = 'https://' + os.environ['VCO_URL'] + '/portal/rest/'
get_edges = vco_url + 'enterprise/getEnterpriseEdges'
pdxpop = (45.58333, -122.6)
laxpop = (33.93333, -118.4)
slcpop = (40.78333, -111.96666)
dfwpop = (32.76666, -96.78333)

def main():
    with open('popdistlist.csv', 'w') as f:
        writer = csv.writer(f)
        writer.writerow(["Edge Name", "Bandwidth Tier", "Miles to PDX", "Miles to LAX", "Miles to SLC", "Miles to DFW", "Closest PoP"])
        #Retrieve all edges
        payload = {
            "id": 901,
            "with": [
                "site",
                "licenses"
            ]
        }
        try:
            edgelist = requests.post(get_edges, headers=headers, data=json.dumps(payload))
        except Exception as e:
            print(e)
        #convert to json
        edgelistjson = edgelist.json()
        #calculate distance to each pop for each edge
        for edge in edgelistjson:
            edgename = str(edge['name'])
            bandwidth = str(edge['licenses'][0]['bandwidthTier'])
            edgelat = edge['site']['lat']
            edgelong = edge['site']['lon']
            edgecoord = (edgelat, edgelong)
            pdxdist = round(GD(pdxpop, edgecoord).miles, 2)
            laxdist = round(GD(laxpop, edgecoord).miles, 2)
            slcdist = round(GD(slcpop, edgecoord).miles, 2)
            dfwdist = round(GD(dfwpop, edgecoord).miles, 2)
            #find closest PoP
            distlist = [pdxdist, laxdist, slcdist, dfwdist]
            smallest = min(distlist)
            if pdxdist == smallest:
                closest = "PDX"
            elif laxdist == smallest:
                closest = "LAX"    
            elif slcdist == smallest:
                closest = "SLC"
            else:
                closest = "DFW"
            #print('Edge ' + str(edgename) + ' is closest to ' + str(closest))
            #write values to csv
            writer.writerow([edgename, bandwidth, pdxdist, laxdist, slcdist, dfwdist, closest])
        

if __name__ == '__main__':
    main()
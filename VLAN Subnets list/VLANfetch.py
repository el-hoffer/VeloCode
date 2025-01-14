#!/usr/bin/env python3

import os
import scriptvars
import requests
import json
import csv

token = "Token %s" %(os.environ['VCO_Token'])
headers = {"Content-Type": "application/json", "Authorization": token}
vco_url = 'https://' + os.environ['VCO_URL'] + '/portal/rest/'
vco_url_v2 = 'https://' + os.environ['VCO_URL'] + '/api/sdwan/v2/'
get_enterprise = vco_url + 'enterprise/getEnterprise'
get_edges = vco_url + 'enterprise/getEnterpriseEdges'


#function record VLANs
def getvlans(enterpriseid, edgeid, edgename):
	#retrieve edge device settings
	edge_dev_settings_mod = vco_url_v2 + 'enterprises/' + enterpriseid + '/edges/' + edgeid + '/deviceSettings'
	try:
		devicesettings = requests.get(edge_dev_settings_mod, headers=headers)
	except Exception as e:
		print(e + 'received on edge ' + str(edgename))
	#convert to json
	devicesettingsjson = devicesettings.json()
	#Record VLAN ID, name, ip, and subnet prefix length in the CSV file
	with open('vlanlist.csv', 'a') as f:
		writer=csv.writer(f)
		for vlan in devicesettingsjson['lan']['networks']:
			vlanid = vlan['vlanId']
			vlanname = vlan['name']
			vlanip = vlan['cidrIp']
			vlanprefix = vlan['cidrPrefix']
			writer.writerow([edgename, vlanname, vlanid, vlanip, vlanprefix])
		

def main():
	#Add headers to CSV file
	with open('vlanlist.csv', 'w') as f:
		writer = csv.writer(f)
		writer.writerow(['Edge Name', 'VLAN Name', 'VLAN ID', 'IP Address', 'Prefix Length'])
	#Record enterprise logical ID for future calls
	try:
		enterprise = requests.post(get_enterprise, headers=headers)
	except Exception as e:
		print(e)
	#convert to json
	enterprisejson = enterprise.json()
	enterpriseid = enterprisejson['logicalId']
	#Retrieve all edges
	try:
		edgelist = requests.post(get_edges, headers=headers)
	except Exception as e:
		print(e)
	#convert to json
	edgelistjson = edgelist.json()
	for edge in edgelistjson:
		edgeid = edge['logicalId']
		edgename = edge['name']
		getvlans(enterpriseid, edgeid, edgename)
		

if __name__ == '__main__':
    main()
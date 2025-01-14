#!/usr/bin/env python3

import os
import scriptvars
import requests
import json

token = "Token %s" %(os.environ['VCO_Token'])
headers = {"Content-Type": "application/json", "Authorization": token}
vco_url = 'https://' + os.environ['VCO_URL'] + '/portal/rest/'
get_edges = vco_url + 'enterprise/getEnterpriseEdges'
edge_conf = vco_url + 'edge/getEdgeConfigurationStack'
conf_update = vco_url + 'configuration/updateConfigurationModule'


#function to set dhcp relay servers
def setdhcprelay(edgeid, edgename):
	edge_attr = {'edgeId': edgeid}
	#retrieve edge configuration stack
	try:
		edgeconf = requests.post(edge_conf, headers=headers, data=json.dumps(edge_attr))
	except Exception as e:
		print(e + 'received on edge ' + str(edgename))
	#convert to json
	edgeconfjson = edgeconf.json()
	confmoduleid = 0
	#Find the Device Settings configuration module in edge specific profile and collect module ID and data object
	for module in edgeconfjson[0]['modules']:
		if module['name'] == 'deviceSettings':
			devicesettings = module['data']
			confmoduleid = module['id']
		else:
			continue
	#replace GE2 dhcp relay servers with 2.2.2.2 and 3.3.3.3
	if confmoduleid != 0:
		devicesettings['routedInterfaces'][1]['dhcpServer']['dhcpRelay']['servers'] = ['2.2.2.2','3.3.3.3']
		#print(str(devsettings))
		setdhcprelayservers = {	"id": confmoduleid,
							  "_update": {
								"data": devicesettings,
								"description": "",
								"name": "WAN"
							  }
							}
		setpolicy = requests.post(conf_update, headers=headers, data=json.dumps(setdhcprelayservers))

	else:
		#print module not found
		print('deviceSettings module not found for edge ' + str(edgename))
		

def main():
	#Retrieve all edges
		try:
			edgelist = requests.post(get_edges, headers=headers)
		except Exception as e:
			print(e)
		#convert to json
		edgelistjson = edgelist.json()
		for edge in edgelistjson:
			edgeid = edge['id']
			edgename = edge['name']
			setdhcprelay(edgeid, edgename)
		

if __name__ == '__main__':
    main()
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


#function to enable ENI on the specified edge
def setdynbwtest(edgeid, edgename):
	edge_attr = {'edgeId': edgeid}
	#retrieve edge configuration stack
	try:
		edgeconf = requests.post(edge_conf, headers=headers, data=json.dumps(edge_attr))
	except Exception as e:
		print(e + 'received on edge ' + str(edgename))
	#convert to json
	edgeconfjson = edgeconf.json()
	confmoduleid = 0
	#Find the WAN configuration module in edge specific profile and collect module ID and data object
	for module in edgeconfjson[0]['modules']:
		if module['name'] == 'WAN':
			wansettings = module['data']
			confmoduleid = module['id']
		else:
			continue
	#if bwMeasurement is not SLOW_START, set to slow start and set up/down BW to null
	if confmoduleid != 0:
		for link in wansettings['links']:
			if link['bwMeasurement'] != 'SLOW_START':
				link['bwMeasurement'] = 'SLOW_START'
				link['upstreamMbps'] = None
				link['downstreamMbps'] = None
				print('Updating Bandwidth Test settings on edge ' + str(edgename) + ' link ' + str(link['name']))
			else:
				print('Edge ' + str(edgename) + ' link' + str(link['name']) + ' is already set for dynamic BW adjustment')
		#print(str(devsettings))
		setslowstartparams = {	"id": confmoduleid,
							  "_update": {
								"data": wansettings,
								"description": "",
								"name": "WAN"
							  }
							}
		setpolicy = requests.post(conf_update, headers=headers, data=json.dumps(setslowstartparams))

	else:
		#print module not found
		print('WAN module not found for edge ' + str(edgename))
		

def main():
	#Retrieve all edges
		try:
			edgelist = requests.post(get_edges, headers=headers)
		except Exception as e:
			print(e)
		#convert to json
		edgelistjson = edgelist.json()
		#ignore edges identify edges with analytics set to "None"
		for edge in edgelistjson:
			edgeid = edge['id']
			edgename = edge['name']
			setdynbwtest(edgeid, edgename)
		

if __name__ == '__main__':
    main()
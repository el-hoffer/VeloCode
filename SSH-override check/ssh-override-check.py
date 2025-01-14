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


#check for support access overrides
def checksupportaccess(edgename, fwsettings):
	if 'services' not in fwsettings:
		return
	if 'ssh' not in fwsettings['services']:
		return
	else:
		print('\n' + str(edgename))
		print(*fwsettings['services']['ssh']['allowSelectedIp'], sep = '\n')

#find firewall module
def modulefind(edgeid, edgename):
	edge_attr = {'edgeId': edgeid,
			 	'enterpriseId': 43 	
				}
	#retrieve edge configuration stack
	try:
		edgeconf = requests.post(edge_conf, headers=headers, data=json.dumps(edge_attr))
	except Exception as e:
		print(e + 'received on edge ' + str(edgename))
	#convert to json
	edgeconfjson = edgeconf.json()
	#Find the firewall configuration module in edge specific profile and collect module ID and data object
	for module in edgeconfjson[0]['modules']:
		if module['name'] == 'firewall':
			firewallsettings = module['data']
			checksupportaccess(edgename, firewallsettings)
		else:
			continue
	#if firewall module includes override for ssh, print edge name and whitelisted IPs

def main():
	#Retrieve all edges
		entSpec = json.dumps({'enterpriseId': 43})
		try:
			edgelist = requests.post(get_edges, headers=headers, data=entSpec)
		except Exception as e:
			print(e)
		#convert to json
		edgelistjson = edgelist.json()
		for edge in edgelistjson:
			edgeid = edge['id']
			edgename = edge['name']
			modulefind(edgeid, edgename)
		

if __name__ == '__main__':
    main()
#!/usr/bin/env python3

import os
import scriptvars #This is just another script that sets the VCO URL and API token as env variables
import requests
import json
import csv

token = "Token %s" %(os.environ['VCO_Token'])
headers = {"Content-Type": "application/json", "Authorization": token}
vco_url = 'https://' + os.environ['VCO_URL'] + '/portal/rest/'
edgeid = os.environ['edgeId']
edge_conf = vco_url + 'edge/getEdgeConfigurationStack'
conf_update = vco_url + 'configuration/updateConfigurationModule'

def routelistfunc(srouteslist):
	#Read CSV "routes" for list of routes/details
	with open('routelist.csv', encoding='utf-8-sig', newline='') as routelist:
		readerobj = csv.DictReader(routelist, dialect='excel')
		for row in readerobj:
			routedict = {'destination':row['destination'],
						'netmask':row['netmask'], 
						'sourceIp':None, 
						'gateway':row['gateway'],
						'cost': 0,
						'preferred': True,
						'description':row['description'],
						'cidrPrefix':row['cidrPrefix'],
						'wanInterface':row['wanInterface'],
						'subinterfaceId':-1,
						'icmpProbeLogicalId':None,
						'vlanId':None,
						'advertise':True}
			srouteslist.append(routedict)
		routelist.close()
	return(srouteslist)

def main():
	#Find/return Device Settings configuration module in Edge Specific Profile
	confcallparams = {'edgeId': edgeid}
	try:
		edgeconf = requests.post(edge_conf, headers=headers, data=json.dumps(confcallparams))
		print(edgeconf)
	except Exception as e:
		print(e)
	#convert to json
	edgeconfjson = edgeconf.json()
	confmoduleid = 0
	#Find the device settings configuration module and collect module ID and modify data object with list from routelistfunc
	for module in edgeconfjson[0]['modules']:
		if module['name'] == 'deviceSettings':
			devsettings = module['data']
			confmoduleid = module['id']
			srouteslist = devsettings['segments'][0]['routes']['static']
			routelistfunc(srouteslist)
			devsettings['segments'][0]['routes']['static'] = srouteslist
		else:
			continue
	#confirm deviceSettings module found and push updated static routes to API
	if confmoduleid != 0:
		#update existing config module with routes added from routelistfunc
		print('modifying existing config module id ' + str(confmoduleid))
		
		#print(str(devsettings))
		edgeenableparams = {	"id": confmoduleid,
							  "_update": {
								"data": devsettings,
								"name": "deviceSettings"
							  }
							}
		#print(edgeenableparams)
		setpolicy = requests.post(conf_update, headers=headers, data=json.dumps(edgeenableparams))
		print(setpolicy.reason)
		print(setpolicy.json())

	else:
		print('Device Settings module not found for edge id ' + str(edgeid))

		


if __name__ == '__main__':
    main()

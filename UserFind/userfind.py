#!/usr/bin/env python3

import os
import sys
import scriptvars
import requests
import json

token = f"Token {os.environ['VCO_Token']}"
headers = {"Content-Type": "application/json", "Authorization": token}
vco_url = f"https://{os.environ['VCO_URL']}/portal/rest/"
get_enterprises = f"{vco_url}network/getNetworkEnterprises"
find_user = f"{vco_url}enterpriseUser/getEnterpriseUser"



def main():
	#Define user to serach for based on command line input
	if len(sys.argv) != 2:
		raise ValueError('Please specify username to search for.  Example usage:  "python3 userfind.py user@velocloud.net"')
	else:
		userid = sys.argv[1]
	print('Searching for user %s on %s' %(userid, os.environ['VCO_URL']))
	
	#Fetch list of all enterprises and convert to JSON
	try:
		enterprises = requests.post(get_enterprises, headers=headers, data='')
	except Exception as e:
		print(e)
		sys.exit()
		
	ent_dict = enterprises.json()
	#List to track whether the username is found
	userents = 0
	print('There are %d enterprises to check.  This will take approximately %d seconds' %(len(ent_dict), (len(ent_dict)/3)))
	#Iterate through enterprise list and search for userid
	for enterprise in ent_dict:
		eid = enterprise['id']
		params = {	'enterpriseId': eid, 
					'username': userid	}
		
		try:
			usercheck = requests.post(find_user, headers=headers, data=json.dumps(params))
		except Exception as e:
			print(e)
			
		result = usercheck.json()
		
		if 'id' in result:
			userents += 1
			print('User %s exists in enterprise "%s" with enterprise ID %d' %(userid, enterprise['name'], eid))
			
	if not userents:
		print('User not found in any enterprise on this VCO (%s)' %(os.environ['VCO_URL']))

if __name__ == '__main__':
    main()
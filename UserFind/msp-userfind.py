#!/usr/bin/env python3

import os
import sys
import scriptvars
import requests
import json

token = "Token %s" %(os.environ['VCO_Token'])
headers = {"Content-Type": "application/json", "Authorization": token}
vco_url = 'https://' + os.environ['VCO_URL'] + '/portal/rest/'
get_partners = vco_url + 'network/getNetworkEnterpriseProxies'
find_user = vco_url + 'enterpriseProxy/getEnterpriseProxyUsers'



def main():
    #Define user to serach for based on command line input
    if len(sys.argv) != 2:
        raise ValueError('Please specify username to search for.  Example usage:  "python3 userfind.py user@velocloud.net"')
    else:
        userid = sys.argv[1]
    print('Searching for user %s on %s' %(userid, os.environ['VCO_URL']))
    
    #Fetch list of all partners and convert to JSON
    netid = {'networkId': 1}
    try:
        partners = requests.post(get_partners, headers=headers, data=json.dumps(netid))
    except Exception as e:
        print(e)
        sys.exit()
        
    ent_dict = partners.json()
    #List to track whether the username is found
    userents = 0
    print('There are %d partners to check.  This will take approximately %d seconds' %(len(ent_dict), (len(ent_dict)/3)))
    #Iterate through partner list and search for userid
    for partner in ent_dict:
        eid = partner['id']
        params = {'enterpriseProxyId': eid}
        try:
            usercheck = requests.post(find_user, headers=headers, data=json.dumps(params))	
            result = usercheck.json()
            for user in result:
                if user.get('username') == userid:
                    userents += 1
                    print('User %s exists in partner "%s" with enterprise proxy ID %d' %(userid, partner['name'], eid))
        except Exception as e:
            print(e)
            
    if not userents:
        print('User not found in any enterprise on this VCO (%s)' %(os.environ['VCO_URL']))

if __name__ == '__main__':
    main()
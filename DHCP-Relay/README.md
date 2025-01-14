# dhcpRelay.py

scriptvars.py- Script that just sets your VCO URL, API token, and edge ID as environment variables so you don’t have to include credentials in your main script.  This gets called by the main script so just update the values here with and save in the same folder that you’ll run the main script from.  VCO URL and API token are easy but for your reference, the easiest way to get the edge id is to just pull the edge up in the UI and look at the URI path. 

dhcpRelay.py- Main script so this is what you’ll actually run to push the changes.  Will loop through all edges in an enterprise and as written will modify the DHCP Relay configuration on the GE2 interface to set 2.2.2.2 and 3.3.3.3 as the DHCP servers to relay to.

# VLANfetch.py

scriptvars.py- Script that just sets your VCO URL, API token, and edge ID as environment variables so you don’t have to include credentials in your main script.  This gets called by the main script so just update the values here with and save in the same folder that you’ll run the main script from. 

VLANfetch.py- Main script so this is what you’ll actually run.  This script loops through all edges in an enterprise and collects the edge name, all switched VLANs configured and their associated IP subnets.  Results are written to a CSV file called vlanlist.csv.

# ssh-override-check.py

scriptvars.py- Script that just sets your VCO URL, API token, and edge ID as environment variables so you don’t have to include credentials in your main script.  This gets called by the main script so just update the values here with and save in the same folder that you’ll run the main script from.  VCO URL and API token are easy but for your reference, the easiest way to get the edge id is to just pull the edge up in the UI and look at the URI path. 

ssh-override-check.py- Main script so this is what you’ll actually run.  This script loops through all edges in an enterprise and checks for edge level overrides to the whitelisted support access (SSH) IPs and when present, prints the edge name and the whitelisted IPs.

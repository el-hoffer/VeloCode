# bwtest.py
scriptvars.py- Script that just sets your VCO URL, API token, and edge ID as environment variables so you don’t have to include credentials in your main script.  This gets called by the main script so just update the values here with and save in the same folder that you’ll run the main script from.

bwtest.py- Main script so this is what you’ll actually run to push the changes.  This will loop through all edges in an enterprise and change the bandwidth measurement settings for all WAN links to SLOW_START.

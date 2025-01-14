# static-add.py
Simple script to add static routes read from a CSV to a specific edge

routelist.csv- CSV file where you’ll enter the static route info so just save it under the same name in the same folder that you’ll be running the script from.  The way it’s written now assumes we’re routing out of a physical interface but if you’ll need to specify sub-interfaces you can add a column for that and reference it in row 30 of the main script (which is currently just hard coded as “-1” indicating no sub-interface) as with some of the other optional parameters.  You should be able to just enter as many rows as you need.

scriptvars.py- Script that just sets your VCO URL, API token, and edge ID as environment variables so you don’t have to include credentials in your main script.  This gets called by the main script so just update the values here with and save in the same folder that you’ll run the main script from.

static-add.py- Main script so this is what you’ll actually run to push the changes.  This will append static routes in the CSV file to any existing static routes configured.

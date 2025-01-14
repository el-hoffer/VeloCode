# popfinder.py

scriptvars.py- Script that just sets your VCO URL, API token, and edge ID as environment variables so you don’t have to include credentials in your main script.  This gets called by the main script so just update the values here with and save in the same folder that you’ll run the main script from.

popfinder.py- Main script so this is what you’ll actually run.  This script loops through all edges in an enterprise and collects the edge location and bandwidth license tier, then measures the distance from the edge to the specified PoP locations (rows 14-17 in the example).  Results are output into a csv file with the distance to each PoP, the closest PoP, and the bandwidth.  This helps to predict the amount of capacity that an enterprise will present to a given PoP to add in throughput forecasting.

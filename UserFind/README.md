# userfind.py & msp-userfind.py

scriptvars.py- Script that just sets your VCO URL, API token, and edge ID as environment variables so you don’t have to include credentials in your main script.  This gets called by the main script so just update the values here with and save in the same folder that you’ll run the main script from.  These scripts require operator access for the user account token used to run the main scripts.

userfind.py- Script that takes a user id (i.e. user@sdwanenterprise.com) as an argument (i.e. 'python3 userfind.py user@sdwanenterprise.com') and loops through all enterprises in the VCO looking for a user configured with that user ID.  Results are printed to the terminal.

msp-userfind.py- Same as userfind.py but searches partner/MSP accounts instead of enterprises.  Takes a user id (i.e. user@sdwanmsp.com) as an argument (i.e. 'python3 userfind.py user@sdwanmsp.com') and loops through all partners/MSPs in the VCO looking for a user configured with that user ID.  Results are printed to the terminal.
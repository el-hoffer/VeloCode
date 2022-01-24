import os

#Replace <URL of target VCO> with the actual URL, without the leading "https://" (i.e. 'vco123-usmn1.velocloud.net')
os.environ['VCO_URL'] = '<replace with VCO URL>'
#API token generated via VCO
os.environ['VCO_Token'] = '<replace with API token>'
#Edge ID of the target edge
os.environ['edgeId'] = '<replace with edge id>'
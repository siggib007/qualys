'''
Qualys API Sample Script
Author Siggi Bjarnason Copyright 2017
Website http://www.ipcalc.us/ and http://www.icecomputing.com

Description:
This is script where I start to explore Qualys API calls, parsing the XML responses, etc.

Following packages need to be installed as administrator
pip install requests
pip install xmltodict

'''
# Import libraries
import sys
import requests
import json
import os
import string
import time
import xmltodict
import urllib.parse as urlparse
# End imports
strConf_File = "QualysConf.ini"

dictParams = {}
dictParams["action"] = "launch"
dictParams["scan_title"] = "PCF Test Scan"
dictParams["target_from"] = "assets"
dictParams["iscanner_id"] = 18014
dictParams["option_id"] = 759776
dictParams["ip"] = "10.93.120.204"

print ("This is a Qualys API Sample script. This is running under Python Version {0}.{1}.{2}".format(sys.version_info[0],sys.version_info[1],sys.version_info[2]))
now = time.asctime()
print ("The time now is {}".format(now))

if os.path.isfile(strConf_File):
	print ("Configuration File exists")
else:
	print ("Can't find configuration file {}, make sure it is the same directory as this script".format(strConf_File))
	sys.exit(4)

strLine = "  "
print ("Reading in configuration")
objINIFile = open(strConf_File,"r")
strLines = objINIFile.readlines()
objINIFile.close()

for strLine in strLines:
	strLine = strLine.strip()
	if "=" in strLine:
		strConfParts = strLine.split("=")
		if strConfParts[0] == "APIBaseURL":
			strBaseURL = strConfParts[1]
		if strConfParts[0] == "APIRequestHeader":
			strHeadReq = strConfParts[1]
		if strConfParts[0] == "QUserID":
			strUserName = strConfParts[1]
		if strConfParts[0] == "QUserPWD":
			strPWD = strConfParts[1]
		if strConfParts[0] == "APIFunction":
			strScanAPI = strConfParts[1]

print ("calculating stuff ...")
strHeader={'X-Requested-With': strHeadReq}

if strBaseURL[-1:] != "/":
	strBaseURL += "/"

if strScanAPI[-1:] != "/":
	strScanAPI += "/"

def MakeAPICall (strURL, strHeader, strUserName,strPWD, strMethod):

	print ("Doing a {} to URL: \n {}\n".format(strMethod,strURL))
	iErrCode = ""
	iErrText = ""

	try:
		if strMethod.lower() == "get":
			WebRequest = requests.get(strURL, headers=strHeader, auth=(strUserName, strPWD))
		if strMethod.lower() == "post":
			WebRequest = requests.post(strURL, headers=strHeader, auth=(strUserName, strPWD))
	except Exception as err:
		print ("Issue with API call. {}".format(err))
		raise
		sys.exit(7)

	if isinstance(WebRequest,requests.models.Response)==False:
		print ("response is unknown type")
		sys.exit(5)

	if WebRequest.text[:6].lower()=="<html>":
		print (WebRequest.text)
		iErrCode = "Unknown"
		iErrText = "Unexpected error"
	if iErrCode != "" or WebRequest.status_code !=200:
		return "There was a problem with your request. HTTP error {} code {} {}".format(WebRequest.status_code,iErrCode,iErrText)
	else:
		dictResponse = xmltodict.parse(WebRequest.text)

	if isinstance(dictResponse,dict):
		if "SIMPLE_RETURN" in dictResponse:
			try:
				if "CODE" in dictResponse["SIMPLE_RETURN"]["RESPONSE"]:
					iErrCode = dictResponse["SIMPLE_RETURN"]["RESPONSE"]["CODE"]
					iErrText = dictResponse["SIMPLE_RETURN"]["RESPONSE"]["TEXT"]
			except KeyError as e:
				print ("KeyError: {}".format(e))
				print (WebRequest.text)
				iErrCode = "Unknown"
				iErrText = "Unexpected error"
	else:
		print ("Response not a dictionary")
		sys.exit(8)

	if iErrCode != "" or WebRequest.status_code !=200:
		return "There was a problem with your request. HTTP error {} code {} {}".format(WebRequest.status_code,iErrCode,iErrText)
	else:
		return dictResponse

strListScans = urlparse.urlencode(dictParams)
strURL = strBaseURL + strScanAPI +"?" + strListScans

APIResponse = MakeAPICall(strURL,strHeader,strUserName,strPWD,"post")
if isinstance(APIResponse,str):
	print(APIResponse)
if isinstance(APIResponse,dict):
	if "SIMPLE_RETURN" in APIResponse:
		if "RESPONSE" in APIResponse["SIMPLE_RETURN"]:
			if "TEXT" in APIResponse["SIMPLE_RETURN"]["RESPONSE"]:
				print (APIResponse["SIMPLE_RETURN"]["RESPONSE"]["TEXT"])
			if "ITEM_LIST" in APIResponse["SIMPLE_RETURN"]["RESPONSE"]:
				for item in APIResponse["SIMPLE_RETURN"]["RESPONSE"]["ITEM_LIST"]["ITEM"]:
					print ("{}: {}".format(item["KEY"],item["VALUE"]))
			else:
				print ("No further details")
		else:
			print ("Don't understand this reponse: {}".format(APIResponse))
	else:
		print ("Don't understand this reponse: {}".format(APIResponse))
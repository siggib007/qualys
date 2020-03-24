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

strConf_File = "QualysAPI.ini"
iSizeLimit = 5000000
strOutFile = "c:\\temp\\QualysAPIOut2.txt"

strAPIFunction = "api/2.0/fo/auth/unix"
dictParams = {}
dictParams["action"] = "list"
dictParams["ids"] = "27413"

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


print ("calculating stuff ...")
strHeader={'X-Requested-With': strHeadReq}

if strBaseURL[-1:] != "/":
	strBaseURL += "/"

if strAPIFunction[-1:] != "/":
	strAPIFunction += "/"

def MakeAPICall (strURL, strHeader, strUserName,strPWD):

	iErrCode = ""
	iErrText = ""

	print ("Doing a get to URL: \n {}\n".format(strURL))
	try:
		WebRequest = requests.get(strURL, headers=strHeader, auth=(strUserName, strPWD))
	except:
		print ("Failed to connect to Qualys")
		sys.exit(7)
	# end try

	if isinstance(WebRequest,requests.models.Response)==False:
		print ("response is unknown type")
		sys.exit(5)
	# end if
	print ("call resulted in status code {}".format(WebRequest.status_code))

	if len(WebRequest.text) < iSizeLimit :
		dictResponse = xmltodict.parse(WebRequest.text)
		# return dictResponse

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
	else:
		return WebRequest.text



strListScans = urlparse.urlencode(dictParams)
strURL = strBaseURL + strAPIFunction +"?" + strListScans

APIResponse = MakeAPICall(strURL,strHeader,strUserName,strPWD)

# objFileOut = open(strOutFile,"w")
# objFileOut.write ("{}".format(APIResponse))
# objFileOut.close()

# print ("Done")

# sys.exit(0)

if isinstance(APIResponse,str):
	print(APIResponse)
if isinstance(APIResponse,dict):
	if "AUTH_UNIX_LIST" in APIResponse["AUTH_UNIX_LIST_OUTPUT"]["RESPONSE"]:
		if "TITLE" in APIResponse["AUTH_UNIX_LIST_OUTPUT"]["RESPONSE"]["AUTH_UNIX_LIST"]["AUTH_UNIX"] :
			print ("TITLE: {}".format(APIResponse["AUTH_UNIX_LIST_OUTPUT"]["RESPONSE"]["AUTH_UNIX_LIST"]["AUTH_UNIX"]["TITLE"]))
		if "IP_RANGE" in APIResponse["AUTH_UNIX_LIST_OUTPUT"]["RESPONSE"]["AUTH_UNIX_LIST"]["AUTH_UNIX"]["IP_SET"] :
			if isinstance (APIResponse["AUTH_UNIX_LIST_OUTPUT"]["RESPONSE"]["AUTH_UNIX_LIST"]["AUTH_UNIX"]["IP_SET"]["IP_RANGE"] ,list):
				print ("There are {} IP ranges".format(len(APIResponse["AUTH_UNIX_LIST_OUTPUT"]["RESPONSE"]["AUTH_UNIX_LIST"]["AUTH_UNIX"]["IP_SET"]["IP_RANGE"])))
				for IPRange in APIResponse["AUTH_UNIX_LIST_OUTPUT"]["RESPONSE"]["AUTH_UNIX_LIST"]["AUTH_UNIX"]["IP_SET"]["IP_RANGE"]:
					print ("{}".format(IPRange))
			else:
				print ("Single IP Range {}".format(APIResponse["AUTH_UNIX_LIST_OUTPUT"]["RESPONSE"]["AUTH_UNIX_LIST"]["AUTH_UNIX"]["IP_SET"]["IP_RANGE"]))
		if "IP" in APIResponse["AUTH_UNIX_LIST_OUTPUT"]["RESPONSE"]["AUTH_UNIX_LIST"]["AUTH_UNIX"]["IP_SET"] :
			if isinstance (APIResponse["AUTH_UNIX_LIST_OUTPUT"]["RESPONSE"]["AUTH_UNIX_LIST"]["AUTH_UNIX"]["IP_SET"]["IP"] ,list):
				print ("There are {} IP addresses".format(len(APIResponse["AUTH_UNIX_LIST_OUTPUT"]["RESPONSE"]["AUTH_UNIX_LIST"]["AUTH_UNIX"]["IP_SET"]["IP"])))
				for IPRange in APIResponse["AUTH_UNIX_LIST_OUTPUT"]["RESPONSE"]["AUTH_UNIX_LIST"]["AUTH_UNIX"]["IP_SET"]["IP"]:
					print ("{}".format(IPRange))
			else:
				print ("Single IP address {}".format(APIResponse["AUTH_UNIX_LIST_OUTPUT"]["RESPONSE"]["AUTH_UNIX_LIST"]["AUTH_UNIX"]["IP_SET"]["IP"]))
	else:
		print ("There are no results")
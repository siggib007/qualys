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
# End imports

strConf_File = "QSInput.ini"

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
		if strConfParts[0] == "ShowNumDays":
			iNumDays = int(strConfParts[1])
		if strConfParts[0] == "ShowStartTime":
			strTimeLastNight = str(strConfParts[1])
		if strConfParts[0] == "QUserID":
			strUserName = strConfParts[1]
		if strConfParts[0] == "QUserPWD":
			strPWD = strConfParts[1]

print ("calculating stuff ...")
strHeader={'X-Requested-With': strHeadReq}
strScanAPI = "api/2.0/fo/scan/?"
iSecInDays = 86400
iSecDays = iSecInDays * iNumDays

timeNow = time.localtime(time.time())
iGMT_offset = timeNow.tm_gmtoff


def getInput(strPrompt):
    if sys.version_info[0] > 2 :
        return input(strPrompt)
    else:
        return raw_input(strPrompt)
# end getInput

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


timeLastNightLocal = time.strftime("%Y-%m-%d",time.localtime(time.time()-iSecDays)) + " " + strTimeLastNight
timeLastNightGMT = time.localtime(time.mktime(time.strptime(timeLastNightLocal,"%Y-%m-%d %H:%M"))-iGMT_offset)
strQualysTime = time.strftime("%Y-%m-%dT%H:%M:%SZ",timeLastNightGMT)
strLastNight = time.strftime("%m/%d/%Y %H:%M %Z",time.localtime(time.mktime(time.strptime(timeLastNightLocal,"%Y-%m-%d %H:%M"))))

strListScans = "action=list&user_login={}&launched_after_datetime={}".format("tmbeu2sb1",strQualysTime)
strURL = strBaseURL + strScanAPI + strListScans

APIResponse = MakeAPICall(strURL,strHeader,strUserName,strPWD)
if isinstance(APIResponse,str):
	print(APIResponse)
if isinstance(APIResponse,dict):
	if "SCAN_LIST" in APIResponse["SCAN_LIST_OUTPUT"]["RESPONSE"]:
		if isinstance (APIResponse["SCAN_LIST_OUTPUT"]["RESPONSE"]["SCAN_LIST"]["SCAN"],list):
			print ("There are {} scans since {}".format(len(APIResponse["SCAN_LIST_OUTPUT"]["RESPONSE"]["SCAN_LIST"]["SCAN"]), strLastNight))
			for scan in APIResponse["SCAN_LIST_OUTPUT"]["RESPONSE"]["SCAN_LIST"]["SCAN"]:
				print ("Title: {} Ref: {} Status: {}".format(scan["TITLE"],scan["REF"],scan["STATUS"]["STATE"]))
				if "SUB_STATE" in scan["STATUS"]:
					print ("     --  Status Details:{}".format(scan["STATUS"]["SUB_STATE"]))
		else:
			print ("There is one scan since {}".format(strLastNight))
			scan = APIResponse["SCAN_LIST_OUTPUT"]["RESPONSE"]["SCAN_LIST"]["SCAN"]
			print ("Title: {} Ref: {} Status: {}".format(scan["TITLE"],scan["REF"],scan["STATUS"]["STATE"]))
			if "SUB_STATE" in scan["STATUS"]:
				print ("     --  Status Details:{}".format(scan["STATUS"]["SUB_STATE"]))
	else:
		print ("There are no scans since {}".format(strLastNight))
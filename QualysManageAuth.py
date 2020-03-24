'''
Qualys API Authenitcation Management
Author Siggi Bjarnason Copyright 2018
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
import os
import string
import time
import xmltodict
import urllib.parse as urlparse
import subprocess as proc
# End imports

dictParams = {}
#
# Begin User Input: Make changes to this section as needed. To disable an line not needed put # in front of it.
#
strSystemType = "windows" # Requires unix, windows or other qualys authentication system types. Cisco and Checkpoint not supported at this time.
dictParams["action"] = "update" #required to be create, update or delete
dictParams["ips"] = "10.93.120.248" # IP address list. Required for create, optional for update, not valid for delete. Has to be unique when provided
dictParams["username"] = "MyTest" # Username. Required for create, optional for update, not valid for delete.
dictParams["password"] = "qawerewrqwert" # Password. Required for create, optional for update, not valid for delete.
dictParams["title"] = "Siggi's API Auth Windows Test #3" # Authentication title. Required for create, optional for update, not valid for delete. Has to be unique when provided
dictParams["ids"] = "130657" # Authentication profile ID, required for update and delete, not valid for create
#
#End User Input: Any changes below this line will either break the script or change how it operates. Proceed with caution.
#

print ("This is a Qualys API Sample script. This is running under Python Version {0}.{1}.{2}".format(sys.version_info[0],sys.version_info[1],sys.version_info[2]))
now = time.asctime()
print ("The time now is {}".format(now))

strConf_File = "QualysAPI.ini"
strMethod = "post"

strAPIFunction = "api/2.0/fo/auth/" + strSystemType

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
		if strConfParts[0] == "SaveLocation":
			strSavePath = strConfParts[1]


print ("calculating stuff ...")
strHeader={'X-Requested-With': strHeadReq}

if strBaseURL[-1:] != "/":
	strBaseURL += "/"

if strAPIFunction[-1:] != "/":
	strAPIFunction += "/"

if strSavePath[-1:] != "\\":
	strSavePath += "\\"

def MakeAPICall (strURL, strHeader, strUserName,strPWD, strMethod):

	iErrCode = ""
	strErrText = ""

	print ("Doing a {} to URL: \n{}\n".format(strMethod,strURL))
	try:
		if strMethod.lower() == "get":
			WebRequest = requests.get(strURL, headers=strHeader, auth=(strUserName, strPWD))
			print ("get executed")
		if strMethod.lower() == "post":
			WebRequest = requests.post(strURL, headers=strHeader, auth=(strUserName, strPWD))
			print ("post executed")
	except Exception as err:
		print ("Issue with API call. {}".format(err))
		raise
		sys.exit(7)



	if isinstance(WebRequest,requests.models.Response)==False:
		print ("response is unknown type")
		sys.exit(5)
	# end if
	print ("call resulted in status code {}".format(WebRequest.status_code))

	dictResponse = xmltodict.parse(WebRequest.text)

	if isinstance(dictResponse,dict):
		if "SIMPLE_RETURN" in dictResponse:
			try:
				if "CODE" in dictResponse["SIMPLE_RETURN"]["RESPONSE"]:
					iErrCode = dictResponse["SIMPLE_RETURN"]["RESPONSE"]["CODE"]
					strErrText = dictResponse["SIMPLE_RETURN"]["RESPONSE"]["TEXT"][:-1]
			except KeyError as e:
				print ("KeyError: {}".format(e))
				print (WebRequest.text)
				iErrCode = "Unknown"
				strErrText = "Unexpected error"
		if "BATCH_RETURN" in dictResponse:
			if "CODE" in dictResponse["BATCH_RETURN"]["RESPONSE"]["BATCH_LIST"]["BATCH"] :
				iErrCode = dictResponse["BATCH_RETURN"]["RESPONSE"]["BATCH_LIST"]["BATCH"]["CODE"]
				strErrText = dictResponse["BATCH_RETURN"]["RESPONSE"]["BATCH_LIST"]["BATCH"]["TEXT"][:-1]
	else:
		print ("Response not a dictionary")
		sys.exit(8)

	if iErrCode == "1920" :
		tmpErrStr = ""
		dictTemp = {}
		strErrParts = strErrText.splitlines()
		# errResponse = {"Failure":{"errCode":iErrCode,"errText":strErrParts[0]+"\n"+strErrParts[1]}}
		# print (strErrParts[0]+"\n"+strErrParts[1])
		for strErrPart in strErrParts:
			iLoc = strErrPart.find(" is used by ")
			if iLoc > 8:
				strIPAddr = strErrPart[5:iLoc]
				strAuthName = strErrPart[iLoc+12:]
				dictTemp[strIPAddr]=strAuthName
				# print ("{} : {}".format(strIPAddr,strAuthName))
			else:
				# print (strErrPart)
				tmpErrStr += strErrPart + "\n"
		if len(dictTemp) > 0:
			return {"Failure":{"errCode":iErrCode,"errText":tmpErrStr,"IP_List":dictTemp}}
		else:
			return {"Failure":{"errCode":iErrCode,"errText":tmpErrStr}}

	if iErrCode != "" or WebRequest.status_code !=200:
		return "There was a problem with your request. HTTP error {} code {} {}".format(WebRequest.status_code,iErrCode,strErrText)
	else:
		return dictResponse



strListScans = urlparse.urlencode(dictParams)
strURL = strBaseURL + strAPIFunction +"?" + strListScans

APIResponse = MakeAPICall(strURL,strHeader,strUserName,strPWD,strMethod)


if isinstance(APIResponse,str):
	print(APIResponse)
if isinstance(APIResponse,dict):
	if "Failure" in APIResponse:
		print ("Unexpected issue occured.\nCode: {}\n{}".format(APIResponse["Failure"]["errCode"],APIResponse["Failure"]["errText"]))
		if "IP_List" in APIResponse["Failure"]:
			for strIPKey in APIResponse["Failure"]["IP_List"]:
				print ("{} uses {}".format(APIResponse["Failure"]["IP_List"][strIPKey],strIPKey))
	if "BATCH_RETURN" in APIResponse:
		if "BATCH_LIST" in APIResponse["BATCH_RETURN"]["RESPONSE"]:
			if "TEXT" in APIResponse["BATCH_RETURN"]["RESPONSE"]["BATCH_LIST"]["BATCH"] :
				print ("{}".format(APIResponse["BATCH_RETURN"]["RESPONSE"]["BATCH_LIST"]["BATCH"]["TEXT"]))
			if "ID" in APIResponse["BATCH_RETURN"]["RESPONSE"]["BATCH_LIST"]["BATCH"]["ID_SET"] :
				print ("ID: {}".format(APIResponse["BATCH_RETURN"]["RESPONSE"]["BATCH_LIST"]["BATCH"]["ID_SET"]["ID"]))
		else:
			print ("No records")

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
strAPIFunction = "api/2.0/fo/auth"
strIPListPathAdd = "IPRanges"
dictParams = {}
dictParams["action"] = "list"

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
		if strConfParts[0] == "SaveLocation":
			strSavePath = strConfParts[1]

if strSavePath[-1:] != "\\":
	strSavePath += "\\"

if strIPListPathAdd[-1:] != "\\":
	strIPListPathAdd += "\\"

if not os.path.exists (strSavePath+strIPListPathAdd) :
	os.makedirs(strSavePath+strIPListPathAdd)
	print ("\nPath '{0}' for output files didn't exists, so I create it!\n".format(strSavePath+strIPListPathAdd))

print ("Saving to: {}".format(strSavePath))
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
strURL = strBaseURL + strAPIFunction +"?" + strListScans
dictObjOut = {}
APIResponse = MakeAPICall(strURL,strHeader,strUserName,strPWD)
if isinstance(APIResponse,str):
	print(APIResponse)
if isinstance(APIResponse,dict):
	if "AUTH_RECORDS" in APIResponse["AUTH_RECORDS_OUTPUT"]["RESPONSE"]:
		keyAuthRecords = APIResponse["AUTH_RECORDS_OUTPUT"]["RESPONSE"]["AUTH_RECORDS"].keys()
		for strAuthKey in keyAuthRecords:
			print ("\n\n" + strAuthKey[:-4])
			strKeyL1 = strAuthKey[:-4] + "_LIST_OUTPUT"
			strKeyL2 = "RESPONSE"
			strKeyL3 = strAuthKey[:-4] + "_LIST"
			strKeyL4 = strAuthKey[:-4]
			strURL = strBaseURL + strAPIFunction + strAuthKey[5:-4].lower() +"/?" + strListScans
			APIResponse = MakeAPICall(strURL,strHeader,strUserName,strPWD)
			if isinstance(APIResponse,str):
				print(APIResponse)
			if isinstance(APIResponse,dict):
				if strKeyL3 in APIResponse[strKeyL1][strKeyL2]:
					print ("{} auth records".format (len(APIResponse[strKeyL1][strKeyL2][strKeyL3][strKeyL4])))
					for AuthRecord in APIResponse[strKeyL1][strKeyL2][strKeyL3][strKeyL4]:
						strTemp = " "
						if strAuthKey[5:-4].lower() not in dictObjOut:
							dictObjOut[strAuthKey[5:-4].lower()] = open(strSavePath + strAuthKey + ".csv","w")
							dictObjOut[strAuthKey[5:-4].lower()].write ("AuthID,TITLE,UID,IPRangeCount,SingleIPCount,TotalIPObjects,Other\n")
						if strAuthKey[5:-4].lower() == "windows":
							if "WINDOWS_AD_DOMAIN" in AuthRecord:
								strTemp += AuthRecord["WINDOWS_AD_DOMAIN"]
							if "NTLM" in AuthRecord:
								strTemp += " NTLMv" + AuthRecord["NTLM"]
						if strAuthKey[5:-4].lower() == "unix":
							if "SKIP_PASSWORD" in AuthRecord:
								if AuthRecord["SKIP_PASSWORD"] == "1":
									strTemp += "PWDSkip"
							else:
								strTemp += "NoPWDSkip"
							if "CLEARTEXT_PASSWORD" in AuthRecord:
								if AuthRecord["CLEARTEXT_PASSWORD"] == "1":
									strTemp += "CLRTXT"
							else:
								strTemp += "No CLRTXT"
						print ("ID {} : {} {}".format(AuthRecord["ID"],AuthRecord["TITLE"],strTemp))
						if "IP_SET" in AuthRecord:
							objFileOut = open(strSavePath+strIPListPathAdd+AuthRecord["ID"]+".txt","w")
							if "IP_RANGE" in AuthRecord["IP_SET"] :
								if isinstance (AuthRecord["IP_SET"]["IP_RANGE"] ,list):
									iRangeCount = len(AuthRecord["IP_SET"]["IP_RANGE"])
									print ("There are {} IP ranges".format(iRangeCount))
									for IPRange in AuthRecord["IP_SET"]["IP_RANGE"]:
										objFileOut.write ("{}\n".format(IPRange))
								else:
									objFileOut.write ("{}\n".format(AuthRecord["IP_SET"]["IP_RANGE"]))
									iRangeCount = 1
							else:
								iRangeCount = 0
							if "IP" in AuthRecord["IP_SET"]:
								if isinstance (AuthRecord["IP_SET"]["IP"] ,list):
									iIPCount = len(AuthRecord["IP_SET"]["IP"])
									print ("There are {} IP addresses".format(iIPCount))
									for IPAddr in AuthRecord["IP_SET"]["IP"]:
										objFileOut.write ("{}\n".format(IPAddr))
								else:
									iIPCount = 1
									print ("Single IP address {}".format(AuthRecord["IP_SET"]["IP"]))
									objFileOut.write ("{}\n".format(AuthRecord["IP_SET"]["IP"]))
							else:
								iIPCount = 0
							objFileOut.close()
						else:
							iRangeCount = 0
							iIPCount = 0
						if "ID" in AuthRecord:
							strID = AuthRecord["ID"]
						else:
							strID = ""
						if "TITLE" in AuthRecord:
							strTitle = AuthRecord["TITLE"].replace(","," ")
						else:
							strTitle = ""
						if "USERNAME" in AuthRecord:
							strUName = AuthRecord["USERNAME"]
						else:
							strUName = ""
						dictObjOut[strAuthKey[5:-4].lower()].write("{},{},{},{},{},{},{}\n".format(strID,strTitle,strUName,iRangeCount,iIPCount,iRangeCount+iIPCount,strTemp))
for strObjKey in dictObjOut:
	print ("Closing {}".format(strObjKey))
	dictObjOut[strObjKey].close()
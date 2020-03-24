'''
Qualys API Sample Script
Author Siggi Bjarnason Copyright 2017
Website http://www.ipcalc.us/ and http://www.icecomputing.com

Description:
This is script where I start to explore Qualys API calls, parsing the XML responses, etc.

Following packages need to be installed as administrator
pip install requests
pip install xmltodict
pip install pymysql

'''
# Import libraries
import sys
import requests
import os
import xmltodict
import pymysql
# End imports

print ("This is a Qualys API Sample script, testing appliances API. This is running under Python Version {0}.{1}.{2}".format(sys.version_info[0],sys.version_info[1],sys.version_info[2]))

strConf_File = "QSInput.ini"

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

def SQLConn (strServer,strDBUser,strDBPWD,strInitialDB):
	try:
		# Open database connection
		return pymysql.connect(strServer,strDBUser,strDBPWD,strInitialDB)
	except pymysql.err.InternalError as err:
		print ("Error: unable to connect: {}".format(err))
		sys.exit(5)
	except pymysql.err.OperationalError as err:
		print ("Operational Error: unable to connect: {}".format(err))
		sys.exit(5)
	except pymysql.err.ProgrammingError as err:
		print ("Programing Error: unable to connect: {}".format(err))
		sys.exit(5)

def SQLQuery (strSQL,db):
	try:
		# prepare a cursor object using cursor() method
		dbCursor = db.cursor()
		# Execute the SQL command
		dbCursor.execute(strSQL)
		# Count rows
		iRowCount = dbCursor.rowcount
		if strSQL[:6].lower() == "select":
			dbResults = dbCursor.fetchall()
		else:
			db.commit()
			dbResults = ()
		return [iRowCount,dbResults]
	except pymysql.err.InternalError as err:
		if strSQL[:6].lower() != "select":
			db.rollback()
		return "Internal Error: unable to execute: {}".format(err)
	except pymysql.err.ProgrammingError as err:
		if strSQL[:6].lower() != "select":
			db.rollback()
		return "Programing Error: unable to execute: {}".format(err)
	except pymysql.err.OperationalError as err:
		if strSQL[:6].lower() != "select":
			db.rollback()
		return "Programing Error: unable to execute: {}".format(err)
	except pymysql.err.IntegrityError as err:
		if strSQL[:6].lower() != "select":
			db.rollback()
		return "Integrity Error: unable to execute: {}".format(err)

def ValidReturn(lsttest):
	if isinstance(lsttest,list):
		if len(lsttest) == 2:
			if isinstance(lsttest[0],int) and isinstance(lsttest[1],tuple):
				return True
			else:
				return False
		else:
			return False
	else:
		return False


def getInput(strPrompt):
    if sys.version_info[0] > 2 :
        return input(strPrompt)
    else:
        return raw_input(strPrompt)
# end getInput

def isInt (CheckValue):
	# function to safely check if a value can be interpreded as an int
	if isinstance(CheckValue,int):
		return True
	elif isinstance(CheckValue,str):
		if CheckValue.isnumeric():
			return True
		else:
			return False
	else:
		return False

def DotDec2Int (strValue):
	strHex = ""
	if ValidateIP(strValue) == False:
		return -10
	# end if

	Quads = strValue.split(".")
	for Q in Quads:
		QuadHex = hex(int(Q))
		strwp = "00"+ QuadHex[2:]
		strHex = strHex + strwp[-2:]
	# next

	return int(strHex,16)

def ValidateIP(strToCheck):
	Quads = strToCheck.split(".")
	if len(Quads) != 4:
		return False
	# end if

	for Q in Quads:
		try:
			iQuad = int(Q)
		except ValueError:
			return False
		# end try

		if iQuad > 255 or iQuad < 0:
			return False
		# end if

	return True

def ValidMask(strToCheck):
	iNumBits=0
	if ValidateIP(strToCheck) == False:
		return 0
	# end if

	iDecValue = DotDec2Int(strToCheck)
	strBinary = bin(iDecValue)

	strTemp = "0"*32 + strBinary[2:]
	strBinary = strTemp[-32:]
	cBit = strBinary[0]
	bFound = False
	x=0
	for c in strBinary:
		x=x+1
		if cBit != c:
			iNumBits = x-1
			if bFound:
				return 0
			else:
				cBit=c
				bFound = True
			# end if
		# end if
	# next
	if iNumBits==0:
		iNumBits = x
	# end if
	return iNumBits
# end function

def DotDecGen (iDecValue):
	if iDecValue < 1 or iDecValue > 4294967295:
		return "Invalid"
	# end if

	# Convert decimal to hex
	HexValue = hex(iDecValue)

	#Ensure the results is 8 hex digits long.
	#IP's lower than 16.0.0.0 have trailing 0's that get trimmed off by hex function
	HexValue = "0"*8+HexValue[2:]
	HexValue = "0x"+HexValue[-8:]
	# Convert Hex to dot dec
	strTemp = str(int(HexValue[2:4],16)) + "." + str(int(HexValue[4:6],16)) + "."
	strTemp = strTemp + str(int(HexValue[6:8],16)) + "." + str(int(HexValue[8:10],16))
	return strTemp
# End Function

def IPCalc (strIPAddress):
	strIPAddress=strIPAddress.strip()
	strIPAddress=strIPAddress.replace("\t"," ")
	strIPAddress=strIPAddress.replace("  "," ")
	strIPAddress=strIPAddress.replace(" /","/")
	dictIPInfo={}
	iBitMask=0
	if "/" in strIPAddress:
		IPAddrParts = strIPAddress.split("/")
		strIPAddress=IPAddrParts[0]
		try:
			iBitMask=int(IPAddrParts[1])
		except ValueError:
			iBitMask=32
		# end try
	else:
		iBitMask = 32
	# end if

	if ValidateIP(strIPAddress):
		dictIPInfo['IPAddr'] = strIPAddress
		dictIPInfo['BitMask'] = str(iBitMask)
		iHostcount = 2**(32 - iBitMask)
		dictIPInfo['Hostcount'] = iHostcount
		iDecIPAddr = DotDec2Int(strIPAddress)
		iDecSubID = iDecIPAddr-(iDecIPAddr%iHostcount)
		iDecBroad = iDecSubID + iHostcount - 1
		dictIPInfo['iDecIPAddr'] = iDecIPAddr
		dictIPInfo['iDecSubID'] = iDecSubID
		dictIPInfo['iDecBroad'] = iDecBroad
		dictIPInfo['Subnet'] = DotDecGen(iDecSubID)
		dictIPInfo['Broadcast'] = DotDecGen(iDecBroad)
	else:
		dictIPInfo['IPError'] = "'" + strIPAddress + "' is not a valid IP!"
	# End if
	return dictIPInfo

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

def CollectApplianceData (dictTemp):
	lstOut = []
	dictInt1 = dictTemp["INTERFACE_SETTINGS"][0]
	dictInt2 = dictTemp["INTERFACE_SETTINGS"][1]
	lstOut.append(dictTemp["NAME"])
	lstOut.append(dictTemp["ID"])
	lstOut.append(dictTemp["UUID"])
	lstOut.append(dictTemp["STATUS"])
	lstOut.append(dictTemp["MODEL_NUMBER"])
	lstOut.append(dictTemp["TYPE"])
	lstOut.append(dictTemp["SERIAL_NUMBER"])
	strIPAddr1 = dictInt1["IP_ADDRESS"] + "/" + str(ValidMask(dictInt1["NETMASK"]))
	iIPAddr1 = DotDec2Int(dictInt1["IP_ADDRESS"])
	lstOut.append(strIPAddr1)
	lstOut.append(str(iIPAddr1))
	lstOut.append(dictInt1["GATEWAY"])
	lstOut.append(str(DotDec2Int(dictInt1["GATEWAY"])))
	lstOut.append(dictInt2["SETTING"])
	if isinstance(dictInt2["IP_ADDRESS"],str):
		strIPAddr2 = dictInt2["IP_ADDRESS"] + "/" + str(ValidMask(dictInt2["NETMASK"]))
		iIPAddr2 = DotDec2Int(dictInt2["IP_ADDRESS"])
		strGWaddr = dictInt2["GATEWAY"]
		iIPGW = DotDec2Int(dictInt2["GATEWAY"])
	else:
		strIPAddr2 = ""
		iIPAddr2 = ""
		iIPGW = ""
		strGWaddr = ""
	lstOut.append(strIPAddr2)
	lstOut.append(str(iIPAddr2))
	lstOut.append(strGWaddr)
	lstOut.append(str(iIPGW))
	if isinstance(dictTemp["STATIC_ROUTES"],type(None)):
		iStaticCount = 0
	elif isinstance(dictTemp["STATIC_ROUTES"]["ROUTE"],list):
		iStaticCount = len (dictTemp["STATIC_ROUTES"]["ROUTE"])
		for dictRoute in dictTemp["STATIC_ROUTES"]["ROUTE"]:
			strIPRoute = dictRoute["IP_ADDRESS"] + "/" + str(ValidMask(dictRoute["NETMASK"]))
			iIPRoute   = DotDec2Int(dictRoute["IP_ADDRESS"])
			iGWIP = DotDec2Int(dictRoute["GATEWAY"])
			lstOut.append("{} ({}) -> {} ({})".format(strIPRoute, iIPRoute, dictRoute["GATEWAY"], iGWIP ))
	else:
		iStaticCount = 1
		dictRoute=dictTemp["STATIC_ROUTES"]["ROUTE"]
		strIPRoute = dictRoute["IP_ADDRESS"] + "/" + str(ValidMask(dictRoute["NETMASK"]))
		iIPRoute   = DotDec2Int(dictRoute["IP_ADDRESS"])
		iGWIP = DotDec2Int(dictRoute["GATEWAY"])
		lstOut.append("{} ({}) -> {} ({})".format(strIPRoute, iIPRoute, dictRoute["GATEWAY"], iGWIP ))

	print ("{} {},{} {} GW {},{} {} {} GW {}, Static Routes: {}".format(dictTemp["NAME"], dictTemp["STATUS"], dictInt1["INTERFACE"],strIPAddr1,dictInt1["GATEWAY"],
		dictInt2["INTERFACE"],dictInt2["SETTING"],strIPAddr2,dictInt2["GATEWAY"],iStaticCount))
	return ",".join(lstOut)

strHeader={'X-Requested-With': strHeadReq}
strAPI = "api/2.0/fo/appliance/?"
# strAction = "action=list&output_mode=full&name=SCNPOL03"
strAction = "action=list&output_mode=full"
strURL = strBaseURL + strAPI + strAction
APIResponse = MakeAPICall(strURL,strHeader,strUserName,strPWD)
if isinstance(APIResponse,str):
	print(APIResponse)
elif isinstance(APIResponse,dict):
	if "APPLIANCE_LIST" in APIResponse["APPLIANCE_LIST_OUTPUT"]["RESPONSE"]:
		objFileOut = open("c:/temp/QualysAppliance.csv" ,"w")
		objFileOut.write ("Name,ID,UUID,Status,Model,Type,Serial Number,Int1 IP,iIP1,Int1 GW,iGWIP1,Int2 Status,Int2 IP,iIP2,Int2 GW,iGWIP2,Static Routes -> next hop\n")
		if isinstance(APIResponse["APPLIANCE_LIST_OUTPUT"]["RESPONSE"]["APPLIANCE_LIST"]["APPLIANCE"],list):
			print ("Number of appliances: {}".format(len(APIResponse["APPLIANCE_LIST_OUTPUT"]["RESPONSE"]["APPLIANCE_LIST"]["APPLIANCE"])))
			for dictTemp in APIResponse["APPLIANCE_LIST_OUTPUT"]["RESPONSE"]["APPLIANCE_LIST"]["APPLIANCE"]:
				objFileOut.write (CollectApplianceData(dictTemp)+"\n")
		else:
			print ("Number of appliances: 1")
			objFileOut.write (CollectApplianceData (APIResponse["APPLIANCE_LIST_OUTPUT"]["RESPONSE"]["APPLIANCE_LIST"]["APPLIANCE"])+"\n")
	else:
		print ("There are no appliances")
else:
	print ("API Response neither a dictionary nor a string. Here is what I got: {}".format(APIResponse))
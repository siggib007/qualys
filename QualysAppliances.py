'''
Qualys Appliance API Script
Author Siggi Bjarnason Copyright 2017
Website http://www.icecomputing.com

Description:
This script will pull all details about our Qualys Scanner appliances using the Qualys API and write the results to a database.
All IP addressess are convereted to an integer to make subnet matching easier to do.

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
import json
import platform
import time
import urllib.parse as urlparse
# End imports

# strConf_File = "QSAppliance.ini"
ISO = time.strftime("-%Y-%m-%d-%H-%M-%S")
strScriptName = os.path.basename(sys.argv[0])
iLoc = sys.argv[0].rfind(".")
strConf_File = sys.argv[0][:iLoc] + ".ini"
strScriptHost = platform.node().upper()
if strScriptHost == "DEV-APS-RHEL-STD-A":
  strScriptHost = "VMSAWS01"
strBaseDir = os.path.dirname(sys.argv[0])
if strBaseDir != "":
  if strBaseDir[-1:] != "/":
    strBaseDir += "/"
strLogDir  = strBaseDir + "Logs"

if not os.path.exists (strLogDir) :
  os.makedirs(strLogDir)
  print ("\nPath '{0}' for log files didn't exists, so I create it!\n".format(strLogDir))

iLoc = strScriptName.rfind(".")
strLogFile = strLogDir + "/" + strScriptName[:iLoc] + ISO + ".log"
strRealPath = os.path.realpath(sys.argv[0])
strVersion = "{0}.{1}.{2}".format(sys.version_info[0],sys.version_info[1],sys.version_info[2])
localtime = time.localtime(time.time())
gmt_time = time.gmtime()
iGMTOffset = (time.mktime(localtime) - time.mktime(gmt_time))/3600
now = time.asctime()
print ("This is a Qualys Appliance API script. This is running under Python Version {0}".format(strVersion))
print ("Running from: {}".format(strRealPath))

print ("The time now is {}".format(now))
print ("Logs saved to {}".format(strLogFile))
objLogOut = open(strLogFile,"w",1)


def SendNotification (strMsg):
  if not bNotifyEnabled:
    return "notifications not enabled"
  dictNotify = {}
  dictNotify["token"] = strNotifyToken
  dictNotify["channel"] = strNotifyChannel
  dictNotify["text"]=strMsg[:9999]
  strNotifyParams = urlparse.urlencode(dictNotify)
  strURL = strNotifyURL + "?" + strNotifyParams
  bStatus = False
  WebRequest = ""
  try:
    WebRequest = requests.get(strURL)
  except Exception as err:
    LogEntry ("Issue with sending notifications. {}".format(err))
  if isinstance(WebRequest,requests.models.Response)==False:
    LogEntry ("response is unknown type")
  else:
    try:
      dictResponse = json.loads(WebRequest.text)
    except Exception as err:
      LogEntry ("Issue with json results while sending notifications. {}".format(err))
      LogEntry (WebRequest.text,True)
    if isinstance(dictResponse,dict):
      if "ok" in dictResponse:
        bStatus = dictResponse["ok"]
    if not bStatus or WebRequest.status_code != 200:
      LogEntry ("Slack Problem: Status Code:{} API Response OK={}".format(WebRequest.status_code,dictResponse["ok"]))
      LogEntry (WebRequest.text)

def CleanExit(strCause):
  if dbConn !="":
    strSQL = "update tblScriptExecuteList set dtStopTime=now(), bComplete=0, iRowsUpdated={} where iExecuteID = {} ;".format(iNumRows,iEntryID)
    lstReturn = SQLQuery (strSQL,dbConn)
    dbConn.close()

  SendNotification("{} is exiting abnormally on {} {}".format(strScriptName,strScriptHost, strCause))
  objLogOut.close()
  sys.exit(9)

def LogEntry(strMsg,bAbort=False):
  strTemp = ""
  strDBMsg = DBClean(strMsg)
  strSQL = "INSERT INTO tblLogs (dtTimestamp, vcScriptName, vcLogEntry) VALUES (now(),'{}','{}');".format(strScriptName,strDBMsg)
  if dbConn !="":
    lstReturn = SQLQuery (strSQL,dbConn)
    if not ValidReturn(lstReturn):
      strTemp = ("   Unexpected issue inserting log entry to the database: {}\n{}".format(lstReturn,strSQL))
    elif lstReturn[0] != 1:
      strTemp = ("   Records affected {}, expected 1 record affected when inserting log entry to the database".format(lstReturn[0]))
  else:
    strTemp = ". Database connection not established yet"

  strMsg += strTemp
  strTimeStamp = time.strftime("%m-%d-%Y %H:%M:%S")
  objLogOut.write("{0} : {1}\n".format(strTimeStamp,strMsg))
  print (strMsg)
  if bAbort:
    SendNotification("{} on {}: {}".format (strScriptName,strScriptHost,strMsg[:99]))
    CleanExit("")

def processConf():
  global strBaseURL
  global strHeadReq
  global strUserName
  global strPWD
  global strServer
  global strDBUser
  global strDBPWD
  global strInitialDB
  global strNotifyURL
  global strNotifyToken
  global strNotifyChannel
  global bNotify
  global bNotifyEnabled

  strBaseURL=None
  strUserName=None
  strPWD=None
  strNotifyURL=None
  strNotifyToken=None
  strNotifyChannel=None

  if os.path.isfile(strConf_File):
    LogEntry ("Configuration File exists")
  else:
    LogEntry ("Can't find configuration file {}, make sure it is the same directory as this script".format(strConf_File),True)

  strLine = "  "
  LogEntry ("Reading in configuration")
  objINIFile = open(strConf_File,"r")
  strLines = objINIFile.readlines()
  objINIFile.close()

  for strLine in strLines:
    strLine = strLine.strip()
    iCommentLoc = strLine.find("#")
    if iCommentLoc > -1:
      strLine = strLine[:iCommentLoc].strip()
    else:
      strLine = strLine.strip()
    if "=" in strLine:
      strConfParts = strLine.split("=")
      strVarName = strConfParts[0].strip()
      strValue = strConfParts[1].strip()
      strConfParts = strLine.split("=")
      if strVarName == "APIBaseURL":
        strBaseURL = strValue
      if strVarName == "APIRequestHeader":
        strHeadReq = strValue
      if strVarName == "QUserID":
        strUserName = strValue
      if strVarName == "QUserPWD":
        strPWD = strValue
      if strVarName == "Server":
        strServer = strValue
      if strVarName == "dbUser":
        strDBUser = strValue
      if strVarName == "dbPWD":
        strDBPWD = strValue
      if strVarName == "InitialDB":
        strInitialDB = strValue
      if strVarName == "NotificationURL":
        strNotifyURL = strValue
      if strVarName == "NotifyChannel":
        strNotifyChannel = strValue
      if strVarName == "NotifyToken":
        strNotifyToken = strValue
      if strVarName == "NotifyEnabled":
        bNotify = strValue.lower()=="yes" or strValue.lower()=="true"
  if strNotifyToken is None or strNotifyChannel is None or strNotifyURL is None:
    bNotifyEnabled = False
    LogEntry("Missing configuration items for Slack notifications, turned slack notifications off")
  else:
    bNotifyEnabled = True

  if strBaseURL[-1:] != "/":
    strBaseURL += "/"

  LogEntry ("Done processing configuration, moving on")

def SQLConn (strServer,strDBUser,strDBPWD,strInitialDB):
  try:
    # Open database connection
    return pymysql.connect(strServer,strDBUser,strDBPWD,strInitialDB)
  except pymysql.err.InternalError as err:
    LogEntry ("Error: unable to connect: {}".format(err),True)
  except pymysql.err.OperationalError as err:
    LogEntry ("Operational Error: unable to connect: {}".format(err),True)
  except pymysql.err.ProgrammingError as err:
    LogEntry ("Programing Error: unable to connect: {}".format(err),True)

def SQLQuery (strSQL,db):
  try:
    # prepare a cursor object using cursor() method
    dbCursor = db.cursor()
    # Execute the SQL command
    dbCursor.execute(strSQL)
    # Count rows
    iRowCount = dbCursor.rowcount
    if strSQL[:6].lower() == "select" or strSQL[:4].lower() == "call":
      dbResults = dbCursor.fetchall()
    else:
      db.commit()
      dbResults = ()
    return [iRowCount,dbResults]
  except pymysql.err.InternalError as err:
    return "Internal Error: unable to execute: {}\n{}\nLength of SQL statement {}\n".format(err,strSQL[:255],len(strSQL))
  except pymysql.err.ProgrammingError as err:
    return "Programing Error: unable to execute: {}\n{}\nLength of SQL statement {}\n".format(err,strSQL[:255],len(strSQL))
  except pymysql.err.OperationalError as err:
    return "Programing Error: unable to execute: {}\n{}\nLength of SQL statement {}\n".format(err,strSQL[:255],len(strSQL))
  except pymysql.err.IntegrityError as err:
    return "Integrity Error: unable to execute: {}\n{}\nLength of SQL statement {}\n".format(err,strSQL[:255],len(strSQL))
  except pymysql.err.DataError as err:
    return "Data Error: unable to execute: {}\n{}\nLength of SQL statement {}\n".format(err,strSQL[:255],len(strSQL))
  except pymysql.err.InterfaceError as err:
    return "Interface Error: unable to execute: {}\n{}\nLength of SQL statement {}\n".format(err,strSQL[:255],len(strSQL))

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

def ConvertFloat (fValue):
  if isinstance(fValue,(float,int,str)):
    try:
      fTemp = float(fValue)
    except ValueError:
      fTemp = "NULL"
  else:
    fTemp = "NULL"
  return fTemp

def QDate2DB(strDate):
  strTemp = DBClean(strDate)
  strTemp = strTemp.replace("T"," ")
  return strTemp.replace("Z","")

def DBClean(strText):
  strTemp = strText.encode("ascii","ignore")
  strTemp = strTemp.decode("ascii","ignore")
  strTemp = strTemp.replace("\\","\\\\")
  strTemp = strTemp.replace("'","\\'")
  return strTemp

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

def MakeAPICall (strURL, strHeader, strUserName,strPWD, strMethod):

  iErrCode = ""
  iErrText = ""
  dictResponse = {}

  LogEntry ("Doing a {} to URL: \n {}\n".format(strMethod,strURL))
  try:
    if strMethod.lower() == "get":
      WebRequest = requests.get(strURL, headers=strHeader, auth=(strUserName, strPWD))
      LogEntry ("get executed")
    if strMethod.lower() == "post":
      WebRequest = requests.post(strURL, headers=strHeader, auth=(strUserName, strPWD))
      LogEntry ("post executed")
  except Exception as err:
    LogEntry ("Issue with API call. {}".format(err))
    CleanExit("due to issue with API, please check the logs")

  if isinstance(WebRequest,requests.models.Response)==False:
    LogEntry ("response is unknown type")
    iErrCode = "ResponseErr"
    iErrText = "response is unknown type"

  LogEntry ("call resulted in status code {}".format(WebRequest.status_code))

  try:
    dictResponse = xmltodict.parse(WebRequest.text)
  except xml.parsers.expat.ExpatError as err:
    # LogEntry("Expat Error: {}\n{}".format(err,WebRequest.text))
    iErrCode = "Expat Error"
    iErrText = "Expat Error: {}\n{}".format(err,WebRequest.text)
  except Exception as err:
    LogEntry("Unkown xmltodict exception: {}".format(err))
    CleanExit(", Unkown xmltodict exception, please check the logs")

  if isinstance(dictResponse,dict):
    if "SIMPLE_RETURN" in dictResponse:
      try:
        if "CODE" in dictResponse["SIMPLE_RETURN"]["RESPONSE"]:
          iErrCode = dictResponse["SIMPLE_RETURN"]["RESPONSE"]["CODE"]
          iErrText = dictResponse["SIMPLE_RETURN"]["RESPONSE"]["TEXT"]
      except KeyError as e:
        LogEntry ("KeyError while decoding error response in XML: {}".format(e))
        LogEntry (WebRequest.text)
        iErrCode = "Unknown"
        iErrText = "Unexpected error"
  else:
    LogEntry ("Aborting abnormally because API response not translated to a dictionary",True)

  if iErrCode != "" or WebRequest.status_code !=200:
    return "There was a problem with your request. HTTP error {} code {} {}".format(WebRequest.status_code,iErrCode,iErrText)
  else:
    return dictResponse

def CollectApplianceData (dictTemp):
  global strNotifyMsg

  dictOut = {}

  LogEntry("Processing {}".format(dictTemp["NAME"]) )
  if dictTemp["SS_LAST_CONNECTED"] == "N/A":
    dictOut["LastConn"] = "NULL"
  else:
    dictOut["LastConn"] = "'" + QDate2DB(dictTemp["SS_LAST_CONNECTED"]) + "'"
  dictOut["MissedHB"] = int(dictTemp["HEARTBEATS_MISSED"])
  if dictTemp["COMMENTS"] is None:
    dictOut["Comment"] = ""
  else:
    dictOut["Comment"] = dictTemp["COMMENTS"]
  if "#text" in dictTemp["ML_VERSION"]:
    dictOut["MLVer"] = dictTemp["ML_VERSION"]["#text"]
  else:
    dictOut["MLVer"] = ""
  if "#text" in dictTemp["VULNSIGS_VERSION"]:
    dictOut["VULNVER"] = dictTemp["VULNSIGS_VERSION"]["#text"]
  else:
    dictOut["VULNVER"] = ""
  if dictTemp["STATUS"]=="Offline" and bNotify:
    if int(dictTemp["HEARTBEATS_MISSED"]) < 700 and int(dictTemp["HEARTBEATS_MISSED"]) > 0:
      strNotifyMsg += ("Scanner {} has been Offline since {} GMT\n".format(dictTemp["NAME"],dictOut["LastConn"]))
  else:
    if dictTemp["ML_VERSION"]["@updated"] == "no" and dictOut["MLVer"] != "" and bNotify:
      strNotifyMsg += ("Scanner {} is at version {}, latest is {}\n".format(dictTemp["NAME"],dictOut["MLVer"],dictTemp["ML_LATEST"]))
    if dictTemp["VULNSIGS_VERSION"]["@updated"] == "no" and dictOut["VULNVER"] != "" and bNotify:
      strNotifyMsg += ("Signatures on {} are at version {}, latest is {}\n".format(dictTemp["NAME"],dictOut["VULNVER"],dictTemp["VULNSIGS_LATEST"]))
  dictOut["ML_LATEST"] = dictTemp["ML_LATEST"]
  dictOut["VulnLatest"] = dictTemp["VULNSIGS_LATEST"]
  dictOut["SoftVer"] = dictTemp["SOFTWARE_VERSION"]
  if dictTemp["LAST_UPDATED_DATE"] == "N/A":
    dictOut["LastUpdate"] = "NULL"
  else:
    dictOut["LastUpdate"] = "'" + QDate2DB(dictTemp["LAST_UPDATED_DATE"]) + "'"
  dictInt1 = dictTemp["INTERFACE_SETTINGS"][0]
  dictInt2 = dictTemp["INTERFACE_SETTINGS"][1]
  dictOut["name"] = dictTemp["NAME"]
  dictOut["ID"] = dictTemp["ID"]
  dictOut["UUID"] = dictTemp["UUID"]
  dictOut["state"] = dictTemp["STATUS"]
  dictOut["model"] = dictTemp["MODEL_NUMBER"]
  dictOut["type"] = dictTemp["TYPE"]
  if dictTemp["TYPE"] == "Virtual":
    dictOut["SN"] = dictTemp["ACTIVATION_CODE"]
  else:
    dictOut["SN"] = dictTemp["SERIAL_NUMBER"]
  if isinstance(dictInt1["IP_ADDRESS"],str):
    strIPAddr1 = dictInt1["IP_ADDRESS"] + "/" + str(ValidMask(dictInt2["NETMASK"]))
    iIPAddr1 = DotDec2Int(dictInt1["IP_ADDRESS"])
    strGWaddr = dictInt1["GATEWAY"]
    iIPGW = DotDec2Int(dictInt1["GATEWAY"])
  else:
    strIPAddr1 = ""
    iIPAddr1 = "NULL"
    iIPGW = "NULL"
    strGWaddr = ""
  dictOut["IPaddr1"] = strIPAddr1
  dictOut["intIP1"] = str(iIPAddr1)
  dictOut["GW1"] = strGWaddr
  dictOut["intGW1"] =str(iIPGW)
  dictOut["DNS1-1"] = dictInt1["DNS"]["PRIMARY"]
  dictOut["DNS1-2"] = dictInt1["DNS"]["SECONDARY"]
  dictOut["Int2State"] = dictInt2["SETTING"]
  if isinstance(dictInt2["IP_ADDRESS"],str):
    strIPAddr2 = dictInt2["IP_ADDRESS"] + "/" + str(ValidMask(dictInt2["NETMASK"]))
    iIPAddr2 = DotDec2Int(dictInt2["IP_ADDRESS"])
    strGWaddr = dictInt2["GATEWAY"]
    iIPGW = DotDec2Int(dictInt2["GATEWAY"])
  else:
    strIPAddr2 = ""
    iIPAddr2 = "NULL"
    iIPGW = "NULL"
    strGWaddr = ""
  dictOut["IPaddr2"] = strIPAddr2
  dictOut["intIP2"] = str(iIPAddr2)
  dictOut["GW2"] = strGWaddr
  dictOut["intGW2"] = str(iIPGW)
  dictOut["DNS2-1"] = dictInt2["DNS"]["PRIMARY"]
  dictOut["DNS2-2"] = dictInt2["DNS"]["SECONDARY"]
  dictOut["ProxyState"] = dictTemp["PROXY_SETTINGS"]["SETTING"]
  dictOut["StaticRoute"] = []
  dictStatic = {}
  if isinstance(dictTemp["STATIC_ROUTES"],type(None)):
    iStaticCount = 0
  elif isinstance(dictTemp["STATIC_ROUTES"]["ROUTE"],list):
    iStaticCount = len (dictTemp["STATIC_ROUTES"]["ROUTE"])
    for dictRoute in dictTemp["STATIC_ROUTES"]["ROUTE"]:
      dictStatic.clear()
      dictStatic["NetBlock"] = dictRoute["IP_ADDRESS"] + "/" + str(ValidMask(dictRoute["NETMASK"]))
      dictStatic["intSubnetID"] = DotDec2Int(dictRoute["IP_ADDRESS"])
      dictStatic["NextHop"] = dictRoute["GATEWAY"]
      dictStatic["intGW"] = DotDec2Int(dictRoute["GATEWAY"])
      dictOut["StaticRoute"].append(dictStatic.copy())
  else:
    iStaticCount = 1
    dictRoute = dictTemp["STATIC_ROUTES"]["ROUTE"]
    dictStatic.clear()
    dictStatic["NetBlock"] = dictRoute["IP_ADDRESS"] + "/" + str(ValidMask(dictRoute["NETMASK"]))
    dictStatic["intSubnetID"] = DotDec2Int(dictRoute["IP_ADDRESS"])
    dictStatic["NextHop"] = dictRoute["GATEWAY"]
    dictStatic["intGW"] = DotDec2Int(dictRoute["GATEWAY"])
    dictOut["StaticRoute"].append(dictStatic.copy())
  return dictOut

def UpdateDB (dictAppliance):

  strSQL = "select * from tblAppliances where vcName = '{}';".format(dictAppliance["name"])
  lstReturn = SQLQuery (strSQL,dbConn)
  if not ValidReturn(lstReturn):
    LogEntry ("Unexpected: {}".format(lstReturn))
    CleanExit("due to unexpected SQL return, please check the logs")
  elif lstReturn[0] == 0:
    strSQL = "select * from tblAppliances where iApplianceID = '{}';".format(dictAppliance["ID"])
    lstReturn = SQLQuery (strSQL,dbConn)
    if not ValidReturn(lstReturn):
      LogEntry ("Unexpected: {}".format(lstReturn))
      CleanExit("due to unexpected SQL return, please check the logs")
    elif lstReturn[0] == 1:
      LogEntry ("Appliance ID {} exists, need to update {}".format(dictAppliance["ID"],dictAppliance["name"]))
      strSQL = ("UPDATE tblAppliances SET vcUUID = '{}', vcName = '{}', vcState = '{}', vcModel = '{}', vcType = '{}', vcSerialNum = '{}', vcIPAddr1 = '{}', vcGW1 = '{}', iIPaddr1 = {}, "
          " iGW1 = {}, vcInt2State = '{}', vcIPAddr2 = '{}', vcGW2 = '{}', iIPAddr2 = {}, iGW2 = {}, vcDNS1_1 = '{}', vcDNS1_2 = '{}', vcDNS2_1 = '{}', "
          " vcDNS2_2 = '{}', vcProxyState = '{}', dtLastAPIUpdate=now(),iMissedHB = {},dtLastConnected = {},vcLatestML = '{}',vcLatestVuln = '{}', "
          " vcSoftVer = '{}',dtLatestUpdate = {},vcMLVer = '{}',vcVulnVer = '{}',vcComment = '{}', iApplianceID = {} WHERE iApplianceID = '{}' ;".format(
            dictAppliance["UUID"],dictAppliance["name"],dictAppliance["state"],dictAppliance["model"],dictAppliance["type"],dictAppliance["SN"],dictAppliance["IPaddr1"],
            dictAppliance["GW1"],dictAppliance["intIP1"],dictAppliance["intGW1"],dictAppliance["Int2State"],dictAppliance["IPaddr2"],dictAppliance["GW2"],dictAppliance["intIP2"],
            dictAppliance["intGW2"],dictAppliance["DNS1-1"],dictAppliance["DNS1-2"],dictAppliance["DNS2-1"],dictAppliance["DNS2-2"],dictAppliance["ProxyState"],
            dictAppliance["MissedHB"],dictAppliance["LastConn"],dictAppliance["ML_LATEST"],dictAppliance["VulnLatest"],dictAppliance["SoftVer"],dictAppliance["LastUpdate"],
            dictAppliance["MLVer"],dictAppliance["VULNVER"],DBClean(dictAppliance["Comment"]),dictAppliance["ID"],dictAppliance["ID"]
            )
        )
    elif lstReturn[0] == 0:
      LogEntry ("Adding appliance {} {}".format(dictAppliance["ID"],dictAppliance["name"]))
      strSQL = ("INSERT INTO tblAppliances (iApplianceID,vcUUID,vcName,vcState,vcModel,vcType,vcSerialNum,vcIPAddr1,vcGW1,iIPaddr1,iGW1,vcInt2State,vcIPAddr2,vcGW2,iIPAddr2,iGW2,"
          "vcDNS1_1,vcDNS1_2,vcDNS2_1,vcDNS2_2,vcProxyState,dtLastAPIUpdate,iMissedHB,dtLastConnected,vcLatestML,vcLatestVuln,vcSoftVer,dtLatestUpdate,vcMLVer,vcVulnVer,vcComment) "
          "VALUES({},'{}','{}','{}','{}','{}','{}','{}','{}',{},{},'{}','{}','{}',{},{},'{}','{}','{}','{}','{}',now(),{},{},'{}','{}','{}',{},'{}','{}','{}');".format(
            dictAppliance["ID"],dictAppliance["UUID"],dictAppliance["name"],dictAppliance["state"],dictAppliance["model"],dictAppliance["type"],dictAppliance["SN"],dictAppliance["IPaddr1"],
            dictAppliance["GW1"],dictAppliance["intIP1"],dictAppliance["intGW1"],dictAppliance["Int2State"],dictAppliance["IPaddr2"],dictAppliance["GW2"],dictAppliance["intIP2"],
            dictAppliance["intGW2"],dictAppliance["DNS1-1"],dictAppliance["DNS1-2"],dictAppliance["DNS2-1"],dictAppliance["DNS2-2"],dictAppliance["ProxyState"],
            dictAppliance["MissedHB"],dictAppliance["LastConn"],dictAppliance["ML_LATEST"],dictAppliance["VulnLatest"],dictAppliance["SoftVer"],
            dictAppliance["LastUpdate"],dictAppliance["MLVer"],dictAppliance["VULNVER"],DBClean(dictAppliance["Comment"]))
          )
    else:
      LogEntry ("Something is horrible wrong, there are {} appliance with name of {}".format(lstReturn[0],dictAppliance["name"]))
      return "Abort!!!"
  elif lstReturn[0] == 1:
    LogEntry ("Appliance name {} exists, need to update {}".format(dictAppliance["name"],dictAppliance["ID"]))
    strSQL = ("UPDATE tblAppliances SET vcUUID = '{}', vcName = '{}', vcState = '{}', vcModel = '{}', vcType = '{}', vcSerialNum = '{}', vcIPAddr1 = '{}', vcGW1 = '{}', iIPaddr1 = {}, "
          " iGW1 = {}, vcInt2State = '{}', vcIPAddr2 = '{}', vcGW2 = '{}', iIPAddr2 = {}, iGW2 = {}, vcDNS1_1 = '{}', vcDNS1_2 = '{}', vcDNS2_1 = '{}', "
          " vcDNS2_2 = '{}', vcProxyState = '{}', dtLastAPIUpdate=now(),iMissedHB = {},dtLastConnected = {},vcLatestML = '{}',vcLatestVuln = '{}', "
          " vcSoftVer = '{}',dtLatestUpdate = {},vcMLVer = '{}',vcVulnVer = '{}',vcComment = '{}', iApplianceID = {} WHERE vcName = '{}' ;".format(
            dictAppliance["UUID"],dictAppliance["name"],dictAppliance["state"],dictAppliance["model"],dictAppliance["type"],dictAppliance["SN"],dictAppliance["IPaddr1"],
            dictAppliance["GW1"],dictAppliance["intIP1"],dictAppliance["intGW1"],dictAppliance["Int2State"],dictAppliance["IPaddr2"],dictAppliance["GW2"],dictAppliance["intIP2"],
            dictAppliance["intGW2"],dictAppliance["DNS1-1"],dictAppliance["DNS1-2"],dictAppliance["DNS2-1"],dictAppliance["DNS2-2"],dictAppliance["ProxyState"],
            dictAppliance["MissedHB"],dictAppliance["LastConn"],dictAppliance["ML_LATEST"],dictAppliance["VulnLatest"],dictAppliance["SoftVer"],dictAppliance["LastUpdate"],
            dictAppliance["MLVer"],dictAppliance["VULNVER"],DBClean(dictAppliance["Comment"]),dictAppliance["ID"],dictAppliance["name"]
            )
        )
  else:
    LogEntry ("Something is horrible wrong, there are {} appliance with name of {}".format(lstReturn[0],dictAppliance["name"]))
    return "Abort!!!"
  lstReturn = SQLQuery (strSQL,dbConn)
  if not ValidReturn(lstReturn):
    LogEntry ("Unexpected: {}".format(lstReturn))
    LogEntry (strSQL)
    CleanExit("due to unexpected SQL return, please check the logs")
  elif lstReturn[0] != 1:
    LogEntry ("Records affected {}, expected 1 record affected".format(lstReturn[0]))
  for dictRoute in dictAppliance["StaticRoute"]:
    strSQL = ("INSERT INTO tblScannerRoutes (iApplianceID,vcNetBlock,vcNextHop,iNetBlock,iNextHop) "
          "VALUES ({0},'{1}','{2}',{3},{4}) ".format(dictAppliance["ID"],dictRoute["NetBlock"],dictRoute["NextHop"],dictRoute["intSubnetID"],dictRoute["intGW"]))
    lstReturn = SQLQuery (strSQL,dbConn)
    if not ValidReturn(lstReturn):
      LogEntry ("Unexpected: {}".format(lstReturn))
      CleanExit("due to unexpected SQL return, please check the logs")
    elif lstReturn[0] != 1:
      LogEntry ("Records affected {}, expected 1 record affected".format(lstReturn[0]))

dbConn = ""
strNotifyMsg = ""
iNumRows = 0
iEntryID = -15
processConf()
dbConn = SQLConn (strServer,strDBUser,strDBPWD,strInitialDB)
strSQL = "INSERT INTO tblScriptExecuteList (vcScriptName,dtStartTime,iGMTOffset) VALUES('{}',now(),{});".format(strScriptName,iGMTOffset)
lstReturn = SQLQuery (strSQL,dbConn)
if not ValidReturn(lstReturn):
  LogEntry ("Unexpected: {}".format(lstReturn))
  CleanExit("due to unexpected SQL return, please check the logs")
elif lstReturn[0] != 1:
  LogEntry ("Records affected {}, expected 1 record affected".format(lstReturn[0]))

strSQL = "select iExecuteID,dtStartTime from tblScriptExecuteList where vcScriptName = '{}' order by dtStartTime desc limit 1;".format(strScriptName)
lstReturn = SQLQuery (strSQL,dbConn)
if not ValidReturn(lstReturn):
  LogEntry ("Unexpected: {}".format(lstReturn))
  CleanExit("due to unexpected SQL return, please check the logs")
elif lstReturn[0] != 1:
  LogEntry ("Records affected {}, expected 1 record affected".format(lstReturn[0]))
  iEntryID = -10
else:
  iEntryID = lstReturn[1][0][0]
  dtStartTime = lstReturn[1][0][1]

LogEntry("Recorded start entry, ID {}".format(iEntryID))

strHeader={'X-Requested-With': strHeadReq}
strAPI = "api/2.0/fo/appliance/?"
strAction = "action=list&output_mode=full"
# strAction = "action=list&output_mode=full&name=SCNTTN16"
strURL = strBaseURL + strAPI + strAction
APIResponse = MakeAPICall(strURL,strHeader,strUserName,strPWD,"get")
if isinstance(APIResponse,str):
  LogEntry(APIResponse)
elif isinstance(APIResponse,dict):
  if "APPLIANCE_LIST" in APIResponse["APPLIANCE_LIST_OUTPUT"]["RESPONSE"]:
    if isinstance(APIResponse["APPLIANCE_LIST_OUTPUT"]["RESPONSE"]["APPLIANCE_LIST"]["APPLIANCE"],list):
      iNumRows = len(APIResponse["APPLIANCE_LIST_OUTPUT"]["RESPONSE"]["APPLIANCE_LIST"]["APPLIANCE"])
      LogEntry ("Number of appliances: {}".format(iNumRows))
      for dictTemp in APIResponse["APPLIANCE_LIST_OUTPUT"]["RESPONSE"]["APPLIANCE_LIST"]["APPLIANCE"]:
        UpdateDB(CollectApplianceData(dictTemp))
    else:
      iNumRows = 1
      LogEntry ("Number of appliances: {}".format(iNumRows))
      UpdateDB(CollectApplianceData (APIResponse["APPLIANCE_LIST_OUTPUT"]["RESPONSE"]["APPLIANCE_LIST"]["APPLIANCE"]))
  else:
    LogEntry ("There are no appliances")
else:
  LogEntry ("API Response neither a dictionary nor a string. Here is what I got: {}".format(APIResponse))

LogEntry ("Doing validation checks")
strSQL = "select count(*) from tblAppliances where dtLastAPIUpdate > '{}';".format(dtStartTime)
lstReturn = SQLQuery (strSQL,dbConn)
if not ValidReturn(lstReturn):
  LogEntry ("Unexpected: {}".format(lstReturn))
  CleanExit("due to unexpected SQL return, please check the logs")
elif lstReturn[0] != 1:
  LogEntry ("Records affected {}, expected 1 record affected".format(lstReturn[0]))
else:
  iCountChange = lstReturn[1][0][0]

LogEntry ("VALIDATE: Total Number of scanner appliances downloaded {}; Total number of scanner appliances updated in the database {}".format(iNumRows,iCountChange))
if iNumRows != iCountChange:
  LogEntry ("VALIDATE: Host validation failed")
  strNotifyMsg += ("{} has completed processing on {}, and validation checks failed\n".format(strScriptName,strScriptHost))
else:
  LogEntry ("VALIDATE: Host validation successful")
  strNotifyMsg += ("{} has completed processing on {}, validation checks are good. Processed {} scanner appliances.\n".format(strScriptName,strScriptHost,iNumRows))

SendNotification ("Complete!\n{}".format(strNotifyMsg))
LogEntry("Updating completion entry")
strSQL = "update tblScriptExecuteList set dtStopTime=now(), bComplete=1, iRowsUpdated={} where iExecuteID = {} ;".format(iNumRows,iEntryID)
lstReturn = SQLQuery (strSQL,dbConn)
if not ValidReturn(lstReturn):
  LogEntry ("Unexpected: {}".format(lstReturn))
elif lstReturn[0] != 1:
  LogEntry ("Records affected {}, expected 1 record affected".format(lstReturn[0]))
LogEntry ("All Done!")
dbConn.close()
objLogOut.close()
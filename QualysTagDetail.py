'''
Script to pull all Vulnerability details data from Qualys Knowledge Base
Version 2
Author Siggi Bjarnason Copyright 2018
Website http://www.ipcalc.us/ and http://www.icecomputing.com

Following packages need to be installed as administrator
pip install requests
pip install xmltodict
pip install pymysql
pip install jason
pip install pyodbc

'''
# Import libraries
import sys
import requests
import os
import time
import xmltodict
import urllib.parse as urlparse
import xml.parsers.expat
import json
import platform
# End imports

dictHeader = {}

strFormat = "json"
ISO = time.strftime("-%Y-%m-%d-%H-%M-%S")
iLoc = sys.argv[0].rfind(".")
strConf_File = sys.argv[0][:iLoc] + ".ini"
strChild_File = sys.argv[0][:iLoc] + "-children.txt"
strBaseDir = os.path.dirname(sys.argv[0])
if strBaseDir != "":
  if strBaseDir[-1:] != "/":
    strBaseDir += "/"
strLogDir  = strBaseDir + "Logs"

if not os.path.exists (strLogDir) :
  os.makedirs(strLogDir)
  print ("\nPath '{0}' for log files didn't exists, so I create it!\n".format(strLogDir))


strScriptName = os.path.basename(sys.argv[0])
iLoc = strScriptName.rfind(".")
strLogFile = strLogDir + "/" + strScriptName[:iLoc] + ISO + ".log"
strRealPath = os.path.realpath(sys.argv[0])
strVersion = "{0}.{1}.{2}".format(sys.version_info[0],sys.version_info[1],sys.version_info[2])
localtime = time.localtime(time.time())
gmt_time = time.gmtime()
iGMTOffset = (time.mktime(localtime) - time.mktime(gmt_time))/3600

strScriptHost = platform.node().upper()
if strScriptHost == "DEV-APS-RHEL-STD-A":
  strScriptHost = "VMSAWS01"

print ("This is a script to gather all asset tag details from Qualys via API. This is running under Python Version {}".format(strVersion))
print ("Running from: {}".format(strRealPath))
now = time.asctime()
print ("The time now is {}".format(now))
print ("Logs saved to {}".format(strLogFile))
objLogOut = open(strLogFile,"w",1)

dboErr = None
dbo = None
iTotalCount = 0
iEntryID = 0
iCountHostChange = 0
iCountTagChange = 0
strDBType = "undef"
strDBUser = ""
strDBPWD = ""
strdbNow = time.strftime("%Y-%m-%d %H:%M:%S")
objChildFile = None

def SendNotification (strMsg):
  dictNotify = {}
  dictNotify["token"] = strNotifyToken
  dictNotify["channel"] = strNotifyChannel
  dictNotify["text"]=strMsg[:199]
  strNotifyParams = urlparse.urlencode(dictNotify)
  strURL = strNotifyURL + "?" + strNotifyParams
  bStatus = False
  try:
    WebRequest = requests.get(strURL)
  except Exception as err:
    LogEntry ("Issue with sending notifications. {}".format(err))
  if isinstance(WebRequest,requests.models.Response)==False:
    LogEntry ("response is unknown type")
  else:
    dictResponse = json.loads(WebRequest.text)
    if isinstance(dictResponse,dict):
      if "ok" in dictResponse:
        bStatus = dictResponse["ok"]
    if not bStatus or WebRequest.status_code != 200:
      LogEntry ("Problme: Status Code:[] API Response OK={}")
      LogEntry (WebRequest.text)

def CleanExit(strCause):
  if dbConn !="":
      strdbNow = time.strftime("%Y-%m-%d %H:%M:%S")
      strSQL = ("update tblScriptExecuteList set dtStopTime='{}', bComplete=0, "
          " iRowsUpdated={} where iExecuteID = {} ;".format(strdbNow, iTotalCount,iEntryID))
      lstReturn = SQLQuery (strSQL,dbConn)
      dbConn.close()

  SendNotification("{} is exiting abnormally on {} {}".format(strScriptName,strScriptHost, strCause))
  objLogOut.close()
  if objChildFile is not None:
    objChildFile.close()
  sys.exit(9)

def LogEntry(strMsg,bAbort=False):
  strTemp = ""
  strDBMsg = DBClean(strMsg)
  strSQL = "INSERT INTO tblLogs (vcScriptName, vcLogEntry) VALUES ('{}','{}');".format(strScriptName,strDBMsg)
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
  global dictHeader
  global strUserName
  global strPWD
  global strServer
  global strDBUser
  global strDBPWD
  global strInitialDB
  global iMinQuietTime
  global strLoadType
  global dtFullLoad
  global iTagID
  global strFormat
  global strNotifyURL
  global strNotifyToken
  global strNotifyChannel
  global strDBType

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
        dictHeader["X-Requested-With"] = strValue
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
      if strVarName == "MinQuietTime":
        iMinQuietTime = int(strValue)
      if strVarName == "LoadType":
        strLoadType = strValue
      if strVarName == "Format":
        strFormat = strValue
      if strVarName == "FullFromDate":
        dtFullLoad = strValue
      if strVarName == "TagID":
        if isInt(strValue):
          iTagID = int(strValue)
        else:
          iTagID = "-10"
      if strVarName == "NotificationURL":
        strNotifyURL = strValue
      if strVarName == "NotifyChannel":
        strNotifyChannel = strValue
      if strVarName == "NotifyToken":
        strNotifyToken = strValue
      if strVarName == "DBType":
        strDBType  = strValue

  if strBaseURL[-1:] != "/":
    strBaseURL += "/"

  LogEntry ("Done processing configuration, moving on")

def MakeAPICall (strURL, dictHeader, strUserName,strPWD, strMethod):

  iErrCode = ""
  iErrText = ""
  dictResponse = {}

  LogEntry ("Doing a {} to URL: \n {}\n".format(strMethod,strURL))
  try:
    if strMethod.lower() == "get":
      WebRequest = requests.get(strURL, headers=dictHeader, auth=(strUserName, strPWD))
      LogEntry ("get executed")
    if strMethod.lower() == "post":
      WebRequest = requests.post(strURL, headers=dictHeader, auth=(strUserName, strPWD))
      LogEntry ("post executed")
  except Exception as err:
    LogEntry ("Issue with API call. {}".format(err))
    CleanExit("due to issue with API, please check the logs")

  if isinstance(WebRequest,requests.models.Response)==False:
    LogEntry ("response is unknown type")
    iErrCode = "ResponseErr"
    iErrText = "response is unknown type"

  LogEntry ("call resulted in status code {}".format(WebRequest.status_code))

  if WebRequest.status_code == 200:
    if strFormat == "xml":
      try:
        dictResponse = xmltodict.parse(WebRequest.text)
      except xml.parsers.expat.ExpatError as err:
        # LogEntry("Expat Error: {}\n{}".format(err,WebRequest.text))
        iErrCode = "Expat Error"
        iErrText = "Expat Error: {}\n{}".format(err,WebRequest.text)
      except Exception as err:
        LogEntry("Unkown xmltodict exception: {}".format(err))
        CleanExit(", Unkown xmltodict exception, please check the logs")
    elif strFormat == "json":
      dictResponse = json.loads(WebRequest.text)
  else:
    iErrCode = WebRequest.status_code
    iErrText = WebRequest.text


  if isinstance(dictResponse,dict):
    if "SIMPLE_RETURN" in dictResponse:
      try:
        if "CODE" in dictResponse["SIMPLE_RETURN"]["RESPONSE"]:
          iErrCode = dictResponse["SIMPLE_RETURN"]["RESPONSE"]["CODE"]
          iErrText = dictResponse["SIMPLE_RETURN"]["RESPONSE"]["TEXT"]
      except KeyError as e:
        LogEntry ("KeyError: {}".format(e))
        LogEntry (WebRequest.text)
        iErrCode = "Unknown"
        iErrText = "Unexpected error"
    elif "ServiceResponse" in dictResponse:
      if "responseCode" in dictResponse["ServiceResponse"]:
        if dictResponse["ServiceResponse"]["responseCode"] != "SUCCESS":
          iErrCode = "json error"
          iErrText = dictResponse["ServiceResponse"]["responseCode"]
      else:
        LogEntry ("KeyError: No response code")
        LogEntry (WebRequest.text)
        iErrCode = "Unknown"
        iErrText = "Unexpected error"
  else:
    LogEntry ("Aborting abnormally because API response not translated to a dictionary",True)

  if iErrCode != "" or WebRequest.status_code !=200:
    LogEntry ("There was a problem with your request. HTTP error {} code {} {}".format(WebRequest.status_code,iErrCode,iErrText))
    if WebRequest.status_code !=200:
      LogEntry ("Since HTTP status is {}, Exiting".format(WebRequest.status_code),True)
  else:
    return dictResponse

def SQLConn (strServer,strDBUser,strDBPWD,strInitialDB):
  global dboErr
  global dbo
  strError = ""

  try:
    # Open database connection
    if strDBType == "mssql":
      import pyodbc as dbo
      import pyodbc as dboErr
      if strDBUser == "":
        strConnect = (" DRIVER={{ODBC Driver 17 for SQL Server}};"
                      " SERVER={};"
                      " DATABASE={};"
                      " Trusted_Connection=yes;".format(strServer,strInitialDB))
        LogEntry ("Connecting to MSSQL server {} via trusted connection".format(strServer))
      else:
        strConnect = (" DRIVER={{ODBC Driver 17 for SQL Server}};"
                      " SERVER={};"
                      " DATABASE={};"
                      " UID={};"
                      " PWD={};".format(strServer,strInitialDB,strDBUser,strDBPWD))
        LogEntry ("Connecting to MSSQL server {} via username/password".format(strServer))
      return dbo.connect(strConnect)
    elif strDBType == "mysql":
      import pymysql as dbo
      from pymysql import err as dboErr
      LogEntry ("Connecting to MySQL server {}".format(strServer))
      return dbo.connect(strServer,strDBUser,strDBPWD,strInitialDB)
    else:
      strError = ("Unknown database type: {}".format(strDBType))
  except dboErr.InternalError as err:
    LogEntry ("Error: unable to connect: {}".format(err),True)
  except dboErr.OperationalError as err:
    LogEntry ("Operational Error: unable to connect: {}".format(err),True)
  except dboErr.ProgrammingError as err:
    LogEntry ("Programing Error: unable to connect: {}".format(err),True)
  if strError != "":
    LogEntry (strError,True)

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
  except dboErr.InternalError as err:
    return "Internal Error: unable to execute: {}\n{}\nLength of SQL statement {}\n".format(err,strSQL[:255],len(strSQL))
  except dboErr.ProgrammingError as err:
    return "Programing Error: unable to execute: {}\n{}\nLength of SQL statement {}\n".format(err,strSQL[:255],len(strSQL))
  except dboErr.OperationalError as err:
    return "Programing Error: unable to execute: {}\n{}\nLength of SQL statement {}\n".format(err,strSQL[:255],len(strSQL))
  except dboErr.IntegrityError as err:
    return "Integrity Error: unable to execute: {}\n{}\nLength of SQL statement {}\n".format(err,strSQL[:255],len(strSQL))
  except dboErr.DataError as err:
    return "Data Error: unable to execute: {}\n{}\nLength of SQL statement {}\n".format(err,strSQL[:255],len(strSQL))
  except dboErr.InterfaceError as err:
    return "Interface Error: unable to execute: {}\n{}\nLength of SQL statement {}\n".format(err,strSQL[:255],len(strSQL))


def ValidReturn(lsttest):
  if isinstance(lsttest,list):
    if len(lsttest) == 2:
      if isinstance(lsttest[0],int) and (isinstance(lsttest[1],tuple) or isinstance(lsttest[1],list)):
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
  strTemp = strTemp.replace("'","\"")
  return strTemp

# Function BinMask2Dec
# Convert bitmask to Decimal
# Takes in an integer from 1 to 32 as mask reprisenting number of bits in the subnet
# converts that to a decimal number that can be converted lated to a dotted decimal
def BitMask2Dec(iBitMask):
  if iBitMask < 0 or iBitMask > 32:
    return 0
  # end if
  iBitLeft = 32 - iBitMask
  strBinMask=("1"*iBitMask) + ("0"*iBitLeft)
  return int(strBinMask,2)
# End Function

# Function DotDecGen
# Takes a decimal value and converts it to a dotted decimal string
# Number has to be greater than 0 and 32 bits.
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


# Function ValidateIP
# Takes in a string and validates that it follows standard IP address format
# Should be four parts with period deliniation
# Each nubmer should be a number from 0 to 255.
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
# end function

# Function DotDec2Int
# Takes in a string like an IP address or a mask
# returns decimal integer representation of that string
def DotDec2Int (strValue):
  strHex = ""
  if ValidateIP(strValue) == False:
    return 0
  # end if

  Quads = strValue.split(".")
  for Q in Quads:
    QuadHex = hex(int(Q))
    strwp = "00"+ QuadHex[2:]
    strHex = strHex + strwp[-2:]
  # next

  return int(strHex,16)
# end function

# Function ValidMask
# Takes in a string containing a dotted decimal mask
# validates that it is valid, by checking if it follows normal IP format
# and that bits are all sequential, such as 111111100000 not 1100111110001111, etc
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

# Function MaskType
# Takes is a string with a subnet mask and determines if it is:
# - standard dotted decimal format
# - inverse dotted decimal format
# - neither, aka invalid mask format
def MaskType (strToCheck):
  if ValidMask(strToCheck)==False:
    return "Invalid Mask"
  # end if

  Quads = strToCheck.split(".")
  if int(Quads[0]) == int(Quads[3]):
    if int(Quads[0]) ==255:
      return "dotDec"
    else:
      return "inv"
    # end if
  # end if

  if int(Quads[0]) > int(Quads[3]):
    return "dotDec"
  else:
    return "inv"
  # end if
# End Function

# Function SubnetCompare
# Takes in three integers, two are int represenation of IP addresses, one is int of a mask
def SubnetCompare (iIP1,iIP2,iMask):
  iSubnet1 = iIP1 | iMask
  iSubnet2 = iIP2 | iMask
  return iSubnet1==iSubnet2
# End function

# Function ConvertMask
# Switches between dotted decimal and inverse dotted decimal
def ConvertMask (strToCheck):
  if ValidMask(strToCheck)==False:
    return "Invalid Mask"
  # end if
  strTemp = ""
  Quads = strToCheck.split(".")
  for Q in Quads:
    if strTemp =="":
      strTemp = str(255-int(Q))
    else:
      strTemp = strTemp + "." + str(255-int(Q))
    # End if
  #next
  return strTemp
# End function

# Function IPCalc
# This function takes in a string of IP address and does the actual final colculation
def IPCalc (strIPAddress):
  strIPAddress=strIPAddress.strip()
  strIPAddress=strIPAddress.replace("\t"," ")
  strIPAddress=strIPAddress.replace("  "," ")
  strIPAddress=strIPAddress.replace(" /","/")
  dictIPInfo={}
  strMask=""
  iBitMask=0
  if " " in strIPAddress:
    IPAddrParts = strIPAddress.split(" ")
    strIPAddress=IPAddrParts[0]
    strMask = IPAddrParts[1]
  if "/" in strIPAddress:
    IPAddrParts = strIPAddress.split("/")
    strIPAddress=IPAddrParts[0]
    try:
      iBitMask=int(IPAddrParts[1])
    except ValueError:
      iBitMask=0
    # end try
    strMask = DotDecGen(BitMask2Dec(iBitMask))
    if strMask != "Invalid":
      dictIPInfo['Maskmsg'] = "You provided the mask as a bit mask"
    else:
      dictIPInfo['MaskErr'] = str(iBitMask) + " is an invalid bit mask, changing to /32"
      iBitMask=32
      strMask = DotDecGen(BitMask2Dec(iBitMask))
    # end if
  # end if

  iBitMask = ValidMask(strMask)
  if iBitMask==0:
    if strMask=="":
      dictIPInfo['MaskErr'] = "You didn't provide a mask, assuming host only"
    else:
      dictIPInfo['MaskErr'] = strMask + " is an invalid mask, changing to host only"
    iBitMask=32
    strMask = DotDecGen(BitMask2Dec(iBitMask))
  # end if

  strMask2 = ConvertMask(strMask)
  strType = MaskType(strMask)
  if strType =="dotDec":
    dictIPInfo['Mask'] = strMask
    dictIPInfo['InvMask'] = strMask2
  elif strType == "inv":
    dictIPInfo['Mask'] = strMask2
    dictIPInfo['InvMask'] = strMask
  # end if

  if ValidateIP(strIPAddress):
    dictIPInfo['IPAddr'] = strIPAddress
    dictIPInfo['BitMask'] = str(iBitMask)
    iHostcount = 2**(32 - iBitMask)
    dictIPInfo['Hostcount'] = iHostcount
    iDecIPAddr = DotDec2Int(strIPAddress)
    iDecSubID = iDecIPAddr-(iDecIPAddr%iHostcount)
    iDecBroad = iDecSubID + iHostcount - 1
    dictIPInfo['Subnet'] = DotDecGen(iDecSubID)
    dictIPInfo['Broadcast'] = DotDecGen(iDecBroad)
    dictIPInfo['iDecIPAddr'] = iDecIPAddr
    dictIPInfo['iDecSubID'] = iDecSubID
    dictIPInfo['iDecBroad'] = iDecBroad
  else:
    dictIPInfo['IPError'] = "'" + strIPAddress + "' is not a valid IP!"
  # End if
  return dictIPInfo
# end function

def UpdateDB (dictResults):
  global lstChildren
  lstParts=[]

  if "id" in dictResults:
    if isInt(dictResults["id"]):
      iTagID = int(dictResults["id"])
    else:
      iTagID = "NULL"
  else:
    iTagID = "NULL"

  if "modified" in dictResults:
    dtModified = "'" + QDate2DB(dictResults["modified"]) + "'"
  else:
    dtModified = "NULL"

  if "name" in dictResults:
    strTagName = DBClean (dictResults["name"])
  else:
    strTagName = ""

  if "ruleText" in dictResults:
    strRuleText = DBClean(dictResults["ruleText"])
  else:
    strRuleText = ""

  if strRuleText[:8] == "<RANGES>":
    dictRules = xmltodict.parse(strRuleText)
    if isinstance(dictRules["RANGES"]["RANGE"],dict):
      if "@type" in dictRules["RANGES"]["RANGE"]:
        if dictRules["RANGES"]["RANGE"]["@type"].lower() == "ip":
          lstParts = dictRules["RANGES"]["RANGE"]["#text"].split(",")
      else:
        lstParts = dictRules["RANGES"]["RANGE"]["#text"].split(",")
    elif isinstance(dictRules["RANGES"]["RANGE"],list):
      for dictTemp in dictRules["RANGES"]["RANGE"]:
        if "@type" in dictTemp:
          if dictTemp["@type"].lower() == "ip":
            lstParts.extend(dictTemp["#text"].split(","))
        else:
          lstParts.extend(dictTemp["#text"].split(","))
    else:
      LogEntry ("Type {} not expected".format(type(dictRules["RANGES"]["RANGE"])))
  elif "<IP_RANGES>" in strRuleText:
    dictRules = xmltodict.parse(strRuleText)
    if "TAG_CRITERIA" in dictRules:
      if "IP_RANGES" in dictRules["TAG_CRITERIA"]:
        if "IP_RANGE" in dictRules["TAG_CRITERIA"]["IP_RANGES"]:
          if isinstance(dictRules["TAG_CRITERIA"]["IP_RANGES"]["IP_RANGE"],list):
            lstParts = dictRules["TAG_CRITERIA"]["IP_RANGES"]["IP_RANGE"]

  elif strRuleText[:27] == "aws.ec2.privateIpAddress: `":
    lstParts = strRuleText[27:-1].split(",")
  elif strRuleText.count(".") > 2:
    lstParts = strRuleText.split(",")

  if len(lstParts) > 0:
    LogEntry ("Tag {} {} has {} rule elements.".format(iTagID,strTagName,len(lstParts)))
    strSQL = "delete from tblRule_Element where iTagID = {};".format(iTagID)
    lstReturn = SQLQuery (strSQL,dbConn)
    if not ValidReturn(lstReturn):
      LogEntry ("Unexpected: {}".format(lstReturn))
      CleanExit("due to unexpected SQL return, please check the logs")
    else:
      LogEntry ("Deleted {} tag elements for tag {} {}".format(lstReturn[0],iTagID,strTagName))

  if "srcBusinessUnitId" in dictResults:
    if isInt(dictResults["srcBusinessUnitId"]):
      iSrcBusinessUnitID = int(dictResults["srcBusinessUnitId"])
    else:
      iSrcBusinessUnitID = "NULL"
  else:
    iSrcBusinessUnitID = "NULL"

  if "parentTagId" in dictResults:
    if isInt(dictResults["parentTagId"]):
      iParentTagID = int(dictResults["parentTagId"])
    else:
      iParentTagID = "NULL"
  else:
    iParentTagID = "NULL"


  if "srcAssetGroupId" in dictResults:
    if isInt(dictResults["srcAssetGroupId"]):
      iSrcAssetGroupID = int(dictResults["srcAssetGroupId"])
    else:
      iSrcAssetGroupID = "NULL"
  else:
    iSrcAssetGroupID = "NULL"

  if "created" in dictResults:
    dtCreated = "'" + QDate2DB(dictResults["created"]) + "'"
  else:
    dtCreated = "NULL"

  if "ruleType" in dictResults:
    strRuleType = DBClean(dictResults["ruleType"])
  else:
    strRuleType = ""

  iChildCount = -10
  if "children" in dictResults:
    if "list" in dictResults["children"]:
      if isinstance(dictResults["children"]["list"],list):
        iChildCount = len(dictResults["children"]["list"])
        LogEntry("Child count {}".format(iChildCount))
        lstTemp = dictResults["children"]["list"]
        for dictTemp in lstTemp:
          iChildID = dictTemp["TagSimple"]["id"]
          strChildName = dictTemp["TagSimple"]["name"]
          if not iChildID in lstChildren:
            lstChildren.append(iChildID)
            objChildFile.write("{}\n".format(iChildID))
      elif dictResults["children"]["list"] is None:
        iChildCount = 0
      else:
        LogEntry("TagID {} children list is not a list or a none type, so weird".format(iTagID))
    else:
      LogEntry("TagID {} children element is present but without the list sub element".format(iTagID))
  else:
    LogEntry("No children element on TagID {} ".format(iTagID))

  strdbNow = time.strftime("%Y-%m-%d %H:%M:%S")
  strSQL = "select * from tblTags where iTagID = {};".format(iTagID)
  lstReturn = SQLQuery (strSQL,dbConn)
  if not ValidReturn(lstReturn):
    LogEntry ("Unexpected: {}".format(lstReturn))
    CleanExit("due to unexpected SQL return, please check the logs")
  elif len(lstReturn[1]) == 0:
    LogEntry ("Adding Tag {} {}".format(iTagID,strTagName))
    strSQL = ("INSERT INTO tblTags (iTagID, vcTagName, dtLastModified, tRuleText, iSrcBusinessUnitID, "
              " iParentTagID, iSrcAssetGroupID, dtCreated, iChildCount, vcRuleType, dtLastAPIUpdate) "
              " VALUES ({}, '{}', {}, '{}', {}, {}, {}, {}, {}, '{}', '{}');".format(iTagID,strTagName, dtModified,
                strRuleText,iSrcBusinessUnitID,iParentTagID,iSrcAssetGroupID,dtCreated,iChildCount,strRuleType,strdbNow))
  elif len(lstReturn[1]) == 1:
    strSQL = ("UPDATE tblTags SET dtLastModified = {}, tRuleText = '{}', iSrcBusinessUnitID = {}, "
                    " iParentTagID = {}, iSrcAssetGroupID = {}, dtCreated = {}, iChildCount = {}, "
                    " vcRuleType = '{}', dtLastAPIUpdate = '{}' WHERE iTagID = {};".format(dtModified,
                      strRuleText,iSrcBusinessUnitID,iParentTagID,iSrcAssetGroupID,dtCreated,iChildCount,
                      strRuleType,strdbNow, iTagID))
  else:
    LogEntry ("Something is horrible wrong, there are {} entries with Tag ID of {}".format(len(lstReturn[1]),iTagID))
    CleanExit("due to unexpected SQL return, please check the logs")
  lstReturn = SQLQuery (strSQL,dbConn)
  if not ValidReturn(lstReturn):
    LogEntry ("Unexpected: {}".format(lstReturn))
    LogEntry (strSQL)
    CleanExit("due to unexpected SQL return, please check the logs")
  elif lstReturn[0] != 1:
    LogEntry ("Records affected {}, expected 1 record affected".format(lstReturn[0]))

  LogEntry("Processing tag elements")
  x=1
  for strElement in lstParts:
    if len(strElement)>400:
      LogEntry("Element is longer than 400 characters, truncating")
      strElement = strElement[:400]
    if "-" in strElement:
      strElementParts = strElement.split("-")
      iBitMask = ValidMask(strElementParts[1])
      if iBitMask > 0:
        strSubnet = strElementParts[0]+"/"+str(iBitMask)
        dictIPAddress = IPCalc(strSubnet)
        strIPStart = dictIPAddress["Subnet"]
        strIPEnd = dictIPAddress["Broadcast"]
        iIPStart = dictIPAddress["iDecSubID"]
        iIPEnd = dictIPAddress["iDecBroad"]
      else:
        strIPStart = strElementParts[0]
        strIPEnd = strElementParts[1]
        iIPStart = DotDec2Int(strIPStart)
        iIPEnd = DotDec2Int(strIPEnd)
        strSubnet = strElement
    else:
      dictIPAddress = IPCalc(strElement)
      strIPStart = dictIPAddress["Subnet"]
      strIPEnd = dictIPAddress["Broadcast"]
      iIPStart = dictIPAddress["iDecSubID"]
      iIPEnd = dictIPAddress["iDecBroad"]
      strSubnet = dictIPAddress["IPAddr"] + "/" + dictIPAddress["BitMask"]

    strSQL = ("INSERT INTO tblRule_Element (iTagID, vcElement,vcSubnet,vcStartIP,vcEndIP,iStartIP,iEndIP) "
      " VALUES ({},'{}','{}','{}','{}',{},{});".format(iTagID,DBClean(strElement),strSubnet,strIPStart,strIPEnd,iIPStart,iIPEnd))
    lstReturn = SQLQuery (strSQL,dbConn)
    if not ValidReturn(lstReturn):
      LogEntry ("Unexpected: {}".format(lstReturn))
      LogEntry (strSQL)
    elif lstReturn[0] != 1:
      LogEntry ("Records affected {}, expected 1 record affected".format(lstReturn[0]))
    print ("imported {} records...".format(x),end="\r")
    x+=1
  print("\n...Next...")

def ProcessResponse(APIResponse):
  global iUpdateCount
  if isinstance(APIResponse,str):
    LogEntry(APIResponse)
  if isinstance(APIResponse,dict):
    if "ServiceResponse" in APIResponse:
      if "count" in APIResponse["ServiceResponse"]:
        if isInt(APIResponse["ServiceResponse"]["count"]):
          iCount = int(APIResponse["ServiceResponse"]["count"])
        else:
          iCount = -10
      else:
        iCount = -10
      if "data" in APIResponse["ServiceResponse"]:
        if isinstance(APIResponse["ServiceResponse"]["data"],list):
          if iCount != len(APIResponse["ServiceResponse"]["data"]):
            LogEntry("Count is {} but len is {}".format(iCount,len(APIResponse["ServiceResponse"]["data"])))
          lstTemp = APIResponse["ServiceResponse"]["data"]
        else:
          if iCount != 1:
            LogEntry("Count is {} but there is only one entry".format(iCount))
          lstTemp = [APIResponse["ServiceResponse"]["data"]]
        for dictTemp in lstTemp:
          if "Tag" in dictTemp:
            if "id" in dictTemp["Tag"]:
              if iCount < 0:
                LogEntry("No count attribute, or count attribute not numeric for ID {}".format(dictTemp["Tag"]["id"]))
              elif iCount == 0:
                LogEntry("count attribute = 0 for ID {}".format(dictTemp["Tag"]["id"]))
              elif iCount > 1:
                LogEntry("count attribute = {} for ID {}".format(iCount, dictTemp["Tag"]["id"]))
            else:
              LogEntry("Tag ID missing in APIResponse: {}".format(APIResponse))
            UpdateDB (dictTemp["Tag"])
          else:
            LogEntry("No Tag in APIResponse: {}".format(APIResponse))
      else:
        LogEntry("No data in APIResponse: {}".format(APIResponse))
    else:
      LogEntry ("There are no results")
  iUpdateCount += 1

dbConn = ""
processConf()
dbConn = SQLConn (strServer,strDBUser,strDBPWD,strInitialDB)
strSQL = ("select dtStartTime from tblScriptExecuteList where iExecuteID = "
    " (select max(iExecuteID) from tblScriptExecuteList where vcScriptName = '{}')").format(strScriptName)
lstReturn = SQLQuery (strSQL,dbConn)
if not ValidReturn(lstReturn):
  LogEntry ("Unexpected: {}".format(lstReturn))
  CleanExit("due to unexpected SQL return, please check the logs")
elif len(lstReturn[1]) != 1:
  LogEntry ("Looking for last execution date, fetched {} rows, expected 1 record affected".format(len(lstReturn[1])))
  dtLastExecute = -10
else:
  dtLastExecute = lstReturn[1][0][0].date()

if strDBType == "mysql":
  strSQL = ("select TIMESTAMPDIFF(MINUTE,max(dtTimestamp),now()) as timediff "
              " from tblLogs where vcLogEntry not like '%last execution date%' and vcScriptName = '{}';".format(strScriptName))
elif strDBType == "mssql":
  strSQL = ("select datediff(MINUTE,max(dtTimestamp),GETDATE()) as timediff "
              " from tblLogs where vcLogEntry not like '%last execution date%' and vcScriptName = '{}';".format(strScriptName))
else:
  LogEntry ("Unknown database type {}".format(strDBType),True)

lstReturn = SQLQuery (strSQL,dbConn)
if not ValidReturn(lstReturn):
  LogEntry ("Unexpected: {}".format(lstReturn))
  CleanExit("due to unexpected SQL return, please check the logs")
elif len(lstReturn[1]) != 1:
  LogEntry ("While looking for quiet time fetched {}, rows expected 1 record affected".format(len(lstReturn[1])))
  iQuietMin = iMinQuietTime
else:
  if isInt(lstReturn[1][0][0]):
    iQuietMin = int(lstReturn[1][0][0])
  else:
    LogEntry ("This is the first time this script is run in this environment, "
      " setting last scan time to {} minutes to work around quiet time logic".format(iMinQuietTime))
    iQuietMin = iMinQuietTime

if iQuietMin < iMinQuietTime :
  dbConn = ""
  LogEntry ("Either the script is already running or it's been less that {0} min since it last run, please wait until after {0} since last run. Exiting".format(iMinQuietTime))
  sys.exit()
else:
  LogEntry("{} Database connection established. It's been {} minutes since last log entry.".format(strDBType, iQuietMin))

LogEntry("Starting Processing. Script {} running under Python version {}".format(strRealPath,strVersion))

lstChildren = []
if os.path.isfile(strChild_File):
  LogEntry ("Child file exists, loading in the content")
  objChildFile = open(strChild_File,"r",1)
  strLines = objChildFile.readlines()
  objChildFile.close()
  for strline in strLines:
    lstChildren.append(strline)
  objChildFile = open(strChild_File,"a")
else:
  LogEntry ("Child file does not exists, creating it")
  objChildFile = open(strChild_File,"w")

strdbNow = time.strftime("%Y-%m-%d %H:%M:%S")
strSQL = ("INSERT INTO tblScriptExecuteList (vcScriptName,dtStartTime,iGMTOffset) "
          " VALUES('{}','{}',{});".format(strScriptName,strdbNow,iGMTOffset))
lstReturn = SQLQuery (strSQL,dbConn)
if not ValidReturn(lstReturn):
  LogEntry ("Unexpected: {}".format(lstReturn))
  CleanExit("due to unexpected SQL return, please check the logs")
elif lstReturn[0] != 1:
  LogEntry ("Records affected {}, expected 1 record affected".format(lstReturn[0]))

strSQL = ("select iExecuteID,dtStartTime from tblScriptExecuteList where iExecuteID in "
  " (select max(iExecuteID) from tblScriptExecuteList where vcScriptName = '{}');".format(strScriptName))
lstReturn = SQLQuery (strSQL,dbConn)
if not ValidReturn(lstReturn):
  LogEntry ("Unexpected: {}".format(lstReturn))
  CleanExit("due to unexpected SQL return, please check the logs")
elif len(lstReturn[1]) != 1:
  LogEntry ("Records affected {}, expected 1 record affected".format(len(lstReturn[1])))
  iEntryID = -10
  dtStartTime = strdbNow
else:
  iEntryID = lstReturn[1][0][0]
  dtStartTime = lstReturn[1][0][1]

LogEntry("Recorded start entry, ID {}".format(iEntryID))

if strLoadType.lower() == "full":
  LogEntry("Per configuration file doing a full load")
  strSQL = "select distinct iTagID from tblTags;"
elif strLoadType.lower() == "test" :
  LogEntry("Per configuration file doing a test load focusing on Tag {}".format(iTagID))
  strSQL = "select distinct iTagID from tblTags where iTagID = {};".format(iTagID)
elif strLoadType.lower() == "last" :
  LogEntry("Per configuration file updating all recoreds not updated since {}".format(dtLastExecute))
  strSQL = "select iTagID from tblTags where dtLastAPIUpdate < '{}';".format(dtLastExecute)
else:
  LogEntry("Per configuration file doing an incremental load")
  strSQL = "select distinct iTagID from tblTags where tRuleText is NULL;"

LogEntry ("Fetching list of Tag's from the database")
lstTags = SQLQuery (strSQL,dbConn)
if not ValidReturn(lstTags):
  LogEntry ("Unexpected: {}".format(lstTags))
  CleanExit("due to unexpected SQL return, please check the logs")
else:
  LogEntry ("Fetched {} rows".format(len(lstTags[1])))

iTotalRows = lstTags[0]
iRowNum = 1
iUpdateCount = 0

LogEntry ("Configuration file specifies format of {}".format(strFormat))
strMethod = "get"
if strFormat == "json":
  dictHeader["Content-Type"] = "application/json"
  dictHeader["Accept"] = "application/json"

for dbRow in lstTags[1]:
  strAPIFunction = "qps/rest/2.0/get/am/tag/" + str(dbRow[0])
  LogEntry("\n--------------\nWorking on Tag: {} record {} out of {}. {:.1%} complete. Childcount at: {}".format(dbRow[0],iRowNum,iTotalRows,(iRowNum-1)/iTotalRows,len(lstChildren)))
  strURL = strBaseURL + strAPIFunction
  APIResponse = MakeAPICall(strURL,dictHeader,strUserName,strPWD,strMethod)
  strdbNow = time.strftime("%Y-%m-%d %H:%M:%S")
  strSQL = ("update tblScriptExecuteList set dtStopTime='{}', bComplete=0, iRowsUpdated={} "
              " where iExecuteID = {} ;".format(strdbNow,iUpdateCount,iEntryID))
  lstReturn = SQLQuery (strSQL,dbConn)
  if not ValidReturn(lstReturn):
    LogEntry ("Unexpected: {}".format(lstReturn))
  elif lstReturn[0] != 1:
    LogEntry ("Records affected {}, expected 1 record affected".format(lstReturn[0]))
  ProcessResponse(APIResponse)
  iRowNum += 1

LogEntry("Finished first round, no fetching childrens")
iRowNum = 1
for iChildID in lstChildren:
  iTotalRows = len(lstChildren)
  strAPIFunction = "qps/rest/2.0/get/am/tag/" + str(iChildID)
  LogEntry("\n--------------\nWorking on Tag: {} record {} out of {}. {:.1%} complete".format(iChildID,iRowNum,iTotalRows,(iRowNum-1)/iTotalRows))
  strURL = strBaseURL + strAPIFunction
  APIResponse = MakeAPICall(strURL,dictHeader,strUserName,strPWD,strMethod)
  strdbNow = time.strftime("%Y-%m-%d %H:%M:%S")
  strSQL = ("update tblScriptExecuteList set dtStopTime='{}', bComplete=0, iRowsUpdated={} "
              " where iExecuteID = {} ;".format(strdbNow,iUpdateCount,iEntryID))
  lstReturn = SQLQuery (strSQL,dbConn)
  if not ValidReturn(lstReturn):
    LogEntry ("Unexpected: {}".format(lstReturn))
  elif lstReturn[0] != 1:
    LogEntry ("Records affected {}, expected 1 record affected".format(lstReturn[0]))
  ProcessResponse(APIResponse)
  iRowNum += 1

objChildFile.close()
os.remove(strChild_File)

LogEntry ("Doing validation checks")
strSQL = "select count(*) from tblTags where dtLastAPIUpdate > '{}';".format(dtStartTime)
lstReturn = SQLQuery (strSQL,dbConn)
if not ValidReturn(lstReturn):
  LogEntry ("Unexpected: {}".format(lstReturn))
  CleanExit("due to unexpected SQL return, please check the logs")
elif len(lstReturn[1]) != 1:
  LogEntry ("Records affected {}, expected 1 record affected".format(len(lstReturn[1])))
else:
  iCountTagChanged = lstReturn[1][0][0]

LogEntry ("VALIDATE: Total Number of vulnerabitlities downloaded {}; Total number of vulnerabitlities updated in the database {}".format(iUpdateCount,iCountTagChanged))
if iUpdateCount != iCountTagChanged:
  LogEntry ("VALIDATE: Host validation failed")
  SendNotification("{} has completed processing on {}, and validation checks failed".format(strScriptName,strScriptHost))
else:
  LogEntry ("VALIDATE: Host validation successful")
  SendNotification("{} has completed processing on {}, validation checks are good. Processed {} vulnerabitlities.".format(strScriptName,strScriptHost,iUpdateCount))

strdbNow = time.strftime("%Y-%m-%d %H:%M:%S")
LogEntry("Updating completion entry")
strSQL = ("update tblScriptExecuteList set dtStopTime='{}' , bComplete=1, "
        " iRowsUpdated={} where iExecuteID = {} ;".format(strdbNow,iUpdateCount,iEntryID))
lstReturn = SQLQuery (strSQL,dbConn)
if not ValidReturn(lstReturn):
  LogEntry ("Unexpected: {}".format(lstReturn))
elif lstReturn[0] != 1:
  LogEntry ("Records affected {}, expected 1 record affected".format(lstReturn[0]))
LogEntry ("All Done!")
dbConn.close()
objLogOut.close()

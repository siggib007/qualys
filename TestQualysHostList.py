'''
Script to pull all Host Detection data from Qualys
Version 2
Author Siggi Bjarnason Copyright 2017
Website http://www.ipcalc.us/ and http://www.icecomputing.com

Following packages need to be installed as administrator
pip install requests
pip install xmltodict
pip install pymysql
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
dictPayload = {}
dictHeader["Content-Type"] = "application/json"
dictHeader["Accept"] = "application/json"
ISO = time.strftime("-%Y-%m-%d-%H-%M-%S")
iLoc = sys.argv[0].rfind(".")
strConf_File = sys.argv[0][:iLoc] + ".ini"
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

print ("This is a script to gather all asset host detections from Qualys via API. This is running under Python Version {}".format(strVersion))
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
  if dbConn != "":
    strdbNow = time.strftime("%Y-%m-%d %H:%M:%S")
    strSQL = ("update tblScriptExecuteList set dtStopTime='{}', bComplete=0, "
      " iRowsUpdated={} where iExecuteID = {} ;".format(strdbNow, iTotalCount,iEntryID))
    lstReturn = SQLQuery (strSQL,dbConn)
    dbConn.close()
  SendNotification("{} is exiting abnormally on {} {}".format(strScriptName,strScriptHost, strCause))
  objLogOut.close()
  objFileOut.close()
  sys.exit(9)

def LogEntry(strMsg,bAbort=False):
  strTemp = ""
  strDBMsg = DBClean(strMsg[:9990])
  if dbConn !="":
    strSQL = "INSERT INTO tblLogs (vcScriptName, vcLogEntry) VALUES ('{}','{}');".format(strScriptName,strDBMsg)
    lstReturn = SQLQuery (strSQL,dbConn)
    if not ValidReturn(lstReturn):
      strTemp = ("   Unexpected issue inserting log entry to the database: {}\n{}".format(lstReturn,strSQL))
    elif lstReturn[0] != 1:
      strTemp = ("   Records affected {}, expected 1 record affected when inserting log entry to the database".format(lstReturn[0]))
  else:
    strTemp = ". Database connection not established yet"

  # strMsg += strTemp
  strTimeStamp = time.strftime("%m-%d-%Y %H:%M:%S")
  objLogOut.write("{0} : {1}\n".format(strTimeStamp,strMsg))
  print (strMsg)
  if bAbort:
    SendNotification("{} on {}: {}".format (strScriptName,strScriptHost,strMsg[:99]))
    CleanExit("")

def processConf():
  global strBaseURL
  global strHeader
  global strUserName
  global strPWD
  global strServer
  global strDBUser
  global strDBPWD
  global strInitialDB
  global iMinQuietTime
  global strLoadType
  global dtFullLoad
  global strNotifyURL
  global strNotifyToken
  global strNotifyChannel
  global strDBType
  global strOutFile
  global strSNOWUser
  global strSNOWPWD

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
    iCommentLoc = strLine.find("###")
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
        strHeader={'X-Requested-With': strValue}
      if strVarName == "QUserID":
        strUserName = strValue
      if strVarName == "QUserPWD":
        strPWD = strValue
      if strVarName == "SNUserID":
        strSNOWUser = strValue
      if strVarName == "SNUserPWD":
        strSNOWPWD = strValue
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
      if strVarName == "FullFromDate":
        dtFullLoad = strValue
      if strVarName == "NotificationURL":
        strNotifyURL = strValue
      if strVarName == "NotifyChannel":
        strNotifyChannel = strValue
      if strVarName == "NotifyToken":
        strNotifyToken = strValue
      if strVarName == "DBType":
        strDBType  = strValue
      if strVarName == "OutFile":
        strOutFile  = strValue

  if strBaseURL[-1:] != "/":
    strBaseURL += "/"

  LogEntry ("Done processing configuration, moving on")

def MakeAPICall (strURL, strHeader, strUserName,strPWD, strMethod, dictPayload=""):

  iErrCode = ""
  iErrText = ""
  dictResponse = {}

  LogEntry ("Doing a {} to URL: \n {}\n".format(strMethod,strURL))
  try:
    if strMethod.lower() == "get":
      WebRequest = requests.get(strURL, headers=strHeader, auth=(strUserName, strPWD))
      LogEntry ("get executed")
    if strMethod.lower() == "post":
      if dictPayload != {}:
        WebRequest = requests.post(strURL, json=dictPayload, headers=dictHeader, auth=(strUserName, strPWD))
        print ("payload post executed")
      else:
        WebRequest = requests.post(strURL, headers=dictHeader, auth=(strUserName, strPWD))
        print ("no payload post executed")
  except Exception as err:
    LogEntry ("Issue with API call. {}".format(err))
    CleanExit("due to issue with API, please check the logs")

  if isinstance(WebRequest,requests.models.Response)==False:
    LogEntry ("response is unknown type")
    iErrCode = "ResponseErr"
    iErrText = "response is unknown type"

  LogEntry ("call resulted in status code {}".format(WebRequest.status_code))

  if WebRequest.text[:5] == "<?xml":
    strType = "xml"
  elif WebRequest.text[:1] == "[" or WebRequest.text[:1] == "{" :
    strType = "json"
  else:
    strType = "unknown"
  # print ("Type: {}\nFirstFive:!{}!".format(strType,WebRequest.text[:5]))
  if strType.lower() == "xml":
    try:
      dictResponse = xmltodict.parse(WebRequest.text)
    except xml.parsers.expat.ExpatError as err:
      # LogEntry("Expat Error: {}\n{}".format(err,WebRequest.text))
      iErrCode = "Expat Error"
      iErrText = "Expat Error: {}\n{}".format(err,WebRequest.text)
    except Exception as err:
      LogEntry("Unkown xmltodict exception: {}".format(err))
      CleanExit(", Unkown xmltodict exception, please check the logs")
  elif strType == "json" :
    dictResponse = json.loads(WebRequest.text)
    LogEntry ("json loaded into dictionary")
  else:
    dictResponse = {}
    dictResponse["error"]="Unreconized response"
    dictResponse["response"] = WebRequest.text
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
    if "result" in dictResponse:
      if "error_message" in dictResponse["result"]:
        iErrCode = "json error"
        iErrText = dictResponse["result"]["error_message"]
    if "error" in dictResponse:
      iErrCode = "problem"
      iErrText = dictResponse["error"]
  else:
    LogEntry ("Response not a dictionary",True)

  if iErrCode != "" or WebRequest.status_code !=200:
    return "There was a problem with your request. HTTP error {} code {} {}".format(WebRequest.status_code,iErrCode,iErrText)
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

def DotDec2Int (strValue):
  strHex = ""
  if ValidateIP(strValue) == False:
    return "NULL"
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

def DBClean(strText):
  strTemp = strText.encode("ascii","ignore")
  strTemp = strTemp.decode("ascii","ignore")
  strTemp = strTemp.replace("\\","\\\\")
  strTemp = strTemp.replace("'","\"")
  return strTemp

def QDate2DB(strDate):
  strTemp = strDate.replace("T"," ")
  return strTemp.replace("Z","")

def UpdateDB (dictResults):
  global iTotalTagCount

  if "DNS" in dictResults:
    strHostName = DBClean(dictResults["DNS"])
  else:
    strHostName = "Unknown"

  if "OS" in dictResults:
    strOS = DBClean(dictResults["OS"])
  else:
    strOS = "Unknown"

  if "LAST_VM_SCANNED_DATE" in dictResults:
    dtLastVMSCan = "'" + QDate2DB(dictResults["LAST_VM_SCANNED_DATE"]) + "'"
  else:
    dtLastVMSCan = "NULL"

  if "LAST_VM_SCANNED_DURATION" in dictResults:
    iVMScanDuration = "'" + DBClean(dictResults["LAST_VM_SCANNED_DURATION"]) + "'"
  else:
    iVMScanDuration = "NULL"

  if "TRACKING_METHOD" in dictResults:
    # strTracking = "'" + DBClean(dictResults["TRACKING_METHOD"]) + "'"
    strTracking = DBClean(dictResults["TRACKING_METHOD"])
  else:
    strTracking = "NULL"

  if "NETBIOS" in dictResults:
    strNetBIOS = DBClean(dictResults["NETBIOS"])
  else:
    strNetBIOS = "NULL"

  if "IP" in dictResults:
    strIPaddr = DBClean(dictResults["IP"])
    iIPaddr = DotDec2Int(strIPaddr)
    # strIPaddr = "'" + strIPaddr + "'"
    strIPaddr = strIPaddr
  else:
    strIPaddr = "NULL"
    iIPaddr = "NULL"

  if "LAST_VM_AUTH_SCANNED_DATE" in dictResults:
    dtVMAuth = "'" + QDate2DB(dictResults["LAST_VM_AUTH_SCANNED_DATE"]) + "'"
  else:
    dtVMAuth = "NULL"

  if "LAST_VULN_SCAN_DATETIME" in dictResults:
    dtScan = "'" + QDate2DB(dictResults["LAST_VULN_SCAN_DATETIME"]) + "'"
  else:
    dtScan = "NULL"

  if "LAST_VM_AUTH_SCANNED_DURATION" in dictResults:
    if isInt(dictResults["LAST_VM_AUTH_SCANNED_DURATION"]):
      iAuthDuration = int(dictResults["LAST_VM_AUTH_SCANNED_DURATION"])
    else:
      iAuthDuration = "NULL"
  else:
    iAuthDuration = "NULL"

  if "EC2_INSTANCE_ID" in dictResults:
    strECID =  "'" + DBClean(dictResults["EC2_INSTANCE_ID"]) + "'"
  else:
    strECID = "NULL"

  if "QG_HOSTID" in dictResults:
    strQGID = "'" + DBClean(dictResults["QG_HOSTID"]) + "'"
  else:
    strQGID = "NULL"

  strSNSName = "n/a"
  strSNsClass = "n/a"
  strBizName = "n/a"
  strOwner = "n/a"
  strURL = "https://tmusworker.service-now.com/api/tmus2/t_cmdb/get_server_service_from_ip"
  strMethod = "post"
  dictPayload["ip_address"] = strIPaddr
  APIResponse = MakeAPICall(strURL,dictHeader,strSNOWUser,strSNOWPWD,strMethod,dictPayload)
  if isinstance(APIResponse,str):
    LogEntry(APIResponse)
  if isinstance(APIResponse,dict):
    if "result" in APIResponse:
      if "server" in APIResponse["result"]:
        if "name" in APIResponse["result"]["server"]:
          strSNSName = APIResponse["result"]["server"]["name"]
        if "name" in APIResponse["result"]["server"]:
          strSNsClass = APIResponse["result"]["server"]["sys_class"]
    if "business_service" in APIResponse["result"]:
      if "name" in APIResponse["result"]["business_service"]:
        strBizName = APIResponse["result"]["business_service"]["name"]
      if "owned_by" in APIResponse["result"]["business_service"]:
        strOwner = APIResponse["result"]["business_service"]["owned_by"]

  # print (APIResponse)
  objFileOut.write ("{},{},{},{},{},{},{},{},{}\n".format(strHostName,strOS,strNetBIOS,strIPaddr,strTracking,strSNSName,strSNsClass,strBizName,strOwner))

  return "Done"
  strdbNow = time.strftime("%Y-%m-%d %H:%M:%S")
  strSQL = "select * from tblhostlist where iHostID = {};".format(dictResults["ID"])
  lstReturn = SQLQuery (strSQL,dbConn)
  if not ValidReturn(lstReturn):
    LogEntry ("Unexpected: {}".format(lstReturn))
    CleanExit("due to unexpected SQL return, please check the logs")
    return lstReturn
  elif lstReturn[0] == 0:
    LogEntry ("Adding ID {} {}".format(dictResults["ID"],strHostName))
    strSQL = ("INSERT INTO tblhostlist (iHostID,vcIPAddr,vcOperatingSystem,vcHostName,dtLastScan,dtVMScanned,"
          "iLastScanDuration,vcTrackingMethod,vcNetBIOS,dtVMAuthScanned,iVMAuthDuration,vcEC_ID,"
          "vcQGid,dtLastAPIUpdate,iIPAddress) "
          "VALUES({},{},'{}','{}',{},{},{},{},{},{},{},{},{},'{}',{});".format(
            dictResults["ID"],strIPaddr,strOS,strHostName,dtScan,
            dtLastVMSCan,iVMScanDuration,strTracking,strNetBIOS,dtVMAuth,iAuthDuration,strECID,
            strQGID,strdbNow,iIPaddr)
          )
  elif lstReturn[0] == 1:
    LogEntry ("ID {} exists, need to update record for {}".format(dictResults["ID"],strHostName))
    strSQL = ("UPDATE tblhostlist SET vcIPAddr = {},vcOperatingSystem = '{}',vcHostName = '{}',dtLastScan = {},"
          "dtVMScanned = {},iLastScanDuration = {},vcTrackingMethod = {},vcNetBIOS = {},"
          "dtVMAuthScanned = {},iVMAuthDuration = {},vcEC_ID = {},vcQGid = {},"
          "dtLastAPIUpdate = '{}', iIPAddress = {} WHERE iHostID = {};".format(strIPaddr,strOS,strHostName,
            dtScan,dtLastVMSCan,iVMScanDuration,strTracking,
            strNetBIOS,dtVMAuth,iAuthDuration,strECID,strQGID,strdbNow,iIPaddr,dictResults["ID"]
            )
        )
  else:
    LogEntry ("Something is horrible wrong, there are {} entries with ID of {}".format(lstReturn[0],dictResults["ID"]))
    return "Abort!!!"
  lstReturn = SQLQuery (strSQL,dbConn)
  if not ValidReturn(lstReturn):
    LogEntry ("Unexpected: {}".format(lstReturn))
    LogEntry (strSQL)
    CleanExit("due to unexpected SQL return, please check the logs")
  elif lstReturn[0] > 1:
    LogEntry ("Records affected {}, expected 1 record affected".format(lstReturn[0]))
  lstTemp = []

  if "TAGS" in dictResults:
    if isinstance(dictResults["TAGS"],dict):
      if "TAG" in dictResults["TAGS"]:
        if isinstance(dictResults["TAGS"]["TAG"],list):
          lstTemp = dictResults["TAGS"]["TAG"]
        else:
          lstTemp = [dictResults["TAGS"]["TAG"]]
        LogEntry("There are {} Asset Tags.".format(len(lstTemp)))
      else:
        LogEntry("No TAG inside TAGS collection, weird")
    else:
      LogEntry("TAGS collection not a dictionary")
  else:
    LogEntry("No Asset Tags")

  if len(lstTemp) > 0:
    strSQL = "delete from tblHost2Tag where iHostID = {};".format(dictResults["ID"])
    lstReturn = SQLQuery (strSQL,dbConn)
    if not ValidReturn(lstReturn):
      LogEntry ("Unexpected: {}".format(lstReturn))
      CleanExit("due to unexpected SQL return, please check the logs")
    else:
      LogEntry ("Deleted {} tag to host mappings for host ID {} ".format(lstReturn[0],dictResults["ID"]))

  iTotalTagCount += len(lstTemp)
  for dictTags in lstTemp:
    if "TAG_ID" in dictTags:
      strTagID = dictTags["TAG_ID"]
    else:
      strTagID = ""
    if "NAME" in dictTags:
      strTagName = DBClean(dictTags["NAME"])
    else:
      strTagName = ""
    if strTagID != "" and strTagName != "" and isInt(strTagID):
      iTagID = int(strTagID)
      strSQL = "select * from tblTags where iTagID = {}".format(iTagID)
      lstReturn = SQLQuery (strSQL,dbConn)
      if not ValidReturn(lstReturn):
        LogEntry ("Unexpected: {}".format(lstReturn))
        LogEntry (strSQL)
        CleanExit("due to unexpected SQL return, please check the logs")
      elif lstReturn[0]==0:
        LogEntry ("Tag ID {} doesn't exists, inserting it".format(iTagID))
        strSQL = "INSERT INTO tblTags (iTagID,vcTagName) VALUES ({}, '{}');".format(iTagID,strTagName)
        lstReturn = SQLQuery (strSQL,dbConn)
        if not ValidReturn(lstReturn):
          LogEntry ("Unexpected: {}".format(lstReturn))
          CleanExit("due to unexpected SQL return, please check the logs")
      # else:
        # LogEntry("Tag ID {} already exists, found {} records, don't need to create it".format(iTagID,lstReturn[0]))

      strSQL = "INSERT INTO tblHost2Tag (iHostID,iTagID) VALUES ({},{});".format(dictResults["ID"],iTagID)
      lstReturn = SQLQuery (strSQL,dbConn)
      if not ValidReturn(lstReturn):
        LogEntry ("Unexpected: {}".format(lstReturn))
        CleanExit("due to unexpected SQL return, please check the logs")
    else:
      LogEntry("either TagID or Tag Name is missing or invalid, here is what I have: {}".format(dictTags))

# End Update DB

dbConn = ""
processConf()
# dbConn = SQLConn (strServer,strDBUser,strDBPWD,strInitialDB)
# strSQL = ("select dtStartTime from tblScriptExecuteList where iExecuteID = "
#     " (select max(iExecuteID) from tblScriptExecuteList where vcScriptName = '{}')").format(strScriptName)
# lstReturn = SQLQuery (strSQL,dbConn)
# if not ValidReturn(lstReturn):
#   LogEntry ("Unexpected: {}".format(lstReturn))
#   CleanExit("due to unexpected SQL return, please check the logs")
# else:
#   if len(lstReturn[1]) > 0:
#     dtLastExecute = lstReturn[1][0][0].date()
#   else:
#     LogEntry ("Looks like this is the first time the script is run in this environment, starting from scratch")
#     dtLastExecute = dtFullLoad

# if strDBType == "mysql":
#   strSQL = ("select TIMESTAMPDIFF(MINUTE,max(dtTimestamp),now()) as timediff "
#               " from tblLogs where vcScriptName = '{}';".format(strScriptName))
# elif strDBType == "mssql":
#   strSQL = ("select datediff(MINUTE,max(dtTimestamp),GETDATE()) as timediff "
#               " from tblLogs where vcScriptName = '{}';".format(strScriptName))
# else:
#   LogEntry ("Unknown database type {}".format(strDBType),True)
# lstReturn = SQLQuery (strSQL,dbConn)
# if not ValidReturn(lstReturn):
#   LogEntry ("Unexpected: {}".format(lstReturn))
#   CleanExit("due to unexpected SQL return, please check the logs")
# elif lstReturn[0] == 0:
#   iQuietMin = -15
# elif lstReturn[0] > 1:
#   iQuietMin = lstReturn[0] * -15
# else:
#   if isInt(lstReturn[1][0][0]):
#     iQuietMin = int(lstReturn[1][0][0])
#   else:
#     iQuietMin = -15

# strSQL = "select vcLogEntry from tblLogs where ILogID = (select max(ILogID) from tblLogs where vcScriptName = '{}');".format(strScriptName)
# lstReturn = SQLQuery (strSQL,dbConn)
# if not ValidReturn(lstReturn):
#   LogEntry ("Unexpected: {}".format(lstReturn))
#   CleanExit("due to unexpected SQL return, please check the logs")
# else:
#   strLastEntry = lstReturn[1][0][0]

# if iQuietMin == -15:
#   LogEntry ("This is the first time this script is run in this environment, setting last scan time to {} "
#               "minutes to work around quiet time logic".format(iMinQuietTime))
#   iQuietMin = iMinQuietTime
# elif iQuietMin < -15:
#   LogEntry ("There were {} records returned when querying for last execute, this should not happen. Since I can't "
#             "deterministicly figure out this out, setting last scan time {} minutes to work "
#             "around quiet time logic".format(iQuietMin * -1, iMinQuietTime))
#   iQuietMin = iMinQuietTime


# if iQuietMin < iMinQuietTime :
#   dbConn.close()
#   dbConn = ""
#   LogEntry ("Last Log update {1} min ago. Either the script is already running or it's been less that {0} min since it last run, "
#         "please wait until after {0} since last run. Exiting".format(iMinQuietTime,iQuietMin ))
#   objLogOut.close()
#   sys.exit()
# else:
#   LogEntry("Connection to a {} database established. It's been {} minutes since last log entry.".format(strDBType, iQuietMin))


LogEntry("Starting Processing. Script {} running under Python version {}".format(strRealPath,strVersion))

# strdbNow = time.strftime("%Y-%m-%d %H:%M:%S")
# strSQL = ("INSERT INTO tblScriptExecuteList (vcScriptName,dtStartTime,iGMTOffset) "
#           " VALUES('{}','{}',{});".format(strScriptName,strdbNow,iGMTOffset))
# lstReturn = SQLQuery (strSQL,dbConn)
# if not ValidReturn(lstReturn):
#   LogEntry ("Unexpected: {}".format(lstReturn))
#   CleanExit("due to unexpected SQL return, please check the logs")
# elif lstReturn[0] != 1:
#   LogEntry ("Records affected {}, expected 1 record affected".format(lstReturn[0]))

# strSQL = ("select iExecuteID,dtStartTime from tblScriptExecuteList where iExecuteID in "
#   " (select max(iExecuteID) from tblScriptExecuteList where vcScriptName = '{}');".format(strScriptName))
# lstReturn = SQLQuery (strSQL,dbConn)
# if not ValidReturn(lstReturn):
#   LogEntry ("Unexpected: {}".format(lstReturn))
#   CleanExit("due to unexpected SQL return, please check the logs")
# else:
#   iEntryID = lstReturn[1][0][0]
#   dtStartTime = lstReturn[1][0][1]

# LogEntry("Recorded start entry, ID {} at {}".format(iEntryID,dtStartTime))

if strLoadType.lower() == "full":
  dtLastExecute = dtFullLoad
  LogEntry("Doing a Full Load per directive from configuration file, going back to {}".format(dtFullLoad))
else:
  # LogEntry("Configuration file indicates incementatal load, finding last execution date")
  # LogEntry ("starting from {}".format(dtLastExecute))
  LogEntry ("Since this is a test script I'm doing a full load regardless")
  dtLastExecute = dtFullLoad

strAPIFunction = "/api/2.0/fo/asset/host/"
if strAPIFunction[0] == "/":
  strAPIFunction = strAPIFunction[1:]

if strAPIFunction[-1:] != "/":
  strAPIFunction += "/"

objFileOut = open(strOutFile,"w")
objFileOut.write ("Host Name,OS,NetBIOS Name,IP address,Tracking Method,SNOW Name,SNOW Class,EAL,Owner\n")

LogEntry ("API Function: {}".format(strAPIFunction))

strMethod = "get"
dictParams = {}
dictParams["action"] = "list"
dictParams["id_min"] = 0
# dictParams["ids"] = "13474944"
dictParams["vm_scan_since"]=dtLastExecute
# dictParams["details"]="All/AGs"
# dictParams["show_tags"]=1
dictPayload = {}

strListScans = urlparse.urlencode(dictParams)
bMoreData = True
iTotalCount = 0
iTotalTagCount = 0

# if strLastEntry != "All Done!":
#   LogEntry ("Either this is the first time this script is being run or it ended abnormally last time.")
#   strSQL = ("select vcLogEntry from tblLogs where ILogID = (select max(ILogID) from tblLogs where vcLogEntry like "
#             " '%Next URL%'and vcScriptName = '{}');").format(strScriptName)
#   lstReturn = SQLQuery (strSQL,dbConn)
#   if not ValidReturn(lstReturn):
#     LogEntry ("Unexpected: {}".format(lstReturn))
#     CleanExit("due to unexpected SQL return, please check the logs")
#   else:
#     if len(lstReturn[1]) > 0:
#       LogEntry ("confirmed last job ended abnormally, found were it left off and starting from there.")
#       strURL = lstReturn[1][0][0][10:]
#     else:
#       LogEntry ("confirmed this is the first time, starting from scratch")
#       strURL = strBaseURL + strAPIFunction +"?" + strListScans
# else:
#   LogEntry ("Confirmed last job exited normally, starting from scratch")
#   strURL = strBaseURL + strAPIFunction +"?" + strListScans

strURL = strBaseURL + strAPIFunction +"?" + strListScans
LogEntry ("Next URL: {}".format(strURL))
APIResponse = MakeAPICall(strURL,strHeader,strUserName,strPWD,strMethod)


while bMoreData:
  # strdbNow = time.strftime("%Y-%m-%d %H:%M:%S")
  # strSQL = ("update tblScriptExecuteList set dtStopTime='{}', bComplete=0, "
  #   " iRowsUpdated={} where iExecuteID = {} ;".format(strdbNow, iTotalCount,iEntryID))
  # lstReturn = SQLQuery (strSQL,dbConn)
  # if not ValidReturn(lstReturn):
  #   LogEntry ("Unexpected: {}".format(lstReturn))
  #   CleanExit("due to unexpected SQL return, please check the logs")
  # elif lstReturn[0] != 1:
  #   LogEntry ("Records affected {}, expected 1 record affected".format(lstReturn[0]))
  if isinstance (APIResponse,str):
    LogEntry (APIResponse)
    bMoreData = False
  if isinstance(APIResponse,dict):
    if "HOST_LIST" in APIResponse["HOST_LIST_OUTPUT"]["RESPONSE"]:
      if "HOST" in APIResponse["HOST_LIST_OUTPUT"]["RESPONSE"]["HOST_LIST"]:
        if isinstance(APIResponse["HOST_LIST_OUTPUT"]["RESPONSE"]["HOST_LIST"]["HOST"],list):
          iResultCount = len(APIResponse["HOST_LIST_OUTPUT"]["RESPONSE"]["HOST_LIST"]["HOST"])
          # iTotalCount += iResultCount
          LogEntry ("{} hosts in results".format(iResultCount))
          for dictResults in APIResponse["HOST_LIST_OUTPUT"]["RESPONSE"]["HOST_LIST"]["HOST"]:
            UpdateDB (dictResults)
            iTotalCount += 1
        else:
          iTotalCount += 1
          LogEntry ("Only one host in results")
          UpdateDB (APIResponse["HOST_LIST_OUTPUT"]["RESPONSE"]["HOST_LIST"]["HOST"])
      else:
        LogEntry("there is hosts list but no hosts, weird!!!!")
    else:
      LogEntry ("There are no results")
    if "WARNING" in APIResponse["HOST_LIST_OUTPUT"]["RESPONSE"]:
      strURL = APIResponse["HOST_LIST_OUTPUT"]["RESPONSE"]["WARNING"]["URL"]
      LogEntry ("Next URL: {}".format(strURL))
      APIResponse = MakeAPICall(strURL,strHeader,strUserName,strPWD,strMethod)
    else:
      bMoreData = False
# LogEntry ("Doing validation checks")
# strSQL = "select count(*) from tblhostlist where dtLastAPIUpdate > '{}';".format(dtStartTime)
# lstReturn = SQLQuery (strSQL,dbConn)
# if not ValidReturn(lstReturn):
#   LogEntry ("Unexpected: {}".format(lstReturn))
#   CleanExit("due to unexpected SQL return, please check the logs")
# else:
#   iCountHostChange = lstReturn[1][0][0]

# strSQL = "select count(*) from tblHost2Tag where dtLastAPIUpdate > '{}';".format(dtStartTime)
# lstReturn = SQLQuery (strSQL,dbConn)
# if not ValidReturn(lstReturn):
#   LogEntry ("Unexpected: {}".format(lstReturn))
#   CleanExit("due to unexpected SQL return, please check the logs")
# else:
#   iCountTagChange = lstReturn[1][0][0]

# bValidate = True

# LogEntry ("VALIDATE: Total Number of hosts downloaded {}; Total number of hosts updated in the database {}".format(iTotalCount,iCountHostChange))
# if iTotalCount != iCountHostChange:
#   LogEntry ("VALIDATE: Host validation failed")
#   bValidate = False
# else:
#   LogEntry ("VALIDATE: Host validation successful")

# LogEntry ("VALIDATE: Total number of tags processed {}; Total number of tags updated in database {}".format(iTotalTagCount,iCountTagChange))
# if iTotalTagCount != iCountTagChange:
#   LogEntry ("VALIDATE: Tag validation failed")
#   bValidate = False
# else:
#   LogEntry ("VALIDATE: Tag validation successful")

# LogEntry ("Updating completion entry")
# strdbNow = time.strftime("%Y-%m-%d %H:%M:%S")
# strSQL = ("update tblScriptExecuteList set dtStopTime='{}', bComplete=1, "
#           " iRowsUpdated={} where iExecuteID = {} ;".format(strdbNow,iTotalCount,iEntryID))
# lstReturn = SQLQuery (strSQL,dbConn)
# if not ValidReturn(lstReturn):
#   LogEntry ("Unexpected: {}".format(lstReturn))
# elif lstReturn[0] != 1:
#   LogEntry ("Records affected {}, expected 1 record affected".format(lstReturn[0]))
LogEntry ("All Done!")
# dbConn.close()
objLogOut.close()
objFileOut.close()
# if bValidate:
#   SendNotification("{} has completed processing on {}, and validation checks are good. Processed {} hosts and {} tags.".format(strScriptName,strScriptHost,iTotalCount,iTotalTagCount))
# else:
#   SendNotification("{} has completed processing on {}, and validation checks failed".format(strScriptName,strScriptHost))
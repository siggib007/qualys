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
import platform
import json
# End imports

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

print ("This is a script to gather all asset host detections from Qualys via API."
        " This is running under Python Version {}".format(strVersion))
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
strDBType = ""

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

  strMsg += strTemp
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
  global iBatchSize
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
        strHeader={'X-Requested-With': strValue}
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
      if strVarName == "FullFromDate":
        dtFullLoad = strValue
      if strVarName == "NotificationURL":
        strNotifyURL = strValue
      if strVarName == "NotifyChannel":
        strNotifyChannel = strValue
      if strVarName == "NotifyToken":
        strNotifyToken = strValue
      if strVarName == "BatchSize":
        iBatchSize = int(strValue)
      if strVarName == "DBType":
        strDBType  = strValue

  if strBaseURL[-1:] != "/":
    strBaseURL += "/"

  LogEntry ("Done processing configuration, moving on")

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
  # LogEntry ("response is {} char long".format(len(WebRequest.text)))

  try:
    dictResponse = xmltodict.parse(WebRequest.text)
  except xml.parsers.expat.ExpatError as err:
    # LogEntry("Expat Error: {}\n{}".format(err,WebRequest.text))
    iErrCode = "Expat Error"
    iErrText = "Expat Error: {}\n{}".format(err,WebRequest.text)
  except Exception as err:
    LogEntry("Unkown xmltodict exception: {}.".format(err))
    CleanExit(", Unkown xmltodict exception, please check the logs")

  if isinstance(dictResponse,dict):
    if "SIMPLE_RETURN" in dictResponse:
      try:
        if "CODE" in dictResponse["SIMPLE_RETURN"]["RESPONSE"]:
          iErrCode = dictResponse["SIMPLE_RETURN"]["RESPONSE"]["CODE"]
          iErrText = dictResponse["SIMPLE_RETURN"]["RESPONSE"]["TEXT"]
      except KeyError as e:
        LogEntry ("KeyError while evaluating error code in MakeAPICall: {}".format(e))
        LogEntry (WebRequest.text)
        iErrCode = "Unknown"
        iErrText = "Unexpected error"
  else:
    LogEntry ("Aborting abnormally because response not a dictionary",True)

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
  if strText is None:
    return ""
  strTemp = strText.encode("ascii","ignore")
  strTemp = strTemp.decode("ascii","ignore")
  strTemp = strTemp.replace("\\","\\\\")
  strTemp = strTemp.replace("'","\"")
  return strTemp

def QDate2DB(strDate):
  strTemp = DBClean(strDate)
  strTemp = strTemp.replace("T"," ")
  return strTemp.replace("Z","")

def UpdateDB (dictResults):
  global iTotalDetect

  strSQL = "delete from tbldetections where iHostID = {};".format(dictResults["ID"])
  lstReturn = SQLQuery (strSQL,dbConn)
  if not ValidReturn(lstReturn):
    LogEntry ("Unexpected: {}".format(lstReturn))
    LogEntry (strSQL)
    CleanExit("due to unexpected SQL return, please check the logs")
  else:
    LogEntry ("Deleted {} detections".format(lstReturn[0]))

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
    iVMScanDuration = DBClean(dictResults["LAST_VM_SCANNED_DURATION"])
  else:
    iVMScanDuration = "NULL"

  if "OS_CPE" in dictResults:
    strOS_CPE = DBClean(dictResults["OS_CPE"])
  else:
    strOS_CPE = ""

  if "TRACKING_METHOD" in dictResults:
    strTracking = DBClean(dictResults["TRACKING_METHOD"])
  else:
    strTracking = ""

  if "NETBIOS" in dictResults:
    strNetBIOS = DBClean(dictResults["NETBIOS"])
  else:
    strNetBIOS = ""

  if "LAST_VM_AUTH_SCANNED_DATE" in dictResults:
    dtVMAuth = "'" + QDate2DB(dictResults["LAST_VM_AUTH_SCANNED_DATE"]) + "'"
  else:
    dtVMAuth = "NULL"

  if "LAST_PC_SCANNED_DATE" in dictResults:
    dtPCScan = "'" + QDate2DB(dictResults["LAST_PC_SCANNED_DATE"]) + "'"
  else:
    dtPCScan = "NULL"

  if "LAST_VM_AUTH_SCANNED_DURATION" in dictResults:
    if isInt(dictResults["LAST_VM_AUTH_SCANNED_DURATION"]):
      iAuthDuration = int(dictResults["LAST_VM_AUTH_SCANNED_DURATION"])
    else:
      iAuthDuration = "NULL"
  else:
    iAuthDuration = "NULL"

  if "EC2_INSTANCE_ID" in dictResults:
    strECID = DBClean(dictResults["EC2_INSTANCE_ID"])
  else:
    strECID = ""

  if "QG_HOSTID" in dictResults:
    strQGID = DBClean(dictResults["QG_HOSTID"])
  else:
    strQGID = ""

  strdbNow = time.strftime("%Y-%m-%d %H:%M:%S")
  strSQL = "select * from tblhostlist where iHostID = {};".format(dictResults["ID"])
  lstReturn = SQLQuery (strSQL,dbConn)
  if not ValidReturn(lstReturn):
    LogEntry ("Unexpected: {}".format(lstReturn))
    LogEntry (strSQL)
    CleanExit("due to unexpected SQL return, please check the logs")
  elif len(lstReturn[1]) == 0:
    LogEntry ("Adding ID {} {}".format(dictResults["ID"],strHostName))
    try:
      strSQL = ("INSERT INTO tblhostlist (iHostID,vcIPAddr,vcOperatingSystem,vcHostName,dtLastScan,dtVMScanned,"
          "iLastScanDuration,vcOS_CPE,vcTrackingMethod,vcNetBIOS,dtVMAuthScanned,iVMAuthDuration,dtLastPCScan,vcEC_ID,"
          "vcQGid,dtLastAPIUpdate) "
          "VALUES({0},'{1}','{2}','{3}','{4}',{5},{6},'{7}','{8}','{9}',{10},{11},{12},'{13}','{14}','{15}');".format(
            dictResults["ID"],dictResults["IP"],strOS,strHostName,QDate2DB(dictResults["LAST_SCAN_DATETIME"]),
            dtLastVMSCan,iVMScanDuration,strOS_CPE,strTracking,strNetBIOS,dtVMAuth,iAuthDuration,dtPCScan,strECID,
            strQGID,strdbNow)
          )
    except KeyError as e:
      LogEntry ("keyError in insert into tblhostlist: {}".format(e),True)
  elif len(lstReturn[1])  == 1:
    LogEntry ("ID {} exists, need to update record for {}".format(dictResults["ID"],strHostName))
    try:
      strSQL = ("UPDATE tblhostlist SET vcIPAddr = '{}',vcOperatingSystem = '{}',vcHostName = '{}',dtLastScan = '{}',"
          "dtVMScanned = {},iLastScanDuration = {},vcOS_CPE = '{}',vcTrackingMethod = '{}',vcNetBIOS = '{}',"
          "dtVMAuthScanned = {},iVMAuthDuration = {},dtLastPCScan = {},vcEC_ID = '{}',vcQGid = '{}',"
          "dtLastAPIUpdate = '{}' WHERE iHostID = {};".format(dictResults["IP"],strOS,strHostName,
            QDate2DB(dictResults["LAST_SCAN_DATETIME"]),dtLastVMSCan,iVMScanDuration,strOS_CPE,strTracking,
            strNetBIOS,dtVMAuth,iAuthDuration,dtPCScan,strECID,strQGID,strdbNow,dictResults["ID"]
            )
        )
    except KeyError as e:
      LogEntry ("keyError in update tblhostlist: {}".format(e),True)
  else:
    LogEntry ("Something is horrible wrong, there are {} entries with ID of {}".format(len(lstReturn[1]),dictResults["ID"]))
    LogEntry (strSQL)
    CleanExit("due to unexpected SQL return, please check the logs")
  lstReturn = SQLQuery (strSQL,dbConn)
  if not ValidReturn(lstReturn):
    LogEntry ("Unexpected: {}".format(lstReturn))
    LogEntry (strSQL)
    CleanExit("due to unexpected SQL return, please check the logs")

  if isinstance(dictResults["DETECTION_LIST"]["DETECTION"],list):
    LogEntry ("There are {} detections".format(len(dictResults["DETECTION_LIST"]["DETECTION"])))
    lstTemp = dictResults["DETECTION_LIST"]["DETECTION"]
  else:
    LogEntry ("Only One detection")
    lstTemp = [dictResults["DETECTION_LIST"]["DETECTION"]]

  iTotalDetect += len(lstTemp)
  for dictTemp in lstTemp:
    if "PORT" in dictTemp:
      strPort = DBClean(dictTemp["PORT"])
    else:
      strPort = "NULL"

    if "PROTOCOL" in dictTemp:
      strProtocol = DBClean(dictTemp["PROTOCOL"])
    else:
      strProtocol = ""

    if "RESULTS" in dictTemp:
      strResults = DBClean(dictTemp["RESULTS"][:999999])
    else:
      strResults = ""

    if "LAST_PROCESSED_DATETIME" in dictTemp:
      dtProccess = "'" + QDate2DB(dictTemp["LAST_PROCESSED_DATETIME"]) +"'"
    else:
      dtProccess = "NULL"

    if "FQDN" in dictTemp:
      strFQDN = DBClean(dictTemp["FQDN"])
    else:
      strFQDN = ""

    if "LAST_FIXED_DATETIME" in dictTemp:
      dtFixed = "'" + QDate2DB(dictTemp["LAST_FIXED_DATETIME"]) + "'"
    else:
      dtFixed = "NULL"

    if "FIRST_REOPENED_DATETIME" in dictTemp:
      dtReopened = "'" + QDate2DB(dictTemp["FIRST_REOPENED_DATETIME"]) + "'"
    else:
      dtReopened = "NULL"

    if "LAST_REOPENED_DATETIME" in dictTemp:
      dtLastReopen = "'" + QDate2DB(dictTemp["LAST_REOPENED_DATETIME"]) + "'"
    else:
      dtLastReopen = "NULL"

    if "SSL" in dictTemp:
      if isInt(dictTemp["SSL"]):
        bSSL = int(dictTemp["SSL"])
      else:
        bSSL = "NULL"
    else:
      bSSL = "NULL"

    if "STATUS" in dictTemp:
      strStatus = dictTemp["STATUS"]
    else:
      strStatus = ""

    if "TIMES_REOPENED" in dictTemp:
      if isInt(dictTemp["TIMES_REOPENED"]):
        iReopenCount = int(dictTemp["TIMES_REOPENED"])
      else:
        iReopenCount = "NULL"
    else:
      iReopenCount = "NULL"

    if "TIMES_FOUND" in dictTemp:
      if isInt(dictTemp["TIMES_FOUND"]):
        iTimesFound = int(dictTemp["TIMES_FOUND"])
      else:
        iTimesFound = "NULL"
    else:
      iTimesFound = "NULL"

    if "SERVICE" in dictTemp:
      strService = DBClean(dictTemp["SERVICE"])
    else:
      strService = ""

    if "FIRST_FOUND_DATETIME" in dictTemp:
      dtFirstFound = "'" + QDate2DB(dictTemp["FIRST_FOUND_DATETIME"]) + "'"
    else:
      dtFirstFound = "NULL"

    if "LAST_FOUND_DATETIME" in dictTemp:
      dtLastFound = "'" + QDate2DB(dictTemp["LAST_FOUND_DATETIME"]) + "'"
    else:
      dtLastFound = "NULL"

    if "LAST_TEST_DATETIME" in dictTemp:
      dtLastTest = "'" + QDate2DB(dictTemp["LAST_TEST_DATETIME"]) + "'"
    else:
      dtLastTest = "NULL"

    if "LAST_UPDATE_DATETIME" in dictTemp:
      dtLastUpdate = "'" + QDate2DB(dictTemp["LAST_UPDATE_DATETIME"]) + "'"
    else:
      dtLastUpdate = "NULL"

    if "IS_IGNORED" in dictTemp:
      if isInt(dictTemp["IS_IGNORED"]):
        bIsIgnored = int(dictTemp["IS_IGNORED"])
      else:
        bIsIgnored = "NULL"
    else:
      bIsIgnored = "NULL"

    if "IS_DISABLED" in dictTemp:
      if isInt(dictTemp["IS_DISABLED"]):
        bIsDisabled = int(dictTemp["IS_DISABLED"])
      else:
        bIsDisabled = "NULL"
    else:
      bIsDisabled = "NULL"

    strdbNow = time.strftime("%Y-%m-%d %H:%M:%S")
    try:
      strSQL = ("INSERT INTO tbldetections (iHostID, iQID, vcType, iSeverity, iPortNumber, vcProtocol, bSSL, "
          "tResults, vcStatus, dtFirstFound, dtLastFound, iTimesFound, dtLastTest, dtLastUpdate, bIsIgnored, "
          "bIsDisabled, dtLastProcessed, vcFQDN, dtLastFixed, dtFirstReopened, dtLastReopened, iTimesReopened, "
          "vcService, dtLastAPIUpdate) "
          "VALUES({0},{1},'{2}',{3},{4},'{5}',{6},'{7}','{8}',{9},{10},{11},{12},{13},{14},"
          " {15},{16},'{17}',{18},{19},{20}, "
          "{21},'{22}','{23}');".format(
            DBClean(dictResults["ID"]),DBClean(dictTemp["QID"]),DBClean(dictTemp["TYPE"]),DBClean(dictTemp["SEVERITY"]),
            strPort,strProtocol,bSSL,strResults,strStatus,dtFirstFound,dtLastFound,iTimesFound,dtLastTest,dtLastUpdate,
            bIsIgnored,bIsDisabled, dtProccess, strFQDN,dtFixed,dtReopened,dtLastReopen,iReopenCount,strService,strdbNow)
          )
    except KeyError as e:
      LogEntry ("keyError in insert tbldetections: {}".format(e),True)
    lstReturn = SQLQuery (strSQL,dbConn)
    if not ValidReturn(lstReturn):
      LogEntry ("Unexpected: {}".format(lstReturn))
      # LogEntry (strSQL)
      CleanExit("due to unexpected SQL return, please check the logs")
    elif lstReturn[0] != 1:
      LogEntry ("Records affected {}, expected 1 record affected".format(lstReturn[0]))

dbConn = ""
processConf()
dbConn = SQLConn (strServer,strDBUser,strDBPWD,strInitialDB)
if strDBType == "mysql":
  strSQL = ("select TIMESTAMPDIFF(MINUTE,max(dtTimestamp),now()) as timediff "
              " from tblLogs where vcScriptName = '{}';".format(strScriptName))
elif strDBType == "mssql":
  strSQL = ("select datediff(MINUTE,max(dtTimestamp),GETDATE()) as timediff "
              " from tblLogs where vcScriptName = '{}';".format(strScriptName))
else:
  LogEntry ("Unknown database type {}".format(strDBType),True)
lstReturn = SQLQuery (strSQL,dbConn)
if not ValidReturn(lstReturn):
  LogEntry ("Unexpected: {}".format(lstReturn))
  LogEntry (strSQL)
  CleanExit("due to unexpected SQL return, please check the logs")
elif len(lstReturn[1]) == 0:
  LogEntry ("No records returned, indicating the log file is empty, setting quiet timet to MinQuietTime")
  iQuietMin = iMinQuietTime
elif lstReturn[1][0][0] is None:
  LogEntry ("Nonetype returned for Quiet min, indicating the log file is empty, setting quiet timet to MinQuietTime")
  iQuietMin = iMinQuietTime
else:
  iQuietMin = int(lstReturn[1][0][0])

strSQL = ("select vcLogEntry from tblLogs where ILogID = "
      " (select max(ILogID) from tblLogs where vcScriptName = '{}');".format(strScriptName))
lstReturn = SQLQuery (strSQL,dbConn)
if not ValidReturn(lstReturn):
  LogEntry ("Unexpected: {}".format(lstReturn))
  LogEntry (strSQL)
  CleanExit("due to unexpected SQL return, please check the logs")
elif len(lstReturn[1]) == 0:
  LogEntry ("No records returned, indicating the log file is empty.".format(lstReturn[0]))
  strLastEntry = "All Done!"
else:
  strLastEntry = lstReturn[1][0][0]


if iQuietMin < iMinQuietTime :
  dbConn.close()
  dbConn = ""
  LogEntry ("Last Log update {1} min ago. Either the script is already running or it's been less that {0} min since it last run, "
        "please wait until after {0} since last run. Exiting".format(iMinQuietTime,iQuietMin ))
  objLogOut.close()
  sys.exit()
else:
  LogEntry("{} Database connection established. It's been {} minutes since last log entry.".format(strDBType, iQuietMin))


LogEntry("Starting Processing. Script {} running under Python version {}".format(strRealPath,strVersion))

strdbNow = time.strftime("%Y-%m-%d %H:%M:%S")
strSQL = ("INSERT INTO tblScriptExecuteList (vcScriptName,dtStartTime,iGMTOffset) "
          " VALUES('{}','{}',{});".format(strScriptName,strdbNow,iGMTOffset))
lstReturn = SQLQuery (strSQL,dbConn)
if not ValidReturn(lstReturn):
  LogEntry ("Unexpected: {}".format(lstReturn))
  LogEntry (strSQL)
  CleanExit("due to unexpected SQL return, please check the logs")
elif lstReturn[0] != 1:
  LogEntry ("inserting into tblScriptExecuteList Records affected {}, expected 1 record affected".format(lstReturn[0]))

strSQL = ("select iExecuteID,dtStartTime from tblScriptExecuteList where iExecuteID in "
  " (select max(iExecuteID) from tblScriptExecuteList where vcScriptName = '{}');".format(strScriptName))
lstReturn = SQLQuery (strSQL,dbConn)
if not ValidReturn(lstReturn):
  LogEntry ("Unexpected: {}".format(lstReturn))
  LogEntry (strSQL)
  CleanExit("due to unexpected SQL return, please check the logs")
elif len(lstReturn[1]) == 0:
  LogEntry ("Nothing returned when looking for Entry ID we just inserted",True)
else:
  iEntryID = lstReturn[1][0][0]
  dtStartTime = lstReturn[1][0][1]

LogEntry("Recorded start entry, ID {}".format(iEntryID))

if strLoadType.lower() == "full":
  dtLastStart = dtFullLoad
  LogEntry("Doing a Full Load per directive from configuration file, going back to {}".format(dtFullLoad))
else:
  LogEntry("Configuration file indicates incementatal load, finding last execution date")
  if strDBType == "mysql":
    strSQL = ("select dtStartTime -INTERVAL 1 DAY from tblScriptExecuteList where dtStartTime = "
              " (select max(dtStartTime) from tblScriptExecuteList where vcScriptName = '{}' "
              " and bComplete = 1 and iExecuteID < {});").format(strScriptName,iEntryID)
  elif strDBType == "mssql":
    strSQL = ("select dateadd(DAY,-1,dtStartTime) from tblScriptExecuteList where dtStartTime = "
              " (select max(dtStartTime) from tblScriptExecuteList where vcScriptName = '{}' "
              " and bComplete = 1 and iExecuteID < {});").format(strScriptName,iEntryID)
  else:
    LogEntry ("Unknown database type {}".format(strDBType),True)

  lstReturn = SQLQuery (strSQL,dbConn)
  if not ValidReturn(lstReturn):
    LogEntry ("Unexpected: {}".format(lstReturn))
    LogEntry (strSQL)
    CleanExit("due to unexpected SQL return, please check the logs")
  elif len(lstReturn[1]) == 0:
    LogEntry ("No records returned, switching to full load, going back to {}".format(dtFullLoad))
    dtLastStart = dtFullLoad
  else:
    dtLastStart = lstReturn[1][0][0].date()
    LogEntry ("starting from {}".format(dtLastStart))

strAPIFunction = "/api/2.0/fo/asset/host/vm/detection"
if strAPIFunction[0] == "/":
  strAPIFunction = strAPIFunction[1:]

if strAPIFunction[-1:] != "/":
  strAPIFunction += "/"

LogEntry ("API Function: {}".format(strAPIFunction))

strMethod = "get"
dictParams = {}
dictParams["action"] = "list"
dictParams["output_format"] = "XML"
dictParams["show_reopened_info"] = "1"
dictParams["id_min"] = 0
dictParams["vm_scan_since"] = dtLastStart
dictParams["show_igs"] = 1
dictParams["truncation_limit"] = iBatchSize
# dictParams["status"] = "New,Active,Re-Opened,Fixed"
# dictParams["ids"] = "12391298"
# dictParams["qids"] = "87313"

bMoreData = True
iTotalCount = 0
iTotalDetect = 0
strListScans = urlparse.urlencode(dictParams)


if strLastEntry != "All Done!":
  LogEntry ("Either this is the first time this script is being run or it ended abnormally last time.")
  strSQL = ("select vcLogEntry from tblLogs where ILogID = (select max(ILogID) from tblLogs where vcLogEntry like "
            " '%Next URL%'and vcScriptName = '{}');").format(strScriptName)
  lstReturn = SQLQuery (strSQL,dbConn)
  if not ValidReturn(lstReturn):
    LogEntry ("Unexpected: {}".format(lstReturn))
    CleanExit("due to unexpected SQL return, please check the logs")
  else:
    if len(lstReturn[1]) > 0:
      LogEntry ("confirmed last job ended abnormally, found were it left off and starting from there.")
      strURL = lstReturn[1][0][0][10:]
    else:
      LogEntry ("confirmed this is the first time, starting from scratch")
      strURL = strBaseURL + strAPIFunction +"?" + strListScans
else:
  LogEntry ("Confirmed last job exited normally, starting from scratch")
  strURL = strBaseURL + strAPIFunction +"?" + strListScans


LogEntry ("Next URL: {}".format(strURL))
APIResponse = MakeAPICall(strURL,strHeader,strUserName,strPWD,strMethod)


while bMoreData:
  strdbNow = time.strftime("%Y-%m-%d %H:%M:%S")
  strSQL = ("update tblScriptExecuteList set dtStopTime='{}', bComplete=0, "
    " iRowsUpdated={} where iExecuteID = {} ;".format(strdbNow, iTotalCount,iEntryID))
  lstReturn = SQLQuery (strSQL,dbConn)
  if not ValidReturn(lstReturn):
    LogEntry ("Unexpected: {}".format(lstReturn))
    LogEntry (strSQL)
    CleanExit("due to unexpected SQL return, please check the logs")
  elif lstReturn[0] != 1:
    LogEntry ("Records affected {}, expected 1 record affected".format(lstReturn[0]))
  if isinstance(APIResponse,str):
    LogEntry(APIResponse)
  if isinstance(APIResponse,dict):
    if "HOST_LIST" in APIResponse["HOST_LIST_VM_DETECTION_OUTPUT"]["RESPONSE"]:
      if "HOST" in APIResponse["HOST_LIST_VM_DETECTION_OUTPUT"]["RESPONSE"]["HOST_LIST"]:
        if isinstance(APIResponse["HOST_LIST_VM_DETECTION_OUTPUT"]["RESPONSE"]["HOST_LIST"]["HOST"],list):
          iResultCount = len(APIResponse["HOST_LIST_VM_DETECTION_OUTPUT"]["RESPONSE"]["HOST_LIST"]["HOST"])
          iTotalCount += iResultCount
          LogEntry ("{} hosts in results".format(iResultCount))
          for dictHosts in APIResponse["HOST_LIST_VM_DETECTION_OUTPUT"]["RESPONSE"]["HOST_LIST"]["HOST"]:
            UpdateDB (dictHosts)
        else:
          iTotalCount += 1
          LogEntry ("Only one host in results")
          UpdateDB (APIResponse["HOST_LIST_VM_DETECTION_OUTPUT"]["RESPONSE"]["HOST_LIST"]["HOST"])
      else:
        LogEntry("there is hosts list but no hosts, weird!!!!")
    else:
      LogEntry ("There are no results")
    if "WARNING" in APIResponse["HOST_LIST_VM_DETECTION_OUTPUT"]["RESPONSE"]:
      strURL = APIResponse["HOST_LIST_VM_DETECTION_OUTPUT"]["RESPONSE"]["WARNING"]["URL"]
      LogEntry ("Next URL: {}".format(strURL))
      APIResponse = MakeAPICall(strURL,strHeader,strUserName,strPWD,strMethod)
    else:
      bMoreData = False
  else:
    LogEntry ("APIResponse is not a dictionary it is a {}, this should not be so I'm bailing".format(type(APIResponse)),True)

LogEntry ("Doing validation checks")
strSQL = "select count(*) from tblhostlist where dtLastAPIUpdate > '{}';".format(dtStartTime)
lstReturn = SQLQuery (strSQL,dbConn)
if not ValidReturn(lstReturn):
  LogEntry ("Unexpected: {}".format(lstReturn))
  CleanExit("due to unexpected SQL return, please check the logs")
else:
  iCountHostChange = lstReturn[1][0][0]

strSQL = "select count(*) from tbldetections where dtLastAPIUpdate > '{}';".format(dtStartTime)
lstReturn = SQLQuery (strSQL,dbConn)
if not ValidReturn(lstReturn):
  LogEntry ("Unexpected: {}".format(lstReturn))
  CleanExit("due to unexpected SQL return, please check the logs")
else:
  iCountDetections = lstReturn[1][0][0]

bValidate = True

LogEntry ("VALIDATE: Total Number of hosts downloaded {}; "
          " Total number of hosts updated in the database {}".format(iTotalCount,iCountHostChange))
if iTotalCount != iCountHostChange:
  LogEntry ("VALIDATE: Host validation failed")
  bValidate = False
else:
  LogEntry ("VALIDATE: Host validation successful")

LogEntry ("VALIDATE: Total number of detections processed {}; "
          " Total number of detections updated in database {}".format(iTotalDetect,iCountDetections))
if iTotalDetect != iCountDetections:
  LogEntry ("VALIDATE: Tag validation failed")
  bValidate = False
else:
  LogEntry ("VALIDATE: Tag validation successful")

LogEntry("Updating completion entry")
strdbNow = time.strftime("%Y-%m-%d %H:%M:%S")
strSQL = ("update tblScriptExecuteList set dtStopTime='{}', bComplete=1, "
          " iRowsUpdated={} where iExecuteID = {} ;".format(strdbNow,iTotalCount,iEntryID))
lstReturn = SQLQuery (strSQL,dbConn)
if not ValidReturn(lstReturn):
  LogEntry ("Unexpected: {}".format(lstReturn))
elif lstReturn[0] != 1:
  LogEntry ("Records affected {}, expected 1 record affected".format(lstReturn[0]))
LogEntry ("All Done!")
dbConn.close()
objLogOut.close()
if bValidate:
  SendNotification("{} has completed processing on {}, and validation checks are good. "
    " Processed {} hosts and {} detections.".format(strScriptName,strScriptHost,iTotalCount,iTotalDetect))
else:
  SendNotification("{} has completed processing on {}, and validation checks failed".format(strScriptName,strScriptHost))
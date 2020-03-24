'''
Script to pull summary list of all scans from Qualys
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

print ("This is a script to pull a sumamry list of all scan results from Qualys via API. "
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
  global iLookBackDays

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
      if strVarName == "PartialPeriod":
        iLookBackDays = int(strValue)

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
  global iTotalCount

  if "REF" in dictResults:
    strScanRef = DBClean(dictResults["REF"])
  else:
    strScanRef = ""

  if "TYPE" in dictResults:
    strType = DBClean(dictResults["TYPE"])
  else:
    strType = ""

  if "LAUNCH_DATETIME" in dictResults:
    dtLaunched = "'" + QDate2DB(dictResults["LAUNCH_DATETIME"]) + "'"
  else:
    dtLaunched = "NULL"

  if "TITLE" in dictResults:
    strTitle = DBClean(dictResults["TITLE"])
  else:
    strTitle = ""

  if "USER_LOGIN" in dictResults:
    strLaunchedBy = DBClean(dictResults["USER_LOGIN"])
  else:
    strLaunchedBy = ""

  if "DURATION" in dictResults:
    strDuration = DBClean(dictResults["DURATION"])
  else:
    strDuration = ""

  if "TARGET" in dictResults:
    strTargets = DBClean(dictResults["TARGET"])
  else:
    strTargets = ""

  if "OPTION_PROFILE" in dictResults:
    if "TITLE" in dictResults["OPTION_PROFILE"]:
      strOptionProfile = DBClean(dictResults["OPTION_PROFILE"]["TITLE"])
    else:
      strOptionProfile = ""
  else:
    strOptionProfile = ""

  if "STATUS" in dictResults:
    if "STATE" in dictResults["STATUS"]:
      strStatus = DBClean(dictResults["STATUS"]["STATE"])
    else:
      strStatus = ""
  else:
    strStatus = ""

  strdbNow = time.strftime("%Y-%m-%d %H:%M:%S")
  strSQL = "select * from tblScanList where vcScanRef = '{}';".format(strScanRef)
  lstReturn = SQLQuery (strSQL,dbConn)
  if not ValidReturn(lstReturn):
    LogEntry ("Unexpected: {}".format(lstReturn))
    LogEntry (strSQL)
    CleanExit("due to unexpected SQL return, please check the logs")
  elif len(lstReturn[1]) == 0:
    LogEntry ("Adding scan {} {}".format(strScanRef,strTitle))
    iTotalCount += 1
    try:
      strSQL = ("INSERT INTO tblScanList (vcScanRef,vcType,vcTitle,vcUser,dtLaunched,vcDuration,"
        "vcTargets,vcOptionProfile,vcStatus,dtLastAPIUpdate) "
          "VALUES('{0}','{1}','{2}','{3}',{4},'{5}','{6}','{7}','{8}','{9}');".format(
            strScanRef,strType,strTitle,strLaunchedBy,dtLaunched,strDuration,strTargets,strOptionProfile,strStatus,strdbNow)
          )
    except KeyError as e:
      LogEntry ("keyError in insert into tblhostlist: {}".format(e),True)
  elif len(lstReturn[1]) == 1:
    LogEntry ("Scan {} {} already in the database, not doing anything".format(strScanRef,strTitle))
  else:
    LogEntry ("Something is horrible wrong, there are {} entries with ID of {}".format(len(lstReturn[1]),dictResults["ID"]))
    LogEntry (strSQL)
    CleanExit("due to unexpected SQL return, please check the logs")
  lstReturn = SQLQuery (strSQL,dbConn)
  if not ValidReturn(lstReturn):
    LogEntry ("Unexpected: {}".format(lstReturn))
    LogEntry (strSQL)
    CleanExit("due to unexpected SQL return, please check the logs")
  elif lstReturn[0] > 1:
    LogEntry ("Records affected {}, expected 1 record affected".format(lstReturn[0]))


dbConn = ""
processConf()
dbConn = SQLConn (strServer,strDBUser,strDBPWD,strInitialDB)
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
  LogEntry (strSQL)
  CleanExit("due to unexpected SQL return, please check the logs")
elif len(lstReturn[1]) != 1:
  LogEntry ("Records affected {}, expected 1 record affected".format(len(lstReturn[1])))
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
elif len(lstReturn[1]) != 1:
  LogEntry ("Records affected {}, expected 1 record affected".format(len(lstReturn[1])))
  strLastEntry = "All Done!"
else:
  strLastEntry = lstReturn[1][0][0]


if iQuietMin < iMinQuietTime :
  dbConn = ""
  LogEntry ("Last Log update {1} min ago. Either the script is already running or it's been less that {0} min since it last run, "
        "please wait until after {0} since last run. Exiting".format(iMinQuietTime,iQuietMin ))
  objLogOut.close()
  sys.exit()
else:
  LogEntry("{} Database connection established. It's been {} minutes since last log entry.".format(strDBType.upper(),iQuietMin))


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
  LogEntry ("Records affected {}, expected 1 record affected".format(lstReturn[0]))

strSQL = ("select iExecuteID,dtStartTime from tblScriptExecuteList where iExecuteID in "
  " (select max(iExecuteID) from tblScriptExecuteList where vcScriptName = '{}');".format(strScriptName))
lstReturn = SQLQuery (strSQL,dbConn)
if not ValidReturn(lstReturn):
  LogEntry ("Unexpected: {}".format(lstReturn))
  LogEntry (strSQL)
  CleanExit("due to unexpected SQL return, please check the logs")
elif len(lstReturn[1]) != 1:
  LogEntry ("Records affected {}, expected 1 record affected".format(len(lstReturn[1])))
  iEntryID = -10
else:
  iEntryID = lstReturn[1][0][0]
  dtStartTime = lstReturn[1][0][1]

LogEntry("Recorded start entry, ID {}".format(iEntryID))

if strLoadType.lower() == "full":
  dtLastStart = dtFullLoad
  LogEntry("Doing a Full Load per directive from configuration file, going back to {}".format(dtFullLoad))
else:
  LogEntry("Configuration file indicates incrementatal load, finding last execution date")
  if strDBType == "mysql":
    strSQL = ("select dtStartTime -INTERVAL {} DAY from tblScriptExecuteList where dtStartTime = "
              " (select max(dtStartTime) from tblScriptExecuteList where vcScriptName = '{}' "
              " and bComplete = 1 and iExecuteID < {});").format(iLookBackDays,strScriptName,iEntryID)
  elif strDBType == "mssql":
    strSQL = ("select dateadd(DAY,-{},dtStartTime) from tblScriptExecuteList where dtStartTime = "
              " (select max(dtStartTime) from tblScriptExecuteList where vcScriptName = '{}' "
              " and bComplete = 1 and iExecuteID < {});").format(iLookBackDays,strScriptName,iEntryID)
  lstReturn = SQLQuery (strSQL,dbConn)
  if not ValidReturn(lstReturn):
    LogEntry ("Unexpected: {}".format(lstReturn))
    LogEntry (strSQL)
    CleanExit("due to unexpected SQL return, please check the logs")
  elif len(lstReturn[1]) != 1:
    LogEntry ("Records affected {}, expected 1 record affected".format(len(lstReturn[1])))
    LogEntry ("Since the result set is Unexpected, switching to full load, going back to {}".format(dtFullLoad))
    dtLastStart = dtFullLoad
  else:
    dtLastStart = lstReturn[1][0][0].date()
    LogEntry ("starting from {}".format(dtLastStart))

strAPIFunction = "api/2.0/fo/scan/"
if strAPIFunction[0] == "/":
  strAPIFunction = strAPIFunction[1:]

if strAPIFunction[-1:] != "/":
  strAPIFunction += "/"

LogEntry ("API Function: {}".format(strAPIFunction))

strMethod = "get"
dictParams = {}
dictParams["action"] = "list"
dictParams["launched_after_datetime"]=dtLastStart
dictParams["state"] = "Canceled,Finished,Error"
dictParams["show_op"] = 1

bMoreData = True
iTotalCount = 0
strListScans = urlparse.urlencode(dictParams)


if strLastEntry != "All Done!":
  LogEntry ("Either this is the first time this script is being run or it ended abnormally last time.")
  strSQL = ("select vcLogEntry from tblLogs where ILogID = (select max(ILogID) from tblLogs where vcLogEntry like "
            " '%Next URL%'and vcScriptName = '{}');").format(strScriptName)
  lstReturn = SQLQuery (strSQL,dbConn)
  if not ValidReturn(lstReturn):
    LogEntry ("Unexpected: {}".format(lstReturn))
    LogEntry (strSQL)
    CleanExit("due to unexpected SQL return, please check the logs")
  elif len(lstReturn[1]) != 1:
    LogEntry ("Records affected {}, expected 1 record affected".format(len(lstReturn[1])))
    if len(lstReturn[1]) == 0:
      LogEntry ("Looks like this is the first time the script is run in this environment, starting from scratch")
    else:
      LogEntry ("don't know what to do with multiple next URL's, so starting from scratch")
    strURL = strBaseURL + strAPIFunction +"?" + strListScans
  else:
    LogEntry ("confirmed last job ended abnormally, found were it left off and starting from there.")
    strURL = lstReturn[1][0][0][10:]
else:
  LogEntry ("Confirmed last job exited normally, starting from scratch")
  strURL = strBaseURL + strAPIFunction +"?" + strListScans

LogEntry ("Next URL: {}".format(strURL))
APIResponse = MakeAPICall(strURL,strHeader,strUserName,strPWD,strMethod)

while bMoreData:
  strdbNow = time.strftime("%Y-%m-%d %H:%M:%S")
  strSQL = ("update tblScriptExecuteList set dtStopTime='{}', bComplete=0, iRowsUpdated={} "
              " where iExecuteID = {} ;".format(strdbNow,iTotalCount,iEntryID))
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
    if "SCAN_LIST" in APIResponse["SCAN_LIST_OUTPUT"]["RESPONSE"]:
      if "SCAN" in APIResponse["SCAN_LIST_OUTPUT"]["RESPONSE"]["SCAN_LIST"]:
        if isinstance(APIResponse["SCAN_LIST_OUTPUT"]["RESPONSE"]["SCAN_LIST"]["SCAN"],list):
          iResultCount = len(APIResponse["SCAN_LIST_OUTPUT"]["RESPONSE"]["SCAN_LIST"]["SCAN"])
          # iTotalCount += iResultCount
          LogEntry ("{} scans in results".format(iResultCount))
          for dictScans in APIResponse["SCAN_LIST_OUTPUT"]["RESPONSE"]["SCAN_LIST"]["SCAN"]:
            UpdateDB (dictScans)
        else:
          # iTotalCount += 1
          LogEntry ("Only one scan in results")
          UpdateDB (APIResponse["SCAN_LIST_OUTPUT"]["RESPONSE"]["SCAN_LIST"]["SCAN"])
      else:
        LogEntry("there is scan list but no scans, weird!!!!")
    else:
      LogEntry ("There are no results")
    if "WARNING" in APIResponse["SCAN_LIST_OUTPUT"]["RESPONSE"]:
      strURL = APIResponse["SCAN_LIST_OUTPUT"]["RESPONSE"]["WARNING"]["URL"]
      LogEntry ("Next URL: {}".format(strURL))
      APIResponse = MakeAPICall(strURL,strHeader,strUserName,strPWD,strMethod)
    else:
      bMoreData = False
  else:
    LogEntry ("APIResponse is not a dictionary it is a {}, this should not be, so I'm bailing".format(type(APIResponse)),True)

LogEntry ("Doing validation checks")
strSQL = "select count(*) from tblScanList where dtLastAPIUpdate > '{}';".format(dtStartTime)
lstReturn = SQLQuery (strSQL,dbConn)
if not ValidReturn(lstReturn):
  LogEntry ("Unexpected: {}".format(lstReturn))
  CleanExit("due to unexpected SQL return, please check the logs")
elif len(lstReturn[1]) != 1:
  LogEntry ("Records affected {}, expected 1 record affected".format(len(lstReturn[1])))
else:
  iCountScanChange = lstReturn[1][0][0]

LogEntry ("VALIDATE: Total Number of scans downloaded {}; Total number of scans updated in the database {}".format(iTotalCount,iCountScanChange))
if iTotalCount != iCountScanChange:
  LogEntry ("VALIDATE: Host validation failed")
  SendNotification("{} has completed processing on {}, and validation checks failed".format(strScriptName,strScriptHost))
else:
  LogEntry ("VALIDATE: Scan validation successful")
  SendNotification("{} has completed processing on {}, validation checks are good. Processed {} scans.".format(strScriptName,strScriptHost,iTotalCount))

strdbNow = time.strftime("%Y-%m-%d %H:%M:%S")
LogEntry("Updating completion entry")
strSQL = ("update tblScriptExecuteList set dtStopTime='{}' , bComplete=1, "
        " iRowsUpdated={} where iExecuteID = {} ;".format(strdbNow,iTotalCount,iEntryID))
lstReturn = SQLQuery (strSQL,dbConn)
if not ValidReturn(lstReturn):
  LogEntry ("Unexpected: {}".format(lstReturn))
elif lstReturn[0] != 1:
  LogEntry ("Records affected {}, expected 1 record affected".format(lstReturn[0]))
LogEntry ("All Done!")
dbConn.close()
objLogOut.close()

'''
Script to pull all Vulnerability details data from Qualys Knowledge Base
Version 2
Author Siggi Bjarnason Copyright 2018
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

print ("This is a script to gather all Knowledge base entries from Qualys via API. "
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
iCountTagChange = 0
strDBType = ""
iStopNum = 499999

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
      strTemp = ("   Records affected {}, expected 1 record affected when inserting log entry to the database".format(len(lstReturn[1])))
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
  global iTestQID
  global strNotifyURL
  global strNotifyToken
  global strNotifyChannel
  global strDBType
  global iBatchSize

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
      if strVarName == "BatchSize":
        iBatchSize = int(strValue)
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
  strTemp = strDate.replace("T"," ")
  return strTemp.replace("Z","")

def DBClean(strText):
  strTemp = strText.encode("ascii","ignore")
  strTemp = strTemp.decode("ascii","ignore")
  strTemp = strTemp.replace("\\","\\\\")
  strTemp = strTemp.replace("'","\"")
  return strTemp

def UpdateDB (dictResults):
  global iUpdateCount
  LogEntry ("processing ID {}".format(dictResults["QID"]))

  if "DISCOVERY" in dictResults:
    if "ADDITIONAL_INFO" in dictResults["DISCOVERY"]:
      strAddDetail = DBClean(dictResults["DISCOVERY"]["ADDITIONAL_INFO"])
    else:
      strAddDetail = ""
    if "REMOTE" in dictResults["DISCOVERY"]:
      strRemoteDisc = dictResults["DISCOVERY"]["REMOTE"]
    else:
      strRemoteDisc = ""
  else:
    strRemoteDisc = ""
    strAddDetail = ""

  strSQL = "delete from tblQID2Module where iQID = {};".format(dictResults["QID"])
  lstReturn = SQLQuery (strSQL,dbConn)
  if not ValidReturn(lstReturn):
    LogEntry ("Unexpected: {}".format(lstReturn))
    CleanExit("due to unexpected SQL return, please check the logs")
  else:
    LogEntry ("Deleted {} QID to Supported Module mappings".format(lstReturn[0]))

  if "SUPPORTED_MODULES" in dictResults:
    lstSupportModules = dictResults["SUPPORTED_MODULES"].split(",")
    for strMod in lstSupportModules:
      strSQL = "select * from tblModules where vcModuleName = '{}';".format(strMod)
      lstReturn = SQLQuery (strSQL,dbConn)
      if not ValidReturn(lstReturn):
        LogEntry ("Unexpected: {}".format(lstReturn),True)
      elif len(lstReturn[1]) == 0:
        strSQL = "INSERT INTO tblModules (vcModuleName) VALUES ('{}');".format(strMod)
        lstReturn = SQLQuery (strSQL,dbConn)
        if not ValidReturn(lstReturn):
          LogEntry ("Unexpected: {}".format(lstReturn))
          LogEntry (strSQL)
          CleanExit("due to unexpected SQL return, please check the logs")
        elif lstReturn[0] != 1:
          LogEntry ("Records affected {}, expected 1 record affected when insert Supported Module name".format(len(lstReturn[1])))
        strSQL = "select * from tblModules where vcModuleName = '{}';".format(strMod)
        lstReturn = SQLQuery (strSQL,dbConn)
        if not ValidReturn(lstReturn):
          LogEntry ("Unexpected: {}".format(lstReturn),True)
        elif len(lstReturn[1]) == 0:
          LogEntry ("Just inserted new Supported Module Name, but I can't find it, aborting.",True)
        else:
          iModID = int(lstReturn[1][0][0])
      else:
        iModID = int(lstReturn[1][0][0])
      strSQL = "INSERT INTO tblQID2Module (iQID,iModID) VALUES ({},{});".format(dictResults["QID"],iModID)
      lstReturn = SQLQuery (strSQL,dbConn)
      if not ValidReturn(lstReturn):
        LogEntry ("Unexpected: {}".format(lstReturn))
        LogEntry (strSQL)
        CleanExit("due to unexpected SQL return, please check the logs")
      elif lstReturn[0] != 1:
        LogEntry ("Records affected {}, expected 1 record affected when insert new QID to Module map".format(len(lstReturn[1])))


  if "CVSS" in dictResults:
    if "BASE" in dictResults["CVSS"]:
      if isinstance(dictResults["CVSS"]["BASE"],str):
        iCVSSBase = dictResults["CVSS"]["BASE"]
      elif isinstance(dictResults["CVSS"]["BASE"],dict):
        iCVSSBase = dictResults["CVSS"]["BASE"]["#text"]
      else:
        iCVSSBase = "NULL"
    else:
      iCVSSBase = "NULL"
    if "TEMPORAL" in dictResults["CVSS"]:
      iCVSSTemp = ConvertFloat(dictResults["CVSS"]["TEMPORAL"])
    else:
      iCVSSTemp = "NULL"
  else:
    iCVSSTemp = "NULL"
    iCVSSBase = "NULL"


  if "SOLUTION" in dictResults:
    strSolution = DBClean(dictResults["SOLUTION"])
  else:
    strSolution = ""

  if "CONSEQUENCE" in dictResults:
    strConsequence = DBClean(dictResults["CONSEQUENCE"])
  else:
    strConsequence = ""

  if "DIAGNOSIS" in dictResults:
    strDiagnosis = DBClean(dictResults["DIAGNOSIS"])
  else:
    strDiagnosis = ""

  strdbNow = time.strftime("%Y-%m-%d %H:%M:%S")
  strSQL = "select * from tblVulnDetails where iQID = {};".format(dictResults["QID"])
  lstReturn = SQLQuery (strSQL,dbConn)
  if not ValidReturn(lstReturn):
    LogEntry ("Unexpected: {}".format(lstReturn))
    sys.exit(9)
  elif len(lstReturn[1]) == 0:
    LogEntry ("Adding QID {} {}".format(dictResults["QID"],dictResults["TITLE"] ))
    try:
      strSQL = ("INSERT INTO tblVulnDetails (iQID, iSeverity, vcTitle, vcCategory, dtLastServiceModified, dtPublished,"
                " bPatchable, tDiagnosis, tSolution, iCVSSBase, iCVSSTemporal, bPCIFlag, bRemoteDisc, tAdditionalInfo, "
                " tConsequence,dtLastTouched) "
                "VALUES('{0}','{1}','{2}','{3}','{4}','{5}','{6}','{7}','{8}',{9},{10},'{11}','{12}','{13}','{14}','{15}');".format(
                dictResults["QID"],dictResults["SEVERITY_LEVEL"],DBClean(dictResults["TITLE"]),DBClean(dictResults["CATEGORY"]),
                QDate2DB(dictResults["LAST_SERVICE_MODIFICATION_DATETIME"]), QDate2DB(dictResults["PUBLISHED_DATETIME"]),
                dictResults["PATCHABLE"],strDiagnosis,strSolution,iCVSSBase,iCVSSTemp,dictResults["PCI_FLAG"],strRemoteDisc,
                strAddDetail,strConsequence,strdbNow
            )
          )
    except KeyError as e:
      LogEntry ("KeyError during insert into tblVulnDetails: {}".format(e),True)
  elif len(lstReturn[1]) == 1:
    LogEntry ("QID {} exists, need to update record for {}".format(dictResults["QID"],dictResults["TITLE"] ))
    try:
      strSQL = ("UPDATE tblVulnDetails SET iSeverity = '{}', vcTitle = '{}', vcCategory = '{}', "
                " dtLastServiceModified = '{}', dtPublished = '{}', bPatchable = '{}',tConsequence = '{}',"
            " tDiagnosis = '{}',tSolution = '{}', iCVSSBase = {}, iCVSSTemporal = {}, bPCIFlag = '{}', "
            " bRemoteDisc = '{}', tAdditionalInfo = '{}', dtLastTouched = '{}' "
            " WHERE iQID = '{}'; ".format(
            dictResults["SEVERITY_LEVEL"],DBClean(dictResults["TITLE"]),DBClean(dictResults["CATEGORY"]),
            QDate2DB(dictResults["LAST_SERVICE_MODIFICATION_DATETIME"]),
            QDate2DB(dictResults["PUBLISHED_DATETIME"]),dictResults["PATCHABLE"],strConsequence, strDiagnosis,
            strSolution,iCVSSBase,iCVSSTemp,dictResults["PCI_FLAG"],strRemoteDisc,strAddDetail,strdbNow,dictResults["QID"]
            )
        )
    except KeyError as e:
      LogEntry ("KeyError during update of tblVulnDetails: {}".format(e),True)
  else:
    LogEntry ("Something is horrible wrong, there are {} entries with QID of {}".format(len(lstReturn[1]),dictResults["QID"]),True)
  lstReturn = SQLQuery (strSQL,dbConn)
  if not ValidReturn(lstReturn):
    LogEntry ("Unexpected: {}".format(lstReturn))
    LogEntry (strSQL)
    CleanExit("due to unexpected SQL return, please check the logs")
  elif lstReturn[0] != 1:
    LogEntry ("Records affected {}, expected 1 record affected when updating tblVulnDetails".format(len(lstReturn[1])))

  iUpdateCount += 1
  if "BUGTRAQ_LIST" in dictResults:
    strSQL = "delete from tblQID2Bugtraq where iQID = {};".format(dictResults["QID"])
    lstReturn = SQLQuery (strSQL,dbConn)
    if not ValidReturn(lstReturn):
      LogEntry ("Unexpected: {}".format(lstReturn))
      CleanExit("due to unexpected SQL return, please check the logs")
    else:
      LogEntry ("Deleted {} QID to bugtraq mappings".format(lstReturn[0]))


    if isinstance(dictResults["BUGTRAQ_LIST"]["BUGTRAQ"] ,list):
      LogEntry("{} bugtraq's on this QID".format(len(dictResults["BUGTRAQ_LIST"]["BUGTRAQ"])))
      lstTemp = dictResults["BUGTRAQ_LIST"]["BUGTRAQ"]
    else:
      lstTemp = [dictResults["BUGTRAQ_LIST"]["BUGTRAQ"]]
      LogEntry("Only one bugtraq on this QID")

    for dictBugTraq in lstTemp:
      strSQL = "select * from tblBugTraq where iBugTraqID = {};".format(dictBugTraq["ID"])
      lstReturn = SQLQuery (strSQL,dbConn)
      LogEntry("Records affected: {}".format(len(lstReturn[1])))
      if not ValidReturn(lstReturn):
        LogEntry ("Unexpected: {}".format(lstReturn))
        CleanExit("due to unexpected SQL return, please check the logs")
      elif len(lstReturn[1]) == 0:
        LogEntry ("bugtraq ID {} doesn't exists, inserting it".format(dictBugTraq["ID"]))
        strSQL = "INSERT INTO tblBugTraq (iBugTraqID,vcURL) VALUES ({}, '{}');".format(dictBugTraq["ID"],dictBugTraq["URL"])
        lstReturn = SQLQuery (strSQL,dbConn)
        if not ValidReturn(lstReturn):
          LogEntry ("Unexpected: {}".format(lstReturn))
          CleanExit("due to unexpected SQL return, please check the logs")
      else:
        LogEntry("bugtraq ID {} already exists, not doing anything".format(dictBugTraq["ID"]))

      strSQL = "INSERT INTO tblQID2Bugtraq (iQID,iBugTraqID) VALUES ({},{});".format(dictResults["QID"],dictBugTraq["ID"])
      lstReturn = SQLQuery (strSQL,dbConn)
      if not ValidReturn(lstReturn):
        LogEntry ("Unexpected: {}".format(lstReturn))
        CleanExit("due to unexpected SQL return, please check the logs")
  else:
    LogEntry("No bugtraq in this one")

  if "CVE_LIST" in dictResults:
    strSQL = "delete from tblQID2CVE where iQID = {};".format(dictResults["QID"])
    lstReturn = SQLQuery (strSQL,dbConn)
    if not ValidReturn(lstReturn):
      LogEntry ("Unexpected: {}".format(lstReturn))
      CleanExit("due to unexpected SQL return, please check the logs")
    else:
      LogEntry ("Deleted {} QID to CVE mappings".format(lstReturn[0]))


    if isinstance(dictResults["CVE_LIST"]["CVE"],list):
      LogEntry("{} CVE's on this QID".format(len(dictResults["CVE_LIST"]["CVE"])))
      lstTemp = dictResults["CVE_LIST"]["CVE"]
    else:
      lstTemp = [dictResults["CVE_LIST"]["CVE"]]
      LogEntry("Only one CVE on this QID")

    for dictCVEs in lstTemp:
      strSQL = "select * from tblCVEs where vcCVEID = '{}';".format(dictCVEs["ID"])
      lstReturn = SQLQuery (strSQL,dbConn)
      LogEntry("Records affected: {}".format(len(lstReturn[1])))
      if not ValidReturn(lstReturn):
        LogEntry ("Unexpected: {}".format(lstReturn))
        CleanExit("due to unexpected SQL return, please check the logs")
      elif len(lstReturn[1]) == 0:
        LogEntry ("CVE ID {} doesn't exists, inserting it".format(dictCVEs["ID"]))
        strSQL = "INSERT INTO tblCVEs (vcCVEID,vcURL) VALUES ('{}', '{}');".format(dictCVEs["ID"],dictCVEs["URL"])
        lstReturn = SQLQuery (strSQL,dbConn)
        if not ValidReturn(lstReturn):
          LogEntry ("Unexpected: {}".format(lstReturn))
          CleanExit("due to unexpected SQL return, please check the logs")
      else:
        LogEntry("CVE ID {} already exists, not doing anything".format(dictCVEs["ID"]))

      strSQL = "INSERT INTO tblQID2CVE (iQID,vcCVEID) VALUES ({},'{}');".format(dictResults["QID"],dictCVEs["ID"])
      lstReturn = SQLQuery (strSQL,dbConn)
      if not ValidReturn(lstReturn):
        LogEntry ("Unexpected: {}".format(lstReturn))
        CleanExit("due to unexpected SQL return, please check the logs")
  else:
    LogEntry("No CVE in this one")


def ProcessResponse(APIResponse):
  global iUpdateCount
  global iMinQID
  iRowCount = 0
  if isinstance(APIResponse,str):
    LogEntry(APIResponse)
  if isinstance(APIResponse,dict):
    if "VULN_LIST" in APIResponse["KNOWLEDGE_BASE_VULN_LIST_OUTPUT"]["RESPONSE"]:
      if "VULN" in APIResponse["KNOWLEDGE_BASE_VULN_LIST_OUTPUT"]["RESPONSE"]["VULN_LIST"]:
        if isinstance(APIResponse["KNOWLEDGE_BASE_VULN_LIST_OUTPUT"]["RESPONSE"]["VULN_LIST"]["VULN"],list):
          iRowCount = len(APIResponse["KNOWLEDGE_BASE_VULN_LIST_OUTPUT"]["RESPONSE"]["VULN_LIST"]["VULN"])
          LogEntry ("{} QIDs in results".format(iRowCount))
          for dictVuln in APIResponse["KNOWLEDGE_BASE_VULN_LIST_OUTPUT"]["RESPONSE"]["VULN_LIST"]["VULN"]:
            UpdateDB (dictVuln)
        else:
          LogEntry ("Only one QID in results")
          iRowCount = 1
          UpdateDB (APIResponse["KNOWLEDGE_BASE_VULN_LIST_OUTPUT"]["RESPONSE"]["VULN_LIST"]["VULN"])
      else:
        LogEntry("there is vulnerabitlity list but no vulnerabitlities, weird!!!!")
    else:
      LogEntry ("There are no results")
      iMinQID = iStopNum + 100
    if "WARNING" in APIResponse["KNOWLEDGE_BASE_VULN_LIST_OUTPUT"]["RESPONSE"]:
      strURL = APIResponse["KNOWLEDGE_BASE_VULN_LIST_OUTPUT"]["RESPONSE"]["WARNING"]["URL"]
      LogEntry ("Next URL: {}".format(strURL))
      APIResponse = MakeAPICall(strURL,strHeader,strUserName,strPWD,strMethod)
      ProcessResponse(APIResponse)


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
  LogEntry (strSQL,True)
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
  dbConn.close()
  dbConn = ""
  LogEntry ("Either the script is already running or it's been less that {0} min since it last run, "
    " please wait until after {0} since last run. Exiting".format(iMinQuietTime))
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
  CleanExit("due to unexpected SQL return, please check the logs")
elif lstReturn[0] != 1:
  LogEntry ("Records affected {}, expected 1 record affected when inserting int tblScriptExecuteList".format(len(lstReturn[1])))

strSQL = ("select iExecuteID,dtStartTime from tblScriptExecuteList where iExecuteID in "
  " (select max(iExecuteID) from tblScriptExecuteList where vcScriptName = '{}');".format(strScriptName))
lstReturn = SQLQuery (strSQL,dbConn)
if not ValidReturn(lstReturn):
  LogEntry ("Unexpected: {}".format(lstReturn))
  CleanExit("due to unexpected SQL return, please check the logs")
elif len(lstReturn[1]) != 1:
  LogEntry ("Records affected {}, expected 1 record affected when finding iEntryID".format(len(lstReturn[1])))
  iEntryID = -10
  dtStartTime = strdbNow
else:
  iEntryID = lstReturn[1][0][0]
  dtStartTime = lstReturn[1][0][1]

LogEntry("Recorded start entry, ID {}".format(iEntryID))


iRowNum = 1
iUpdateCount = 0
iMinQID = 0
iMaxQID = iMinQID + iBatchSize


strAPIFunction = "/api/2.0/fo/knowledge_base/vuln/"

if strAPIFunction[0] == "/":
  strAPIFunction = strAPIFunction[1:]

if strAPIFunction[-1:] != "/":
  strAPIFunction += "/"

strMethod = "get"
dictParams = {}
dictParams["action"] = "list"
dictParams["show_supported_modules_info"] = "1"

while iMaxQID < iStopNum:
  dictParams["id_min"] = iMinQID
  dictParams["id_max"] = iMaxQID
  strListScans = urlparse.urlencode(dictParams)
  strURL = strBaseURL + strAPIFunction +"?" + strListScans
  APIResponse = MakeAPICall(strURL,strHeader,strUserName,strPWD,strMethod)
  strdbNow = time.strftime("%Y-%m-%d %H:%M:%S")
  strSQL = ("update tblScriptExecuteList set dtStopTime='{}', bComplete=0, iRowsUpdated={} "
              " where iExecuteID = {} ;".format(strdbNow,iUpdateCount,iEntryID))
  lstReturn = SQLQuery (strSQL,dbConn)
  if not ValidReturn(lstReturn):
    LogEntry ("Unexpected: {}".format(lstReturn))
  elif lstReturn[0] != 1:
    LogEntry ("Records affected {}, expected 1 record affected when updating tblScriptExecuteList".format(len(lstReturn[1])))
  ProcessResponse(APIResponse)
  iRowNum += 1
  iMinQID = iMaxQID + 1
  iMaxQID = iMinQID + iBatchSize

LogEntry ("Doing validation checks")
strSQL = "select count(*) from tblVulnDetails where dtLastTouched > '{}';".format(dtStartTime)
lstReturn = SQLQuery (strSQL,dbConn)
if not ValidReturn(lstReturn):
  LogEntry ("Unexpected: {}".format(lstReturn))
  CleanExit("due to unexpected SQL return, please check the logs")
else:
  iCountVulnChange = lstReturn[1][0][0]

LogEntry ("VALIDATE: Total Number of vulnerabitlities downloaded {}; "
  " Total number of vulnerabitlities updated in the database {}".format(iUpdateCount,iCountVulnChange))
if iUpdateCount != iCountVulnChange:
  LogEntry ("VALIDATE: KB validation failed")
  SendNotification("{} has completed processing on {}, and validation checks failed".format(strScriptName,strScriptHost))
else:
  LogEntry ("VALIDATE: KB validation successful")
  SendNotification("{} has completed processing on {}, validation checks are good. "
            " Processed {} vulnerabitlities.".format(strScriptName,strScriptHost,iUpdateCount))

strdbNow = time.strftime("%Y-%m-%d %H:%M:%S")
LogEntry("Updating completion entry")
strSQL = ("update tblScriptExecuteList set dtStopTime='{}' , bComplete=1, "
        " iRowsUpdated={} where iExecuteID = {} ;".format(strdbNow,iUpdateCount,iEntryID))
lstReturn = SQLQuery (strSQL,dbConn)
if not ValidReturn(lstReturn):
  LogEntry ("Unexpected: {}".format(lstReturn))
LogEntry ("All Done!")
dbConn.close()
objLogOut.close()
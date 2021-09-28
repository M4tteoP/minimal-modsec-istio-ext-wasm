#include "rules.h"
//##############################
//##      Hardcoded Rules     ##
//##############################
//by https://www.cescaper.com/
//json escape post cescaper for yaml config: https://jsonformatter.curiousconcept.com/# 


// Default Config Rules
// TODO merge modsecurity.conf + crs-setup.conf
// SecRuleEngine On 
// crs_setup_version indispensabile per far funzionare il CRS
/*
SecRuleEngine DetectionOnly
SecRequestBodyAccess On
SecRuleEngine On
SecDebugLogLevel 9
SecRequestBodyLimit 13107200
SecRequestBodyNoFilesLimit 131072
SecRequestBodyLimitAction Reject
SecDefaultAction "phase:1,log,auditlog,deny,status:403"
SecDefaultAction "phase:2,log,auditlog,deny,status:403"
SecCollectionTimeout 600
SecAction "id:900990,phase:1,nolog,pass,t:none,setvar:tx.crs_setup_version=332"
SecAction "id:900100,phase:1,nolog,pass,t:none,setvar:tx.critical_anomaly_score=5,setvar:tx.error_anomaly_score=4,setvar:tx.warning_anomaly_score=3,setvar:tx.notice_anomaly_score=2"
*/
std::string defaultConfigRules = "SecRuleEngine Detect"
   "ionOnly\r\n"
   "SecRequestBodyAccess"
   " On\r\n"
   "SecRuleEngine On\r\n"
   "SecDebugLogLevel 9\r"
   "\n"
   "SecRequestBodyLimit "
   "13107200\r\n"
   "SecRequestBodyNoFile"
   "sLimit 131072\r\n"
   "SecRequestBodyLimitA"
   "ction Reject\r\n"
   "SecDefaultAction \"p"
   "hase:1,log,auditlog,"
   "deny,status:403\"\r"
   "\n"
   "SecDefaultAction \"p"
   "hase:2,log,auditlog,"
   "deny,status:403\"\r"
   "\n"
   "SecCollectionTimeout"
   " 600\r\n"
   "SecAction \"id:90099"
   "0,phase:1,nolog,pass"
   ",t:none,setvar:tx.cr"
   "s_setup_version=332"
   "\"\r\n"
   "SecAction \"id:90010"
   "0,phase:1,nolog,pass"
   ",t:none,setvar:tx.cr"
   "itical_anomaly_score"
   "=5,setvar:tx.error_a"
   "nomaly_score=4,setva"
   "r:tx.warning_anomaly"
   "_score=3,setvar:tx.n"
   "otice_anomaly_score="
   "2\"";

// Default xss Rules
// TODO merge XSS CRS
/*
SecRule ARGS|REQUEST_HEADERS "@rx <script>" "id:101,msg:'XSS Attack',severity:ERROR,deny,status:404"
*/
// std::string xssRules = "SecRule ARGS|REQUEST"
//    "_HEADERS \"@rx <scri"
//    "pt>\" \"id:101,msg:"
//    "\'XSS Attack\',sever"
//    "ity:CRITICAL,deny,statu"
//    "s:404\"";


std::string xssRules = "SecRule REQUEST_COOK"
   "IES|!REQUEST_COOKIES"
   ":/__utm/|REQUEST_COO"
   "KIES_NAMES|REQUEST_F"
   "ILENAME|REQUEST_HEAD"
   "ERS:User-Agent|REQUE"
   "ST_HEADERS:Referer|A"
   "RGS_NAMES|ARGS|XML:/"
   "* \"@rx (?i)<script["
   "^>]*>[\\s\\S]*?\" \\"
   "\r\n"
   "    \"id:941110,\\\r"
   "\n"
   "    phase:2,\\\r\n"
   "    block,\\\r\n"
   "    capture,\\\r\n"
   "    t:none,t:utf8toU"
   "nicode,t:urlDecodeUn"
   "i,t:htmlEntityDecode"
   ",t:jsDecode,t:cssDec"
   "ode,t:removeNulls,\\"
   "\r\n"
   "    msg:\'XSS Filter"
   " - Category 1: Scrip"
   "t Tag Vector\',\\\r"
   "\n"
   "    logdata:\'Matche"
   "d Data: %{TX.0} foun"
   "d within %{MATCHED_V"
   "AR_NAME}: %{MATCHED_"
   "VAR}\',\\\r\n"
   "    tag:\'applicatio"
   "n-multi\',\\\r\n"
   "    tag:\'language-m"
   "ulti\',\\\r\n"
   "    tag:\'platform-m"
   "ulti\',\\\r\n"
   "    tag:\'attack-xss"
   "\',\\\r\n"
   "    tag:\'paranoia-l"
   "evel/1\',\\\r\n"
   "    tag:\'OWASP_CRS"
   "\',\\\r\n"
   "    tag:\'capec/1000"
   "/152/242\',\\\r\n"
   "    ctl:auditLogPart"
   "s=+E,\\\r\n"
   "    ver:\'OWASP_CRS/"
   "3.3.2\',\\\r\n"
   "    severity:\'CRITI"
   "CAL\',\\\r\n"
   "    setvar:\'tx.xss_"
   "score=+%{tx.critical"
   "_anomaly_score}\',\\"
   "\r\n"
   "    setvar:\'tx.anom"
   "aly_score_pl1=+%{tx."
   "critical_anomaly_sco"
   "re}\'\"";

// Default sqli Rules
// TODO at least a dummy SQLI RULE
/*
....
*/
std::string sqliRules = "SecRule ARGS|REQUEST"
   "_HEADERS \"@rx <sqli"
   ">\" \"id:103,msg:"
   "\'sqli\',sever"
   "ity:ERROR,deny,statu"
   "s:404\"";
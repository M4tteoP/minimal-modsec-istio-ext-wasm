#include "rules.h"
//##############################
//##      Hardcoded Rules     ##
//##############################
//by https://www.cescaper.com/
//json escape post cescaper for yaml config: https://jsonformatter.curiousconcept.com/# 


// Default Config Rules
// TODO merge modsecurity.conf + crs-setup.conf
// SecRuleEngine On 
/*
SecRuleEngine DetectionOnly
SecRequestBodyAccess On
SecRuleEngine On
SecDebugLogLevel 9
SecDefaultAction "phase:1,log,auditlog,deny,status:403"
SecDefaultAction "phase:2,log,auditlog,deny,status:403"
*/
std::string defaultConfigRules = "SecRuleEngine Detect"
   "ionOnly\r\n"
   "SecRequestBodyAccess"
   " On\r\n"
   "SecRuleEngine On\r\n"
   "SecDebugLogLevel 9\r"
   "\n"
   "SecDefaultAction \"p"
   "hase:1,log,auditlog,"
   "deny,status:403\"\r"
   "\n"
   "SecDefaultAction \"p"
   "hase:2,log,auditlog,"
   "deny,status:403\"";

// Default xss Rules
// TODO merge XSS CRS
/*
SecRule ARGS|REQUEST_HEADERS "@rx <script>" "id:101,msg:'XSS Attack',severity:ERROR,deny,status:404"
*/
std::string xssRules = "SecRule ARGS|REQUEST"
   "_HEADERS \"@rx <scri"
   "pt>\" \"id:101,msg:"
   "\'XSS Attack\',sever"
   "ity:CRITICAL,deny,statu"
   "s:404\"";

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
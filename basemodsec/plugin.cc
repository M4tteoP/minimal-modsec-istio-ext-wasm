#include <stdio.h>
#include <strings.h>
#include <errno.h>
#include "plugin.h"


using ::nlohmann::json;
using ::Wasm::Common::JsonArrayIterate;
using ::Wasm::Common::JsonGetField;
using ::Wasm::Common::JsonObjectIterate;
using ::Wasm::Common::JsonValueAs;

// Boilderplate code to register the extension implementation.
static RegisterContextFactory register_Example(CONTEXT_FACTORY(PluginContext), ROOT_FACTORY(PluginRootContext));

//################################################
//##              Support Functions             ##
//################################################ 

inline std::string BoolToString(bool b){
  return b ? "true" : "false";
}

inline void printInterventionRet(std::string mainfunc, std::string func, int intervention_ret){
std::string outinter{""};
outinter += "[";
outinter += mainfunc;
outinter += "] ";
outinter += func;
outinter += " intervention_ret = ";
outinter += std::to_string(intervention_ret);
logWarn(outinter);
outinter="";
}

bool extractBoolFromJSON(const json& configuration, std::string key, bool* bool_ptr) {
  std::string temp_value;
  auto it = configuration.find(key);
  if (it != configuration.end()) {
    auto parse_result = JsonValueAs<std::string>(it.value());
    if (parse_result.second != Wasm::Common::JsonParserResultDetail::OK ||
        !parse_result.first.has_value()) {
      LOG_WARN(absl::StrCat("failed to parse field ", key));
      return false;
    }
    temp_value = parse_result.first.value();
    // modSecConfig.detect_sqli = (temp_value == YES);  mi piace ma poco restrittivo
    if(temp_value == YES){
      *bool_ptr = true;
    }else if(temp_value == NO){
      *bool_ptr = false;
    }
  }else{
    LOG_WARN(absl::StrCat("Missing field ", key));
  }
  return true;
}

bool extractJSON(const json& configuration, PluginRootContext::ModSecConfigStruct *modSecConfig) {

  // Check if DEFAULT CONFIG RULES must be enabled
  if(!extractBoolFromJSON(configuration, DEFAULT_KEY, &modSecConfig->enable_default)){
    LOG_WARN(absl::StrCat("failed to parse configuration for ", DEFAULT_KEY,". Set by default as true"));
    modSecConfig->enable_default = true;
  }

  // Check SQLI detection
  if(!extractBoolFromJSON(configuration, SQLI_KEY, &modSecConfig->detect_sqli)){
    LOG_WARN(absl::StrCat("failed to parse configuration for ", SQLI_KEY,". Set by default as false"));
    modSecConfig->detect_sqli = false;
  }
  
  // Check XSS detection
  if(!extractBoolFromJSON(configuration, XSS_KEY, &modSecConfig->detect_xss)){
    LOG_WARN(absl::StrCat("failed to parse configuration for ", XSS_KEY,". Set by default as false"));
    modSecConfig->detect_xss = false;
  }

  // Check and populate CUSTOM RULES (iterate over them)
  if (!JsonArrayIterate(
          configuration, CUSTOM_KEY, [&](const json& rule) -> bool {
            auto rule_string = JsonValueAs<std::string>(rule);
            if (rule_string.second != Wasm::Common::JsonParserResultDetail::OK) {
              return false;
            }
            modSecConfig->custom_rules.push_back(rule_string.first.value());
            return true;
          })) {
    LOG_WARN(absl::StrCat("failed to parse configuration for ",CUSTOM_KEY,". No custom rules will be applied"));
    return false;
  }
  if (modSecConfig->custom_rules.size() <= 0) {
    LOG_WARN("No custom rules loaded");
  }
  return true;
}

// TODO remove char request_uri[] = "/wp-config.php";
char request_uri[] = "/test.php";

char request_body_first[] = "" \
    "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n\r" \
    "<soap:Envelope xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" " \
    "xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" ";
char request_body_second[] = "" \
    "xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\">\n\r" \
    "  <soap:Body>\n\r" \
    "  <EnlightenResponse xmlns=\"http://clearforest.com/\">\n\r" \
    "  <EnlightenResult>string</EnlightenResult>\n\r";
char request_body_third[] = "" \
    "  </EnlightenResponse>\n\r" \
    "  </soap:Body>\n\r" \
    "</soap:Envelope>\n\r";

char response_body_first[] = "" \
    "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n\r" \
    "<soap:Envelope xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" " \
    "xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" ";
char response_body_second[] = "" \
    "xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\">\n\r" \
    "  <soap:Body>\n\r" \
    "  <EnlightenResponse xmlns=\"http://clearforest.com/\">\n\r" \
    "  <EnlightenResult>string</EnlightenResult>\n\r";
char response_body_third[] = "" \
    "  </EnlightenResponse>\n\r" \
    "  </soap:Body>\n\r" \
    "</soap:Envelope>\n\r";

char ip[] = "200.249.12.31";

//by https://www.cescaper.com/
// attenzione anche agli escape del JSON, usare https://jsonformatter.curiousconcept.com/# post cescaper

//###########################
//##     Hardcoded Rule    ##
//###########################

// Default Config Rules
// TODO merge modsecurity.conf + crs-setup.conf
/*
SecRuleEngine DetectionOnly
SecRequestBodyAccess On
SecRuleEngine On
SecDebugLogLevel 9
SecDefaultAction "phase:1,log,auditlog,deny,status:403"
SecDefaultAction "phase:2,log,auditlog,deny,status:403"
*/
char defaultConfigRules[] = "SecRuleEngine Detect"
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

   

//##############################
//##     Reaction function    ##
//##############################

static void logCb(void *data, const void *ruleMessagev) {
    if (ruleMessagev == NULL) {
          logWarn("I've got a call but the message was null ;(\n");
        return;
    }

    const modsecurity::RuleMessage *ruleMessage = reinterpret_cast<const modsecurity::RuleMessage *>(ruleMessagev);
    std::string output{""};
    output += "Rule Id: ";
    output += std::to_string(ruleMessage->m_ruleId);
    output += " phase: ";
    output += std::to_string(ruleMessage->m_phase);
    output += "\n";
    if (ruleMessage->m_isDisruptive) {
        output += " * Disruptive action: ";
        output += modsecurity::RuleMessage::log(ruleMessage);
        output += "\n";
        output += " ** %d is meant to be informed by the webserver.";
        output += "\n";
    } else {
        output += " * Match, but no disruptive action: ";
        output += modsecurity::RuleMessage::log(ruleMessage);
        output += "\n";
    }
      logWarn(output);
}

int process_intervention(modsecurity::Transaction *transaction) {
    modsecurity::ModSecurityIntervention intervention;
    intervention.status = 200;
    intervention.url = NULL;
    intervention.log = NULL;
    intervention.disruptive = 0;
    std::string output{""};

    if (msc_intervention(transaction, &intervention) == 0) {
        LOG_WARN("[msc_intervention] returning here");
        return 0;
    }

    if (intervention.log == NULL) {
        intervention.log = strdup("(no log message was specified)");
    }

    output += "Log: ";
    output += intervention.log;
    output += "\n";
    free(intervention.log);
    intervention.log = NULL;

    if (intervention.url != NULL) {
        output += "Intervention, redirect to: ";
        output += intervention.url;
        output += " with status code: ";
        output += intervention.status;
        output += "\n";
        free(intervention.url);
        intervention.url = NULL;
        LOG_WARN(output);
        return intervention.status;
    }

    if (intervention.status != 200) {
        output += "Intervention, returning code: ";
        output += std::to_string(intervention.status);
        output += "\n";
        LOG_WARN(output);
        return intervention.status;
    }
    LOG_WARN(output);
    return 0;
}


//######################################################
//######################################################
//######################################################

bool PluginRootContext::onConfigure(size_t size) {
  // Parse configuration JSON string from YAML file
  if (size > 0 && !configure(size)) {
    LOG_WARN("configuration has errors initialization will not continue.");
    return false;
  }
  // modSecConfig struct populated with configuration requests.
  std::string output{""};
  
  /**
   * ModSecurity initial setup
   *
   */
    modsec = new modsecurity::ModSecurity();
    modsec->setConnectorInformation("ModSecurity-test v0.0.1-alpha (ModSecurity test)");
    modsec->setServerLogCb(logCb, modsecurity::RuleMessageLogProperty | modsecurity::IncludeFullHighlightLogProperty);

    output += "\n";
    output += "ModSecurity initial setup done";
    output += "\n";
    logWarn(output);

    /**
    * loading the rules....
    *
    */
    rules = new modsecurity::RulesSet();

    std::string rulesConcat{""};
        
    if(modSecConfig.enable_default==true){
      rulesConcat+=defaultConfigRules;
      rulesConcat+="\n";
    }
    if(modSecConfig.detect_xss==true){
      rulesConcat+=xssRules;
      rulesConcat+="\n";
    }
    if(modSecConfig.detect_sqli==true){
      rulesConcat+=sqliRules;
      rulesConcat+="\n";
    }

    // merging custom Rules with predefined ones
    if (modSecConfig.custom_rules.size() > 0) {  
      for (auto i = modSecConfig.custom_rules.begin(); i != modSecConfig.custom_rules.end(); ++i){
        rulesConcat+=*i;
        rulesConcat+="\n";
      }
    }

    if (rules->load(rulesConcat.c_str()) < 0){
        
        output += absl::StrCat("Problems loading the rules...\n", rules->m_parserError.str(), "\n");
        logWarn(output);
        return -1;
    }
    
    output += "\nRules Loaded\n";
    logWarn(output);

    return true;
}

bool PluginRootContext::configure(size_t configuration_size) {
  auto configuration_data = getBufferBytes(WasmBufferType::PluginConfiguration, 0, configuration_size);
  // Parse configuration JSON string.
  auto result = ::Wasm::Common::JsonParse(configuration_data->view());
  if (!result.has_value()) {
    LOG_WARN(absl::StrCat("cannot parse configuration JSON string: ", configuration_data->view()));
    return false;
  }
  // j is a JsonObject holds configuration data
  auto j = result.value();
  if (!JsonArrayIterate(j, JSON_NAME, [&](const json& configuration) -> bool {
                          return extractJSON(configuration, &modSecConfig);
                        })) {
    // TODO: atm never reached. Enabled default values if errors on parsing json
    LOG_WARN(absl::StrCat("cannot parse plugin configuration JSON string: ",configuration_data->view()));
    return false;
  }

  // Print the whole config file just for debug purposes
  LOG_WARN(absl::StrCat("modSecConfig->enable_default: ", BoolToString(modSecConfig.enable_default)));
  LOG_WARN(absl::StrCat("modSecConfig->detect_sqli: ", BoolToString(modSecConfig.detect_sqli)));
  LOG_WARN(absl::StrCat("modSecConfig->detect_xss: ", BoolToString(modSecConfig.detect_xss)));
  std::string output{"\n"};
  if (modSecConfig.custom_rules.size() > 0) {
    for (auto i = modSecConfig.custom_rules.begin(); i != modSecConfig.custom_rules.end(); ++i){
        output+=*i;
        output+="\n";
      }
    LOG_WARN(output);
  }

  return true;
}

bool PluginRootContext::initprocess(modsecurity::Transaction * modsecTransaction) {
  std::string output{""};

  // starting transaction
  
  printInterventionRet("initprocess","starting",process_intervention(modsecTransaction));

  // connection setup
  // TODO REAL DATA
  // getValue({"request", "url_path"}, &request_info->url_path);
  modsecTransaction -> processConnection(ip, 12345, "127.0.0.1", 80);
  printInterventionRet("initprocess","processConnection",process_intervention(modsecTransaction));



  output += "[initprocess] Connetion setup done\n";
  logWarn(output);
  output = "";

  // add URI
  // TODO REAL URI
  // request_operation
  modsecTransaction -> processURI(request_uri, "GET", "1.1"); 
  
  // process URI
  printInterventionRet("initprocess","processURI",process_intervention(modsecTransaction));

  output += "[initprocess] Url added\n";
  logWarn(output);
  output = "";

  return true;
}

bool PluginRootContext::myProcessRequestHeaders() {
  // DEBUG PURPOSES
  // printing all the headers

  // std::string headers_string{"\n=== Starting Intercepting Headers ===\n"};
  // for (auto& pair : pairs) { // pair è puntatore
  //   headers_string += (std::string(pair.first) + std::string(" : ") + std::string(pair.second)+ std::string("\n"));
  // }
  // headers_string += std::string("\n=== Ending Intercepting Headers ===\n");
  // logWarn(headers_string);

  //delete modsecTransaction;
  return true;
}


FilterHeadersStatus PluginContext::onRequestHeaders(uint32_t, bool) {
  int ret=0;
  std::string keyUri{":path"};
  std::string errorUri{"/error"};

  // beginning of the transaction
  modsecurity::Transaction* modsecTransaction = new modsecurity::Transaction(rootContext()->modsec, rootContext()->rules, NULL);
  std::string output{""};

  // TODO manage returns from initprocess
  rootContext()->initprocess(modsecTransaction);

  // intercepting and collecting all the headers
  // std::vector<std::pair<std::string_view, StringView>>
  LOG_WARN(std::string("onRequestHeaders ") + std::to_string(id()));
  auto result = getRequestHeaderPairs();
  auto pairs = result->pairs();
  LOG_WARN(std::string("headers: ") + std::to_string(pairs.size()));
  
  // printing all the headers - DEBUG PURPOSES
  for (auto& p : pairs) {
    LOG_WARN(std::string(p.first) + std::string(" -> ") + std::string(p.second));
  }


  // adding Headers to the transaction
  // modsecTransaction -> addRequestHeader("Host","net.tutsplus.com<script>alert('0')</script>");
  for (auto& pair : pairs) { // pair è puntatore
    modsecTransaction -> addRequestHeader(std::string(pair.first),std::string(pair.second));
  }
  ret=process_intervention(modsecTransaction);
  printInterventionRet("onRequestHeaders","addRequestHeader",ret);
  if(ret!=0){
    replaceRequestHeader(keyUri,errorUri);
    return FilterHeadersStatus::ContinueAndEndStream;
  }

  output += "Request Headers added\n";
  logWarn(output);
  output = "";

  // process Headers
  modsecTransaction -> processRequestHeaders();
  ret=process_intervention(modsecTransaction);
  printInterventionRet("onRequestHeaders","processRequestHeaders",ret);
  if(ret!=0){
    replaceRequestHeader(keyUri,errorUri);
    return FilterHeadersStatus::ContinueAndEndStream;
  }
 
  output += "Request Headers processed with no detection\n";
  logWarn(output);
  output = "";
  
  return FilterHeadersStatus::Continue;
}


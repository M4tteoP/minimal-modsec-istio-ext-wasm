#include <stdio.h>
#include <strings.h>
#include <errno.h>
#include "plugin.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_split.h"
#include "extensions/common/wasm/base64.h"
#include "extensions/common/wasm/json_util.h"
#include "modsec/include/modsecurity/rule_message.h"
#include "modsec/include/modsecurity/modsecurity.h"
#include "modsec/include/modsecurity/rules_set.h"

using ::nlohmann::json;
using ::Wasm::Common::JsonArrayIterate;
using ::Wasm::Common::JsonGetField;
using ::Wasm::Common::JsonObjectIterate;
using ::Wasm::Common::JsonValueAs;

// Boilderplate code to register the extension implementation.
static RegisterContextFactory register_Example(CONTEXT_FACTORY(PluginContext),
                                               ROOT_FACTORY(PluginRootContext));

//################################################
//##              Support Functions             ##
//################################################ 

inline std::string BoolToString(bool b){
  return b ? "true" : "false";
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

  // Check SQLI detection
  if(!extractBoolFromJSON(configuration, SQLI_KEY, &modSecConfig->detect_sqli)){
    LOG_WARN(absl::StrCat("failed to parse configuration for ", SQLI_KEY));
    return false;
  }
  
  // Check XSS detection
  if(!extractBoolFromJSON(configuration, XSS_KEY, &modSecConfig->detect_xss)){
    LOG_WARN(absl::StrCat("failed to parse configuration for ", XSS_KEY));
    return false;
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
    LOG_WARN(absl::StrCat("failed to parse configuration for ",CUSTOM_KEY));
    return false;
  }
  if (modSecConfig->custom_rules.size() <= 0) {
    LOG_WARN("No custom rules loaded");
  }
  return true;
}

char request_uri[] = "/wp-config.php";

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

//###########################
//##     Hardcoded Rule    ##
//###########################


char customHardcodedRule[] = "SecDebugLog /dev/std"
   "out\r\n"
   "SecDebugLogLevel 1\r"
   "\n"
   "SecRule RESPONSE_BOD"
   "Y \"/soap:Body\" \"i"
   "d:1,phase:5,deny\"\r"
   "\n"
   "SecRule ARGS|REQUEST"
   "_HEADERS “@rx <scrip"
   "t>” \"id:101,msg:\'X"
   "SS Attack\',severity"
   ":ERROR,deny,status:4"
   "04\"\r\n"
   "SecRule REQUEST_URI "
   "\"@streq /wp-config."
   "php\" \"id:102,phase"
   ":1,t:lowercase,deny"
   "\"";

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
        logWarn(output);
        return intervention.status;
    }

    if (intervention.status != 200) {
        output += "Intervention, returning code: ";
        output += intervention.status;
        output += "\n";
        logWarn(output);
        return intervention.status;
    }
    logWarn(output);
    return 0;
}


//################################################
//################################################
//################################################ 

bool PluginRootContext::onConfigure(size_t size) {
  // Parse configuration JSON string from YAML file
  if (size > 0 && !configure(size)) {
    LOG_WARN("configuration has errors initialization will not continue.");
    return false;
  }
  // modSecConfig struct populated with configuration requests.

  modsecurity::ModSecurity *modsec;
  modsecurity::RulesSet *rules;
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

    std::string customRules{""};
    for (auto i = modSecConfig.custom_rules.begin(); i != modSecConfig.custom_rules.end(); ++i){
      customRules+=*i;
      customRules+="\n"; // todo vedere se serve \r\n o solo \n
    }
    // from string to char[] for load()

    // TODO preparare versione dummy di regola fissa e se c'è il boolean una un più la si aggiunge


    if (rules->load(customRules.c_str()) < 0){ // TODO se non funziona https://www.journaldev.com/37220/convert-string-to-char-array-c-plus-plus
        output += "Problems loading the rules...";
        output += "\n";
        output += rules->m_parserError.str();
        output += "\n";
        logWarn(output);
        return -1;
    }
    
    output += "\n";
    output += "Rules Loaded";
    output += "\n";
    logWarn(output);
    output = "";

    /**
     * We are going to have a transaction
     *
     */
    modsecurity::Transaction *modsecTransaction = new modsecurity::Transaction(modsec, rules, NULL);
    process_intervention(modsecTransaction);

    /**
     * Initial connection setup
     *
     */
    modsecTransaction->processConnection(ip, 12345, "127.0.0.1", 80);
    process_intervention(modsecTransaction);

    output += "Connetion setup done";
    output += "\n";
    logWarn(output);
    output = "";
    
    /**
     * Finally we've got the URI
     *
     */
    modsecTransaction->processURI(request_uri, "GET", "1.1");
    process_intervention(modsecTransaction);
    
    output += "Url added";
    output += "\n";
    logWarn(output);
    output = "";


    /**
     * Lets add our request headers.
     *
     */
    modsecTransaction->addRequestHeader("Host",
        "net.tutsplus.com");
    process_intervention(modsecTransaction);

    output += "Request Headers added";
    output += "\n";
    logWarn(output);
    output = "";
    /**
     * No other reuqest header to add, let process it.
     *
     */
    modsecTransaction->processRequestHeaders();
    process_intervention(modsecTransaction);

    output += "Request Headers processed";
    output += "\n";
    logWarn(output);
    output = "";

    // [...]

    /**
     * cleanup.
     */
    delete modsecTransaction;
    delete rules;
    delete modsec;

    output += "Cleanup done";
    output += "\n";
    logWarn(output);
    output = "";



  return true;
}

bool PluginRootContext::configure(size_t configuration_size) {
  auto configuration_data = getBufferBytes(WasmBufferType::PluginConfiguration,
                                           0, configuration_size);
  // Parse configuration JSON string.
  auto result = ::Wasm::Common::JsonParse(configuration_data->view());
  if (!result.has_value()) {
    LOG_WARN(absl::StrCat("cannot parse configuration JSON string: ", configuration_data->view()));
    return false;
  }
  // j is a JsonObject holds configuration data
  auto j = result.value();
  if (!JsonArrayIterate(j, JSON_NAME,
                        [&](const json& configuration) -> bool {
                          return extractJSON(configuration, &modSecConfig);
                        })) {
    LOG_WARN(absl::StrCat("cannot parse plugin configuration JSON string: ",
                          configuration_data->view()));
    return false;
  }

  // Print the whole config file just for debug purposes
  LOG_WARN(absl::StrCat("modSecConfig->detect_sqli: ", BoolToString(modSecConfig.detect_sqli))); 
  LOG_WARN(absl::StrCat("modSecConfig->detect_xss: ", BoolToString(modSecConfig.detect_xss)));
  std::string output{""};
  for (auto i = modSecConfig.custom_rules.begin(); i != modSecConfig.custom_rules.end(); ++i){
      output+=*i;
      output+="\n";
    }
  LOG_WARN(output);

  return true;
}

FilterHeadersStatus PluginContext::onRequestHeaders(uint32_t, bool) {
  // intercepting and printing all the headers
  // std::vector<std::pair<std::string_view, StringView>>
  auto pairs = getRequestHeaderPairs()->pairs();

  std::string headers_string{"\n=== Starting Intercepting Headers ===\n"};
  for (auto& pair : pairs) { // pair è puntatore
    headers_string += (std::string(pair.first) + std::string(" : ") + std::string(pair.second)+ std::string("\n"));
  }
  headers_string += std::string("=== Ending Intercepting Headers ===\n");
  logWarn(headers_string);

  return FilterHeadersStatus::Continue;
}

#include <stdio.h>
#include <strings.h>
#include <errno.h>
#include "plugin.h"


using ::nlohmann::json;
using ::Wasm::Common::JsonArrayIterate;
using ::Wasm::Common::JsonGetField;
using ::Wasm::Common::JsonObjectIterate;
using ::Wasm::Common::JsonValueAs;

// WASM_PROLOG
#ifndef NULL_PLUGIN
#include "proxy_wasm_intrinsics.h"

#else  // NULL_PLUGIN

#include "include/proxy-wasm/null_plugin.h"

using proxy_wasm::WasmHeaderMapType;
using proxy_wasm::null_plugin::getHeaderMapValue;
using proxy_wasm::null_plugin::getProperty;
using proxy_wasm::null_plugin::getValue;

#endif  // NULL_PLUGIN

// END WASM_PROLOG


#include "rules.h"

// Boilderplate code to register the extension implementation.
static RegisterContextFactory register_Example(CONTEXT_FACTORY(PluginContext), ROOT_FACTORY(PluginRootContext));

//################################################
//##              Support Functions             ##
//################################################ 

inline std::string BoolToString(bool b){
  return b ? "true" : "false";
}

inline void printInterventionRet(std::string mainfunc, std::string func, int intervention_ret){
  logWarn(absl::StrCat("[", mainfunc, "] ", func, " intervention_ret = ", std::to_string(intervention_ret)));
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

// TODO remove useless stack chars
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
    output += absl::StrCat("Rule Id: ", std::to_string(ruleMessage->m_ruleId), " phase: ", std::to_string(ruleMessage->m_phase), "\n");
    if (ruleMessage->m_isDisruptive) {
        output += absl::StrCat(" * Disruptive action: ", modsecurity::RuleMessage::log(ruleMessage), "\n ** %d is meant to be informed by the webserver.\n");
    } else {
        output += absl::StrCat(" * Match, but no disruptive action: ", modsecurity::RuleMessage::log(ruleMessage), "\n");
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

    output += absl::StrCat("Log: ", intervention.log, "\n";
    free(intervention.log);
    intervention.log = NULL;

    if (intervention.url != NULL) {
        output += absl::StrCat("Intervention, redirect to: ", intervention.url, " with status code: ", intervention.status, "\n");
        free(intervention.url);
        intervention.url = NULL;
        LOG_WARN(output);
        return intervention.status;
    }

    if (intervention.status != 200) {
        output += absl::StrCat("Intervention, returning code: ", std::to_string(intervention.status), "\n");
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
  
  // ModSecurity setup
  modsec = new modsecurity::ModSecurity();
  modsec->setConnectorInformation("ModSecurity-test v0.0.1-alpha (ModSecurity test)");
  modsec->setServerLogCb(logCb, modsecurity::RuleMessageLogProperty | modsecurity::IncludeFullHighlightLogProperty);

  output += "\nModSecurity initial setup done\n";
  logWarn(output);
  
  // Concatenation of the provided rules and loading
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
  if (modSecConfig.custom_rules.size() > 0){  
    for (auto i = modSecConfig.custom_rules.begin(); i != modSecConfig.custom_rules.end(); ++i){
      rulesConcat+=*i;
      rulesConcat+="\n";
    }
  }

  // Loading rules
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
  std::string output{"modSecConfig->custom_rules:\n"};
  if (modSecConfig.custom_rules.size() > 0) {
    for (auto i = modSecConfig.custom_rules.begin(); i != modSecConfig.custom_rules.end(); ++i){
        output+=*i;
        output+="\n";
      }
    LOG_WARN(output);
  }

  return true;
}

bool PluginRootContext::initprocess(modsecurity::Transaction * modsecTransaction){
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
  // TODO REAL URI. GET/POST prenderlo dall' header, sempre con getValue
  // request_operation
  modsecTransaction -> processURI(request_uri, "GET", "1.1"); 
  
  // process URI
  printInterventionRet("initprocess","processURI",process_intervention(modsecTransaction));

  output += "[initprocess] Url added\n";
  logWarn(output);
  output = "";

  return true;
}

FilterHeadersStatus PluginContext::onRequestHeaders(uint32_t, bool) {
  int ret=0;
  //std::string keyUri{":path"};
  //std::string errorUri{"/error"};

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
    alertActionHeader(ret);
  }

  output += "Request Headers added\n";
  logWarn(output);
  output = "";

  // process Headers
  modsecTransaction -> processRequestHeaders();
  ret=process_intervention(modsecTransaction);
  printInterventionRet("onRequestHeaders","processRequestHeaders",ret);
  if(ret!=0){
    alertActionHeader(ret);
  }
 
  output += "Request Headers processed with no detection\n";
  logWarn(output);
  output = "";

  // Testing getValue
  /*
  getValue({"cluster_name"}, &request_info->upstream_cluster);
  getValue({"route_name"}, &request_info->route_name);
  getValue({"request", "headers", "x-b3-sampled"}, &trace_sampled)
  getValue({"request", "url_path"}, &request_info->url_path);
  getValue({"request", "path"}, &request_info->path);
  getValue({"request", "host"}, &request_info->url_host);
  getValue({"request", "scheme"}, &request_info->url_scheme);
  getValue({"source", "address"}, &request_info->source_address);
  getValue({"destination", "address"}, &request_info->destination_address);
  getValue({"source", "port"}, &request_info->source_port);
  getValue({"destination", "port"}, &request_info->source_port);
  getValue({"upstream", "address"}, &request_info->upstream_host);
  getValue({"upstream", "port"}, &destination_port);
  */

  std::string pippo{""};
  getValue({"cluster_name"}, &pippo);
  logWarn(absl::StrCat(pippo,"\n"));
  getValue({"route_name"}, &pippo);
  logWarn(absl::StrCat(pippo,"\n"));
  getValue({"request", "headers", "x-b3-sampled"}, &pippo);
  logWarn(absl::StrCat(pippo,"\n"));
  getValue({"request", "url_path"}, &pippo);
  logWarn(absl::StrCat(pippo,"\n"));
  getValue({"request", "path"}, &pippo);
  logWarn(absl::StrCat(pippo,"\n"));
  getValue({"request", "host"}, &pippo);
  logWarn(absl::StrCat(pippo,"\n"));
  getValue({"request", "scheme"}, &pippo);
  logWarn(absl::StrCat(pippo,"\n"));
  getValue({"source", "address"}, &pippo);
  logWarn(absl::StrCat(pippo,"\n"));
  getValue({"destination", "address"}, &pippo);
  logWarn(absl::StrCat(pippo,"\n"));
  uint64_t aaa;
  getValue({"source", "port"},&aaa);
  logWarn(absl::StrCat(std::to_string(aaa),"\n"));
  getValue({"destination", "port"}, &aaa);
  logWarn(absl::StrCat(std::to_string(aaa),"\n"));
  getValue({"upstream", "address"}, &pippo);
  logWarn(absl::StrCat(pippo,"\n"));
  getValue({"upstream", "port"}, &aaa);
  logWarn(absl::StrCat(std::to_string(aaa),"\n"));
  
  return FilterHeadersStatus::Continue;
}



FilterDataStatus PluginContext::onRequestBody(unsigned long body_buffer_length, bool end_of_stream) {
  int ret=0;

  // beginning of the transaction
  modsecurity::Transaction* modsecTransaction = new modsecurity::Transaction(rootContext()->modsec, rootContext()->rules, NULL);
  
  // TODO manage returns from initprocess
  rootContext()->initprocess(modsecTransaction);
  
  auto body = getBufferBytes(WasmBufferType::HttpRequestBody, 0, body_buffer_length);
  std::string bodyString = std::string(body->view());
  logWarn(absl::StrCat("[onRequestBody] bodyString = \n", bodyString));

  // TODO remove, static version of request body
    // modsecTransaction->appendRequestBody(
    //     (const unsigned char*)request_body_first,
    //     strlen((const char*)request_body_first));
    // process_intervention(modsecTransaction);
    // modsecTransaction->processRequestBody();
    // process_intervention(modsecTransaction);A


  // adding Body to the transaction
  modsecTransaction->appendRequestBody((const unsigned char*)bodyString.c_str(),bodyString.length());
  process_intervention(modsecTransaction);
  if(ret!=0){
    alertActionBody(ret);
  }

  logWarn("Request Body added\n");

  // Process body
  modsecTransaction->processRequestBody();
  process_intervention(modsecTransaction);
  if(ret!=0){
    alertActionBody(ret);
  }

  logWarn("Request Body processed with no detection\n");

  return FilterDataStatus::Continue;
}


/*
// Ref sendLocalResponse: https://github.com/proxy-wasm/proxy-wasm-cpp-sdk/blob/master/proxy_wasm_api.h
// signature: 
    inline WasmResult sendLocalResponse(uint32_t response_code, std::string_view response_code_details,
                                    std::string_view body,
                                    const HeaderStringPairs &additional_response_headers,
                                    GrpcStatus grpc_status = GrpcStatus::InvalidCode) {
*/
FilterHeadersStatus PluginContext::alertActionHeader(int response){
    sendLocalResponse(403, absl::StrCat("Request dropped by alertActionHeader response= ",std::to_string(response)), "", {});
    return FilterHeadersStatus::StopIteration;
}

FilterDataStatus PluginContext::alertActionBody(int response){
    sendLocalResponse(403, absl::StrCat("Request dropped by alertActionBody response= ",std::to_string(response)), "", {});
    return FilterDataStatus::StopIterationNoBuffer;
}

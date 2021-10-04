#include <stdio.h>
#include <strings.h>
#include <errno.h>
#include "plugin.h"
#ifndef NULL_PLUGIN // WASM_PROLOG
  #include "proxy_wasm_intrinsics.h"
#else  // NULL_PLUGIN
  #include "include/proxy-wasm/null_plugin.h"
  using proxy_wasm::WasmHeaderMapType;
  using proxy_wasm::null_plugin::getProperty;
  using proxy_wasm::null_plugin::getValue;
#endif

using ::nlohmann::json;
using ::Wasm::Common::JsonArrayIterate;
using ::Wasm::Common::JsonGetField;
using ::Wasm::Common::JsonObjectIterate;
using ::Wasm::Common::JsonValueAs;

// inclusion of hardcoded rules
#include "rules.h"

// uncomment DEBUG definition to compile the wasm with each request/response complete log on sidecar (istio-proxy) log.s
#define DEBUG 1

// Registration of the extension implementation.
static RegisterContextFactory register_Example(CONTEXT_FACTORY(PluginContext), ROOT_FACTORY(PluginRootContext));

//################################################
//##              Support Functions             ##
//################################################

inline std::string boolToString(bool b){
  return b ? "true" : "false";
}

inline std::string removeFromDelimiter(std::string input, std::string delimiter){
  return input.substr(0, input.find(delimiter));
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
    if(temp_value == YES){
      *bool_ptr = true;
    }else if(temp_value == NO){
      *bool_ptr = false;
    }
  }else{
    LOG_WARN(absl::StrCat("[extractBoolFromJSON] Missing field ", key));
  }
  return true;
}

bool extractJSON(const json& configuration, PluginRootContext::ModSecConfigStruct *modSecConfig) {

  // Basic config rules for Modsecurity
    if(!extractBoolFromJSON(configuration, DEFAULT_KEY, &modSecConfig->enable_default)){
    LOG_WARN(absl::StrCat("failed to parse configuration for ", DEFAULT_KEY,". Set by default as true"));
    modSecConfig->enable_default = true; // default case: true
  }

  // Core Rule Set
    if(!extractBoolFromJSON(configuration, CRS_KEY, &modSecConfig->enable_crs)){
    LOG_WARN(absl::StrCat("failed to parse configuration for ", CRS_KEY,". Set by default as true"));
    modSecConfig->enable_crs = true; // default case: true
  }

  // Check SQLI detection
  // example of configuration flexibility. Users may disable crs but still activate specific detections.
  // if crs is true, sqli is implicitly true
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

//##############################
//##     Reaction function    ##
//##############################

static void logCb(void *data, const void *ruleMessagev) {
    if (ruleMessagev == NULL) {
          LOG_WARN("[logCb] call with ruleMessagev = NULL\n");
        return;
    }

    const modsecurity::RuleMessage *ruleMessage = reinterpret_cast<const modsecurity::RuleMessage *>(ruleMessagev);
    std::string output{"[logCb]"};
    output += absl::StrCat("Rule Id: ", std::to_string(ruleMessage->m_ruleId), " phase: ", std::to_string(ruleMessage->m_phase), "\n");
    if (ruleMessage->m_isDisruptive) {
        output += absl::StrCat(" * Match of disruptive action: ", modsecurity::RuleMessage::log(ruleMessage), "\n ** %d is meant to be informed by the webserver.\n");
    } else {
        output += absl::StrCat(" * Match of no disruptive action: ", modsecurity::RuleMessage::log(ruleMessage), "\n");
    }
      logWarn(output);
}

int process_intervention(modsecurity::Transaction *transaction) {
    modsecurity::ModSecurityIntervention intervention;
    intervention.status = 200;
    intervention.url = NULL;
    intervention.log = NULL;
    intervention.disruptive = 1;  // TODO check param https://github.com/SpiderLabs/ModSecurity/blob/v3/master/src/transaction.cc#L1433
    std::string output{"[process_intervention] "};

    if (msc_intervention(transaction, &intervention) == 0) {
        #ifdef DEBUG
        LOG_WARN("[process_intervention][msc_intervention] returning here");
        #endif
        return 0;
    }

    if (intervention.log == NULL) {
        intervention.log = strdup("(no log message was specified)");
    }

    // Check: working on removing useless "Log: (no log message was specified)" showed in the log.
    if(intervention.status!=200){
      output += absl::StrCat("Log: ", intervention.log, "intervention.status = ", std::to_string(intervention.status) , "\n");
      free(intervention.log);
      intervention.log = NULL;
    }

    if (intervention.url != NULL) {
      output += absl::StrCat("Intervention, redirect to: ", intervention.url, " with status code: ", std::to_string(intervention.status), "\n");
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

//#######################################################
//##              Root Callbacks Functions             ##
//#######################################################
// Root context, configuration of main elements that will have the life of the VM.

bool PluginRootContext::onConfigure(size_t size) {
  // Parse configuration JSON string from YAML file
  if (size > 0 && !configure(size)) {
    LOG_WARN("[onConfigure][configure] FATAL ERROR: JSON configuration inside YAML file has errors initialization.");
    return false;
  }
  // now modSecConfig struct is populated with the configuration requested

  // ModSecurity setup
  modsec = new modsecurity::ModSecurity();
  // TODO update this value
  modsec->setConnectorInformation("ModSecurity-test v0.0.1-alpha (WASM ModSecurity test)");
  modsec->setServerLogCb(logCb, modsecurity::RuleMessageLogProperty | modsecurity::IncludeFullHighlightLogProperty);

  LOG_WARN("[onConfigure] ModSecurity initial setup done");

  // Concatenation of the requested rules and loading
  rules = new modsecurity::RulesSet();

  std::string rulesConcat{""};

  if(modSecConfig.enable_default==true){
    rulesConcat+=defaultConfigRules;
    rulesConcat+="\n";
  }
  if(modSecConfig.enable_crs==true){
    rulesConcat+=crsRules;
    rulesConcat+="\n";
  }else{
    // just an example of possible flexible rule implementation
    // xss and sqli are already included inside crs. I take into account these values only if crs is disabled
    if(modSecConfig.detect_xss==true){
      rulesConcat+=xssRules;
      rulesConcat+="\n";
    }
    if(modSecConfig.detect_sqli==true){
      rulesConcat+=sqliRules;
      rulesConcat+="\n";
    }
  }

  // merging custom Rules with predefined ones
  if (modSecConfig.custom_rules.size() > 0){
    for (auto i = modSecConfig.custom_rules.begin(); i != modSecConfig.custom_rules.end(); ++i){
      rulesConcat+=*i;
      rulesConcat+="\n";
    }
  }

  #ifdef DEBUG
  LOG_WARN(absl::StrCat("[onConfigure][DEBUG] rulesConcat:\n",rulesConcat)); // Printing all the rules that are going to be loaded
  #endif

  // Loading rules
  if (rules->load(rulesConcat.c_str()) < 0){
      LOG_WARN(absl::StrCat("[onConfigure] FATAL ERROR: Problems loading the rules\n", rules->m_parserError.str(), "\n"));
      return false;
  }

  LOG_WARN("[onConfigure] Modsecurity Rules Loaded");

  return true;
}

bool PluginRootContext::configure(size_t configuration_size) {
  WasmDataPtr configuration_data = getBufferBytes(WasmBufferType::PluginConfiguration, 0, configuration_size);
  // Parse configuration JSON string.
  auto result = ::Wasm::Common::JsonParse(configuration_data->view());
  if (!result.has_value()) {
    LOG_WARN(absl::StrCat("[configure] Cannot parse configuration JSON string: ", configuration_data->view()));
    return false;
  }
  // j is a JsonObject holds configuration data
  auto j = result.value();
  if (!JsonArrayIterate(j, JSON_NAME, [&](const json& configuration) -> bool {
                          return extractJSON(configuration, &modSecConfig);
                        })) {
    // check: atm never reached. Enabled default values if errors on parsing json
    LOG_WARN(absl::StrCat("[configure] cannot parse plugin configuration JSON string: ",configuration_data->view()));
    return false;
  }

  // Print the whole config file just for debug purposes
  LOG_WARN("[configure] Recap of configuration read by YAML file:");
  LOG_WARN(absl::StrCat("modSecConfig->enable_default: ", boolToString(modSecConfig.enable_default)));
  LOG_WARN(absl::StrCat("modSecConfig->enable_crs: ", boolToString(modSecConfig.enable_crs)));
  LOG_WARN(absl::StrCat("modSecConfig->detect_sqli: ", boolToString(modSecConfig.detect_sqli)));
  LOG_WARN(absl::StrCat("modSecConfig->detect_xss: ", boolToString(modSecConfig.detect_xss)));
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


//#########################################################
//##              Stream Callbacks Functions             ##
//#########################################################
// The scope of PluginContext is limited to the single request
// Deallocation of elements must be performed meticulously

//########################################
//#         onRequestHeaders             #
//########################################
FilterHeadersStatus PluginContext::onRequestHeaders(uint32_t, bool) {
  int ret=0;
  std::string method;
  int body_size = 0;

  // Beginning of the transaction, generation of the object inside the context of this request.
  modsecTransaction = new modsecurity::Transaction(rootContext()->modsec, rootContext()->rules, NULL);

  if(initTransaction()!=0){
    return alertActionHeader(ret);
  }

  // Collecting all the headers
  WasmDataPtr result = getRequestHeaderPairs();
  std::vector<std::pair<std::string_view,std::string_view>> pairs = result->pairs();
  
  #ifdef DEBUG
  LOG_WARN(std::string("[onRequestHeaders][DEBUG] id:") + std::to_string(id()));
  LOG_WARN(std::string("[onRequestHeaders][DEBUG] #headers: ") + std::to_string(pairs.size()));
  for (auto& p : pairs) { // printing all the headers
    LOG_WARN(std::string(p.first) + std::string(" -> ") + std::string(p.second));
  }
  #endif

  // adding headers to the transaction
  for (auto& pair : pairs) {
    modsecTransaction -> addRequestHeader(std::string(pair.first),std::string(pair.second));
    // retrieveing size of the body
    if(pair.first == "content-length"){
      body_size = std::stoi(std::string(pair.second));
    }
  }
  ret=process_intervention(modsecTransaction);
  printInterventionRet("onRequestHeaders","addRequestHeader",ret);
  if(ret!=0){
    return alertActionHeader(ret);
  }

  LOG_WARN("[onRequestHeaders] Request Headers added\n");

  // process Headers
  if(modsecTransaction -> processRequestHeaders()){
    LOG_WARN("[onRequestHeaders][processRequestHeaders] correctly executed");
  }else{
    LOG_WARN("[onRequestHeaders][processRequestHeaders][!] Errors on processing request headers");
  }
  ret = process_intervention(modsecTransaction);
  printInterventionRet("onRequestHeaders","processRequestHeaders",ret);
  if(ret != 0){
    return alertActionHeader(ret);
  }

  getValue({"request", "headers", ":method"}, &method);
  // getValue({"request", "headers", "content-length"}, &body_size);  // TODO fix. atm retrieved from the for

  #ifdef DEBUG
  LOG_WARN(absl::StrCat("[onRequestHeaders][DEBUG] method: ",method, " content-length: ", std::to_string(body_size)));
  #endif

  // if request has NO body (typically GET requests), we still want to analyze the headers with modSec (typical CRS rules at phase:2)
  if(method == "GET" || body_size == 0){
    // I add an empty body to the process
    modsecTransaction->appendRequestBody((const unsigned char*)"",1);
    ret=process_intervention(modsecTransaction);
    printInterventionRet("onRequestHeaders","appendRequestBody (empty)",ret);
    if(ret!=0){
      return alertActionHeader(ret);
    }
    // I process it
    if(modsecTransaction->processRequestBody()){
      LOG_WARN("[onRequestHeaders][processRequestBody] (empty) correctly executed");
    }else{
      LOG_WARN("[onRequestHeaders][processRequestBody][!](empty) Errors on processing the request body");
    }
    ret=process_intervention(modsecTransaction);
    printInterventionRet("onRequestHeaders","processRequestBody (empty)",ret);
    if(ret!=0){
      return alertActionHeader(ret);
    }
  }

  LOG_WARN("[onRequestHeaders] Request Headers processed with no detection\n");

  return FilterHeadersStatus::Continue;
}

//#######################################
//#         initTransaction             #
//#######################################
int PluginContext::initTransaction(){
  int ret=0;
  std::string clientIP;
  uint64_t clientPort;
  std::string serverIP;
  uint64_t serverPort;
  std::string uri;
  std::string method;
  std::string version;

  // starting transaction
  ret = process_intervention(modsecTransaction);
  printInterventionRet("initTransaction","starting",ret);
  if(ret != 0){
    return ret;
  }

  // connection setup

  // Retrieving basic information of the connection
  // depending on WAF position deployment, some information may be not so relevant (e.g. internal IP as source address)
  getValue({"source", "address"}, &clientIP);
  clientIP = removeFromDelimiter(clientIP,":");
  getValue({"source", "port"}, &clientPort);
  getValue({"destination", "address"}, &serverIP);
  serverIP = removeFromDelimiter(serverIP,":");
  getValue({"destination", "port"}, &serverPort);

  LOG_WARN(absl::StrCat("[initTransaction] New connection ", clientIP,":",std::to_string(clientPort)," -> ",serverIP,":",std::to_string(serverPort)));

  // processing basic information
  modsecTransaction -> processConnection(clientIP.c_str(), clientPort, serverIP.c_str(), serverPort);
  ret = process_intervention(modsecTransaction);
  printInterventionRet("initTransaction","processConnection",ret);
  if(ret != 0){
    return ret;
  }

  LOG_WARN("[initTransaction] Connection setup done");

  // Retrieving further information of the connection
  getValue({"request", "headers", ":path"}, &uri); // URI x-envoy-original-path se path modificato con rewrite
  getValue({"request", "headers", ":method"}, &method); // GET/POST
  // TODO, not yet implemented http version distinction https://github.com/istio/proxy/blob/master/extensions/common/context.cc#L508
  version = "1.1";

  LOG_WARN(absl::StrCat("[initTransaction] method: ", method," version: ", version, " path: ", uri));

  modsecTransaction->processURI(uri.c_str(), method.c_str(), version.c_str());

  // process URI
  ret = process_intervention(modsecTransaction);
  printInterventionRet("initTransaction","processURI",ret);
  if(ret != 0){
    return ret;
  }

  logWarn("[initTransaction] URI information added\n");

  return 0;
}

//#####################################
//#         onRequestBody             #
//#####################################
FilterDataStatus PluginContext::onRequestBody(unsigned long body_buffer_length, bool end_of_stream) {
  int ret=0;

  WasmDataPtr body = getBufferBytes(WasmBufferType::HttpRequestBody, 0, body_buffer_length);
  std::string bodyString = std::string(body->view());

  if(modsecTransaction == NULL){
    // Should never happen, body arrived without previously handled headers;
    // Log and drop the request
    LOG_WARN("[onRequestBody][!] ERROR: Body received with modsecTransaction = NULL");
    #ifdef DEBUG
    LOG_WARN(absl::StrCat("[onRequestBody][DEBUG][!] bodyString = \n", bodyString));
    #endif
    return alertActionBody(-1);
  }

  #ifdef DEBUG
  LOG_WARN(absl::StrCat("[onRequestBody][DEBUG] bodyString = \n", bodyString));
  #endif

  // adding Body to the transaction
  modsecTransaction->appendRequestBody((const unsigned char*)bodyString.c_str(),bodyString.length());

  ret=process_intervention(modsecTransaction);
  if(ret!=0){
    return alertActionBody(ret);
  }

  LOG_WARN("[onRequestBody] Request Body added");

  // Process body
  if(modsecTransaction->processRequestBody()){
    LOG_WARN("[onRequestBody][processRequestBody] Correctly executed");
  }else{
    LOG_WARN("[onRequestBody][processRequestBody][!] Errors on processing the requet body");
  }

  ret=process_intervention(modsecTransaction);
  if(ret!=0){
    return alertActionBody(ret);
  }

  logWarn("[onRequestBody] Request Body processed with no detection\n");

  return FilterDataStatus::Continue;
}

//#########################################
//#         onResponseHeaders             #
//#########################################
FilterHeadersStatus PluginContext::onResponseHeaders(uint32_t, bool) {
  int ret=0;
  int response_status=200;

  // Collecting all the headers
  WasmDataPtr result = getResponseHeaderPairs();
  std::vector<std::pair<std::string_view,std::string_view>> pairs = result->pairs();

  if(modsecTransaction == NULL){
    // Should never happen, the request should have generated the context
    // Log and drop
    LOG_WARN("[onResponseHeaders][!] ERROR: Response Headers received with modsecTransaction = NULL");
    #ifdef DEBUG
    LOG_WARN(std::string("[onResponseHeaders][DEBUG][!] Printing response headers: ") + std::to_string(pairs.size()));
    for (std::pair<std::string_view,std::string_view> &p : pairs) {
      LOG_WARN(std::string(p.first) + std::string(" -> ") + std::string(p.second));
    }
    #endif
    return alertActionHeader(-1);
  }
  #ifdef DEBUG
  LOG_WARN(std::string("[onResponseHeaders][DEBUG] Printing response headers: ") + std::to_string(pairs.size()));
  for (std::pair<std::string_view,std::string_view> &p : pairs) {
    LOG_WARN(std::string(p.first) + std::string(" -> ") + std::string(p.second));
  }
  #endif

  // adding headers to the modsec transaction
  for (std::pair<std::string_view,std::string_view>& pair : pairs) {
    modsecTransaction -> addResponseHeader(std::string(pair.first),std::string(pair.second));
    if(pair.first == ":status"){
     response_status = std::stoi(std::string(pair.second));
    }
  }

  #ifdef DEBUG
  LOG_WARN(absl::StrCat("[onResponseHeaders][DEBUG] response status: ", std::to_string(response_status)));
  #endif

  ret=process_intervention(modsecTransaction);
  printInterventionRet("onResponseHeaders","addResponseHeader",ret);
  if(ret!=0){
    return alertActionHeader(ret);
  }

  LOG_WARN("[onResponseHeaders] Request Headers added\n");

  // process response Headers
  // TODO: HTTP version
  // https://github.com/SpiderLabs/ModSecurity/blob/bf881a4eda343d37629e39ede5e28b70dc4067c0/src/transaction.cc#L1048
  modsecTransaction->processResponseHeaders(response_status,"HTTP 1.1");
  ret=process_intervention(modsecTransaction);
  printInterventionRet("onResponseHeaders","processResponseHeaders",ret);
  if(ret!=0){
    return alertActionHeader(ret);
  }

  LOG_WARN("[onResponseHeaders] Request Headers processed with no detection\n");
  return FilterHeadersStatus::Continue;
}

//######################################
//#         onResponseBody             #
//######################################
// Example of setting a response: setBuffer(WasmBufferType::HttpResponseBody, 0, 12, "Hello, world");
FilterDataStatus PluginContext::onResponseBody(unsigned long body_buffer_length, bool end_of_stream){
  int ret=0;
  WasmDataPtr responseBody = getBufferBytes(WasmBufferType::HttpResponseBody, 0, body_buffer_length);
  std::string responseBodyString = std::string(responseBody->view());

  if(modsecTransaction == NULL){
    // Should never happen, the request should have generated the context
    // Log and drop
    LOG_WARN("[onResponseBody][!] ERROR: Response Body received with modsecTransaction = NULL");
    #ifdef DEBUG
    LOG_WARN(absl::StrCat("[onResponseBody][DEBUG][!] responseBodyString = \n", responseBodyString));
    #endif
    return alertActionBody(-1);
  }

  #ifdef DEBUG
  LOG_WARN(absl::StrCat("[onResponseBody][DEBUG] responseBodyString = \n", responseBodyString));
  #endif

  // adding response body to the transaction
  modsecTransaction->appendResponseBody((const unsigned char*)responseBodyString.c_str(),responseBodyString.length());

  ret=process_intervention(modsecTransaction);
  if(ret!=0){
    return alertActionBody(ret);
  }

  LOG_WARN("[onResponseBody] Response Body added");

  // Processing response body
  if(modsecTransaction->processResponseBody()){
    LOG_WARN("[onResponseBody] processResponseBody() correctly executed");
  }else{
    LOG_WARN("[onResponseBody][!] Errors on performing processResponseBody()");
  }
  ret=process_intervention(modsecTransaction);
  if(ret!=0){
    return alertActionBody(ret);
  }

  logWarn("[onResponseBody] Response Body processed with no detection\n");
  return FilterDataStatus::Continue;
}

//################################
//#         onDelete             #
//################################
// Vital callback: at the end of the stream, the modsec object must be deallocated
void PluginContext::onDelete(){
  delete modsecTransaction;
  modsecTransaction = NULL;
  LOG_WARN(std::string("[onDelete][OK] " + std::to_string(id())));
}

//###################################
//#         Alert Functions         #
//###################################
/*
// Ref sendLocalResponse: https://github.com/proxy-wasm/proxy-wasm-cpp-sdk/blob/master/proxy_wasm_api.h
// inline WasmResult sendLocalResponse(uint32_t response_code, std::string_view response_code_details,
                                    std::string_view body,
                                    const HeaderStringPairs &additional_response_headers,
                                    GrpcStatus grpc_status = GrpcStatus::InvalidCode) {
*/
FilterHeadersStatus PluginContext::alertActionHeader(int response){
    sendLocalResponse(403, absl::StrCat("Dropped by alertActionHeader response= ",std::to_string(response)), "", {});
    return FilterHeadersStatus::StopIteration;
}

FilterDataStatus PluginContext::alertActionBody(int response){
    sendLocalResponse(403, absl::StrCat("Dropped by alertActionBody response= ",std::to_string(response)), "", {});
    return FilterDataStatus::StopIterationNoBuffer;
}

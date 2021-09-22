#include <assert.h>
#include <string>
#include <vector>
#include "proxy_wasm_intrinsics.h"

#define ASSERT(_X) assert(_X)
static const std::string EMPTY_STRING;

#include "absl/strings/str_cat.h"
#include "absl/strings/str_split.h"
#include "extensions/common/wasm/base64.h"
#include "extensions/common/wasm/json_util.h"
#include "modsec/include/modsecurity/rule_message.h"
#include "modsec/include/modsecurity/modsecurity.h"
#include "modsec/include/modsecurity/rules_set.h"

// My custom JSON words
#define JSON_NAME "modsec_config"
#define SQLI_KEY "sqli"
#define XSS_KEY "xss"
#define CUSTOM_KEY "custom_rules"
#define YES "yes"
#define NO "no"

class PluginRootContext : public RootContext {
 public:
  explicit PluginRootContext(uint32_t id, std::string_view root_id) : RootContext(id, root_id) {}
  ~PluginRootContext(){
    delete rules;
    delete modsec;
    std::string output{"Cleanup done\n"};
    logWarn(output);
  }
  bool onConfigure(size_t) override;

  struct ModSecConfigStruct {
    bool detect_sqli;
    bool detect_xss;
    std::vector<std::string> custom_rules;
  };

 private:
  bool configure(size_t);
  //bool extractJSON( const json& configuration, PluginRootContext::ModSecConfigStruct* modSecConfig);
  PluginRootContext::ModSecConfigStruct modSecConfig;
  modsecurity::ModSecurity *modsec;
  modsecurity::RulesSet *rules;
};

class PluginContext : public Context {
 public:
  explicit PluginContext(uint32_t id, RootContext* root) : Context(id, root) {}

  FilterHeadersStatus onRequestHeaders(uint32_t, bool) override;

 private:
  inline PluginRootContext* rootContext() {
    return dynamic_cast<PluginRootContext*>(this->root());
  }
};


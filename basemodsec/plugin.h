#include <assert.h>
#include <string>
#include <vector>
#include "proxy_wasm_intrinsics.h"

#define ASSERT(_X) assert(_X)
static const std::string EMPTY_STRING;

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


load("@proxy_wasm_cpp_sdk//bazel/wasm:wasm.bzl", "wasm_cc_binary")

wasm_cc_binary(
    name = "basemodsec.wasm",
    srcs = [
        "plugin.cc",
        "plugin.h",
        "rules.cc",
        "rules.h",
        "@io_istio_proxy//extensions/common/wasm:base64.h",
    ],
    deps = [
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/time",
        "@io_istio_proxy//extensions/common/wasm:json_util",
        "@proxy_wasm_cpp_sdk//:proxy_wasm_intrinsics",
        ":libpcre",
        ":libmodsecurity",
    ],
    copts = [
    "-Imodsec/include/",
    "-Ipcre/include/"
    ],
)

cc_library(
    name = "json_libinj",
    srcs = [
        "plugin.cc",
        "@io_istio_proxy//extensions/common/wasm:base64.h",
    ],
    hdrs = [
        "plugin.h",
    ],
    copts = ["-DNULL_PLUGIN"],
    deps = [
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/time",
        "@io_istio_proxy//extensions/common/wasm:json_util",
        "@proxy_wasm_cpp_host//:lib",
    ],
)

cc_import(
    name = "libmodsecurity",
    static_library = "modsec/lib/libmodsecurity.a",
    hdrs = [
        "modsec/include/modsecurity/actions/action.h",
        "modsec/include/modsecurity/collection/collection.h",
        "modsec/include/modsecurity/collection/collections.h",
        "modsec/include/modsecurity/anchored_set_variable.h",
        "modsec/include/modsecurity/anchored_set_variable_translation_proxy.h",
        "modsec/include/modsecurity/anchored_variable.h",
        "modsec/include/modsecurity/audit_log.h",
        "modsec/include/modsecurity/debug_log.h",
        "modsec/include/modsecurity/intervention.h",
        "modsec/include/modsecurity/modsecurity.h",
        "modsec/include/modsecurity/reading_logs_via_rule_message.h",
        "modsec/include/modsecurity/rule.h",
        "modsec/include/modsecurity/rule_message.h",
        "modsec/include/modsecurity/rule_marker.h",
        "modsec/include/modsecurity/rule_unconditional.h",
        "modsec/include/modsecurity/rule_with_actions.h",
        "modsec/include/modsecurity/rule_with_operator.h",
        "modsec/include/modsecurity/rules.h",
        "modsec/include/modsecurity/rules_exceptions.h",
        "modsec/include/modsecurity/rules_set.h",
        "modsec/include/modsecurity/rules_set_phases.h",
        "modsec/include/modsecurity/rules_set_properties.h",
        "modsec/include/modsecurity/transaction.h",
        "modsec/include/modsecurity/variable_origin.h",
        "modsec/include/modsecurity/variable_value.h"
    ],
    visibility = ["//visibility:public"],
)

cc_import(
    name = "libpcre",
    static_library = "pcre/lib/libpcre.a",
    hdrs = [
        "pcre/include/pcre.h",
    ],
    visibility = ["//visibility:public"],
)


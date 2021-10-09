WAF (ModSecurity) WASM Filter as Envoy extension (Istio control plane)
===========
> **Note**: This project is **experimental** and under development.

WAF WASM Filter is and Envoy filter developed to be deployed on Istio. It is based on [Libmodsecurity](https://github.com/SpiderLabs/ModSecurity) (ModSecurity v3), the C++ library of the common open source Web Application Firewall, and on [WebAssembly for Proxies (C++ SDK)](https://github.com/proxy-wasm/proxy-wasm-cpp-sdk)).
WAF functionalities, implemented as a WebAssembly module, extend the Envoy proxy security capabilities across the Istio service mesh. In terms of detection, the WAF relies on most of the rules provided by the [OWASP CoreRuleSet](https://owasp.org/www-project-modsecurity-core-rule-set/) (**CRS**) v.3.3.2.
> **Note**: See Feature Request section to see the rules excluded and the current limitations.

**TODO**: provide link to Feature Request section

## Repository Structure

- **/basemodsec**: main project folder
- **/demo**: WIP
- **/modsec_rules_collection/**:
    - `/coreruleset-3.3.2-rules`: original collection of rules from CRS v.3.3.2.
    - `excluded rules.txt`: file listing the excluded rules.
    - `raw_wip_rules_collection.txt`: raw collection of working custom rules.
    - `rulethemall_orig.conf`: concatenation of all the CRS rules hardecoded inside the application.
    - `rulethemall.conf`: stripped version of rulethemall_orig.conf.
    - `sqlirules.conf`: stripped version of the CRS `REQUEST-941-APPLICATION-ATTACK-XSS.conf` file.
    - `xssrules.conf`: stripped version of the CRS `REQUEST-942-APPLICATION-ATTACK-SQLI.conf` file.
- **/wasm**: collection of compiled wasm files. `_nodebug` suffix means that the wasm has been compiled with less logs verbosity (e.g. print the whole body of each request). For details navigate the code looking for [DEBUG](/basemodsec/plugin.cc#L24) usage.
- **/yaml**: collection of yamls examples.


# Quick Deployment Guide

**Prerequisites**:
 - Istio service mesh up and running. See the [official istio.io guide](https://istio.io/latest/docs/setup/getting-started/).
 - (optional) [Istio sample application](https://istio.io/latest/docs/setup/getting-started/#bookinfo) deployed. This guide is based on bookinfo sample environment.

The fastest way to have up and running this project relies on one of the already built `.wasm` file provided in this repo [here](/wasm/).

It is just needed to:
1. Download the filter deployment example `.yaml` file.
2. (optional) Customize the location of the deployment (default configuration will deploy it inside the istio-proxy of the `productpage` workload)
3. (optional) Customize the Modsecurity rules provided to the WAF (default configuration enables the CRS).
4. Apply the `.yaml` file via `sudo kubectl apply -f file_name.yaml` 
**TODO**: write wasm file name on 1. and 4.

Check the correct deployment:
- Send a request that matches a modsec rule e.g: ```curl -I http://istio.k3s/productpage?arg=<script>alert(0)</script>```. The expected return code is `403`.
> **Note**: the url that has to be contact will depend on how the service has been exposed to external traffic
- Check the sidecar's logs: ```kubectl get logs name_of_the_pod -c istio-proxy```

## Modsecurity Configuration
One key element of this project is to provide enough flexiblity in terms of Modsecurity configuration without the necessity of recompiling each time the whole WASM file. This is achieved via the possibility of providing a JSON string inside the YAML file that is consumed by the Wasm extension.
The current JSON schema expected by the WASM filter is the following one:
```
{
  "$schema": "http://json-schema.org/draft-04/schema#",
  "title": "WASM Modsec configuration via YAML",
  "type": "object",
  "properties": {
    "modsec_config": {
      "type": "array",
      "items": [
        {
          "type": "object",
          "properties": {
            "enable_default": {
              "type": "string",
              "enum": [
                "yes",
                "no"
              ],
              "default": "yes"
            },
            "enable_crs": {
              "type": "string",
              "enum": [
                "yes",
                "no"
              ],
              "default": "yes"
            },
            "enable_sqli": {
              "type": "string",
              "enum": [
                "yes",
                "no"
              ],
              "default": "no"
            },
            "enable_xss": {
              "type": "string",
              "enum": [
                "yes",
                "no"
              ],
              "default": "no"
            },
            "custom_rules": {
              "type": "array",
              "items": [
                {
                  "type": "string"
                }
              ]
            }
          },
          "required": []
        }
      ]
    }
  }
}
```
Example of a validated json:
```
{
"modsec_config": [
    {
    "enable_default": "yes",
    "enable_crs": "yes",
    "custom_rules":[
    "SecRule ARGS \"@rx matteo\" \"id:103,phase:1,t:lowercase,deny\"",
    "SecRuleRemoveById 920280"
    ]
    }
]
}
```
Notes about the json configuration:
- `enable_` fields refer to already hardcoded rules inside the application: `enable_default` includes mosts of the basic needed rules coming from [modsecurity.conf](https://github.com/SpiderLabs/ModSecurity/blob/v3/master/modsecurity.conf-recommended) and crs-setup.conf. `enable_crs` enables the almost complete collection of CRS rules. Refer to [rules.cc](TODO) to see the complete list of rules and to [feature requests](TODO) for the current rules limitation.  
No fields are mandatory: default values, as indicated inside the schema, are:
    - `enable_default`: `yes` 
    - `enable_crs`: `yes`
    - `enable_xss`: `no`
    - `enable_sqli`: `no`
- `enable_crs` logically includes `enable_sqli` and `enable_xss`. Enabling it leads the filter to do not take into account any possible values of `enable_sqli` and `enable_xss`.
- For a complete custom configuration it is possible to set `enable_default` and `enable_crs` to `no` and provide all the rules via `custom_rules`.

 

# Developer Guide
**TODO**: some text here
## Building Libmodsecurity for WASM
WIP  
**TODO**: be clear about the fact that *.a files are not inside this repo and are needed to build it.
## Building the Filter
### Environment setup
The building process is based on Bazel, downloaded via its wrapper Bazelisk.
 ```
sudo wget -O /usr/local/bin/bazel https://github.com/bazelbuild/bazelisk/releases/latest/download/bazelisk-linux-amd64

sudo chmod +x /usr/local/bin/bazel
 ```
Dependencies:
 ```
sudo apt-get install gcc curl python3
 ``` 
 For further details refer to [Istio Wasm Extensions Development Guides](https://github.com/istio-ecosystem/wasm-extensions#development-guides) and its [Set up Develop Environment](https://github.com/istio-ecosystem/wasm-extensions/blob/master/doc/development-setup.md#set-up-develop-environment).

### Building commands
> **Note**: Do **not** perform `bazel build` command as **root** user
```
cd ./basemodsec
bazel build //:basemodsec.wasm
```
The wasm file will be generated under `./bazel-bin/` folder.

For further details refer to [Develop a Wasm extension with C++](https://github.com/istio-ecosystem/wasm-extensions/blob/master/doc/write-a-wasm-extension-with-cpp.md).

## Deployment
Two `EnvoyFilter` resources are needed to deploy the just built wasm extension with Istio:
- The first declares the filter as HTTP_FILTER and specifies its position inside the filter chain of envoy.
- The second ones provides configuration to the filter including:
    - how to retrieve the `.wasm` file. Local and remote ways can be used to provide the extension. All yaml files in this repository realies on downloading it from a remote http uri. To further details refer to [Istio documentation](https://istio.io/latest/docs/ops/configuration/extensibility/wasm-module-distribution/).
    - JSON configuration that will be internally handled by the filter at the booting phase.

1. Upload the `.wasm` file to be publicly eccessible from a https request (e.g. inside a GitHub repository).
2. Retrieve a link to directly download the `.wasm` file. e.g. `https://github.com/M4tteoP/wasm-repo/raw/main/basemodsec.wasm`.
3. Customize the deployment according to your needs.
    - specify the namespace and/or the specific workload where the WAF must be deployed.
    - update the download uri.
    - update custom rules and flags that will configure Modsecurity (for details see Modsecurity Configuration TODO add link).
4. Apply the yaml file inside the cluster via `kubectl apply -f file_name.yaml`.

## Implementation Examplantion
WIP

## Debugging Tips
- **Change Envoy log level**: by default, Istio injects the istio-proxy (Envoy) with log levels set as `info`. `trace` and `debug` are more verbose alternatives, and can be set:
    - performing the [manual injection](https://istio.io/latest/docs/setup/additional-setup/sidecar-injection/#manual-sidecar-injection) of the sidecar with log level properly configured inside `inject-values.yaml`.
    - via istioctl proxy-config on a specific proxy already deployed: `istioctl pc log pod_name.<namespace> --level wasm:trace`.
- **kubectl logs**: reading the logs provided by kubectl from the istio-proxy container is the main source of logs. To analyze burst of traffic it is possible to redirect the output directly to a file: `kubectl logs -f pod_name -c istio-proxy -n namespace_name > logs.txt`. 
- **dmesg from istio-proxy pod**: executed from inside the istio-proxy container, `dmesg` command may provide some hints about crashes.

- **Monitor resources via**:
    - `crictl stats` directly providing the id of the sidecar container.
    - `Grafana Dashboard` exposing the service [with Istio](https://istio.io/latest/docs/tasks/observability/metrics/using-istio-dashboard/) and analyzing the pre-made **Wasm Extension Dashboard**.


## Useful references
WIP
## Feature Request and Current Limitations
WIP

WAF (ModSecurity) WASM Filter as Envoy extension (Istio control plane)
===========
> **Note**: This project is under development and experimental.

WAF WASM Filter is based on [Libmodsecurity](https://github.com/SpiderLabs/ModSecurity) (ModSecurity v3), the C++ library of the common open source Web Application Firewall, and on [WebAssembly for Proxies (C++ SDK)](https://github.com/proxy-wasm/proxy-wasm-cpp-sdk)).
WAF functionalities, implemented as a WebAssembly module, extend the Envoy proxy security capabilities across the Istio service mesh. For the detection the filter relies on most of the rules provided by the [OWASP CoreRuleSet](https://owasp.org/www-project-modsecurity-core-rule-set/) (**CRS**).
> **Note**: See Feature Request section to see the rules excluded and the current limitations

**TODO**: provide link to Feature Request section

## Repository Structure

- WIP

# Quick Deployment Guide

**Prerequisites**:
 - Istio service mesh up and running. See the [official guide](https://istio.io/latest/docs/setup/getting-started/).
 - (optional) [Istio sample application](https://istio.io/latest/docs/setup/getting-started/#bookinfo) deployed. It is the sample environment on which this guide is based on.

The fastest way to have up and running this project relies on an already built `.wasm` file provided in this repo.

**TODO**: provide link to a stable wasm file

It is just needed to:
1. download the filter deployment example `.yaml` file.
2. (optional) customize the location of the deployment (default configuration will deploy it inside the istio-proxy of the `productpage` workload)
3. (optional) customize the Modsecurity rules provided to the WAF (default configuration enables the CRS).
4. apply the `.yaml` file via `sudo kubectl apply -f file_name.yaml` 
**TODO**: write wasm file name

Check the correct deployment:
- sending a request that matches a modsec rule e.g: ```curl -I http://istio.k3s/productpage?arg=<script>alert(0)</script>```. The expected return code is `403`.
> **Note**: the url that has to be contact will depend on how the service has been exposed to external traffic
- checking the sidecar's logs: ```kubectl get logs name_of_the_pod -c istio-proxy```

# Developer Guide
**TODO**: some text here
## Building Libmodsecurity for WASM
WIP
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
> **Note**: Do not perform `bazel build` command as root user
```
cd ./basemodsec
bazel build //:modsecurity.wasm
```
The wasm file will be generated under `./bazel-bin/` folder.

**TODO**: update wasm name according to yaml files and path

For further details refer to [Develop a Wasm extension with C++](https://github.com/istio-ecosystem/wasm-extensions/blob/master/doc/write-a-wasm-extension-with-cpp.md).

## Deployment
Two `EnvoyFilter` resources are needed to deploy the just built extension with Istio:
- The first declares the filter as HTTP_FILTER and specifies its position inside the filter chain of envoy.
- The second ones provides configuration to the filter including:
    - how to retrieve the `.wasm` file. Local and remote ways can be used to provide the extension. All yaml files in this repository realies on downloading it from a remote http uri. To further details refer to [Istio documentation](https://istio.io/latest/docs/ops/configuration/extensibility/wasm-module-distribution/).
    - JSON configuration that will be internally handled by the filter at the booting phase.

1. Upload the `.wasm` file to be publicly eccessible from a http request (e.g. inside a GitHub repository).
2. Retrieve a link to directly download the `.wasm` file. e.g. `https://github.com/M4tteoP/wasm-repo/raw/main/modsecurity.wasm`.
**TODO**: update wasm name
3. Customize the deployment according to your needs.
    - specify the namespace, or the specific workload where the WAF must be deployed.
    - update the download uri.
    - update custom rules and flags that will configure Modsecurity (for details see the following section).
4. Deploy the yaml file inside the cluster via `kubectl`.

## Modsecurity Configuration
One key element of this project is to provide enough flexiblity in terms of Modsecurity configuration without the necessity of recompiling each time the whole WASM file. This is achieved via the possibility of provide a JSON string inside the YAML file that is consumed by the Wasm extension.
At the moment the JSON string structure expected by the WASM filter is the following:
```
{
"modsec_config": [
    {
    "enable_default": "yes/no",
    "enable_crs": "yes/no",
    "enable_sqli": "yes/no",
    "enable_xss": "yes/no",
    "custom_rules":[
    "SecRule ARGS \"@rx matteo\" \"id:103,phase:1,t:lowercase,deny\"",
    "SecRuleRemoveById 920280"
    ]
    }
]
}
```
Four flags, with legit values resticted to `yes` and `no`, to include or not hardcoded rules:
- enable_default: mosts of the basic needed rules coming from [modsecurity.conf](https://github.com/SpiderLabs/ModSecurity/blob/v3/master/modsecurity.conf-recommended) and crs-setup.conf
- enable_crs: 

## Implementation Examplantion
WIP
## Useful references
WIP
## Feature Request
WIP

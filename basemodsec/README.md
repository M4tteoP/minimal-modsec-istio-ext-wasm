WAF (ModSecurity) WASM Filter as Envoy extension (Istio control plane)
===========
> **Note**: This is an under development and experimental.

ModSecurity WASM Filter is based on [Libmodsecurity](https://github.com/SpiderLabs/ModSecurity) (ModSecurity v3), the C++ library of the common open source Web Application Firewall, and on [WebAssembly for Proxies (C++ SDK)](https://github.com/proxy-wasm/proxy-wasm-cpp-sdk)).
WAF functionalities, implemented as a WebAssembly module, extend the Envoy proxy capabilities across the Istio service mesh.

## Building Libmodsecurity for WASM
--------
WIP
## Building the Filter
--------
### Environment setup
The building process is based on Bazel, downloaded via its wrapper Bazelisk.
 ```
sudo wget -O /usr/local/bin/bazel https://github.com/bazelbuild/bazelisk/releases/latest/download/bazelisk-linux-amd64

sudo chmod +x /usr/local/bin/bazel
 ```
Depndencies:
 ```
sudo apt-get install gcc curl python3
 ```


For further details refer to [Istio Wasm Extensions Development Guides](https://github.com/istio-ecosystem/wasm-extensions#development-guides) and its [Set up Develop Environment](https://github.com/istio-ecosystem/wasm-extensions/blob/master/doc/development-setup.md#set-up-develop-environment).

### Building command
WIP
## Deployment
--------
WIP
## Configuration
--------
WIP
## Implementation Examplantion
--------
WIP
## Useful references
--------
WIP
## Feature Request
--------
WIP
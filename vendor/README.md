# Native engine sources

The following source archives are stored verbatim. Cargo extracts them into its build directory and CMake compiles only the server's instruction architecture. No shared engine library is used at runtime.

| Archive | Source | SHA-256 |
|---|---|---|
| `keystone-0.9.2.tar.gz` | [Keystone 0.9.2 source release](https://github.com/keystone-engine/keystone/releases/tag/0.9.2) | `c9b3a343ed3e05ee168d29daf89820aff9effb2c74c6803c2d9e21d55b5b7c24` |
| `unicorn-engine-sys-2.1.5.tar.gz` | [unicorn-engine-sys 2.1.5 crate archive](https://crates.io/api/v1/crates/unicorn-engine-sys/2.1.5/download) | `685282714d35a6fbfed0ae14d81bb11c91838bc7a165cac778321679a7bb91d8` |

Both archives contain the upstream license files. The `unicorn-engine-sys` crate at version 2.1.5 ships Unicorn C engine version 2.1.4. This build uses its CMake project.

rustup run nightly cbindgen --config bindings/c/cbindgen.toml --crate cilium --output bindings/c/cilium.h
rustup run nightly cbindgen --config bindings/c++/cbindgen.toml --crate cilium --output bindings/c++/cilium.hpp
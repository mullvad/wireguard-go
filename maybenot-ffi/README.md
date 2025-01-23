This is just an empty wrapper around the real `maybenot-ffi` crate. It just depends
on maybenot-ffi and re-exports the entire API. It also contains the C header
file, and a Makefile to aid building a static library out of it.

This allows us check in a Cargo.lock-file in this repository for tracking checksums and version of
the real `maybenot-ffi` and its dependencies. This gives us simpler version management, supply
chain security, and easier reproducible builds.

# maybenot.h

The C header file is copied here from the real `maybenot-ffi` crate.

To update the header, just copy it from the corresponding `maybenot-ffi` release (the same version
as the one specified in [`Cargo.toml`](./Cargo.toml)).
You can use this command, just replace `${VERSION}` with the version you want the header from.
(You first need to install `cargo download` subcommand with `cargo install cargo-download`):
```bash
cargo download maybenot-ffi==${VERSION} | \
    tar xzvf - --wildcards --strip-components=1 '*/maybenot.h'
```

This is just an empty wrapper around the real `maybenot-ffi` crate. It just depends
on maybenot-ffi and re-exports the entire API. It also contains the C header
file, and a Makefile to aid building a static library out of it.

This allows us to include maybenot-ffi in a workspace without it being a direct or
transitive Rust dependency in the workspace. This is achieved by including this crate in the
workspace as a member. Doing this allows tracking the checksums and versions of `maybenot-ffi`
and its dependencies in the workspace lockfile, for simpler version management,
supply chain security and easier reproducible builds.

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

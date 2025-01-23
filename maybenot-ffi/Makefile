CARGO ?= cargo
TARGET ?=
PROFILE ?= release

CARGO_OUTPUT_DIR := $(CARGO_TARGET_DIR)/$(TARGET)/$(PROFILE)
CARGOFLAGS += --target-dir $(CARGO_TARGET_DIR)

ifeq ($(PROFILE), release)
	CARGOFLAGS += --release --locked
endif

ifneq ($(TARGET),)
	CARGOFLAGS += --target $(TARGET)
endif

.PHONY: clean check-env

# copy the library to any arbitrary path, and strip the _ffi part.
# note that arbitraty paths are not considered by the `clean` rule.
%/libmaybenot.a: $(CARGO_OUTPUT_DIR)/libmaybenot_ffi.a check-env
	cp $< $@


# build maybenot-ffi as a static library
$(CARGO_OUTPUT_DIR)/libmaybenot_ffi.a: src/*.rs Cargo.toml check-env
	RUSTFLAGS="-C metadata=maybenot-ffi" ${CARGO} rustc --crate-type=staticlib $(CARGOFLAGS)


# Verify that required environment variables are set.
check-env:
ifndef CARGO_TARGET_DIR
	$(error CARGO_TARGET_DIR is undefined)
endif

clean:
	rm -f libmaybenot.a
	${CARGO} clean $(CARGOFLAGS)

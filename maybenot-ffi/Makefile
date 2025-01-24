CARGO ?= cargo
TARGET ?=
PROFILE ?= release
DESTINATION ?= .

CARGO_OUTPUT_DIR := $(CARGO_TARGET_DIR)/$(TARGET)/$(PROFILE)
CARGOFLAGS += --target-dir $(CARGO_TARGET_DIR)

ifeq ($(PROFILE), release)
	CARGOFLAGS += --release --locked
endif

ifneq ($(TARGET),)
	CARGOFLAGS += --target
	CARGOFLAGS += $(TARGET)
endif

.PHONY: clean check-env


# copy the library to the final destination, and strip the _ffi part
$(DESTINATION)/libmaybenot.a: $(CARGO_OUTPUT_DIR)/libmaybenot_ffi.a check-env
# Copy first prerequisite ($^) to the target ($@)
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
	rm -f $(DESTINATION)/libmaybenot.a
	${CARGO} clean $(CARGOFLAGS)

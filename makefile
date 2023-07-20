.DEFAULT_GOAL := help
PROJECTNAME=$(shell basename "$(PWD)")
SOURCES=$(sort $(wildcard ./src/*.rs ./src/**/*.rs))

OS_NAME=$(shell uname | tr '[:upper:]' '[:lower:]')
PATH := $(ANDROID_NDK_HOME)/toolchains/llvm/prebuilt/$(OS_NAME)-x86_64/bin:$(PATH)

ANDROID_AARCH64_LINKER=$(ANDROID_NDK_HOME)/toolchains/llvm/prebuilt/$(OS_NAME)-x86_64/bin/aarch64-linux-android28-clang
ANDROID_ARMV7_LINKER=$(ANDROID_NDK_HOME)/toolchains/llvm/prebuilt/$(OS_NAME)-x86_64/bin/armv7a-linux-androideabi28-clang
ANDROID_I686_LINKER=$(ANDROID_NDK_HOME)/toolchains/llvm/prebuilt/$(OS_NAME)-x86_64/bin/i686-linux-android28-clang
ANDROID_X86_64_LINKER=$(ANDROID_NDK_HOME)/toolchains/llvm/prebuilt/$(OS_NAME)-x86_64/bin/x86_64-linux-android28-clang
AR=$(ANDROID_NDK_HOME)/toolchains/llvm/prebuilt/$(OS_NAME)-x86_64/bin/llvm-ar

SHELL := /bin/bash

# ##############################################################################
# # GENERAL
# ##############################################################################

.PHONY: help
help: makefile
	@echo
	@echo " Available actions in "$(PROJECTNAME)":"
	@echo
	@sed -n 's/^##//p' $< | column -t -s ':' |  sed -e 's/^/ /'
	@echo

## init: Install missing dependencies.
.PHONY: init
init:
	rustup target add aarch64-apple-ios x86_64-apple-ios
	rustup target add aarch64-apple-darwin x86_64-apple-darwin
	#rustup target add armv7-apple-ios armv7s-apple-ios i386-apple-ios ## deprecated
	rustup target add aarch64-linux-android armv7-linux-androideabi i686-linux-android x86_64-linux-android
	@if [ $$(uname) == "Darwin" ] ; then cargo install cargo-lipo ; fi
	cargo install cbindgen

## :

# ##############################################################################
# # RECIPES
# ##############################################################################

## all: Compile iOS, Android and bindings targets
# all: ios macos android bindings
all: defaultRelease ios android bindings copyBin

defaultRelease:
	cargo build --release --features jni
	mkdir -p $HOME/Library/Java/Extensions
	rm -f $HOME/Library/Java/Extensions/libtssv3.*
	cp target/release/libtssv3.* $HOME/Library/Java/Extensions/

## ios: Compile the iOS universal library
ios: target/universal/release/libtssv3.a

target/universal/release/libtssv3.a: $(SOURCES) ndk-home
	@if [ $$(uname) == "Darwin" ] ; then \
		cargo lipo --release ; \
		else echo "Skipping iOS compilation on $$(uname)" ; \
	fi
	@echo "[DONE] $@"

## macos: Compile the macOS libraries
macos: target/x86_64-apple-darwin/release/libtssv3.dylib target/aarch64-apple-darwin/release/libtssv3.dylib

target/x86_64-apple-darwin/release/libtssv3.dylib: $(SOURCES)
	@if [ $$(uname) == "Darwin" ] ; then \
		cargo lipo --release --targets x86_64-apple-darwin ; \
		else echo "Skipping macOS compilation on $$(uname)" ; \
	fi
	@echo "[DONE] $@"

target/aarch64-apple-darwin/release/libtssv3.dylib: $(SOURCES)
	@if [ $$(uname) == "Darwin" ] ; then \
		cargo lipo --release --targets aarch64-apple-darwin ; \
		else echo "Skipping macOS compilation on $$(uname)" ; \
	fi
	@echo "[DONE] $@"

## android: Compile the android targets (arm64, armv7 and i686)
android: target/aarch64-linux-android/release/libtssv3.so target/armv7-linux-androideabi/release/libtssv3.so target/i686-linux-android/release/libtssv3.so target/x86_64-linux-android/release/libtssv3.so

target/aarch64-linux-android/release/libtssv3.so: $(SOURCES) ndk-home
	CC_aarch64_linux_android=$(ANDROID_AARCH64_LINKER) \
	CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER=$(ANDROID_AARCH64_LINKER) \
		cargo build --target aarch64-linux-android --release
	@echo "[DONE] $@"

target/armv7-linux-androideabi/release/libtssv3.so: $(SOURCES) ndk-home
	CC_armv7_linux_androideabi=$(ANDROID_ARMV7_LINKER) \
	CARGO_TARGET_ARMV7_LINUX_ANDROIDEABI_LINKER=$(ANDROID_ARMV7_LINKER) \
		cargo build --target armv7-linux-androideabi --release
	@echo "[DONE] $@"

target/i686-linux-android/release/libtssv3.so: $(SOURCES) ndk-home
	CC_i686_linux_android=$(ANDROID_I686_LINKER) \
	CARGO_TARGET_I686_LINUX_ANDROID_LINKER=$(ANDROID_I686_LINKER) \
		cargo  build --target i686-linux-android --release
	@echo "[DONE] $@"

target/x86_64-linux-android/release/libtssv3.so: $(SOURCES) ndk-home
	CC_x86_64_linux_android=$(ANDROID_X86_64_LINKER) \
	CARGO_TARGET_X86_64_LINUX_ANDROID_LINKER=$(ANDROID_X86_64_LINKER) \
		cargo build --target x86_64-linux-android --release
	@echo "[DONE] $@"

.PHONY: ndk-home
ndk-home:
	@if [ ! -d "${ANDROID_NDK_HOME}" ] ; then \
		echo "Error: Please, set the ANDROID_NDK_HOME env variable to point to your NDK folder" ; \
		exit 1 ; \
	fi


copyBin:
	mkdir -p ../target/jniLibs/arm64-v8a
	mkdir -p ../target/jniLibs/armeabi-v7a
	mkdir -p ../target/jniLibs/x86
	mkdir -p ../target/jniLibs/x86_64
	mkdir -p ../target/aarch64-apple-ios
	mkdir -p ../target/x86_64-apple-ios
	#create symlink
	#ln -s blockchain-lib/target/jniLibs ./
	cp target/aarch64-linux-android/release/libtssv3.so ../target/jniLibs/arm64-v8a/libtssv3.so
	cp target/armv7-linux-androideabi/release/libtssv3.so ../target/jniLibs/armeabi-v7a/libtssv3.so
	cp target/i686-linux-android/release/libtssv3.so ../target/jniLibs/x86/libtssv3.so
	cp target/x86_64-linux-android/release/libtssv3.so ../target/jniLibs/x86_64/libtssv3.so
	cp target/aarch64-apple-ios/release/libtssv3.a ../target/aarch64-apple-ios/libtssv3.a
	cp target/x86_64-apple-ios/release/libtssv3.a ../target/x86_64-apple-ios/libtssv3.a

	cp ../../gmp/arm64-v8a/libgmp.so ../target/jniLibs/arm64-v8a/libgmp.so
	cp ../../gmp/armeabi-v7a/libgmp.so ../target/jniLibs/armeabi-v7a/libgmp.so
	cp ../../gmp/x86/libgmp.so ../target/jniLibs/x86/libgmp.so
	cp ../../gmp/x86_64/libgmp.so ../target/jniLibs/x86_64/libgmp.so

	cp target/bindings.h ../mobileapp/ios/Runner/libtssv3.h

	# copy lib to local dev
	mkdir -p $HOME/Library/Java/Extensions/
	rm -f $HOME/Library/Java/Extensions/libtssv3.* || true
	cp target/release/libtssv3.* ${HOME}/Library/Java/Extensions/


## bindings: Generate the .h file for iOS
bindings: target/bindings.h

target/bindings.h: $(SOURCES)
	cbindgen src/lib.rs -c cbindgen.toml | grep -v \#include | uniq > $@
	@echo "[DONE] $@"

## :

# ##############################################################################
# # OTHER
# ##############################################################################

## clean:
.PHONY: clean
clean:
	cargo clean
	rm -f target/bindings.h target/bindings.src.h

## test:
.PHONY: test
test:
	cargo test

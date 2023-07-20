
### TSS

This library is a proof-of-concept, cross-platform implementation of threshold signature schemes ECDSA and EDDSA. It exposes several interfaces for the following tasks:

* Decentralized key generation
* Generation of presignatures
* Partial signing and aggregation of signatures for one round or offline signing
* Refreshing of new presignatures
* Most of the code in this library is inspired by the work of Zengo-X. You can find more up-to-date versions of the code on their GitHub repository: <https://github.com/ZenGo-X>

Note: The library has not been audited

### Requirements

* NDK 25 or newer
* rust version 1.70
* gmp lib for mac/linux/android

### Build

* export envs:

```
export ANDROID_NDK_HOME="$HOME/Library/Android/sdk/ndk/25.2.9519653"
export AR="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/darwin-x86_64/bin/llvm-ar"
export ANDROID_HOME="$HOME/Library/Android/sdk"
export ANDROID_SDK_ROOT="$ANDROID_HOME"
```

### GMP library

* For MAC, you can just install it from brew: `brew install gmp`
* For Android, you can download prebuilt from <https://github.com/hoangong/gmp>
* For iOS, you can also download from the above repo, or you can build it with this command. You need xcode and xcode-select --install first. Then:

```
git clone git@github.com:alisw/GMP.git gmp-source && cd gmp-source
brew install pkg-config m4 libtool automake autoconf

CC="$(xcrun --sdk iphoneos --find clang)" \
  CFLAGS="-isysroot $(xcrun --sdk iphoneos --show-sdk-path) -arch arm64 -miphoneos-version-min=7.0" \
  ./configure --disable-assembly --host=arm-apple-darwin --disable-assembly --enable-static --disable-shared

CC="$(xcrun --sdk iphonesimulator --find clang)" \
  CFLAGS="-isysroot $(xcrun --sdk iphonesimulator --show-sdk-path) -arch x86_64 -miphonesimulator-version-min=7.0" \
  ./configure --disable-assembly --host=arm-apple-darwin --disable-assembly --enable-static --disable-shared
  
```

* Once you had all binary built, you can set it in cargo config file at `~/.cargo/config.toml`. For example:

```
[target.aarch64-apple-darwin]
rustflags = ["-L", "/path/to/gmp/aarch64-apple-darwin"]

[target.aarch64-apple-ios]
rustflags = ["-L", "/path/to/gmp/aarch64-apple-ios"]

[target.x86_64-apple-ios]
rustflags = ["-L", "/path/to/gmp/x86_64-apple-ios"]

[target.aarch64-linux-android]
rustflags = ["-L", "/path/to/gmp/arm64-v8a"]

[target.armv7-linux-androideabi]
rustflags = ["-L", "/path/to/gmp/armeabi-v7a"]

[target.i686-linux-android]
rustflags = ["-L", "/path/to/gmp/x86"]

[target.x86_64-linux-android]
rustflags = ["-L", "/path/to/gmp/x86_64"]

[target.x86_64-unknown-linux-gnu]
rustflags = ["-L", "/path/to/gmp/x86_64"]

```

### GMP library

* To build the appropriate library, check the makefile. You can also check the blockchain-lib for some instructions on building, as they are quite similar.

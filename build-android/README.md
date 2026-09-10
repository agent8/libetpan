## Build instruction for Android ##
#Prefer to use release-andriod branch
```
$ export ANDROID_NDK=/path/to/android-ndk
$ cd build-android
$ ./build.sh
```

It will produce the following binaries:

- libetpan-android-*version*.zip
- dependencies/cyrus-sasl/cyrus-sasl-android-*version*.zip
- dependencies/openssl/openssl-android-*version*.zip

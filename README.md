# WatchWitch iOS Companion

A tweak hooking terminusd to allow hackery with Apple Watch communication.

## Usage

Make sure [Theos](https://theos.dev/docs/) is installed on your computer. Dependencies and version incompatibilities can be tricky on linux, macOS might work more smoothly. You will also need [Cephei](https://hbang.github.io/libcephei/) installed on your iPhone.

Install the tweak:
```
iproxy 2222 22
export THEOS_DEVICE_IP=localhost
export THEOS_DEVICE_PORT=2222
make package install
```

To use the tweak, install the [WatchWitch iOS app](https://github.com/rec0de/watchwitch-ios-companion).

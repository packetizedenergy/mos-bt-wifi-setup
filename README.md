# Mongoose OS WiFi Setup via BLE

[![Gitter](https://badges.gitter.im/cesanta/mongoose-os.svg)](https://gitter.im/cesanta/mongoose-os?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge)

## Overview
This library provides a service to setup WiFi on Mongoose OS devices using BLE. Mongoose also provides a [config service] (https://github.com/mongoose-os-libs/bt-service-config) that can be used. However, this service gives any user access to your devices' full config. Instead, we expose only endpoints to allow setting SSID and password, and require authorization prior to accepting any input.

## Attribute Description
The service UUID is `5f706574-5f43-4647-5f53-56435f49445f`. It exposes five BLE endpoints for authorization, setting SSID, password, saving credentials, and checking connection status:

* `30706574-5f43-4647-5f61-7574685f5f30` - a read-write attribute that allows the user to enter an auth code and returns whether the user is authorized when read.
* `31706574-5f43-4647-5f73-7369645f5f31` - a write-only attribute that accepts the network SSID
* `32706574-5f43-4647-5f70-6173735f5f32` - a write-only attribute that accepts the network password
* `33706574-5f43-4647-5f73-6176655f5f33` - a write-only attribute that triggers a cfg save (currently saves when any value is written)
* `34706574-5f43-4647-5f73-746174757334` - a read-only attribute that returns current WiFi status as one of the following:
```c
enum bt_wifi_status_codes {
    ERROR = -1,
    IDLE = 0,
    TESTING = 1,
    SUCCESS = 2,
    TIMEOUT = 3,
    BAD_PARAMS = 4,
};
```

## Usage
It is recommended that you do not set the auth key and instead randomly generate one for each usage.

To use this library, first start advertising and connect to the Mongoose OS device. Enter the correct authorization code, followed by SSID and password. Finally, trigger a save (write `1`), and check status until the device connects or times out.

## Required Libraries and Settings
See `mos.yml`

## License
MIT License

// Copyright 2019 Packetized Energy
#ifndef MOS_BT_WIFI_SETUP_INCLUDE_BT_WIFI_SETUP_H_
#define MOS_BT_WIFI_SETUP_INCLUDE_BT_WIFI_SETUP_H_

#include <stdbool.h>
#include <mgos.h>

#ifdef __cplusplus
extern "C" {
#endif

char *get_bt_auth_key(void);
char *get_bt_wifi_ssid(void);
bool bt_device_authorized(void);

void bt_setup_start(void);
void bt_setup_stop(void);

#ifdef __cplusplus
}
#endif

#endif  // MOS_BT_WIFI_SETUP_INCLUDE_BT_WIFI_SETUP_H_

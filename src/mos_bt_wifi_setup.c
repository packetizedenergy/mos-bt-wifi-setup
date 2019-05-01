// Copyright 2019 Packetized Energy
#include "mos_bt_wifi_setup.h"

#include <math.h>

#include "mgos_bt_gatts.h"
#include "esp32_bt.h"
#include "esp32_bt_gap.h"
#include "esp_bt.h"

#include "mgos.h"
#include "mgos_config.h"
#include "mgos_event.h"
#include "mgos_timers.h"
#include "mgos_utils.h"
#include "mongoose.h"

enum bt_wifi_status_codes {
    ERROR = -1,
    IDLE = 0,
    TESTING = 1,
    SUCCESS = 2,
    TIMEOUT = 3,
    BAD_PARAMS = 4,
};

enum pet_bt_setup_state {
    PET_BT_AUTH_WRITE = 0,
    PET_BT_AUTH_READ = 1,
    PET_BT_WIFI_SSID_ENTRY = 2,
    PET_BT_WIFI_PASS_ENTRY = 3,
    PET_BT_WIFI_SAVE = 4,
    PET_BT_STATUS_READ = 5
};
static enum pet_bt_setup_state s_pet_bt_setup_state = PET_BT_AUTH_WRITE;

static struct mbuf s_wifi_ssid;
static struct mbuf s_wifi_pass;

static enum bt_wifi_status_codes s_wifi_status = IDLE;
static struct mgos_config_wifi_sta sp_test_sta_vals;
static mgos_timer_id s_connect_timer_id = MGOS_INVALID_TIMER_ID;
static bool s_new_wifi_creds = false;

static bool s_const_auth_key = false;
static int s_auth_key_len;
static int s_auth_key_min;
static int s_auth_key_max;
static char *s_auth_key = NULL;
static esp_bd_addr_t s_authorized_device;

// Function definitions
static void sta_connect_timeout_timer_cb(void *arg);
static void remove_event_handlers(void);
static void add_event_handlers(void);
static bool save_wifi_creds(const char *ssid, const char *pass);
static void ip_acquired_cb(int ev, void *ev_data, void *userdata);
static void pet_bt_setup_wifi(void);
static void reset_auth(void);
static void regen_auth(void);

// BT callbacks
static enum mgos_bt_gatt_status pet_bt_cfg_svc_ev(struct mgos_bt_gatts_conn *c, enum mgos_bt_gatts_ev ev,
                                                  void *ev_arg, void *handler_arg);
static enum mgos_bt_gatt_status pet_bt_setup_auth_ev(struct mgos_bt_gatts_conn *c, enum mgos_bt_gatts_ev ev,
    void *ev_arg, void *handler_arg);
static enum mgos_bt_gatt_status pet_bt_setup_ssid_ev(struct mgos_bt_gatts_conn *c, enum mgos_bt_gatts_ev ev,
    void *ev_arg, void *handler_arg);
static enum mgos_bt_gatt_status pet_bt_setup_pass_ev(struct mgos_bt_gatts_conn *c, enum mgos_bt_gatts_ev ev,
    void *ev_arg, void *handler_arg);
static enum mgos_bt_gatt_status pet_bt_setup_save_ev(struct mgos_bt_gatts_conn *c, enum mgos_bt_gatts_ev ev,
    void *ev_arg, void *handler_arg);
static enum mgos_bt_gatt_status pet_bt_setup_status_ev(struct mgos_bt_gatts_conn *c, enum mgos_bt_gatts_ev ev,
    void *ev_arg, void *handler_arg);

static void sta_connect_timeout_timer_cb(void *arg) {
    mgos_clear_timer(s_connect_timer_id);
    remove_event_handlers();
    s_wifi_status = TIMEOUT;
    LOG(LL_ERROR, ("Bluetooth WiFi STA: Connect timeout"));
    (void) arg;
}

static void remove_event_handlers(void) {
    mgos_event_remove_handler(MGOS_WIFI_EV_STA_IP_ACQUIRED, ip_acquired_cb, NULL);
}

static void add_event_handlers(void) {
    // We use NULL for userdata to make sure they are removed correctly
    mgos_event_add_handler(MGOS_WIFI_EV_STA_IP_ACQUIRED, ip_acquired_cb, NULL);
}

static bool save_wifi_creds(const char *ssid, const char *pass) {
    bool ret = false;
    if (pass == NULL) {
        return ret;
    }

    mgos_sys_config_set_wifi_sta_enable(true);
    mgos_sys_config_set_wifi_sta_ssid(ssid);
    mgos_sys_config_set_wifi_sta_pass(pass);

    if (mgos_wifi_setup_sta(mgos_sys_config_get_wifi_sta())) {
        char *err = NULL;
        if (save_cfg(&mgos_sys_config, &err)) {
            ret = true;
            free(err);
        }
    }

    return ret;
}

static void ip_acquired_cb(int ev, void *ev_data, void *userdata) {
    if (s_wifi_status == IDLE) {
        return;
    }

    mgos_clear_timer(s_connect_timer_id);
    s_wifi_status = SUCCESS;

    // TODO(fwallace): Have a wifi setup completed callback?

    remove_event_handlers();

    (void)ev;
    (void)ev_data;
    (void)userdata;
}

static void pet_bt_setup_wifi(void) {
    // TODO(fwallace): Test wifi credentials before saving
    // sp_test_sta_vals.enable = 1; // Same as (*test_sta_vals).enable
    // sp_test_sta_vals.ssid = _wifi_ssid;
    // sp_test_sta_vals.pass = _wifi_pass;

    // Make sure to remove any existing handlers
    remove_event_handlers();

    if (s_connect_timer_id == MGOS_INVALID_TIMER_ID) {
        s_connect_timer_id = mgos_set_timer(15000, 0, sta_connect_timeout_timer_cb, NULL);
    }

    mgos_wifi_disconnect();

    // For consistency sake (cap portal), save directly and try to connect. Will erase old credentials.
    char *ssid;
    mg_asprintf(&ssid, 0, "%.*s", (int) s_wifi_ssid.len, s_wifi_ssid.buf);

    char *pass;
    mg_asprintf(&pass, 0, "%.*s", (int) s_wifi_pass.len, s_wifi_pass.buf);

    if (save_wifi_creds(ssid, pass)) {
        add_event_handlers();
        s_wifi_status = TESTING;
    } else {
        s_wifi_status = BAD_PARAMS;
    }
}

static bool pet_bt_is_authorized(const esp_bd_addr_t a) {
    // Return true if device is authorized or auth not required
    return (!esp32_bt_addr_cmp(a, s_authorized_device) || !mgos_sys_config_get_bt_wifi_setup_require_auth());
}

static void reset_auth(void) {
    // We still use this call to clear the bonded device. Then, set the address to null.
    mgos_bt_gap_remove_all_paired_devices();
    memset(s_authorized_device, 0, sizeof(s_authorized_device));
}

static void regen_auth(void) {
    if (!s_const_auth_key) {
        // Generate and store new auth key
        const int auth_key_int = (int)mgos_rand_range(s_auth_key_min, s_auth_key_max);
        snprintf(s_auth_key, s_auth_key_len + 1, "%d", auth_key_int);
    }
}

char *get_bt_auth_key(void) {
    return s_auth_key;
}

bool bt_device_authorized(void) {
    return (!esp32_bt_addr_is_null(s_authorized_device));
}

void bt_setup_start(void) {
    // TODO(fwallace): Improve security by requiring and limiting pairing. See
    // https://github.com/mongoose-os-libs/bt-common#security
    regen_auth();

    mgos_bt_gap_set_adv_enable(true);

    LOG(LL_DEBUG, ("Starting bt setup, auth key: %s", s_auth_key));
}

void bt_setup_stop(void) {
    reset_auth();
    mgos_bt_gap_set_adv_enable(mgos_sys_config_get_bt_wifi_setup_always_advertise());

    // Remove event handlers
    remove_event_handlers();

    // Clear ssid and pass
    mbuf_free(&s_wifi_ssid);
    mbuf_free(&s_wifi_pass);
}

static enum mgos_bt_gatt_status pet_bt_cfg_svc_ev(struct mgos_bt_gatts_conn *c, enum mgos_bt_gatts_ev ev,
                                                  void *ev_arg, void *handler_arg) {
    enum mgos_bt_gatt_status ret = MGOS_BT_GATT_STATUS_REQUEST_NOT_SUPPORTED;
    switch (ev) {
        case MGOS_BT_GATTS_EV_CONNECT: {
            ret = MGOS_BT_GATT_STATUS_OK;
            break;
        }
        case MGOS_BT_GATTS_EV_DISCONNECT: {
            // We still use this call to clear the bonded devices. Then, set the address to null.
            mgos_bt_gap_remove_all_paired_devices();
            memset(s_authorized_device, 0, sizeof(s_authorized_device));
            regen_auth();
            ret = MGOS_BT_GATT_STATUS_OK;
            break;
        }
        default:
            break;
    }
    return ret;
}

static enum mgos_bt_gatt_status pet_bt_setup_auth_ev(struct mgos_bt_gatts_conn *c, enum mgos_bt_gatts_ev ev,
    void *ev_arg, void *handler_arg) {
    enum mgos_bt_gatt_status ret = MGOS_BT_GATT_STATUS_REQUEST_NOT_SUPPORTED;

    if (ev == MGOS_BT_GATTS_EV_READ) {
        s_pet_bt_setup_state = PET_BT_AUTH_READ;
        struct mgos_bt_gatts_read_arg *ra = (struct mgos_bt_gatts_read_arg *) ev_arg;

        // Return true if authorized or auth not required
        const uint8_t authorized = pet_bt_is_authorized(c->gc.addr.addr);

        // debug log to console
        char buf[BT_ADDR_STR_LEN];
        LOG(LL_DEBUG, ("Was asked by %s if authorized, replying with: %d",
                       esp32_bt_addr_to_str(s_authorized_device, buf), authorized));

        mgos_bt_gatts_send_resp_data(c, ra, mg_mk_str_n((char *) &authorized, sizeof(authorized)));

        ret = MGOS_BT_GATT_STATUS_OK;
    } else if (ev == MGOS_BT_GATTS_EV_WRITE) {
        s_pet_bt_setup_state = PET_BT_AUTH_WRITE;
        struct mgos_bt_gatts_write_arg *wa = (struct mgos_bt_gatts_write_arg *) ev_arg;

        LOG(LL_DEBUG, ("Auth key: %.*s", wa->data.len, wa->data.p));

        // We only allow devices to pair if one is not already paired
        if ((esp32_bt_addr_is_null(s_authorized_device)) &&
            (strncmp(s_auth_key, wa->data.p, s_auth_key_len) == 0)) {
            memcpy(&s_authorized_device, c->gc.addr.addr, sizeof(c->gc.addr.addr));

            // TODO(fwallace): Buf only for debug
            char buf[BT_ADDR_STR_LEN];
            LOG(LL_DEBUG, ("New device authorized: %s", esp32_bt_addr_to_str(s_authorized_device, buf)));

            ret = MGOS_BT_GATT_STATUS_OK;
        } else {
            ret = MGOS_BT_GATT_STATUS_INVALID_OFFSET;
            // TODO(fwallace): or ret = MGOS_BT_GATT_STATUS_INSUF_AUTHORIZATION;
        }
    }

    return ret;
}

static enum mgos_bt_gatt_status pet_bt_setup_ssid_ev(struct mgos_bt_gatts_conn *c, enum mgos_bt_gatts_ev ev,
    void *ev_arg, void *handler_arg) {
    enum mgos_bt_gatt_status ret = MGOS_BT_GATT_STATUS_REQUEST_NOT_SUPPORTED;

    if (ev == MGOS_BT_GATTS_EV_WRITE) {
        if (pet_bt_is_authorized(c->gc.addr.addr)) {
            struct mgos_bt_gatts_write_arg *wa = (struct mgos_bt_gatts_write_arg *) ev_arg;


            if (s_pet_bt_setup_state != PET_BT_WIFI_SSID_ENTRY) {
                s_pet_bt_setup_state = PET_BT_WIFI_SSID_ENTRY;
                mbuf_free(&s_wifi_ssid);
                mbuf_init(&s_wifi_ssid, wa->data.len);
            }
            mbuf_append(&s_wifi_ssid, wa->data.p, wa->data.len);
            LOG(LL_DEBUG, ("Wifi ssid: %.*s", (int) s_wifi_ssid.len, s_wifi_ssid.buf));

            s_new_wifi_creds = true;

            ret = MGOS_BT_GATT_STATUS_OK;
        } else {
            ret = MGOS_BT_GATT_STATUS_INVALID_OFFSET;
            // TODO(fwallace): or ret = MGOS_BT_GATT_STATUS_INSUF_AUTHORIZATION;
        }
    }

    return ret;
}

static enum mgos_bt_gatt_status pet_bt_setup_pass_ev(struct mgos_bt_gatts_conn *c, enum mgos_bt_gatts_ev ev,
    void *ev_arg, void *handler_arg) {
    enum mgos_bt_gatt_status ret = MGOS_BT_GATT_STATUS_REQUEST_NOT_SUPPORTED;

    if (ev == MGOS_BT_GATTS_EV_WRITE) {
        if (pet_bt_is_authorized(c->gc.addr.addr)) {
            struct mgos_bt_gatts_write_arg *wa = (struct mgos_bt_gatts_write_arg *) ev_arg;

            if (s_pet_bt_setup_state != PET_BT_WIFI_PASS_ENTRY) {
                s_pet_bt_setup_state = PET_BT_WIFI_PASS_ENTRY;
                mbuf_free(&s_wifi_pass);
                mbuf_init(&s_wifi_pass, wa->data.len);
            }
            mbuf_append(&s_wifi_pass, wa->data.p, wa->data.len);
            LOG(LL_DEBUG, ("Wifi pass: %.*s", (int) s_wifi_pass.len, s_wifi_pass.buf));

            s_new_wifi_creds = true;

            ret = MGOS_BT_GATT_STATUS_OK;
        } else {
            ret = MGOS_BT_GATT_STATUS_INVALID_OFFSET;
            // TODO(fwallace): or ret = MGOS_BT_GATT_STATUS_INSUF_AUTHORIZATION;
        }
    }

    return ret;
}

static enum mgos_bt_gatt_status pet_bt_setup_save_ev(struct mgos_bt_gatts_conn *c, enum mgos_bt_gatts_ev ev,
    void *ev_arg, void *handler_arg) {
    enum mgos_bt_gatt_status ret = MGOS_BT_GATT_STATUS_REQUEST_NOT_SUPPORTED;

    if (ev == MGOS_BT_GATTS_EV_WRITE) {
        if (pet_bt_is_authorized(c->gc.addr.addr)) {
            struct mgos_bt_gatts_write_arg *wa = (struct mgos_bt_gatts_write_arg *) ev_arg;

            if (wa->data.len > 0 && s_new_wifi_creds) {
                s_pet_bt_setup_state = PET_BT_WIFI_SAVE;
                pet_bt_setup_wifi();
                s_new_wifi_creds = false;
            }

            // debug log to console
            char buf[BT_ADDR_STR_LEN];
            LOG(LL_DEBUG, ("Was asked by %s to save WiFi creds", esp32_bt_addr_to_str(s_authorized_device, buf)));

            ret = MGOS_BT_GATT_STATUS_OK;
        } else {
            ret = MGOS_BT_GATT_STATUS_INVALID_OFFSET;
            // TODO(fwallace): or ret = MGOS_BT_GATT_STATUS_INSUF_AUTHORIZATION;
        }
    }

    return ret;
}

static enum mgos_bt_gatt_status pet_bt_setup_status_ev(struct mgos_bt_gatts_conn *c, enum mgos_bt_gatts_ev ev,
    void *ev_arg, void *handler_arg) {
    enum mgos_bt_gatt_status ret = MGOS_BT_GATT_STATUS_REQUEST_NOT_SUPPORTED;

    if (ev == MGOS_BT_GATTS_EV_READ) {
        s_pet_bt_setup_state = PET_BT_STATUS_READ;

        struct mgos_bt_gatts_read_arg *ra = (struct mgos_bt_gatts_read_arg *) ev_arg;
        // TODO(fwallace): Check auth? if (pet_bt_is_authorized(c->gc.addr.addr))
        // TODO(fwallace): Wifi status should represent current state (only set after asked to save credentials)

        // debug log to console
        char buf[BT_ADDR_STR_LEN];
        LOG(LL_DEBUG, ("Was asked by %s for WiFi status, replying with: %d",
                       esp32_bt_addr_to_str(s_authorized_device, buf), s_wifi_status));

        // Send a response with WiFi status
        mgos_bt_gatts_send_resp_data(c, ra, mg_mk_str_n((char *) &s_wifi_status, sizeof(s_wifi_status)));
        ret = MGOS_BT_GATT_STATUS_OK;
    }

    return ret;
}

static const struct mgos_bt_gatts_char_def pet_bt_setup_def[] = {
    {
     .uuid = "30706574-5f43-4647-5f61-7574685f5f30", /* 0pet_CFG_auth__0 */
     .prop = MGOS_BT_GATT_PROP_RWNI(1, 1, 0, 0),
     .handler = pet_bt_setup_auth_ev,
    },
    {
     .uuid = "31706574-5f43-4647-5f73-7369645f5f31", /* 1pet_CFG_ssid__1 */
     .prop = MGOS_BT_GATT_PROP_RWNI(0, 1, 0, 0),
     .handler = pet_bt_setup_ssid_ev,
    },
    {
     .uuid = "32706574-5f43-4647-5f70-6173735f5f32", /* 2pet_CFG_pass__2 */
     .prop = MGOS_BT_GATT_PROP_RWNI(0, 1, 0, 0),
     .handler = pet_bt_setup_pass_ev,
    },
    {
     .uuid = "33706574-5f43-4647-5f73-6176655f5f33", /* 3pet_CFG_save__3 */
     .prop = MGOS_BT_GATT_PROP_RWNI(0, 1, 0, 0),
     .handler = pet_bt_setup_save_ev,
    },
    {
     .uuid = "34706574-5f43-4647-5f73-746174757334", /* 4pet_CFG_status4 */
     .prop = MGOS_BT_GATT_PROP_RWNI(1, 0, 0, 0),
     .handler = pet_bt_setup_status_ev,
    },
    {.uuid = NULL},
};

bool mgos_mos_bt_wifi_setup_init(void) {
    // Set auth key length from the config. If auth key is given, use that
    s_auth_key_len = mgos_sys_config_get_bt_wifi_setup_auth_key_len();
    s_auth_key = malloc(s_auth_key_len + 1);

    if (mgos_sys_config_get_bt_wifi_setup_auth_key()) {
        s_const_auth_key = true;
        snprintf(s_auth_key, s_auth_key_len + 1, "%s", mgos_sys_config_get_bt_wifi_setup_auth_key());
    } else {
        // Add 0.5 and cast to int to deal with floating point precision issues
        int pow_auth_key = (int) (pow(10, s_auth_key_len) + 0.5);
        s_auth_key_min = pow_auth_key / 10;
        s_auth_key_max = pow_auth_key - 1;
    }

    // Register the setup service
    mgos_bt_gatts_register_service("5f706574-5f43-4647-5f53-56435f49445f", /* _pet_CFG_SVC_ID_ */
        (enum mgos_bt_gatt_sec_level) 0, pet_bt_setup_def, pet_bt_cfg_svc_ev, NULL);

    bt_setup_stop();

    return true;
}

#include "freertos/FreeRTOS.h"
#include "esp_wifi.h"
#include "esp_system.h"
#include "esp_log.h"
#include "nvs_flash.h"
#include <stdio.h>
#include <stdint.h>


#include <string.h>
#include "esp_timer.h"
#include <unistd.h>


#define CHANNEL 6

static const char *TAG = "wifi station";

static void print_auth_mode(int authmode)
{
    switch (authmode) {
    case WIFI_AUTH_OPEN:
        ESP_LOGI(TAG, "Authmode \tWIFI_AUTH_OPEN");
        break;
    case WIFI_AUTH_OWE:
        ESP_LOGI(TAG, "Authmode \tWIFI_AUTH_OWE");
        break;
    case WIFI_AUTH_WEP:
        ESP_LOGI(TAG, "Authmode \tWIFI_AUTH_WEP");
        break;
    case WIFI_AUTH_WPA_PSK:
        ESP_LOGI(TAG, "Authmode \tWIFI_AUTH_WPA_PSK");
        break;
    case WIFI_AUTH_WPA2_PSK:
        ESP_LOGI(TAG, "Authmode \tWIFI_AUTH_WPA2_PSK");
        break;
    case WIFI_AUTH_WPA_WPA2_PSK:
        ESP_LOGI(TAG, "Authmode \tWIFI_AUTH_WPA_WPA2_PSK");
        break;
    case WIFI_AUTH_WPA2_ENTERPRISE:
        ESP_LOGI(TAG, "Authmode \tWIFI_AUTH_WPA2_ENTERPRISE");
        break;
    case WIFI_AUTH_WPA3_PSK:
        ESP_LOGI(TAG, "Authmode \tWIFI_AUTH_WPA3_PSK");
        break;
    case WIFI_AUTH_WPA2_WPA3_PSK:
        ESP_LOGI(TAG, "Authmode \tWIFI_AUTH_WPA2_WPA3_PSK");
        break;
    default:
        ESP_LOGI(TAG, "Authmode \tWIFI_AUTH_UNKNOWN");
        break;
    }
}

static void print_cipher_type(int pairwise_cipher, int group_cipher)
{
    switch (pairwise_cipher) {
    case WIFI_CIPHER_TYPE_NONE:
        ESP_LOGI(TAG, "Pairwise Cipher \tWIFI_CIPHER_TYPE_NONE");
        break;
    case WIFI_CIPHER_TYPE_WEP40:
        ESP_LOGI(TAG, "Pairwise Cipher \tWIFI_CIPHER_TYPE_WEP40");
        break;
    case WIFI_CIPHER_TYPE_WEP104:
        ESP_LOGI(TAG, "Pairwise Cipher \tWIFI_CIPHER_TYPE_WEP104");
        break;
    case WIFI_CIPHER_TYPE_TKIP:
        ESP_LOGI(TAG, "Pairwise Cipher \tWIFI_CIPHER_TYPE_TKIP");
        break;
    case WIFI_CIPHER_TYPE_CCMP:
        ESP_LOGI(TAG, "Pairwise Cipher \tWIFI_CIPHER_TYPE_CCMP");
        break;
    case WIFI_CIPHER_TYPE_TKIP_CCMP:
        ESP_LOGI(TAG, "Pairwise Cipher \tWIFI_CIPHER_TYPE_TKIP_CCMP");
        break;
    case WIFI_CIPHER_TYPE_AES_CMAC128:
        ESP_LOGI(TAG, "Pairwise Cipher \tWIFI_CIPHER_TYPE_AES_CMAC128");
        break;
    case WIFI_CIPHER_TYPE_SMS4:
        ESP_LOGI(TAG, "Pairwise Cipher \tWIFI_CIPHER_TYPE_SMS4");
        break;
    case WIFI_CIPHER_TYPE_GCMP:
        ESP_LOGI(TAG, "Pairwise Cipher \tWIFI_CIPHER_TYPE_GCMP");
        break;
    case WIFI_CIPHER_TYPE_GCMP256:
        ESP_LOGI(TAG, "Pairwise Cipher \tWIFI_CIPHER_TYPE_GCMP256");
        break;
    default:
        ESP_LOGI(TAG, "Pairwise Cipher \tWIFI_CIPHER_TYPE_UNKNOWN");
        break;
    }
 }


 void send(const uint8_t *buf, uint32_t len) {
     for (int i=0; i<len; i++) {
         printf("%02x", buf[i]);
     }
 }

 void send_int(uint32_t i) {
     send((uint8_t*)&i, 4);
 }

 void send_packet(uint32_t ts_sec, uint32_t ts_usec, uint32_t len, const uint8_t* buf) {
     uint32_t incl_len = len > 2000 ? 2000 : len;

     printf("Packet %.3lu %.06lu %lu %lu\n", ts_sec, ts_usec, incl_len, len);

     printf("DATA:");
     send_int(ts_sec);
     send_int(ts_usec);
     send_int(incl_len);
     send_int(len);
     send(buf, incl_len);
     printf("\n");
     usleep(10000); // Delay packet sending
 }

 void sniffer_callback(void *buf, wifi_promiscuous_pkt_type_t type){
     const wifi_promiscuous_pkt_t* pkt = (wifi_promiscuous_pkt_t*)buf;
     const wifi_pkt_rx_ctrl_t ctrl = (wifi_pkt_rx_ctrl_t)pkt->rx_ctrl;
     int64_t t = esp_timer_get_time();
     send_packet(t/1000000, t%1000000, ctrl.sig_len-4, pkt->payload);
 }



  void wifi_scan()
 {
     ESP_ERROR_CHECK(esp_netif_init());
     ESP_ERROR_CHECK(esp_event_loop_create_default());
     esp_netif_t *sta_netif = esp_netif_create_default_wifi_sta();
     assert(sta_netif);

     wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
     ESP_ERROR_CHECK(esp_wifi_init(&cfg));
     
     uint16_t DEFAULT_SCAN_LIST_SIZE = 6;

     uint16_t number = DEFAULT_SCAN_LIST_SIZE;
     wifi_ap_record_t ap_info[DEFAULT_SCAN_LIST_SIZE];
     uint16_t ap_count = 0;
     memset(ap_info, 0, sizeof(ap_info));

     ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
     ESP_ERROR_CHECK(esp_wifi_start());
     ESP_ERROR_CHECK(esp_wifi_scan_start(NULL, true));
     ESP_ERROR_CHECK(esp_wifi_scan_get_ap_records(&number, ap_info));
     ESP_ERROR_CHECK(esp_wifi_scan_get_ap_num(&ap_count));
     ESP_LOGI(TAG, "Total APs scanned = %u", ap_count);
     for (int i = 0; (i < DEFAULT_SCAN_LIST_SIZE) && (i < ap_count); i++) {
         ESP_LOGI(TAG, "SSID \t\t%s", ap_info[i].ssid);
         ESP_LOGI(TAG, "RSSI \t\t%d", ap_info[i].rssi);
         print_auth_mode(ap_info[i].authmode);
         if (ap_info[i].authmode != WIFI_AUTH_WEP) {
             print_cipher_type(ap_info[i].pairwise_cipher, ap_info[i].group_cipher);
         }
         ESP_LOGI(TAG, "Channel \t\t%d\n", ap_info[i].primary);
     }

 }

 void app_main(void) {
     nvs_flash_init();
     wifi_scan();

     //tcpip_adapter_init();
     wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
     ESP_ERROR_CHECK(esp_wifi_init(&cfg));
     ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_RAM));
     ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_AP));
     ESP_ERROR_CHECK(esp_wifi_start());
     esp_wifi_set_promiscuous(true);
     esp_wifi_set_promiscuous_rx_cb(sniffer_callback);
     esp_wifi_set_channel(CHANNEL, WIFI_SECOND_CHAN_NONE);


     wifi_ap_record_t ap;
     esp_wifi_sta_get_ap_info(&ap);
     printf("%d\n", ap.rssi);
 }

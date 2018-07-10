/*
 * ESPRESSIF MIT License
 *
 * Copyright (c) 2018 <ESPRESSIF SYSTEMS (SHANGHAI) PTE LTD>
 *
 * Permission is hereby granted for use on ESPRESSIF SYSTEMS ESP8266 only, in which case,
 * it is free of charge, to any person obtaining a copy of this software and associated
 * documentation files (the "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the Software is furnished
 * to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all copies or
 * substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 * COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 * IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 */

#include <stddef.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "lwip/sockets.h"
#include "sys/socket.h"
#include "netdb.h"
#include "lwip/apps/sntp.h"
#include <wolfssl/ssl.h>
#include "espressif/esp_misc.h"
/* Constants that aren't configurable in menuconfig */
#define WEB_SERVER "www.howsmyssl.com"
#define WEB_PORT 443
#define WEB_URL "https://www.howsmyssl.com/a/check"
//#define WEB_URL "https://www.baidu.com"
#define REQUEST "GET " WEB_URL " HTTP/1.0\r\n" \
    "Host: "WEB_SERVER"\r\n" \
    "User-Agent: esp-idf/1.0 espressif\r\n" \
    "\r\n"

#define WOLFSSL_DEMO_THREAD_NAME        "wolfssl_client"
#define WOLFSSL_DEMO_THREAD_STACK_WORDS 4096
#define WOLFSSL_DEMO_THREAD_PRORIOTY    6

#define WOLFSSL_DEMO_SNTP_SERVERS       "pool.ntp.org"

const char send_data[] = REQUEST;
const int32_t send_bytes = sizeof(send_data);
char recv_data[1024] = { 0 };

const char *CA_CERT = "-----BEGIN CERTIFICATE-----\r\n"
		"MIIGPjCCBSagAwIBAgISA/2LB5XwYbU1ERk1oI1ni5EzMA0GCSqGSIb3DQEBCwUA\r\n"
		"MEoxCzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1MZXQncyBFbmNyeXB0MSMwIQYDVQQD\r\n"
		"ExpMZXQncyBFbmNyeXB0IEF1dGhvcml0eSBYMzAeFw0xODA2MjAwMDI5MjhaFw0x\r\n"
		"ODA5MTgwMDI5MjhaMBwxGjAYBgNVBAMTEXd3dy5ob3dzbXlzc2wuY29tMIIBIjAN\r\n"
		"BgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsr/u4OG03yoWLCNkDsOYw+fAjXfU\r\n"
		"EqbYWgdvRn/dcPsGEkZaY64zwwinsZdSb3KDQFtQBGmgCmJS7OuqG3SN1ywkqdVf\r\n"
		"yfAZUXNLMo4adefFmyzg/lWfhGqkyLxbi0K29iliz/GHKW8dueETsQIKryIoZHjA\r\n"
		"QteqCcl0YfJwZRbDkD/YR380vgaj/DqsV6/U18ZftprLBHeu+zEMNZJSmdlPuGI1\r\n"
		"L4Sp1mapECkby5X0uc/3qgN/kaQ7wcebzmJ3e8Rx4VTVZHxPM5umKyRu8jSXn6Lc\r\n"
		"zC686I/WTAoxczIKowfOJCh3WYnJgABdLKRlKs95Z7Edx4aLzImT5YB+3wIDAQAB\r\n"
		"o4IDSjCCA0YwDgYDVR0PAQH/BAQDAgWgMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggr\r\n"
		"BgEFBQcDAjAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBR4at5eIOP/sbwCS6tbKdTa\r\n"
		"gNoClTAfBgNVHSMEGDAWgBSoSmpjBH3duubRObemRWXv86jsoTBvBggrBgEFBQcB\r\n"
		"AQRjMGEwLgYIKwYBBQUHMAGGImh0dHA6Ly9vY3NwLmludC14My5sZXRzZW5jcnlw\r\n"
		"dC5vcmcwLwYIKwYBBQUHMAKGI2h0dHA6Ly9jZXJ0LmludC14My5sZXRzZW5jcnlw\r\n"
		"dC5vcmcvME0GA1UdEQRGMESCDWhvd3NteXNzbC5jb22CDWhvd3NteXRscy5jb22C\r\n"
		"EXd3dy5ob3dzbXlzc2wuY29tghF3d3cuaG93c215dGxzLmNvbTCB/gYDVR0gBIH2\r\n"
		"MIHzMAgGBmeBDAECATCB5gYLKwYBBAGC3xMBAQEwgdYwJgYIKwYBBQUHAgEWGmh0\r\n"
		"dHA6Ly9jcHMubGV0c2VuY3J5cHQub3JnMIGrBggrBgEFBQcCAjCBngyBm1RoaXMg\r\n"
		"Q2VydGlmaWNhdGUgbWF5IG9ubHkgYmUgcmVsaWVkIHVwb24gYnkgUmVseWluZyBQ\r\n"
		"YXJ0aWVzIGFuZCBvbmx5IGluIGFjY29yZGFuY2Ugd2l0aCB0aGUgQ2VydGlmaWNh\r\n"
		"dGUgUG9saWN5IGZvdW5kIGF0IGh0dHBzOi8vbGV0c2VuY3J5cHQub3JnL3JlcG9z\r\n"
		"aXRvcnkvMIIBBAYKKwYBBAHWeQIEAgSB9QSB8gDwAHYA23Sv7ssp7LH+yj5xbSzl\r\n"
		"uaq7NveEcYPHXZ1PN7Yfv2QAAAFkGs+TMQAABAMARzBFAiAztEGSej1f94TeljBP\r\n"
		"B46aXrIOvIjpoVKUDFDw6BQbtwIhAMTzLF/ikRlBRZ2lGyUHHagALuPDKnrNVrlY\r\n"
		"hOK2V6lYAHYAKTxRllTIOWW6qlD8WAfUt2+/WHopctykwwz05UVH9HgAAAFkGs+T\r\n"
		"RgAABAMARzBFAiAGDVkrVUJNBjRbNyzPv2+8pL9x9pl2v7rWWYT+Sz/s+QIhAOyl\r\n"
		"sutvQiHrB3Cn4Dh96NfWSdW/7E6v6TKjf2kcbtRqMA0GCSqGSIb3DQEBCwUAA4IB\r\n"
		"AQA3XisPPzdF57oR/vRHil6IZ7A6KCrXikn/ywIuZofN24DpJjNOKnbMAzjwRUVp\r\n"
		"kxV6QwFlRYAj1uYLwMpLnitv0MBrovAlg0EivS+R9Iw+Bf9gSmPG+bEkHDGETfTb\r\n"
		"Xa3OjJPARYSXYieVuNqnRGi/QCRkBuXw0RsXQPvQ3EsNCHVw8wtvw5X0WR+v/N1e\r\n"
		"D+NB/ZzgxVpYTwvRWErmHijhi19dEafaqtYRsjgblPf3bReIZ2jTfaLZO7GlKIaJ\r\n"
		"H4hbfHMGS7zBMkE+s32JLC5MPNPq1+WIRNZ5FiiCJFzOwN1RE8Blexw8D7XlG1ew\r\n"
		"0kU/0daLNTrAcVTMMoH0VvUy\r\n"
		"-----END CERTIFICATE-----\r\n";

static void get_time() {
	struct timeval now;
	int sntp_retry_cnt = 0;
	int sntp_retry_time = 0;

	sntp_setoperatingmode(0);
	sntp_setservername(0, WOLFSSL_DEMO_SNTP_SERVERS);
	sntp_init();
	int32_t i = 0;
	while (1) {
		for (i = 0; (i < (SNTP_RECV_TIMEOUT / 100)) && now.tv_sec < 1525952900;
				i++) {
			vTaskDelay(100 / portTICK_RATE_MS);
			gettimeofday(&now, NULL);
		}

		if (now.tv_sec < 1525952900) {
			sntp_retry_time = SNTP_RECV_TIMEOUT << sntp_retry_cnt;

			if (SNTP_RECV_TIMEOUT
					<< (sntp_retry_cnt + 1)< SNTP_RETRY_TIMEOUT_MAX) {
				sntp_retry_cnt++;
			}

			printf("SNTP get time failed, retry after %d ms\n",
					sntp_retry_time);
			vTaskDelay(sntp_retry_time / portTICK_RATE_MS);
		} else {
			printf("SNTP get time success\n");
			break;
		}
	}
}

static void wolfssl_client(void* pv) {
	int ret = 0;
	printf("wolfssl_client task start\r\n");
	uint32_t current_timestamp = 0;
	const portTickType xDelay = 500 / portTICK_RATE_MS;
	WOLFSSL_CTX *ctx = NULL;
	WOLFSSL *ssl = NULL;

	int socket = -1;
	struct sockaddr_in sock_addr;
	struct hostent *entry = NULL;
	 ip_addr_t target_ip;
	/* CA date verification need system time */
	get_time();
	while (1) {
		printf("Setting hostname for TLS session...\n");
		do {
			ret = netconn_gethostbyname(WEB_SERVER, &target_ip);
			vTaskDelay(xDelay);
		} while (ret);
		printf("get target IP is "IPSTR"\n", IP2STR(&target_ip));

		printf("Init wolfSSL...\n");
		ret = wolfSSL_Init();
		if (ret != WOLFSSL_SUCCESS) {
			goto failed1;
		}
		printf("Set wolfSSL ctx ...\n");
		ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method());
		if (!ctx) {
			printf("Set wolfSSL ctx failed...\n");
			goto failed1;
		}
		printf("Creat socket ...\n");
		socket = socket(AF_INET, SOCK_STREAM, 0);

		if (socket < 0) {
			printf("Creat socket failed...\n");
			goto failed2;
		}

#if 0
		printf("Loading the CA root certificate...\n");
		ret = wolfSSL_CTX_load_verify_buffer(ctx, CA_CERT, strlen(CA_CERT),
				WOLFSSL_FILETYPE_PEM);

		if (WOLFSSL_SUCCESS != ret) {
			printf("Loading the CA root certificate failed...\n");
			goto failed3;
		}

		wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_PEER, NULL);
#else
		wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_NONE, NULL);
#endif
		memset(&sock_addr, 0, sizeof(sock_addr));
		sock_addr.sin_family = AF_INET;
		sock_addr.sin_port = htons(WEB_PORT);
//		memcpy(&sock_addr.sin_addr.s_addr, entry->h_addr_list[0],
//				entry->h_length);
		sock_addr.sin_addr.s_addr = target_ip.addr;
		ret = connect(socket, (struct sockaddr*) &sock_addr, sizeof(sock_addr));
		if (ret) {
			goto failed3;
		}

		ssl = wolfSSL_new(ctx);
		if (!ssl) {
			printf("Create wolfSSL failed...\n");
			goto failed3;
		}

		wolfSSL_set_fd(ssl, socket);

//	wolfSSL_set_verify(ssl, WOLFSSL_VERIFY_NONE, NULL);

		ret = wolfSSL_connect(ssl);
		if (WOLFSSL_SUCCESS != ret) {
			printf("Performing the SSL/TLS handshake failed:%d\n", ret);
			goto failed4;
		}

		printf("Writing HTTPS request...\n");
		ret = wolfSSL_write(ssl, send_data, send_bytes);
		if (ret <= 0) {
			printf("Writing HTTPS request failed:%d\n", ret);
			goto failed5;
		}
		printf("Reading HTTPS response...\n");
		do {
			ret = wolfSSL_read(ssl, recv_data, sizeof(recv_data));

			if (ret <= 0) {
				printf("\nConnection closed\n");
				break;
			}

			/* Print response directly to stdout as it is read */\
int i = 0;
			for (i = 0; i < ret; i++) {
				printf("%c", recv_data[i]);
			}
		} while (1);

		failed5: wolfSSL_shutdown(ssl);
		failed4: wolfSSL_free(ssl);
		failed3: close(socket);
		failed2: wolfSSL_CTX_free(ctx);
		failed1: wolfSSL_Cleanup();
		vTaskDelete(NULL);
	}
	return;
}

void user_conn_init(void) {
	int ret;

	ret = xTaskCreate(wolfssl_client, WOLFSSL_DEMO_THREAD_NAME,
			WOLFSSL_DEMO_THREAD_STACK_WORDS, NULL, WOLFSSL_DEMO_THREAD_PRORIOTY,
			NULL);

	if (ret != pdPASS) {
		printf("create thread %s failed\n", WOLFSSL_DEMO_THREAD_NAME);
		return;
	}
}


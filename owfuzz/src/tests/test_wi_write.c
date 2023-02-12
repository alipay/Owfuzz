#include <stddef.h>
#include <string.h>
#include <assert.h>
#include <stdio.h>

#include "osdep_wifi_transmit.h"

void test_single_wi_write(char *iface) {
    struct packet pkt;

    memset(&pkt, 0, sizeof(struct packet));
    strncpy(pkt.data, "HELLO", strlen("HELLO"));
    pkt.len = strlen("HELLO");
    pkt.channel = 7;

    struct wif * wi = wi_open(iface);
    if (wi == NULL) {
        assert("Failed to open interface");
    }
    printf("wi_open successfulL %08X\n", wi);

    struct devices dev;
    memset(&dev, 0, sizeof(struct devices));

    dev.fd_out = wi_fd(wi);
    printf("wi_fd successful: %d\n", dev.fd_out);

    int res = 0;
    if (-1 == (res = wi_write(wi, pkt.data, pkt.len, NULL)))
    {
        assert("Failed to wi_write");
    }
    printf("wi_write successful: %d\n", res);

    wi_close(wi);
    printf("wi_close successful\n");
}

void test_multi_wi_write(char *iface) {
    struct packet pkt;

    memset(&pkt, 0, sizeof(struct packet));
    strncpy(pkt.data, "HELLO", strlen("HELLO"));
    pkt.len = strlen("HELLO");
    pkt.channel = 7;

    struct wif * wi = wi_open(iface);
    if (wi == NULL) {
        assert("Failed to open interface");
    }
    printf("wi_open successfulL %08X\n", wi);

    struct devices dev;
    memset(&dev, 0, sizeof(struct devices));

    dev.fd_out = wi_fd(wi);
    printf("wi_fd successful: %d\n", dev.fd_out);

    for (int i = 0; i < 1000; i++) {
        int res = 0;
        if (-1 == (res = wi_write(wi, pkt.data, pkt.len, NULL)))
        {
            assert("Failed to wi_write");
        }
        printf("wi_write successful: %d (%d out of 1000)\r", res, i);
    }
    printf("\n");

    wi_close(wi);
    printf("wi_close successful\n");
}


void main() {
    printf("\nStarting test_single_wi_write\n");
    test_single_wi_write("wlp59s0");

    printf("\nStarting test_multi_wi_write\n");
    test_multi_wi_write("wlp59s0");
}


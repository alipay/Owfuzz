#include <utypes.h>
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
    assert (wi != NULL && "Failed to open interface");
    printf("wi_open successful %08X\n", wi);

    struct devices dev;
    memset(&dev, 0, sizeof(struct devices));

    dev.fd_out = wi_fd(wi);
    printf("wi_fd successful: %d\n", dev.fd_out);

    int res = wi_write(wi, pkt.data, pkt.len, NULL);
    assert(res != -1 && "Failed to wi_write");
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
    assert (wi != NULL && "Failed to open interface");

    printf("wi_open successful %08X\n", wi);

    struct devices dev;
    memset(&dev, 0, sizeof(struct devices));

    dev.fd_out = wi_fd(wi);
    printf("wi_fd successful: %d\n", dev.fd_out);

    for (int i = 0; i < 1000; i++) {
        int res = wi_write(wi, pkt.data, pkt.len, NULL);
        assert(res != -1 && "Failed to wi_write");
        printf("wi_write successful: %d (%d out of 1000)\r", res, i);
    }
    printf("\n");

    wi_close(wi);
    printf("wi_close successful\n");
}


int main(int argc, char *argv[]) {
    char interface_name[128] = {0};
    if (argc == 2) {
        strcpy(interface_name, argv[1]);
    } else {
        strcpy(interface_name, "wlp59s0");
    }
    printf("Using interface_name: %s\n", interface_name);
    printf("\nStarting test_single_wi_write\n");
    test_single_wi_write(interface_name);

    printf("\nStarting test_multi_wi_write\n");
    test_multi_wi_write(interface_name);

    return 0;
}


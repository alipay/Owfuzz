#include <utypes.h>
#include <string.h>
#include <assert.h>
#include <stdio.h>

#include "osdep_wifi_transmit.h"

void test_single_wi_read(char *iface)
{
    struct packet pkt;
    memset(&pkt, 0, sizeof(struct packet));

    struct wif *wi = wi_open(iface);
    assert (wi != NULL && "Failed to open interface");

    printf("wi_open successful %08X\n", wi);

    struct devices dev;
    memset(&dev, 0, sizeof(struct devices));

    dev.fd_out = wi_fd(wi);
    printf("wi_fd successful: %d\n", dev.fd_out);

    int rc = 0;
    do
	{
		rc = wi_read(wi, pkt.data, MAX_IEEE_PACKET_SIZE, &pkt.ri);
        printf("rc: %d      \r", rc);
		if (-1 == rc)
		{
			assert(0 && "wi_read()");
			pkt.len = 0;
            break;
		}
        sleep(0.1);
	} while (rc < 1);

	pkt.len = rc;
	pkt.channel = 7;
    printf("wi_read successful: %d\n", rc);

    wi_close(wi);
    printf("wi_close successful\n");
}

int main(int argc, char *argv[])
{
    char interface_name[128] = {"wlp59s0"};
    if (argc == 2)
    {
        strcpy(interface_name, argv[1]);
    }
    else
    {
        strcpy(interface_name, "wlp59s0");
    }
    printf("Using interface_name: %s\n", interface_name);
    printf("\nStarting test_single_wi_read\n");
    test_single_wi_read(interface_name);
}
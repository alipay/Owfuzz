#include <utypes.h>
#include <string.h>
#include <assert.h>
#include <stdio.h>
#include <pthread.h>

#include "osdep_wifi_transmit.h"

pthread_mutex_t owq_mutex = PTHREAD_MUTEX_INITIALIZER;

int send_interval = 0;
int receive_interval = 0;

struct packet read_packet_ex(struct wif *wi)
{
	int rc;
	struct packet pkt = {0};

	do
	{
		rc = wi_read(wi, pkt.data, MAX_IEEE_PACKET_SIZE, &pkt.ri);
		if (-1 == rc)
		{
			perror("wi_read()");
			pkt.len = 0;
			return pkt;
		}
	} while (rc < 1);

	pkt.len = rc;

	return pkt;
}

void *receive_thread(void *param)
{
	struct wif *wi = (struct wif *)param;
	struct packet pkt = {0};

	while (true)
	{
        receive_interval++;
		memset(&pkt, 0, sizeof(struct packet));
		pkt = read_packet_ex(wi);
		if (pkt.len > 0)
		{
			pthread_mutex_lock(&owq_mutex);
            sleep(0.1); // Simulate pushing to the queue
			pthread_mutex_unlock(&owq_mutex);
		}
		usleep(10);
	}

	pthread_exit(NULL);
}

void *send_thread(void *param)
{
	struct wif *wi = (struct wif *)param;
	struct packet pkt = {0};
    strcpy(pkt.data, "HELLO");
    pkt.len = strlen("HELLO");
    pkt.channel = 7;

	while (true)
	{
        send_interval++;
		int res = wi_write(wi, pkt.data, pkt.len, NULL);
        assert(res != -1 && "Failed to wi_write");
		sleep(0.1);
	}

	pthread_exit(NULL);
}

void test_threads(char *iface) {
    pthread_t fthread_receive;
    pthread_t fthread_send;

    struct wif *wi = wi_open(iface);
    assert (wi != NULL && "Failed to open interface");

    printf("wi_open successful %08X\n", wi);

    pthread_create(&fthread_receive, NULL, receive_thread, wi);
    pthread_create(&fthread_send, NULL, send_thread, wi);
    
    while(true) {
        printf("receive_interval: %d, send_interval: %d     \r", receive_interval, send_interval);
        sleep(0.5);
    }
}

int main(int argc, char *argv[]) {
    char interface_name[128] = {0};
    if (argc == 2) {
        strcpy(interface_name, argv[1]);
    } else {
        strcpy(interface_name, "wlp59s0");
    }
    printf("Using interface_name: %s\n", interface_name);

    pthread_mutex_init(&owq_mutex, NULL);

    test_threads(interface_name);

    return 0;
}
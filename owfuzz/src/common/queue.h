#ifndef _QUEUE_H
#define _QUEUE_H

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include "osdep_wifi_transmit.h"

struct qlink
{
    struct packet pkt;
    struct qlink *next;
};

struct ow_queue
{
    struct qlink *front;
    struct qlink *rear;
    int size;
};

void ow_queue_init(struct ow_queue *owq);
int ow_queue_empty(struct ow_queue *owq);
void ow_queue_push(struct ow_queue *owq, struct packet *pkt);
int ow_queue_pop(struct ow_queue *owq, struct packet *pkt);
void ow_queue_destroy(struct ow_queue *owq);

#endif

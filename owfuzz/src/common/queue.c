#include "queue.h"

void ow_queue_init(struct ow_queue *owq)
{
    owq->front = NULL;
    owq->rear = NULL;
    owq->size = 0;
}

int ow_queue_empty(struct ow_queue *owq)
{
    return (owq->size == 0);
}

void ow_queue_push(struct ow_queue *owq, struct packet *pkt)
{
    struct qlink *node;
    node = (struct qlink *)malloc(sizeof(struct qlink));
    assert(node != NULL);

    node->pkt = *pkt;
    node->next = NULL;

    if (ow_queue_empty(owq))
    {
        owq->front = node;
        owq->rear = node;
    }
    else
    {
        owq->rear->next = node;
        owq->rear = node;
    }

    ++owq->size;
}

int ow_queue_pop(struct ow_queue *owq, struct packet *pkt)
{
    struct qlink *tmp;

    if (ow_queue_empty(owq))
    {
        return 0;
    }

    tmp = owq->front;
    *pkt = owq->front->pkt;
    owq->front = owq->front->next;
    free(tmp);

    --owq->size;

    return 1;
}

void ow_queue_destroy(struct ow_queue *owq)
{
    struct qlink *tmp;

    while (owq->front)
    {
        tmp = owq->front;
        owq->front = owq->front->next;
        free(tmp);
    }
}

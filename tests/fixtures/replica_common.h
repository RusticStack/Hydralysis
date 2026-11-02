/* Wire format and clock of the owner/replica fixture pair (replica_a.c owner, replica_b.c replica; spec 15.5).
   One message per owner tick over the named pipe \\.\pipe\hydra_replica_<tag>. */
#ifndef REPLICA_COMMON_H
#define REPLICA_COMMON_H
#include "trace_common.h"

#define TICK_MS 20
#define STEPS 200            /* 4 s of owner ticks */
#define OUTAGE_FROM 60       /* owner ticks 60..159 are not sent: a 2 s outage */
#define OUTAGE_TO 160
#define OWNER_ONLY_FROM 30   /* object 2 exists on the owner from tick 30 and is never replicated */
#define DELAY_MS 100         /* injected by the replica between receiving and applying a value */

enum { MSG_SYNC = 1, MSG_VALUE = 2, MSG_END = 3 };

typedef struct Message {
    int kind;
    int obj;
    int seq;
    int value;
    double sent_ms;          /* the owner clock when sent */
} Message;

/* The logged value of object 1 at owner tick seq: a moving value. */
#define MOVING_VALUE(seq) ((seq) * 7)

static void pipe_name(char *out, size_t size, const char *tag) {
    _snprintf(out, size, "\\\\.\\pipe\\hydra_replica_%s", tag);
    out[size - 1] = 0;
}
#endif

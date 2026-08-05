#ifndef RECORDER_SCRIPT_WORKER_H
#define RECORDER_SCRIPT_WORKER_H

#include <stddef.h>

typedef struct ScriptWorker ScriptWorker;

typedef struct {
    const char *const *argv;
    size_t argc;
    const char *json_payload;
    const char *const *env_names;
    const char *const *env_values;
    size_t env_count;
    unsigned timeout_sec;
} ScriptJobSpec;

/* Create a fire-and-forget worker. queue_capacity bounds pending jobs and
 * worker_count bounds concurrent child processes. */
int script_worker_create(size_t queue_capacity, size_t worker_count,
                         ScriptWorker **out);

/* Non-blocking submission. Returns 0, ENOSPC when the queue is full, or
 * EINVAL/ENOMEM for malformed or uncopyable jobs. The worker copies all data. */
int script_worker_submit(ScriptWorker *worker, const ScriptJobSpec *spec);

/* Stop accepting work, wait for queued/running jobs, and release resources. */
void script_worker_destroy(ScriptWorker *worker);

#endif

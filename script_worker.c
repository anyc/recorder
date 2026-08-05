#define _POSIX_C_SOURCE 200809L
#include "script_worker.h"

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define SCRIPT_MAX_ARGC 128u
#define SCRIPT_MAX_ARG_LEN (64u * 1024u)
#define SCRIPT_MAX_JSON (1024u * 1024u)
#define SCRIPT_MAX_ENV 128u
#define SCRIPT_MAX_ENV_LEN (64u * 1024u)
#define SCRIPT_DEFAULT_TIMEOUT 30u

typedef struct ScriptJob {
    char **argv;
    size_t argc;
    char *json;
    char **env_names;
    char **env_values;
    size_t env_count;
    unsigned timeout_sec;
    struct ScriptJob *next;
} ScriptJob;

struct ScriptWorker {
    pthread_mutex_t lock;
    pthread_cond_t cond;
    ScriptJob *head, *tail;
    size_t queued;
    size_t capacity;
    size_t workers;
    int stopping;
    pthread_t *threads;
};

static void job_free(ScriptJob *j) {
    size_t i;
    if (!j) return;
    for (i = 0; i < j->argc; i++) free(j->argv[i]);
    free(j->argv);
    free(j->json);
    for (i = 0; i < j->env_count; i++) {
        free(j->env_names[i]);
        free(j->env_values[i]);
    }
    free(j->env_names);
    free(j->env_values);
    free(j);
}

static int copy_string(const char *s, size_t max, char **out) {
    size_t n;
    if (!s || !out) return EINVAL;
    n = strlen(s);
    if (n > max) return EINVAL;
    *out = strdup(s);
    return *out ? 0 : ENOMEM;
}

static int job_copy(const ScriptJobSpec *spec, ScriptJob **out) {
    ScriptJob *j;
    size_t i;
    int rc;
    if (!spec || !out || !spec->argv || spec->argc == 0 ||
        spec->argc > SCRIPT_MAX_ARGC || !spec->json_payload ||
        spec->env_count > SCRIPT_MAX_ENV) return EINVAL;
    j = calloc(1, sizeof(*j));
    if (!j) return ENOMEM;
    j->argc = spec->argc;
    j->argv = calloc(j->argc + 1, sizeof(char *));
    if (!j->argv) { job_free(j); return ENOMEM; }
    for (i = 0; i < j->argc; i++) {
        rc = copy_string(spec->argv[i], SCRIPT_MAX_ARG_LEN, &j->argv[i]);
        if (rc) { job_free(j); return rc; }
    }
    rc = copy_string(spec->json_payload, SCRIPT_MAX_JSON, &j->json);
    if (rc) { job_free(j); return rc; }
    j->env_count = spec->env_count;
    if (j->env_count) {
        j->env_names = calloc(j->env_count, sizeof(char *));
        j->env_values = calloc(j->env_count, sizeof(char *));
        if (!j->env_names || !j->env_values) { job_free(j); return ENOMEM; }
    }
    for (i = 0; i < j->env_count; i++) {
        if (!spec->env_names || !spec->env_values ||
            strncmp(spec->env_names[i], "REC_", 4) != 0) {
            job_free(j); return EINVAL;
        }
        rc = copy_string(spec->env_names[i], SCRIPT_MAX_ENV_LEN, &j->env_names[i]);
        if (!rc) rc = copy_string(spec->env_values[i], SCRIPT_MAX_ENV_LEN,
                                  &j->env_values[i]);
        if (rc) { job_free(j); return rc; }
    }
    j->timeout_sec = spec->timeout_sec ? spec->timeout_sec : SCRIPT_DEFAULT_TIMEOUT;
    *out = j;
    return 0;
}

static void run_job(const ScriptJob *j) {
    int pipefd[2];
    pid_t pid;
    if (pipe(pipefd) < 0) return;
    pid = fork();
    if (pid < 0) { close(pipefd[0]); close(pipefd[1]); return; }
    if (pid == 0) {
        char **envp;
        size_t i;
        int devnull;
        envp = calloc(j->env_count + 1, sizeof(char *));
        if (!envp) _exit(127);
        for (i = 0; i < j->env_count; i++) {
            size_t n = strlen(j->env_names[i]) + strlen(j->env_values[i]) + 2;
            envp[i] = malloc(n);
            if (!envp[i]) _exit(127);
            (void)snprintf(envp[i], n, "%s=%s", j->env_names[i], j->env_values[i]);
        }
        if (dup2(pipefd[0], STDIN_FILENO) < 0) _exit(127);
        close(pipefd[0]); close(pipefd[1]);
        devnull = open("/dev/null", O_WRONLY);
        if (devnull >= 0) { (void)dup2(devnull, STDOUT_FILENO); (void)dup2(devnull, STDERR_FILENO); close(devnull); }
        execve(j->argv[0], j->argv, envp);
        _exit(127);
    }
    close(pipefd[0]);
    /* Avoid blocking the worker forever if a child never reads stdin. */
    {
        sigset_t set, oldset;
        struct timespec start, now;
        size_t off = 0, total = strlen(j->json);
        (void)clock_gettime(CLOCK_MONOTONIC, &start);
        (void)fcntl(pipefd[1], F_SETFL, fcntl(pipefd[1], F_GETFL) | O_NONBLOCK);
        (void)sigemptyset(&set);
        (void)sigaddset(&set, SIGPIPE);
        (void)pthread_sigmask(SIG_BLOCK, &set, &oldset);
        while (off < total + 1) {
            const char *src = off < total ? j->json + off : "\n";
            size_t left = off < total ? total - off : 1;
            ssize_t n = write(pipefd[1], src, left);
            if (n > 0) { off += (size_t)n; continue; }
            if (n < 0 && (errno == EPIPE || errno == EBADF)) break;
            if (n < 0 && (errno == EAGAIN || errno == EINTR)) {
                struct pollfd pfd = { pipefd[1], POLLOUT, 0 };
                (void)poll(&pfd, 1, 100);
            } else break;
            (void)clock_gettime(CLOCK_MONOTONIC, &now);
            if ((unsigned)((now.tv_sec - start.tv_sec) * 1000 +
                           (now.tv_nsec - start.tv_nsec) / 1000000) >=
                j->timeout_sec * 1000u) break;
        }
        (void)pthread_sigmask(SIG_SETMASK, &oldset, NULL);
    }
    close(pipefd[1]);
    {
        unsigned elapsed = 0;
        int status;
        while (elapsed < j->timeout_sec * 1000u) {
            pid_t r = waitpid(pid, &status, WNOHANG);
            if (r == pid || (r < 0 && errno == ECHILD)) return;
            {
                struct timespec ts = { 0, 10000000L };
                nanosleep(&ts, NULL);
            }
            elapsed += 10;
        }
        (void)kill(pid, SIGKILL);
        (void)waitpid(pid, &status, 0);
    }
}

static void *worker_main(void *arg) {
    ScriptWorker *w = arg;
    for (;;) {
        ScriptJob *j;
        pthread_mutex_lock(&w->lock);
        while (!w->head && !w->stopping) pthread_cond_wait(&w->cond, &w->lock);
        if (!w->head && w->stopping) { pthread_mutex_unlock(&w->lock); break; }
        j = w->head; w->head = j->next; if (!w->head) w->tail = NULL; w->queued--;
        pthread_mutex_unlock(&w->lock);
        run_job(j);
        job_free(j);
    }
    return NULL;
}

int script_worker_create(size_t queue_capacity, size_t worker_count, ScriptWorker **out) {
    ScriptWorker *w;
    size_t i;
    int rc;
    if (!out || queue_capacity == 0 || worker_count == 0) return EINVAL;
    w = calloc(1, sizeof(*w)); if (!w) return ENOMEM;
    w->capacity = queue_capacity; w->workers = worker_count;
    pthread_mutex_init(&w->lock, NULL); pthread_cond_init(&w->cond, NULL);
    w->threads = calloc(worker_count, sizeof(pthread_t));
    if (!w->threads) { script_worker_destroy(w); return ENOMEM; }
    for (i = 0; i < worker_count; i++) {
        rc = pthread_create(&w->threads[i], NULL, worker_main, w);
        if (rc) { w->workers = i; w->stopping = 1; pthread_cond_broadcast(&w->cond); script_worker_destroy(w); return rc; }
    }
    *out = w; return 0;
}

int script_worker_submit(ScriptWorker *w, const ScriptJobSpec *spec) {
    ScriptJob *j; int rc = job_copy(spec, &j);
    if (rc) return rc;
    pthread_mutex_lock(&w->lock);
    if (w->stopping || w->queued >= w->capacity) { pthread_mutex_unlock(&w->lock); job_free(j); return ENOSPC; }
    if (w->tail) w->tail->next = j; else w->head = j; w->tail = j; w->queued++;
    pthread_cond_signal(&w->cond); pthread_mutex_unlock(&w->lock); return 0;
}

void script_worker_destroy(ScriptWorker *w) {
    size_t i; ScriptJob *j, *next;
    if (!w) return;
    pthread_mutex_lock(&w->lock); w->stopping = 1; pthread_cond_broadcast(&w->cond); pthread_mutex_unlock(&w->lock);
    if (w->threads) for (i = 0; i < w->workers; i++) pthread_join(w->threads[i], NULL);
    j = w->head; while (j) { next = j->next; job_free(j); j = next; }
    free(w->threads); pthread_cond_destroy(&w->cond); pthread_mutex_destroy(&w->lock); free(w);
}

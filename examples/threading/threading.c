#include "threading.h"
#include <pthread.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

// Optional: use these functions to add debug or error prints to your application
//#define DEBUG_LOG(msg,...)
#define DEBUG_LOG(msg,...) printf("threading: " msg "\n" , ##__VA_ARGS__)
#define ERROR_LOG(msg,...) printf("threading ERROR: " msg "\n" , ##__VA_ARGS__)

void* threadfunc(void* thread_param)
{
    int err;
    struct thread_data* td = (struct thread_data *) thread_param;

    DEBUG_LOG("Waiting to obtain lock");
    usleep(td->wait_to_obtain_ms * 1000);

    DEBUG_LOG("Locking mutex");
    err = pthread_mutex_lock(td->mutex);
    if (err != 0) {
        ERROR_LOG("Could not lock mutex");
    }

    DEBUG_LOG("Sleeping in critical region");
    usleep(td->wait_to_release_ms * 1000);

    DEBUG_LOG("Unlocking mutex");
    err = pthread_mutex_unlock(td->mutex);
    if (err != 0) {
        ERROR_LOG("Could not unlock mutex");
    }

    td->thread_complete_success = true;

    return thread_param;
}


bool start_thread_obtaining_mutex(pthread_t *thread, pthread_mutex_t *mutex,int wait_to_obtain_ms, int wait_to_release_ms)
{
    struct thread_data* td = malloc(sizeof(struct thread_data));

    // Init thread func parameters
    td->mutex = mutex;
    td->wait_to_obtain_ms = wait_to_obtain_ms;
    td->wait_to_release_ms = wait_to_release_ms;
    td->thread_complete_success = false;

    // Create thread
    int err = pthread_create(thread, NULL, threadfunc, td);

    if (err == 0) {
        return true;
    }

    free(td);
    return false;
}


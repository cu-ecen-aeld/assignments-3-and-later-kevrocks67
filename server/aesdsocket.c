#include <asm-generic/socket.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <errno.h>
#include <string.h>
#include <sys/syslog.h>
#include <syslog.h>
#include <fcntl.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdbool.h>
#include <signal.h>
#include <pthread.h>
#include <sys/queue.h>
#include <stdatomic.h>

#ifndef USE_AESD_CHAR_DEVICE
#define USE_AESD_CHAR_DEVICE 1
#endif

#if USE_AESD_CHAR_DEVICE == 1
#define DATA_FILE_PATH "/dev/aesdchar"
#else
#define DATA_FILE_PATH "/var/tmp/aesdsocketdata"
#endif

#define PORT 9000
#define BLOCK_SIZE 4096
#define TIMESTAMP_BUFFER_SIZE 64
#define TIMESTAMP_INTERVAL_SECS 10

pthread_mutex_t queue_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t file_mutex = PTHREAD_MUTEX_INITIALIZER;

#if USE_AESD_CHAR_DEVICE == 0
pthread_mutex_t time_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_t timestamp_thread_id;
#endif

atomic_bool running = true;

int server_fd = -1;
int read_fd = -1;
int write_fd = -1;

struct thread_data {
    bool thread_complete;
    pthread_mutex_t complete_mutex;
    int accepted_fd;
    struct sockaddr_in peer_addr;
    socklen_t peer_addr_len;
} thread_data;

struct thread {
    pthread_t thread_id;
    struct thread_data* data;
    SLIST_ENTRY(thread) pointers;
};

SLIST_HEAD(thread_id_list, thread) thread_queue;

void signal_handler(int _) {
    //syslog(LOG_USER | LOG_ERR, "Caught signal, exiting");
    atomic_store(&running, false);

    #if USE_AESD_CHAR_DEVICE == 0
    pthread_cancel(timestamp_thread_id);
    pthread_join(timestamp_thread_id, NULL);
    #endif

    pthread_mutex_lock(&queue_mutex);
    struct thread* current = SLIST_FIRST(&thread_queue);
    while (current != NULL) {
        pthread_join(current->thread_id, NULL);
        current = SLIST_NEXT(current, pointers);
    }

    current = SLIST_FIRST(&thread_queue);
    while (current != NULL) {
        struct thread* next_cleanup = SLIST_NEXT(current, pointers);
        if (current->data != NULL) {
            free(current->data);
        }
        SLIST_REMOVE(&thread_queue, current, thread, pointers);
        free(current);
        current = next_cleanup;
    }
    pthread_mutex_unlock(&queue_mutex);

    pthread_mutex_destroy(&queue_mutex);
    pthread_mutex_destroy(&file_mutex);

    pthread_mutex_destroy(&queue_mutex);
    pthread_mutex_destroy(&file_mutex);

    close(server_fd);
    close(read_fd);

    #if USE_AESD_CHAR_DEVICE == 0
    remove(DATA_FILE_PATH);
    #endif

    exit(0);
}

#if USE_AESD_CHAR_DEVICE == 0
void* timestamper(void* _) {
    time_t timer;
    char timestamp_buf[TIMESTAMP_BUFFER_SIZE];
    struct tm tm_info_buf;
    const struct tm* tm_info = NULL;
    int fd;
    ssize_t bytes_written;

    while(atomic_load(&running)) {
        sleep(TIMESTAMP_INTERVAL_SECS);
        time(&timer);

        pthread_mutex_lock(&time_mutex);
        if (localtime_r(&timer, &tm_info_buf) == 0) {
            syslog(LOG_USER | LOG_ERR, "Error getting local time (localtime_r)");
            continue;
        } else {
            tm_info = &tm_info_buf;
        }

        if (tm_info == NULL) {
            syslog(LOG_USER | LOG_ERR, "Error getting local time (localtime)");
            pthread_mutex_unlock(&time_mutex);
            continue;
        }
        pthread_mutex_unlock(&time_mutex);

        if (strftime(timestamp_buf, TIMESTAMP_BUFFER_SIZE, "timestamp:%a, %d %b %Y %H:%M:%S %z\n", &tm_info_buf) == 0) {
            syslog(LOG_USER | LOG_ERR, "Error formatting timestamp");
            continue;
        }

        pthread_mutex_lock(&file_mutex);
        fd = open(DATA_FILE_PATH, O_RDWR | O_CREAT | O_APPEND, 00644);
        if (fd == -1) {
            syslog(LOG_USER | LOG_ERR, "Could not open file to write");
            pthread_mutex_unlock(&file_mutex);
            continue;
        }

        bytes_written = write(fd, timestamp_buf, strlen(timestamp_buf));
        if (bytes_written == -1) {
            syslog(LOG_USER | LOG_ERR, "Error writing timestamp to file: %s", strerror(errno));
        }
        close(fd);
        pthread_mutex_unlock(&file_mutex);
    }
    syslog(LOG_USER | LOG_INFO, "Timestamp writer thread exiting");
    return NULL;
}
#endif

int start_and_listen(int port) {
    int socket_fd;

    struct sockaddr_in bind_addr;
    bind_addr.sin_addr.s_addr = INADDR_ANY;
    bind_addr.sin_port = htons(port);
    bind_addr.sin_family = AF_INET;
    socklen_t bind_addr_len = (socklen_t) sizeof(bind_addr);

    socket_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

    if (socket_fd == -1) {
        perror(strerror(errno));
        return -1;
    }

    int opt_value = 1;
    if (setsockopt(socket_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt_value, sizeof(opt_value)) != 0) {
        perror(strerror(errno));
        return -1;
    }

    if (bind(socket_fd, (const struct sockaddr*) &bind_addr, bind_addr_len) != 0) {
        perror(strerror(errno));
        return -1;
    }

    if (listen(socket_fd, 10) != 0) {
        perror(strerror(errno));
        return -1;
    }
    return socket_fd;
}

int write_to_file(pthread_mutex_t* mutex, const char recv_buf[BLOCK_SIZE], ssize_t size) {
    pthread_mutex_lock(mutex);
    write_fd = open(DATA_FILE_PATH, O_RDWR | O_CREAT | O_APPEND, 00644);

    if (write_fd == -1) {
        syslog(LOG_USER | LOG_ERR, "Could not open file to write");
        pthread_mutex_unlock(mutex);
        return -1;
    }

    syslog(LOG_USER | LOG_DEBUG, "Writing to %s", DATA_FILE_PATH);

    ssize_t bytes_written = write(write_fd, recv_buf, size);
    syslog(LOG_USER | LOG_DEBUG, "Wrote %d bytes to file", (int) bytes_written);

    if (bytes_written < 0) {
        syslog(LOG_USER | LOG_ERR, "Could not write to file %s", DATA_FILE_PATH);
        pthread_mutex_unlock(mutex);
        return -1;
    }

    close(write_fd);
    pthread_mutex_unlock(mutex);
    return bytes_written;
}

char* read_from_file(pthread_mutex_t* mutex) {
    ssize_t fsize = 0;
    char* buff = NULL;

    pthread_mutex_lock(mutex);
    read_fd = open(DATA_FILE_PATH, O_RDONLY);

    if (read_fd == -1) {
        syslog(LOG_USER | LOG_ERR, "Could not open file to read");
        pthread_mutex_unlock(mutex);
        return NULL;
    }

    struct stat file_stat;
    fstat(read_fd, &file_stat);
    fsize = file_stat.st_size + 1;
    close(read_fd);
    pthread_mutex_unlock(mutex);

    syslog(LOG_USER | LOG_DEBUG, "File Size: %d", (int)fsize);

    buff = (char*) malloc(fsize);
    if (buff == NULL) {
        syslog(LOG_USER | LOG_ERR, "Could not allocate memory to read file");
        return NULL;
    }

    memset(buff, '\0', fsize);
    syslog(LOG_USER | LOG_DEBUG, "Reading from %s", DATA_FILE_PATH);

    pthread_mutex_lock(mutex);
    read_fd = open(DATA_FILE_PATH, O_RDONLY);
    if (read_fd == -1) {
        syslog(LOG_USER | LOG_ERR, "Could not open file to read");
        free(buff);
        pthread_mutex_unlock(mutex);
        return NULL;
    }

    ssize_t bytes_read = read(read_fd, buff, fsize - 1);
    if (bytes_read < 0) {
        syslog(LOG_USER | LOG_ERR, "Error reading from file: %s", strerror(errno));
        free(buff);
        close(read_fd);
        pthread_mutex_unlock(mutex);
        return NULL;
    }

    close(read_fd);
    pthread_mutex_unlock(mutex);
    return buff;
}

void* process_connection(void* args) {
    struct thread_data* td = (struct thread_data*) args;
    int accepted_fd = td->accepted_fd;
    char recv_buf[BLOCK_SIZE] = {};
    ssize_t recv_size;
    ssize_t total_recvd;
    char* file_data = NULL;

    syslog(LOG_USER | LOG_DEBUG, "Accepted connection from %s", inet_ntoa(td->peer_addr.sin_addr));
    total_recvd = 0;

    // Clear/Initialize receive buffer
    memset(recv_buf, '\0', sizeof(recv_buf));

    // Receive data from client
    while((recv_size = recv(accepted_fd, recv_buf, BLOCK_SIZE, 0)) > 0 && atomic_load(&running)) {
        ssize_t write_size;
        syslog(LOG_USER | LOG_DEBUG, "recv: %d", (int) recv_size);
        total_recvd = total_recvd + recv_size;
        write_size = write_to_file(&file_mutex, recv_buf, recv_size);

        if (write_size < 0) {
            syslog(LOG_USER | LOG_ERR, "Error writing to file");
            break;
        }

        if (memchr(recv_buf, '\n', recv_size)) {
            break;
        }
    }
    syslog(LOG_USER | LOG_DEBUG, "total_recvd: %d", (int) total_recvd);

    file_data = read_from_file(&file_mutex);

    if (file_data != NULL) {
        ssize_t send_size;
        send_size = send(td->accepted_fd, file_data, strlen(file_data), 0);

        if (send_size != (ssize_t) strlen(file_data)) {
            syslog(LOG_USER | LOG_ERR, "Failed to send back all the data");
        }
        free(file_data);
    } else {
        syslog(LOG_USER | LOG_ERR, "read_from_file failed, not sending data back to %s (fd=%d)", inet_ntoa(td->peer_addr.sin_addr), accepted_fd);
    }

    close(td->accepted_fd);
    syslog(LOG_USER | LOG_ERR, "Closing connection from %s", inet_ntoa(td->peer_addr.sin_addr));
    pthread_mutex_lock(&td->complete_mutex);
    td->thread_complete = true;
    pthread_mutex_unlock(&td->complete_mutex);
    return NULL;
}

void accept_connections(int server_fd) {
    SLIST_INIT(&thread_queue);

    #if USE_AESD_CHAR_DEVICE == 0
    if (pthread_create(&timestamp_thread_id, NULL, timestamper, NULL) != 0) {
        syslog(LOG_USER | LOG_ERR, "Failed to create timestamp writer thread");
    }
    #endif

    while(atomic_load(&running)) {
        struct sockaddr_in peer_addr;
        socklen_t peer_addr_len = sizeof(peer_addr);

        int accepted_fd = accept(server_fd, (struct sockaddr*) &peer_addr, &peer_addr_len);
        printf("%d\n", accepted_fd);

        if (!atomic_load(&running)) {
            if (accepted_fd != -1) {
                close(accepted_fd);
            }
            break;
        }


        if (accepted_fd == -1) {
            perror(strerror(errno));
            syslog(LOG_USER | LOG_ERR, "Could not accept connection");
            perror("Could not accept connection\n");
        } else {
            struct thread_data* td = (struct thread_data*) malloc(sizeof(struct thread_data));
            if (td == NULL) {
                syslog(LOG_USER | LOG_ERR, "Could not allocate memory for thread data");
                close(accepted_fd);
                return;
            }
            td->thread_complete = false;
            td->accepted_fd = accepted_fd;
            td->peer_addr = peer_addr;
            td->peer_addr_len = peer_addr_len;
            pthread_mutex_init(&td->complete_mutex, NULL);

            pthread_t thread_id;
            if (pthread_create(&thread_id, NULL, process_connection, td) != 0) {
                syslog(LOG_USER | LOG_ERR, "Failed to create thread");
                pthread_mutex_destroy(&td->complete_mutex);
                free(td);
                close(accepted_fd);
                continue;
            }

            struct thread* thread_node = (struct thread*) malloc(sizeof(struct thread));
            if (thread_node == NULL) {
                syslog(LOG_USER | LOG_ERR, "Could not allocate memory for thread node");
                pthread_mutex_destroy(&td->complete_mutex);
                free(td);
                close(accepted_fd);
                pthread_cancel(thread_id);
                continue;
            }
            thread_node->thread_id = thread_id;
            thread_node->data = td;

            pthread_mutex_lock(&queue_mutex);
            SLIST_INSERT_HEAD(&thread_queue, thread_node, pointers);
            pthread_mutex_unlock(&queue_mutex);

            // Clean up
            pthread_mutex_lock(&queue_mutex);

            struct thread* current = SLIST_FIRST(&thread_queue);
            struct thread* next_cleanup;

            while (current != NULL) {
                next_cleanup = SLIST_NEXT(current, pointers);
                if (current->data != NULL) {
                    pthread_mutex_lock(&current->data->complete_mutex);
                    if (current->data->thread_complete) {
                        pthread_join(current->thread_id, NULL);
                        pthread_mutex_unlock(&current->data->complete_mutex);
                        pthread_mutex_destroy(&current->data->complete_mutex);
                        free(current->data);
                        SLIST_REMOVE(&thread_queue, current, thread, pointers);
                        free(current);
                    } else {
                        pthread_mutex_unlock(&current->data->complete_mutex);
                    }
                }
                current = next_cleanup;
            }

            pthread_mutex_unlock(&queue_mutex);
        }
    }
}

int main(int argc, char** argv) {
    if (signal(SIGINT, signal_handler) == SIG_ERR) {
        perror("Can't catch SIGINT\n");
    }

    if (signal(SIGTERM, signal_handler) == SIG_ERR) {
        perror("Can't catch SIGTERM\n");
    }


    if (pthread_mutex_init(&file_mutex, NULL) != 0) {
        perror("Mutex initialization failed");
        return -1;
    }

    if ((server_fd = start_and_listen(PORT)) == -1) {
        return -1;
    }

    if (argc > 1) {
        if (strncmp(argv[1], "-d", strlen(argv[1])) == 0) {
            pid_t pid = fork();
            if (pid == -1) {
                syslog(LOG_USER | LOG_ERR, "Could not daemonize server");
                exit(-1);
            }

            if (pid > 0) {
                syslog(LOG_USER | LOG_DEBUG, "Fork created, starting daemon. PID: %d", pid);
                exit(0);
            }

            close(STDIN_FILENO);
            close(STDOUT_FILENO);
            close(STDERR_FILENO);
            accept_connections(server_fd);
        }
    } else {
        accept_connections(server_fd);
    }
    pthread_mutex_destroy(&file_mutex);
    #if USE_AESD_CHAR_DEVICE == 0
    pthread_mutex_destroy(&time_mutex);
    #endif
    return 0;
}

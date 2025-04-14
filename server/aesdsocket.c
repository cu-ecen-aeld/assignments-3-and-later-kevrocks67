#include <asm-generic/socket.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <errno.h>
#include <string.h>
#include <syslog.h>
#include <fcntl.h>
#include <sys/types.h>
#include <unistd.h>
#include <signal.h>

#define PORT 9000
#define BLOCK_SIZE 4096
#define DATA_FILE_PATH "/var/tmp/aesdsocketdata"

int server_fd = -1;
int accepted_fd = -1;
int read_fd = -1;
int write_fd = -1;

void signal_handler(int _) {
    syslog(LOG_USER | LOG_ERR, "Caught signal, exiting");
    close(accepted_fd);
    close(server_fd);
    close(read_fd);
    remove(DATA_FILE_PATH);
    exit(-1);
}

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

int write_to_file(const char recv_buf[BLOCK_SIZE], ssize_t size) {
    write_fd = open(DATA_FILE_PATH, O_RDWR | O_CREAT | O_APPEND, 00644);

    if (write_fd == -1) {
        syslog(LOG_USER | LOG_ERR, "Could not open file to write");
        return -1;
    }

    syslog(LOG_USER | LOG_DEBUG, "Writing to %s", DATA_FILE_PATH);

    ssize_t bytes_written = write(write_fd, recv_buf, size);
    syslog(LOG_USER | LOG_DEBUG, "Wrote %d bytes to file", (int) bytes_written);

    if (bytes_written < 0) {
        syslog(LOG_USER | LOG_ERR, "Could not write to file %s", DATA_FILE_PATH);
        return -1;
    }

    close(write_fd);
    return bytes_written;
}

char* read_from_file() {
    read_fd = open(DATA_FILE_PATH, O_RDONLY);

    if (read_fd == -1) {
        syslog(LOG_USER | LOG_ERR, "Could not open file to read");
        return NULL;
    }

    struct stat file_stat;
    fstat(read_fd, &file_stat);
    ssize_t fsize = file_stat.st_size + 1;
    syslog(LOG_USER | LOG_DEBUG, "File Size: %d", (int)fsize);

    char* buff = (char*) malloc(fsize);
    if (buff == NULL) {
        syslog(LOG_USER | LOG_ERR, "Could not allocate memory to read file");
        close(read_fd);
        return NULL;
    }

    memset(buff, '\0', fsize);
    syslog(LOG_USER | LOG_DEBUG, "Reading from %s", DATA_FILE_PATH);
    read(read_fd, buff, fsize);
    close(read_fd);

    return buff;
}

void accept_connections(int server_fd) {
    struct sockaddr_in peer_addr;
    socklen_t peer_addr_len = (socklen_t) sizeof(peer_addr);

    char recv_buf[BLOCK_SIZE] = {};
    ssize_t recv_size;
    ssize_t total_recvd;
    ssize_t write_size;
    ssize_t send_size;
    char* file_data;

    while(1) {
        accepted_fd = accept(server_fd, (struct sockaddr*) &peer_addr, &peer_addr_len);
        printf("%d\n", accepted_fd);

        if (accepted_fd == -1) {
            perror(strerror(errno));
            perror("Could not accept connection\n");
        } else {
            syslog(LOG_USER | LOG_DEBUG, "Accepted connection from %s", inet_ntoa(peer_addr.sin_addr));
            total_recvd = 0;

            // Clear/Initialize receive buffer
            memset(recv_buf, '\0', sizeof(recv_buf));

            // Receive data from client
            while((recv_size = recv(accepted_fd, recv_buf, BLOCK_SIZE, 0)) > 0) {
                syslog(LOG_USER | LOG_DEBUG, "recv: %d", (int) recv_size);
                total_recvd = total_recvd + recv_size;
                write_size = write_to_file(recv_buf, recv_size);
                if (write_size < 0) {
                    syslog(LOG_USER | LOG_ERR, "Error writing to file");
                    break;
                }

                if (memchr(recv_buf, '\n', recv_size)) { // NEW LINE
                    break;
                }
            }
            syslog(LOG_USER | LOG_DEBUG, "total_recvd: %d", (int) total_recvd);

            file_data = read_from_file();
            if (file_data == NULL) {
                free(file_data);
                close(accepted_fd);
                syslog(LOG_USER | LOG_ERR, "Closing connection from %s", inet_ntoa(peer_addr.sin_addr));
                continue;
            }

            send_size = send(accepted_fd, file_data, strlen(file_data), 0);

            if (send_size != (ssize_t) strlen(file_data)) {
                syslog(LOG_USER | LOG_ERR, "Failed to send back all the data");
            }

            free(file_data);
            close(accepted_fd);
            syslog(LOG_USER | LOG_DEBUG, "Closed connection from %s", inet_ntoa(peer_addr.sin_addr));
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
    return 0;
}

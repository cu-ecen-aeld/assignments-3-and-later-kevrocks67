#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <syslog.h>
#include <string.h>

int main(int argc, char** argv) {
    if (argc != 3) {
        exit(1);
    }

    char* writefile = argv[1];
    char* writestr = argv[2];

    int fd = open(writefile, O_RDWR | O_CREAT, 00644);

    if (fd == -1) {
        syslog(LOG_USER | LOG_ERR, "Could not open file to write");
        exit(1);
    }

    syslog(LOG_USER | LOG_DEBUG, "Writing %s to %s", writestr, writefile);

    ssize_t bytes_written = write(fd, writestr, strlen(writestr));

    if (bytes_written < 0) {
        syslog(LOG_USER | LOG_ERR, "Could not write to file %s", writefile);
        exit(1);
    }

    return 0;
}

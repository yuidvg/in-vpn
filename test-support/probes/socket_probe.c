#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

static int outcome(const char *operation, int result) {
    int saved = result < 0 ? errno : 0;
    printf("{\"operation\":\"%s\",\"result\":%d,\"errno\":%d,\"pid\":%d,\"ppid\":%d}\n", operation, result, saved, getpid(), getppid());
    return result < 0 ? 1 : 0;
}

int main(int argc, char **argv) {
    if (argc != 5) return 2;
    signal(SIGPIPE, SIG_IGN);
    setbuf(stdout, NULL);
    const char *mode = argv[1], *host = argv[2], *token = argv[4];
    int port = atoi(argv[3]);
    if (!strcmp(mode, "controlled")) {
        char command;
        while (read(STDIN_FILENO, &command, 1) == 1) {
            if (command == 'q') return 0;
            if (command != 't' && command != 'u' && command != 'c') return 8;
            char *next[] = {argv[0], command == 't' ? "tcp" : command == 'c' ? "tcp-timed" : "udp", argv[2], argv[3], argv[4], NULL};
            (void)main(5, next);
        }
        return 0;
    }
    if (!strcmp(mode, "inherited")) return outcome("send_inherited", (int)send(port, token, strlen(token), 0));
    if (!strcmp(mode, "fork-tcp")) {
        pid_t child = fork();
        if (child < 0) return 3;
        if (child) {
            int status;
            waitpid(child, &status, 0);
            return WIFEXITED(status) ? WEXITSTATUS(status) : 4;
        }
        execl(argv[0], argv[0], "tcp", host, argv[3], token, NULL);
        _exit(5);
    }
    int family = !strcmp(mode, "unix") ? AF_UNIX : strchr(host, ':') ? AF_INET6 : AF_INET;
    int type = !strncmp(mode, "udp", 3) ? SOCK_DGRAM : SOCK_STREAM;
    int fd = socket(family, type, 0);
    if (fd < 0) return outcome("socket", fd);
    struct sockaddr_storage address = {0};
    socklen_t length;
    if (family == AF_INET) {
        struct sockaddr_in *v4 = (struct sockaddr_in *)&address;
        v4->sin_family = AF_INET; v4->sin_len = sizeof(*v4); v4->sin_port = htons(port);
        if (inet_pton(AF_INET, host, &v4->sin_addr) != 1) return 6;
        length = sizeof(*v4);
    } else if (family == AF_INET6) {
        struct sockaddr_in6 *v6 = (struct sockaddr_in6 *)&address;
        v6->sin6_family = AF_INET6; v6->sin6_len = sizeof(*v6); v6->sin6_port = htons(port);
        if (inet_pton(AF_INET6, host, &v6->sin6_addr) != 1) return 6;
        length = sizeof(*v6);
    } else {
        struct sockaddr_un *local = (struct sockaddr_un *)&address;
        local->sun_family = AF_UNIX; local->sun_len = sizeof(*local);
        if (strlen(host) >= sizeof(local->sun_path)) return 7;
        strcpy(local->sun_path, host);
        length = sizeof(*local);
    }
    int bounded = !strcmp(mode, "tcp-timed");
    int old_flags = fcntl(fd, F_GETFL);
    if (bounded) fcntl(fd, F_SETFL, old_flags | O_NONBLOCK);
    int connected = connect(fd, (struct sockaddr *)&address, length);
    if (bounded && connected < 0 && errno == EINPROGRESS) {
        struct pollfd pending = {.fd = fd, .events = POLLOUT};
        int ready = poll(&pending, 1, 500);
        if (ready > 0) {
            int socket_error = 0;
            socklen_t size = sizeof(socket_error);
            if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &socket_error, &size) == 0) {
                errno = socket_error;
                connected = socket_error ? -1 : 0;
            }
        } else { errno = ready == 0 ? ETIMEDOUT : errno; connected = -1; }
    }
    if (connected) {
        int saved = errno;
        close(fd);
        errno = saved;
        return outcome("connect", -1);
    }
    if (bounded) fcntl(fd, F_SETFL, old_flags);
    int result = (int)send(fd, token, strlen(token), 0);
    if (!strcmp(mode, "udp-roundtrip") && result >= 0) {
        struct pollfd pending = {.fd = fd, .events = POLLIN};
        int ready = poll(&pending, 1, 500);
        char reply[256];
        if (ready > 0) {
            result = (int)recv(fd, reply, sizeof(reply), 0);
            if (result >= 0 && ((size_t)result != strlen(token) || memcmp(reply, token, (size_t)result))) { errno = EIO; result = -1; }
        } else { errno = ready == 0 ? ETIMEDOUT : errno; result = -1; }
    }
    int status = outcome("send", result);
    close(fd);
    return status;
}

#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

static int send_event(int port, int index) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return 1;
    struct sockaddr_in to = {.sin_len = sizeof(to), .sin_family = AF_INET, .sin_port = htons(port)};
    inet_pton(AF_INET, "127.0.0.1", &to.sin_addr);
    char message[180];
    int length = snprintf(message, sizeof(message), "{\"pid\":%d,\"ppid_at_send\":%d,\"index\":%d}", getpid(), getppid(), index);
    int success = sendto(fd, message, length, 0, (struct sockaddr *)&to, sizeof(to)) == length;
    close(fd);
    return !success;
}

int main(int argc, char **argv) {
    if (argc != 4) return 2;
    int port = atoi(argv[2]), count = atoi(argv[3]);
    setbuf(stdout, NULL);
    if (!strcmp(argv[1], "burst")) {
        for (int index = 0; index < count; index++) {
            pid_t child = fork();
            if (child < 0) return 3;
            if (child == 0) _exit(send_event(port, index));
            printf("{\"event\":\"fork\",\"parent\":%d,\"child\":%d,\"index\":%d}\n", getpid(), child, index);
            int status;
            if (waitpid(child, &status, 0) != child || !WIFEXITED(status) || WEXITSTATUS(status)) return 4;
        }
        return 0;
    }
    if (!strcmp(argv[1], "reparent")) {
        // The original process remains as a bounded cleanup supervisor.
        int identity[2], lifetime[2];
        if (pipe(identity) || pipe(lifetime)) return 5;
        pid_t intermediate = fork();
        if (intermediate < 0) return 6;
        if (!intermediate) {
            close(identity[0]); close(lifetime[0]);
            pid_t grandchild = fork();
            if (grandchild < 0) _exit(7);
            if (!grandchild) {
                close(identity[1]);
                pid_t original_parent = getppid();
                for (int n = 0; n < 200 && getppid() == original_parent; n++) usleep(10000);
                int result = send_event(port, 0);
                usleep(300000);
                close(lifetime[1]);
                _exit(result);
            }
            if (write(identity[1], &grandchild, sizeof(grandchild)) != sizeof(grandchild)) _exit(8);
            close(lifetime[1]);
            _exit(0);
        }
        close(identity[1]); close(lifetime[1]);
        pid_t grandchild;
        if (read(identity[0], &grandchild, sizeof(grandchild)) != sizeof(grandchild)) return 9;
        printf("{\"event\":\"double_fork\",\"root\":%d,\"parent\":%d,\"child\":%d}\n", getpid(), intermediate, grandchild);
        int status;
        waitpid(intermediate, &status, 0);
        char byte;
        read(lifetime[0], &byte, 1); // EOF after the descendant closes its descriptor.
        close(identity[0]); close(lifetime[0]);
        return 0;
    }
    return 2;
}

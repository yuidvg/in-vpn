#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <unistd.h>
int main(int argc, char **argv) {
    if (argc != 2) return 2;
    struct addrinfo hints = {.ai_socktype = SOCK_STREAM}, *answers = NULL;
    int result = getaddrinfo(argv[1], "443", &hints, &answers), count = 0;
    printf("{\"pid\":%d,\"getaddrinfo_result\":%d,\"addresses\":[", getpid(), result);
    for (struct addrinfo *p = answers; p; p=p->ai_next) {
        char text[INET6_ADDRSTRLEN];
        void *address = p->ai_family == AF_INET ? (void*)&((struct sockaddr_in*)p->ai_addr)->sin_addr : (void*)&((struct sockaddr_in6*)p->ai_addr)->sin6_addr;
        if (inet_ntop(p->ai_family, address, text, sizeof(text))) printf("%s\"%s\"", count++ ? "," : "", text);
    }
    printf("],\"answer_count\":%d}\n", count);
    if (answers) freeaddrinfo(answers);
    return 0;
}

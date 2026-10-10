#include <curl/curl.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>

static size_t discard(char *data, size_t size, size_t count, void *context) {
    (void)data; (void)context;
    return size * count;
}

int main(int argc, char **argv) {
    signal(SIGPIPE, SIG_IGN);
    setbuf(stdout, NULL);
    if (curl_global_init(CURL_GLOBAL_DEFAULT)) return 2;
    char command;
    while (read(STDIN_FILENO, &command, 1) == 1 && command != 'q') {
        CURL *curl = curl_easy_init();
        if (!curl) return 3;
        curl_easy_setopt(curl, CURLOPT_URL, argc > 1 ? argv[1] : "https://1.1.1.1/cdn-cgi/trace");
        struct curl_slist *resolve = argc > 2 ? curl_slist_append(NULL, argv[2]) : NULL;
        if (resolve) { curl_easy_setopt(curl, CURLOPT_RESOLVE, resolve); curl_easy_setopt(curl, CURLOPT_IPRESOLVE, CURL_IPRESOLVE_V4); }
        curl_easy_setopt(curl, CURLOPT_PROXY, "");
        curl_easy_setopt(curl, CURLOPT_NOPROXY, "*");
        curl_easy_setopt(curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_1);
        curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT_MS, 1000L);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, 2000L);
        curl_easy_setopt(curl, CURLOPT_FRESH_CONNECT, 1L);
        curl_easy_setopt(curl, CURLOPT_FORBID_REUSE, 1L);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, discard);
        CURLcode result = curl_easy_perform(curl);
        long status = 0;
        char *remote = NULL;
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status);
        curl_easy_getinfo(curl, CURLINFO_PRIMARY_IP, &remote);
        printf("{\"pid\":%d,\"curl_result\":%d,\"http_status\":%ld,\"remote_ip\":\"%s\"}\n", getpid(), result, status, remote ? remote : "");
        curl_easy_cleanup(curl);
        curl_slist_free_all(resolve);
    }
    curl_global_cleanup();
    return 0;
}

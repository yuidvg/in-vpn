#include <EndpointSecurity/EndpointSecurity.h>
#include <stdio.h>
#include <unistd.h>

static const char *name(es_new_client_result_t value) {
    switch (value) {
        case ES_NEW_CLIENT_RESULT_SUCCESS: return "success";
        case ES_NEW_CLIENT_RESULT_ERR_NOT_ENTITLED: return "not_entitled";
        case ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED: return "not_permitted";
        case ES_NEW_CLIENT_RESULT_ERR_NOT_PRIVILEGED: return "not_privileged";
        default: return "other_error";
    }
}

int main(void) {
    es_client_t *client = NULL;
    es_handler_block_t handler = ^(es_client_t *c, const es_message_t *m) { (void)c; (void)m; };
    es_new_client_result_t global = es_new_client(&client, handler);
    printf("{\"api\":\"es_new_client\",\"uid\":%d,\"result\":%d,\"name\":\"%s\"}\n", getuid(), global, name(global));
    if (global == ES_NEW_CLIENT_RESULT_SUCCESS) es_delete_client(client);
#if __MAC_OS_X_VERSION_MAX_ALLOWED >= 270000
    if (__builtin_available(macOS 27.0, *)) {
        client = NULL;
        es_new_client_result_t descendants = es_new_descendants_client(&client, handler);
        printf("{\"api\":\"es_new_descendants_client\",\"uid\":%d,\"result\":%d,\"name\":\"%s\"}\n", getuid(), descendants, name(descendants));
        if (descendants == ES_NEW_CLIENT_RESULT_SUCCESS) es_delete_client(client);
    }
#endif
    return 0;
}

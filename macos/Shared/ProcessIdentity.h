#ifndef INVPN_PROCESS_IDENTITY_H
#define INVPN_PROCESS_IDENTITY_H
#include <stdint.h>

// Returns zero when the process is absent or the OS denies observation.
int invpn_process_identity(int32_t pid, uint64_t *seconds, uint64_t *microseconds);
#endif

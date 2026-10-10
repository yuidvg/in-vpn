#include "ProcessIdentity.h"
#include <libproc.h>
#include <sys/proc_info.h>

int invpn_process_identity(int32_t pid, uint64_t *seconds, uint64_t *microseconds) {
    struct proc_bsdinfo info = {0};
    if (pid <= 0 || !seconds || !microseconds ||
        proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, sizeof(info)) != sizeof(info)) return 0;
    *seconds = info.pbi_start_tvsec;
    *microseconds = info.pbi_start_tvusec;
    return 1;
}

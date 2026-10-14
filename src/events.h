#ifndef L2DNS6RW_EVENTS_H
#define L2DNS6RW_EVENTS_H

#include <stddef.h>

#include "l2dns6rw-bpf.h"

const char *events_reason(unsigned int reason);

/* Formats one ring-buffer event as a log line for device (its name). */
void events_format(const struct l2dns6rw_event *event, const char *device, char *line, size_t size);

#endif

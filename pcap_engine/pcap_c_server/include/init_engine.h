#ifndef INIT_ENGINE_H
#define INIT_ENGINE_H

#include "pcap_common.h"

int init_context(EngineContext *ctx);
int init_capture(EngineContext *ctx);
void cleanup_all_resources(EngineContext *ctx);

#endif
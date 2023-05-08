#pragma once
#include "head.h"
extern unsigned long (*g_kallsyms_lookup_name_fun)(const char *name);
extern bool init_kallsyms_lookup_name(void);

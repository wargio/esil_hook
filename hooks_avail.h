#ifndef HOOKS_AVAIL_H
#define HOOKS_AVAIL_H

#include <r_anal.h>

typedef int (*ehook_t) (RAnalEsil *esil);
typedef int (*esil_reg_write)(RAnalEsil *esil, const char *name, ut64 val);

#define HOOKS_NUM 64

void hook_reg_write(RAnal *anal);

bool set_ehook(ut64 address, const char* name, ehook_t hook);
bool call_ehook(ut64 address, RAnalEsil *esil, int *ret);
void list_ehook();
void _send_string(const char* str, int size);


// Hooks

int ehook_exit(RAnalEsil *esil);
int ehook_puts(RAnalEsil *esil);
int ehook_nop(RAnalEsil *esil);

#endif
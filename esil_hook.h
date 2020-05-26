#ifndef ESIL_HELPER_H
#define ESIL_HELPER_H

typedef void (*eh_fcn_t)(RCore *core, const char*);

typedef struct eh_cmd {
	const char* name;
	int name_len;
	eh_fcn_t exec;
} eh_cmd_t;


#endif
/* radare - LGPL - Copyright 2019 - deroad */

#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <r_types.h>
#include <r_lib.h>
#include <r_cmd.h>
#include <r_core.h>
#include <r_cons.h>
#include <r_anal.h>
#include <string.h>
#include <stdlib.h>

#include "esil_hook.h"
#include "hooks_avail.h"

static int server_fd, client_fd;

static inline const char* next_printable (const char* input) {
	if (!input || !*input) {
		return NULL;
	}
	const char whitespaces[] = " \f\n\r\t\v";
	int pos = strspn (input, whitespaces);
	if (pos < 1) {
		return NULL;
	}
	return input + pos;
}

void _send_string(const char* str, int size) {
	if (size < 0) {
		size = strlen (str);
	}
	if (size > 0 && client_fd >= 0) {
		if (size != send(client_fd, str, size, 0)) {
			eprintf("[ehook] cannot talk with client.");
		}
	}
}

static void _enable_socket(RCore *core, const char* sport) {
	hook_reg_write (core->anal);

	struct sockaddr_in server;
	ut64 port = r_num_get (NULL, sport);
	if (port <= 0) {
		port = 8888;
	}
	if (server_fd >= 0) {
		close (server_fd);
		server_fd = -1;
	}

	server_fd = socket (AF_INET, SOCK_STREAM, 0);
	if (server_fd < 0) {
		eprintf("[ehook] cannot create socket.");
		server_fd = -1;
		return;
	}

	server.sin_family = AF_INET;
	server.sin_port = htons ((int)port);
	server.sin_addr.s_addr = htonl (INADDR_ANY);
	int opt_val = 1;
	setsockopt (server_fd, SOL_SOCKET, SO_REUSEADDR, &opt_val, sizeof (opt_val));
	if (bind (server_fd, (struct sockaddr *) &server, sizeof (server)) < 0) {
		close (server_fd);
		server_fd = -1;
		eprintf("[ehook] cannot bind port.");
		return;
	}

	if (listen (server_fd, 128) < 0) {
		close (server_fd);
		server_fd = -1;
		eprintf("[ehook] cannot bind port.");
		return;
	}

	eprintf ("[ehook] listening on %"PFMT64u". waiting for connection.\n", port);

	client_fd = accept (server_fd, NULL, NULL);
	eprintf ("[ehook] connected.\n");
	_send_string ("[ehook] hello.\n", -1);
}

static void _hook_list(RCore *core, const char* str) {
	list_ehook ();
}

static void _hook_exit(RCore *core, const char* str) {
	ut64 address = r_num_get (NULL, str);
	if (!address) {
		eprintf("[ehook] '%s' is NOT a valid address.", str);
	}
	set_ehook (address, "exit(int code)", ehook_exit);
}

static void _hook_puts(RCore *core, const char* str) {
	ut64 address = r_num_get (NULL, str);
	if (!address) {
		eprintf("[ehook] '%s' is NOT a valid address.", str);
	}
	set_ehook (address, "puts(const char*)", ehook_puts);
}

static void _hook_nop(RCore *core, const char* str) {
	ut64 address = r_num_get (NULL, str);
	if (!address) {
		eprintf("[ehook] '%s' is NOT a valid address.", str);
	}
	set_ehook (address, "nop", ehook_nop);
}

const eh_cmd_t _cmd_list[] = {
	{ "enable", 6, _enable_socket },
	{ "list",   4, _hook_list     },
	// -----------------------------
	{ "nop",    3, _hook_nop      },
	{ "puts",   4, _hook_puts     },
	{ "exit",   4, _hook_exit     },
	{ NULL,     0, NULL           },
};

static void usage(const RCore* const core) {
	const char* help[] = {
		"Usage: ehook", "",	"# Hooks ESIL to emulate",
		"ehook", " <cmd> <arg>", "hooks a jump and emulate it based on the hook type",
		NULL
	};

	r_cons_cmd_help(help, core->print->flags & R_PRINT_FLAGS_COLOR);
}

static void _cmd_esil_hook(RCore *core, const char *input) {
	int i;
	const char* cmd = next_printable (input);
	if (!cmd || !(*cmd)) {
		usage (core);
		return;
	}
	const char* arg = next_printable (strchr (cmd, ' '));

	if (client_fd < 0 && strncmp (cmd, "enable", 6) != 0) {
		eprintf("[ehook] client not connected.\n");
		return;
	}

	for (i = 0; _cmd_list[i].name ; i++) {
		if (!strncmp (cmd, _cmd_list[i].name, _cmd_list[i].name_len)) {
			_cmd_list[i].exec(core, arg);
			return;
		}
	}
	usage (core);
}

static int r_cmd_ehook(void *user, const char *input) {
	RCore *core = (RCore *) user;
	if (!strncmp (input, "ehook", 5)) {
		_cmd_esil_hook (core, input + 5);
		return true;
	}
	return false;
}
int r_cmd_ehook_init(void *user, const char *cmd) {
	RCmd *rcmd = (RCmd*) user;
	RCore *core = (RCore *) rcmd->data;
	int i;

	server_fd = -1;
	client_fd = -1;

	// autocomplete here..
	RCoreAutocomplete *ehook = r_core_autocomplete_add (core->autocomplete, "ehook", R_CORE_AUTOCMPLT_DFLT, true);
	for (i = 0; _cmd_list[i].name ; i++) {
		r_core_autocomplete_add (ehook, _cmd_list[i].name, R_CORE_AUTOCMPLT_OPTN, true);
	}

	return true;
}

RCorePlugin r_core_plugin_ehook = {
	.name = "ehook",
	.desc = "ESIL helper for r2",
	.license = "GPL3",
	.call = r_cmd_ehook,
	.init = r_cmd_ehook_init
};

#ifdef _MSC_VER
#define _R_API __declspec(dllexport)
#else
#define _R_API
#endif

#ifndef CORELIB
_R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_CORE,
	.data = &r_core_plugin_ehook,
	.version = R2_VERSION
};
#endif

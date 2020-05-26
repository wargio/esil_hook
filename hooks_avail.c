#include "hooks_avail.h"

typedef struct eh_hook {
	ut64 address;
	const char* name;
	ehook_t hook;
} ehook_entry_t;

//static ut64 previous_pc = 0;
static esil_reg_write original_fcn = NULL;
static ehook_entry_t hooks[HOOKS_NUM] = {0};
static int hooks_used = 0;

static int _esil_hook_reg_write(RAnalEsil *esil, const char *name, ut64 val) {
	if (!esil || !esil->anal || !esil->anal->reg) {
		eprintf ("[ehook] invalid pointer (_esil_hook_reg_write)\n");
		return 0;
	}
	int ret = 1;
	if (!strncmp (name, "pc", 2) && call_ehook (val, esil, &ret)) {
		return ret;
	}
	return original_fcn(esil, name, val);
}

void hook_reg_write(RAnal *anal) {
	if (!original_fcn) {
		if (anal && anal->esil) {
			original_fcn = anal->esil->cb.reg_write;
			anal->esil->cb.reg_write = _esil_hook_reg_write;
		} else {
			eprintf("[ehook] failed to hook set_reg_write.\n");
			return;
		}
	}
}

bool set_ehook(ut64 address, const char* name, ehook_t hook) {
	int i;
	if (hooks_used >= HOOKS_NUM) {
		eprintf ("[ehook] cannot add hook. limit reached.\n");
		return false;
	}
	for (i = 0; i < HOOKS_NUM && i < hooks_used; ++i) {
		if (hooks[i].address == address) {
			eprintf ("[ehook] cannot add hook. address already in list.\n");
			return false;
		}
	}
	hooks[hooks_used].address = address;
	hooks[hooks_used].name = name;
	hooks[hooks_used].hook = hook;
	hooks_used++;
	eprintf ("[ehook] hooked at 0x%"PFMT64x" %s.\n", address, name);
	return true;
}

bool call_ehook(ut64 address, RAnalEsil *esil, int *ret) {
	int i;
	for (i = 0; i < HOOKS_NUM && i < hooks_used; ++i) {
		if (hooks[i].address == address) {
			*ret = hooks[i].hook(esil);
			return true;
		}
	}
	return false;
}

void list_ehook() {
	int i;
	char buffer[256];
	for (i = 0; i < HOOKS_NUM && i < hooks_used; ++i) {
		snprintf (buffer, sizeof (buffer), "[ehook] 0x%08"PFMT64x" %s.\n", hooks[i].address, hooks[i].name);
		r_cons_strcat (buffer);
		r_cons_newline ();
	}
}

// -----------------------------------------
// ----------------- HOOKS -----------------
// -----------------------------------------

int ehook_nop(RAnalEsil *esil) {
	return 1;
}

int ehook_exit(RAnalEsil *esil) {
	if (!esil || !esil->anal || !esil->anal->reg) {
		eprintf ("[ehook] invalid pointer (ehook_exit)\n");
		return 0;
	}
	const char *a0 = r_reg_get_name (esil->anal->reg, R_REG_NAME_A0);
	if (!a0 || strlen (a0) < 1) {
		eprintf ("[ehook] invalid A0 register in profile (ehook_exit)\n");
		return 0;
	}
	char buffer[256];
	ut64 value = r_reg_getv (esil->anal->reg, a0);
	int size = snprintf (buffer, sizeof (buffer), "[ehook] process exit with code %"PFMT64u"\n", value);
	_send_string (buffer, size);


	const char *pc = r_reg_get_name (esil->anal->reg, R_REG_NAME_PC);
	value = r_reg_getv (esil->anal->reg, pc);
	r_reg_setv (esil->anal->reg, pc, value - 4);
	return -1;
}

int ehook_puts(RAnalEsil *esil) {
	if (!esil || !esil->anal || !esil->anal->reg) {
		eprintf ("[ehook] invalid pointer (ehook_puts)\n");
		return 0;
	}
	const char *a0 = r_reg_get_name (esil->anal->reg, R_REG_NAME_A0);
	if (!a0 || strlen (a0) < 1) {
		eprintf ("[ehook] invalid A0 register in profile (ehook_puts)\n");
		return 0;
	}
	ut64 value = r_reg_getv (esil->anal->reg, a0);

	char *string = esil->anal->coreb.cmdstrf (esil->anal->coreb.core, "Cs. @ %"PFMT64u, value);
	char buffer[256];
	int size = snprintf (buffer, sizeof (buffer), string);
	_send_string (buffer, size);
	free (string);
	return 1;
}

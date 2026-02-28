/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0 */
/*
 * HymoFS LKM - ftrace VFS hooks interface.
 *
 * License: Author's work under Apache-2.0; when used as a kernel module
 * (or linked with the Linux kernel), GPL-2.0 applies for kernel compatibility.
 *
 * Author: Anatdx
 */
#ifndef _HYMOFS_FTRACE_H
#define _HYMOFS_FTRACE_H

#include <linux/types.h>
#include <linux/errno.h>
#include <linux/kprobes.h>
#include <asm/ptrace.h>

#ifdef CONFIG_DYNAMIC_FTRACE

/* Try to register ftrace for vfs_getattr, d_path, iterate_dir, vfs_getxattr.
 * On success: fills addr[0..3] with symbol addresses, returns 0.
 * On failure: returns negative errno.
 */
int hymofs_ftrace_try_register(unsigned long addr[4]);

/* Unregister ftrace. Call before unregistering kretprobes. */
void hymofs_ftrace_unregister(void);

/* kretprobe entry/ret handlers when using ftrace for VFS entry. */
int hymo_ftrace_krp_entry(struct kretprobe_instance *ri, struct pt_regs *regs);
int hymo_ftrace_krp_ret(struct kretprobe_instance *ri, struct pt_regs *regs);

#else

static inline int hymofs_ftrace_try_register(unsigned long addr[4])
{
	(void)addr;
	return -EOPNOTSUPP;
}

static inline void hymofs_ftrace_unregister(void)
{
}

static inline int hymo_ftrace_krp_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	(void)ri;
	(void)regs;
	return 0;
}

static inline int hymo_ftrace_krp_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	(void)ri;
	(void)regs;
	return 0;
}

#endif /* CONFIG_DYNAMIC_FTRACE */

#endif /* _HYMOFS_FTRACE_H */

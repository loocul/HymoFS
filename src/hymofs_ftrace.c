// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0
/*
 * HymoFS LKM - ftrace-based VFS entry hooks.
 *
 * License: Author's work under Apache-2.0; when used as a kernel module
 * (or linked with the Linux kernel), GPL-2.0 applies for kernel compatibility.
 *
 * Uses ftrace for entry + kretprobe for exit on vfs_getattr, d_path,
 * iterate_dir, vfs_getxattr. Only compiled when CONFIG_DYNAMIC_FTRACE.
 *
 * Author: Anatdx
 */

#ifdef CONFIG_DYNAMIC_FTRACE

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/percpu.h>
#include <linux/ftrace.h>
#include "hymofs_lkm.h"
#include "hymofs_ftrace.h"

#define HYMO_FTRACE_SLOT_DEPTH 16

struct hymo_ftrace_slot {
	int type; /* 0=getattr 1=dpath 2=iter 3=getxattr, -2=skipped */
	union {
		struct hymo_getattr_ri_data getattr;
		struct hymo_d_path_ri_data dpath;
		struct hymo_iterate_ri_data iter;
		struct hymo_getxattr_ri_data getxattr;
	} u;
};

static DEFINE_PER_CPU(struct hymo_ftrace_slot[HYMO_FTRACE_SLOT_DEPTH], hymo_ftrace_slots);
static DEFINE_PER_CPU(int, hymo_ftrace_depth);
static DEFINE_PER_CPU(int, hymo_ftrace_cb_ran);
static unsigned long hymo_ft_addr[4];
static struct ftrace_ops hymo_ftrace_ops;

/* Forward declarations: handlers implemented in hymofs_core.c */
extern int hymo_krp_vfs_getattr_entry(struct kretprobe_instance *ri, struct pt_regs *regs);
extern int hymo_krp_vfs_getattr_ret(struct kretprobe_instance *ri, struct pt_regs *regs);
extern int hymo_krp_d_path_entry(struct kretprobe_instance *ri, struct pt_regs *regs);
extern int hymo_krp_d_path_ret(struct kretprobe_instance *ri, struct pt_regs *regs);
extern int hymo_krp_iterate_dir_ret(struct kretprobe_instance *ri, struct pt_regs *regs);
extern int hymo_krp_vfs_getxattr_entry(struct kretprobe_instance *ri, struct pt_regs *regs);
extern int hymo_krp_vfs_getxattr_ret(struct kretprobe_instance *ri, struct pt_regs *regs);
extern int hymo_kp_iterate_dir_pre(struct kprobe *p, struct pt_regs *regs);


static void hymo_ftrace_callback(unsigned long ip, unsigned long parent_ip,
				struct ftrace_ops *op, struct ftrace_regs *fregs)
{
	struct pt_regs *regs;
	struct hymo_ftrace_slot *slot;
	int depth, type = -1;
	static struct kprobe kp_dummy;

	(void)parent_ip;
	(void)op;

	/* Defensive: verify fregs is valid */
	if (!fregs)
		return;

	regs = ftrace_get_regs(fregs);
	if (!regs)
		return;

	/* Check if any ftrace addresses are registered */
	if (!hymo_ft_addr[0] && !hymo_ft_addr[1] && !hymo_ft_addr[2] && !hymo_ft_addr[3])
		return;

	this_cpu_write(hymo_ftrace_cb_ran, 0);

	depth = this_cpu_read(hymo_ftrace_depth);
	if (depth >= HYMO_FTRACE_SLOT_DEPTH || depth < 0)
		return;

	if (ip == hymo_ft_addr[0])
		type = 0;
	else if (ip == hymo_ft_addr[1])
		type = 1;
	else if (ip == hymo_ft_addr[2])
		type = 2;
	else if (ip == hymo_ft_addr[3])
		type = 3;
	else
		return;

	slot = &this_cpu_ptr(hymo_ftrace_slots)[depth];
	this_cpu_write(hymo_ftrace_depth, depth + 1);
	this_cpu_write(hymo_ftrace_cb_ran, 1);
	slot->type = type;

	if (type == 0) {
		struct kretprobe_instance ri = { .data = &slot->u.getattr };
		if (hymo_krp_vfs_getattr_entry(&ri, regs) != 0)
			slot->type = -1;
	} else if (type == 1) {
		struct kretprobe_instance ri = { .data = &slot->u.dpath };
		if (hymo_krp_d_path_entry(&ri, regs) != 0)
			slot->type = -1;
	} else if (type == 2) {
		struct dir_context *ictx;
		hymo_kp_iterate_dir_pre(&kp_dummy, regs);
		ictx = (struct dir_context *)regs->regs[1];
		if (ictx && ictx->actor == hymofs_filldir_filter) {
			slot->u.iter.did_swap = 1;
			slot->u.iter.wrapper = container_of(ictx,
				struct hymofs_filldir_wrapper, wrap_ctx);
		} else {
			slot->u.iter.did_swap = 0;
			slot->u.iter.wrapper = NULL;
		}
	} else if (type == 3) {
		struct kretprobe_instance ri = { .data = &slot->u.getxattr };
		if (hymo_krp_vfs_getxattr_entry(&ri, regs) != 0)
			slot->type = -1;
	}
}

int hymo_ftrace_krp_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	int depth;

	(void)regs;
	*(struct hymo_ftrace_slot **)ri->data = NULL;
	if (!this_cpu_read(hymo_ftrace_cb_ran))
		return 0;
	depth = this_cpu_read(hymo_ftrace_depth);
	if (depth > 0 && depth <= HYMO_FTRACE_SLOT_DEPTH)
		*(struct hymo_ftrace_slot **)ri->data =
			&this_cpu_ptr(hymo_ftrace_slots)[depth - 1];
	return 0;
}

int hymo_ftrace_krp_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct hymo_ftrace_slot *slot;
	int depth;

	slot = *(struct hymo_ftrace_slot **)ri->data;
	if (!slot)
		return 0;
	if (slot->type >= 0) {
		if (slot->type == 0) {
			struct kretprobe_instance r = { .data = &slot->u.getattr };
			hymo_krp_vfs_getattr_ret(&r, regs);
		} else if (slot->type == 1) {
			struct kretprobe_instance r = { .data = &slot->u.dpath };
			hymo_krp_d_path_ret(&r, regs);
		} else if (slot->type == 2) {
			struct kretprobe_instance r = { .data = &slot->u.iter };
			hymo_krp_iterate_dir_ret(&r, regs);
		} else if (slot->type == 3) {
			struct kretprobe_instance r = { .data = &slot->u.getxattr };
			hymo_krp_vfs_getxattr_ret(&r, regs);
		}
	}
	depth = this_cpu_read(hymo_ftrace_depth);
	if (depth > 0)
		this_cpu_write(hymo_ftrace_depth, depth - 1);
	return 0;
}

int hymofs_ftrace_try_register(unsigned long addr[4])
{
	int i, ret;
	static const char *ft_syms[] = {"vfs_getattr", "d_path", "iterate_dir", "vfs_getxattr"};

	for (i = 0; i < 4; i++) {
		addr[i] = hymofs_lookup_name(ft_syms[i]);
		/* vfs_getxattr is optional */
		if (!addr[i] && i < 3)
			return -ENOENT;
		if (addr[i] && IS_ERR_VALUE(addr[i]))
			return -EINVAL;
	}
	for (i = 0; i < 4; i++)
		hymo_ft_addr[i] = addr[i];

	memset(&hymo_ftrace_ops, 0, sizeof(hymo_ftrace_ops));
	hymo_ftrace_ops.func = hymo_ftrace_callback;
	hymo_ftrace_ops.flags = FTRACE_OPS_FL_SAVE_REGS;
	ret = register_ftrace_function(&hymo_ftrace_ops);
	if (ret != 0)
		return ret;
	ret = ftrace_set_filter_ips(&hymo_ftrace_ops, hymo_ft_addr, 4, 0, 0);
	if (ret != 0) {
		unregister_ftrace_function(&hymo_ftrace_ops);
		return ret;
	}
	return 0;
}

void hymofs_ftrace_unregister(void)
{
	unregister_ftrace_function(&hymo_ftrace_ops);
}

#endif /* CONFIG_DYNAMIC_FTRACE */

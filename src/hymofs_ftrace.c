// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0
/*
 * HymoFS LKM - ftrace-based VFS entry hooks.
 *
 * License: Author's work under Apache-2.0; when used as a kernel module
 * (or linked with the Linux kernel), GPL-2.0 applies for kernel compatibility.
 *
 * Uses ftrace for entry + kretprobe for exit on vfs_getattr, d_path,
 * iterate_dir, vfs_getxattr. Resolve: 1) __symbol_get, 2) hymofs_lookup_name,
 * 3) fallback to kprobes.
 *
 * Author: Anatdx
 */

#ifdef CONFIG_DYNAMIC_FTRACE

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/stddef.h>
#include <linux/string.h>
#include <linux/version.h>
/* 6.6+ may call arch_ftrace_get_regs without defining it in ftrace.h. */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0) && !defined(arch_ftrace_get_regs)
#define arch_ftrace_get_regs(fregs) (NULL)
#endif
#include <linux/kprobes.h>
#include <linux/smp.h>
#include <linux/vmalloc.h>
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

/* vmalloc-based per-CPU ftrace state (avoids percpu allocator exhaustion on 6.6 Qualcomm) */
struct hymo_ftrace_percpu {
	struct hymo_ftrace_slot slots[HYMO_FTRACE_SLOT_DEPTH];
	int depth;
	int cb_ran;
};
static struct hymo_ftrace_percpu *hymo_ftrace_base;

static inline struct hymo_ftrace_percpu *hymo_ftrace_this_cpu(void)
{
	return hymo_ftrace_base ? hymo_ftrace_base + smp_processor_id() : NULL;
}
static unsigned long hymo_ft_addr[4];
static struct ftrace_ops hymo_ftrace_ops;

/* Resolved at runtime: 1) __symbol_get (if exported), 2) hymofs_lookup_name (kallsyms).
 * __symbol_get/__symbol_put are resolved via kallsyms to avoid link-time dependency
 * on kernels that don't export them (e.g. some OEM builds). */
typedef int (*ftrace_register_fn)(struct ftrace_ops *ops);
typedef void (*ftrace_unregister_fn)(struct ftrace_ops *ops);
typedef int (*ftrace_filter_fn)(struct ftrace_ops *ops, unsigned long *ips,
				unsigned int cnt, int remove, int reset);
typedef void *(*symbol_get_fn)(const char *name);
typedef void (*symbol_put_fn)(const char *name);
static ftrace_register_fn hymo_ftrace_register_fn;
static ftrace_unregister_fn hymo_ftrace_unregister_fn;
static ftrace_filter_fn hymo_ftrace_filter_fn;
static symbol_get_fn hymo_symbol_get;
static symbol_put_fn hymo_symbol_put;
static bool hymo_ftrace_used_symbol_get; /* true = need symbol_put on unregister */

/* C99: flexible array member cannot use designated init; store ptr at data offset */
#define HYMO_RI_WITH_DATA(ri, ptr) do { \
	memset(&(ri), 0, sizeof(ri)); \
	*(void **)((char *)&(ri) + offsetof(struct kretprobe_instance, data)) = (void *)(ptr); \
} while (0)

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
	struct hymo_ftrace_percpu *pcpu;
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

	pcpu = hymo_ftrace_this_cpu();
	if (!pcpu)
		return;

	pcpu->cb_ran = 0;
	depth = pcpu->depth;
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

	slot = &pcpu->slots[depth];
	pcpu->depth = depth + 1;
	pcpu->cb_ran = 1;
	slot->type = type;

	if (type == 0) {
		struct kretprobe_instance ri;
		HYMO_RI_WITH_DATA(ri, &slot->u.getattr);
		if (hymo_krp_vfs_getattr_entry(&ri, regs) != 0)
			slot->type = -1;
	} else if (type == 1) {
		struct kretprobe_instance ri;
		HYMO_RI_WITH_DATA(ri, &slot->u.dpath);
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
		struct kretprobe_instance ri;
		HYMO_RI_WITH_DATA(ri, &slot->u.getxattr);
		if (hymo_krp_vfs_getxattr_entry(&ri, regs) != 0)
			slot->type = -1;
	}
}

int hymo_ftrace_krp_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct hymo_ftrace_percpu *pcpu;
	int depth;

	(void)regs;
	*(struct hymo_ftrace_slot **)ri->data = NULL;
	pcpu = hymo_ftrace_this_cpu();
	if (!pcpu || !pcpu->cb_ran)
		return 0;
	depth = pcpu->depth;
	if (depth > 0 && depth <= HYMO_FTRACE_SLOT_DEPTH)
		*(struct hymo_ftrace_slot **)ri->data = &pcpu->slots[depth - 1];
	return 0;
}

int hymo_ftrace_krp_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct hymo_ftrace_percpu *pcpu;
	struct hymo_ftrace_slot *slot;

	slot = *(struct hymo_ftrace_slot **)ri->data;
	if (!slot)
		return 0;
	if (slot->type >= 0) {
		if (slot->type == 0) {
			struct kretprobe_instance r;
			HYMO_RI_WITH_DATA(r, &slot->u.getattr);
			hymo_krp_vfs_getattr_ret(&r, regs);
		} else if (slot->type == 1) {
			struct kretprobe_instance r;
			HYMO_RI_WITH_DATA(r, &slot->u.dpath);
			hymo_krp_d_path_ret(&r, regs);
		} else if (slot->type == 2) {
			struct kretprobe_instance r;
			HYMO_RI_WITH_DATA(r, &slot->u.iter);
			hymo_krp_iterate_dir_ret(&r, regs);
		} else if (slot->type == 3) {
			struct kretprobe_instance r;
			HYMO_RI_WITH_DATA(r, &slot->u.getxattr);
			hymo_krp_vfs_getxattr_ret(&r, regs);
		}
	}
	pcpu = hymo_ftrace_this_cpu();
	if (pcpu && pcpu->depth > 0)
		pcpu->depth--;
	return 0;
}

int hymofs_ftrace_try_register(unsigned long addr[4])
{
	int i, ret;
	static const char *ft_syms[] = {"vfs_getattr", "d_path", "iterate_dir", "vfs_getxattr"};

	/* 1) Resolve __symbol_get/__symbol_put via kallsyms (avoids link dep on unexported kernels) */
	hymo_ftrace_used_symbol_get = false;
	hymo_symbol_get = NULL;
	hymo_symbol_put = NULL;
	hymo_ftrace_register_fn = NULL;
	hymo_ftrace_unregister_fn = NULL;
	hymo_ftrace_filter_fn = NULL;
	{
		unsigned long sg = hymofs_lookup_name("__symbol_get");
		unsigned long sp = hymofs_lookup_name("__symbol_put");
		if (sg && sp && !IS_ERR_VALUE(sg) && !IS_ERR_VALUE(sp)) {
			hymo_symbol_get = (symbol_get_fn)sg;
			hymo_symbol_put = (symbol_put_fn)sp;
			hymo_ftrace_register_fn = (ftrace_register_fn)hymo_symbol_get("register_ftrace_function");
			hymo_ftrace_unregister_fn = (ftrace_unregister_fn)hymo_symbol_get("unregister_ftrace_function");
			hymo_ftrace_filter_fn = (ftrace_filter_fn)hymo_symbol_get("ftrace_set_filter_ips");
			if (hymo_ftrace_register_fn && hymo_ftrace_unregister_fn && hymo_ftrace_filter_fn)
				hymo_ftrace_used_symbol_get = true;
		}
	}
	if (!hymo_ftrace_register_fn || !hymo_ftrace_unregister_fn || !hymo_ftrace_filter_fn) {
		/* Fallback: resolve ftrace symbols via kallsyms (no symbol_put needed) */
		if (hymo_ftrace_used_symbol_get) {
			if (hymo_ftrace_register_fn)
				hymo_symbol_put("register_ftrace_function");
			if (hymo_ftrace_unregister_fn)
				hymo_symbol_put("unregister_ftrace_function");
			if (hymo_ftrace_filter_fn)
				hymo_symbol_put("ftrace_set_filter_ips");
		}
		{
			unsigned long a1 = hymofs_lookup_name("register_ftrace_function");
			unsigned long a2 = hymofs_lookup_name("unregister_ftrace_function");
			unsigned long a3 = hymofs_lookup_name("ftrace_set_filter_ips");
			if (!a1 || !a2 || !a3 || IS_ERR_VALUE(a1) || IS_ERR_VALUE(a2) || IS_ERR_VALUE(a3)) {
				hymo_ftrace_register_fn = NULL;
				hymo_ftrace_unregister_fn = NULL;
				hymo_ftrace_filter_fn = NULL;
				return -EOPNOTSUPP;
			}
			hymo_ftrace_register_fn = (ftrace_register_fn)a1;
			hymo_ftrace_unregister_fn = (ftrace_unregister_fn)a2;
			hymo_ftrace_filter_fn = (ftrace_filter_fn)a3;
			hymo_ftrace_used_symbol_get = false;
			pr_info("HymoFS: ftrace resolved via kallsyms (not exported)\n");
		}
	}

	hymo_ftrace_base = vmalloc(nr_cpu_ids * sizeof(struct hymo_ftrace_percpu));
	if (!hymo_ftrace_base) {
		pr_warn("HymoFS: ftrace vmalloc failed\n");
		ret = -ENOMEM;
		goto err_put;
	}
	memset(hymo_ftrace_base, 0, nr_cpu_ids * sizeof(struct hymo_ftrace_percpu));

	for (i = 0; i < 4; i++) {
		addr[i] = hymofs_lookup_name(ft_syms[i]);
		/* vfs_getxattr is optional */
		if (!addr[i] && i < 3) {
			pr_warn("HymoFS: ftrace symbol not found: %s\n", ft_syms[i]);
			vfree(hymo_ftrace_base);
			hymo_ftrace_base = NULL;
			ret = -ENOENT;
			goto err_put;
		}
		if (addr[i] && IS_ERR_VALUE(addr[i])) {
			pr_warn("HymoFS: ftrace lookup failed for %s: %ld\n", ft_syms[i], (long)addr[i]);
			vfree(hymo_ftrace_base);
			hymo_ftrace_base = NULL;
			ret = -EINVAL;
			goto err_put;
		}
	}
	for (i = 0; i < 4; i++)
		hymo_ft_addr[i] = addr[i];

	memset(&hymo_ftrace_ops, 0, sizeof(hymo_ftrace_ops));
	hymo_ftrace_ops.func = hymo_ftrace_callback;
	hymo_ftrace_ops.flags = FTRACE_OPS_FL_SAVE_REGS;
	ret = hymo_ftrace_register_fn(&hymo_ftrace_ops);
	if (ret != 0) {
		pr_warn("HymoFS: register_ftrace_function failed: %d\n", ret);
		vfree(hymo_ftrace_base);
		hymo_ftrace_base = NULL;
		goto err_put;
	}
	ret = hymo_ftrace_filter_fn(&hymo_ftrace_ops, hymo_ft_addr, 4, 0, 0);
	if (ret != 0) {
		pr_warn("HymoFS: ftrace_set_filter_ips failed: %d\n", ret);
		hymo_ftrace_unregister_fn(&hymo_ftrace_ops);
		vfree(hymo_ftrace_base);
		hymo_ftrace_base = NULL;
		goto err_put;
	}
	return 0;

err_put:
	if (hymo_ftrace_used_symbol_get && hymo_symbol_put) {
		hymo_symbol_put("register_ftrace_function");
		hymo_symbol_put("unregister_ftrace_function");
		hymo_symbol_put("ftrace_set_filter_ips");
	}
	hymo_ftrace_register_fn = NULL;
	hymo_ftrace_unregister_fn = NULL;
	hymo_ftrace_filter_fn = NULL;
	hymo_ftrace_used_symbol_get = false;
	return ret;
}

void hymofs_ftrace_unregister(void)
{
	if (hymo_ftrace_unregister_fn)
		hymo_ftrace_unregister_fn(&hymo_ftrace_ops);
	vfree(hymo_ftrace_base);
	hymo_ftrace_base = NULL;
	if (hymo_ftrace_used_symbol_get && hymo_symbol_put) {
		hymo_symbol_put("register_ftrace_function");
		hymo_symbol_put("unregister_ftrace_function");
		hymo_symbol_put("ftrace_set_filter_ips");
	}
	hymo_ftrace_register_fn = NULL;
	hymo_ftrace_unregister_fn = NULL;
	hymo_ftrace_filter_fn = NULL;
	hymo_ftrace_used_symbol_get = false;
}

#endif /* CONFIG_DYNAMIC_FTRACE */

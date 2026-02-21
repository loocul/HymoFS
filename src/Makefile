# make -C $KDIR ARCH=arm64 M=$(pwd) modules

obj-m += hymofs_lkm.o
hymofs_lkm-objs := hymofs_core.o hymofs_tracepoint.o hymofs_ftrace.o

ccflags-y += -gz=none
# Do NOT add -fno-sanitize=cfi here: init/exit must have kernel-expected CFI type for
# do_one_initcall. Use HYMO_NOCFI only on functions that make indirect calls to resolved symbols.

clean:
	rm -rf .tmp_versions
	@find . -maxdepth 1 -type f ! -name '*.c' ! -name '*.h' ! -name 'Makefile' ! -name '*.md' ! -name '.gitignore' -exec rm -f {} + 2>/dev/null || true
.PHONY: clean

#!/usr/bin/env python3

from pathlib import Path
import re
import sys


def fail(message):
    raise SystemExit(f"[ERROR] {message}")


def read_file(path):
    return path.read_text(encoding="utf-8")


def write_file(path, text):
    path.write_text(text, encoding="utf-8")


def insert_before_regex(path, pattern, block, label):
    text = read_file(path)

    if block.strip() in text:
        print(f"[INFO] {label} already exists, skipping.")
        return

    match = re.search(pattern, text, re.MULTILINE)

    if not match:
        fail(f"{label}: target not found.")

    text = text[:match.start()] + block + text[match.start():]
    write_file(path, text)

    print(f"[OK] {label} applied.")


def insert_after_function_brace(path, marker, hook, label):
    text = read_file(path)

    if hook.strip() in text:
        print(f"[INFO] {label} already exists, skipping.")
        return

    position = text.find(marker)

    if position == -1:
        fail(f"{label}: function not found: {marker}")

    brace = text.find("{", position)

    if brace == -1:
        fail(f"{label}: opening brace not found.")

    text = text[:brace + 1] + hook + text[brace + 1:]
    write_file(path, text)

    print(f"[OK] {label} applied.")


# ============================================================
# 1. stat hook
# ============================================================

def apply_stat_hooks(kernel):
    path = kernel / "fs/stat.c"

    declaration = """#ifdef CONFIG_KSU_MANUAL_HOOK
__attribute__((hot))
extern int ksu_handle_stat(int *dfd,
                           const char __user **filename_user,
                           int *flags);

extern void ksu_handle_newfstat_ret(unsigned int *fd,
                                    struct stat __user **statbuf_ptr);

#if defined(__ARCH_WANT_STAT64) || defined(__ARCH_WANT_COMPAT_STAT64)
extern void ksu_handle_fstat64_ret(unsigned long *fd,
                                   struct stat64 __user **statbuf_ptr);
#endif
#endif

"""

    insert_before_regex(
        path,
        r"^SYSCALL_DEFINE4\(newfstatat\b",
        declaration,
        "ReSukiSU stat declarations",
    )

    insert_after_function_brace(
        path,
        "SYSCALL_DEFINE4(newfstatat",
        """
#ifdef CONFIG_KSU_MANUAL_HOOK
    ksu_handle_stat(&dfd, &filename, &flag);
#endif
""",
        "ksu_handle_stat(newfstatat)",
    )

    insert_after_function_brace(
        path,
        "SYSCALL_DEFINE2(newfstat",
        """
#ifdef CONFIG_KSU_MANUAL_HOOK
    ksu_handle_newfstat_ret(&fd, &statbuf);
#endif
""",
        "ksu_handle_newfstat_ret",
    )

    text = read_file(path)

    if "SYSCALL_DEFINE4(fstatat64" in text:
        insert_after_function_brace(
            path,
            "SYSCALL_DEFINE4(fstatat64",
            """
#ifdef CONFIG_KSU_MANUAL_HOOK
    ksu_handle_stat(&dfd, &filename, &flag);
#endif
""",
            "ksu_handle_stat(fstatat64)",
        )
    else:
        print("[INFO] fstatat64() not present, skipping.")

    text = read_file(path)

    if "SYSCALL_DEFINE2(fstat64" in text:
        insert_after_function_brace(
            path,
            "SYSCALL_DEFINE2(fstat64",
            """
#ifdef CONFIG_KSU_MANUAL_HOOK
    ksu_handle_fstat64_ret(&fd, &statbuf);
#endif
""",
            "ksu_handle_fstat64_ret",
        )
    else:
        print(
            "[INFO] fstat64() not present; "
            "keeping the conditional declaration required by ReSukiSU."
        )


# ============================================================
# 2. execve hook
# ============================================================

def apply_execve_hook(kernel):
    path = kernel / "fs/exec.c"

    declaration = """#ifdef CONFIG_KSU_MANUAL_HOOK
__attribute__((hot))
extern int ksu_handle_execveat(int *fd,
                               struct filename **filename_ptr,
                               void *argv,
                               void *envp,
                               int *flags);
#endif

"""

    insert_before_regex(
        path,
        r"^static int do_execveat_common\(",
        declaration,
        "ReSukiSU execveat declaration",
    )

    insert_after_function_brace(
        path,
        "static int do_execveat_common(",
        """
#ifdef CONFIG_KSU_MANUAL_HOOK
    ksu_handle_execveat(&fd, &filename, &argv, &envp, &flags);
#endif
""",
        "ksu_handle_execveat",
    )


# ============================================================
# 3. faccessat hook
# ============================================================

def apply_faccessat_hook(kernel):
    path = kernel / "fs/open.c"

    declaration = """#ifdef CONFIG_KSU_MANUAL_HOOK
__attribute__((hot))
extern int ksu_handle_faccessat(int *dfd,
                                const char __user **filename_user,
                                int *mode,
                                int *flags);
#endif

"""

    insert_before_regex(
        path,
        r"^SYSCALL_DEFINE3\(faccessat\b",
        declaration,
        "ReSukiSU faccessat declaration",
    )

    insert_after_function_brace(
        path,
        "SYSCALL_DEFINE3(faccessat",
        """
#ifdef CONFIG_KSU_MANUAL_HOOK
    ksu_handle_faccessat(&dfd, &filename, &mode, NULL);
#endif
""",
        "ksu_handle_faccessat",
    )


# ============================================================
# 4. sys_reboot hook
# ============================================================

def apply_reboot_hook(kernel):
    path = kernel / "kernel/reboot.c"

    declaration = """#ifdef CONFIG_KSU_MANUAL_HOOK
extern int ksu_handle_sys_reboot(int magic1,
                                 int magic2,
                                 unsigned int cmd,
                                 void __user **arg);
#endif

"""

    insert_before_regex(
        path,
        r"^SYSCALL_DEFINE4\(reboot\b",
        declaration,
        "ReSukiSU reboot declaration",
    )

    insert_after_function_brace(
        path,
        "SYSCALL_DEFINE4(reboot",
        """
#ifdef CONFIG_KSU_MANUAL_HOOK
    ksu_handle_sys_reboot(magic1, magic2, cmd, &arg);
#endif
""",
        "ksu_handle_sys_reboot",
    )


# ============================================================
# 5. Input hook
#
# For this kernel we intentionally do NOT manually modify
# drivers/input/input.c.
#
# CONFIG_KSU_MANUAL_HOOK_AUTO_INPUT_HOOK=y
# lets ReSukiSU use the input_handler mechanism.
# ============================================================

def report_optional_hooks():
    print()
    print("===== Optional ReSukiSU hooks =====")
    print("[INFO] Input hook     : AUTO_INPUT_HOOK")
    print("[INFO] Setuid hook    : AUTO_SETUID_HOOK")
    print("[INFO] sys_read hook  : AUTO_INITRC_HOOK")
    print("[INFO] Manual patches for these hooks are not required.")


# ============================================================
# 6. SELinux static exports
# ============================================================

def apply_selinux_exports(kernel):
    selinuxfs = kernel / "security/selinux/selinuxfs.c"
    services = kernel / "security/selinux/ss/services.c"

    print()
    print("===== Applying ReSukiSU SELinux exports =====")

    if selinuxfs.exists():
        text = read_file(selinuxfs)

        new_text = re.sub(
            r"^static (ssize_t \(\*write_op\[\]\))",
            r"\1",
            text,
            count=1,
            flags=re.MULTILINE,
        )

        if new_text != text:
            write_file(selinuxfs, new_text)
            print("[OK] write_op exported.")
        else:
            print("[INFO] write_op already exported or not found.")

        text = read_file(selinuxfs)

        new_text = re.sub(
            r"^static (const struct file_operations "
            r"sel_handle_status_ops)",
            r"\1",
            text,
            count=1,
            flags=re.MULTILINE,
        )

        if new_text != text:
            write_file(selinuxfs, new_text)
            print("[OK] sel_handle_status_ops exported.")
        else:
            print(
                "[INFO] sel_handle_status_ops "
                "already exported or not found."
            )

        text = read_file(selinuxfs)

        new_text = re.sub(
            r"^static (DEFINE_MUTEX\(sel_mutex\);)",
            r"\1",
            text,
            count=1,
            flags=re.MULTILINE,
        )

        if new_text != text:
            write_file(selinuxfs, new_text)
            print("[OK] sel_mutex exported.")
        else:
            print("[INFO] sel_mutex already exported or not found.")

    else:
        print("[INFO] selinuxfs.c not found, skipping.")

    if services.exists():
        text = read_file(services)

        new_text = re.sub(
            r"^static (struct page \*selinux_status_page;)",
            r"\1",
            text,
            count=1,
            flags=re.MULTILINE,
        )

        if new_text != text:
            write_file(services, new_text)
            print("[OK] selinux_status_page exported.")
        else:
            print(
                "[INFO] selinux_status_page "
                "already exported or not found."
            )

        text = read_file(services)

        new_text = re.sub(
            r"^static (DEFINE_MUTEX\(selinux_status_lock\);)",
            r"\1",
            text,
            count=1,
            flags=re.MULTILINE,
        )

        if new_text != text:
            write_file(services, new_text)
            print("[OK] selinux_status_lock exported.")
        else:
            print(
                "[INFO] selinux_status_lock "
                "already exported or not found."
            )

        text = read_file(services)

        new_text = re.sub(
            r"^static (DEFINE_RWLOCK\(policy_rwlock\);)",
            r"\1",
            text,
            count=1,
            flags=re.MULTILINE,
        )

        if new_text != text:
            write_file(services, new_text)
            print("[OK] policy_rwlock exported.")
        else:
            print(
                "[INFO] policy_rwlock "
                "already exported or not found."
            )

    else:
        print("[INFO] services.c not found, skipping.")


# ============================================================
# Verification
# ============================================================

def verify_required_hooks(kernel):
    print()
    print("===== ReSukiSU hook verification =====")

    checks = [
        ("ksu_handle_stat", kernel / "fs/stat.c"),
        ("ksu_handle_newfstat_ret", kernel / "fs/stat.c"),
        ("ksu_handle_fstat64_ret", kernel / "fs/stat.c"),
        ("ksu_handle_execveat", kernel / "fs/exec.c"),
        ("ksu_handle_faccessat", kernel / "fs/open.c"),
        ("ksu_handle_sys_reboot", kernel / "kernel/reboot.c"),
    ]

    failed = False

    for symbol, path in checks:
        if not path.exists():
            print(f"[FAIL] {symbol}: {path} does not exist.")
            failed = True
            continue

        if symbol in read_file(path):
            print(f"[OK]   {symbol}")
        else:
            print(f"[FAIL] {symbol}")
            failed = True

    if failed:
        fail("One or more required ReSukiSU hooks are missing.")

    print("[OK] All required ReSukiSU hook symbols were found.")


# ============================================================
# Main
# ============================================================

def main():
    if len(sys.argv) != 2:
        print(
            f"Usage: {sys.argv[0]} "
            "<kernel-source-directory>"
        )
        return 2

    kernel = Path(sys.argv[1]).resolve()

    if not kernel.is_dir():
        print(
            f"[ERROR] Kernel source directory does not exist: "
            f"{kernel}"
        )
        return 1

    print("===== ReSukiSU manual integration =====")
    print(f"Kernel source: {kernel}")
    print()

    # Follow the order used by the ReSukiSU manual:
    # 1. stat
    # 2. execve
    # 3. faccessat
    # 4. sys_reboot
    # 5. input
    # 6. setuid
    # 7. sys_read
    # 8. SELinux static exports

    print("===== 1. stat hook =====")
    apply_stat_hooks(kernel)

    print()
    print("===== 2. execve hook =====")
    apply_execve_hook(kernel)

    print()
    print("===== 3. faccessat hook =====")
    apply_faccessat_hook(kernel)

    print()
    print("===== 4. sys_reboot hook =====")
    apply_reboot_hook(kernel)

    report_optional_hooks()

    apply_selinux_exports(kernel)

    verify_required_hooks(kernel)

    print()
    print("===== ReSukiSU manual integration finished =====")
    print("[OK] ReSukiSU hooks have been applied successfully.")

    return 0


if __name__ == "__main__":
    sys.exit(main())

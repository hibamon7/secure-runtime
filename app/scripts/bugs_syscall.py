
import pyseccomp as seccomp

DANGEROUS = ["execve", "execveat", "fork", "vfork", "clone", "clone3", "ptrace",
             "mount", "umount2", "reboot", "kexec_load", "init_module",
             "delete_module", "setuid", "setgid", "setreuid", "setregid"]

f = seccomp.SyscallFilter(defaction=seccomp.ALLOW)
for name in DANGEROUS:
    try:
        f.add_rule(seccomp.KILL, name)
        print(f"OK   {name}")
    except Exception as e:
        print(f"FAIL {name}: {type(e).__name__}: {e}")
        break  # s'arrête au premier qui casse, pas la peine de continuer
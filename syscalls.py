import pyseccomp as seccomp

f = seccomp.SyscallFilter(defaction=seccomp.LOG)  # ne bloque rien, journalise tout
f.load()
import subprocess

subprocess.run(["echo", "hello"])

import pyseccomp as seccomp

f = seccomp.SyscallFilter(defaction=seccomp.LOG)  # ne bloque rien, journalise tout
f.load()

# colle ici l'opération à observer, ex:
from pathlib import Path
print(Path("/tmp/test.txt").read_text())
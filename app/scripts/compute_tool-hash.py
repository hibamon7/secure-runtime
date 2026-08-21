import hashlib, sys
from pathlib import Path
print(hashlib.sha256(Path(sys.argv[1]).read_bytes()).hexdigest()) #hexdigest is a hexadecimal string representation of the hash 
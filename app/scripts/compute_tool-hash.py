import hashlib, sys
from pathlib import Path
print(hashlib.sha256(Path(sys.argv[1]).read_bytes()).hexdigest()) #hexdigest is a hexadecimal string representation of the hash 

#va nous servir a construire le hash des tools pour le identity manager:
#python3 scripts/compute_tool-hash.py  app/runtime/tool_manager/tools/calculator.py
import asyncio
import json
import sys
from pathlib import Path

from app.runtime.sandbox_manager import wiring


async def main():
    request = {
        "operation": "tool_exec",
        "dangerous_syscalls": [],
        "script_path": "x",
        "kwargs": {},
    }

    cg = wiring._setup_cgroup(
        "diag",
        memory_max_mb=256,
        pids_max=32,
        cpu_percent=50,
    )

    print("cgroup:", cg)
    print("memory.max:", (cg / "memory.max").read_text().strip())

    ready = Path("/tmp/wrapper-ready")
    go = Path("/tmp/wrapper-go")

    ready.unlink(missing_ok=True)
    go.unlink(missing_ok=True)

    wrapper_code = r"""
import json
import subprocess
import sys
import time
from pathlib import Path

ready = Path("/tmp/wrapper-ready")
go = Path("/tmp/wrapper-go")

ready.write_text("ready")

while not go.exists():
    time.sleep(0.01)

request = json.loads(sys.argv[1])

proc = subprocess.Popen([
    sys.executable,
    "app/scripts/fake_memory_hog_worker.py",
    json.dumps(request),
])

print("WORKER PID:", proc.pid, flush=True)

with open(f"/proc/{proc.pid}/cgroup") as f:
    print("WORKER CGROUP:", f.read().strip(), flush=True)

proc.wait()
sys.exit(proc.returncode)
"""

    wrapper = await asyncio.create_subprocess_exec(
        sys.executable,
        "-c",
        wrapper_code,
        json.dumps(request),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )

    print("wrapper PID:", wrapper.pid)

    while not ready.exists():
        await asyncio.sleep(0.01)

    # Move wrapper into the sandbox BEFORE it creates the worker.
    (cg / "cgroup.procs").write_text(str(wrapper.pid))

    print("cgroup.procs:")
    print((cg / "cgroup.procs").read_text().strip())

    # Tell wrapper it can now create the worker.
    go.write_text("go")

    stdout, stderr = await wrapper.communicate()

    print("returncode:", wrapper.returncode)
    print("stdout:", stdout.decode()[:1000])
    print("stderr:", stderr.decode()[:1000])

    print("memory.events:")
    print((cg / "memory.events").read_text())


asyncio.run(main())
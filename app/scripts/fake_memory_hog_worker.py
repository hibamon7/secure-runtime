import os

print("PID:", os.getpid(), flush=True)

with open("/proc/self/cgroup") as f:
    print("CGROUP:", f.read().strip(), flush=True)

try:
    data = bytearray(500 * 1024 * 1024)

    for i in range(0, len(data), 4096):
        data[i] = 1

    print("ALLOCATION COMPLETED", flush=True)

except MemoryError:
    print("MEMORYERROR", flush=True)
    raise
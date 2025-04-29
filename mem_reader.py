import ctypes
import psutil
import sys

class MemoryReader:
    def __init__(self, pid):
        self.pid = pid
        PROCESS_ALL_ACCESS = 0x1F0FFF
        self.handle = ctypes.windll.kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
        if not self.handle:
            raise Exception(f"无法打开进程: {pid}")

    def read_memory(self, address, size):
        data = ctypes.create_string_buffer(size)
        bytesRead = ctypes.c_size_t(0)
        if not ctypes.windll.kernel32.ReadProcessMemory(self.handle, ctypes.c_void_p(address), data, size, ctypes.byref(bytesRead)):
            raise Exception(f"读取内存失败: 0x{address:X}")
        return data.raw

    def close(self):
        if self.handle:
            ctypes.windll.kernel32.CloseHandle(self.handle)
            self.handle = None

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("用法: python mem_reader.py <pid> <address> <size>")
        sys.exit(1)
    pid = int(sys.argv[1])
    address = int(sys.argv[2], 16)
    size = int(sys.argv[3])
    reader = MemoryReader(pid)
    try:
        data = reader.read_memory(address, size)
        print(f"读取到的数据: {data.hex()}")
    finally:
        reader.close() 
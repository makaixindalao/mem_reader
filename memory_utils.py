import ctypes
import ctypes.wintypes
import struct
import time
import traceback

# --- Win32 API 常量 ---
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
PROCESS_VM_WRITE = 0x0020
PROCESS_VM_OPERATION = 0x0008
LIST_MODULES_ALL = 0x03

# --- Win32 API 函数原型定义 ---
EnumWindows = ctypes.windll.user32.EnumWindows
EnumWindowsProc = ctypes.WINFUNCTYPE(ctypes.wintypes.BOOL, ctypes.wintypes.HWND, ctypes.wintypes.LPARAM)
GetWindowTextW = ctypes.windll.user32.GetWindowTextW
GetWindowTextLengthW = ctypes.windll.user32.GetWindowTextLengthW
GetWindowThreadProcessId = ctypes.windll.user32.GetWindowThreadProcessId
OpenProcess = ctypes.windll.kernel32.OpenProcess
ReadProcessMemory = ctypes.windll.kernel32.ReadProcessMemory
WriteProcessMemory = ctypes.windll.kernel32.WriteProcessMemory
CloseHandle = ctypes.windll.kernel32.CloseHandle

# 定义 WriteProcessMemory 参数和返回类型
WriteProcessMemory.argtypes = [
    ctypes.wintypes.HANDLE,
    ctypes.wintypes.LPCVOID,
    ctypes.wintypes.LPCVOID,
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_size_t)
]
WriteProcessMemory.restype = ctypes.wintypes.BOOL

# --- K32EnumProcessModules 或 Psapi.EnumProcessModules 加载 ---
try:
    EnumProcessModules = ctypes.windll.kernel32.K32EnumProcessModules
    EnumProcessModules.argtypes = [ctypes.wintypes.HANDLE, ctypes.POINTER(ctypes.wintypes.HMODULE), ctypes.wintypes.DWORD, ctypes.POINTER(ctypes.wintypes.DWORD)]
    EnumProcessModules.restype = ctypes.wintypes.BOOL
except AttributeError:
    try:
        psapi = ctypes.WinDLL('Psapi.dll')
        EnumProcessModules = psapi.EnumProcessModules
        EnumProcessModules.argtypes = [ctypes.wintypes.HANDLE, ctypes.POINTER(ctypes.wintypes.HMODULE), ctypes.wintypes.DWORD, ctypes.POINTER(ctypes.wintypes.DWORD)]
        EnumProcessModules.restype = ctypes.wintypes.BOOL
        print("信息：使用 Psapi.dll 中的 EnumProcessModules。")
    except OSError:
        print("错误：无法加载 K32EnumProcessModules 或 Psapi.dll 中的 EnumProcessModules。获取基地址功能将不可用。")
        EnumProcessModules = None

class MemoryAccessor:
    """封装 Windows 内存读写操作和指针链解析。"""

    def __init__(self):
        self._target_pid_map = {} # {title_keyword: pid}
        self._process_handle_cache = {} # {pid: {'handle': handle, 'access_flags': flags}}
        self._base_address_cache = {}   # {pid: base_address}
        self._final_address_cache = {}  # {(pid, base_offset, tuple(offsets)): final_address}
        self._last_error = "" # 记录最后一次发生的错误信息

    def _log_error(self, message):
        """记录错误信息。"""
        print(f"错误：{message}")
        self._last_error = message
        # traceback.print_stack() # 可选：打印调用栈用于调试

    def _log_info(self, message):
        """记录普通信息。"""
        print(f"信息：{message}")

    def _log_debug(self, message):
        """记录调试信息 (可配置开关)。"""
        # print(f"DEBUG: {message}")
        pass

    def get_last_error(self):
        """获取最后一次操作记录的错误信息。"""
        return self._last_error

    # --- 进程查找与句柄管理 ---
    def _enum_windows_callback(self, hwnd, lParam):
        """EnumWindows 的回调函数，用于查找匹配标题的窗口并获取 PID。"""
        # lParam 现在用于传递包含 title_keyword 和 self 的元组
        # 从 LPARAM (本质是地址) 恢复 Python 对象
        callback_obj_ptr = ctypes.c_void_p(lParam)
        callback_data = ctypes.cast(callback_obj_ptr, ctypes.POINTER(ctypes.py_object)).contents.value
        title_keyword = callback_data['keyword']
        target_map = callback_data['map']

        length = GetWindowTextLengthW(hwnd)
        if length > 0:
            buffer = ctypes.create_unicode_buffer(length + 1)
            GetWindowTextW(hwnd, buffer, length + 1)
            window_title = buffer.value
            if title_keyword in window_title:
                pid = ctypes.wintypes.DWORD()
                GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
                target_map[title_keyword] = pid.value
                self._log_debug(f"Found PID {pid.value} for title '{title_keyword}'")
                return False # 找到即停止枚举
        return True

    def find_process_pid_by_title(self, title_keyword="Plants"):
        """通过窗口标题关键字查找进程 PID，并缓存结果。"""
        if title_keyword in self._target_pid_map:
            self._log_debug(f"PID for '{title_keyword}' found in cache: {self._target_pid_map[title_keyword]}")
            return self._target_pid_map[title_keyword]

        self._log_debug(f"Searching for PID with title keyword '{title_keyword}'...")
        # 使用 py_object 传递包含关键字和目标字典的 Python 对象
        callback_data = {'keyword': title_keyword, 'map': self._target_pid_map}
        # 将 Python 对象的地址作为 LPARAM 传递
        # 创建 py_object 并获取其地址
        callback_obj = ctypes.py_object(callback_data)
        lParam_val = ctypes.cast(ctypes.pointer(callback_obj), ctypes.c_void_p).value
        # 创建回调函数实例，确保其生命周期覆盖 EnumWindows 调用
        callback_instance = EnumWindowsProc(self._enum_windows_callback)
        # 调用 EnumWindows，传递回调实例和地址值
        EnumWindows(callback_instance, ctypes.wintypes.LPARAM(lParam_val))

        pid = self._target_pid_map.get(title_keyword)
        if not pid:
            self._log_debug(f"PID not found for '{title_keyword}'.")
            self._last_error = f"未找到标题包含 '{title_keyword}' 的进程。"
        return pid

    def get_process_handle(self, pid, access_flags):
        """获取并缓存进程句柄，确保请求的权限足够。"""
        if pid in self._process_handle_cache:
            cached_info = self._process_handle_cache[pid]
            # 检查缓存的句柄是否拥有所有请求的权限
            if (cached_info['access_flags'] & access_flags) == access_flags:
                 # TODO: 检查句柄有效性 (比较复杂，暂时省略)
                self._log_debug(f"Handle for PID {pid} with sufficient flags found in cache.")
                return cached_info['handle']
            else:
                # 权限不足，需要重新打开
                self._log_debug(f"Cached handle for PID {pid} lacks requested flags {hex(access_flags)}. Re-opening.")
                try:
                    CloseHandle(cached_info['handle'])
                except Exception as e:
                    self._log_info(f"关闭旧句柄时出错（可能已失效）: {e}")
                del self._process_handle_cache[pid] # 从缓存移除旧句柄信息
        else:
             self._log_debug(f"No handle for PID {pid} in cache.")

        self._log_debug(f"Opening process handle for PID {pid} with flags {hex(access_flags)}...")
        process_handle = OpenProcess(access_flags, False, pid)
        if not process_handle:
            error_code = ctypes.GetLastError()
            err_msg = f"无法打开进程 {pid}，错误码: {error_code}。"
            if error_code == 5: # ERROR_ACCESS_DENIED
                err_msg += " 请尝试使用管理员权限运行脚本。"
            self._log_error(err_msg)
            return None

        self._log_debug(f"Successfully opened handle {process_handle} for PID {pid}.")
        self._process_handle_cache[pid] = {'handle': process_handle, 'access_flags': access_flags}
        return process_handle

    def get_process_base_address(self, pid, process_handle):
        """获取并缓存进程基地址。"""
        if pid in self._base_address_cache:
            self._log_debug(f"Base address for PID {pid} found in cache: {hex(self._base_address_cache[pid])}")
            return self._base_address_cache[pid]

        if not EnumProcessModules:
            self._log_error("EnumProcessModules 函数不可用，无法获取基地址。")
            return None

        self._log_debug(f"Querying base address for PID {pid}...")
        modules = (ctypes.wintypes.HMODULE * 1)()
        needed = ctypes.wintypes.DWORD()

        # 确保句柄有查询权限 (虽然 get_process_handle 应该已经请求了)
        # access_flags = PROCESS_QUERY_INFORMATION | PROCESS_VM_READ # 基本权限
        # if pid not in self._process_handle_cache or \
        #    (self._process_handle_cache[pid]['access_flags'] & access_flags) != access_flags:
        #     self._log_info(f"句柄权限不足或不存在，尝试重新获取含查询权限的句柄以获取基地址...")
        #     process_handle = self.get_process_handle(pid, access_flags) # 尝试获取带查询权限的句柄
        #     if not process_handle:
        #         self._log_error("无法获取足够权限的句柄来查询模块。")
        #         return None

        # 直接传递数组，ctypes 会自动转换为指向第一个元素的指针
        if EnumProcessModules(process_handle, modules, ctypes.sizeof(modules), ctypes.byref(needed)):
            if needed.value >= ctypes.sizeof(ctypes.wintypes.HMODULE):
                base_address = modules[0]
                self._log_debug(f"Base address for PID {pid} found: {hex(base_address)}")
                self._base_address_cache[pid] = base_address
                return base_address
            else:
                self._log_info(f"EnumProcessModules 成功，但返回的 needed ({needed.value}) 小于 HMODULE 大小。")
                self._last_error = "EnumProcessModules 未返回有效的模块句柄。"
                return None
        else:
            error_code = ctypes.GetLastError()
            # 处理 32 位读 64 位可能出现的 299 错误
            if error_code == 299 and needed.value >= ctypes.sizeof(ctypes.wintypes.HMODULE):
                 base_address = modules[0]
                 self._log_info(f"EnumProcessModules 遇到部分复制错误 (299)，但成功获取到基地址: {hex(base_address)}")
                 self._base_address_cache[pid] = base_address
                 return base_address
            else:
                self._log_error(f"EnumProcessModules 获取基地址失败，错误码: {error_code}")
                # 清除可能无效的句柄缓存，以便下次重试
                self.clear_caches(pid_list=[pid], clear_handle=True, clear_base=False, clear_final=False)
                return None

    def clear_caches(self, pid_list=None, clear_pid=True, clear_handle=True, clear_base=True, clear_final=True):
        """
        清除指定的缓存。

        Args:
            pid_list (list, optional): 如果提供，则只清除指定 PID 的相关缓存。否则清除所有。
            clear_pid (bool): 是否清除 PID 缓存。
            clear_handle (bool): 是否清除句柄缓存 (并关闭句柄)。
            clear_base (bool): 是否清除基地址缓存。
            clear_final (bool): 是否清除最终地址缓存。
        """
        cleared = []
        pids_to_clear = pid_list if pid_list else list(self._process_handle_cache.keys()) + list(self._base_address_cache.keys())

        if clear_pid:
            if pid_list:
                keywords_to_clear = [kw for kw, p in self._target_pid_map.items() if p in pid_list]
                for kw in keywords_to_clear:
                    del self._target_pid_map[kw]
            else:
                self._target_pid_map.clear()
            cleared.append("PID")

        if clear_handle:
            handles_closed = 0
            pids_cleared = []
            for pid in pids_to_clear:
                if pid in self._process_handle_cache:
                    try:
                        CloseHandle(self._process_handle_cache[pid]['handle'])
                        handles_closed += 1
                    except Exception as e:
                        self._log_info(f"警告：关闭 PID {pid} 的缓存句柄时出错: {e}")
                    del self._process_handle_cache[pid]
                    pids_cleared.append(pid)
            if pids_cleared or not pid_list: # 如果指定了pid列表但没找到，或者清空所有
                 cleared.append(f"句柄 ({handles_closed} closed for {len(pids_cleared)} PIDs)")


        if clear_base:
            pids_cleared = []
            for pid in pids_to_clear:
                if pid in self._base_address_cache:
                    del self._base_address_cache[pid]
                    pids_cleared.append(pid)
            if pids_cleared or not pid_list:
                cleared.append(f"基地址 ({len(pids_cleared)} PIDs)")

        if clear_final:
            keys_to_clear = []
            for cache_key in self._final_address_cache.keys():
                pid, _, _ = cache_key
                if pid_list is None or pid in pid_list:
                    keys_to_clear.append(cache_key)
            for key in keys_to_clear:
                del self._final_address_cache[key]
            if keys_to_clear or not pid_list:
                cleared.append(f"最终地址 ({len(keys_to_clear)} entries)")

        if cleared:
            self._log_info(f"缓存已清除: {', '.join(cleared)}")

    def close_handles(self):
        """关闭所有缓存的进程句柄。"""
        self.clear_caches(clear_pid=False, clear_handle=True, clear_base=False, clear_final=False)

    # --- 内存读写核心 ---
    def _read_memory_at_address(self, process_handle, address, data_size):
        """在指定绝对地址读取指定大小的内存 (内部使用)。"""
        if not process_handle or address is None or address == 0:
            self._log_debug(f"Invalid parameters for read: handle={process_handle}, address={address}")
            self._last_error = "读取内存的参数无效（句柄或地址为空）。"
            return None
        buffer = ctypes.create_string_buffer(data_size)
        bytes_read = ctypes.c_size_t(0)

        if ReadProcessMemory(process_handle, ctypes.c_void_p(address), buffer, data_size, ctypes.byref(bytes_read)):
            if bytes_read.value == data_size:
                self._log_debug(f"Read {bytes_read.value} bytes from {hex(address)}: {buffer.raw.hex()}")
                return buffer.raw
            else:
                # 部分读取通常意味着地址无效或跨越了不可读区域
                self._log_debug(f"Read partial data ({bytes_read.value}/{data_size}) from {hex(address)}")
                self._last_error = f"从地址 {hex(address)} 部分读取数据 ({bytes_read.value}/{data_size})。"
                return None # 返回 None 表示失败
        else:
            error_code = ctypes.GetLastError()
            # 常见错误 299 (ERROR_PARTIAL_COPY), 5 (ERROR_ACCESS_DENIED), 998 (ERROR_NOACCESS)
            self._log_debug(f"ReadProcessMemory failed at {hex(address)}, error code: {error_code}")
            self._last_error = f"ReadProcessMemory 在 {hex(address)} 失败，错误码: {error_code}"
            return None

    def _write_memory_at_address(self, process_handle, address, data_bytes):
        """在指定绝对地址写入字节数据 (内部使用)。"""
        if not process_handle or address is None or address == 0:
            self._log_debug(f"Invalid parameters for write: handle={process_handle}, address={address}")
            self._last_error = "写入内存的参数无效（句柄或地址为空）。"
            return False
        data_size = len(data_bytes)
        buffer = ctypes.create_string_buffer(data_bytes)
        bytes_written = ctypes.c_size_t(0)

        if WriteProcessMemory(process_handle, ctypes.c_void_p(address), buffer, data_size, ctypes.byref(bytes_written)):
            if bytes_written.value == data_size:
                self._log_debug(f"Wrote {bytes_written.value} bytes to {hex(address)}")
                return True
            else:
                self._log_error(f"WriteProcessMemory 在 {hex(address)} 写入的字节数 ({bytes_written.value}) 与请求的 ({data_size}) 不符。")
                return False
        else:
            error_code = ctypes.GetLastError()
            self._log_error(f"WriteProcessMemory 在地址 {hex(address)} 写入失败，错误码: {error_code}")
            return False

    # --- 指针链解析 ---
    def _resolve_pointer_chain(self, pid, process_handle, base_offset, offsets, pointer_size=4):
        """解析指针链并返回最终地址，利用缓存。"""
        cache_key = (pid, base_offset, tuple(offsets))
        if cache_key in self._final_address_cache:
            cached_addr = self._final_address_cache[cache_key]
            self._log_debug(f"Final address for {cache_key} found in cache: {hex(cached_addr)}")
            # 可选：快速读取测试缓存地址有效性
            # if self._read_memory_at_address(process_handle, cached_addr, 1) is None:
            #     self._log_debug(f"Cached address {hex(cached_addr)} seems invalid, removing from cache.")
            #     del self._final_address_cache[cache_key]
            # else:
            #     return cached_addr
            return cached_addr # 暂时不加检查

        self._log_debug(f"Resolving pointer chain for {cache_key}...")
        base_address = self.get_process_base_address(pid, process_handle)
        if base_address is None:
            self._log_error("无法获取进程基地址，无法解析指针链。")
            return None
        self._log_debug(f"进程基地址: {hex(base_address)}")

        current_address = base_address + base_offset
        self._log_debug(f"步骤 1: 计算基地址+偏移 = {hex(base_address)} + {hex(base_offset)} = {hex(current_address)}")

        if not offsets:
            self._log_debug("步骤 2: 无后续偏移，最终地址是基地址+偏移")
            self._final_address_cache[cache_key] = current_address
            self._log_debug(f"Caching final address {hex(current_address)} for {cache_key}")
            return current_address

        # 读取第一个指针值
        self._log_debug(f"步骤 2: 尝试从 {hex(current_address)} 读取 {pointer_size} 字节 (pointer 1)")
        pointer_bytes = self._read_memory_at_address(process_handle, current_address, pointer_size)
        if pointer_bytes is None:
            self._log_error(f"读取指针链失败：无法在地址 {hex(current_address)} 读取第一个指针。")
            return None

        try:
            if pointer_size == 4:
                current_pointer_value = struct.unpack('<I', pointer_bytes)[0]
            elif pointer_size == 8:
                current_pointer_value = struct.unpack('<Q', pointer_bytes)[0]
            else:
                self._log_error(f"不支持的指针大小 {pointer_size}")
                return None
            self._log_debug(f"读取到 pointer 1 = {hex(current_pointer_value)}")
        except struct.error as e:
             self._log_error(f"解析第一个指针值时出错: {e}")
             return None


        # 循环处理后续偏移量
        for i, offset in enumerate(offsets):
            next_address_to_read = current_pointer_value + offset
            self._log_debug(f"步骤 {3 + i*2}: 计算地址 = pointer{i+1} + offset{i+1} = {hex(current_pointer_value)} + {hex(offset)} = {hex(next_address_to_read)}")

            # 在最后一个偏移之前，读取的是下一个指针
            if i < len(offsets) - 1:
                self._log_debug(f"步骤 {4 + i*2}: 尝试从 {hex(next_address_to_read)} 读取 {pointer_size} 字节 (pointer {i+2})")
                pointer_bytes = self._read_memory_at_address(process_handle, next_address_to_read, pointer_size)
                if pointer_bytes is None:
                    self._log_error(f"读取指针链失败：无法在地址 {hex(next_address_to_read)} 读取指针 {i+2}。")
                    return None

                try:
                    if pointer_size == 4:
                        current_pointer_value = struct.unpack('<I', pointer_bytes)[0]
                    else: # pointer_size == 8
                        current_pointer_value = struct.unpack('<Q', pointer_bytes)[0]
                    self._log_debug(f"读取到 pointer {i+2} = {hex(current_pointer_value)}")
                except struct.error as e:
                    self._log_error(f"解析指针 {i+2} 值时出错: {e}")
                    return None
            else:
                # 这是最后一个偏移，next_address_to_read 就是最终要读/写的地址
                final_address = next_address_to_read
                self._log_debug(f"步骤 {4 + i*2}: 最后一个偏移，最终地址 = {hex(final_address)}")
                self._final_address_cache[cache_key] = final_address
                self._log_debug(f"Caching final address {hex(final_address)} for {cache_key}")
                return final_address

        # 理论上不应到达这里
        self._log_error("指针链解析逻辑可能存在问题，未能确定最终地址。")
        return None

    # --- 公开接口 ---
    def read_value(self, title_keyword, base_offset, offsets, final_data_size=4, pointer_size=4, data_format=None):
        """
        读取多级指针链指向的数据。

        Args:
            title_keyword (str): 窗口标题关键字。
            base_offset (int): 相对于进程基地址的第一个偏移量。
            offsets (list or tuple): 后续的偏移量列表 (可以为空)。
            final_data_size (int): 最终要读取的数据字节数 (默认为 4)。
            pointer_size (int): 指针的大小（字节），4 或 8 (默认 4)。
            data_format (str or None): struct 格式化字符串 (如 '<i', '<f', '<Q') 用于解析最终数据。
                                         如果为 None，则返回原始 bytes。

        Returns:
            int, float, bytes, or None: 读取到的最终数据 (根据 data_format 解析)，失败则返回 None。
        """
        self._last_error = "" # 清除之前的错误信息
        pid = self.find_process_pid_by_title(title_keyword)
        if not pid:
            # find_process_pid_by_title 内部已记录错误
            return None
        self._log_debug(f"找到 PID: {pid}")

        # 请求读权限
        access_flags = PROCESS_QUERY_INFORMATION | PROCESS_VM_READ
        process_handle = self.get_process_handle(pid, access_flags)
        if not process_handle:
            # get_process_handle 内部已记录错误
            return None
        self._log_debug(f"获取到进程句柄: {process_handle}")

        # 解析指针链获取最终地址
        final_address = self._resolve_pointer_chain(pid, process_handle, base_offset, offsets, pointer_size)

        if final_address is None:
            self._log_error("读取失败：无法解析指针链得到最终地址。")
            # 句柄仍在缓存中
            return None
        self._log_debug(f"最终地址: {hex(final_address)}")

        # 从最终地址读取数据
        self._log_debug(f"尝试从最终地址 {hex(final_address)} 读取 {final_data_size} 字节...")
        read_bytes = self._read_memory_at_address(process_handle, final_address, final_data_size)

        if read_bytes is None:
            self._log_error(f"读取失败：无法从最终地址 {hex(final_address)} 读取数据。")
            # 地址可能失效，清除缓存
            cache_key = (pid, base_offset, tuple(offsets))
            if cache_key in self._final_address_cache:
                self._log_debug(f"Removing potentially invalid final address cache for {cache_key}")
                del self._final_address_cache[cache_key]
            return None

        self._log_debug(f"成功读取原始字节: {read_bytes.hex()}")

        # 解析数据
        if data_format:
            try:
                expected_size = struct.calcsize(data_format)
                if len(read_bytes) == expected_size:
                    unpacked_value = struct.unpack(data_format, read_bytes)[0]
                    self._log_debug(f"解析后的值 ({data_format}): {unpacked_value}")
                    return unpacked_value
                else:
                    self._log_error(f"读取的字节数 ({len(read_bytes)}) 与数据格式 '{data_format}' 要求的大小 ({expected_size}) 不匹配。")
                    self._last_error += f" 读取字节数与期望格式大小不符。" # 追加错误信息
                    return read_bytes # 返回原始字节供调试
            except struct.error as e:
                self._log_error(f"使用格式 '{data_format}' 解析字节时出错: {e}")
                return read_bytes # 返回原始字节供调试
        else:
            self._log_debug("未指定 data_format，返回原始字节。")
            return read_bytes

    def write_value(self, title_keyword, base_offset, offsets, value_to_write, pointer_size=4, data_format='<i'):
        """
        向多级指针链指向的最终地址写入数据。

        Args:
            title_keyword (str): 窗口标题关键字。
            base_offset (int): 相对于进程基地址的第一个偏移量。
            offsets (list or tuple): 后续的偏移量列表 (可以为空)。
            value_to_write: 要写入的值 (int, float, etc.)。
            pointer_size (int): 指针的大小（字节），4 或 8 (默认 4)。
            data_format (str): struct 格式化字符串 (如 '<i', '<f') 用于将 value_to_write 打包成字节。
                               必须提供。

        Returns:
            bool: True 表示写入成功，False 表示失败。
        """
        self._last_error = "" # 清除之前的错误信息
        pid = self.find_process_pid_by_title(title_keyword)
        if not pid:
            return False
        self._log_debug(f"找到 PID: {pid}")

        # 请求读和写权限
        access_flags = PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION
        process_handle = self.get_process_handle(pid, access_flags)
        if not process_handle:
            return False
        self._log_debug(f"获取到进程句柄 (含写入权限): {process_handle}")

        # 解析指针链获取最终地址
        final_address = self._resolve_pointer_chain(pid, process_handle, base_offset, offsets, pointer_size)

        if final_address is None:
            self._log_error("写入失败：无法解析指针链得到最终地址。")
            return False
        self._log_debug(f"最终地址: {hex(final_address)}")

        # 打包数据
        try:
            bytes_to_write = struct.pack(data_format, value_to_write)
            self._log_debug(f"准备写入的值: {value_to_write}, 打包格式: '{data_format}', 字节: {bytes_to_write.hex()}")
        except struct.error as e:
            self._log_error(f"使用格式 '{data_format}' 打包值 {value_to_write} 时出错: {e}")
            return False
        except TypeError as e:
             self._log_error(f"值 {value_to_write} 的类型与格式 '{data_format}' 不兼容: {e}")
             return False

        # 写入数据
        self._log_debug(f"尝试向最终地址 {hex(final_address)} 写入 {len(bytes_to_write)} 字节...")
        success = self._write_memory_at_address(process_handle, final_address, bytes_to_write)

        if not success:
            # _write_memory_at_address 内部已记录错误
            self._log_error(f"写入失败：无法向最终地址 {hex(final_address)} 写入数据。")
            # 地址可能失效，清除缓存
            cache_key = (pid, base_offset, tuple(offsets))
            if cache_key in self._final_address_cache:
                self._log_debug(f"Removing potentially invalid final address cache for {cache_key}")
                del self._final_address_cache[cache_key]
            return False

        self._log_info("写入成功。")
        return True

    def __del__(self):
        """对象销毁时尝试关闭所有缓存的句柄。"""
        self._log_info("MemoryAccessor 对象销毁，关闭所有缓存的句柄...")
        self.close_handles()
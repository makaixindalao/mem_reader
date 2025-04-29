import time
import sys
from memory_utils import MemoryAccessor # 导入新的类

# --- 使用示例 ---
if __name__ == "__main__":
    # 创建 MemoryAccessor 实例
    accessor = MemoryAccessor()

    target_title_keyword = "Plants" # 目标窗口标题关键字 (请替换成你的目标)
    # 示例：假设要读取阳光值 (通常是整数 int, 4字节)
    # 假设 CE 找到的地址是 "popcapgame1.exe"+355E0C -> 指针1
    # 读取 [指针1 + 868] -> 指针2
    # 读取 [指针2 + 5578] -> 阳光值地址
    sun_base_offset = 0x355E0C
    sun_offsets = [0x868, 0x5578]
    sun_data_size = 4
    sun_data_format = '<i' # 小端 4 字节有符号整数
    # 假设目标进程是 32 位，指针大小为 4
    # 如果目标是 64 位，需要改为 pointer_size=8
    pointer_size = 4

    print(f"正在尝试读取 '{target_title_keyword}' 的阳光值...")
    print(f"基地址偏移: {hex(sun_base_offset)}")
    print(f"后续偏移: {[hex(o) for o in sun_offsets]}")
    print(f"指针大小: {pointer_size} 字节")
    print(f"最终读取大小: {sun_data_size} 字节, 解析格式: '{sun_data_format}'")
    print("-" * 30)

    # 第一次读取 (会进行完整查找和解析)
    start_time = time.time()
    current_sun = accessor.read_value(
        title_keyword=target_title_keyword,
        base_offset=sun_base_offset,
        offsets=sun_offsets,
        final_data_size=sun_data_size,
        pointer_size=pointer_size,
        data_format=sun_data_format
    )
    end_time = time.time()
    print("-" * 30)
    if current_sun is not None:
        print(f"第一次读取 - 当前阳光值: {current_sun} (耗时: {end_time - start_time:.4f} 秒)")
    else:
        print("第一次读取失败。请检查：")
        print(f"  - 错误信息: {accessor.get_last_error()}") # 获取具体错误
        print("  - 目标进程是否运行且窗口标题匹配?")
        print("  - 脚本是否以管理员权限运行?")
        print("  - 所有偏移量是否对当前进程版本有效?")
        print(f"  - 指针大小 ({pointer_size}) 是否与目标进程架构 (32/64位) 匹配?")
        # sys.exit(1) # 如果第一次失败，后续操作可能无意义

    print("-" * 30)

    # 第二次读取 (应使用缓存，速度更快)
    if current_sun is not None: # 仅在第一次成功时尝试
        print("尝试第二次读取 (应利用缓存)...")
        start_time = time.time()
        current_sun_cached = accessor.read_value(
            title_keyword=target_title_keyword,
            base_offset=sun_base_offset,
            offsets=sun_offsets,
            final_data_size=sun_data_size,
            pointer_size=pointer_size,
            data_format=sun_data_format
        )
        end_time = time.time()
        if current_sun_cached is not None:
            print(f"第二次读取 - 当前阳光值: {current_sun_cached} (耗时: {end_time - start_time:.4f} 秒)")
        else:
            print(f"第二次读取失败。错误: {accessor.get_last_error()}")
        print("-" * 30)


    # 示例：尝试写入阳光值 (谨慎操作！)
    if current_sun is not None: # 仅在读取成功时尝试写入
        new_sun_value = 9990
        print(f"尝试将阳光值写入为: {new_sun_value}")
        start_time = time.time()
        write_success = accessor.write_value(
            title_keyword=target_title_keyword,
            base_offset=sun_base_offset,
            offsets=sun_offsets,
            value_to_write=new_sun_value,
            pointer_size=pointer_size,
            data_format=sun_data_format # 使用与读取相同的格式
        )
        end_time = time.time()

        if write_success:
            print(f"写入操作完成 (耗时: {end_time - start_time:.4f} 秒)。请在游戏中检查效果。")
            # 读取写入后的值进行验证
            time.sleep(0.1) # 短暂等待，确保内存写入生效
            written_sun = accessor.read_value(
                title_keyword=target_title_keyword,
                base_offset=sun_base_offset,
                offsets=sun_offsets,
                final_data_size=sun_data_size,
                pointer_size=pointer_size,
                data_format=sun_data_format
            )
            if written_sun is not None:
                print(f"写入后读取 - 当前阳光值: {written_sun}")
            else:
                print(f"写入后读取失败。错误: {accessor.get_last_error()}")
        else:
            print(f"写入操作失败。错误: {accessor.get_last_error()}")

        print("-" * 30)

    # 示例：清除最终地址缓存，然后再次读取
    print("清除最终地址缓存...")
    # 只清除最终地址缓存，保留 PID、句柄和基地址缓存
    accessor.clear_caches(clear_pid=False, clear_handle=False, clear_base=False, clear_final=True)
    print("再次读取 (应重新解析指针链)...")
    start_time = time.time()
    current_sun_after_clear = accessor.read_value(
        title_keyword=target_title_keyword,
        base_offset=sun_base_offset,
        offsets=sun_offsets,
        final_data_size=sun_data_size,
        pointer_size=pointer_size,
        data_format=sun_data_format
    )
    end_time = time.time()
    if current_sun_after_clear is not None:
        print(f"清除缓存后读取 - 当前阳光值: {current_sun_after_clear} (耗时: {end_time - start_time:.4f} 秒)")
    else:
        print(f"清除缓存后读取失败。错误: {accessor.get_last_error()}")

    # 脚本结束时，MemoryAccessor 的 __del__ 方法会自动尝试关闭缓存的句柄
    print("\n脚本执行完毕。")

    # 如果需要显式关闭句柄（例如在长时间运行的应用中），可以调用：
    # accessor.close_handles()

using System.Runtime.InteropServices;

namespace Doomsday;

internal static unsafe class Native
{
    public const uint MEM_COMMIT = 0x1000;
    public const uint MEM_FREE = 0x10000;
    public const uint MEM_IMAGE = 0x1000000;

    public const uint PAGE_NOACCESS = 0x01;
    public const uint PAGE_GUARD = 0x100;
    public const uint EXEC_MASK = 0x10 | 0x20 | 0x40 | 0x80;
    public const uint WRITE_MASK = 0x04 | 0x08 | 0x40 | 0x80;

    [Flags]
    public enum ProcessAccess : uint
    {
        QueryInformation = 0x0400,
        QueryLimitedInformation = 0x1000,
        VmRead = 0x0010,
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct MEMORY_BASIC_INFORMATION
    {
        public IntPtr BaseAddress;
        public IntPtr AllocationBase;
        public uint AllocationProtect;
        private readonly uint __align1;
        public ulong RegionSize;
        public uint State;
        public uint Protect;
        public uint Type;
        private readonly uint __align2;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct MEMORY_WORKING_SET_EX_INFORMATION
    {
        public IntPtr VirtualAddress;
        public ulong VirtualAttributes;

        public bool Valid => (VirtualAttributes & 1) != 0;
        public int ShareCount => (int)((VirtualAttributes >> 1) & 7);
        public bool Shared => ((VirtualAttributes >> 15) & 1) != 0;
        public bool SharedOriginal => ((VirtualAttributes >> 30) & 1) != 0;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct UNICODE_STRING
    {
        public ushort Length;
        public ushort MaximumLength;
        private readonly uint __pad;
        public IntPtr Buffer;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SYSTEM_INFO
    {
        public ushort ProcessorArchitecture;
        public ushort Reserved;
        public uint PageSize;
        public IntPtr MinimumApplicationAddress;
        public IntPtr MaximumApplicationAddress;
        public IntPtr ActiveProcessorMask;
        public uint NumberOfProcessors;
        public uint ProcessorType;
        public uint AllocationGranularity;
        public ushort ProcessorLevel;
        public ushort ProcessorRevision;
    }

    public enum MEMORY_INFORMATION_CLASS
    {
        MemoryBasicInformation = 0,
        MemoryMappedFilenameInformation = 2,
        MemoryWorkingSetExInformation = 4,
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr OpenProcess(ProcessAccess access, bool inherit, int pid);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool CloseHandle(IntPtr h);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr addr, byte* buffer,
        nuint size, out nuint read);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern nuint VirtualQueryEx(IntPtr hProcess, IntPtr addr,
        out MEMORY_BASIC_INFORMATION mbi, nuint len);

    [DllImport("kernel32.dll")]
    public static extern void GetSystemInfo(out SYSTEM_INFO info);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool QueryFullProcessImageNameW(IntPtr hProcess, uint flags,
        char* buffer, ref uint size);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool IsWow64Process(IntPtr hProcess, out bool wow64);

    [DllImport("ntdll.dll")]
    public static extern int NtQueryVirtualMemory(IntPtr hProcess, IntPtr addr,
        MEMORY_INFORMATION_CLASS cls, void* buffer, nuint len, nuint* retLen);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern int QueryDosDeviceW(string device, char* buf, int size);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool OpenProcessToken(IntPtr process, uint access, out IntPtr token);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool LookupPrivilegeValueW(string? system, string name, out long luid);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool AdjustTokenPrivileges(IntPtr token, bool disableAll,
        void* newState, uint bufferLength, void* previous, uint* returnLength);

    [DllImport("kernel32.dll")]
    public static extern IntPtr GetCurrentProcess();

    public static bool EnablePrivilege(string name)
    {
        if (!OpenProcessToken(GetCurrentProcess(), 0x0020 | 0x0008, out IntPtr tok)) return false;
        try
        {
            if (!LookupPrivilegeValueW(null, name, out long luid)) return false;
            var buf = stackalloc long[3];
            *(uint*)buf = 1;
            *(long*)((byte*)buf + 4) = luid;
            *(uint*)((byte*)buf + 12) = 2;
            return AdjustTokenPrivileges(tok, false, buf, 16, null, null)
                   && Marshal.GetLastWin32Error() == 0;
        }
        finally { CloseHandle(tok); }
    }

    public static byte[]? Read(IntPtr h, ulong addr, int len)
    {
        if (len <= 0 || len > 64 * 1024 * 1024) return null;
        var buf = new byte[len];
        fixed (byte* p = buf)
        {
            if (!ReadProcessMemory(h, (IntPtr)addr, p, (nuint)len, out nuint got)) return null;
            if (got != (nuint)len) return null;
        }
        return buf;
    }

    public static string? MappedFile(IntPtr h, ulong addr)
    {
        const int cap = 4096;
        byte* buf = stackalloc byte[cap];
        nuint ret;
        if (NtQueryVirtualMemory(h, (IntPtr)addr,
                MEMORY_INFORMATION_CLASS.MemoryMappedFilenameInformation, buf, cap, &ret) != 0)
            return null;

        var us = *(UNICODE_STRING*)buf;
        if (us.Length == 0) return null;
        string nt = new string((char*)(buf + sizeof(UNICODE_STRING)), 0, us.Length / 2);
        return DeviceMap.ToDos(nt) ?? nt;
    }

    public static string Prot(uint p) => (p & 0xFF) switch
    {
        0x01 => "---",
        0x02 => "R--",
        0x04 => "RW-",
        0x08 => "RWC",
        0x10 => "--X",
        0x20 => "R-X",
        0x40 => "RWX",
        0x80 => "RWXC",
        _ => $"0x{p & 0xFF:X2}",
    };
}

internal static unsafe class DeviceMap
{
    private static readonly Dictionary<string, string> Map = Build();

    private static Dictionary<string, string> Build()
    {
        var d = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        char* buf = stackalloc char[1024];
        for (char c = 'A'; c <= 'Z'; c++)
        {
            int n = Native.QueryDosDeviceW($"{c}:", buf, 1024);
            if (n <= 0) continue;
            string target = new string(buf);
            if (target.Length > 0) d[target] = $"{c}:";
        }
        return d;
    }

    public static string? ToDos(string ntPath)
    {
        foreach (var kv in Map)
            if (ntPath.StartsWith(kv.Key, StringComparison.OrdinalIgnoreCase))
                return kv.Value + ntPath.Substring(kv.Key.Length);
        return null;
    }
}

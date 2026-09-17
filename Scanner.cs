using System.Diagnostics;
using static Doomsday.Native;

namespace Doomsday;

internal enum PageState { Shared, Private, Unknown }

internal sealed class DiffRun
{
    public uint Rva;
    public byte[] Memory = Array.Empty<byte>();
    public byte[] Disk = Array.Empty<byte>();
    public string Function = "";
}

internal sealed class PageInfo
{
    public ulong Address;
    public uint Rva;
    public string Section = "";
    public uint Protect;
    public uint Type;
    public PageState State;
    public bool SharedOriginal;
    public int ShareCount;
    public bool? MatchesDisk;
    public bool HasRelocs;
    public List<DiffRun> Diffs = new();
    public string NearestExport = "";
    public uint NearestOffset;
    public int FunctionsStarting;
    public List<string> Exports = new();

    public bool Executable => (Protect & EXEC_MASK) != 0;
}

internal sealed class RegionInfo
{
    public ulong Base;
    public ulong Size;
    public ulong AllocationBase;
    public uint State;
    public uint Type;
    public uint Protect;
}

internal sealed class ModuleScan
{
    public string Path = "";
    public string Name = "";
    public ulong Base;
    public PeImage Image = null!;
    public PeImage? Disk;
    public byte[]? DiskBytes;
    public long DiskLength;
    public string DiskError = "";
    public List<RegionInfo> Regions = new();
    public List<PageInfo> Pages = new();

    public int ExecPages => Pages.Count(p => p.Executable);
    public int ExecResident => Pages.Count(p => p.Executable && p.State != PageState.Unknown);
    public int ExecPrivate => Pages.Count(p => p.Executable && p.State == PageState.Private);
    public int ExecUnknown => Pages.Count(p => p.Executable && p.State == PageState.Unknown);
}

internal sealed class TargetInfo
{
    public int Pid;
    public string Name = "";
    public string Path = "";
    public long WorkingSet;
    public bool Wow64;
    public string Window = "";
}

internal static unsafe class Scanner
{
    public static Process? FindTarget()
    {
        Process? best = null;
        long bestSize = -1;

        foreach (var p in Process.GetProcesses())
        {
            string name;
            try { name = p.ProcessName; }
            catch { p.Dispose(); continue; }

            if (!name.Equals("javaw", StringComparison.OrdinalIgnoreCase)) { p.Dispose(); continue; }

            long size;
            try { size = p.WorkingSet64; }
            catch { p.Dispose(); continue; }

            if (size > bestSize)
            {
                best?.Dispose();
                best = p;
                bestSize = size;
            }
            else p.Dispose();
        }
        return best;
    }

    public static IntPtr Open(int pid)
    {
        IntPtr h = OpenProcess(ProcessAccess.QueryInformation | ProcessAccess.VmRead, false, pid);
        if (h == IntPtr.Zero)
            h = OpenProcess(ProcessAccess.QueryLimitedInformation | ProcessAccess.VmRead, false, pid);
        if (h == IntPtr.Zero)
            throw new InvalidOperationException(
                $"OpenProcess({pid}) = {System.Runtime.InteropServices.Marshal.GetLastWin32Error()}");
        return h;
    }

    public static TargetInfo Describe(IntPtr h, Process p)
    {
        var info = new TargetInfo { Pid = p.Id };
        try { info.Name = p.ProcessName; } catch { }
        try { info.WorkingSet = p.WorkingSet64; } catch { }
        try { info.Window = p.MainWindowTitle; } catch { }

        uint cap = 4096;
        var buf = stackalloc char[(int)cap];
        if (QueryFullProcessImageNameW(h, 0, buf, ref cap)) info.Path = new string(buf, 0, (int)cap);
        if (IsWow64Process(h, out bool wow)) info.Wow64 = wow;
        return info;
    }

    public static List<MEMORY_BASIC_INFORMATION> Enumerate(IntPtr h, ulong from, ulong to)
    {
        var list = new List<MEMORY_BASIC_INFORMATION>();
        ulong addr = from;
        while (addr < to)
        {
            if (VirtualQueryEx(h, (IntPtr)addr, out var mbi,
                    (nuint)sizeof(MEMORY_BASIC_INFORMATION)) == 0)
            {
                addr += 0x1000;
                continue;
            }
            ulong size = mbi.RegionSize;
            if (size == 0) { addr += 0x1000; continue; }
            if (mbi.State != MEM_FREE) list.Add(mbi);

            ulong next = (ulong)mbi.BaseAddress.ToInt64() + size;
            if (next <= addr) break;
            addr = next;
        }
        return list;
    }

    public static List<(ulong Base, string Path)> FindImages(IntPtr h, string fileName)
    {
        GetSystemInfo(out var si);
        var regions = Enumerate(h, 0, (ulong)si.MaximumApplicationAddress.ToInt64());
        var seen = new HashSet<ulong>();
        var result = new List<(ulong, string)>();

        foreach (var r in regions)
        {
            if (r.Type != MEM_IMAGE) continue;
            ulong alloc = (ulong)r.AllocationBase.ToInt64();
            if (alloc == 0 || !seen.Add(alloc)) continue;

            string? path = MappedFile(h, alloc);
            if (path is null) continue;
            if (!System.IO.Path.GetFileName(path).Equals(fileName, StringComparison.OrdinalIgnoreCase))
                continue;
            result.Add((alloc, path));
        }
        return result;
    }

    public static ModuleScan? Scan(IntPtr h, ulong baseAddr, string path)
    {
        var img = PeImage.FromMemory(h, baseAddr);
        if (img is null) return null;

        var m = new ModuleScan
        {
            Path = path,
            Name = System.IO.Path.GetFileName(path),
            Base = baseAddr,
            Image = img,
        };

        LoadDisk(m);

        ulong end = baseAddr + Math.Max(img.SizeOfImage, 0x1000u);
        foreach (var r in Enumerate(h, baseAddr, end))
        {
            var ri = new RegionInfo
            {
                Base = (ulong)r.BaseAddress.ToInt64(),
                Size = r.RegionSize,
                AllocationBase = (ulong)r.AllocationBase.ToInt64(),
                State = r.State,
                Type = r.Type,
                Protect = r.Protect,
            };
            m.Regions.Add(ri);
        }

        foreach (var sec in img.Sections)
        {
            bool exec = sec.Executable || m.Regions.Any(r =>
                r.State == MEM_COMMIT && (r.Protect & EXEC_MASK) != 0 &&
                r.Base < baseAddr + sec.End && r.Base + r.Size > baseAddr + sec.Va);
            if (!exec) continue;
            ScanSection(h, m, sec);
        }

        return m;
    }

    private static void LoadDisk(ModuleScan m)
    {
        try
        {
            var file = File.ReadAllBytes(m.Path);
            m.DiskLength = file.LongLength;
            m.Disk = PeImage.FromFile(file);
            if (m.Disk is null) { m.DiskError = "файл на диске не разбирается как PE64"; return; }
            m.DiskBytes = file;
        }
        catch (Exception ex)
        {
            m.DiskError = ex.Message;
        }
    }

    private static void ScanSection(IntPtr h, ModuleScan m, Section sec)
    {
        uint first = sec.Va & ~0xFFFu;
        uint last = (sec.End + 0xFFF) & ~0xFFFu;
        int pages = (int)((last - first) / 0x1000);
        if (pages <= 0 || pages > 65536) return;

        var mem = new byte[pages][];
        for (int i = 0; i < pages; i++)
            mem[i] = Native.Read(h, m.Base + first + (uint)i * 0x1000, 0x1000) ?? Array.Empty<byte>();

        var ws = new MEMORY_WORKING_SET_EX_INFORMATION[pages];
        fixed (MEMORY_WORKING_SET_EX_INFORMATION* p = ws)
        {
            for (int i = 0; i < pages; i++)
                p[i].VirtualAddress = (IntPtr)(m.Base + first + (uint)i * 0x1000);
            int st = NtQueryVirtualMemory(h, IntPtr.Zero,
                MEMORY_INFORMATION_CLASS.MemoryWorkingSetExInformation, p,
                (nuint)(pages * sizeof(MEMORY_WORKING_SET_EX_INFORMATION)), null);
            if (st != 0)
                for (int i = 0; i < pages; i++) p[i].VirtualAttributes = 0;
        }

        for (int i = 0; i < pages; i++)
        {
            uint rva = first + (uint)i * 0x1000;
            ulong addr = m.Base + rva;
            var region = m.Regions.FirstOrDefault(r => addr >= r.Base && addr < r.Base + r.Size);
            if (region is null || region.State != MEM_COMMIT) continue;
            if ((region.Protect & PAGE_GUARD) != 0 || (region.Protect & 0xFF) == PAGE_NOACCESS) continue;

            var page = new PageInfo
            {
                Address = addr,
                Rva = rva,
                Section = sec.Name,
                Protect = region.Protect,
                Type = region.Type,
                SharedOriginal = ws[i].SharedOriginal,
                ShareCount = ws[i].ShareCount,
                State = !ws[i].Valid ? PageState.Unknown
                      : ws[i].Shared ? PageState.Shared : PageState.Private,
            };

            (page.NearestExport, page.NearestOffset) = m.Image.NearestExport(rva);
            page.FunctionsStarting = m.Image.FunctionsStartingIn(rva, rva + 0x1000);
            page.Exports = m.Image.ExportsIn(rva, rva + 0x1000).Select(e => e.Name).ToList();

            Compare(m, page, mem[i]);
            m.Pages.Add(page);
        }
    }

    private static void Compare(ModuleScan m, PageInfo page, byte[] memory)
    {
        if (m.Disk is null || m.DiskBytes is null || memory.Length == 0) return;

        var expected = new byte[0x1000];
        long off = PeImage.FileOffset(m.Disk.Sections, page.Rva, m.DiskLength);
        if (off >= 0)
        {
            int avail = (int)Math.Min(0x1000, m.DiskLength - off);
            var sec = m.Disk.SectionOf(page.Rva);
            if (sec is not null)
            {
                long rawLeft = (long)sec.RawPtr + sec.RawSize - off;
                avail = (int)Math.Min(avail, Math.Max(0, rawLeft));
            }
            if (avail > 0) Buffer.BlockCopy(m.DiskBytes, (int)off, expected, 0, avail);
        }
        else if (off == -1) return;

        long delta = (long)m.Base - (long)m.Disk.ImageBase;
        foreach (var rel in m.Disk.Relocs)
        {
            if (rel.Rva < page.Rva || rel.Rva >= page.Rva + 0x1000) continue;
            page.HasRelocs = true;
            int at = (int)(rel.Rva - page.Rva);
            if (rel.Type == 10 && at + 8 <= expected.Length)
            {
                ulong v = BitConverter.ToUInt64(expected, at);
                BitConverter.TryWriteBytes(expected.AsSpan(at, 8), (ulong)((long)v + delta));
            }
            else if (rel.Type == 3 && at + 4 <= expected.Length)
            {
                uint v = BitConverter.ToUInt32(expected, at);
                BitConverter.TryWriteBytes(expected.AsSpan(at, 4), (uint)((long)v + delta));
            }
        }

        var diffs = new List<DiffRun>();
        int n = Math.Min(memory.Length, expected.Length);
        int i = 0;
        while (i < n)
        {
            if (memory[i] == expected[i]) { i++; continue; }
            int start = i;
            int quiet = 0;
            int endRun = i;
            while (i < n && quiet < 4)
            {
                if (memory[i] != expected[i]) { quiet = 0; endRun = i + 1; }
                else quiet++;
                i++;
            }
            int len = Math.Min(endRun - start, 32);
            uint rva = page.Rva + (uint)start;
            diffs.Add(new DiffRun
            {
                Rva = rva,
                Memory = memory.AsSpan(start, len).ToArray(),
                Disk = expected.AsSpan(start, len).ToArray(),
                Function = Describe(m.Image, rva),
            });
            if (diffs.Count >= 64) break;
        }

        page.Diffs = diffs;
        page.MatchesDisk = diffs.Count == 0;
    }

    public static string Describe(PeImage img, uint rva)
    {
        var f = img.FunctionAt(rva);
        if (f is not null)
        {
            var e = img.ExportOf(rva);
            if (e is not null) return $"{e.Value.Name}+0x{rva - e.Value.Rva:X}";
            var (name, off) = img.NearestExport(rva);
            return name.Length > 0
                ? $"неэкспортируемая функция 0x{f.Value.Begin:X} ({name}+0x{off:X})"
                : $"неэкспортируемая функция 0x{f.Value.Begin:X}";
        }
        var (n2, o2) = img.NearestExport(rva);
        return n2.Length > 0 ? $"{n2}+0x{o2:X}" : $"RVA 0x{rva:X}";
    }
}

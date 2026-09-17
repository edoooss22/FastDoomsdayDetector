using System.Text;

namespace Doomsday;

internal sealed class Section
{
    public string Name = "";
    public uint Va;
    public uint VSize;
    public uint RawPtr;
    public uint RawSize;
    public uint Characteristics;

    public bool Executable => (Characteristics & 0x20000000) != 0;
    public uint End => Va + Math.Max(VSize, RawSize);
    public bool Contains(uint rva) => rva >= Va && rva < End;
}

internal readonly record struct Export(uint Rva, string Name);
internal readonly record struct Function(uint Begin, uint End);
internal readonly record struct Reloc(uint Rva, int Type);

internal sealed class PeImage
{
    public uint TimeDateStamp;
    public uint SizeOfImage;
    public uint SizeOfHeaders;
    public ulong ImageBase;
    public ushort DllCharacteristics;
    public ushort Machine;
    public List<Section> Sections = new();
    public Export[] Exports = Array.Empty<Export>();
    public Function[] Functions = Array.Empty<Function>();
    public Reloc[] Relocs = Array.Empty<Reloc>();

    public Section? SectionOf(uint rva) => Sections.FirstOrDefault(s => s.Contains(rva));

    public (string Name, uint Offset) NearestExport(uint rva)
    {
        int found = UpperBound(Exports.Length, i => Exports[i].Rva <= rva);
        if (found < 0) return ("", 0);
        return (Exports[found].Name, rva - Exports[found].Rva);
    }

    public Function? FunctionAt(uint rva)
    {
        int found = UpperBound(Functions.Length, i => Functions[i].Begin <= rva);
        if (found < 0) return null;
        var f = Functions[found];
        return rva < f.End ? f : null;
    }

    public Export? ExportOf(uint rva)
    {
        var f = FunctionAt(rva);
        uint begin = f?.Begin ?? rva;
        foreach (var e in Exports) if (e.Rva == begin) return e;
        return null;
    }

    public Export? Export(string name)
    {
        foreach (var e in Exports)
            if (e.Name.Equals(name, StringComparison.Ordinal)) return e;
        return null;
    }

    public uint FunctionEnd(uint begin)
    {
        var f = FunctionAt(begin);
        return f is not null && f.Value.Begin == begin ? f.Value.End : begin + 16;
    }

    public IEnumerable<Export> ExportsIn(uint lo, uint hi) =>
        Exports.Where(e => e.Rva >= lo && e.Rva < hi);

    public int FunctionsStartingIn(uint lo, uint hi) =>
        Functions.Count(f => f.Begin >= lo && f.Begin < hi);

    private static int UpperBound(int n, Func<int, bool> le)
    {
        int lo = 0, hi = n - 1, found = -1;
        while (lo <= hi)
        {
            int mid = (lo + hi) / 2;
            if (le(mid)) { found = mid; lo = mid + 1; }
            else hi = mid - 1;
        }
        return found;
    }

    public static PeImage? FromMemory(IntPtr h, ulong baseAddr) =>
        Parse((rva, len) => Native.Read(h, baseAddr + rva, len));

    public static PeImage? FromFile(byte[] file)
    {
        var sections = HeaderSections(file);
        if (sections is null) return null;

        byte[]? Read(uint rva, int len)
        {
            if (len <= 0) return null;
            long off = FileOffset(sections, rva, file.Length);
            if (off < 0 || off + len > file.Length) return null;
            var res = new byte[len];
            Buffer.BlockCopy(file, (int)off, res, 0, len);
            return res;
        }

        return Parse(Read);
    }

    public static long FileOffset(List<Section> sections, uint rva, long fileLength)
    {
        if (sections.Count == 0 || rva < sections.Min(s => s.Va)) return rva < fileLength ? rva : -1;
        foreach (var s in sections)
        {
            if (rva < s.Va || rva >= s.Va + Math.Max(s.VSize, s.RawSize)) continue;
            uint inside = rva - s.Va;
            if (inside >= s.RawSize) return -2;
            return s.RawPtr + inside;
        }
        return -1;
    }

    private static List<Section>? HeaderSections(byte[] d)
    {
        if (d.Length < 0x200 || d[0] != (byte)'M' || d[1] != (byte)'Z') return null;
        int lfanew = BitConverter.ToInt32(d, 0x3C);
        if (lfanew <= 0 || lfanew + 0x108 > d.Length) return null;
        if (BitConverter.ToUInt32(d, lfanew) != 0x00004550) return null;
        int nsec = BitConverter.ToUInt16(d, lfanew + 6);
        int optSize = BitConverter.ToUInt16(d, lfanew + 20);
        int secTable = lfanew + 24 + optSize;
        if (nsec <= 0 || nsec > 96 || secTable + nsec * 40 > d.Length) return null;
        return ReadSections(d, secTable, nsec);
    }

    private static List<Section> ReadSections(byte[] d, int at, int nsec)
    {
        var list = new List<Section>(nsec);
        for (int i = 0; i < nsec; i++)
        {
            int o = at + i * 40;
            int nameEnd = 0;
            while (nameEnd < 8 && d[o + nameEnd] != 0) nameEnd++;
            list.Add(new Section
            {
                Name = Encoding.ASCII.GetString(d, o, nameEnd),
                VSize = BitConverter.ToUInt32(d, o + 8),
                Va = BitConverter.ToUInt32(d, o + 12),
                RawSize = BitConverter.ToUInt32(d, o + 16),
                RawPtr = BitConverter.ToUInt32(d, o + 20),
                Characteristics = BitConverter.ToUInt32(d, o + 36),
            });
        }
        return list;
    }

    private static PeImage? Parse(Func<uint, int, byte[]?> read)
    {
        var head = read(0, 0x1000);
        if (head is null || head.Length < 0x200) return null;
        if (head[0] != (byte)'M' || head[1] != (byte)'Z') return null;

        int lfanew = BitConverter.ToInt32(head, 0x3C);
        if (lfanew <= 0 || lfanew + 0x108 > head.Length) return null;
        if (BitConverter.ToUInt32(head, lfanew) != 0x00004550) return null;

        int opt = lfanew + 24;
        ushort magic = BitConverter.ToUInt16(head, opt);
        if (magic != 0x20B) return null;

        var img = new PeImage
        {
            Machine = BitConverter.ToUInt16(head, lfanew + 4),
            TimeDateStamp = BitConverter.ToUInt32(head, lfanew + 8),
            ImageBase = BitConverter.ToUInt64(head, opt + 24),
            SizeOfImage = BitConverter.ToUInt32(head, opt + 56),
            SizeOfHeaders = BitConverter.ToUInt32(head, opt + 60),
            DllCharacteristics = BitConverter.ToUInt16(head, opt + 70),
        };

        int nsec = BitConverter.ToUInt16(head, lfanew + 6);
        int optSize = BitConverter.ToUInt16(head, lfanew + 20);
        int secTable = opt + optSize;
        if (nsec <= 0 || nsec > 96 || secTable + nsec * 40 > head.Length) return img;
        img.Sections = ReadSections(head, secTable, nsec);

        (uint Rva, uint Size) Dir(int index) => (
            BitConverter.ToUInt32(head, opt + 112 + index * 8),
            BitConverter.ToUInt32(head, opt + 116 + index * 8));

        ParseExports(img, read, Dir(0));
        ParseFunctions(img, read, Dir(3));
        ParseRelocs(img, read, Dir(5));
        return img;
    }

    private static void ParseExports(PeImage img, Func<uint, int, byte[]?> read, (uint Rva, uint Size) dir)
    {
        if (dir.Rva == 0 || dir.Size < 40 || dir.Size > 8 * 1024 * 1024) return;
        var d = read(dir.Rva, (int)dir.Size);
        if (d is null) return;

        uint numberOfFunctions = BitConverter.ToUInt32(d, 0x14);
        uint numberOfNames = BitConverter.ToUInt32(d, 0x18);
        uint addressOfFunctions = BitConverter.ToUInt32(d, 0x1C);
        uint addressOfNames = BitConverter.ToUInt32(d, 0x20);
        uint addressOfOrdinals = BitConverter.ToUInt32(d, 0x24);
        if (numberOfNames == 0 || numberOfNames > 65535) return;
        if (numberOfFunctions == 0 || numberOfFunctions > 65535) return;

        byte[]? Slice(uint rva, int len)
        {
            if (rva == 0 || len <= 0) return null;
            long inside = (long)rva - dir.Rva;
            if (inside >= 0 && inside + len <= d.Length)
            {
                var res = new byte[len];
                Buffer.BlockCopy(d, (int)inside, res, 0, len);
                return res;
            }
            return read(rva, len);
        }

        var names = Slice(addressOfNames, (int)numberOfNames * 4);
        var ordinals = Slice(addressOfOrdinals, (int)numberOfNames * 2);
        var functions = Slice(addressOfFunctions, (int)numberOfFunctions * 4);
        if (names is null || ordinals is null || functions is null) return;

        var list = new List<Export>((int)numberOfNames);
        for (int i = 0; i < numberOfNames; i++)
        {
            uint nameRva = BitConverter.ToUInt32(names, i * 4);
            int ord = BitConverter.ToUInt16(ordinals, i * 2);
            if (ord * 4 + 4 > functions.Length) continue;
            uint funcRva = BitConverter.ToUInt32(functions, ord * 4);
            if (funcRva == 0) continue;
            if (funcRva >= dir.Rva && funcRva < dir.Rva + dir.Size) continue;

            string name = ReadString(read, d, dir.Rva, nameRva);
            if (name.Length == 0) continue;
            list.Add(new Export(funcRva, name));
        }

        list.Sort((a, b) => a.Rva.CompareTo(b.Rva));
        img.Exports = list.ToArray();
    }

    private static string ReadString(Func<uint, int, byte[]?> read, byte[] dir, uint dirRva, uint rva)
    {
        if (rva == 0) return "";
        long inside = (long)rva - dirRva;
        if (inside >= 0 && inside < dir.Length)
        {
            int end = (int)inside;
            while (end < dir.Length && dir[end] != 0) end++;
            return Encoding.ASCII.GetString(dir, (int)inside, end - (int)inside);
        }
        var buf = read(rva, 256);
        if (buf is null) return "";
        int n = Array.IndexOf(buf, (byte)0);
        return Encoding.ASCII.GetString(buf, 0, n < 0 ? buf.Length : n);
    }

    private static void ParseFunctions(PeImage img, Func<uint, int, byte[]?> read, (uint Rva, uint Size) dir)
    {
        if (dir.Rva == 0 || dir.Size < 12 || dir.Size > 16 * 1024 * 1024) return;
        var d = read(dir.Rva, (int)(dir.Size / 12 * 12));
        if (d is null) return;

        var list = new List<Function>(d.Length / 12);
        for (int o = 0; o + 12 <= d.Length; o += 12)
        {
            uint begin = BitConverter.ToUInt32(d, o);
            uint end = BitConverter.ToUInt32(d, o + 4);
            if (begin == 0 || end <= begin) continue;
            list.Add(new Function(begin, end));
        }
        list.Sort((a, b) => a.Begin.CompareTo(b.Begin));
        img.Functions = list.ToArray();
    }

    private static void ParseRelocs(PeImage img, Func<uint, int, byte[]?> read, (uint Rva, uint Size) dir)
    {
        if (dir.Rva == 0 || dir.Size < 8 || dir.Size > 16 * 1024 * 1024) return;
        var d = read(dir.Rva, (int)dir.Size);
        if (d is null) return;

        var list = new List<Reloc>();
        int o = 0;
        while (o + 8 <= d.Length)
        {
            uint pageRva = BitConverter.ToUInt32(d, o);
            int blockSize = (int)BitConverter.ToUInt32(d, o + 4);
            if (blockSize < 8 || o + blockSize > d.Length) break;
            for (int k = o + 8; k + 2 <= o + blockSize; k += 2)
            {
                ushort e = BitConverter.ToUInt16(d, k);
                int type = e >> 12;
                if (type == 0) continue;
                list.Add(new Reloc(pageRva + (uint)(e & 0xFFF), type));
            }
            o += blockSize;
        }
        img.Relocs = list.ToArray();
    }
}

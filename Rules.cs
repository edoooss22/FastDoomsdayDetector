namespace Doomsday;

internal sealed record Verdict(string Result, string Rule, List<string> Marks)
{
    public bool Detected => Result == "DETECTED";
}

internal static class Rules
{
    public const string Module = "glfw.dll";

    private sealed record Anchor(string Export, uint[] LegacyRvas);

    private static readonly Anchor[] Anchors =
    {
        new("glfwGetKey", new uint[] { 0x3000 }),
        new("glfwGetKeyScancode", new uint[] { 0x4000 }),
        new("glfwGetMouseButton", new uint[] { 0x4000 }),
        new("glfwGetCursorPos", new uint[] { 0x3000 }),
        new("glfwSetCursorPos", new uint[] { 0x4000 }),
        new("glfwGetInputMode", new uint[] { 0x3000 }),
        new("glfwSetInputMode", new uint[] { 0x4000 }),
        new("glfwRawMouseMotionSupported", new uint[] { 0x4000 }),
        new("glfwSetKeyCallback", new uint[] { 0x4000 }),
        new("glfwSetCharCallback", new uint[] { 0x4000 }),
        new("glfwSetCharModsCallback", new uint[] { 0x4000 }),
        new("glfwSetMouseButtonCallback", new uint[] { 0x4000 }),
        new("glfwSetCursorPosCallback", new uint[] { 0x4000 }),
        new("glfwSetCursorEnterCallback", new uint[] { 0x4000 }),
        new("glfwSetScrollCallback", new uint[] { 0x4000 }),
    };

    public static IEnumerable<string> AnchorNames => Anchors.Select(a => a.Export);

    public static Verdict Evaluate(ModuleScan m)
    {
        var marks = new List<string>();
        foreach (var page in m.Pages.Where(p => p.Executable && p.State == PageState.Private))
        {
            foreach (var a in Anchors)
            {
                string? hit = Match(m, page, a);
                if (hit is not null) marks.Add(hit);
            }
        }

        return marks.Count == 0
            ? new Verdict("UNDETECTED", "", marks)
            : new Verdict("DETECTED", "doomsday", marks);
    }

    public static List<string> AnchorsOn(ModuleScan m, PageInfo page) =>
        Anchors.Where(a => Match(m, page, a) is not null).Select(a => a.Export).ToList();

    private static string? Match(ModuleScan m, PageInfo page, Anchor a)
    {
        uint lo = page.Rva, hi = page.Rva + 0x1000;
        string state = page.MatchesDisk switch
        {
            true => "байты возвращены",
            false => "байты изменены",
            null => "диск не сверен",
        };

        var e = m.Image.Export(a.Export);
        if (e is not null)
        {
            return e.Value.Rva >= lo && e.Value.Rva < hi
                ? $"{a.Export} @0x{e.Value.Rva:X} в приватной странице 0x{lo:X} ({state})"
                : null;
        }

        if (m.Image.Exports.Length > 0) return null;
        foreach (uint legacy in a.LegacyRvas)
            if (legacy >= lo && legacy < hi)
                return $"{a.Export}: приватная страница 0x{lo:X} (по адресу, {state})";
        return null;
    }

    public static string Hex(byte[] b) => string.Join(" ", b.Take(12).Select(x => x.ToString("X2")))
                                          + (b.Length > 12 ? " …" : "");
}

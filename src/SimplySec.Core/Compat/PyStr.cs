using System.Text;
using System.Text.RegularExpressions;

namespace SimplySec.Core.Compat;

/// <summary>Python string semantics the port relies on.</summary>
public static class PyStr
{
    public static string Strip(string? s) => (s ?? "").Trim();

    public static string Strip(string? s, char c) => (s ?? "").Trim(c);

    public static string Lower(string? s) => (s ?? "").ToLowerInvariant();

    public static string Upper(string? s) => (s ?? "").ToUpperInvariant();

    /// <summary><c>str.title()</c>: first cased letter after a non-cased character upper, the rest lower.</summary>
    public static string Title(string s)
    {
        var sb = new StringBuilder(s.Length);
        var prevCased = false;
        foreach (var ch in s)
        {
            var cased = char.IsUpper(ch) || char.IsLower(ch) || char.GetUnicodeCategory(ch) == System.Globalization.UnicodeCategory.TitlecaseLetter;
            if (cased)
            {
                sb.Append(prevCased ? char.ToLowerInvariant(ch) : char.ToUpperInvariant(ch));
                prevCased = true;
            }
            else
            {
                sb.Append(ch);
                prevCased = false;
            }
        }
        return sb.ToString();
    }

    /// <summary><c>fnmatch.fnmatchcase(name, pattern)</c>.</summary>
    public static bool FnMatchCase(string name, string pattern) =>
        Regex.IsMatch(name, FnTranslate(pattern), RegexOptions.Singleline | RegexOptions.CultureInvariant);

    private static string FnTranslate(string pat)
    {
        var res = new StringBuilder("^(?:");
        int i = 0, n = pat.Length;
        while (i < n)
        {
            var c = pat[i++];
            if (c == '*')
            {
                while (i < n && pat[i] == '*')
                {
                    i++;
                }
                res.Append(".*");
            }
            else if (c == '?')
            {
                res.Append('.');
            }
            else if (c == '[')
            {
                var j = i;
                if (j < n && pat[j] == '!')
                {
                    j++;
                }
                if (j < n && pat[j] == ']')
                {
                    j++;
                }
                while (j < n && pat[j] != ']')
                {
                    j++;
                }
                if (j >= n)
                {
                    res.Append("\\[");
                }
                else
                {
                    var stuff = pat[i..j].Replace("\\", "\\\\", StringComparison.Ordinal);
                    i = j + 1;
                    if (stuff.Length == 0)
                    {
                        res.Append("(?!)");
                        continue;
                    }
                    if (stuff == "!")
                    {
                        res.Append('.');
                        continue;
                    }
                    if (stuff[0] == '!')
                    {
                        stuff = "^" + stuff[1..];
                    }
                    else if (stuff[0] is '^' or '[')
                    {
                        stuff = "\\" + stuff;
                    }
                    res.Append('[').Append(stuff).Append(']');
                }
            }
            else
            {
                res.Append(Regex.Escape(c.ToString()));
            }
        }
        res.Append(")$");
        return res.ToString();
    }
}

/// <summary>Python's <c>ntpath</c> functions (3.11).</summary>
public static class NtPath
{
    public static (string Drive, string Tail) SplitDrive(string p)
    {
        if (p.Length >= 2)
        {
            var normp = p.Replace('/', '\\');
            if (normp.StartsWith("\\\\", StringComparison.Ordinal))
            {
                var start = normp.Length >= 8 && normp[..8].ToUpperInvariant() == "\\\\?\\UNC\\" ? 8 : 2;
                var index = normp.IndexOf('\\', start);
                if (index == -1)
                {
                    return ("", p);
                }
                var index2 = normp.IndexOf('\\', index + 1);
                if (index2 == -1)
                {
                    index2 = p.Length;
                }
                return (p[..index2], p[index2..]);
            }
            if (normp[1] == ':')
            {
                return (p[..2], p[2..]);
            }
        }
        return ("", p);
    }

    public static string NormPath(string path)
    {
        if (path.StartsWith("\\\\.\\", StringComparison.Ordinal) || path.StartsWith("\\\\?\\", StringComparison.Ordinal))
        {
            return path;
        }
        path = path.Replace('/', '\\');
        var (prefix, rest) = SplitDrive(path);
        if (rest.StartsWith('\\'))
        {
            prefix += "\\";
            rest = rest.TrimStart('\\');
        }
        var comps = rest.Split('\\').ToList();
        var i = 0;
        while (i < comps.Count)
        {
            if (comps[i].Length == 0 || comps[i] == ".")
            {
                comps.RemoveAt(i);
            }
            else if (comps[i] == "..")
            {
                if (i > 0 && comps[i - 1] != "..")
                {
                    comps.RemoveRange(i - 1, 2);
                    i -= 1;
                }
                else if (i == 0 && prefix.EndsWith('\\'))
                {
                    comps.RemoveAt(i);
                }
                else
                {
                    i += 1;
                }
            }
            else
            {
                i += 1;
            }
        }
        if (prefix.Length == 0 && comps.Count == 0)
        {
            comps.Add(".");
        }
        return prefix + string.Join('\\', comps);
    }

    public static string Basename(string p)
    {
        var (_, rest) = SplitDrive(p);
        var i = rest.Length;
        while (i > 0 && rest[i - 1] is not ('\\' or '/'))
        {
            i--;
        }
        return rest[i..];
    }

    public static string Dirname(string p)
    {
        var (d, rest) = SplitDrive(p);
        var i = rest.Length;
        while (i > 0 && rest[i - 1] is not ('\\' or '/'))
        {
            i--;
        }
        var head = rest[..i];
        var stripped = head.TrimEnd('\\', '/');
        return d + (stripped.Length > 0 ? stripped : head);
    }
}

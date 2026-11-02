using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace SimplySec.Windows.Interop;

/// <summary>
/// Authenticode status of a file, embedded or catalog-signed, with the signer's subject, using
/// WinVerifyTrust the way Get-AuthenticodeSignature does (no revocation checks, no UI).
/// </summary>
internal static partial class WinTrust
{
    private static readonly Guid GenericVerifyV2 = new("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");
    private static readonly Guid DriverActionVerify = new("F750E6C3-38EE-11d1-85E5-00C04FC295EE");

    private const uint WtdUiNone = 2;
    private const uint WtdRevokeNone = 0;
    private const uint WtdChoiceFile = 1;
    private const uint WtdChoiceCatalog = 2;
    private const uint WtdStateActionVerify = 1;
    private const uint WtdStateActionClose = 2;
    private const uint WtdCacheOnlyUrlRetrieval = 0x1000;

    [StructLayout(LayoutKind.Sequential)]
    private struct WintrustFileInfo
    {
        public uint cbStruct;
        public IntPtr pcwszFilePath;
        public IntPtr hFile;
        public IntPtr pgKnownSubject;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WintrustCatalogInfo
    {
        public uint cbStruct;
        public uint dwCatalogVersion;
        public IntPtr pcwszCatalogFilePath;
        public IntPtr pcwszMemberTag;
        public IntPtr pcwszMemberFilePath;
        public IntPtr hMemberFile;
        public IntPtr pbCalculatedFileHash;
        public uint cbCalculatedFileHash;
        public IntPtr pcCatalogContext;
        public IntPtr hCatAdmin;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WintrustData
    {
        public uint cbStruct;
        public IntPtr pPolicyCallbackData;
        public IntPtr pSIPClientData;
        public uint dwUIChoice;
        public uint fdwRevocationChecks;
        public uint dwUnionChoice;
        public IntPtr pInfo;
        public uint dwStateAction;
        public IntPtr hWVTStateData;
        public IntPtr pwszURLReference;
        public uint dwProvFlags;
        public uint dwUIContext;
        public IntPtr pSignatureSettings;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct CatalogInfo
    {
        public uint cbStruct;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
        public string wszCatalogFile;
    }

    [DllImport("wintrust.dll", ExactSpelling = true)]
    private static extern int WinVerifyTrust(IntPtr hwnd, ref Guid action, ref WintrustData data);

    [DllImport("wintrust.dll", ExactSpelling = true)]
    private static extern IntPtr WTHelperProvDataFromStateData(IntPtr hStateData);

    [DllImport("wintrust.dll", ExactSpelling = true)]
    private static extern IntPtr WTHelperGetProvSignerFromChain(IntPtr provData, uint idxSigner, [MarshalAs(UnmanagedType.Bool)] bool counterSigner, uint idxCounterSigner);

    [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptCATAdminAcquireContext2(out IntPtr hCatAdmin, ref Guid subsystem, [MarshalAs(UnmanagedType.LPWStr)] string hashAlgorithm, IntPtr strongHashPolicy, uint flags);

    [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptCATAdminReleaseContext(IntPtr hCatAdmin, uint flags);

    [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptCATAdminCalcHashFromFileHandle2(IntPtr hCatAdmin, SafeFileHandle hFile, ref uint cbHash, [Out] byte[]? hash, uint flags);

    [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = true)]
    private static extern IntPtr CryptCATAdminEnumCatalogFromHash(IntPtr hCatAdmin, byte[] hash, uint cbHash, uint flags, IntPtr prevCatInfo);

    [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptCATCatalogInfoFromContext(IntPtr hCatInfo, ref CatalogInfo info, uint flags);

    [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptCATAdminReleaseCatalogContext(IntPtr hCatAdmin, IntPtr hCatInfo, uint flags);

    [DllImport("crypt32.dll", ExactSpelling = true, CharSet = CharSet.Unicode)]
    private static extern uint CertNameToStrW(uint encodingType, IntPtr pName, uint strType, StringBuilder? psz, uint csz);

    private const uint X509Asn = 1;
    private const uint PkcsAsn = 0x10000;
    private const uint CertX500NameStr = 3;
    private const uint CertNameStrReverseFlag = 0x02000000;

    public readonly record struct Result(string Status, string Signer);

    /// <summary>Status names as Get-AuthenticodeSignature reports them.</summary>
    private static string StatusFor(int hr) => unchecked((uint)hr) switch
    {
        0 => "Valid",
        0x800B0100 => "NotSigned", // TRUST_E_NOSIGNATURE
        0x800B0003 => "UnknownError", // TRUST_E_SUBJECT_FORM_UNKNOWN (what PowerShell reports)
        0x80096010 => "HashMismatch", // TRUST_E_BAD_DIGEST
        0x80092003 => "NotSigned", // CRYPT_E_FILE_ERROR
        0x800B0109 or 0x800B010A or 0x800B0111 or 0x800B010C or 0x800B0101 or 0x800B0110 or 0x800B0004 => "NotTrusted",
        _ => "UnknownError",
    };

    public static Result Verify(string path)
    {
        if (!File.Exists(path))
        {
            return new Result("Unreadable", "");
        }
        var embedded = VerifyEmbedded(path);
        if (embedded.Status != "NotSigned")
        {
            return embedded;
        }
        var catalog = VerifyCatalog(path);
        return catalog ?? embedded;
    }

    private static Result VerifyEmbedded(string path)
    {
        var pathPtr = Marshal.StringToHGlobalUni(path);
        var fileInfo = new WintrustFileInfo { cbStruct = (uint)Marshal.SizeOf<WintrustFileInfo>(), pcwszFilePath = pathPtr };
        var infoPtr = Marshal.AllocHGlobal(Marshal.SizeOf<WintrustFileInfo>());
        try
        {
            Marshal.StructureToPtr(fileInfo, infoPtr, false);
            var data = NewData(WtdChoiceFile, infoPtr);
            return Run(ref data);
        }
        finally
        {
            Marshal.FreeHGlobal(infoPtr);
            Marshal.FreeHGlobal(pathPtr);
        }
    }

    private static Result? VerifyCatalog(string path)
    {
        var subsystem = DriverActionVerify;
        foreach (var algorithm in new[] { "SHA256", "SHA1" })
        {
            if (!CryptCATAdminAcquireContext2(out var admin, ref subsystem, algorithm, IntPtr.Zero, 0))
            {
                continue;
            }
            try
            {
                using var fh = File.OpenHandle(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                uint cb = 0;
                CryptCATAdminCalcHashFromFileHandle2(admin, fh, ref cb, null, 0);
                if (cb == 0)
                {
                    continue;
                }
                var hash = new byte[cb];
                if (!CryptCATAdminCalcHashFromFileHandle2(admin, fh, ref cb, hash, 0))
                {
                    continue;
                }
                var catInfo = CryptCATAdminEnumCatalogFromHash(admin, hash, cb, 0, IntPtr.Zero);
                if (catInfo == IntPtr.Zero)
                {
                    continue;
                }
                try
                {
                    var ci = new CatalogInfo { cbStruct = (uint)Marshal.SizeOf<CatalogInfo>() };
                    if (!CryptCATCatalogInfoFromContext(catInfo, ref ci, 0))
                    {
                        continue;
                    }
                    var tag = Convert.ToHexString(hash);
                    var catPath = Marshal.StringToHGlobalUni(ci.wszCatalogFile);
                    var tagPtr = Marshal.StringToHGlobalUni(tag);
                    var memberPath = Marshal.StringToHGlobalUni(path);
                    var hashPtr = Marshal.AllocHGlobal(hash.Length);
                    Marshal.Copy(hash, 0, hashPtr, hash.Length);
                    var cat = new WintrustCatalogInfo
                    {
                        cbStruct = (uint)Marshal.SizeOf<WintrustCatalogInfo>(),
                        pcwszCatalogFilePath = catPath,
                        pcwszMemberTag = tagPtr,
                        pcwszMemberFilePath = memberPath,
                        pbCalculatedFileHash = hashPtr,
                        cbCalculatedFileHash = cb,
                        hCatAdmin = admin,
                    };
                    var infoPtr = Marshal.AllocHGlobal(Marshal.SizeOf<WintrustCatalogInfo>());
                    try
                    {
                        Marshal.StructureToPtr(cat, infoPtr, false);
                        var data = NewData(WtdChoiceCatalog, infoPtr);
                        return Run(ref data);
                    }
                    finally
                    {
                        Marshal.FreeHGlobal(infoPtr);
                        Marshal.FreeHGlobal(hashPtr);
                        Marshal.FreeHGlobal(memberPath);
                        Marshal.FreeHGlobal(tagPtr);
                        Marshal.FreeHGlobal(catPath);
                    }
                }
                finally
                {
                    CryptCATAdminReleaseCatalogContext(admin, catInfo, 0);
                }
            }
            catch (IOException)
            {
                return null;
            }
            catch (UnauthorizedAccessException)
            {
                return null;
            }
            finally
            {
                CryptCATAdminReleaseContext(admin, 0);
            }
        }
        return null;
    }

    private static WintrustData NewData(uint choice, IntPtr info) => new()
    {
        cbStruct = (uint)Marshal.SizeOf<WintrustData>(),
        dwUIChoice = WtdUiNone,
        fdwRevocationChecks = WtdRevokeNone,
        dwUnionChoice = choice,
        pInfo = info,
        dwStateAction = WtdStateActionVerify,
        dwProvFlags = WtdCacheOnlyUrlRetrieval,
    };

    private static Result Run(ref WintrustData data)
    {
        var action = GenericVerifyV2;
        var hr = WinVerifyTrust(new IntPtr(-1), ref action, ref data);
        var signer = "";
        try
        {
            signer = SignerSubject(data.hWVTStateData);
        }
        finally
        {
            data.dwStateAction = WtdStateActionClose;
            WinVerifyTrust(new IntPtr(-1), ref action, ref data);
        }
        return new Result(StatusFor(hr), signer);
    }

    /// <summary>The signer certificate's subject, formatted like .NET's X500DistinguishedName.</summary>
    private static string SignerSubject(IntPtr state)
    {
        if (state == IntPtr.Zero)
        {
            return "";
        }
        var prov = WTHelperProvDataFromStateData(state);
        if (prov == IntPtr.Zero)
        {
            return "";
        }
        var sgnr = WTHelperGetProvSignerFromChain(prov, 0, false, 0);
        if (sgnr == IntPtr.Zero)
        {
            return "";
        }
        // CRYPT_PROVIDER_SGNR: cbStruct(4) + sftVerifyAsOf(8) + csCertChain(4) + pasCertChain(ptr)
        var csCertChain = Marshal.ReadInt32(sgnr, 12);
        if (csCertChain <= 0)
        {
            return "";
        }
        var chain = Marshal.ReadIntPtr(sgnr, 16);
        // CRYPT_PROVIDER_CERT: cbStruct(4) + pad + pCert(ptr)
        var pCert = Marshal.ReadIntPtr(chain, IntPtr.Size);
        if (pCert == IntPtr.Zero)
        {
            return "";
        }
        // CERT_CONTEXT: dwCertEncodingType(4)+pad, pbCertEncoded, cbCertEncoded(4)+pad, pCertInfo
        var pCertInfo = Marshal.ReadIntPtr(pCert, IntPtr.Size * 3);
        // CERT_INFO: dwVersion(4)+pad, SerialNumber(CRYPT_INTEGER_BLOB 16), SignatureAlgorithm(CRYPT_ALGORITHM_IDENTIFIER 24),
        // Issuer(CERT_NAME_BLOB 16), NotBefore(8), NotAfter(8), Subject(CERT_NAME_BLOB)
        var subjectBlob = pCertInfo + 8 + 16 + 24 + 16 + 8 + 8;
        var size = CertNameToStrW(X509Asn | PkcsAsn, subjectBlob, CertX500NameStr | CertNameStrReverseFlag, null, 0);
        if (size <= 1)
        {
            return "";
        }
        var sb = new StringBuilder((int)size);
        CertNameToStrW(X509Asn | PkcsAsn, subjectBlob, CertX500NameStr | CertNameStrReverseFlag, sb, size);
        return sb.ToString();
    }
}

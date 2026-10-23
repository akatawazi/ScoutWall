using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;

namespace ScoutWall.Sensor.Analyst;

/// <summary>
/// Who signed a program, as Windows itself verifies it: the signature embedded in the file, or for Windows' own
/// files (msiexec.exe, svchost.exe and nearly everything else in System32) the system catalog that lists the file's
/// hash. Revocation isn't checked and nothing is fetched from the network, so a verdict costs a few milliseconds.
/// </summary>
public static class CodeSignature
{
    public record Signature(string Signer, bool IsCatalog);

    /// <summary>
    /// The verified signer, or null when the file isn't signed, the signature doesn't match the file, or the chain
    /// doesn't lead to a root Windows trusts.
    /// </summary>
    public static Signature? Verify(string path)
    {
        if (!OperatingSystem.IsWindows())
            return null;

        try
        {
            var embedded = VerifyEmbedded(path);
            return embedded ?? VerifyCatalog(path);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or DllNotFoundException or EntryPointNotFoundException)
        {
            return null;
        }
    }

    private static Signature? VerifyEmbedded(string path)
    {
        var fileInfo = new WINTRUST_FILE_INFO { cbStruct = Marshal.SizeOf<WINTRUST_FILE_INFO>(), pcwszFilePath = path };
        var fileInfoPointer = Marshal.AllocHGlobal(fileInfo.cbStruct);
        try
        {
            Marshal.StructureToPtr(fileInfo, fileInfoPointer, false);
            var signer = RunWinVerifyTrust(WTD_CHOICE_FILE, fileInfoPointer);
            return signer == null ? null : new Signature(signer, false);
        }
        finally
        {
            Marshal.FreeHGlobal(fileInfoPointer);
        }
    }

    private static Signature? VerifyCatalog(string path)
    {
        // Current catalogs list SHA-256 hashes; older ones only SHA-1.
        foreach (var algorithm in new[] { "SHA256", null })
        {
            var signer = VerifyCatalog(path, algorithm);
            if (signer != null)
                return new Signature(signer, true);
        }

        return null;
    }

    private static string? VerifyCatalog(string path, string? algorithm)
    {
        if (!CryptCATAdminAcquireContext2(out var catalogAdmin, IntPtr.Zero, algorithm, IntPtr.Zero, 0))
            return null;

        var catalogContext = IntPtr.Zero;
        try
        {
            byte[] hash;
            using (var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
            {
                var handle = stream.SafeFileHandle.DangerousGetHandle();
                var hashSize = 0;
                CryptCATAdminCalcHashFromFileHandle2(catalogAdmin, handle, ref hashSize, null, 0);
                if (hashSize == 0)
                    return null;

                hash = new byte[hashSize];
                if (!CryptCATAdminCalcHashFromFileHandle2(catalogAdmin, handle, ref hashSize, hash, 0))
                    return null;
            }

            var previous = IntPtr.Zero;
            catalogContext = CryptCATAdminEnumCatalogFromHash(catalogAdmin, hash, hash.Length, 0, ref previous);
            if (catalogContext == IntPtr.Zero)
                return null;

            var catalogInfo = new CATALOG_INFO { cbStruct = Marshal.SizeOf<CATALOG_INFO>() };
            if (!CryptCATCatalogInfoFromContext(catalogContext, ref catalogInfo, 0))
                return null;

            var memberTag = Convert.ToHexString(hash);
            var info = new WINTRUST_CATALOG_INFO
            {
                cbStruct = Marshal.SizeOf<WINTRUST_CATALOG_INFO>(),
                pcwszCatalogFilePath = catalogInfo.wszCatalogFile,
                pcwszMemberTag = memberTag,
                pcwszMemberFilePath = path,
                hCatAdmin = catalogAdmin
            };

            var hashPointer = Marshal.AllocHGlobal(hash.Length);
            var infoPointer = Marshal.AllocHGlobal(info.cbStruct);
            try
            {
                Marshal.Copy(hash, 0, hashPointer, hash.Length);
                info.pbCalculatedFileHash = hashPointer;
                info.cbCalculatedFileHash = hash.Length;
                Marshal.StructureToPtr(info, infoPointer, false);
                return RunWinVerifyTrust(WTD_CHOICE_CATALOG, infoPointer);
            }
            finally
            {
                Marshal.DestroyStructure<WINTRUST_CATALOG_INFO>(infoPointer);
                Marshal.FreeHGlobal(infoPointer);
                Marshal.FreeHGlobal(hashPointer);
            }
        }
        finally
        {
            if (catalogContext != IntPtr.Zero)
                CryptCATAdminReleaseCatalogContext(catalogAdmin, catalogContext, 0);
            CryptCATAdminReleaseContext(catalogAdmin, 0);
        }
    }

    /// <summary>
    /// Runs the standard Authenticode policy and, when it passes, reads the leaf certificate of the first signer.
    /// </summary>
    private static string? RunWinVerifyTrust(int unionChoice, IntPtr choiceInfo)
    {
        var data = new WINTRUST_DATA
        {
            cbStruct = Marshal.SizeOf<WINTRUST_DATA>(),
            dwUIChoice = WTD_UI_NONE,
            fdwRevocationChecks = WTD_REVOKE_NONE,
            dwUnionChoice = unionChoice,
            pInfo = choiceInfo,
            dwStateAction = WTD_STATEACTION_VERIFY,
            dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL
        };

        var action = GenericVerifyV2;
        var result = WinVerifyTrust((IntPtr)(-1), ref action, ref data);
        try
        {
            return result == 0 ? SignerName(data.hWVTStateData) : null;
        }
        finally
        {
            data.dwStateAction = WTD_STATEACTION_CLOSE;
            WinVerifyTrust((IntPtr)(-1), ref action, ref data);
        }
    }

    private static string? SignerName(IntPtr stateData)
    {
        var providerData = WTHelperProvDataFromStateData(stateData);
        if (providerData == IntPtr.Zero)
            return null;

        var signer = WTHelperGetProvSignerFromChain(providerData, 0, false, 0);
        if (signer == IntPtr.Zero)
            return null;

        // CRYPT_PROVIDER_SGNR: cbStruct, sftVerifyAsOf (FILETIME), csCertChain, then the pointer to the chain (offset
        // 16 on both 32- and 64-bit).
        var chainCount = Marshal.ReadInt32(signer, 12);
        var chain = Marshal.ReadIntPtr(signer, 16);
        if (chainCount == 0 || chain == IntPtr.Zero)
            return null;

        // CRYPT_PROVIDER_CERT: cbStruct, then the certificate context, pointer aligned.
        var certificateContext = Marshal.ReadIntPtr(chain, IntPtr.Size);
        if (certificateContext == IntPtr.Zero)
            return null;

        using var certificate = new X509Certificate2(certificateContext);
        var name = certificate.GetNameInfo(X509NameType.SimpleName, false);
        return string.IsNullOrWhiteSpace(name) ? null : name;
    }

    private const int WTD_UI_NONE = 2;
    private const int WTD_REVOKE_NONE = 0;
    private const int WTD_CHOICE_FILE = 1;
    private const int WTD_CHOICE_CATALOG = 2;
    private const int WTD_STATEACTION_VERIFY = 1;
    private const int WTD_STATEACTION_CLOSE = 2;
    private const int WTD_CACHE_ONLY_URL_RETRIEVAL = 0x1000;
    private static readonly Guid GenericVerifyV2 = new("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WINTRUST_FILE_INFO
    {
        public int cbStruct;
        public string pcwszFilePath;
        public IntPtr hFile;
        public IntPtr pgKnownSubject;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WINTRUST_CATALOG_INFO
    {
        public int cbStruct;
        public int dwCatalogVersion;
        public string pcwszCatalogFilePath;
        public string pcwszMemberTag;
        public string pcwszMemberFilePath;
        public IntPtr hMemberFile;
        public IntPtr pbCalculatedFileHash;
        public int cbCalculatedFileHash;
        public IntPtr pcCatalogContext;
        public IntPtr hCatAdmin;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WINTRUST_DATA
    {
        public int cbStruct;
        public IntPtr pPolicyCallbackData;
        public IntPtr pSIPClientData;
        public int dwUIChoice;
        public int fdwRevocationChecks;
        public int dwUnionChoice;
        public IntPtr pInfo;
        public int dwStateAction;
        public IntPtr hWVTStateData;
        public IntPtr pwszURLReference;
        public int dwProvFlags;
        public int dwUIContext;
        public IntPtr pSignatureSettings;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct CATALOG_INFO
    {
        public int cbStruct;

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
        public string wszCatalogFile;
    }

    [DllImport("wintrust.dll", CharSet = CharSet.Unicode)]
    private static extern int WinVerifyTrust(IntPtr hwnd, ref Guid pgActionID, ref WINTRUST_DATA pWVTData);

    [DllImport("wintrust.dll")]
    private static extern IntPtr WTHelperProvDataFromStateData(IntPtr hStateData);

    [DllImport("wintrust.dll")]
    private static extern IntPtr WTHelperGetProvSignerFromChain(IntPtr pProvData, int idxSigner, bool fCounterSigner, int idxCounterSigner);

    [DllImport("wintrust.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool CryptCATAdminAcquireContext2(out IntPtr phCatAdmin, IntPtr pgSubsystem, string? pwszHashAlgorithm, IntPtr pStrongHashPolicy, int dwFlags);

    [DllImport("wintrust.dll", SetLastError = true)]
    private static extern bool CryptCATAdminCalcHashFromFileHandle2(IntPtr hCatAdmin, IntPtr hFile, ref int pcbHash, byte[]? pbHash, int dwFlags);

    [DllImport("wintrust.dll", SetLastError = true)]
    private static extern IntPtr CryptCATAdminEnumCatalogFromHash(IntPtr hCatAdmin, byte[] pbHash, int cbHash, int dwFlags, ref IntPtr phPrevCatInfo);

    [DllImport("wintrust.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool CryptCATCatalogInfoFromContext(IntPtr hCatInfo, ref CATALOG_INFO psCatInfo, int dwFlags);

    [DllImport("wintrust.dll")]
    private static extern bool CryptCATAdminReleaseCatalogContext(IntPtr hCatAdmin, IntPtr hCatInfo, int dwFlags);

    [DllImport("wintrust.dll")]
    private static extern bool CryptCATAdminReleaseContext(IntPtr hCatAdmin, int dwFlags);
}

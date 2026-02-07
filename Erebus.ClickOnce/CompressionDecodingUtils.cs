using System.Runtime.InteropServices;
using System.Text.RegularExpressions;
using System.Text;

namespace Erebus.ClickOnce
{
    public enum CompressionFormat
    {
        None = 0,
        LZNT1 = 1,
        RLE = 2
    }

    public enum DetectEncodingFormat
    {
        None = 0,
        Base64 = 1,
        ASCII85 = 2,
        ALPHA32 = 3,
        WORDS256 = 4
    }

    public static class CompressionDecodingUtils
    {
        public static byte[] AutoDetectAndDecode(byte[] input)
        {
            CompressionFormat format = DetectCompressionFormat(input);
            return DecodeByFormat(input, format);
        }

        public static byte[] AutoDetectAndDecodeString(string input)
        {
            DetectEncodingFormat format = DetectEncodingFormatString(input);
            return DecodeStringByFormat(input, format);
        }

        public static CompressionFormat DetectCompressionFormat(byte[] data)
        {
            if (data == null || data.Length < 2)
                return CompressionFormat.None;

            if (data.Length >= 4)
            {
                if ((data[0] & 0x80) != 0)
                {
                    DebugLogger.WriteLine("[*] Detected LZNT1 compression");
                    return CompressionFormat.LZNT1;
                }
            }

            if (data.Length >= 3)
            {
                int rleMarkerCount = 0;
                for (int i = 0; i < Math.Min(data.Length - 2, 100); i++)
                {
                    if (data[i] == 0xFF && i + 2 < data.Length)
                    {
                        rleMarkerCount++;
                    }
                }
                if (rleMarkerCount > 0)
                {
                    DebugLogger.WriteLine($"[*] Detected RLE compression ({rleMarkerCount} markers found)");
                    return CompressionFormat.RLE;
                }
            }

            DebugLogger.WriteLine("[*] No compression detected");
            return CompressionFormat.None;
        }

        public static DetectEncodingFormat DetectEncodingFormatString(string data)
        {
            if (string.IsNullOrEmpty(data))
                return DetectEncodingFormat.None;

            if (IsValidBase64(data))
            {
                DebugLogger.WriteLine("[*] Detected Base64 encoding");
                return DetectEncodingFormat.Base64;
            }

            if (IsValidASCII85(data))
            {
                DebugLogger.WriteLine("[*] Detected ASCII85 encoding");
                return DetectEncodingFormat.ASCII85;
            }

            if (IsValidALPHA32(data))
            {
                DebugLogger.WriteLine("[*] Detected ALPHA32 encoding");
                return DetectEncodingFormat.ALPHA32;
            }

            if (IsValidWORDS256(data))
            {
                DebugLogger.WriteLine("[*] Detected WORDS256 encoding");
                return DetectEncodingFormat.WORDS256;
            }

            DebugLogger.WriteLine("[*] No encoding detected");
            return DetectEncodingFormat.None;
        }

        private static bool IsValidBase64(string data)
        {
            try
            {
                string cleaned = Regex.Replace(data, @"\s+", "");
                if (cleaned.Length % 4 != 0) return false;
                if (!Regex.IsMatch(cleaned, @"^[A-Za-z0-9+/]*={0,2}$"))
                    return false;
                
                byte[] buffer = Convert.FromBase64String(cleaned);
                return buffer.Length > 0;
            }
            catch { return false; }
        }

        private static bool IsValidASCII85(string data)
        {
            if (string.IsNullOrEmpty(data)) return false;
            int validCharCount = 0;
            foreach (char c in data)
            {
                if ((c >= 33 && c <= 117) || c == '!' || char.IsWhiteSpace(c))
                    validCharCount++;
            }
            return validCharCount > (data.Length * 0.8);
        }

        private static bool IsValidALPHA32(string data)
        {
            if (string.IsNullOrEmpty(data)) return false;
            const string Alpha32Alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/";
            foreach (char c in data)
            {
                if (!Alpha32Alphabet.Contains(c.ToString()))
                    return false;
            }
            return true;
        }

        private static bool IsValidWORDS256(string data)
        {
            if (string.IsNullOrEmpty(data)) return false;
            string[] words = data.Split(new[] { ' ', '\t', '\n', '\r' }, StringSplitOptions.RemoveEmptyEntries);
            if (words.Length == 0) return false;
            foreach (string word in words)
            {
                if (!int.TryParse(word, out int num) || num < 0 || num > 255)
                    return false;
            }
            return true;
        }

        public static byte[] DecodeByFormat(byte[] input, CompressionFormat format)
        {
            switch (format)
            {
                case CompressionFormat.LZNT1:
                    return DecompressionLZNT(input);
                case CompressionFormat.RLE:
                    return DecompressionRLE(input);
                default:
                    return input;
            }
        }

        public static byte[] DecodeStringByFormat(string input, DetectEncodingFormat format)
        {
            switch (format)
            {
                case DetectEncodingFormat.Base64:
                    return DecodeBase64(input);
                case DetectEncodingFormat.ASCII85:
                    return DecodeASCII85(input);
                case DetectEncodingFormat.ALPHA32:
                    return DecodeALPHA32(input);
                case DetectEncodingFormat.WORDS256:
                    return DecodeWORDS256(input);
                default:
                    return new byte[0];
            }
        }

        public static byte[] DecompressionLZNT(byte[] input)
        {
            try
            {
                byte[] output = new byte[input.Length * 6];
                uint uncompressedSize = 0;

                int status = NtStatusHelper.RtlDecompressBuffer(
                    (ushort)2,
                    output,
                    (uint)output.Length,
                    input,
                    (uint)input.Length,
                    out uncompressedSize
                );

                if (status != 0)
                {
                    DebugLogger.WriteLine($"[-] RtlDecompressBuffer failed with status: 0x{status:X8}");
                    return input;
                }

                Array.Resize(ref output, (int)uncompressedSize);
                return output;
            }
            catch (Exception ex)
            {
                DebugLogger.WriteLine($"[-] LZNT decompression error: {ex.Message}");
                return input;
            }
        }

        public static byte[] DecompressionRLE(byte[] input)
        {
            try
            {
                using (var output = new System.IO.MemoryStream())
                {
                    for (int i = 0; i < input.Length; i++)
                    {
                        if (input[i] == 0xFF && i + 2 < input.Length)
                        {
                            i++;
                            byte count = input[i];
                            i++;
                            byte value = input[i];
                            for (int j = 0; j < count; j++)
                                output.WriteByte(value);
                        }
                        else
                        {
                            output.WriteByte(input[i]);
                        }
                    }
                    return output.ToArray();
                }
            }
            catch (Exception ex)
            {
                DebugLogger.WriteLine($"[-] RLE decompression error: {ex.Message}");
                return input;
            }
        }

        public static byte[] DecodeBase64(string input)
        {
            try
            {
                return Convert.FromBase64String(input);
            }
            catch (Exception ex)
            {
                DebugLogger.WriteLine($"[-] Base64 decode error: {ex.Message}");
                return new byte[0];
            }
        }

        public static byte[] DecodeASCII85(string input)
        {
            try
            {
                using (var output = new System.IO.MemoryStream())
                {
                    for (int i = 0; i < input.Length; i += 5)
                    {
                        if (i + 4 >= input.Length) break;
                        uint value = 0;
                        for (int j = 0; j < 5; j++)
                        {
                            char c = input[i + j];
                            if (c < 33 || c > 117) continue;
                            value = value * 85 + (uint)(c - 33);
                        }
                        output.WriteByte((byte)((value >> 24) & 0xFF));
                        output.WriteByte((byte)((value >> 16) & 0xFF));
                        output.WriteByte((byte)((value >> 8) & 0xFF));
                        output.WriteByte((byte)(value & 0xFF));
                    }
                    return output.ToArray();
                }
            }
            catch (Exception ex)
            {
                DebugLogger.WriteLine($"[-] ASCII85 decode error: {ex.Message}");
                return new byte[0];
            }
        }

        public static byte[] DecodeALPHA32(string input)
        {
            try
            {
                const string Alpha32Alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/";
                using (var output = new System.IO.MemoryStream())
                {
                    foreach (char c in input)
                    {
                        int index = Alpha32Alphabet.IndexOf(c);
                        if (index >= 0) output.WriteByte((byte)index);
                    }
                    return output.ToArray();
                }
            }
            catch (Exception ex)
            {
                DebugLogger.WriteLine($"[-] ALPHA32 decode error: {ex.Message}");
                return new byte[0];
            }
        }

        public static byte[] DecodeWORDS256(string input)
        {
            try
            {
                using (var output = new System.IO.MemoryStream())
                {
                    string[] words = input.Split(new[] { ' ', '\t', '\n', '\r' }, StringSplitOptions.RemoveEmptyEntries);
                    foreach (string word in words)
                    {
                        if (int.TryParse(word, out int wordIndex) && wordIndex >= 0 && wordIndex <= 255)
                        {
                            output.WriteByte((byte)wordIndex);
                        }
                    }
                    return output.ToArray();
                }
            }
            catch (Exception ex)
            {
                DebugLogger.WriteLine($"[-] WORDS256 decode error: {ex.Message}");
                return new byte[0];
            }
        }
    }

    /// <summary>
    /// Native method declarations for NTAPI functions
    /// </summary>
    public static class NtStatusHelper
    {
        [DllImport("ntdll.dll", SetLastError = false)]
        public static extern int RtlDecompressBuffer(
            ushort CompressionFormat,   // FIXED: ushort (0x0002 for LZNT1)
            byte[] uncompressedBuffer,
            uint uncompressedBufferSize,
            byte[] compressedBuffer,
            uint compressedBufferSize,
            out uint finalUncompressedSize
        );
    }
}

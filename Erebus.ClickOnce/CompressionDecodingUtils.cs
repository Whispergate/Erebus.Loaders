using System;
using System.Runtime.InteropServices;

namespace Erebus.ClickOnce
{
    /// <summary>
    /// Encoding/Compression format enumeration
    /// </summary>
    public enum CompressionFormat
    {
        None = 0,
        LZNT1 = 1,
        RLE = 2,
        Base64 = 3,
        ASCII85 = 4,
        ALPHA32 = 5,
        WORDS256 = 6
    }

    /// <summary>
    /// Utility class for decompression and decoding operations with auto-detection
    /// </summary>
    public static class CompressionDecodingUtils
    {
        /// <summary>
        /// Auto-detects the compression/encoding format and decompresses/decodes accordingly
        /// </summary>
        public static byte[] AutoDetectAndDecode(byte[] input)
        {
            CompressionFormat format = DetectCompressionFormat(input);
            return DecodeByFormat(input, format);
        }

        /// <summary>
        /// Auto-detects the compression/encoding format and decompresses/decodes accordingly for string input
        /// </summary>
        public static byte[] AutoDetectAndDecodeString(string input)
        {
            CompressionFormat format = DetectEncodingFormatString(input);
            return DecodeStringByFormat(input, format);
        }

        /// <summary>
        /// Detects the compression format from binary data
        /// </summary>
        public static CompressionFormat DetectCompressionFormat(byte[] data)
        {
            if (data == null || data.Length < 2)
                return CompressionFormat.None;

            // Check for LZNT1 signature
            if (data.Length >= 4)
            {
                // LZNT1 compressed blocks start with specific headers
                if ((data[0] & 0x80) != 0)
                {
                    DebugLogger.WriteLine("[*] Detected LZNT1 compression");
                    return CompressionFormat.LZNT1;
                }
            }

            // Check for RLE (Run-Length Encoding) - look for 0xFF markers
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

        /// <summary>
        /// Detects the encoding format from string data
        /// </summary>
        public static CompressionFormat DetectEncodingFormatString(string data)
        {
            if (string.IsNullOrEmpty(data))
                return CompressionFormat.None;

            // Check for Base64 (contains A-Z, a-z, 0-9, +, /, and possibly = padding)
            if (IsValidBase64(data))
            {
                DebugLogger.WriteLine("[*] Detected Base64 encoding");
                return CompressionFormat.Base64;
            }

            // Check for ASCII85 (contains characters 33-117 and ! for runs)
            if (IsValidASCII85(data))
            {
                DebugLogger.WriteLine("[*] Detected ASCII85 encoding");
                return CompressionFormat.ASCII85;
            }

            // Check for ALPHA32 (only a-z, A-Z, 0-9, +, /)
            if (IsValidALPHA32(data))
            {
                DebugLogger.WriteLine("[*] Detected ALPHA32 encoding");
                return CompressionFormat.ALPHA32;
            }

            // Check for WORDS256 (space-separated numbers 0-255)
            if (IsValidWORDS256(data))
            {
                DebugLogger.WriteLine("[*] Detected WORDS256 encoding");
                return CompressionFormat.WORDS256;
            }

            DebugLogger.WriteLine("[*] No encoding detected");
            return CompressionFormat.None;
        }

        /// <summary>
        /// Validates if string is valid Base64
        /// </summary>
        private static bool IsValidBase64(string data)
        {
            try
            {
                // Remove whitespace
                string cleaned = System.Text.RegularExpressions.Regex.Replace(data, @"\s+", "");
                
                // Check if it only contains valid Base64 characters
                if (!System.Text.RegularExpressions.Regex.IsMatch(cleaned, @"^[A-Za-z0-9+/]*={0,2}$"))
                    return false;

                // Try to decode it
                byte[] buffer = Convert.FromBase64String(cleaned);
                return buffer.Length > 0;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Validates if string is valid ASCII85
        /// </summary>
        private static bool IsValidASCII85(string data)
        {
            if (string.IsNullOrEmpty(data))
                return false;

            // ASCII85 uses characters 33-117 (! to u)
            int validCharCount = 0;
            foreach (char c in data)
            {
                if ((c >= 33 && c <= 117) || c == '!' || char.IsWhiteSpace(c))
                    validCharCount++;
            }

            // If more than 80% valid characters, likely ASCII85
            return validCharCount > (data.Length * 0.8);
        }

        /// <summary>
        /// Validates if string is valid ALPHA32
        /// </summary>
        private static bool IsValidALPHA32(string data)
        {
            if (string.IsNullOrEmpty(data))
                return false;

            const string Alpha32Alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/";
            
            foreach (char c in data)
            {
                if (!Alpha32Alphabet.Contains(c.ToString()))
                    return false;
            }
            return true;
        }

        /// <summary>
        /// Validates if string is valid WORDS256
        /// </summary>
        private static bool IsValidWORDS256(string data)
        {
            if (string.IsNullOrEmpty(data))
                return false;

            string[] words = data.Split(new[] { ' ', '\t', '\n', '\r' }, StringSplitOptions.RemoveEmptyEntries);
            
            if (words.Length == 0)
                return false;

            // Check if all words are numbers 0-255
            foreach (string word in words)
            {
                if (!int.TryParse(word, out int num) || num < 0 || num > 255)
                    return false;
            }
            return true;
        }

        /// <summary>
        /// Decodes binary data based on detected format
        /// </summary>
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

        /// <summary>
        /// Decodes string data based on detected format
        /// </summary>
        public static byte[] DecodeStringByFormat(string input, CompressionFormat format)
        {
            switch (format)
            {
                case CompressionFormat.Base64:
                    return DecodeBase64(input);
                case CompressionFormat.ASCII85:
                    return DecodeASCII85(input);
                case CompressionFormat.ALPHA32:
                    return DecodeALPHA32(input);
                case CompressionFormat.WORDS256:
                    return DecodeWORDS256(input);
                default:
                    return new byte[0];
            }
        }

        /// <summary>
        /// Decompresses data using LZNT1 (Windows compression)
        /// </summary>
        public static byte[] DecompressionLZNT(byte[] input)
        {
            try
            {
                byte[] output = new byte[input.Length * 2];
                uint uncompressedSize = 0;

                // Use RtlDecompressBuffer through P/Invoke
                int status = NtStatusHelper.RtlDecompressBuffer(
                    1, // COMPRESSION_FORMAT_LZNT1
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

        /// <summary>
        /// Decompresses data using RLE (Run-Length Encoding)
        /// </summary>
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

        /// <summary>
        /// Decodes Base64 encoded data
        /// </summary>
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

        /// <summary>
        /// Decodes ASCII85 (Base85) encoded data
        /// </summary>
        public static byte[] DecodeASCII85(string input)
        {
            try
            {
                using (var output = new System.IO.MemoryStream())
                {
                    for (int i = 0; i < input.Length; i += 5)
                    {
                        if (i + 4 >= input.Length)
                            break;

                        uint value = 0;
                        for (int j = 0; j < 5; j++)
                        {
                            char c = input[i + j];
                            if (c < 33 || c > 117)
                                continue;
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

        /// <summary>
        /// Decodes ALPHA32 encoded data
        /// </summary>
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
                        if (index >= 0)
                            output.WriteByte((byte)index);
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

        /// <summary>
        /// Decodes WORDS256 encoded data (word-indexed encoding)
        /// </summary>
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
            uint uncompressedFormat,
            byte[] uncompressedBuffer,
            uint uncompressedBufferSize,
            byte[] compressedBuffer,
            uint compressedBufferSize,
            out uint finalUncompressedSize
        );
    }
}


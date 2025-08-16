using System.Text.Json;

namespace Gufel.EcdKey
{
    public static class EcdTools
    {
        public static readonly JsonSerializerOptions KeyJsonOption = new()
        {
            Converters = { new UrlSafeBase64Converter() },
            WriteIndented = true,
        };

        public static string ToUrlSafeBase64(byte[] data)
        {
            var base64 = Convert.ToBase64String(data);
            return base64.Replace('+', '-').Replace('/', '_').TrimEnd('=');
        }

        public static byte[] FromUrlSafeBase64(string urlSafeBase64)
        {
            var base64 = urlSafeBase64
                .Replace('-', '+')
                .Replace('_', '/');

            // Pad with '=' to make length a multiple of 4
            var padding = 4 - (base64.Length % 4);
            if (padding != 4)
            {
                base64 = base64.PadRight(base64.Length + padding, '=');
            }

            return Convert.FromBase64String(base64);
        }
    }
}

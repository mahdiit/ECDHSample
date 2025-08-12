using System.Text.Json;

namespace EcdService
{
    public static class EcdTools
    {
        public static readonly JsonSerializerOptions KeyJsonOption = new()
        {
            Converters = { new UrlSafeBase64Converter() },
            WriteIndented = true,
        };
    }
}

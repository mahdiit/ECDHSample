using Gufel.EcdKey;

namespace ECDHSample;

static class EcdhEncryptionWithSigning
{
    static void Main()
    {
        using var serverKey = EcdExchangeKey.Create();
        File.WriteAllText("exchangeKey-server-private.json", serverKey.ToJson(EcdKeyType.Private));
        File.WriteAllText("exchangeKey-server-public.json", serverKey.ToJson(EcdKeyType.Public));

        using var clientKey = EcdExchangeKey.Create();
        File.WriteAllText("exchangeKey-client-private.json", clientKey.ToJson(EcdKeyType.Private));
        File.WriteAllText("exchangeKey-client-public.json", clientKey.ToJson(EcdKeyType.Public));

        //sender
        var serverEncrypted = EcdExchangeKey.EncryptString("Server Private Message!", serverKey, EcdExchangeKey.CreateFromJson(File.ReadAllText("exchangeKey-client-public.json")));

        var json = serverEncrypted.ToJson();
        var obj = EcdEncryptDto.CreateFromJson(json);
        Console.WriteLine($"Tag length: {obj.Tag.Length}");

        //receiver
        var clientDecrypted = EcdExchangeKey.DecryptString(serverEncrypted, EcdExchangeKey.CreateFromJson(File.ReadAllText("exchangeKey-server-public.json")), clientKey);
        Console.WriteLine(clientDecrypted);

        //Sign sender
        var serverSignKey = EcdSignKey.Create();
        File.WriteAllText("signKey-server-private.json", serverSignKey.ToJson(EcdKeyType.Private));
        File.WriteAllText("signKey-server-public.json", serverSignKey.ToJson(EcdKeyType.Public));

        var signature = EcdSignKey.SignData("Server Private Message!"u8.ToArray(), serverSignKey);

        //Sign receiver
        var result = EcdSignKey.VerifyData("Server Private Message!"u8.ToArray(), signature, EcdSignKey.CreateFromJson(File.ReadAllText("signKey-server-public.json")));
        Console.WriteLine($"Verify result : {result}");

        Console.WriteLine("-------------- End --------------");
        Console.ReadKey();
    }
}
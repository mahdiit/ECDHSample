using System.Text.Json;
using EcdService;

namespace ECDHSample;

static class EcdhEncryptionWithSigning
{
    static void Main()
    {
        var options = new JsonSerializerOptions
        {
            Converters = { new UrlSafeBase64Converter() },
            WriteIndented = true
        };

        using var alice = new EcdExchangeKey();
        var serverKey = JsonSerializer.Serialize(alice);
        File.WriteAllText("server.json", serverKey);

        using var bob = new EcdExchangeKey();
        var clientKey = JsonSerializer.Serialize(bob);
        File.WriteAllText("client.json", clientKey);

        Console.ReadKey();

        //sender
        var sender = EcdExchangeKey.CreatePrivateKey(alice.PrivateKey);
        var receiver = EcdExchangeKey.CreatePublicKey(bob.PublicKey);
        var encrypted = EcdTools.EncryptFromString("hello", sender.Key, receiver.Key);



        string json = JsonSerializer.Serialize(encrypted, options);
        var obj = JsonSerializer.Deserialize<EcdEncryptDto>(json, options);

        //receiver
        sender = EcdExchangeKey.CreatePublicKey(alice.PublicKey);
        receiver = EcdExchangeKey.CreatePrivateKey(bob.PrivateKey);
        var decrypt = EcdTools.DecryptToString(encrypted, sender.Key, receiver.Key);
        Console.WriteLine(decrypt);

        //Sign sender
        var aliceSign = new EcdSignKey();
        var signature = EcdTools.SignData("hello"u8.ToArray(), aliceSign.Key);

        //Sign receiver
        var bobAliceKey = EcdSignKey.CreatePublicKey(aliceSign.PublicKey);
        var result = EcdTools.VerifyData("hello"u8.ToArray(), signature, bobAliceKey.Key);
        Console.WriteLine(result);

        Console.ReadKey();

    }

    static ReadOnlySpan<byte> Combine(byte[] a, byte[] b)
    {
        var result = new byte[a.Length + b.Length];
        Buffer.BlockCopy(a, 0, result, 0, a.Length);
        Buffer.BlockCopy(b, 0, result, a.Length, b.Length);
        return result;
    }
}
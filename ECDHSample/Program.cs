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
            WriteIndented = true,

        };

        using var alice = EcdExchangeKey.Create();
        var serverKey = JsonSerializer.Serialize(alice);
        File.WriteAllText("exchangeKey-server.json", serverKey);

        var aliceDeserialize = JsonSerializer.Deserialize<EcdKey>(serverKey);
        Console.WriteLine(aliceDeserialize?.KeyType);

        using var bob = EcdExchangeKey.Create();
        var clientKey = JsonSerializer.Serialize(bob);
        File.WriteAllText("exchangeKey-client.json", clientKey);

        //sender
        var sender = EcdExchangeKey.CreatePrivateKey(aliceDeserialize.PrivateKey);
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
        var aliceSign = EcdSignKey.Create();
        var sigKey = JsonSerializer.Serialize(aliceSign);
        File.WriteAllText("signKey-server.json", clientKey);

        var aliceSignDeserialize = JsonSerializer.Deserialize<EcdKey>(sigKey);
        Console.WriteLine(aliceSignDeserialize?.KeyType);

        var signature = EcdTools.SignData("hello"u8.ToArray(), EcdSignKey.CreatePrivateKey(aliceSignDeserialize.PrivateKey).Key);

        //Sign receiver
        var bobAliceKey = EcdSignKey.CreatePublicKey(aliceSignDeserialize.PublicKey);
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
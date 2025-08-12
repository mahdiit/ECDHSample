using EcdService;

namespace ECDHSample;

static class EcdhEncryptionWithSigning
{
    static void Main()
    {
        using var alice = EcdExchangeKey.Create();
        var serverKey = alice.ToJson();
        File.WriteAllText("exchangeKey-server.json", serverKey);

        using var aliceDeserialize = EcdExchangeKey.CreateFromJson(serverKey);
        Console.WriteLine(aliceDeserialize.KeyType);

        using var bob = EcdExchangeKey.Create();
        var clientKey = bob.ToJson();
        File.WriteAllText("exchangeKey-client.json", clientKey);

        //sender
        var receiver = EcdExchangeKey.CreateFromPublicKey(bob.PublicKey);
        var encrypted = EcdExchangeKey.EncryptString("hello", aliceDeserialize, receiver);

        string json = encrypted.ToJson();
        var obj = EcdEncryptDto.CreateFromJson(json);
        Console.WriteLine(obj.Tag.Length);

        //receiver
        var sender = EcdExchangeKey.CreateFromPublicKey(alice.PublicKey);
        receiver = EcdExchangeKey.CreateFromPrivateKey(bob.PrivateKey);
        var decrypt = EcdExchangeKey.DecryptString(encrypted, sender, receiver);
        Console.WriteLine(decrypt);

        //Sign sender
        var aliceSign = EcdSignKey.Create();
        var sigKey = aliceSign.ToJson();
        File.WriteAllText("signKey-server.json", clientKey);

        var aliceSignDeserialize = EcdSignKey.CreateFromJson(sigKey);
        Console.WriteLine(aliceSignDeserialize.KeyType);

        var signature = EcdSignKey.SignData("hello"u8.ToArray(), aliceSignDeserialize);

        //Sign receiver
        var bobAliceKey = EcdSignKey.CreateFromPublicKey(aliceSignDeserialize.PublicKey);
        var result = EcdSignKey.VerifyData("hello"u8.ToArray(), signature, bobAliceKey);
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
using System.Security.Cryptography;
using System.Text.Json;

namespace Gufel.EcdKey;

public static class ECAlgorithmHelper
{
    public static string ToJson<T>(T input) where T : ECAlgorithm
    {
        var ecParams = input.ExportParameters(true);
        var keyData = new EcdKeyJsonModel
        {
            Curve = ecParams.Curve.Oid.FriendlyName,
            D = ecParams.D,
            X = ecParams.Q.X,
            Y = ecParams.Q.Y
        };
        return JsonSerializer.Serialize(keyData, EcdTools.KeyJsonOption);
    }


}
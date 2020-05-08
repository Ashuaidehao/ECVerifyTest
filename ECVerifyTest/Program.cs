using System;
using System.Diagnostics;
using System.Linq;
using System.Security.Cryptography;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;

namespace ECVerifyTest
{
    class Program
    {
        private static X9ECParameters _ecParams  = NistNamedCurves.GetByName("P-256");
        private static ECDomainParameters _domainParameters = new ECDomainParameters(_ecParams.Curve, _ecParams.G, _ecParams.N, _ecParams.H, _ecParams.GetSeed());
        private static Org.BouncyCastle.Math.EC.ECCurve _curve = _ecParams.Curve;



        static void Main(string[] args)
        {

            var publicKey =
                "77d28f103c37eb03d62decd4fdbda01dd69fea878325bc1bebc5074a876455eb9d2f4e719ba0a0838df3b07479ed2179358f711fe9d004b693c62922e95772d0"
                    .HexToBytes();
            var signature =
                "61516a23f99962b4417c87d26592b52060b19c5b7481a2318c665af540ae721c69611c073c6e34a358343e9ad43b4966ce0f9a8914c5e77f2cb3fe28ae2bf4d0"
                    .HexToBytes();
            var message =
                "38900d0000000000bd3bde894f6ddb7e5ae89e7d7c1eef5c271875c5a2bd6b75faba07c8c8423902e8c4d7a4ebf3542d7d8eee65a996bb45211e546bd995ae5b1d099a90464886981b9e479971010000214e0000bf1740f6c1e1f913d2f307b29b8082551ba9a5c5"
                    .HexToBytes();


            var v = VerifyData(message, signature, publicKey);
            var v2 = VerifyDataBouncy(message, signature, publicKey);

            Console.WriteLine($"{v},{v2}");

            int count = 1000;

            var sw = new Stopwatch();
            sw.Start();
            for (int i = 0; i < count ; i++)
            {
                VerifyData(message, signature, publicKey);
            }
            sw.Stop();

            Console.WriteLine($"VerifyData : {sw.Elapsed.TotalSeconds} s");
            sw.Restart();
            for (int i = 0; i < count; i++)
            {
                VerifyDataBouncy(message, signature, publicKey);
            }

            sw.Stop();

            Console.WriteLine($"VerifyDataBouncy : {sw.Elapsed.TotalSeconds} s");

            Console.WriteLine(v);
            Console.ReadLine();
        }



        static bool VerifyData(ReadOnlySpan<byte> message, ReadOnlySpan<byte> signature, ReadOnlySpan<byte> pubkey)
        {
            using var ecdsa = ECDsa.Create(new ECParameters
            {
                Curve = ECCurve.NamedCurves.nistP256,
                Q = new ECPoint
                {
                    X = pubkey[..32].ToArray(),
                    Y = pubkey[32..].ToArray()
                }
            });
            return ecdsa.VerifyData(message, signature, HashAlgorithmName.SHA256);
        }



        static bool VerifyDataBouncy(byte[] message, byte[] signature, byte[] pubkey)
        {
            BigInteger x = new BigInteger(1, pubkey.Take(32).ToArray());
            BigInteger y = new BigInteger(1, pubkey.Skip(32).ToArray());

            var derSignature = new DerSequence(
                    // first 32 bytes is "r" number
                    new DerInteger(new BigInteger(1, signature.Take(32).ToArray())),
                    // last 32 bytes is "s" number
                    new DerInteger(new BigInteger(1, signature.Skip(32).ToArray())))
                .GetDerEncoded();
            Org.BouncyCastle.Math.EC.ECPoint q = _curve.CreatePoint(x, y);

            ECPublicKeyParameters pubkeyParam = new ECPublicKeyParameters(q, _domainParameters);

            var verifier = SignerUtilities.GetSigner("SHA-256withECDSA");
            verifier.Init(false, pubkeyParam);
            verifier.BlockUpdate(message, 0, message.Length);
            return verifier.VerifySignature(derSignature);

        }

    }


}
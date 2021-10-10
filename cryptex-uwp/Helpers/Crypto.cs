using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Crypto.Parameters;
using System;
using System.Diagnostics;

namespace cryptex_uwp.Helpers
{

    class Crypto
    {


        private static IBlockCipher CreateEngine(string algo)
        {
            switch (algo)
            {
                case "AES":
                    return new AesEngine();
                case "SM4":
                    return new SM4Engine();
                case "DES":
                    return new DesEngine();
                case "3DES":
                    return new DesEdeEngine();
                case "RC2":
                    return new RC2Engine();
                case "RC6":
                    return new RC6Engine();
                case "RC532":
                    return new RC532Engine();
                case "RC564":
                    return new RC564Engine();
                case "Rijndael":
                    return new RijndaelEngine();
                case "SEED":
                    return new SeedEngine();
                case "SKIPJACK":
                    return new SkipjackEngine();
                case "TEA":
                    return new TeaEngine();
                case "Twofish":
                    return new TwofishEngine();
                case "XTEA":
                    return new XteaEngine();
                default:
                    // TODO: exception
                    throw new Exception(String.Format("unkown algorithm: {0}", algo));
            }
        }

        private static IBlockCipher CreateBlockCipherMode(IBlockCipher engine, string mod)
        {
            switch (mod)
            {
                case "CBC":
                    return new CbcBlockCipher(engine);
                case "ECB":
                    return engine;
                case "CFB":
                    return new CfbBlockCipher(engine, engine.GetBlockSize() * 8);
                case "CTR":
                    return new KCtrBlockCipher(engine);
                case "OFB":
                    return new OfbBlockCipher(engine, engine.GetBlockSize() * 8);
                default:
                    throw new Exception(String.Format("unkown block cipher mode: {0}", mod));
            }
        }

        private static BufferedBlockCipher CreateBufferedCipher(IBlockCipher cipher, bool isPad)
        {
            if (isPad)
            {
                return new PaddedBufferedBlockCipher(cipher);
            }
            return new BufferedBlockCipher(cipher);
        }


        private static BufferedBlockCipher CreateBufferBlockCipher(string algo, string mod, bool pad)
        {
            IBlockCipher engine = CreateEngine(algo);
            IBlockCipher blockCipher = CreateBlockCipherMode(engine, mod);
            return CreateBufferedCipher(blockCipher, pad);
        }

        public static byte[] Enc(string algo, string mod, bool pad, byte[] key, byte[] iv, byte[] plain)
        {
            BufferedBlockCipher cipher = CreateBufferBlockCipher(algo, mod, pad);

            KeyParameter keyParam = new KeyParameter(key);
            ParametersWithIV keyParamWithIV = new ParametersWithIV(keyParam, iv, 0, iv.Length);

            cipher.Init(true, keyParamWithIV);

            byte[] inputBytes = plain;
            byte[] outputBytes = new byte[cipher.GetOutputSize(inputBytes.Length)];
            int length = cipher.ProcessBytes(inputBytes, outputBytes, 0);
            cipher.DoFinal(outputBytes, length);

            string encrypted = Convert.ToBase64String(outputBytes);
            Debug.WriteLine(String.Format("encrypted: {0}", encrypted));
            return outputBytes;
        }

        public static byte[] Dec(string algo, string mod, bool pad, byte[] key, byte[] iv, byte[] crypt)
        {
            BufferedBlockCipher cipher = CreateBufferBlockCipher(algo, mod, pad);

            KeyParameter keyParam = new KeyParameter(key);
            ParametersWithIV keyParamWithIV = new ParametersWithIV(keyParam, iv, 0, iv.Length);

            cipher.Init(false, keyParamWithIV);

            byte[] inputBytes = crypt;
            byte[] outputBytes = new byte[cipher.GetOutputSize(inputBytes.Length)];
            int length = cipher.ProcessBytes(inputBytes, outputBytes, 0);
            cipher.DoFinal(outputBytes, length);

            string decrypted = Convert.ToBase64String(outputBytes);
            Debug.WriteLine(String.Format("decrypted: {0}", decrypted));
            return outputBytes;

        }

        public static byte[] EncGCM(string algo, string mod, bool pad, byte[] key, byte[] iv, byte[] plain, byte[] associated)
        {
            IBlockCipher engine = CreateEngine(algo);
            GcmBlockCipher gcmblock = new GcmBlockCipher(engine);
            BufferedAeadBlockCipher cipher = new BufferedAeadBlockCipher(gcmblock);
            KeyParameter keyParam = new KeyParameter(key);

            const int MacBitSize = 128;
            var parameters = new AeadParameters(keyParam, MacBitSize, iv, associated);
            cipher.Init(true, parameters);

            byte[] inputBytes = plain;
            byte[] outputBytes = new byte[cipher.GetOutputSize(inputBytes.Length)];
            int length = cipher.ProcessBytes(inputBytes, outputBytes, 0);
            cipher.DoFinal(outputBytes, length);

            string encrypted = Convert.ToBase64String(outputBytes);
            Debug.WriteLine(String.Format("encrypted: {0}", encrypted));
            return outputBytes;
        }

        public static byte[] DecGCM(string algo, string mod, bool pad, byte[] key, byte[] iv, byte[] ciphtext, byte[] associated)
        {
            IBlockCipher engine = CreateEngine(algo);
            GcmBlockCipher gcmblock = new GcmBlockCipher(engine);
            BufferedAeadBlockCipher cipher = new BufferedAeadBlockCipher(gcmblock);
            KeyParameter keyParam = new KeyParameter(key);

            const int MacBitSize = 128;
            var parameters = new AeadParameters(keyParam, MacBitSize, iv, associated);
            cipher.Init(false, parameters);

            byte[] inputBytes = ciphtext;
            byte[] outputBytes = new byte[cipher.GetOutputSize(inputBytes.Length)];
            int length = cipher.ProcessBytes(inputBytes, outputBytes, 0);
            cipher.DoFinal(outputBytes, length);

            string plain = Convert.ToBase64String(outputBytes);
            Debug.WriteLine(String.Format("encrypted: {0}", plain));
            return outputBytes;
        }
    }
}

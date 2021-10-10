using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace cryptex_uwp.Models
{
    public struct BlockCipherDesc
    {
        public BlockCipherDesc(string l, string d) { link = l; desc = d; }
        public string link;
        public string desc;
    }

    public class BlockCipherInfo
    {
        private Dictionary<string, BlockCipherDesc> descs;

        public BlockCipherInfo()
        {
            descs = new Dictionary<string, BlockCipherDesc>() {
            { "AES", new BlockCipherDesc(@"https://en.wikipedia.org/wiki/Advanced_Encryption_Standard", @"block size: 128
key size: 128/192/256") },

            {"DES", new BlockCipherDesc("https://en.wikipedia.org/wiki/Data_Encryption_Standard", @"block size: 64
key size: 56") },

            {"3DES", new BlockCipherDesc("https://en.wikipedia.org/wiki/Triple_DES", @"block size: 64
key size: 112/168") },

            {"SM4", new BlockCipherDesc("http://www.gmbz.org.cn/upload/2018-04-04/1522788048733065051.pdf", @"block size: 128
key size: 128") },

            {"RC2", new BlockCipherDesc("https://en.wikipedia.org/wiki/RC2", @"block size: 64
key size: 8–1024 bits, in steps of 8 bits; default 64 bits") },

            {"RC6", new BlockCipherDesc("https://en.wikipedia.org/wiki/RC6", @"block size: 128
key size: 128/192/256") },

            {"RC532", new BlockCipherDesc("https://en.wikipedia.org/wiki/RC5", @"The specification for RC5 came from the RC5 Encryption Algorithm publication in RSA CryptoBytes, Spring of 1995. http://www.rsasecurity.com/rsalabs/cryptobytes This implementation has a word size of 32 bits.
block size: 64
key size: 0 to 2040 bits (128 suggested)") },

            {"RC564", new BlockCipherDesc("https://en.wikipedia.org/wiki/RC5", @"The specification for RC5 came from the RC5 Encryption Algorithm publication in RSA CryptoBytes, Spring of 1995. http://www.rsasecurity.com/rsalabs/cryptobytes This implementation has a word size of 64 bits.
block size: 128
key size: 0 to 2040 bits (128 suggested)") },

            {"Rijndael", new BlockCipherDesc("https://www.arib.or.jp/english/html/overview/doc/T53v6_5_pdf/3_Standard_Part/6_Ancillary_Specification/ARIB_STD-T53-S.S0078-Av2_0.pdf", @"The Advanced Encryption Standard (AES), also known by its original name Rijndael.
block size: 128
key size: 128/192/256") },

            {"SEED", new BlockCipherDesc("https://en.wikipedia.org/wiki/SEED", @"block size: 128
key size: 128") },

            {"SKIPJACK", new BlockCipherDesc("https://en.wikipedia.org/wiki/Skipjack_(cipher)", @"block size: 64
key size: 80") },

            {"TEA", new BlockCipherDesc("https://en.wikipedia.org/wiki/Tiny_Encryption_Algorithm", @"Tiny Encryption Algorithm
block size: 64
key size: 128") },

            {"XTEA", new BlockCipherDesc("https://en.wikipedia.org/wiki/XTEA", @"eXtended TEA
block size: 64
key size: 128") },

            {"Twofish", new BlockCipherDesc("https://en.wikipedia.org/wiki/Twofish", @"eXtended TEA
block size: 128
key size: 128/192/256") } };

        }

        public BlockCipherDesc Get(String algo)
        {
            BlockCipherDesc value;
            if (descs.TryGetValue(algo, out value))
            {
                return value;
            }
            throw new ArgumentException($"unown algorithm {algo}");
        }
    }
}

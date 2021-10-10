using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using cryptex_uwp.Models;
using Microsoft.Toolkit.Mvvm.ComponentModel;

namespace cryptex_uwp.ViewModels
{

    public class BlockCipherViewModel : ObservableObject
    {
        public BlockCipherInfo AlgoInfo { get; } = new BlockCipherInfo();


        public const int INPUT_FORMAT_STR = 0;
        public const int INPUT_FORMAT_HEX = 1;

        private string plaintextContent;
        private string ciphertextContent;


        public string CipherAlgorithm { get; set; }
        public string CipherMode { get; set; }

        public int KeyFormatIndex { get; set; }
        public int IVFormatIndex { get; set; }
        public int AsoFormatIndex { get; set; }

        public int PlaintextFormatIndex { get; set; }
        public int CiphertextFormatIndex { get; set; }

        // PKCS7
        public bool IsPadding { get; set; }

        public string KeyContent { get; set; }
        public string IVContent { get; set; }
        public string AsoContent { get; set; }

        public string PlaintextContent
        {
            get => plaintextContent;
            set => SetProperty(ref plaintextContent, value);
        }
        public void SetPlainBytes(byte[] value)
        {
            String v = null;
            if (PlaintextFormatIndex == INPUT_FORMAT_STR)
            {
                v = Encoding.Default.GetString(value);
            }
            else
            {
                v = BitConverter.ToString(value);
            }
            PlaintextContent = v;
        }

        public string CiphertextContent
        {
            get => ciphertextContent;
            set => SetProperty(ref ciphertextContent, value);
        }

        public void SetCipherBytes(byte[] value)
        {
            String v = null;
            if (CiphertextFormatIndex == INPUT_FORMAT_STR)
            {
                v = Encoding.Default.GetString(value);
            }
            else
            {
                v = BitConverter.ToString(value);
            }
            CiphertextContent = v;
        }

        public BlockCipherViewModel()
        {
            CipherAlgorithm = "AES";
            CipherMode = "CBC";
            IsPadding = true;

            KeyFormatIndex = INPUT_FORMAT_HEX;
            IVFormatIndex = INPUT_FORMAT_HEX;
            PlaintextFormatIndex = INPUT_FORMAT_HEX;
            CiphertextFormatIndex = INPUT_FORMAT_HEX;
            AsoFormatIndex = INPUT_FORMAT_HEX;
        }

        public byte[] KeyBytes
        {
            get
            {
                return GetBytes(KeyContent, KeyFormatIndex);
            }
        }

        public byte[] IVBytes
        {
            get { return GetBytes(IVContent, IVFormatIndex); }
        }

        public byte[] AsoBytes
        {
            get { return GetBytes(AsoContent, AsoFormatIndex); }
        }
        public byte[] PlaintexBytes
        {
            get { return GetBytes(PlaintextContent, PlaintextFormatIndex); }
        }

        public byte[] CiphertextBytes
        {
            get { return GetBytes(CiphertextContent, CiphertextFormatIndex); }
        }

        private byte[] GetBytes(string content, int format)
        {
            if (format == INPUT_FORMAT_STR)
            {
                return Encoding.Default.GetBytes(content);
            }
            return HexToBytes(content);
        }
        public static byte[] HexToBytes(string hexStr)
        {
            if (hexStr == null || hexStr.Length == 0)
            {
                return null;
            }
            string hex = Regex.Replace(hexStr, @"[^0-9a-fA-F]+", "");

            return Enumerable.Range(0, hex.Length)
                 .Where(x => x % 2 == 0)
                 .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
                 .ToArray();
        }
    }
}

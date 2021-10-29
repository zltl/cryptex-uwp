using System;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Toolkit.Mvvm.ComponentModel;

namespace cryptex_uwp.ViewModels
{
    public class HASHViewModel : ObservableObject
    {
        public const int INPUT_FORMAT_STR = 0;
        public const int INPUT_FORMAT_HEX = 1;

        private string hashAlgorithm;

        private string plaintextContent;
        private string ciphertextContent;

        public int PlaintextFormatIndex { get; set; }
        public int CiphertextFormatIndex { get; set; }
        public string PlaintextContent
        {
            get => plaintextContent;
            set => SetProperty(ref plaintextContent, value);
        }
        public string CiphertextContent
        {
            get => ciphertextContent;
            set => SetProperty(ref ciphertextContent, value);
        }



        public string HashAlgorithm { get => hashAlgorithm; set => SetProperty(ref hashAlgorithm, value); }

        public HASHViewModel()
        {
            HashAlgorithm = "MD5";
            PlaintextFormatIndex = INPUT_FORMAT_HEX;
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

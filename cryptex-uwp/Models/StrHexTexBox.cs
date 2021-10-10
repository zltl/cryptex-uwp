using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace cryptex_uwp.Models
{
    public class StrHexTexBox
    {
        public const int CONTENT_FORMAT_STR = 0;
        public const int CONTENT_FORMAT_HEX = 1;

        private byte[] content;

        public StrHexTexBox()
        {
            SelectedIndex = CONTENT_FORMAT_HEX;
        }

        public StrHexTexBox(byte[] contentBytes, int selectedIndex)
        {
            ContentBytes = contentBytes;
            SelectedIndex = selectedIndex;
        }

        public byte[] ContentBytes { get => content; set => content = value; }

        public int SelectedIndex { get; set; }

        public void SetContent(int selectedIndex, String value)
        {
            switch (SelectedIndex)
            {
                case CONTENT_FORMAT_STR:
                    ContentStr = value;
                    break;
                case CONTENT_FORMAT_HEX:
                    ContentHex = value;
                    break;
                default:
                    throw new ArgumentException("unkown content format");

            }
        }

        public String ContentHex
        {
            get => BitConverter.ToString(content);
            set => HexToBytes(value);
        }

        public String ContentStr
        {
            get
            {
                if (content == null)
                {
                    return null;
                }
                return Encoding.Default.GetString(content);
            }
            set => Encoding.Default.GetBytes(value);
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

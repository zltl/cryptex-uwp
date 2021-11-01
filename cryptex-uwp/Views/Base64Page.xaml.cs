using System;
using System.Text;
using cryptex_uwp.ViewModels;

using Windows.UI.Xaml.Controls;

namespace cryptex_uwp.Views
{
    public sealed partial class Base64Page : Page
    {
        public Base64ViewModel ViewModel { get; } = new Base64ViewModel();

        public Base64Page()
        {
            InitializeComponent();
        }

        static readonly char[] basepadding = { '=' };

        private String base64URL(byte[] s)
        {
            string returnValue = Convert.ToBase64String(s)
                .TrimEnd(basepadding).Replace('+', '-').Replace('/', '_');
            return returnValue;
        }

        private byte[] base64URLDecode(string src)
        {
            var s = src.Replace('_', '/').Replace('-', '+');
            switch (s.Length % 4)
            {
                case 2: s += "=="; break;
                case 3: s += "="; break;
            }
            byte[] bytes = Convert.FromBase64String(s);

            return bytes;
        }

        private void StartBaseButton_Click(object sender, Windows.UI.Xaml.RoutedEventArgs e)
        {
            try
            {
                switch (ViewModel.BaseAlgorithm)
                {

                    case "Base64":
                        ViewModel.CiphertextContent = Convert.ToBase64String(ViewModel.PlaintexBytes);
                        break;
                    case "Base64URL":
                        ViewModel.CiphertextContent = base64URL(ViewModel.PlaintexBytes);
                        break;
                    default:
                        throw new Exception($"unkown algorithm {ViewModel.BaseAlgorithm}");
                }

            }
            catch (Exception exc)
            {
                INFO.Message = exc.ToString();
                INFO.Title = "!Exception";
                INFO.IsOpen = true;
            }
        }

        private void StartBaseDecodeButton_Click(object sender, Windows.UI.Xaml.RoutedEventArgs e)
        {
            try
            {
                switch (ViewModel.BaseAlgorithm)
                {

                    case "Base64":
                        ViewModel.PlaintexBytes = Convert.FromBase64String(ViewModel.CiphertextContent);
                        break;
                    case "Base64URL":
                        ViewModel.PlaintexBytes = base64URLDecode(ViewModel.CiphertextContent);
                        break;
                    default:
                        throw new Exception($"unkown algorithm {ViewModel.BaseAlgorithm}");
                }

            }
            catch (Exception exc)
            {
                INFO.Message = exc.ToString();
                INFO.Title = "!Exception";
                INFO.IsOpen = true;
            }
        }
    }
}

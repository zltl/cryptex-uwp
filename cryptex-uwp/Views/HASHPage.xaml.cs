using System;

using cryptex_uwp.ViewModels;
using Org.BouncyCastle.Crypto.Digests;
using Windows.UI.Xaml.Controls;

namespace cryptex_uwp.Views
{
    public sealed partial class HASHPage : Page
    {
        public HASHViewModel ViewModel { get; } = new HASHViewModel();

        public HASHPage()
        {
            InitializeComponent();
        }

        private void StartHashButton_Click(object sender, Windows.UI.Xaml.RoutedEventArgs e)
        {
            try
            {
                GeneralDigest sha = null;
                LongDigest longSha = null;

                switch (ViewModel.HashAlgorithm)
                {

                    case "MD5":
                        sha = new MD5Digest();
                        break;
                    case "SHA1":
                        sha = new Sha1Digest();
                        break;
                    case "SHA256":
                        sha = new Sha256Digest();
                        break; ;
                    case "SHA384":
                        longSha = new Sha384Digest();
                        break;
                    case "SHA512":
                        longSha = new Sha512Digest();
                        break;
                    case "SM3":
                        sha = new SM3Digest();
                        break;
                    default:
                        return;
                }

                if (sha != null)
                {
                    var plainBytes = ViewModel.PlaintexBytes;
                    sha.BlockUpdate(plainBytes, 0, plainBytes.Length);
                    byte[] checksum = new byte[sha.GetDigestSize()];
                    sha.DoFinal(checksum, 0);
                    var encryptedS = BitConverter.ToString(checksum);
                    ViewModel.CiphertextContent = encryptedS;
                }
                else
                {
                    var plainBytes = ViewModel.PlaintexBytes;
                    longSha.BlockUpdate(plainBytes, 0, plainBytes.Length);
                    byte[] checksum = new byte[longSha.GetDigestSize()];
                    longSha.DoFinal(checksum, 0);
                    var encryptedS = BitConverter.ToString(checksum);
                    ViewModel.CiphertextContent = encryptedS;
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

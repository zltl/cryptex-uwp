using System;
using System.Diagnostics;
using System.Text;
using cryptex_uwp.ViewModels;

using Windows.UI.Xaml.Controls;

namespace cryptex_uwp.Views
{
    public sealed partial class BlockCipherPage : Page
    {
        public BlockCipherViewModel ViewModel { get; } = new BlockCipherViewModel();


        public BlockCipherPage()
        {
            InitializeComponent();
        }

        private void EncryptButton_Click(object sender, Windows.UI.Xaml.RoutedEventArgs e)
        {
            try
            {
                byte[] outputBytes = null;
                if (ViewModel.CipherMode == "GCM")
                {
                    outputBytes = Helpers.Crypto.EncGCM(ViewModel.CipherAlgorithm, ViewModel.CipherMode,
                        ViewModel.IsPadding, ViewModel.KeyBytes, ViewModel.IVBytes,
                        ViewModel.PlaintexBytes, ViewModel.AsoBytes);
                }
                else
                {
                    outputBytes = Helpers.Crypto.Enc(ViewModel.CipherAlgorithm, ViewModel.CipherMode,
                       ViewModel.IsPadding, ViewModel.KeyBytes, ViewModel.IVBytes,
                       ViewModel.PlaintexBytes);
                }

                ViewModel.SetCipherBytes(outputBytes);
            }
            catch (Exception exc)
            {
                INFO.Message = exc.ToString();
                INFO.Title = "!Exception";
                INFO.IsOpen = true;
            }
        }

        private void DecryptButton_Click(object sender, Windows.UI.Xaml.RoutedEventArgs e)
        {

            try
            {
                byte[] outputBytes = null;
                if (ViewModel.CipherMode == "GCM")
                {
                    outputBytes = Helpers.Crypto.DecGCM(ViewModel.CipherAlgorithm, ViewModel.CipherMode,
                         ViewModel.IsPadding, ViewModel.KeyBytes, ViewModel.IVBytes,
                         ViewModel.CiphertextBytes, ViewModel.AsoBytes);
                }
                else
                {
                    outputBytes = Helpers.Crypto.Dec(ViewModel.CipherAlgorithm, ViewModel.CipherMode,
                     ViewModel.IsPadding, ViewModel.KeyBytes, ViewModel.IVBytes,
                     ViewModel.CiphertextBytes);
                }
                ViewModel.SetPlainBytes(outputBytes);
            }
            catch (Exception exc)
            {
                INFO.Message = exc.ToString();
                INFO.Title = "!";
                INFO.IsOpen = true;
            }
        }

        private void AlgoDescButton_Click(object sender, Windows.UI.Xaml.RoutedEventArgs e)
        {
            if (AlgoDescBlock.Visibility == Windows.UI.Xaml.Visibility.Visible)
            {

                AlgoDescBlock.Visibility = Windows.UI.Xaml.Visibility.Collapsed;
            }
            else
            {
                AlgoDescBlock.Visibility = Windows.UI.Xaml.Visibility.Visible;
            }
        }

        private void BlockCipherAlgorithm_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            AlgoHiperLink.Content = "About " + ViewModel.CipherAlgorithm;

            var desc = ViewModel.AlgoInfo.Get(ViewModel.CipherAlgorithm);
            AlgoHiperLink.NavigateUri = new Uri(desc.link);
            AlgoDescTextBlock.Text = desc.desc;
        }

        private void CipherMode_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (ViewModel.CipherMode == "ECB")
            {
                IVStack.Visibility = Windows.UI.Xaml.Visibility.Collapsed;
            }
            else
            {
                IVStack.Visibility = Windows.UI.Xaml.Visibility.Visible;
            }

            if (ViewModel.CipherMode == "GCM")
            {
                AssociatedContent.Visibility = Windows.UI.Xaml.Visibility.Visible;
            }
            else
            {
                AssociatedContent.Visibility = Windows.UI.Xaml.Visibility.Collapsed;
            }
        }
    }
}

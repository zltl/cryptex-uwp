using System;
using System.Collections.ObjectModel;
using cryptex.Models;
using Microsoft.Toolkit.Mvvm.ComponentModel;

namespace cryptex_uwp.ViewModels
{
    public class PKIViewModel : ObservableObject
    {

        private string subjectKeyPem;
        private int subjectKeyTypeI;
        private string issuerKeyPem;
        private int issuerKeyTypeI;
        private string csrPem;
        private string issuerCrtPem;
        private string subjectCrtPem;

        public const int SKT_RSA = 0;
        public const int SKT_ECC = 1;
        public const int SKT_SM2 = 2;

        public string SubjectKeyPem { get => subjectKeyPem; set => SetProperty(ref subjectKeyPem, value); }
        public int SubjectKeyType { get => subjectKeyTypeI; set => SetProperty(ref subjectKeyTypeI, value); }
        public string IssuerKeyPem { get => issuerKeyPem; set => SetProperty(ref issuerKeyPem, value); }
        public int IssuerKeyType { get => issuerKeyTypeI; set => SetProperty(ref issuerKeyTypeI, value); }
        public string IssuerCrtPem { get => issuerCrtPem; set => SetProperty(ref issuerCrtPem, value); }
        public string SubjectCrtPem { get => subjectCrtPem; set => SetProperty(ref subjectCrtPem, value); }

        public string CsrPem { get => csrPem; set => SetProperty(ref csrPem, value); }


        public PKIViewModel()
        {
            subjectKeyTypeI = SKT_RSA;
            issuerKeyTypeI = SKT_RSA;
        }

        public ObservableCollection<Pair> SubjectKeyViewSource { get; set; } = new ObservableCollection<Pair>();
        public ObservableCollection<Pair> IssuerKeyViewSource { get; set; } = new ObservableCollection<Pair>();

        public ObservableCollection<Pair> CsrViewSource { get; set; } = new ObservableCollection<Pair>();
        public ObservableCollection<Pair> IssuerCrtViewSource { get; set; } = new ObservableCollection<Pair>();
        public ObservableCollection<Pair> SubjectCrtViewSource { get; set; } = new ObservableCollection<Pair>();
    }
}

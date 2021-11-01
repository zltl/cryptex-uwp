using System;

using cryptex_uwp.ViewModels;

using Windows.UI.Xaml.Controls;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using System.Collections.ObjectModel;
using cryptex.Models;
using System.IO;
using System.Text;

namespace cryptex_uwp.Views
{
    public sealed partial class PKIPage : Page
    {
        public PKIViewModel ViewModel { get; } = new PKIViewModel();

        public PKIPage()
        {
            InitializeComponent();
        }

        private ObservableCollection<Pair> getKeyInfo(String keyPem, int keyType)
        {

            var reader = new StringReader(keyPem);
            var pemReader = new PemReader(reader);
            AsymmetricCipherKeyPair keypair = (AsymmetricCipherKeyPair)pemReader.ReadObject();
            var res = new ObservableCollection<Pair>();

            switch (keyType)
            {
                case PKIViewModel.SKT_RSA:
                    {
                        RsaPrivateCrtKeyParameters key = (RsaPrivateCrtKeyParameters)keypair.Private;
                        res.Add(item: new Pair() { First = "Modulus", Second = key.Modulus.ToString(16) });
                        res.Add(item: new Pair() { First = "Public Exponent", Second = key.PublicExponent.ToString(16) });
                        res.Add(item: new Pair() { First = "Private Exponent", Second = key.Exponent.ToString(16) });
                        res.Add(item: new Pair() { First = "P", Second = key.P.ToString(16) });
                        res.Add(item: new Pair() { First = "Q", Second = key.Q.ToString(16) });
                        res.Add(item: new Pair() { First = "DP", Second = key.DP.ToString(16) });
                        res.Add(item: new Pair() { First = "DQ", Second = key.DQ.ToString(16) });
                        res.Add(item: new Pair() { First = "QInv", Second = key.QInv.ToString(16) });
                        break;
                    }
                case PKIViewModel.SKT_ECC:
                case PKIViewModel.SKT_SM2:
                    {
                        ECPrivateKeyParameters key = (ECPrivateKeyParameters)keypair.Private;
                        ECPublicKeyParameters keypub = (ECPublicKeyParameters)keypair.Public;

                        res.Add(item: new Pair() { First = "D", Second = key.D.ToString(16) });
                        res.Add(item: new Pair() { First = "A", Second = key.Parameters.Curve.A.ToBigInteger().ToString(16) });
                        res.Add(item: new Pair() { First = "B", Second = key.Parameters.Curve.B.ToBigInteger().ToString(16) });
                        res.Add(item: new Pair() { First = "N", Second = key.Parameters.N.ToString(16) });
                        res.Add(item: new Pair() { First = "H", Second = key.Parameters.H.ToString(16) });
                        res.Add(item: new Pair() { First = "G.X", Second = key.Parameters.G.XCoord.ToBigInteger().ToString(16) });
                        res.Add(item: new Pair() { First = "G.Y", Second = key.Parameters.G.YCoord.ToBigInteger().ToString(16) });
                        res.Add(item: new Pair() { First = "Q.X", Second = keypub.Q.XCoord.ToBigInteger().ToString(16) });
                        res.Add(item: new Pair() { First = "Q.Y", Second = keypub.Q.YCoord.ToBigInteger().ToString(16) });
                        break;
                    }
            }

            {
                var writer = new StringWriter();
                var pemWriter = new PemWriter(writer);
                pemWriter.WriteObject(keypair.Public);

                res.Add(item: new Pair() { First = "Public Pem", Second = writer.ToString() });
            }
            return res;
        }

        private void ShowSubjectKeyButton_Click(object sender, Windows.UI.Xaml.RoutedEventArgs e)
        {
            try
            {
                ViewModel.SubjectKeyViewSource.Clear();
                var res = getKeyInfo(ViewModel.SubjectKeyPem, ViewModel.SubjectKeyType);
                foreach (Pair p in res)
                {
                    ViewModel.SubjectKeyViewSource.Add(p);
                }
            }
            catch (Exception exc)
            {
                INFO.Message = exc.ToString();
                INFO.Title = "!Exception";
                INFO.IsOpen = true;
            }
        }

        private String genKeyPem(int keyType)
        {
            String res = "";
            switch (keyType)
            {
                case PKIViewModel.SKT_RSA:
                    {
                        var generator = new RsaKeyPairGenerator();
                        generator.Init(new KeyGenerationParameters(new SecureRandom(), 2048));
                        var keypair = generator.GenerateKeyPair();
                        var rsaKey = keypair.Private as RsaPrivateCrtKeyParameters;

                        var writer = new StringWriter();
                        var pemWriter = new PemWriter(writer);
                        pemWriter.WriteObject(keypair);
                        res = writer.ToString();

                        break;
                    }
                case PKIViewModel.SKT_ECC:
                    {
                        var generator = new ECKeyPairGenerator();
                        generator.Init(new KeyGenerationParameters(new SecureRandom(), 256));
                        var keypair = generator.GenerateKeyPair();
                        var eckey = keypair.Private as ECPrivateKeyParameters;

                        var writer = new StringWriter();
                        var pemWriter = new PemWriter(writer);
                        pemWriter.WriteObject(keypair);
                        res = writer.ToString();
                        break;
                    }
                case PKIViewModel.SKT_SM2:
                    {
                        /* TODO: generate as random */
                        res = @"-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIDqapdxXTh4ksCWkHI69p3zvnGUw8SbpkzFuVOLsth6zoAoGCCqBHM9V
AYItoUQDQgAET/YXETFacZuUeQ7n83xmu2rT+ZjubBLtVHI7aTT5JJFv9XaFOFXX
P4+HF5F8SLftj4XMdiMnWwG+M3Gdg8K6Vg==
-----END EC PRIVATE KEY-----";

                        break;
                    }
            }
            return res;
        }

        private void NewSubjectKeyButton_Click(object sender, Windows.UI.Xaml.RoutedEventArgs e)
        {
            try
            {
                ViewModel.SubjectKeyPem = genKeyPem(ViewModel.SubjectKeyType);
                ShowSubjectKeyButton_Click(sender, e);
            }
            catch (Exception exc)
            {
                INFO.Message = exc.ToString();
                INFO.Title = "!Exception";
                INFO.IsOpen = true;
            }
        }

        private void NewCSRButton_Click(object sender, Windows.UI.Xaml.RoutedEventArgs e)
        {
            try
            {
                var reader = new StringReader(ViewModel.SubjectKeyPem);
                var pemReader = new Org.BouncyCastle.OpenSsl.PemReader(reader);
                AsymmetricCipherKeyPair keypair = (AsymmetricCipherKeyPair)pemReader.ReadObject();

                var subjectName = "CN=cryptex.example,O=Primitive Steelmaking Interest Group,OU=IT,L=Beijing,ST=Beijing,C=CN";
                var subject = new X509Name(subjectName);
                var signAlgo = "SHA256WITHRSA";
                if (ViewModel.SubjectKeyType != PKIViewModel.SKT_RSA)
                {
                    signAlgo = "SHA256WITHECDSA";
                }

                var csr = new Pkcs10CertificationRequest(signAlgo, subject, keypair.Public, null, keypair.Private);
                StringBuilder CSRPem = new StringBuilder();
                PemWriter CSRPemWriter = new PemWriter(new StringWriter(CSRPem));
                CSRPemWriter.WriteObject(csr);
                CSRPemWriter.Writer.Flush();

                //get CSR text
                var CSRtext = CSRPem.ToString();
                ViewModel.CsrPem = CSRtext;

                ViewCsrButton_Click(sender, e);
            }
            catch (Exception exc)
            {
                INFO.Message = exc.ToString();
                INFO.Title = "!Exception";
                INFO.IsOpen = true;
            }
        }

        private void ViewCsrButton_Click(object sender, Windows.UI.Xaml.RoutedEventArgs e)
        {
            try
            {
                Pkcs10CertificationRequest csr = (Pkcs10CertificationRequest)new PemReader(new StringReader(ViewModel.CsrPem)).ReadObject();
                var info = csr.GetCertificationRequestInfo();

                /*
                var writer = new StringWriter();
                var pemWriter = new PemWriter(writer);
                pemWriter.WriteObject(csr.GetPublicKey());
                */

                ViewModel.CsrViewSource.Clear();
                ViewModel.CsrViewSource.Add(item: new Pair() { First = "Subject", Second = info.Subject.ToString() });
                // ViewModel.CsrViewSource.Add(item: new Pair() { First = "Public Key", Second = writer.ToString() });
            }
            catch (Exception exc)
            {
                INFO.Message = exc.ToString();
                INFO.Title = "!Exception";
                INFO.IsOpen = true;
            }
        }

        private void UpdateCSRButton_Click(object sender, Windows.UI.Xaml.RoutedEventArgs e)
        {
            try
            {
                var subjectStr = "CN=cryptex.example,O=Primitive Steelmaking Interest Group,OU=IT,L=Beijing,ST=Beijing,C=CN";
                foreach (Pair pair in ViewModel.CsrViewSource)
                {
                    if (pair.First == "Subject")
                    {
                        subjectStr = pair.Second;
                        break;
                    }
                }

                var reader = new StringReader(ViewModel.SubjectKeyPem);
                var pemReader = new Org.BouncyCastle.OpenSsl.PemReader(reader);
                AsymmetricCipherKeyPair keypair = (AsymmetricCipherKeyPair)pemReader.ReadObject();

                var subject = new X509Name(subjectStr);
                var signAlgo = "SHA256WITHRSA";
                if (ViewModel.SubjectKeyType != PKIViewModel.SKT_RSA)
                {
                    signAlgo = "SHA256WITHECDSA";
                }

                var newcsr = new Pkcs10CertificationRequest(signAlgo, subject, keypair.Public, null, keypair.Private);
                StringBuilder CSRPem = new StringBuilder();
                PemWriter CSRPemWriter = new PemWriter(new StringWriter(CSRPem));
                CSRPemWriter.WriteObject(newcsr);
                CSRPemWriter.Writer.Flush();

                //get CSR text
                var CSRtext = CSRPem.ToString();
                ViewModel.CsrPem = CSRtext;
            }
            catch (Exception exc)
            {
                INFO.Message = exc.ToString();
                INFO.Title = "!Exception";
                INFO.IsOpen = true;
            }
        }

        private bool isSelfSign = false;
        private void SelfSignButton_Click(object sender, Windows.UI.Xaml.RoutedEventArgs e)
        {
            try
            {
                if (IssuerCrtInfo.Visibility == Windows.UI.Xaml.Visibility.Collapsed)
                {
                    IssuerCrtInfo.Visibility = Windows.UI.Xaml.Visibility.Visible;
                    isSelfSign = false;
                }
                else
                {
                    IssuerCrtInfo.Visibility = Windows.UI.Xaml.Visibility.Collapsed;
                    isSelfSign = true;
                }
            }
            catch (Exception exc)
            {
                INFO.Message = exc.ToString();
                INFO.Title = "!Exception";
                INFO.IsOpen = true;
            }
        }

        private void ShowIssuerKeyButton_Click(object sender, Windows.UI.Xaml.RoutedEventArgs e)
        {
            try
            {
                ViewModel.IssuerKeyViewSource.Clear();
                var res = getKeyInfo(ViewModel.IssuerKeyPem, ViewModel.IssuerKeyType);
                foreach (Pair p in res)
                {
                    ViewModel.IssuerKeyViewSource.Add(p);
                }
            }
            catch (Exception exc)
            {
                INFO.Message = exc.ToString();
                INFO.Title = "!Exception";
                INFO.IsOpen = true;
            }
        }

        private void NewIssuerKeyButton_Click(object sender, Windows.UI.Xaml.RoutedEventArgs e)
        {
            try
            {
                ViewModel.IssuerKeyPem = genKeyPem(ViewModel.IssuerKeyType);
                ShowIssuerKeyButton_Click(sender, e);
            }
            catch (Exception exc)
            {
                INFO.Message = exc.ToString();
                INFO.Title = "!Exception";
                INFO.IsOpen = true;
            }
        }

        private ObservableCollection<Pair> getInfoFromCrt(String crtPem)
        {
            var res = new ObservableCollection<Pair>();
            X509CertificateParser crtParser = new X509CertificateParser();

            X509Certificate crt = crtParser.ReadCertificate(Encoding.Default.GetBytes(crtPem));

            res.Add(new Pair { First = "SerialNumber", Second = crt.SerialNumber.ToString(16) });
            res.Add(new Pair { First = "Subject", Second = crt.SubjectDN.ToString() });
            res.Add(new Pair { First = "Issuer", Second = crt.IssuerDN.ToString() });
            res.Add(new Pair { First = "NotBefore", Second = crt.NotBefore.ToString() });
            res.Add(new Pair { First = "NotAfter", Second = crt.NotAfter.ToString() });
            {
                var writer = new StringWriter();
                var pemWriter = new PemWriter(writer);
                pemWriter.WriteObject(crt.GetPublicKey());
                res.Add(new Pair { First = "PublicKey", Second = writer.ToString() });

            }

            return res;

        }

        private void ViewIssuerCrtButton_Click(object sender, Windows.UI.Xaml.RoutedEventArgs e)
        {
            try
            {
                var res = getInfoFromCrt(ViewModel.IssuerCrtPem);
                ViewModel.IssuerCrtViewSource.Clear();
                foreach (Pair p in res)
                {
                    ViewModel.IssuerCrtViewSource.Add(p);
                }
            }
            catch (Exception exc)
            {
                INFO.Message = exc.ToString();
                INFO.Title = "!Exception";
                INFO.IsOpen = true;
            }
        }

        public BigInteger getRandom(int length)
        {
            Random random = new Random();
            byte[] data = new byte[length];
            byte[] datar = new byte[1 + length];
            random.NextBytes(data);
            for (int i = 0; i < length; i++)
            {
                datar[i + 1] = data[i];
            }
            return new BigInteger(datar);
        }

        private String newCrtPem(X509Name subject, X509Name issuer,
            AsymmetricKeyParameter subjectPubKey,
            AsymmetricKeyParameter issuerPrivateKey,
            int issuerKeyType)
        {
            X509V3CertificateGenerator gen = new X509V3CertificateGenerator();
            gen.SetSerialNumber(getRandom(16));
            if (issuerKeyType == PKIViewModel.SKT_RSA)
            {
                gen.SetSignatureAlgorithm("SHA256WITHRSA");
            }
            else
            {
                gen.SetSignatureAlgorithm("SHA256WITHECDSA");
            }
            gen.SetIssuerDN((issuer));
            gen.SetSubjectDN((subject));
            var cur = DateTime.UtcNow;
            var curAdd = cur.AddDays(365 * 100);
            gen.SetNotAfter(curAdd);
            gen.SetNotBefore(cur);

            gen.SetPublicKey(subjectPubKey);


            var crt = gen.Generate(issuerPrivateKey);

            var writer = new StringWriter();
            var pemWriter = new PemWriter(writer);
            pemWriter.WriteObject(crt);

            return writer.ToString();
        }

        private void NewIssuerCrtButton_Click(object sender, Windows.UI.Xaml.RoutedEventArgs e)
        {
            try
            {
                // csr
                var subject = "CN=CA.example,O=Primitive Steelmaking Interest Group,OU=IT,L=Beijing,ST=Beijing,C=CN";
                var subjectX = new X509Name(subject);
                var reader = new StringReader(ViewModel.IssuerKeyPem);
                var pemReader = new PemReader(reader);
                AsymmetricCipherKeyPair keypair = (AsymmetricCipherKeyPair)pemReader.ReadObject();

                // selfsign
                ViewModel.IssuerCrtPem = newCrtPem(subjectX, subjectX, keypair.Public, keypair.Private, ViewModel.IssuerKeyType);
                ViewIssuerCrtButton_Click(sender, e);
            }
            catch (Exception exc)
            {
                INFO.Message = exc.ToString();
                INFO.Title = "!Exception";
                INFO.IsOpen = true;
            }
        }

        private void UpdateIssuerCrtButton_Click(object sender, Windows.UI.Xaml.RoutedEventArgs e)
        {
            try
            {
                var sn = "1001";
                var subject = "CN=CAExample";
                DateTime NotBefore = DateTime.UtcNow;
                DateTime NotAfter = DateTime.UtcNow.AddYears(100);
                foreach (Pair pair in ViewModel.IssuerCrtViewSource)
                {
                    switch (pair.First)
                    {
                        case "Subject":
                            subject = pair.Second;
                            break;
                        case "SerialNumber":
                            sn = pair.Second;
                            break;
                        case "NotBefore":
                            NotBefore = DateTime.Parse(pair.Second);
                            break;
                        case "NotAfter":
                            NotAfter = DateTime.Parse(pair.Second);
                            break;
                        default:
                            break;
                    }
                }
                var subjectX = new X509Name(subject);
                var reader = new StringReader(ViewModel.IssuerKeyPem);
                var pemReader = new PemReader(reader);
                AsymmetricCipherKeyPair keypair = (AsymmetricCipherKeyPair)pemReader.ReadObject();

                X509V3CertificateGenerator gen = new X509V3CertificateGenerator();

                System.Numerics.BigInteger b1 = System.Numerics.BigInteger.Parse(sn, System.Globalization.NumberStyles.AllowHexSpecifier);
                BigInteger bn = new BigInteger(b1.ToByteArray());
                gen.SetSerialNumber(bn);

                if (ViewModel.IssuerKeyType == PKIViewModel.SKT_RSA)
                {
                    gen.SetSignatureAlgorithm("SHA256WITHRSA");
                }
                else
                {
                    gen.SetSignatureAlgorithm("SHA256WITHECDSA");
                }
                gen.SetIssuerDN(subjectX);
                gen.SetSubjectDN(subjectX);
                gen.SetNotAfter(NotBefore);
                gen.SetNotBefore(NotAfter);

                gen.SetPublicKey(keypair.Public);
                var crt = gen.Generate(keypair.Private);

                var writer = new StringWriter();
                var pemWriter = new PemWriter(writer);
                pemWriter.WriteObject(crt);

                ViewModel.IssuerCrtPem = writer.ToString();
                ViewIssuerCrtButton_Click(sender, e);
            }
            catch (Exception exc)
            {
                INFO.Message = exc.ToString();
                INFO.Title = "!Exception";
                INFO.IsOpen = true;
            }
        }

        private void ViewSubjectCrtButton_Click(object sender, Windows.UI.Xaml.RoutedEventArgs e)
        {
            try
            {
                var res = getInfoFromCrt(ViewModel.SubjectCrtPem);
                ViewModel.SubjectCrtViewSource.Clear();
                foreach (Pair p in res)
                {
                    ViewModel.SubjectCrtViewSource.Add(p);
                }
            }
            catch (Exception exc)
            {
                INFO.Message = exc.ToString();
                INFO.Title = "!Exception";
                INFO.IsOpen = true;
            }
        }

        private void UpdateSubjectCrtButton_Click(object sender, Windows.UI.Xaml.RoutedEventArgs e)
        {
            try
            {
                int keyType = 0;
                var sn = getRandom(16);
                var subject = "CN=cryptex.example,O=Primitive Steelmaking Interest Group,OU=IT,L=Beijing,ST=Beijing,C=CN";
                DateTime NotBefore = DateTime.UtcNow;
                DateTime NotAfter = DateTime.UtcNow.AddYears(100);
                foreach (Pair pair in ViewModel.IssuerCrtViewSource)
                {
                    switch (pair.First)
                    {
                        case "Subject":
                            subject = pair.Second;
                            break;
                        case "SerialNumber":
                            System.Numerics.BigInteger b1 = System.Numerics.BigInteger.Parse(pair.Second, System.Globalization.NumberStyles.AllowHexSpecifier);
                            sn = new BigInteger(b1.ToByteArray());
                            break;
                        case "NotBefore":
                            NotBefore = DateTime.Parse(pair.Second);
                            break;
                        case "NotAfter":
                            NotAfter = DateTime.Parse(pair.Second);
                            break;
                        default:
                            break;
                    }
                }
                var subjectX = new X509Name(subject);

                AsymmetricKeyParameter subjectPubKey = null;
                if (ViewModel.CsrPem != null || ViewModel.CsrPem.Length > 0)
                {
                    Pkcs10CertificationRequest csr = (Pkcs10CertificationRequest)new PemReader(new StringReader(ViewModel.CsrPem)).ReadObject();
                    var info = csr.GetCertificationRequestInfo();
                    // subjectX = info.Subject;
                    subjectPubKey = csr.GetPublicKey();
                }
                else
                {
                    var reader = new StringReader(ViewModel.SubjectKeyPem);
                    var pemReader = new PemReader(reader);
                    AsymmetricCipherKeyPair keypair = (AsymmetricCipherKeyPair)pemReader.ReadObject();
                    subjectPubKey = keypair.Public;
                }

                // issuer
                AsymmetricKeyParameter issuerPrivateKey = null;
                var issuerX = subjectX;
                if (isSelfSign)
                {
                    var reader = new StringReader(ViewModel.SubjectKeyPem);
                    var pemReader = new PemReader(reader);
                    AsymmetricCipherKeyPair keypair = (AsymmetricCipherKeyPair)pemReader.ReadObject();
                    issuerPrivateKey = keypair.Private;
                    keyType = ViewModel.SubjectKeyType;
                }
                else
                {
                    var reader = new StringReader(ViewModel.IssuerKeyPem);
                    var pemReader = new PemReader(reader);
                    AsymmetricCipherKeyPair keypair = (AsymmetricCipherKeyPair)pemReader.ReadObject();
                    issuerPrivateKey = keypair.Private;

                    X509CertificateParser crtParser = new X509CertificateParser();
                    X509Certificate crt = crtParser.ReadCertificate(Encoding.Default.GetBytes(ViewModel.IssuerCrtPem));
                    issuerX = crt.SubjectDN;
                    keyType = ViewModel.IssuerKeyType;
                }

                // gen
                X509V3CertificateGenerator gen = new X509V3CertificateGenerator();
                gen.SetSerialNumber(sn);
                if (keyType == PKIViewModel.SKT_RSA)
                {
                    gen.SetSignatureAlgorithm("SHA256WITHRSA");
                }
                else
                {
                    gen.SetSignatureAlgorithm("SHA256WITHECDSA");
                }
                gen.SetIssuerDN(subjectX);
                gen.SetSubjectDN(subjectX);
                gen.SetNotAfter(NotBefore);
                gen.SetNotBefore(NotAfter);
                gen.SetPublicKey(subjectPubKey);
                var subjcrt = gen.Generate(issuerPrivateKey);
                var writer = new StringWriter();
                var pemWriter = new PemWriter(writer);
                pemWriter.WriteObject(subjcrt);

                ViewModel.SubjectCrtPem = writer.ToString();
            }
            catch (Exception exc)
            {
                INFO.Message = exc.ToString();
                INFO.Title = "!Exception";
                INFO.IsOpen = true;
            }
        }

        private void NewSubjectCrtButton_Click(object sender, Windows.UI.Xaml.RoutedEventArgs e)
        {
            try
            {
                // subject
                int keyType = 0;
                var sn = getRandom(16);
                var subject = "CN=cryptex.example,O=Primitive Steelmaking Interest Group,OU=IT,L=Beijing,ST=Beijing,C=CN";
                DateTime NotBefore = DateTime.UtcNow;
                DateTime NotAfter = DateTime.UtcNow.AddYears(100);
                var subjectX = new X509Name(subject);
                AsymmetricKeyParameter subjectPubKey = null;
                if (ViewModel.CsrPem != null || ViewModel.CsrPem.Length > 0)
                {
                    Pkcs10CertificationRequest csr = (Pkcs10CertificationRequest)new PemReader(new StringReader(ViewModel.CsrPem)).ReadObject();
                    var info = csr.GetCertificationRequestInfo();
                    subjectX = info.Subject;
                    subjectPubKey = csr.GetPublicKey();
                }
                else
                {
                    var reader = new StringReader(ViewModel.SubjectKeyPem);
                    var pemReader = new PemReader(reader);
                    AsymmetricCipherKeyPair keypair = (AsymmetricCipherKeyPair)pemReader.ReadObject();
                    subjectPubKey = keypair.Public;
                }

                // issuer
                AsymmetricKeyParameter issuerPrivateKey = null;
                var issuerX = subjectX;
                if (isSelfSign)
                {
                    var reader = new StringReader(ViewModel.SubjectKeyPem);
                    var pemReader = new PemReader(reader);
                    AsymmetricCipherKeyPair keypair = (AsymmetricCipherKeyPair)pemReader.ReadObject();
                    issuerPrivateKey = keypair.Private;
                    keyType = ViewModel.SubjectKeyType;
                }
                else
                {
                    var reader = new StringReader(ViewModel.IssuerKeyPem);
                    var pemReader = new PemReader(reader);
                    AsymmetricCipherKeyPair keypair = (AsymmetricCipherKeyPair)pemReader.ReadObject();
                    issuerPrivateKey = keypair.Private;

                    X509CertificateParser crtParser = new X509CertificateParser();
                    X509Certificate crt = crtParser.ReadCertificate(Encoding.Default.GetBytes(ViewModel.IssuerCrtPem));
                    issuerX = crt.SubjectDN;
                    keyType = ViewModel.IssuerKeyType;
                }

                // gen
                X509V3CertificateGenerator gen = new X509V3CertificateGenerator();
                gen.SetSerialNumber(sn);
                if (keyType == PKIViewModel.SKT_RSA)
                {
                    gen.SetSignatureAlgorithm("SHA256WITHRSA");
                }
                else
                {
                    gen.SetSignatureAlgorithm("SHA256WITHECDSA");
                }
                gen.SetIssuerDN(subjectX);
                gen.SetSubjectDN(subjectX);
                gen.SetNotAfter(NotBefore);
                gen.SetNotBefore(NotAfter);
                gen.SetPublicKey(subjectPubKey);
                var subjcrt = gen.Generate(issuerPrivateKey);
                var writer = new StringWriter();
                var pemWriter = new PemWriter(writer);
                pemWriter.WriteObject(subjcrt);

                ViewModel.SubjectCrtPem = writer.ToString();
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

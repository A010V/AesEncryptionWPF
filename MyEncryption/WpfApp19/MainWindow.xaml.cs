using Microsoft.Win32;
using System;
using System.IO;
using System.Security.Cryptography;
using System.Windows;

namespace WpfApp19
{

    public partial class MainWindow : Window
    {
        CspParameters cssParametrs = new CspParameters();
        RSACryptoServiceProvider RsaCrypt;

        const string EncryptPath = @"C:\AES\Encrypt\";
        const string DecryptPath = @"C:\AES\Decrypt\";
        const string WorkFolder = @"C:\AES\";

        public MainWindow()
        {
            InitializeComponent();
        }

        #region "Methods"

        private void EncryptFile(string inFile)
        {
            Aes aes = Aes.Create();
            ICryptoTransform transform = aes.CreateEncryptor();
            byte[] keyEncrypted = RsaCrypt.Encrypt(aes.Key, false);
            byte[] LenK = new byte[4];
            byte[] LenIV = new byte[4];
            int lKey = keyEncrypted.Length;
            LenK = BitConverter.GetBytes(lKey);
            int lIV = aes.IV.Length;
            LenIV = BitConverter.GetBytes(lIV);
            int startFileName = inFile.LastIndexOf("\\") + 1;
            string outFile = "";
            try
            {
                outFile = EncryptPath + inFile.Substring(startFileName, inFile.LastIndexOf(".") - startFileName) + inFile.Substring(inFile.LastIndexOf(".")) + ".encrypted";
            }

            catch
            {
                MessageBox.Show("This file Can't encrypted Because it hasn't extension");
            }

            try
            {

                using (FileStream outFs = new FileStream(outFile, FileMode.Create))
                {
                    outFs.Write(LenK, 0, 4);
                    outFs.Write(LenIV, 0, 4);
                    outFs.Write(keyEncrypted, 0, lKey);
                    outFs.Write(aes.IV, 0, lIV);
                    using (CryptoStream outStreamEncrypted = new CryptoStream(outFs, transform, CryptoStreamMode.Write))
                    {
                        int count = 0;
                        int offset = 0;
                        int blockSizeBytes = aes.BlockSize / 8;
                        byte[] data = new byte[blockSizeBytes];
                        int bytesRead = 0;
                        try
                        {
                            using (FileStream inFs = new FileStream(inFile, FileMode.Open))
                            {
                                do
                                {
                                    count = inFs.Read(data, 0, blockSizeBytes);
                                    offset += count;
                                    outStreamEncrypted.Write(data, 0, count);
                                    bytesRead += blockSizeBytes;
                                }
                                while (count > 0);
                                inFs.Close();
                            }

                        }
                        catch { }

                        outStreamEncrypted.FlushFinalBlock();
                        outStreamEncrypted.Close();
                    }
                    outFs.Close();
                }
                MessageBox.Show("FileEncrypted");
            }
            catch { }
        }
        private void DecryptFile(string inFile)
        {
            Aes aes = Aes.Create();
            byte[] LenK = new byte[4];
            byte[] LenIV = new byte[4];
            string outFile = "";
            try
            {
                outFile = DecryptPath + inFile.Substring(0, inFile.LastIndexOf("."));
            }

            catch
            {
                MessageBox.Show("This file Can't Decrypted Because it hasn't extension");
                RsaCrypt = null;

            }

            try
            {
                using (FileStream inFs = new FileStream(EncryptPath + inFile, FileMode.Open))
                {
                    inFs.Seek(0, SeekOrigin.Begin);
                    inFs.Seek(0, SeekOrigin.Begin);
                    inFs.Read(LenK, 0, 3);
                    inFs.Seek(4, SeekOrigin.Begin);
                    inFs.Read(LenIV, 0, 3);
                    int lenK = BitConverter.ToInt32(LenK, 0);
                    int lenIV = BitConverter.ToInt32(LenIV, 0);
                    int startC = lenK + lenIV + 8;
                    int lenC = (int)inFs.Length - startC;
                    byte[] KeyEncrypted = new byte[lenK];
                    byte[] IV = new byte[lenIV];
                    inFs.Seek(8, SeekOrigin.Begin);
                    inFs.Read(KeyEncrypted, 0, lenK);
                    inFs.Seek(8 + lenK, SeekOrigin.Begin);
                    inFs.Read(IV, 0, lenIV);
                    Directory.CreateDirectory(DecryptPath);
                    try
                    {
                        byte[] KeyDecrypted = RsaCrypt.Decrypt(KeyEncrypted, false);
                        ICryptoTransform transform = aes.CreateDecryptor(KeyDecrypted, IV);
                        using (FileStream outFs = new FileStream(outFile, FileMode.Create))
                        {
                            int count = 0;
                            int offset = 0;
                            int blockSizeBytes = aes.BlockSize / 8;
                            byte[] data = new byte[blockSizeBytes];
                            inFs.Seek(startC, SeekOrigin.Begin);
                            using (CryptoStream outStreamDecrypted = new CryptoStream(outFs, transform, CryptoStreamMode.Write))
                            {
                                do
                                {
                                    count = inFs.Read(data, 0, blockSizeBytes);
                                    offset += count;
                                    outStreamDecrypted.Write(data, 0, count);
                                }
                                while (count > 0);
                                outStreamDecrypted.FlushFinalBlock();
                                outStreamDecrypted.Close();
                            }
                            outFs.Close();
                        }
                        inFs.Close();
                        MessageBox.Show("FileDecrypted");

                    }
                    catch (Exception)
                    {
                        MessageBox.Show("The Key is wrong!");
                    }
                }
            }
            catch { }
        }

        #endregion "Methods"

        #region "Event Handlers"

        private void GetPrivateKey_Button_Click(object sender, EventArgs e)
        {
            if (string.IsNullOrWhiteSpace(Privaatekey.Text))
            {
                MessageBox.Show("The Field is Empty!");
            }
            else
            {
                cssParametrs.KeyContainerName = Privaatekey.Text + Privaatekey.Text;
                RsaCrypt = new RSACryptoServiceProvider(cssParametrs);
                RsaCrypt.PersistKeyInCsp = true;
            }
        }
        private void Decrypt_Button_Click(object sender, RoutedEventArgs e)
        {
            MainPage.Visibility = Visibility.Collapsed;
            DecryptPage.Visibility = Visibility.Visible;
            Privatekey.Text = "";
            Privaatekey.Text = "";
        }
        private void Encrypt_Button_Click(object sender, RoutedEventArgs e)
        {
            MainPage.Visibility = Visibility.Collapsed;
            EncryptPage.Visibility = Visibility.Visible;
            Privatekey.Text = "";
            Privaatekey.Text = "";
        }
        private void Exit_Button_Click(object sender, RoutedEventArgs e)
        {

            DecryptPage.Visibility = Visibility.Collapsed;
            EncryptPage.Visibility = Visibility.Collapsed;
            MainPage.Visibility = Visibility.Visible;
            RsaCrypt = null;
        }
        private void Clear_Button_Click(object sender, RoutedEventArgs e)
        {
            Privatekey.Clear();
            Privaatekey.Clear();
        }
        private void CreateKeysExport_Button_Click(object sender, RoutedEventArgs e)
        {
            if (string.IsNullOrWhiteSpace(Privatekey.Text))
            {
                MessageBox.Show("The Field is Empty!");
            }
            else
            {
                cssParametrs.KeyContainerName = Privatekey.Text + Privatekey.Text;
                RsaCrypt = new RSACryptoServiceProvider(cssParametrs);
                RsaCrypt.PersistKeyInCsp = true;
                Directory.CreateDirectory(EncryptPath);
            }
        }
        private void EncryptFile_Button_Click(object sender, RoutedEventArgs e)
        {
            if (RsaCrypt == null)
            {
                MessageBox.Show("Write Key!");
            }
            else
            {
                OpenFileDialog openFileDialog1 = new OpenFileDialog();
                openFileDialog1.InitialDirectory = WorkFolder;
                openFileDialog1.Filter = "All files (*.*)|*.*";
                if (openFileDialog1.ShowDialog() == true)
                {
                    string fName = openFileDialog1.FileName;
                    if (fName != null)
                    {
                        FileInfo finfo = new FileInfo(fName);
                        string name = finfo.FullName;
                        EncryptFile(name);
                    }
                }
            }

            Privatekey.Text = "";
            Privaatekey.Text = "";
            RsaCrypt = null;
        }
        private void DecryptFile_Button_Click(object sender, RoutedEventArgs e)
        {
            OpenFileDialog openFileDialog2 = new OpenFileDialog();
            if (RsaCrypt == null)
            {
                MessageBox.Show("Write Key!");
            }
            else
            {
                openFileDialog2.InitialDirectory = WorkFolder;
                openFileDialog2.Filter = "All files (*.*)|*.*";
                if (openFileDialog2.ShowDialog() == true)
                {
                    string fName = openFileDialog2.FileName;
                    if (fName != null)
                    {
                        FileInfo fn = new FileInfo(fName);
                        string name = fn.Name;
                        DecryptFile(name);
                    }
                }
            }
            Privatekey.Text = "";
            Privaatekey.Text = "";
            RsaCrypt = null;
        }

        #endregion "Event Handlers"
    }
}

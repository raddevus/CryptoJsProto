<Query Kind="Program">
  <Output>DataGrids</Output>
  <Namespace>System.Security.Cryptography</Namespace>
</Query>

void Main()
{
	EncryptFile(@"C:\Users\roger.deutsch\temp\cyapass.json","xab");
	DecryptFile(@"C:\Users\roger.deutsch\temp\cyapass.json.enc","xab");
}

public byte[] AES_Encrypt(byte[] bytesToBeEncrypted, byte[] passwordBytes)
{
    byte[] encryptedBytes = null;

    // Set your salt here, change it to meet your flavor:
    // The salt bytes must be at least 8 bytes.
    byte[] saltBytes = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };

    using (MemoryStream ms = new MemoryStream())
    {
        using (RijndaelManaged AES = new RijndaelManaged())
        {
            AES.KeySize = 256;
            AES.BlockSize = 128;

            var key = new Rfc2898DeriveBytes(passwordBytes, saltBytes, 1000);
            AES.Key = key.GetBytes(AES.KeySize / 8);
            AES.IV = key.GetBytes(AES.BlockSize / 8);

            AES.Mode = CipherMode.CBC;

            using (var cs = new CryptoStream(ms, AES.CreateEncryptor(), CryptoStreamMode.Write))
            {
                cs.Write(bytesToBeEncrypted, 0, bytesToBeEncrypted.Length);
                cs.Close();
            }
            encryptedBytes = ms.ToArray();
        }
    }

    return encryptedBytes;
}

public byte[] AES_Decrypt(byte[] bytesToBeDecrypted, byte[] passwordBytes)
{
    byte[] decryptedBytes = null;

    // Set your salt here, change it to meet your flavor:
    // The salt bytes must be at least 8 bytes.
    byte[] saltBytes = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };

    using (MemoryStream ms = new MemoryStream())
    {
        using (RijndaelManaged AES = new RijndaelManaged())
        {
            AES.KeySize = 256;
            AES.BlockSize = 128;

            var key = new Rfc2898DeriveBytes(passwordBytes, saltBytes, 1000);
            AES.Key = key.GetBytes(AES.KeySize / 8);
            AES.IV = key.GetBytes(AES.BlockSize / 8);

            AES.Mode = CipherMode.CBC;

            using (var cs = new CryptoStream(ms, AES.CreateDecryptor(), CryptoStreamMode.Write))
            {
                cs.Write(bytesToBeDecrypted, 0, bytesToBeDecrypted.Length);
                cs.Close();
            }
            decryptedBytes = ms.ToArray();
        }
    }

    return decryptedBytes;
}


public void EncryptFile(string clearTextFile, string password)
{
    string file = clearTextFile;

    byte[] bytesToBeEncrypted = File.ReadAllBytes(file);
    byte[] passwordBytes = Encoding.UTF8.GetBytes(password);

    // Hash the password with SHA256
    passwordBytes = SHA256.Create().ComputeHash(passwordBytes);

    byte[] bytesEncrypted = AES_Encrypt(bytesToBeEncrypted, passwordBytes);

    string fileEncrypted = clearTextFile +  ".enc";
	Console.WriteLine($"wrote {fileEncrypted}");
    File.WriteAllBytes(fileEncrypted, bytesEncrypted);
	
}

public void DecryptFile(string cipherTextFile, string password)
{
    string fileEncrypted = cipherTextFile;
    
    byte[] bytesToBeDecrypted = File.ReadAllBytes(fileEncrypted);
    byte[] passwordBytes = Encoding.UTF8.GetBytes(password);
    passwordBytes = SHA256.Create().ComputeHash(passwordBytes);

    byte[] bytesDecrypted = AES_Decrypt(bytesToBeDecrypted, passwordBytes);
	
    string file = Path.GetFileNameWithoutExtension(fileEncrypted);
	file = Path.Combine(Path.GetDirectoryName(fileEncrypted), file);
	Console.WriteLine(file);
    File.WriteAllBytes(file, bytesDecrypted);
}
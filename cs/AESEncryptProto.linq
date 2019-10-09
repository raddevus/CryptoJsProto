<Query Kind="Program">
  <Output>DataGrids</Output>
  <Namespace>System.Security.Cryptography</Namespace>
</Query>

void Main()
{
	var plainText = "This is a an extremely long message <strong> with </strong> CRLF \n and other items in it.";
	SecurityController sc = new SecurityController();
	
	var cipherText = sc.Encrypt("Secret Passphrase", plainText);
	Console.WriteLine(cipherText);
	Console.WriteLine(sc.Decrypt("Secret Passphrase",cipherText));
}



class SecurityController
{
public string Encrypt( string key, string data )
{
  string encData = null;
  byte[][] keys = GetHashKeys(key);

  try
  {
    encData = EncryptStringToBytes_Aes( data, keys[0], keys[1] );
  }
  catch ( CryptographicException ) { }
  catch ( ArgumentNullException ) { }

  return encData;
}

public string Decrypt( string key, string data )
{
  string decData = null;
  byte[][] keys = GetHashKeys(key);

  try
  {
    decData = DecryptStringFromBytes_Aes( data, keys[0], keys[1] );
  }
  catch ( CryptographicException ) { }
  catch ( ArgumentNullException ) { }

  return decData;
}

private byte[][] GetHashKeys( string key)
{
  byte[][] result = new byte[2][];
  Encoding enc = Encoding.UTF8;

  SHA256 sha2 = new SHA256CryptoServiceProvider();

  byte[] rawKey = enc.GetBytes(key);
  byte[] rawIV = enc.GetBytes(key);

  byte[] hashKey = sha2.ComputeHash(rawKey);
  byte[] hashIV = sha2.ComputeHash(rawIV);

  Array.Resize( ref hashIV, 16 );
	result[0] = hashKey;
	result[1] = hashIV;
	Console.WriteLine(BytesToHex(result[0]));
	Console.WriteLine(BytesToHex(result[1]));


  return result;
}

//source: https://msdn.microsoft.com/de-de/library/system.security.cryptography.aes(v=vs.110).aspx
private static string EncryptStringToBytes_Aes( string plainText, byte[] Key, byte[] IV )
{
  if ( plainText == null || plainText.Length <= 0 )
    throw new ArgumentNullException( "plainText" );
  if ( Key == null || Key.Length <= 0 )
    throw new ArgumentNullException( "Key" );
  if ( IV == null || IV.Length <= 0 )
    throw new ArgumentNullException( "IV" );

  byte[] encrypted;

  using ( AesManaged aesAlg = new AesManaged() )
  {
    aesAlg.Key = Key;
    aesAlg.IV = IV;

    ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

    using ( MemoryStream msEncrypt = new MemoryStream() )
    {
      using ( CryptoStream csEncrypt = 
              new CryptoStream( msEncrypt, encryptor, CryptoStreamMode.Write ) )
      {
        using ( StreamWriter swEncrypt = new StreamWriter( csEncrypt ) )
        {
          swEncrypt.Write( plainText );
        }
        encrypted = msEncrypt.ToArray();
      }
    }
  }
  return Convert.ToBase64String( encrypted );
}

private string BytesToHex(byte[] bytes) 
{ 
	// write each byte as two char hex output.
	return String.Concat(Array.ConvertAll(bytes, x => x.ToString("X2"))); 
}

//source: https://msdn.microsoft.com/de-de/library/system.security.cryptography.aes(v=vs.110).aspx
private static string DecryptStringFromBytes_Aes( string cipherTextString, byte[] Key, byte[] IV )
{
  byte[] cipherText = Convert.FromBase64String(cipherTextString);

  if ( cipherText == null || cipherText.Length <= 0 )
    throw new ArgumentNullException( "cipherText" );
  if ( Key == null || Key.Length <= 0 )
    throw new ArgumentNullException( "Key" );
  if ( IV == null || IV.Length <= 0 )
    throw new ArgumentNullException( "IV" );

  string plaintext = null;

  using ( Aes aesAlg = Aes.Create() )
  {
    aesAlg.Key = Key;
    aesAlg.IV = IV;

    ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

    using ( MemoryStream msDecrypt = new MemoryStream( cipherText ) )
    {
      using ( CryptoStream csDecrypt = 
              new CryptoStream( msDecrypt, decryptor, CryptoStreamMode.Read ) )
      {
        using ( StreamReader srDecrypt = new StreamReader( csDecrypt ) )
        {
          plaintext = srDecrypt.ReadToEnd();
        }
      }
    }
  }
  return plaintext;
}
}

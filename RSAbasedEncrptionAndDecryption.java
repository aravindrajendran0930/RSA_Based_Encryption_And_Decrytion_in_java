

import javax.crypto.Cipher;
import java.math.BigInteger;
import java.security.KeyPairGenerator;
import java.io.BufferedOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;


public class RSAbasedEncrptionAndDecryption {

 private static String PublicKeyStore = "Public.key";
 private static String PrivateKeyStore = "Private.key";
 
 public static void main(String[] args) throws IOException {

  try {
   System.out.println("Public and Private key generation and storing into file");
   KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
   keyPairGenerator.initialize(1024);
   KeyPair newkeyPair = keyPairGenerator.generateKeyPair();
   PublicKey publicKey = newkeyPair.getPublic();
   PrivateKey privateKey = newkeyPair.getPrivate();
   KeyFactory keyFactory = KeyFactory.getInstance("RSA");
   RSAPublicKeySpec publicKeySpec = keyFactory.getKeySpec(publicKey, RSAPublicKeySpec.class);
   RSAPrivateKeySpec privateKeySpec = keyFactory.getKeySpec(privateKey, RSAPrivateKeySpec.class);
   RSAbasedEncrptionAndDecryption savingKeys = new RSAbasedEncrptionAndDecryption();
   savingKeys.saveKeys(PublicKeyStore, publicKeySpec.getModulus(), publicKeySpec.getPublicExponent());
   savingKeys.saveKeys(PrivateKeyStore, privateKeySpec.getModulus(), privateKeySpec.getPrivateExponent());
   System.out.println("Public Key -> Modulus : " + publicKeySpec.getModulus());
   System.out.println("Exponent : " + publicKeySpec.getPublicExponent());
   System.out.println("Private Key Modulus : " + privateKeySpec.getModulus());
   System.out.println("Private Key Modulus : " + privateKeySpec.getModulus());
   System.out.println("Private Key Modulus : " + privateKeySpec.getModulus());
   System.out.println("Exponent : " + privateKeySpec.getPrivateExponent());
   String plainTextInitial = "“Our names are Aravind and Abhishek. We are enrolled in CSE 539.";
   System.out.println("Data Before Encryption :" + plainTextInitial);
   byte[] data1 = plainTextInitial.getBytes();
   byte[] encryptedData = null;
    PublicKey pubKey = fetchPublicKeyFromStore(PublicKeyStore);
    Cipher cipher = Cipher.getInstance("RSA");
    cipher.init(Cipher.ENCRYPT_MODE, pubKey);
    encryptedData = cipher.doFinal(data1);
    System.out.println("Data After Encryption : " + encryptedData);
   byte[] plaintext = null;
    PrivateKey privateKey1 = fetchPrivateKeyFromStore(PrivateKeyStore);
    Cipher decryptCipher = Cipher.getInstance("RSA");
    decryptCipher.init(Cipher.DECRYPT_MODE, privateKey1);
    plaintext = decryptCipher.doFinal(encryptedData);
    System.out.println("Plaintext after Decryption: " + new String(plaintext));
 }
  catch (Exception e) {
	    throw new IOException("Unexpected error", e);
	  } 
 }

 void saveKeys(String fileName,BigInteger mod,BigInteger exp) throws Exception{
	 ObjectOutputStream oos = new ObjectOutputStream(
	new BufferedOutputStream(new FileOutputStream(fileName)));
	try {
		oos.writeObject(mod);
		oos.writeObject(exp);
		oos.close();
	} catch (Exception e) {
		throw new IOException("Unexpected error", e);
	} 
  }
 
 public static PublicKey fetchPublicKeyFromStore(String fileName) throws Exception{
  FileInputStream fi = null;
  ObjectInputStream oi = null;
  try {
   fi = new FileInputStream(new File(fileName));
   oi = new ObjectInputStream(fi);
   
      BigInteger modulus = (BigInteger) oi.readObject();
      BigInteger exponent = (BigInteger) oi.readObject();
      RSAPublicKeySpec rsaPublicKeySpec = new RSAPublicKeySpec(modulus, exponent);
      KeyFactory keyFact = KeyFactory.getInstance("RSA");
      PublicKey publicKey = keyFact.generatePublic(rsaPublicKeySpec);
      oi.close();   
      return publicKey;
      
  } catch (Exception e) {
   e.printStackTrace();
  }
  return null;
  }
 
 public static PrivateKey fetchPrivateKeyFromStore(String fileName) throws Exception{
  FileInputStream fi = null;
  ObjectInputStream oi = null;
  try {
   fi = new FileInputStream(new File(fileName));
   oi = new ObjectInputStream(fi);
   
   BigInteger modulus = (BigInteger) oi.readObject();
      BigInteger exponent = (BigInteger) oi.readObject();
      RSAPrivateKeySpec rsaPrivateKeySpec = new RSAPrivateKeySpec(modulus, exponent);
      KeyFactory keyFact = KeyFactory.getInstance("RSA");
      PrivateKey privateKey = keyFact.generatePrivate(rsaPrivateKeySpec);
      oi.close();    
      return privateKey;
      
  } catch (Exception e) {
   e.printStackTrace();
  }
  return null;
 }
}

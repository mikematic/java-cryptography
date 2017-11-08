package com.javacrypto;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.Cipher;

public class CipherAsymmetricImpl {
	/*
	 * Using standard Java libraries to encrypt and decrypt a data using Asymmetric
	 * key algorithm (Public/Private key pair). Data encrypted by
	 * private key can only be decrypted using the public key pair. Also, data
	 * encrypted by public key can only be decrypted using a private key.
	 * 
	 * Note: Asymmetric algorithms (such as RSA) are generally much slower than
	 * symmetric ones. These algorithms are not designed for efficiently protecting
	 * large amounts of data. In practice, asymmetric algorithms are used to
	 * exchange smaller secret keys which are used to initialize symmetric
	 * algorithms.
	 * 
	 */

	public static void main(String[] args) throws Exception {
		String theText = "abc456";
		byte[] asciiByteArr = theText.getBytes("UTF-8");
		System.out.println("String to Charset Array:" + theText + " ===> " + Arrays.toString(asciiByteArr));

		// Step 1 - Generate the public and private key using a key pair generator
		//
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
		keyPairGenerator.initialize(1024);
		KeyPair keyPair = keyPairGenerator.generateKeyPair();
		PrivateKey privKey = keyPair.getPrivate();
		PublicKey pubKey = keyPair.getPublic();

		// Step 2 - Encrypt data using Public Key
		// Initialize Cipher object with the transformation algorithm and the public key
		Cipher encryptingCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		encryptingCipher.init(Cipher.ENCRYPT_MODE, pubKey);

		// Encrypt the data
		byte[] encryptedByteArr = encryptingCipher.doFinal(asciiByteArr);

		// Encode the encrypted byte array to base 64
		String encryptedString = Base64.getEncoder().encodeToString(encryptedByteArr);
		System.out.println("Encrypted Byte Array: " + Arrays.toString(asciiByteArr) + " ===> "
				+ Arrays.toString(encryptedByteArr));
		System.out.println("Encrypted byte array encoded to Base64 String: " + encryptedString);

		// Step 3 - Decrypt the data using the private key
		// Initialize Cipher object with the transformation algorithm and the private
		// key
		encryptedByteArr = Base64.getDecoder().decode(encryptedString); // Decode string from Base64 to byte array
		Cipher decryptingCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		decryptingCipher.init(Cipher.DECRYPT_MODE, privKey);
		byte[] decryptedByteArr = decryptingCipher.doFinal(encryptedByteArr);
		String decryptedString = new String(decryptedByteArr, "UTF-8");
		System.out.println("Decrypted String: " + decryptedString);

	}
}

package com.javacrypto;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.AlgorithmParameters;
import java.security.Key;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.SealedObject;
import javax.crypto.SecretKey;

public class CipherSymmetricImpl {
	/*
	 * Using standard Java libraries to encrypt and decrypt a data using symmetric
	 * key algorithm. In other words one secret key is used to encrypt as well as
	 * decrypt the data. The converse of this implementation is asymmetric
	 * encryption also known as Public/Private key pair cipher.
	 * 
	 * Note: Symmetric ciphers are generally much faster than asymmetric ones.
	 * However, since there is only one key for encryption and decryption it
	 * requires another cipher to exchange this key in the open (e.g internet).
	 * Hence, it is very common to see symmetric cipher being used along asymmetric
	 * cipher in the real world. A good example of this is data transfer between
	 * client browser and web server over HTTPS. When a client browser first
	 * connects to a web server over HTTPS, it requests the server for its public
	 * key. The browser then verifies the public certificate for integrity using its
	 * CA store. After verification, the browser generates a secret-key that will be
	 * used to encrypt and decrypt data for that session. The browser encrypts this
	 * secret key using the public key of the web server and sends it to the web
	 * server. The webserver uses its private key to decrypt the data and unveil the
	 * secret-key. The webserver then encrypts the webcontent using this secret key
	 * and sends it to the browser. All communications after this stage are
	 * encrypted and decrypted using the secret key.
	 * 
	 */
	public static void main(String[] args) throws Exception {
		String theText = "abc456";
		byte[] asciiByteArr = theText.getBytes();
		System.out.println("String to Charset Array:" + theText + " ===> " + Arrays.toString(asciiByteArr));

		// Step 1
		// Obtain an instance of key generator engine with the specified algorithm. Then
		// generate the
		// secret key to be used by the cipher.
		//
		SecretKey secretKey = KeyGenerator.getInstance("DES").generateKey();

		// Step 2a - Encrypting to a byte array
		// Obtain an instance of the Cipher object and pass the transformation algorithm
		// as
		// parameters. The format for the transformation is Algorithm/Mode/Padding.
		// Note: You can pass only the algorithm and the engine uses the default for
		// Mode and Padding.
		//
		Cipher baseCipher = Cipher.getInstance("DES/CBC/PKCS5PADDING");
		baseCipher.init(Cipher.ENCRYPT_MODE, secretKey);
		baseCipher.update(asciiByteArr);
		byte[] encryptedText = baseCipher.doFinal();
		System.out.println(
				"Step 1: Encryption: " + Arrays.toString(asciiByteArr) + " ===> " + Arrays.toString(encryptedText));

		// Some algorithms require parameters some don't. If it requires parameters, it
		// needs to be given to
		// the user who will be decrypting it.
		AlgorithmParameters algParams = baseCipher.getParameters();
		System.out.println("Step 2: Algorithm Parameters are : " + Arrays.toString(algParams.getEncoded()));

		// Wrap the secret key for a secure transfer (Additional security)
		Key wrapKey = KeyGenerator.getInstance("AES").generateKey();
		Cipher wrappingCipher = Cipher.getInstance("AES");
		wrappingCipher.init(Cipher.WRAP_MODE, wrapKey);
		byte[] wrappedKey = wrappingCipher.wrap(secretKey);

		// Step 2b - Decrypting from a byte array.
		//
		// First, Unwrap the key and obtain the secret key...
		Cipher unWrappingCipher = Cipher.getInstance("AES");
		unWrappingCipher.init(Cipher.UNWRAP_MODE, wrapKey);
		secretKey = (SecretKey) unWrappingCipher.unwrap(wrappedKey, "DES", Cipher.SECRET_KEY);
		// Use the recovered secret key to decrypt the data
		baseCipher = Cipher.getInstance("DES/CBC/PKCS5PADDING");
		baseCipher.init(Cipher.DECRYPT_MODE, secretKey, algParams);
		baseCipher.update(encryptedText);
		byte[] decryptedText = baseCipher.doFinal();
		System.out.println(
				"Step 3: Decryption: " + Arrays.toString(encryptedText) + " ===> " + Arrays.toString(decryptedText));

		// Step 3a - Encrypting to a file
		// The CipherOutputStream object takes a Cipher object initialized for
		// encryption and writes the
		// encrypted output to the file.
		//
		CipherOutputStream cos = new CipherOutputStream(new FileOutputStream("CipherOut.txt"), baseCipher);
		cos.write(asciiByteArr, 0, asciiByteArr.length);
		cos.flush();
		cos.close();

		// Step 3b - Decrypting from a file
		// - Use the Cipher initialized for decrypting
		//
		byte[] buffer = new byte[16];
		CipherInputStream cis = new CipherInputStream(new FileInputStream("CipherOut.txt"), baseCipher);
		while (cis.read(buffer) != -1) {
			System.out.println("Step 4: Decryption from file: " + Arrays.toString(buffer));
		}

		// Step 4a - Encrypting to a sealed object
		//
		Key sealingKey = KeyGenerator.getInstance("AES").generateKey();
		Cipher sealingCipher = Cipher.getInstance("AES");
		sealingCipher.init(Cipher.ENCRYPT_MODE, sealingKey);
		SealedObject so = new SealedObject(new String(theText), sealingCipher);

		// Step 4b - decrypting from a sealed object
		// - Use the Cipher initialized for decrypting
		//
		sealingCipher.init(Cipher.DECRYPT_MODE, sealingKey);
		String theString = (String) so.getObject(sealingCipher);
		System.out.println("Step 4b: Decryption from sealed object: " + theString);
	}
}

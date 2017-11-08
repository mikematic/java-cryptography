package com.javacryptography;

import java.util.Arrays;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;

public class MacAuthImpl {
	/**
	 * Using standard Java libraries to perform a Hash-based message authentication
	 * code (HMAC) for verifying data integrity and authentication
	 * 
	 */
	public static void main(String[] args) throws Exception {
		// Generate secret key for HMAC-MD5
		KeyGenerator kg = KeyGenerator.getInstance("HmacMD5");
		SecretKey sk = kg.generateKey();

		// Get instance of Mac object implementing HMAC-MD5 algorithm and
		// initialize it with the above secret key
		Mac mac = Mac.getInstance("HmacMD5");
		mac.init(sk);
		byte[] result = mac.doFinal("Hi There".getBytes());
		System.out.println(
				"Conversion is " + Arrays.toString("Hi There".getBytes()) + " ===> " + Arrays.toString(result));
		byte[] recoverBack = mac.doFinal(result);
		System.out.println("Decryption is " + Arrays.toString(recoverBack));
	}
}

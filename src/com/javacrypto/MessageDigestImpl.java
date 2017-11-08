package com.javacrypto;

import java.security.MessageDigest;
import java.security.Provider;
import java.security.Security;
import java.util.Arrays;

public class MessageDigestImpl {
	/*
	 * Using standard Java libraries to digest a data and output a hexadecimal
	 * encoded string (hashing). This is used commonly for storing passwords and
	 * other sensitive information in the database. It is also used for doing
	 * checksums and verifying integrity of files. Below are the three main steps
	 * involved in the process.
	 * 
	 */
	public static void main(String[] args) throws Exception {
		String theText = "abc456";

		// Step 1
		// Convert the string "abcd" to an array of bytes that contains ASCII map value
		// of each character
		// Using ASCII mapping the string "abc456" translates to a byte array [97, 98,
		// 99, 52, 53, 54].
		// Note that 97 is ASCII map value for character "a", 54 for 6 and so forth.
		//
		byte[] asciiByteArr = theText.getBytes();
		System.out.println("String to ASCII char mapping: " + theText + " => " + Arrays.toString(asciiByteArr));
		Provider provider = Security.getProvider("SUN");
		MessageDigest algorithm = MessageDigest.getInstance("MD5", provider);
		algorithm.reset();
		algorithm.update(asciiByteArr);

		// Step 2
		// Convert the array of ASCII mapping to an array of integers based on the
		// algorithm chosen above.
		// This array is of fixed length; 16 for MD5 and 20 for SHA1.
		// Note that MD5 is called 16 bit and SHA1 20 bit for this reason.
		// Using MD5, [97, 98, 99] translates to [-112, 1, 80, -104, 60, -46, 79, -80,
		// -42, -106, 63, 125, 40, -31, 127, 114]
		//
		byte digestedMessage[] = algorithm.digest();
		System.out.println("ASCII to encrypted values" + Arrays.toString(asciiByteArr) + " => "
				+ Arrays.toString(digestedMessage));

		// Step 3
		// For each element in the digested message array
		// a) Perform bitwise operation with the hexadecimal string FF
		// b) Convert the result from above to a hexadecimal string
		// c) Concatenate all the hexadecimal strings as one string.
		// d) Apply salting to prevent brute force (*Not implemented below)
		// Note, JVM treats any identifier that begins with "0x" as a hex string
		//
		StringBuffer hexString = new StringBuffer();
		int bitWiseOperationResult;
		for (int element : digestedMessage) {
			// Perform bitwise operation
			bitWiseOperationResult = 0xFF & element;
			// Concatenate the result from above
			hexString.append(Integer.toHexString(bitWiseOperationResult));
			// System.out.println("BitWise operation result on 0xFF and " +
			// digestedMessage[i] + " is " + bitWiseOperationResult);
			// System.out.println("Integer result converted to HexString is "
			// +Integer.toHexString(bitWiseOperationResult));
		}
		System.out.println("Encrypted Array to Hexadecimal String" + Arrays.toString(digestedMessage) + " => "
				+ hexString.toString());

	}
}

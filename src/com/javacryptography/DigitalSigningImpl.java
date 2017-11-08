package com.javacryptography;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.DSAPrivateKeySpec;
import java.security.spec.DSAPublicKeySpec;

public class DigitalSigningImpl {

	/*
	 * Using standard Java libraries to perform digital signing of data for
	 * authenticity and integrity. The two methods show how to digitally sign a data
	 * using either a keygen or a keyfactory. 
	 * 
	 */
	public static void signUsingKeyGen() throws Exception {
		String theText = "abc456";
		byte[] asciiByteArr = theText.getBytes();

		// Step 1 - Create public and private key
		// Obtain an instance of key pair generator engine with the specified
		// algorithm. Then use a well seeded random object to initialize the
		// engine in order to generate the public/private key pairs.
		//
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DSA");
		SecureRandom random = SecureRandom.getInstance("SHA1PRNG", "SUN");
		byte[] seed = { 12, 31, 23, 44 };
		random.setSeed(seed);
		keyGen.initialize(1024, random);
		KeyPair pair = keyGen.generateKeyPair();
		PrivateKey privKey = pair.getPrivate();
		PublicKey pubKey = pair.getPublic();

		// Step 2 - Sign the data
		// Use the private key to initialize the Signature object and sign the data
		//
		Signature senderSigObj = Signature.getInstance("SHA1withDSA");
		senderSigObj.initSign(privKey);
		senderSigObj.update(asciiByteArr);
		byte[] signature = senderSigObj.sign();

		// Verification by recipient
		// Recipient receives the public key, signature and data.
		// Use the public key to initialize the signature object.
		// Then input the data and signature to the object for verification.
		//
		Signature receiverSigObj = Signature.getInstance("SHA1withDSA");
		receiverSigObj.initVerify(pubKey);
		receiverSigObj.update(asciiByteArr);
		boolean verifies = receiverSigObj.verify(signature);
		System.out.println("1. signature verifies: " + verifies);
	}

	/*
	 * Generating/Verifying Signatures using KeyFactory
	 */
	public static void signUsingKeyFactory() throws Exception {
		String theText = "abc456";
		byte[] asciiByteArr = theText.getBytes();

		// Step 1 - Initialize key spec for public and private key
		//
		BigInteger privKeySpec = BigInteger.valueOf(207);
		BigInteger pubKeySpec = BigInteger.valueOf(209);
		BigInteger primeSpec = BigInteger.valueOf(293);
		BigInteger subPrimeSpec = BigInteger.valueOf(149);
		BigInteger baseSpec = BigInteger.valueOf(253);

		// Step 2 - Create public and private key
		// Obtain an instance of key factory engine based on the specification of the
		// KeySpec.
		// Then use key factory to generate the public/private key pairs.
		//
		DSAPrivateKeySpec dsaPrivKeySpec = new DSAPrivateKeySpec(privKeySpec, primeSpec, subPrimeSpec, baseSpec);
		DSAPublicKeySpec dsaPubKeySpec = new DSAPublicKeySpec(pubKeySpec, primeSpec, subPrimeSpec, baseSpec);
		KeyFactory keyFactory = KeyFactory.getInstance("DSA");
		PrivateKey privKey = keyFactory.generatePrivate(dsaPrivKeySpec);
		PublicKey pubKey = keyFactory.generatePublic(dsaPubKeySpec);

		// Step 3 - Sign the data
		// Use the private key to initialize the Signature object and sign the data
		Signature senderSigObj = Signature.getInstance("SHA1withDSA");
		senderSigObj.initSign(privKey);
		senderSigObj.update(asciiByteArr);
		byte[] signature = senderSigObj.sign();

		// Verification by recipient
		// Recipient receives the public key, signature and data.
		// Use the public key to initialize the signature object.
		// Then input the data and signature to the object for verification.
		//
		Signature receiverSigObj = Signature.getInstance("SHA1withDSA");
		receiverSigObj.initVerify(pubKey);
		receiverSigObj.update(asciiByteArr);
		boolean verifies = receiverSigObj.verify(signature);
		System.out.println("2. signature verifies: " + verifies);
	}

	public static void main(String[] args) throws Exception {
		signUsingKeyGen();
		signUsingKeyFactory();
	}
}

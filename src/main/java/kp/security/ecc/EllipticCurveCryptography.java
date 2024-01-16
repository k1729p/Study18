package kp.security.ecc;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.EnumMap;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyAgreement;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import kp.utils.Printer;
import kp.utils.Utils;

/*- http://netnix.org/2015/04/19/aes-encryption-with-hmac-integrity-in-java/#more-544 */

/**
 * The Elliptic-curve Cryptography.
 * 
 */
public class EllipticCurveCryptography {

	private static final String ALGORITHM_AES = "AES";
	private static final String ALGORITHM_AES_GCM_NO_PADDING = "AES/GCM/NoPadding";
	private static final String ALGORITHM_SHA3_256 = "SHA3-256";
	private static final String ALGORITHM_EC = "EC";
	private static final String ALGORITHM_ECDH = "ECDH";
	private static final String ALGORITHM_SHA3_512_WITH_ECDSA = "SHA3-512withECDSA";
	private static final String STANDARD_NAME = "secp256r1";

	private static final String CLEARTEXT = "ĄĆĘ ŁŃÓ ŚŻŹ ąćę łńó śżź";

	/**
	 * The constructor.
	 */
	public EllipticCurveCryptography() {
		super();
	}

	/**
	 * Launches encrypted texts exchange.
	 * 
	 */
	public static void launch() {

		try {
			new EllipticCurveCryptography().launchWithSecurityExceptionsThrowing();
		} catch (Exception e) {
			Printer.printExc(e);
			System.exit(1);
		}
		Printer.printHor();
	}

	/**
	 * Launches encrypted texts exchange.
	 * 
	 * @throws NoSuchAlgorithmException           the security exception
	 * @throws InvalidAlgorithmParameterException the security exception
	 * @throws InvalidKeySpecException            the security exception
	 * @throws InvalidKeyException                the security exception
	 * @throws SignatureException                 the security exception
	 * @throws IllegalBlockSizeException          the cryptography exception
	 * @throws BadPaddingException                the cryptography exception
	 * @throws NoSuchPaddingException             the cryptography exception
	 */
	private void launchWithSecurityExceptionsThrowing() throws NoSuchAlgorithmException,
			InvalidAlgorithmParameterException, InvalidKeySpecException, InvalidKeyException, SignatureException,
			IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException {

		/*-
		 * Initialize three boxes with personal data and
		 * a link between given person and its counterpart.
		 */
		final EnumMap<Person, PrivateBox> privateBoxMap = new EnumMap<>(Person.class);
		final EnumMap<Person, PublicStaticBox> publicStaticBoxMap = new EnumMap<>(Person.class);
		final EnumMap<Person, PublicEphemeralBox> publicEphemeralBoxMap = new EnumMap<>(Person.class);
		final EnumMap<Person, Person> counterpartMap = new EnumMap<>(Person.class);
		for (Person person : Person.values()) {
			privateBoxMap.put(person, new PrivateBox());
			publicStaticBoxMap.put(person, new PublicStaticBox());
			publicEphemeralBoxMap.put(person, new PublicEphemeralBox());
		}
		counterpartMap.put(Person.ALICE, Person.BOB);
		counterpartMap.put(Person.BOB, Person.ALICE);

		final KeyPairGenerator keyPairGenerator = initKeyPairGenerator();
		final MessageDigest messageDigest = MessageDigest.getInstance(ALGORITHM_SHA3_256);
		/*
		 * Generate private keys and public static keys.
		 */
		for (Person person : Person.values()) {
			generateKeyPairECDSA(privateBoxMap.get(person), publicStaticBoxMap.get(person), keyPairGenerator);
			Printer.printf("Person[%1$5s], public ECDSA SHA3-512 hash[%2$x]", person.name(),
					new BigInteger(1, messageDigest.digest(publicStaticBoxMap.get(person).publicKeyECDSA)));
		}
		Printer.print("→ → →          Session start                ← ← ←");
		/*-
		 Generate public ephemeral keys.
		 
		 Ephemeral keys: a new public/private key pair per session.
		 A public-key system has the property of forward secrecy
		 if it generates one random secret key per session.
		 */
		for (Person person : Person.values()) {
			generateKeyPairECDH(privateBoxMap.get(person), publicEphemeralBoxMap.get(person), keyPairGenerator);
			signPublicKeyECDHWithPrivateKeyECDSA(privateBoxMap.get(person), publicEphemeralBoxMap.get(person));
			Printer.printf("Person[%1$5s], public ECDH  SHA3-256 hash[%2$x]", person.name(),
					new BigInteger(1, messageDigest.digest(publicEphemeralBoxMap.get(person).publicKeyECDH)));
		}
		for (Person person : Person.values()) {
			final Person counterpart = counterpartMap.get(person);
			verifyCounterpartPublicKeys(person.name(), publicStaticBoxMap.get(counterpart),
					publicEphemeralBoxMap.get(counterpart));
			computeSecretKey(person.name(), privateBoxMap.get(person), publicEphemeralBoxMap.get(counterpart));
		}
		/*-
		Person and its counterpart have the same authenticated 128-bit shared secret
		which they use with AES-GCM algorithm.
		*/
		Printer.print("▼ ▼ ▼          Cleartext exchange           ▼ ▼ ▼");
		for (Person person : Person.values()) {
			/*-
			The person encrypts the text for its counterpart using his/her shared secret.
			*/
			final String ciphertext = encrypt(CLEARTEXT, privateBoxMap.get(person).sharedSecret);
			Printer.printf("Person[%5s], ciphertext[%s]", person.name(), ciphertext);
			/*-
			The counterpart decrypts the text from person using his/her shared secret.
			*/
			final Person counterpart = counterpartMap.get(person);
			final String cleartext = decrypt(ciphertext, privateBoxMap.get(counterpart).sharedSecret);
			Printer.printf("Person[%5s], cleartext[%s]", counterpart.name(), cleartext);
		}
		Printer.print("▲ ▲ ▲                                       ▲ ▲ ▲");
	}

	/**
	 * Initializes the key pair generator.<br>
	 * Generates keypair items for the Elliptic Curve algorithm.
	 * 
	 * @return the key pair generator
	 * @throws NoSuchAlgorithmException           the security exception
	 * @throws InvalidAlgorithmParameterException the security exception
	 */
	private KeyPairGenerator initKeyPairGenerator()
			throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {

		final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(ALGORITHM_EC);
		keyPairGenerator.initialize(new ECGenParameterSpec(STANDARD_NAME));
		return keyPairGenerator;
	}

	/**
	 * Generates the Elliptic-Curve Digital Signature Algorithm key pair.
	 * 
	 * @param privateBox       the private box
	 * @param publicStaticBox  the public static box
	 * @param keyPairGenerator the key pair generator
	 */
	private void generateKeyPairECDSA(PrivateBox privateBox, PublicStaticBox publicStaticBox,
			KeyPairGenerator keyPairGenerator) {

		/*-
		Person:
		1. generates a static ECDSA Key Pair
		2. securely stores her/his ECDSA Private Key on disk using symmetric encryption
		3. sends his/her ECDSA Public Key to counterpart person
		*/
		final KeyPair keyPair = keyPairGenerator.generateKeyPair();
		privateBox.privateKeyECDSA = keyPair.getPrivate();
		publicStaticBox.publicKeyECDSA = keyPair.getPublic().getEncoded();
	}

	/**
	 * Generates the Elliptic-Curve Diffie-Hellman key pair.
	 * 
	 * @param privateBox         the private box
	 * @param publicEphemeralBox the public ephemeral box
	 * @param keyPairGenerator   the key pair generator
	 */
	private void generateKeyPairECDH(PrivateBox privateBox, PublicEphemeralBox publicEphemeralBox,
			KeyPairGenerator keyPairGenerator) {
		/*-
		Person:
		1. generates an ephemeral ECDH Key Pair
		*/
		final KeyPair keyPair = keyPairGenerator.genKeyPair();
		privateBox.privateKeyECDH = keyPair.getPrivate();
		publicEphemeralBox.publicKeyECDH = keyPair.getPublic().getEncoded();
	}

	/**
	 * Signs the Elliptic-Curve Diffie-Hellman public key with<br>
	 * the Elliptic-Curve Digital Signature Algorithm private key.
	 * 
	 * @param privateBox         the private box
	 * @param publicEphemeralBox the public ephemeral box
	 * @throws InvalidKeyException      the security exception
	 * @throws NoSuchAlgorithmException the security exception
	 * @throws SignatureException       the security exception
	 */
	private void signPublicKeyECDHWithPrivateKeyECDSA(PrivateBox privateBox, PublicEphemeralBox publicEphemeralBox)
			throws InvalidKeyException, NoSuchAlgorithmException, SignatureException {
		/*-
		Person:
		1. signs her/his ephemeral ECDH Public Key with his/her static ECDSA Private Key
		2. sends her/his ephemeral ECDH Public Key with the ECDSA Signature to counterpart
		*/
		final Signature signatureForSigning = Signature.getInstance(ALGORITHM_SHA3_512_WITH_ECDSA);
		signatureForSigning.initSign(privateBox.privateKeyECDSA);
		signatureForSigning.update(publicEphemeralBox.publicKeyECDH);
		publicEphemeralBox.signatureECDSA = signatureForSigning.sign();
	}

	/**
	 * Verifies counterpart public keys.
	 * 
	 * @param name                          the name of the person
	 * @param counterpartPublicStaticBox    the counterpart public static box
	 * @param counterpartPublicEphemeralBox the counterpart public ephemeral box
	 * @throws InvalidKeyException      the security exception
	 * @throws NoSuchAlgorithmException the security exception
	 * @throws SignatureException       the security exception
	 * @throws InvalidKeySpecException  the security exception
	 */
	private void verifyCounterpartPublicKeys(String name, PublicStaticBox counterpartPublicStaticBox,
			PublicEphemeralBox counterpartPublicEphemeralBox)
			throws InvalidKeyException, NoSuchAlgorithmException, SignatureException, InvalidKeySpecException {

		final PublicKey verifiedPublicKeyECDSA = verifyCounterpartPublicKeyECDSA(counterpartPublicStaticBox);
		final MessageDigest messageDigest = MessageDigest.getInstance(ALGORITHM_SHA3_256);
		Printer.printf("Cntrp.[%1$5s], public ECDSA SHA3-512 hash[%2$x] verified", name,
				new BigInteger(1, messageDigest.digest(verifiedPublicKeyECDSA.getEncoded())));
		verifyCounterpartPublicKeyECDH(counterpartPublicEphemeralBox, verifiedPublicKeyECDSA);
	}

	/**
	 * Verifies counterpart Elliptic-Curve Digital Signature Algorithm public key.
	 * 
	 * @param counterpartPublicStaticBox the counterpart public static box
	 * @return the verified public ECDSA key
	 * @throws InvalidKeySpecException  the security exception
	 * @throws NoSuchAlgorithmException the security exception
	 */
	private PublicKey verifyCounterpartPublicKeyECDSA(PublicStaticBox counterpartPublicStaticBox)
			throws InvalidKeySpecException, NoSuchAlgorithmException {
		/*-
		Person:
		1. recovers counterpart's ECDSA Public Key and verifies SHA3-512 Hash Offline
		2. once verified, person should keep this verified ECDSA Public Key for future authentications
		*/
		final KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM_EC);
		final KeySpec keySpec = new X509EncodedKeySpec(counterpartPublicStaticBox.publicKeyECDSA);
		return keyFactory.generatePublic(keySpec);
	}

	/**
	 * Verifies counterpart Elliptic-Curve Diffie-Hellman public key.
	 * 
	 * @param counterpartPublicEphemeralBox the counterpart public ephemeral box
	 * @param verifiedPublicKeyECDSA        the verified public key ECDSA
	 * @throws InvalidKeyException      the security exception
	 * @throws NoSuchAlgorithmException the security exception
	 * @throws SignatureException       the security exception
	 */
	private void verifyCounterpartPublicKeyECDH(PublicEphemeralBox counterpartPublicEphemeralBox,
			PublicKey verifiedPublicKeyECDSA) throws InvalidKeyException, NoSuchAlgorithmException, SignatureException {

		/*-
		Person:
		1. verifies counterpart's ephemeral ECDH Public Key with ECDSA Signature
		   using counterpart's trusted ECDSA Public Key
		*/
		final Signature signatureForVerification = Signature.getInstance(ALGORITHM_SHA3_512_WITH_ECDSA);
		signatureForVerification.initVerify(verifiedPublicKeyECDSA);
		signatureForVerification.update(counterpartPublicEphemeralBox.publicKeyECDH);

		if (!signatureForVerification.verify(counterpartPublicEphemeralBox.signatureECDSA)) {
			Printer.print("Error: person can't verify signature of counterpart's Public Key ECDH");
			System.exit(0);
		}
	}

	/**
	 * Computes the Shared Secret Key by combining two keys:
	 * <ul>
	 * <li>the local private key
	 * <li>the received public key
	 * </ul>
	 * 
	 * @param name                          the name of the person
	 * @param privateBox                    the private box
	 * @param counterpartPublicEphemeralBox the counterpart public ephemeral box
	 * @throws InvalidKeyException      the security exception
	 * @throws NoSuchAlgorithmException the security exception
	 * @throws InvalidKeySpecException  the security exception
	 */
	private void computeSecretKey(String name, PrivateBox privateBox, PublicEphemeralBox counterpartPublicEphemeralBox)
			throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException {
		/*-
		Person:
		1. generates Secret Key using
		   a. person's ECDH Private Key and
		   b. counterpart's verified ECDH Public Key
		*/
		final KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM_EC);
		// convert received byte array back into Diffie-Hellman Public Key
		final KeySpec keySpec = new X509EncodedKeySpec(counterpartPublicEphemeralBox.publicKeyECDH);
		final PublicKey counterpartPublicKeyECDH = keyFactory.generatePublic(keySpec);
		/*
		 * Key agreement is a protocol by which 2 or more parties can establish the same
		 * cryptographic keys, without having to exchange any secret information.
		 */
		final KeyAgreement keyAgreement = KeyAgreement.getInstance(ALGORITHM_ECDH);
		keyAgreement.init(privateBox.privateKeyECDH);
		keyAgreement.doPhase(counterpartPublicKeyECDH, true);
		final MessageDigest messageDigest = MessageDigest.getInstance(ALGORITHM_SHA3_256);
		/*- Use the first 128 bits (i.e. 16 bytes)
		 *  of the SHA3-256 hash of the 256-bit shared secret key */
		privateBox.sharedSecret = Arrays.copyOfRange(messageDigest.digest(keyAgreement.generateSecret()), 0, 16);

		Printer.printf("Person[%5s], shared secret[%s]", name, Utils.bytesToHexAndUtf(privateBox.sharedSecret));
	}

	/**
	 * Encrypts using the AES-GCM algorithm.<br>
	 * (algorithm: Advanced Encryption Standard, mode: Galois/Counter Mode).
	 * 
	 * @param cleartext the cleartext
	 * @param secret    the secret
	 * @return the encrypted
	 * @throws NoSuchAlgorithmException           the security exception
	 * @throws IllegalBlockSizeException          the cryptography exception
	 * @throws BadPaddingException                the cryptography exception
	 * @throws InvalidKeyException                the security exception
	 * @throws InvalidAlgorithmParameterException the security exception
	 * @throws NoSuchPaddingException             the cryptography exception
	 */
	private String encrypt(String cleartext, byte[] secret) throws NoSuchAlgorithmException, IllegalBlockSizeException,
			BadPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, NoSuchPaddingException {

		final byte[] initializationVector = new byte[12];// 96 bits
		SecureRandom.getInstanceStrong().nextBytes(initializationVector);

		final SecretKeySpec secretKey = new SecretKeySpec(secret, ALGORITHM_AES);
		// transformation name: "algorithm/mode/padding"
		final Cipher cipherForEncryption = Cipher.getInstance(ALGORITHM_AES_GCM_NO_PADDING);
		cipherForEncryption.init(Cipher.ENCRYPT_MODE, secretKey, new GCMParameterSpec(128, initializationVector));
		final byte[] es = cipherForEncryption.doFinal(cleartext.getBytes(StandardCharsets.UTF_8));

		final byte[] os = new byte[12 + es.length];
		System.arraycopy(initializationVector, 0, os, 0, 12);
		System.arraycopy(es, 0, os, 12, es.length);
		return Base64.getEncoder().encodeToString(os);
	}

	/**
	 * Decrypts using the AES-GCM algorithm.<br>
	 * (algorithm: Advanced Encryption Standard, mode: Galois/Counter Mode).
	 * 
	 * @param encrypted the encrypted
	 * @param secret    the secret
	 * @return the clear text
	 * @throws NoSuchAlgorithmException           the security exception
	 * @throws NoSuchPaddingException             the cryptography exception
	 * @throws InvalidKeyException                the security exception
	 * @throws InvalidAlgorithmParameterException the security exception
	 * @throws IllegalBlockSizeException          the cryptography exception
	 * @throws BadPaddingException                the cryptography exception
	 */
	private String decrypt(String encrypted, byte[] secret) throws NoSuchAlgorithmException, NoSuchPaddingException,
			InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {

		final byte[] os = Base64.getDecoder().decode(encrypted);
		// confirming 'encrypted' contains at least the Initialization Vector
		// (12 bytes) and the Authentication Tag (16 bytes)
		if (os.length <= 28) {
			Printer.printf("Error: too small cleartext length[%d].", os.length);
			System.exit(0);
		}
		final byte[] initializationVector = Arrays.copyOfRange(os, 0, 12);
		final byte[] es = Arrays.copyOfRange(os, 12, os.length);

		final SecretKeySpec secretKey = new SecretKeySpec(secret, ALGORITHM_AES);
		final Cipher cipherForDecryption = Cipher.getInstance(ALGORITHM_AES_GCM_NO_PADDING);
		cipherForDecryption.init(Cipher.DECRYPT_MODE, secretKey, new GCMParameterSpec(128, initializationVector));
		return new String(cipherForDecryption.doFinal(es), StandardCharsets.UTF_8);
	}

	/**
	 * The fictional characters.
	 * 
	 */
	private enum Person {
		ALICE, BOB
	}

	/**
	 * The box with the private data. Those secret data are never exchanged.
	 * 
	 */
	private static class PrivateBox {
		/**
		 * Elliptic-Curve Digital Signature Algorithm private key.
		 */
		PrivateKey privateKeyECDSA;
		/**
		 * Elliptic-Curve Diffie-Hellman private key.
		 */
		PrivateKey privateKeyECDH;

		/**
		 * The secret shared between given person and its counterpart.
		 */
		byte[] sharedSecret;
	}

	/**
	 * The box with the public static data.<br>
	 * Those data were exchanged offline between the person and its counterpart.
	 * 
	 */
	private static class PublicStaticBox {
		/**
		 * Elliptic-Curve Digital Signature Algorithm public static key.
		 */
		byte[] publicKeyECDSA;
	}

	/**
	 * The box with the public ephemeral data.<br>
	 * These data are exchanged in session between the person and its counterpart.
	 */
	private static class PublicEphemeralBox {
		/**
		 * Elliptic-Curve Diffie-Hellman public ephemeral key.
		 */
		byte[] publicKeyECDH;
		/**
		 * Elliptic-Curve Digital Signature Algorithm ephemeral signature.
		 */
		byte[] signatureECDSA;
	}

}
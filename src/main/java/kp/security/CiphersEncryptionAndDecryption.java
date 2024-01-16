package kp.security;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.ChaCha20ParameterSpec;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import kp.utils.Printer;
import kp.utils.Utils;

/*-
 * The AES cipher with GCM mode is an AEAD (Authenticated Encryption with Associated Data) cipher.
 * The AEAD cipher assures the confidentiality and the authenticity of data.
 * The ECB mode (the default in the JDK) should not be used for multiple data blocks. 
 */
/**
 * Researching ciphers with various algorithm, mode, and padding.
 * 
 */
public class CiphersEncryptionAndDecryption {

	private static final boolean VERBOSE = false;

	private static final String ALGORITHM_AES = "AES";
	private static final String ALGORITHM_MODE_GCM = "/GCM/";
	private static final String ALGORITHM_AES_GCM_NO_PADDING = "AES/GCM/NoPadding";
	private static final String ALGORITHM_AES_CBC_PKCS5_PADDING = "AES/CBC/PKCS5PADDING";

	// ChaCha20 as a simple stream cipher with no authentication.
	// The algorithm name causes vulnerability in 'SonarQube':
	// "Use secure mode and padding scheme."
	private static final String ALGORITHM_CHA_CHA_20 = "ChaCha20";

	// ChaCha20 as an AEAD cipher using Poly1305 as the authenticator.
	// The algorithm name causes vulnerability in 'SonarQube':
	// "Use secure mode and padding scheme."
	private static final String ALGORITHM_CHA_CHA_20_POLY_1305 = "ChaCha20-Poly1305";

	private static final String CLEARTEXT = "The quick brown fox jumps over the lazy dog.";
	private static final String DECRYPTED_MSG = "decrypted text[%s]";

	/**
	 * The constructor.
	 */
	private CiphersEncryptionAndDecryption() {
		throw new IllegalStateException("Utility class");
	}

	/**
	 * Researches algorithm <b>AES</b> with mode <b>GCM</b>.<br>
	 * <ul>
	 * <li>AES: Advanced Encryption Standard
	 * <li>GCM: Galois Counter Mode
	 * </ul>
	 */
	public static void launchAesWithGcm() {

		final TransferBox transferBox = new TransferBox();
		try {
			byte[] encrypted = encryptAes(ALGORITHM_AES_GCM_NO_PADDING, transferBox);
			Printer.printf("Algorithm/Mode/Padding[%s], encrypted bytes length[%d]", ALGORITHM_AES_GCM_NO_PADDING,
					encrypted.length);
			Printer.printf("Transferring: secret[%s], initializationVector[%s]", transferBox.secret,
					transferBox.initializationVector);
			if (VERBOSE) {
				Printer.printf("encrypted bytes:%n%s", Utils.bytesToHexAndUtf(encrypted));
			}
			decryptAes(ALGORITHM_AES_GCM_NO_PADDING, transferBox, encrypted);
		} catch (InvalidKeyException | InvalidAlgorithmParameterException | NoSuchAlgorithmException
				| NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException e) {
			Printer.printExc(e);
			System.exit(1);
		}
		Printer.printHor();
	}

	/**
	 * Researches algorithm <b>AES</b> with mode <b>CBC</b>.<br>
	 * <ul>
	 * <li>AES: Advanced Encryption Standard
	 * <li>CBC: Cipher Block Chaining
	 * </ul>
	 */
	public static void launchAesWithCbc() {

		final TransferBox transferBox = new TransferBox();
		try {
			byte[] encrypted = encryptAes(ALGORITHM_AES_CBC_PKCS5_PADDING, transferBox);
			Printer.printf("Algorithm/Mode/Padding[%s], encrypted bytes length[%d]", ALGORITHM_AES_CBC_PKCS5_PADDING,
					encrypted.length);
			Printer.printf("Transferring: secret[%s], initializationVector[%s]", transferBox.secret,
					transferBox.initializationVector);
			decryptAes(ALGORITHM_AES_CBC_PKCS5_PADDING, transferBox, encrypted);
		} catch (InvalidKeyException | InvalidAlgorithmParameterException | NoSuchAlgorithmException
				| NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException e) {
			Printer.printExc(e);
			System.exit(1);
		}
		Printer.printHor();
	}

	/**
	 * Researches algorithm <b>ChaCha20</b><br>
	 * This is a simple stream cipher with no authentication.
	 * 
	 */
	public static void launchChaCha20() {

		final TransferBox transferBox = new TransferBox();
		try {
			byte[] encrypted = encryptChaCha20(transferBox);
			Printer.printf("Algorithm[ChaCha20], encrypted bytes length[%d]", encrypted.length);
			decryptChaCha20(transferBox, encrypted);
		} catch (InvalidKeyException | InvalidAlgorithmParameterException | NoSuchAlgorithmException
				| NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException e) {
			Printer.printExc(e);
			System.exit(1);
		}
		Printer.printHor();
	}

	/**
	 * Researches algorithm <b>ChaCha20-Poly1305</b>.<br>
	 * This is a cipher in <b>AEAD</b> mode using the <b>Poly1305</b> authenticator.
	 * 
	 */
	public static void launchChaCha20WithPoly1305() {

		final TransferBox transferBox = new TransferBox();
		try {
			byte[] encrypted = encryptChaCha20WithPoly1305(transferBox);
			Printer.printf("Algorithm[ChaCha20-Poly1305], encrypted bytes length[%d]", encrypted.length);
			decryptChaCha20WithPoly1305(transferBox, encrypted);
		} catch (InvalidKeyException | InvalidAlgorithmParameterException | NoSuchAlgorithmException
				| NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException e) {
			Printer.printExc(e);
			System.exit(1);
		}
		Printer.printHor();
	}

	/**
	 * Encrypts the cleartext to temporary file and decrypts it from that file.
	 * 
	 */
	public static void encryptToFileAndDecryptFromFile() {

		try {
			final SecretKey secretKey = KeyGenerator.getInstance(ALGORITHM_AES).generateKey();
			final byte[] initializationVector = new byte[16];
			final Path encryptedFile = encryptToFile(secretKey, initializationVector);
			decryptFromFile(secretKey, initializationVector, encryptedFile);
		} catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException
				| InvalidAlgorithmParameterException | IOException e) {
			Printer.printExc(e);
			System.exit(1);
		}
		Printer.printHor();
	}

	/**
	 * Encrypts the clear text with the algorithm <b>AES</b>.
	 * 
	 * @param algorithmModePadding the algorithm/mode/padding combination
	 * @param transferBox          the transfer box
	 * @return the encrypted bytes
	 * @throws InvalidAlgorithmParameterException the security exception
	 * @throws InvalidKeyException                the security exception
	 * @throws NoSuchAlgorithmException           the security exception
	 * @throws BadPaddingException                the cryptography exception
	 * @throws IllegalBlockSizeException          the cryptography exception
	 * @throws NoSuchPaddingException             the cryptography exception
	 */
	private static byte[] encryptAes(String algorithmModePadding, TransferBox transferBox)
			throws InvalidAlgorithmParameterException, InvalidKeyException, NoSuchAlgorithmException,
			BadPaddingException, IllegalBlockSizeException, NoSuchPaddingException {

		final KeyGenerator keyGenerator = KeyGenerator.getInstance(ALGORITHM_AES);
		final SecretKey secretKey = keyGenerator.generateKey();

		// 16 bytes i.e. 128 bits - this is AES key length
		final byte[] initializationVector = new byte[16];
		SecureRandom.getInstanceStrong().nextBytes(initializationVector);

		final Cipher cipher = Cipher.getInstance(algorithmModePadding);
		final boolean modeFlag = algorithmModePadding.contains(ALGORITHM_MODE_GCM);
		final AlgorithmParameterSpec parameterSpec = modeFlag ? new GCMParameterSpec(128, initializationVector)
				: new IvParameterSpec(initializationVector);
		cipher.init(Cipher.ENCRYPT_MODE, secretKey, parameterSpec);

		transferBox.secret = Base64.getEncoder().encodeToString(secretKey.getEncoded());
		transferBox.initializationVector = Base64.getEncoder().encodeToString(initializationVector);
		return cipher.doFinal(CLEARTEXT.getBytes(StandardCharsets.UTF_8));
	}

	/**
	 * Decrypts the encrypted bytes with the algorithm <b>AES</b>.
	 * 
	 * @param algorithmModePadding the algorithm/mode/padding combination
	 * @param transferBox          the transfer box
	 * @param encrypted            the encrypted bytes
	 * @throws InvalidAlgorithmParameterException the security exception
	 * @throws InvalidKeyException                the security exception
	 * @throws NoSuchAlgorithmException           the security exception
	 * @throws BadPaddingException                the cryptography exception
	 * @throws IllegalBlockSizeException          the cryptography exception
	 * @throws NoSuchPaddingException             the cryptography exception
	 */
	private static void decryptAes(String algorithmModePadding, TransferBox transferBox, byte[] encrypted)
			throws InvalidAlgorithmParameterException, InvalidKeyException, NoSuchAlgorithmException,
			BadPaddingException, IllegalBlockSizeException, NoSuchPaddingException {

		final SecretKey secretKey = new SecretKeySpec(Base64.getDecoder().decode(transferBox.secret), ALGORITHM_AES);
		final byte[] initializationVector = Base64.getDecoder().decode(transferBox.initializationVector);
		final boolean modeFlag = algorithmModePadding.contains(ALGORITHM_MODE_GCM);

		// 'initializationVector' causes vulnerability in the 'SonarQube'.
		// The 'SonarQube' advises:
		// "Use a dynamically-generated, random initialization vector."
		final AlgorithmParameterSpec parameterSpec = modeFlag ? new GCMParameterSpec(128, initializationVector)
				: new IvParameterSpec(initializationVector);
		final Cipher cipher = Cipher.getInstance(algorithmModePadding);
		cipher.init(Cipher.DECRYPT_MODE, secretKey, parameterSpec);

		final byte[] decrypted = cipher.doFinal(encrypted);
		Printer.printf(DECRYPTED_MSG, new String(decrypted, StandardCharsets.UTF_8));
	}

	/**
	 * Encrypts the clear text with the algorithm <b>ChaCha20</b>.
	 * 
	 * @param transferBox the transfer box
	 * @return the encrypted bytes
	 * @throws InvalidAlgorithmParameterException the security exception
	 * @throws InvalidKeyException                the security exception
	 * @throws NoSuchAlgorithmException           the security exception
	 * @throws BadPaddingException                the cryptography exception
	 * @throws IllegalBlockSizeException          the cryptography exception
	 * @throws NoSuchPaddingException             the cryptography exception
	 */
	private static byte[] encryptChaCha20(TransferBox transferBox)
			throws InvalidAlgorithmParameterException, InvalidKeyException, NoSuchAlgorithmException,
			BadPaddingException, IllegalBlockSizeException, NoSuchPaddingException {

		final SecretKey secretKey = KeyGenerator.getInstance(ALGORITHM_CHA_CHA_20).generateKey();

		final byte[] initializationVector = new byte[12];
		SecureRandom.getInstanceStrong().nextBytes(initializationVector);
		final Cipher cipher = Cipher.getInstance(ALGORITHM_CHA_CHA_20);
		// Use a starting counter value of "7"
		final ChaCha20ParameterSpec parameterSpec = new ChaCha20ParameterSpec(initializationVector, 7);
		cipher.init(Cipher.ENCRYPT_MODE, secretKey, parameterSpec);

		transferBox.secret = Base64.getEncoder().encodeToString(secretKey.getEncoded());
		transferBox.initializationVector = Base64.getEncoder().encodeToString(initializationVector);
		return cipher.doFinal(CLEARTEXT.getBytes(StandardCharsets.UTF_8));
	}

	/**
	 * Decrypts the encrypted bytes with the algorithm <b>ChaCha20</b>.
	 * 
	 * @param transferBox the transfer box
	 * @param encrypted   the encrypted bytes
	 * @throws InvalidAlgorithmParameterException the security exception
	 * @throws InvalidKeyException                the security exception
	 * @throws NoSuchAlgorithmException           the security exception
	 * @throws BadPaddingException                the cryptography exception
	 * @throws IllegalBlockSizeException          the cryptography exception
	 * @throws NoSuchPaddingException             the cryptography exception
	 */
	private static void decryptChaCha20(TransferBox transferBox, byte[] encrypted)
			throws InvalidAlgorithmParameterException, InvalidKeyException, NoSuchAlgorithmException,
			BadPaddingException, IllegalBlockSizeException, NoSuchPaddingException {

		final SecretKey secretKey = new SecretKeySpec(Base64.getDecoder().decode(transferBox.secret),
				ALGORITHM_CHA_CHA_20);
		final byte[] initializationVector = Base64.getDecoder().decode(transferBox.initializationVector);
		final Cipher cipher = Cipher.getInstance(ALGORITHM_CHA_CHA_20);
		final ChaCha20ParameterSpec parameterSpec = new ChaCha20ParameterSpec(initializationVector, 7);
		cipher.init(Cipher.DECRYPT_MODE, secretKey, parameterSpec);

		final byte[] decrypted = cipher.doFinal(encrypted);
		Printer.printf(DECRYPTED_MSG, new String(decrypted, StandardCharsets.UTF_8));
	}

	/**
	 * Encrypts the clear text with the algorithm <b>ChaCha20-Poly1305</b>.
	 * 
	 * @param transferBox the transfer box
	 * @return the encrypted bytes
	 * @throws InvalidAlgorithmParameterException the security exception
	 * @throws InvalidKeyException                the security exception
	 * @throws NoSuchAlgorithmException           the security exception
	 * @throws BadPaddingException                the cryptography exception
	 * @throws IllegalBlockSizeException          the cryptography exception
	 * @throws NoSuchPaddingException             the cryptography exception
	 */
	private static byte[] encryptChaCha20WithPoly1305(TransferBox transferBox)
			throws InvalidAlgorithmParameterException, InvalidKeyException, NoSuchAlgorithmException,
			BadPaddingException, IllegalBlockSizeException, NoSuchPaddingException {

		final SecretKey secretKey = KeyGenerator.getInstance(ALGORITHM_CHA_CHA_20).generateKey();
		final byte[] initializationVector = new byte[12];
		SecureRandom.getInstanceStrong().nextBytes(initializationVector);
		final Cipher cipher = Cipher.getInstance(ALGORITHM_CHA_CHA_20_POLY_1305);
		final AlgorithmParameterSpec parameterSpec = new IvParameterSpec(initializationVector);
		cipher.init(Cipher.ENCRYPT_MODE, secretKey, parameterSpec);

		transferBox.secret = Base64.getEncoder().encodeToString(secretKey.getEncoded());
		transferBox.initializationVector = Base64.getEncoder().encodeToString(initializationVector);
		return cipher.doFinal(CLEARTEXT.getBytes(StandardCharsets.UTF_8));
	}

	/**
	 * Decrypts the encrypted bytes with the algorithm <b>ChaCha20-Poly1305</b>.
	 * 
	 * @param transferBox the transfer box
	 * @param encrypted   the encrypted bytes
	 * @throws InvalidAlgorithmParameterException the security exception
	 * @throws InvalidKeyException                the security exception
	 * @throws NoSuchAlgorithmException           the security exception
	 * @throws BadPaddingException                the cryptography exception
	 * @throws IllegalBlockSizeException          the cryptography exception
	 * @throws NoSuchPaddingException             the cryptography exception
	 */
	private static void decryptChaCha20WithPoly1305(TransferBox transferBox, byte[] encrypted)
			throws InvalidAlgorithmParameterException, InvalidKeyException, NoSuchAlgorithmException,
			BadPaddingException, IllegalBlockSizeException, NoSuchPaddingException {

		final SecretKey secretKey = new SecretKeySpec(Base64.getDecoder().decode(transferBox.secret),
				ALGORITHM_CHA_CHA_20_POLY_1305);
		final byte[] initializationVector = Base64.getDecoder().decode(transferBox.initializationVector);
		final Cipher cipher = Cipher.getInstance(ALGORITHM_CHA_CHA_20_POLY_1305);
		final AlgorithmParameterSpec parameterSpec = new IvParameterSpec(initializationVector);
		cipher.init(Cipher.DECRYPT_MODE, secretKey, parameterSpec);

		final byte[] decrypted = cipher.doFinal(encrypted);
		Printer.printf(DECRYPTED_MSG, new String(decrypted, StandardCharsets.UTF_8));
	}

	/**
	 * Encrypts the cleartext to a temporary file.
	 * 
	 * @param secretKey            the secret key
	 * @param initializationVector the initialization vector
	 * @return the encrypted temporary file
	 * @throws InvalidKeyException                the security exception
	 * @throws InvalidAlgorithmParameterException the security exception
	 * @throws NoSuchAlgorithmException           the security exception
	 * @throws NoSuchPaddingException             the cryptography exception
	 * @throws IOException                        the I/O exception
	 */
	private static Path encryptToFile(SecretKey secretKey, byte[] initializationVector) throws InvalidKeyException,
			InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchPaddingException, IOException {

		SecureRandom.getInstanceStrong().nextBytes(initializationVector);

		final Cipher cipher = Cipher.getInstance(ALGORITHM_AES_GCM_NO_PADDING);
		cipher.init(Cipher.ENCRYPT_MODE, secretKey, new GCMParameterSpec(128, initializationVector));

		final File encryptedFile = File.createTempFile("encrypted", ".txt",
				new File(System.getProperty("java.io.tmpdir")));
		final FileOutputStream fileOutputStream = new FileOutputStream(encryptedFile);
		final CipherOutputStream cipherOutputStream = new CipherOutputStream(fileOutputStream, cipher);
		try (fileOutputStream; cipherOutputStream) {
			cipherOutputStream.write(CLEARTEXT.getBytes(StandardCharsets.UTF_8));
		}
		Printer.printf("Encrypted data were written to the file[%s]", encryptedFile);
		if (VERBOSE) {
			try (InputStream inputStream = Files.newInputStream(encryptedFile.toPath())) {
				Printer.printf("encrypted file content:%n%s",
						new String(inputStream.readAllBytes(), StandardCharsets.UTF_8));
			}
		}
		return encryptedFile.toPath();
	}

	/**
	 * Decrypts the encrypted bytes from a temporary file.
	 * 
	 * @param secretKey            the secret key
	 * @param initializationVector the initialization vector
	 * @param encryptedFile        the encrypted temporary file
	 * @throws InvalidKeyException                the security exception
	 * @throws InvalidAlgorithmParameterException the security exception
	 * @throws NoSuchAlgorithmException           the security exception
	 * @throws NoSuchPaddingException             the cryptography exception
	 * @throws IOException                        the I/O exception
	 */
	private static void decryptFromFile(SecretKey secretKey, byte[] initializationVector, Path encryptedFile)
			throws InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException,
			NoSuchPaddingException, IOException {

		final Cipher cipher = Cipher.getInstance(ALGORITHM_AES_GCM_NO_PADDING);
		cipher.init(Cipher.DECRYPT_MODE, secretKey, new GCMParameterSpec(128, initializationVector));

		final FileInputStream fileInputStream = new FileInputStream(encryptedFile.toFile());
		final CipherInputStream cipherInputStream = new CipherInputStream(fileInputStream, cipher);
		try (fileInputStream; cipherInputStream) {
			final byte[] decrypted = cipherInputStream.readAllBytes();
			Printer.printf(DECRYPTED_MSG, new String(decrypted, StandardCharsets.UTF_8));
		}
	}

}

/**
 * The box with the secret and the initialization vector.<br>
 * For transferring simulation from the sender to the receiver.
 * 
 */
class TransferBox {
	/**
	 * The secret key.
	 */
	String secret;
	/**
	 * The initialization vector.
	 */
	String initializationVector;
}

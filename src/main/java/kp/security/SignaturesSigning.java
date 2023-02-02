package kp.security;

import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.util.LinkedHashMap;
import java.util.Map;

import kp.utils.Printer;
import kp.utils.Utils;

/**
 * Signing the signatures with different algorithms.
 *
 */
public class SignaturesSigning {

	private static final boolean VERBOSE = false;
	private static final boolean USE_RANDOM = true;
	private static final String CONTENT = "The quick brown fox jumps over the lazy dog.";

	/**
	 * The constructor.
	 */
	private SignaturesSigning() {
		throw new IllegalStateException("Utility class");
	}

	/**
	 * Launches the keys generation, the signature signing and verification.
	 * 
	 */
	public static void launch() {

		final Map<String, String> signatureAlgorithmsMap = new LinkedHashMap<>();
		signatureAlgorithmsMap.put("SHA3-512withRSA", "RSA");
		signatureAlgorithmsMap.put("SHA3-512withDSA", "DSA");
		signatureAlgorithmsMap.put("SHA3-512withECDSA", "EC");
		try {
			for (Map.Entry<String, String> entrySet : signatureAlgorithmsMap.entrySet()) {
				final KeyPair keyPair = generateKeyPair(entrySet.getValue());
				final byte[] signatureBytes = signSignature(entrySet.getKey(), keyPair.getPrivate());
				if (VERBOSE) {
					Printer.printf("signature bytes:%n%s", Utils.bytesToHexAndUtf(signatureBytes));
				}
				final boolean verified = verifySignature(entrySet.getKey(), keyPair.getPublic(), signatureBytes);
				Printer.printf(
						"signature algorithm[%-17s], key pair algorithm[%3s], signature bytes length[%3d], verified[%b]",
						entrySet.getKey(), entrySet.getValue(), signatureBytes.length, verified);
			}
		} catch (InvalidKeyException | NoSuchAlgorithmException | SignatureException e) {
			Printer.printExc(e);
			System.exit(1);
		}
		Printer.printHor();
	}

	/**
	 * Generates key pair.
	 * 
	 * @param keyPairAlgorithm the name of key pair algorithm
	 * @return the key pair
	 * @throws NoSuchAlgorithmException the security exception
	 */
	private static KeyPair generateKeyPair(String keyPairAlgorithm) throws NoSuchAlgorithmException {

		final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(keyPairAlgorithm);
		if (USE_RANDOM) {
			keyPairGenerator.initialize("EC".equals(keyPairAlgorithm) ? 256 : 1024, new SecureRandom());
		}
		return keyPairGenerator.generateKeyPair();
	}

	/**
	 * Signs the signature.
	 * 
	 * @param signatureAlgorithm the name of signature algorithm
	 * @param privateKey         the private key
	 * @return the signature bytes
	 * @throws NoSuchAlgorithmException the security exception
	 * @throws SignatureException       the security exception
	 * @throws InvalidKeyException      the security exception
	 */
	private static byte[] signSignature(String signatureAlgorithm, PrivateKey privateKey)
			throws NoSuchAlgorithmException, SignatureException, InvalidKeyException {

		final Signature signSignature = Signature.getInstance(signatureAlgorithm);
		signSignature.initSign(privateKey);
		signSignature.update(CONTENT.getBytes());
		return signSignature.sign();
	}

	/**
	 * Verifies the signatures.
	 * 
	 * @param signatureAlgorithm the name of signature algorithm
	 * @param publicKey          the public key
	 * @param signatureBytes     the signature bytes
	 * @return the verification result
	 * @throws NoSuchAlgorithmException the security exception
	 * @throws InvalidKeyException      the security exception
	 * @throws SignatureException       the security exception
	 */
	private static boolean verifySignature(String signatureAlgorithm, PublicKey publicKey, byte[] signatureBytes)
			throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {

		final Signature verifySignature = Signature.getInstance(signatureAlgorithm);
		verifySignature.initVerify(publicKey);
		verifySignature.update(CONTENT.getBytes());
		return verifySignature.verify(signatureBytes);
	}
}
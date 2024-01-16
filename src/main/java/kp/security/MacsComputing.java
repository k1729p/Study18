package kp.security;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;

import kp.utils.Printer;
import kp.utils.Utils;

/*-
 * The algorithms not researched here are 'HmacMD5' and 'HmacSHA1':
 *  - the 'MD5' has been replaced with the 'SHA'
 *  - the 'SHA-1' message digest is flawed
 *  
 * The MACs are used between two parties that share a secret key
 * in order to validate information transmitted between these parties.
 * A MAC mechanism that is based on cryptographic hash functions is referred to as HMAC. 
 */
/**
 * Computing the Message Authentication Codes with different algorithms.
 *
 */
public class MacsComputing {
	private static final boolean VERBOSE = false;

	private static final boolean USE_RANDOM = true;

	private static final String CONTENT = "The quick brown fox jumps over the lazy dog.";

	private static final String[] MAC_ALGORITHMS = { "HmacSHA3-256", "HmacSHA3-512" };

	/**
	 * The constructor.
	 */
	private MacsComputing() {
		throw new IllegalStateException("Utility class");
	}

	/**
	 * Launches key generation and MAC computing.
	 * 
	 */
	public static void launch() {

		try {
			for (String macAlgorithm : MAC_ALGORITHMS) {
				final KeyGenerator keyGenerator = KeyGenerator.getInstance(macAlgorithm);
				if (USE_RANDOM) {
					keyGenerator.init(1024, new SecureRandom());
				}
				final SecretKey secretKey = keyGenerator.generateKey();
				final byte[] macBytesComputedAlice = computeMac(macAlgorithm, secretKey);
				final byte[] macBytesComputedBob = computeMac(macAlgorithm, secretKey);
				if (VERBOSE) {
					Printer.printf("MAC bytes:%n%s", Utils.bytesToHexAndUtf(macBytesComputedAlice));
				}
				Printer.printf("MAC algorithm[%10s], length[%d], MACs are equal[%b]", macAlgorithm,
						macBytesComputedAlice.length, Arrays.equals(macBytesComputedAlice, macBytesComputedBob));
			}
			Printer.printHor();
		} catch (InvalidKeyException | NoSuchAlgorithmException e) {
			Printer.printExc(e);
			System.exit(1);
		}
	}

	/**
	 * Computes the message authentication code.
	 * 
	 * @param macAlgorithm the MAC algorithm
	 * @param secretKeyArr the secret key array
	 * @return the MAC data tag
	 * @throws NoSuchAlgorithmException the security exception
	 * @throws InvalidKeyException      the security exception
	 */
	private static byte[] computeMac(String macAlgorithm, SecretKey secretKeyArr)
			throws NoSuchAlgorithmException, InvalidKeyException {

		final Mac mac = Mac.getInstance(macAlgorithm);
		mac.init(secretKeyArr);
		mac.update(CONTENT.getBytes());
		return mac.doFinal();
	}
}

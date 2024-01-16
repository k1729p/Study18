package kp;

import kp.security.ChecksumsComputing;
import kp.security.CiphersEncryptionAndDecryption;
import kp.security.DigestsComputing;
import kp.security.KeysAndDigestsExchanging;
import kp.security.MacsComputing;
import kp.security.SecureClass;
import kp.security.SignaturesSigning;
import kp.security.ecc.EllipticCurveCryptography;

/**
 * The main application for the security research.
 *
 */
public class Application {
	private static final boolean ALL = true;
	private static boolean ellipticCurveCryptography = false;
	private static boolean checksumsComputing = false;
	private static boolean ciphersEncryptionAndDecryption = false;
	private static boolean digestsComputing = false;
	private static boolean keysAndDigestsExchanging = false;
	private static boolean macsComputing = false;
	private static boolean secureClass = false;
	private static boolean signaturesSigning = false;

	/**
	 * The constructor.
	 */
	public Application() {
		super();
	}

	/**
	 * The main method.
	 * 
	 * @param args the arguments
	 */
	public static void main(String[] args) {

		if (ALL) {
			ellipticCurveCryptography = true;
			checksumsComputing = true;
			ciphersEncryptionAndDecryption = true;
			digestsComputing = true;
			keysAndDigestsExchanging = true;
			macsComputing = true;
			secureClass = true;
			signaturesSigning = true;
		}
		if (ellipticCurveCryptography) {
			EllipticCurveCryptography.launch();
		}
		if (checksumsComputing) {
			ChecksumsComputing.launch();
		}
		if (ciphersEncryptionAndDecryption) {
			CiphersEncryptionAndDecryption.launchAesWithGcm();
		}
		if (ciphersEncryptionAndDecryption) {
			CiphersEncryptionAndDecryption.launchAesWithCbc();
		}
		if (ciphersEncryptionAndDecryption) {
			CiphersEncryptionAndDecryption.launchChaCha20();
		}
		if (ciphersEncryptionAndDecryption) {
			CiphersEncryptionAndDecryption.launchChaCha20WithPoly1305();
		}
		if (ciphersEncryptionAndDecryption) {
			CiphersEncryptionAndDecryption.encryptToFileAndDecryptFromFile();
		}
		if (digestsComputing) {
			DigestsComputing.launch();
		}
		if (keysAndDigestsExchanging) {
			KeysAndDigestsExchanging.launch();
		}
		if (macsComputing) {
			MacsComputing.launch();
		}
		if (secureClass) {
			SecureClass.newSecureClass().launch();
		}
		if (signaturesSigning) {
			SignaturesSigning.launch();
		}
	}
}
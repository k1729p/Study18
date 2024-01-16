package kp.security;

import java.util.Arrays;

import kp.utils.Printer;

/**
 * 
 * Example of a secure class that does not permit subclassing.
 *
 */
public class SecureClass {

	private static final String CLEARTEXT = "ABCDEFGHIJKLMNOP";
	private static final byte[] SECRET = { //
			(byte) 0x41, (byte) 0x42, (byte) 0x43, (byte) 0x44, //
			(byte) 0x45, (byte) 0x46, (byte) 0x47, (byte) 0x48, //
			(byte) 0x49, (byte) 0x4A, (byte) 0x4B, (byte) 0x4C, //
			(byte) 0x4D, (byte) 0x4E, (byte) 0x4F, (byte) 0x50 //
	};

	/**
	 * The hidden constructor.<br>
	 * Avoids exposing constructors of sensitive classes.
	 * 
	 */
	private SecureClass() {
		super();
	}

	/**
	 * The guarded construction method.<br>
	 * Defines static factory methods instead of public constructors.
	 * 
	 * @return the new secure class
	 */
	public static SecureClass newSecureClass() {

		return new SecureClass();
	}

	/**
	 * Launches actions.
	 */
	public void launch() {

		Printer.printf("The SECRET equals CLEARTEXT[%s]: [%b]", CLEARTEXT, Arrays.equals(CLEARTEXT.getBytes(), SECRET));
		Printer.printHor();
	}
}

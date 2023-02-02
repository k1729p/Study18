package kp.security;

import java.util.List;
import java.util.zip.Adler32;
import java.util.zip.CRC32;
import java.util.zip.CRC32C;
import java.util.zip.Checksum;

import kp.utils.Printer;

/**
 * Computing the checksums.
 *
 */
public class ChecksumsComputing {

	/**
	 * The constructor.
	 */
	private ChecksumsComputing() {
		throw new IllegalStateException("Utility class");
	}

	private static final String CONTENT = "The quick brown fox jumps over the lazy dog.";

	// CRC32C (Castagnoli) is implemented in hardware in Intel CPUs
	private static final List<Checksum> CHECKSUMS = List.of(new CRC32C(), new CRC32(), new Adler32());

	/**
	 * Computes the checksums with different algorithms.
	 * 
	 */
	public static void launch() {

		CHECKSUMS.forEach(checksum -> {
			checksum.reset();
			checksum.update(CONTENT.getBytes(), 0, CONTENT.length());
			Printer.printf("checksum algorithm[%7s], value[%10d]", checksum.getClass().getSimpleName(),
					checksum.getValue());
		});
		Printer.printHor();
	}
}

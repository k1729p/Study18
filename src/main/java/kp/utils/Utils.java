package kp.utils;

import java.nio.charset.StandardCharsets;
import java.util.Objects;

/**
 * The utilities.
 *
 */
public interface Utils {

	/**
	 * Converts a byte array to hex string.
	 * 
	 * @param block the block
	 * @return the result
	 */
	static String bytesToHexAndUtf(byte[] block) {

		if (Objects.isNull(block)) {
			return "null";
		}
		return bytesToHexAndUtf(block, block.length);
	}

	/**
	 * Converts a byte array to hex string.
	 * 
	 * @param block     the block
	 * @param bytesRead the bytes read
	 * @return the result
	 */
	static String bytesToHexAndUtf(byte[] block, int bytesRead) {

		StringBuilder utfBuf = new StringBuilder();
		StringBuilder hexBuf = new StringBuilder();
		for (int i = 0; i < bytesRead; i++) {
			hexBuf.append(String.format("%02X ", block[i]));
			utfBuf.append(new String(block, i, 1, StandardCharsets.UTF_8));
		}
		hexBuf.append("   ".repeat(Math.max(0, 8 - bytesRead)));
		String utfStr = utfBuf.toString();
		utfStr = utfStr.replace("\n", " ");// 0A - line feed character
		utfStr = utfStr.replace("\r", " ");// 0D - carriage-return character
		hexBuf.append("| ").append(utfStr);
		return hexBuf.toString();
	}
}
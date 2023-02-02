package kp.utils;

import java.io.IOException;
import java.io.InputStream;
import java.lang.invoke.MethodHandles;
import java.util.logging.Level;
import java.util.logging.LogManager;
import java.util.logging.Logger;

/**
 * The wrapper on 'Java Util Logging' with simplified format.<br>
 * It prints only the message without any other items (like date, level).
 * <p>
 * The code which uses 'System.out.println' is noncompliant in 'SonarQube'.
 */
public class Printer {

	private static final Logger logger = Logger.getLogger(MethodHandles.lookup().lookupClass().getName());
	static {
		final InputStream inputStream = Printer.class.getClassLoader().getResourceAsStream("logging.properties");
		try (inputStream) {
			// Configuring logger that way causes the security issue in 'SonarQube':
			// "Make sure that this logger's configuration is safe."
			LogManager.getLogManager().readConfiguration(inputStream);
		} catch (IOException e) {
			logger.log(Level.SEVERE, e.getMessage(), e);
		}
	}

	/**
	 * The constructor.
	 */
	private Printer() {
		throw new IllegalStateException("Utility class");
	}

	/**
	 * Prints the message to the console with simplified logger.
	 * 
	 * @param message the message
	 */
	public static void print(String message) {

		if (logger.isLoggable(Level.INFO)) {
			logger.info(message);
		}
	}

	/**
	 * Formats the message and prints it to the console with simplified logger.
	 * 
	 * @param format the message format
	 * @param args   the message items
	 */
	public static void printf(String format, Object... args) {

		if (logger.isLoggable(Level.INFO)) {
			logger.info(String.format(format, args));
		}
	}

	/**
	 * Prints the horizontal rule.
	 * 
	 */
	public static void printHor() {

		if (logger.isLoggable(Level.INFO)) {
			logger.info("- ".repeat(50));
		}
	}

	/**
	 * Prints the exception message.
	 * 
	 * @param exception the exception
	 */
	public static void printExc(Throwable exception) {
		logger.log(Level.SEVERE, exception.getMessage(), exception);
	}
}

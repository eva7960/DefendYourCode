import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.Scanner;
import java.security.MessageDigest;
import java.nio.charset.StandardCharsets;

/**
 * Defend your code
 * Prompts the user to enter the following along with verifying all necessary edge cases:
 * User's First and Last Name
 * An int with range from -2147483648 to 2147483647
 * Name of the input file
 *
 * @author Ibadat Sandhu and Eva Howard
 * @version February 20, 2026
 */
public class JavaVersion {

    private static final String ERROR_LOG = "error.log";
    private static final String PASSWORD_FILE = "password.txt";

    public static void main(String[] args) {
        clearErrorLog();
        try (Scanner scanner = new Scanner(System.in)) {

            String firstName = getValidName(scanner, "First");
            String lastName = getValidName(scanner, "Last");

            int firstInt = getValidInt(scanner, "First");
            int secondInt = getValidInt(scanner, "Second");

            int sum = safeAdd(firstInt, secondInt);
            int product = safeMultiply(firstInt, secondInt);

            String inputFile = getValidInputFile(scanner);
            String outputFile = getValidOutputFile(scanner);

            handlePassword(scanner);

            writeOutputFile(firstName, lastName, firstInt, secondInt,
                    sum, product, inputFile, outputFile);

            System.out.println("Program completed successfully.");

        } catch (Exception e) {
            logError("Unexpected crash: " + e.getMessage());
            System.out.println("A fatal error occurred. Check error.log.");
        }
    }

    public static void clearErrorLog() {
        try (PrintWriter writer = new PrintWriter(new FileWriter(ERROR_LOG))) {
        } catch (IOException e) {
            System.out.println("WARNING: Could not clear error log.");
        }
    }
    public static String getValidName(Scanner scanner, String type) {
        while (true) {
            System.out.println("\nEnter your " + type + " Name (1-50 letters only, A-Z or a-z):");
            String input = scanner.nextLine().trim();

            if (input.matches("^[A-Za-z]{1,50}$")) {
                return input;
            }

            System.out.println("ERROR: Invalid name.");
            logError("Invalid " + type + " name entered.");
        }
    }

    public static int getValidInt(Scanner scanner, String type) {
        while (true) {
            System.out.println("\nEnter the " + type + " Integer:");
            System.out.println("Range: -2,147,483,648 to 2,147,483,647");

            try {
                return Integer.parseInt(scanner.nextLine().trim());
            } catch (NumberFormatException e) {
                System.out.println("ERROR: Invalid integer.");
                logError("Invalid integer input.");
            }
        }
    }

    public static int safeAdd(int a, int b) {
        try {
            return Math.addExact(a, b);
        } catch (ArithmeticException e) {
            logError("Integer overflow during addition.");
            throw new ArithmeticException("Overflow occurred during addition.");
        }
    }

    public static int safeMultiply(int a, int b) {
        try {
            return Math.multiplyExact(a, b);
        } catch (ArithmeticException e) {
            logError("Integer overflow during multiplication.");
            throw new ArithmeticException("Overflow occurred during multiplication.");
        }
    }

    public static String getValidInputFile(Scanner scanner) {
        while (true) {
            System.out.println("\nEnter input file (.txt only, must exist and be readable):");
            String fileName = scanner.nextLine().trim();

            File file = new File(fileName);

            if (fileName.isEmpty()) {
                System.out.println("ERROR: File name cannot be empty.");
            } else if (!fileName.endsWith(".txt")) {
                System.out.println("ERROR: File must end in .txt");
            } else if (!file.exists()) {
                System.out.println("ERROR: File does not exist.");
            } else if (!file.isFile()) {
                System.out.println("ERROR: Not a valid file.");
            } else if (!file.canRead()) {
                System.out.println("ERROR: File not readable.");
            } else {
                return fileName;
            }

            logError("Invalid input file attempt: " + fileName);
        }
    }

    public static String getValidOutputFile(Scanner scanner) {
        while (true) {
            System.out.println("\nEnter output file name (.txt only):");
            String fileName = scanner.nextLine().trim();

            if (fileName.isEmpty()) {
                System.out.println("ERROR: File name cannot be empty.");
                continue;
            }

            if (!fileName.endsWith(".txt")) {
                System.out.println("ERROR: Output file must end in .txt");
                continue;
            }

            File file = new File(fileName);

            if (file.exists()) {
                System.out.println("File exists. Overwrite? (yes/no)");
                if (!scanner.nextLine().trim().equalsIgnoreCase("yes")) {
                    continue;
                }
            }

            try {
                file.createNewFile();
                return fileName;
            } catch (IOException e) {
                logError("Could not create output file.");
                System.out.println("ERROR: Could not create file.");
            }
        }
    }

    public static void handlePassword(Scanner scanner) throws Exception {
        while (true) {
            System.out.println("\nEnter password:");
            System.out.println("Must be at least 15 characters.");
            System.out.println("Must include uppercase, lowercase, digit, and symbol.");

            String password = scanner.nextLine().trim();

            if (!password.matches(
                    "^(?=.*[A-Z])(?=.*[a-z])(?=.*\\d)(?=.*[!@#$%^&*()_\\-+=\\[\\]{};:'\",.<>/?\\\\|`~]).{15,}$")) {
                System.out.println("ERROR: Weak password.");
                logError("Weak password attempt.");
                continue;
            }

            byte[] salt = generateSalt();
            String hash = hashWithSalt(password, salt);

            writePasswordFile(salt, hash);

            System.out.println("Re-enter password for verification:");
            String verify = scanner.nextLine().trim();

            if (verifyPassword(verify)) {
                System.out.println("Password verified successfully.");
                return;
            } else {
                System.out.println("Passwords did not match.");
                logError("Password verification failed.");
            }
        }
    }

    public static byte[] generateSalt() {
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[16];
        random.nextBytes(salt);
        return salt;
    }

    public static String hashWithSalt(String password, byte[] salt) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        digest.update(salt);
        byte[] hashed = digest.digest(password.getBytes(StandardCharsets.UTF_8));
        return bytesToHex(hashed);
    }

    public static void writePasswordFile(byte[] salt, String hash) throws IOException {
        try (PrintWriter writer = new PrintWriter(new FileWriter(PASSWORD_FILE))) {
            writer.println(bytesToHex(salt) + ":" + hash);
        }
    }

    public static boolean verifyPassword(String password) throws Exception {
        String content = Files.readString(Path.of(PASSWORD_FILE)).trim();
        String[] parts = content.split(":");

        byte[] salt = hexToBytes(parts[0]);
        String newHash = hashWithSalt(password, salt);

        return newHash.equals(parts[1]);
    }

    public static void writeOutputFile(String firstName, String lastName,
                                       int firstInt, int secondInt,
                                       int sum, int product,
                                       String inputFile, String outputFile) {

        try (PrintWriter writer = new PrintWriter(new FileWriter(outputFile));
             Scanner fileScan = new Scanner(new File(inputFile))) {

            writer.println("First Name: " + firstName);
            writer.println("Last Name: " + lastName);
            writer.println("First Integer: " + firstInt);
            writer.println("Second Integer: " + secondInt);
            writer.println("Sum: " + sum);
            writer.println("Product: " + product);
            writer.println("Input File Name: " + inputFile);
            writer.println("Input File Contents:");

            while (fileScan.hasNextLine()) {
                writer.println(fileScan.nextLine());
            }

        } catch (IOException e) {
            logError("Error writing output file.");
        }
    }

    public static void logError(String message) {
        try (PrintWriter log = new PrintWriter(new FileWriter(ERROR_LOG, true))) {
            log.println(message);
        } catch (IOException ignored) {}
    }

    public static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) sb.append('0');
            sb.append(hex);
        }
        return sb.toString();
    }

    public static byte[] hexToBytes(String hex) {
        byte[] bytes = new byte[hex.length() / 2];
        for (int i = 0; i < bytes.length; i++) {
            bytes[i] = (byte) Integer.parseInt(hex.substring(2*i, 2*i+2), 16);
        }
        return bytes;
    }
}
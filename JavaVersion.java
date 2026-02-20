import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.Scanner;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.nio.charset.StandardCharsets;
/*
 * Defend your code
 * Prompts the user to enter the following along with verifying all necessary edge cases:
 * User's First and Last Name
 * An int with range from -2147483648 to 2147483647
 * Name of the input file
 *
 * @author Ibadat Sandhu and Eva Howard
 * @version February 20, 2026
 **/
public class JavaVersion {

    /**
     * Main method that coordinates user input collection and validation.
     *
     * @param args command-line arguments (not used)
     */
    public static void main(String[] args) {

        // Creating Scanner object to read user input from console
        Scanner scanner = new Scanner(System.in);

        // Collecting and validating first and last name
        String firstName = getValidName(scanner, "First");
        String lastName = getValidName(scanner, "Last");


        // Collecting and validating first and last int
        int firstInt = getValidInt(scanner, "First");
        int secondInt = getValidInt(scanner, "Second");
        int add = firstInt + secondInt;
        int multiply = firstInt * secondInt;

        // Collecting and validating input file name
        String inputFileName = getValidInputFile(scanner);
        System.out.println(inputFileName);
        String outputFile = getValidOutputFile(scanner);

        getValidPassword(scanner);

        //write everything to output file
        try (PrintWriter writer = new PrintWriter(new FileWriter(outputFile));
             Scanner inputScan = new Scanner(new File(inputFileName))) {
            writer.println("First Name: " + firstName);
            writer.println("Last Name: " + lastName);
            writer.println("Result of adding " + firstInt + " and " + secondInt + ": " + add);
            writer.println("Result of multiplying " + firstInt + " and " + secondInt + ": " + multiply);
            writer.println("Input file contents:");
            while(inputScan.hasNextLine()) {
                writer.println(inputScan.nextLine());
            }
            System.out.println("Data successfully written to the file.");
        } catch (IOException e) {
            System.out.println("Could not print results to output file.");
        }
        scanner.close();
    }

    /** Prompts the user to enter a valid name (first or last).
     * The name must: contain only letters (A-Z or a-z) and be between 1 and 50 characters long
     *
     * @param scanner Scanner object for user input
     * @param type Indicating whether this is "first" or "last" name
     * @return name Validated name string
     */
    public static String getValidName(Scanner scanner, String type) {
        String name;

        // Infinite loop ensures program keeps asking until valid input is entered
        while (true) {
            System.out.println("\nEnter your " + type + " Name:");
            System.out.println("Please follow these input requirements:");
            System.out.println("• Must be 1–50 characters");
            System.out.println("• Letters only (A–Z or a–z)");
            System.out.println("• No numbers, spaces, or special characters\n");

            // Reading user input and removing whitespace
            name = scanner.nextLine().trim();

            // Validating using regular expression
            if (name.matches("^[A-Za-z]{1,50}$")) {
                return name;
            } else {
                // If validation fails, print error and repeat loop
                System.out.println("ERROR: Invalid " + type + " name. Please try again!");
            }
        }
    }

    /**
     * Prompts the user to enter a valid 4-byte integer.
     * The int must be in valid range: -2147483648 to 2147483647
     *
     * @param scanner Scanner object for user input
     * @param type Indicating whether this is "first" or "second" integer
     * @return value Validated integer value
     */
    public static int getValidInt(Scanner scanner, String type) {

        // Infinite loop ensures program keeps asking until valid input is entered
        while (true) {
            System.out.println("\nEnter the " + type + " Integer:");
            System.out.println("Please follow these input requirements:");
            System.out.println("• Must be a 4-byte integer");
            System.out.println("• Valid range: -2147483648 to 2147483647\n");

            try {
                // Reading input as String first to prevent Scanner crash
                String input = scanner.nextLine().trim();

                // Attempting conversion to int
                int value = Integer.parseInt(input);

                return value; // valid int

            } catch (NumberFormatException e) {

                // If parsing fails, NumberFormatException is thrown
                System.out.println("ERROR: Invalid integer. Please enter a valid 4-byte integer.\n");
            }
        }
    }

    /**
     * Prompts the user to enter a valid input file name.
     * The file must: exist , be a regular file (not directory) and be readable
     *
     * @param scanner Scanner object for user input
     * @return Validated file name
     */
    public static String getValidInputFile(Scanner scanner) {

        // Infinite loop ensures program keeps asking until valid input is entered
        while (true) {
            System.out.println("\nEnter the input file name:");
            System.out.println("Please follow these input requirements:");
            System.out.println("• Enter a file name (if in project directory)");
            System.out.println("• Or enter a full file path (example: C:\\Users\\Name\\Desktop\\data.txt)");
            System.out.println("• Include extension (example: data.txt)");
            System.out.println("• File must be readable\n");

            // Reading user input and removing whitespace
            String fileName = scanner.nextLine().trim();
            // Creating File object using the provided path
            File file = new File(fileName);

            // Checking if the input was empty
            if (fileName.isEmpty()) {
                System.out.println("ERROR: File name cannot be empty.");
            }
            // Checking if the file exists in the specified location
            else if (!file.exists()) {
                System.out.println("ERROR: File does not exist.");
            }
            // Checking that the path refers to a regular file
            else if (!file.isFile()) {
                System.out.println("ERROR: This is not a valid file.");
            }
            // Checking if the file has read permissions
            else if (!file.canRead()) {
                System.out.println("ERROR: File cannot be read.");
            }
            // If all validation checks pass, return the valid file name
            else {
                return fileName;
            }
        }
    }

    /**
     * Prompts the user to enter a valid input file name.
     * The file must: exist , be a regular file (not directory) and be readable
     *
     * @param scanner Scanner object for user input
     * @return Validated file name
     */
    public static String getValidOutputFile(Scanner scanner) {

        while (true) {
            System.out.println("\nEnter the output file name:");
            System.out.println("Please follow these input requirements:");
            System.out.println("• Enter a file name (if in project directory)");
            System.out.println("• Or enter a full file path (example: C:\\Users\\Name\\Desktop\\data.txt)");
            System.out.println("• Include extension (example: data.txt)\n");

            String fileName = scanner.nextLine().trim();

            if (fileName.isEmpty()) {
                System.out.println("ERROR: File name cannot be empty.");
                continue;
            }
            File file = new File(fileName);

            // If file exists, ask for overwrite confirmation
            if (file.exists()) {
                System.out.println("WARNING: File already exists.");
                System.out.print("Do you want to overwrite it? (yes/no): ");
                String response = scanner.nextLine().trim().toLowerCase();

                if (!response.equals("yes")) {
                    System.out.println("Please choose a different file name.");
                    continue;
                }
            }
            try {
                file.createNewFile();
                return fileName;
            } catch (Exception e) {
                System.out.println("ERROR: Cannot create or access file.");
            }
        }
    }

    /**
     * Prompts the user for a password, stores the password, and asks the user to re-enter password to verify.
     * Password is hashed and written to a file. Passwords need to be at least 15 characters, include at least
     * 1 capital letter, 1 number, and 1 symbol.
     * @param scan Scanner to read user input
     */
    public static void getValidPassword(Scanner scan) {
        boolean validPass = false;

        while (!validPass) {
            System.out.println("\nEnter a password.");
            System.out.println("Please follow these requirements:");
            System.out.println("• Must be at least 15 characters");
            System.out.println("• Must include at least 1 uppercase letter");
            System.out.println("• Must include at least 1 lowercase letter");
            System.out.println("• Must include at least 1 number(digits 0-9)");
            System.out.println("• Must include at least 1 symbol(!@#$%^&*()_\\-+=\\[\\]{};:'\",.<>/?\\\\|`~)\n");

            String pass = scan.nextLine().trim(); //remove any trailing whitespace

            if (pass.matches("^(?=.*[A-Z])(?=.*[a-z])(?=.*\\d)(?=.*[!@#$%^&*()_\\-+=\\[\\]{};:'\",.<>/?\\\\|`~]).{15,}$")) {
                validPass = true;
                try (PrintWriter writer = new PrintWriter(new FileWriter("password.txt"))) {
                    writer.println(hash(pass));
                    System.out.println(hash(pass));
                } catch (IOException e) {
                    System.out.println("ERROR: Could not write password to file.");
                }
            } else {
                System.out.println("ERROR: Invalid password. Please try again!");
            }
        }
        verifyPassword(scan);
    }

    /**
     * uses Sha-256 hashing method.
     * @param input password to be hashed
     * @return hashed password
     */
    public static String hash(String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashBytes = digest.digest(input.getBytes(StandardCharsets.UTF_8));

            // Convert bytes to hex
            StringBuilder hexString = new StringBuilder();
            for (byte b : hashBytes) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) {
                    hexString.append('0');
                }
                hexString.append(hex);
            }
            return hexString.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 algorithm not available", e);
        }
    }

    /**
     * Prompts user to retype in password to verify it's correct. Hashes user input and compares with
     * hashed password stored in password.txt to verify correctness.
     */
    public static void verifyPassword(Scanner scan) {
        boolean match = false;
        while(!match) {
            System.out.println("\nPlease re-enter password for verification.");
            String userInput = hash(scan.nextLine().trim());
            Path path = Path.of("password.txt");
            try {
                String storedPass = Files.readString(path, StandardCharsets.UTF_8).trim();
                System.out.println("Stored: " + storedPass);
                System.out.println("input: " + userInput);
                if(storedPass.equals(userInput)) {
                    match = true;
                    System.out.println("SUCCESS: Password verified!");
                }
            } catch (IOException e) {
                System.out.println("Password did not match. Try again.");
            }
        }
    }
}
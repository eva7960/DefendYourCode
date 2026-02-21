import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.*;
import java.util.Scanner;

class JavaVersionTest {

    private static final Path PASSWORD_PATH = Path.of("password.txt");
    private static final Path ERROR_LOG_PATH = Path.of("error.log");

    @AfterEach
    void cleanup() throws IOException {
        Files.deleteIfExists(PASSWORD_PATH);
        Files.deleteIfExists(ERROR_LOG_PATH);
    }

    /* =====================================================
       NAME VALIDATION
       ===================================================== */

    @Test
    void testValidName_MinLength() {
        Scanner scanner = new Scanner("A\n");
        assertEquals("A", JavaVersion.getValidName(scanner, "First"));
    }

    @Test
    void testValidName_MaxLength() {
        String name = "A".repeat(50);
        Scanner scanner = new Scanner(name + "\n");
        assertEquals(name, JavaVersion.getValidName(scanner, "First"));
    }

    @Test
    void testInvalidName_TooLongThenValid() {
        String invalid = "A".repeat(51);
        Scanner scanner = new Scanner(invalid + "\nEva\n");
        assertEquals("Eva", JavaVersion.getValidName(scanner, "First"));
        assertTrue(Files.exists(ERROR_LOG_PATH));
    }

    @Test
    void testInvalidName_WithNumbersThenValid() {
        Scanner scanner = new Scanner("Eva123\nEva\n");
        assertEquals("Eva", JavaVersion.getValidName(scanner, "First"));
    }

    /* =====================================================
       INTEGER VALIDATION
       ===================================================== */

    @Test
    void testValidInt_MinBoundary() {
        Scanner scanner = new Scanner(Integer.MIN_VALUE + "\n");
        assertEquals(Integer.MIN_VALUE,
                JavaVersion.getValidInt(scanner, "First"));
    }

    @Test
    void testValidInt_MaxBoundary() {
        Scanner scanner = new Scanner(Integer.MAX_VALUE + "\n");
        assertEquals(Integer.MAX_VALUE,
                JavaVersion.getValidInt(scanner, "First"));
    }

    @Test
    void testInvalidInt_NonNumericThenValid() {
        Scanner scanner = new Scanner("abc\n42\n");
        assertEquals(42,
                JavaVersion.getValidInt(scanner, "First"));
        assertTrue(Files.exists(ERROR_LOG_PATH));
    }

    /* =====================================================
       SAFE ADD / MULTIPLY
       ===================================================== */

    @Test
    void testSafeAdd_Normal() {
        assertEquals(10, JavaVersion.safeAdd(5, 5));
    }

    @Test
    void testSafeAdd_Overflow() {
        assertThrows(ArithmeticException.class,
                () -> JavaVersion.safeAdd(Integer.MAX_VALUE, 1));
        assertTrue(Files.exists(ERROR_LOG_PATH));
    }

    @Test
    void testSafeMultiply_Normal() {
        assertEquals(20, JavaVersion.safeMultiply(4, 5));
    }

    @Test
    void testSafeMultiply_Overflow() {
        assertThrows(ArithmeticException.class,
                () -> JavaVersion.safeMultiply(Integer.MAX_VALUE, 2));
        assertTrue(Files.exists(ERROR_LOG_PATH));
    }

    /* =====================================================
       INPUT FILE VALIDATION
       ===================================================== */

    @Test
    void testInputFile_EmptyThenValid(@TempDir Path tempDir) throws IOException {
        Path validFile = Files.createFile(tempDir.resolve("valid.txt"));

        Scanner scanner = new Scanner(
                "\n" +
                        validFile.toString() + "\n"
        );

        assertEquals(validFile.toString(),
                JavaVersion.getValidInputFile(scanner));
    }

    @Test
    void testInputFile_WrongExtensionThenValid(@TempDir Path tempDir) throws IOException {
        Path validFile = Files.createFile(tempDir.resolve("valid.txt"));

        Scanner scanner = new Scanner(
                "file.doc\n" +
                        validFile.toString() + "\n"
        );

        assertEquals(validFile.toString(),
                JavaVersion.getValidInputFile(scanner));
    }

    @Test
    void testInputFile_NotExistThenValid(@TempDir Path tempDir) throws IOException {
        Path validFile = Files.createFile(tempDir.resolve("valid.txt"));

        Scanner scanner = new Scanner(
                "fake.txt\n" +
                        validFile.toString() + "\n"
        );

        assertEquals(validFile.toString(),
                JavaVersion.getValidInputFile(scanner));
    }

    /* =====================================================
       OUTPUT FILE VALIDATION
       ===================================================== */

    @Test
    void testOutputFile_NewFile(@TempDir Path tempDir) {
        Path output = tempDir.resolve("output.txt");

        Scanner scanner = new Scanner(output.toString() + "\n");

        assertEquals(output.toString(),
                JavaVersion.getValidOutputFile(scanner));

        assertTrue(Files.exists(output));
    }

    @Test
    void testOutputFile_WrongExtensionThenValid(@TempDir Path tempDir) {
        Path valid = tempDir.resolve("output.txt");

        Scanner scanner = new Scanner(
                "output.doc\n" +
                        valid.toString() + "\n"
        );

        assertEquals(valid.toString(),
                JavaVersion.getValidOutputFile(scanner));
    }

    @Test
    void testOutputFile_OverwriteNoThenYes(@TempDir Path tempDir) throws IOException {
        Path existing = Files.createFile(tempDir.resolve("output.txt"));

        Scanner scanner = new Scanner(
                existing.toString() + "\n" +
                        "no\n" +
                        existing.toString() + "\n" +
                        "yes\n"
        );

        assertEquals(existing.toString(),
                JavaVersion.getValidOutputFile(scanner));
    }

    /* =====================================================
       SALT + HASH
       ===================================================== */

    @Test
    void testGenerateSalt_Length() {
        byte[] salt = JavaVersion.generateSalt();
        assertEquals(16, salt.length);
    }

    @Test
    void testHashWithSalt_DifferentSaltDifferentHash() throws Exception {
        byte[] salt1 = JavaVersion.generateSalt();
        byte[] salt2 = JavaVersion.generateSalt();
        String password = "StrongPassword123!";

        String hash1 = JavaVersion.hashWithSalt(password, salt1);
        String hash2 = JavaVersion.hashWithSalt(password, salt2);

        assertNotEquals(hash1, hash2);
    }

    @Test
    void testWriteAndVerifyPassword() throws Exception {
        String password = "VeryStrongPassword123!";
        byte[] salt = JavaVersion.generateSalt();
        String hash = JavaVersion.hashWithSalt(password, salt);

        JavaVersion.writePasswordFile(salt, hash);

        assertTrue(JavaVersion.verifyPassword(password));
        assertFalse(JavaVersion.verifyPassword("WrongPassword!123"));
    }

    /* =====================================================
       OUTPUT FILE CONTENT
       ===================================================== */

    @Test
    void testWriteOutputFile_ContentCorrect(@TempDir Path tempDir) throws IOException {

        Path input = tempDir.resolve("input.txt");
        Files.writeString(input, "Line1\nLine2");

        Path output = tempDir.resolve("output.txt");

        JavaVersion.writeOutputFile(
                "Eva",
                "Howard",
                5,
                10,
                15,
                50,
                input.toString(),
                output.toString()
        );

        String content = Files.readString(output);

        assertAll(
                () -> assertTrue(content.contains("First Name: Eva")),
                () -> assertTrue(content.contains("Last Name: Howard")),
                () -> assertTrue(content.contains("First Integer: 5")),
                () -> assertTrue(content.contains("Second Integer: 10")),
                () -> assertTrue(content.contains("Sum: 15")),
                () -> assertTrue(content.contains("Product: 50")),
                () -> assertTrue(content.contains("Input File Name: " + input)),
                () -> assertTrue(content.contains("Line1")),
                () -> assertTrue(content.contains("Line2"))
        );
    }

    /* =====================================================
       HEX UTILITIES
       ===================================================== */

    @Test
    void testHexConversion_RoundTrip() {
        byte[] original = {0, 1, 2, 15, 16, -1};
        String hex = JavaVersion.bytesToHex(original);
        byte[] converted = JavaVersion.hexToBytes(hex);

        assertArrayEquals(original, converted);
    }

    @Test
    void testHexConversion_EmptyArray() {
        byte[] original = {};
        String hex = JavaVersion.bytesToHex(original);
        byte[] converted = JavaVersion.hexToBytes(hex);

        assertArrayEquals(original, converted);
    }
}
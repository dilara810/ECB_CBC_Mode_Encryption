import java.io.*;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.awt.image.BufferedImage;
import javax.imageio.ImageIO;

public class Main {
    public static final String ecb = "AES/ECB/PKCS5Padding"; // For the algorithm of AES define ECB mode
    public static final String cbc = "AES/CBC/PKCS5Padding"; // For AES algorithm define CBC mode
    public static final int BLOCK_SIZE = 16; // Sets the block size for AES to 16 bytes

    public static void main(String[] args) throws Exception {
        //Specifies the image file we want to encrypt
        File file = new File("odev.png");

        // Reads the contents of the image file
        BufferedImage img = ImageIO.read(file);

        // Converts image to grayscale
        BufferedImage grayImage = convertToGray(img);

        // Creates key
        KeyGenerator keyGen = KeyGenerator.getInstance("AES"); // Generates key generator for AES
        keyGen.init(128); // Set key size to 128 bits
        SecretKey key = keyGen.generateKey(); // Generates a random key

        // Official block by block ciphers
        BufferedImage encryptedECBImage = encryptImage(grayImage, key, ecb); // Generates encrypted image with ECB mode
        BufferedImage encryptedCBCImage = encryptImage(grayImage, key, cbc); // Generates encrypted image with CBC mode

        // Saves encrypted images to file
        File outputFileECB = new File("encrypted_image_ecb.png"); // Specifies the file to save the image encrypted with ECB mode
        File outputFileCBC = new File("encrypted_image_cbc.png"); // Specifies the file to save the image encrypted with CBC mode
        ImageIO.write(encryptedECBImage, "png", outputFileECB); // Writes encrypted image to file with ECB mode
        ImageIO.write(encryptedCBCImage, "png", outputFileCBC); // Writes encrypted image to file with CBC mode

        System.out.println("Encrypted images saved successfully."); // Prints the successful completion of the encryption process on the screen
    }

    public static BufferedImage convertToGray(BufferedImage img) {
        int width = img.getWidth(); // Take the width of the image
        int height = img.getHeight(); // Take the height of the image
        BufferedImage grayImage = new BufferedImage(width, height, BufferedImage.TYPE_BYTE_GRAY); // Creates a grayscale image

        //For each pixel of the img, it takes the following parameters from the img format and converts them to a gray color
        for (int y = 0; y < height; y++) {
            for (int x = 0; x < width; x++) {
                int rgb = img.getRGB(x, y);
                int r = (rgb >> 16) & 0xFF;
                int g = (rgb >> 8) & 0xFF;
                int b = rgb & 0xFF;
                int gray = (r + g + b) / 3;
                int grayPixel = (gray << 16) | (gray << 8) | gray;
                grayImage.setRGB(x, y, grayPixel); // Adding the gray pixel to the gray image
            }
        }

        return grayImage;
    }

    public static BufferedImage encryptImage(BufferedImage img, SecretKey key, String mode) throws Exception {
        int width = img.getWidth();
        int height = img.getHeight();
        BufferedImage encryptedImage = new BufferedImage(width, height, BufferedImage.TYPE_USHORT_GRAY); // Generates an encrypted image

        Cipher cipher = Cipher.getInstance(mode); // Creates an encryptor in the specified mode
        if (mode.equals(ecb)) {
            cipher = Cipher.getInstance(ecb); // Creates an encryptor in the ECB mode
            cipher.init(Cipher.ENCRYPT_MODE, key); // Initialize the encryptor with key

            for (int y = 0; y < height; y++) {
                for (int x = 0; x < width; x++) {
                    int pixel = img.getRGB(x, y); // Gets the value of the pixel
                    byte[] pixelBytes = intToBytes(pixel); // Convert to the byte array
                    byte[] encryptedPixelBytes = cipher.doFinal(pixelBytes); // Convert to the encrypted
                    int encryptedPixel = bytesToInt(encryptedPixelBytes)*1; // Convert encrypted pixel to integer
                    encryptedImage.setRGB(x, y, encryptedPixel); // Adds encrypted pixel to encrypted image
                }
            }
            return encryptedImage;

        } else if (mode.equals(cbc)) {
            byte[] iv = new byte[BLOCK_SIZE]; // Create a byte array for IV
            SecureRandom random = new SecureRandom(); // Creates a secure random number generator
            random.nextBytes(iv); // Fills IV with random bytes
            IvParameterSpec ivSpec = new IvParameterSpec(iv); // Sets IV as a parameter
            cipher = Cipher.getInstance(cbc); // Creates an encryptor in CBC mode
            cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec); // Initialize the encryptor with key and IV

            byte[] previousCipherBlock = iv; // Designates the previous encrypted block as IV

            for (int y = 0; y < height; y++) {
                for (int x = 0; x < width; x++) {
                    int pixel = img.getRGB(x, y); // Gets the value of the pixel
                    byte[] pixelBytes = intToBytes(pixel); // // Convert to the byte array

                    for (int i = 0; i < pixelBytes.length; i++) {
                        pixelBytes[i] ^= previousCipherBlock[i]; // XORs the pixel with the previous encrypted block
                    }

                    byte[] encryptedPixelBytes = cipher.doFinal(pixelBytes); // Ciphers the pixel
                    int encryptedPixel = bytesToInt(encryptedPixelBytes)*-1; // Converts encrypted pixel to integer
                    encryptedImage.setRGB(x, y, encryptedPixel); // Adds encrypted pixel to encrypted image


                    previousCipherBlock = encryptedPixelBytes; // Updates the previous encrypted block
                }
            }
            return encryptedImage;

        } else {
            throw new IllegalArgumentException("Invalid mode specified: " + mode); // throw an error message
        }
    }




    public static byte[] intToBytes(int value) {
        return new byte[]{
                (byte) (value >> 24), // Get the most significant byte of the integer and convert it to byte type
                (byte) (value >> 16), // Take the second most significant byte of the integer and convert it to byte type
                (byte) (value >> 8), // Take the third most significant byte of the integer and convert it to byte type
                (byte) value // Take the least significant byte of the integer and convert it to byte type
        };
    }

    public static int bytesToInt(byte[] bytes) {
        return ((bytes[0] & 0xFF) << 24) | // AND the first element of the byte array with 0xFF and shift it 24 bits to the left
                ((bytes[1] & 0xFF) << 16) | // AND the second element of the byte array with 0xFF and shift it 16 bits to the left
                ((bytes[2] & 0xFF) << 8) | // AND the third element of the byte array with 0xFF and shift it 8 bits to the left
                (bytes[3] & 0xFF); // ANDs the fourth element of the byte array with 0xFF
    }
}


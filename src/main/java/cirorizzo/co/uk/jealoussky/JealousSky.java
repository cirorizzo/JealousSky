package cirorizzo.co.uk.jealoussky;

import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.util.Base64;
import android.util.Log;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class JealousSky {
    private final String TAG = JealousSky.class.getSimpleName();

    private static JealousSky instance = null;

    private final String INIT_ILLEGAL_ARG_KEY = "Invalid Key Argument";
    private final String INIT_ILLEGAL_ARG_SALT = "Invalid Salt Argument";

    private final int DEFAULT_ITERATIONS = 1024;
    private final int DEFAULT_KEY_LENGTH = 128;

    private final String SECURE_RANDOM_ALGORITHM = "SHA1PRNG";

    private final String SECRETKEY_DIGEST_SHA1 = "SHA1";

    private final String SECRETKEY_ALGORITHM_SHA1 = "PBKDF2WithHmacSHA1";
    private final String SECRETKEY_ALGORITHM_CBC = "PBEWithSHA256And256BitAES-CBC-BC";
    private final String ENCRYPTION_ALGORITHM_PCKS5 = "AES/CBC/PKCS5Padding";
    private final String ENCRYPTION_ALGORITHM_NOPAD = "AES/CBC/NoPadding";

    private String key;
    private byte[] salt;
    private byte[] iv;

    private SecureRandom secureRandom;
    private IvParameterSpec ivParameterSpec;

    protected JealousSky() {
        // Exists only to avoid instantiation.
    }

    public static JealousSky getInstance() {
        if (instance == null) {
            instance = new JealousSky();
        }
        return instance;
    }

    /**
     * Initialization for SecureRandom, IVParamSpec, Key (Password) and Salt
     * @param key Password used for Encryption/Decryption
     * @param salt Salt used Password derivation
     * @throws IllegalArgumentException
     * @throws NoSuchAlgorithmException
     */
    public void initialize(String key, String salt) throws IllegalArgumentException, NoSuchAlgorithmException {

        if (!isValidArgKey(key)) {
            throw new IllegalArgumentException(INIT_ILLEGAL_ARG_KEY);
        } else {
            this.key = key;
        }
        if (!isValidArg(salt)) {
            throw new IllegalArgumentException(INIT_ILLEGAL_ARG_SALT);
        } else {
            this.salt = hexStringToByteArray(salt);
        }
        this.iv = new byte[16];

        secureRandom = SecureRandom.getInstance(SECURE_RANDOM_ALGORITHM);
        ivParameterSpec = new IvParameterSpec(this.iv);
    }

    /**
     * Encryption Method
     * @param clearString String to Encrypt
     * @return Byte Array of Encrypted String
     * @throws IOException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchPaddingException
     * @throws InvalidAlgorithmParameterException
     * @throws InvalidKeyException
     * @throws InvalidKeySpecException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     */
    public byte[] encrypt(String clearString)
            throws IOException, NoSuchAlgorithmException, NoSuchPaddingException,
            InvalidAlgorithmParameterException, InvalidKeyException, InvalidKeySpecException,
            BadPaddingException, IllegalBlockSizeException {

        if ((clearString == null) || (clearString.isEmpty())) {
            return null;
        }

        Cipher cipher = getCipher(Cipher.ENCRYPT_MODE);

        return cipher.doFinal(clearString.getBytes("UTF8"));
    }

    /**
     * Encryption Method Wrapper
     * @param clearString String to Encrypt
     * @return Encrypted String
     * @throws NoSuchPaddingException
     * @throws InvalidKeyException
     * @throws NoSuchAlgorithmException
     * @throws IOException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     * @throws InvalidAlgorithmParameterException
     * @throws InvalidKeySpecException
     */
    public String encryptToString(String clearString) throws NoSuchPaddingException,
            InvalidKeyException, NoSuchAlgorithmException, IOException, BadPaddingException,
            IllegalBlockSizeException, InvalidAlgorithmParameterException, InvalidKeySpecException {

        return Base64.encodeToString(encrypt(clearString), Base64.DEFAULT);
    }

    /**
     * Encryption Method Wrapper
     * @param fileInput InputStream of File to Encrypt
     * @return Byte Array of Encryped InputStream
     * @throws IOException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchPaddingException
     * @throws InvalidAlgorithmParameterException
     * @throws InvalidKeyException
     * @throws InvalidKeySpecException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     */
    public byte[] encrypt(InputStream fileInput)
            throws IOException, NoSuchAlgorithmException, NoSuchPaddingException,
            InvalidAlgorithmParameterException, InvalidKeyException, InvalidKeySpecException,
            BadPaddingException, IllegalBlockSizeException {

        Cipher cipher = getCipher(Cipher.ENCRYPT_MODE);

        return getEncryptInputStream(fileInput, cipher);
    }

    /**
     * Encryption Method Wrapper
     * @param fileInput InputStream of File to Encrypt
     * @param fileNameOutput File name of Encrypted File
     * @return Encrypted File
     * @throws NoSuchPaddingException
     * @throws InvalidKeyException
     * @throws NoSuchAlgorithmException
     * @throws IOException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     * @throws InvalidAlgorithmParameterException
     * @throws InvalidKeySpecException
     */
    public File encryptToFile(InputStream fileInput, String fileNameOutput)
            throws NoSuchPaddingException, InvalidKeyException, NoSuchAlgorithmException,
            IOException, BadPaddingException, IllegalBlockSizeException,
            InvalidAlgorithmParameterException, InvalidKeySpecException {

        if ((fileNameOutput == null) || (fileNameOutput.isEmpty())) {
            return null;
        }

        File fileOutput = new File(fileNameOutput);
        FileOutputStream out = new FileOutputStream(fileOutput);

        byte[] encrypted = encrypt(fileInput);

        out.write(encrypted);

        out.flush();
        out.close();

        return fileOutput;
    }

    /**
     * Decryption Method
     * @param encryptedString String to Decrypt
     * @return Byte Array of Decrypted String
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     * @throws IOException
     * @throws NoSuchPaddingException
     * @throws InvalidAlgorithmParameterException
     * @throws InvalidKeyException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     */
    public byte[] decrypt(String encryptedString) throws NoSuchAlgorithmException,
            InvalidKeySpecException, IOException, NoSuchPaddingException,
            InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException,
            IllegalBlockSizeException {

        if ((encryptedString == null) || (encryptedString.isEmpty())) {
            return null;
        }

        Cipher cipher = getCipher(Cipher.DECRYPT_MODE);

        return cipher.doFinal(Base64.decode(encryptedString, Base64.DEFAULT));
    }

    /**
     * Decryption Method Wrapper
     * @param encryptedString String to Decrypt
     * @return Decrypted String
     * @throws NoSuchPaddingException
     * @throws InvalidKeyException
     * @throws NoSuchAlgorithmException
     * @throws IOException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     * @throws InvalidAlgorithmParameterException
     * @throws InvalidKeySpecException
     */
    public String decryptToString(String encryptedString) throws NoSuchPaddingException,
            InvalidKeyException, NoSuchAlgorithmException, IOException, BadPaddingException,
            IllegalBlockSizeException, InvalidAlgorithmParameterException, InvalidKeySpecException {

        return new String(decrypt(encryptedString));
    }

    /**
     * Decryption Method Wrapper
     * @param fileInput InputStream to Decrypt
     * @return Byte Array of Decrypted InputStream
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     * @throws IOException
     * @throws NoSuchPaddingException
     * @throws InvalidAlgorithmParameterException
     * @throws InvalidKeyException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     */
    public byte[] decrypt(InputStream fileInput) throws NoSuchAlgorithmException,
            InvalidKeySpecException, IOException, NoSuchPaddingException,
            InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException,
            IllegalBlockSizeException {

        if ((fileInput == null) || (fileInput.available() == 0)) {
            return null;
        }

        Cipher cipher = getCipher(Cipher.DECRYPT_MODE);

        return getDecryptFromCipherInputStream(fileInput, cipher);
    }

    /**
     * Decryption Method Wrapper
     * @param fileInput InputStream to Decrypt
     * @param fileNameOutput File name of Decrypted File
     * @return Decrypted File
     * @throws NoSuchPaddingException
     * @throws InvalidKeyException
     * @throws NoSuchAlgorithmException
     * @throws IOException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     * @throws InvalidAlgorithmParameterException
     * @throws InvalidKeySpecException
     */
    public File decryptToFile(InputStream fileInput, String fileNameOutput)
            throws NoSuchPaddingException, InvalidKeyException, NoSuchAlgorithmException,
            IOException, BadPaddingException, IllegalBlockSizeException,
            InvalidAlgorithmParameterException, InvalidKeySpecException {

        if ((fileNameOutput == null) || (fileNameOutput.isEmpty())) {
            return null;
        }

        File fileOutput = new File(fileNameOutput);
        FileOutputStream outdec = new FileOutputStream(fileOutput);

        byte[] decryptedStream = decrypt(fileInput);
        outdec.write(decryptedStream);

        outdec.flush();
        outdec.close();

        return fileOutput;
    }

    /**
     * Decryption Method Wrapper
     * @param fileInput InputStream to Decrypt
     * @return Bitmap of Decrypted InputStream
     * @throws NoSuchPaddingException
     * @throws InvalidKeyException
     * @throws NoSuchAlgorithmException
     * @throws IOException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     * @throws InvalidAlgorithmParameterException
     * @throws InvalidKeySpecException
     */
    public Bitmap decryptToBitmap(InputStream fileInput)
            throws NoSuchPaddingException, InvalidKeyException, NoSuchAlgorithmException,
            IOException, BadPaddingException, IllegalBlockSizeException,
            InvalidAlgorithmParameterException, InvalidKeySpecException {

        return BitmapFactory.decodeStream(new ByteArrayInputStream(decrypt(fileInput)));
    }


    //----------------------------------------------------------------------------------------------

    private SecretKey getSecretKey(String secretKeyAlgorithm) throws NoSuchAlgorithmException,
            UnsupportedEncodingException, InvalidKeySpecException {

        SecretKeyFactory factory = SecretKeyFactory.getInstance(secretKeyAlgorithm);
        KeySpec spec = new PBEKeySpec(hashTheKey(key), salt, DEFAULT_ITERATIONS, DEFAULT_KEY_LENGTH);
        SecretKey tmp = factory.generateSecret(spec);

        Log.d(TAG, String.format("hashTheKey(key) %s from (%s)", hashTheKey(key), key));
        return new SecretKeySpec(tmp.getEncoded(), "AES");
    }

    private char[] hashTheKey(String key) throws UnsupportedEncodingException, NoSuchAlgorithmException {

        MessageDigest messageDigest = MessageDigest.getInstance(SECRETKEY_DIGEST_SHA1);
        messageDigest.update(key.getBytes("UTF8"));
        return Base64.encodeToString(messageDigest.digest(), Base64.NO_WRAP).toCharArray();
    }

    private boolean isValidArgKey(String arg) {

        return ((arg != null) && (!arg.isEmpty()));
    }

    private boolean isValidArg(String arg) {

        return ((arg != null) && (!arg.isEmpty()) && ((arg.length() % 2) == 0) && (arg.length() >= 16)) ;
    }

    private byte[] hexStringToByteArray(String s) {

        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }

    private Cipher getCipher(int operationMode) throws NoSuchAlgorithmException, InvalidKeySpecException,
            UnsupportedEncodingException, NoSuchPaddingException, InvalidAlgorithmParameterException,
            InvalidKeyException {

        Cipher cipher = Cipher.getInstance(ENCRYPTION_ALGORITHM_PCKS5);

        cipher.init(
                operationMode,
                getSecretKey(SECRETKEY_ALGORITHM_SHA1),
                ivParameterSpec,
                secureRandom);
        return cipher;
    }



    private byte[] getDecryptFromCipherInputStream(InputStream fis, Cipher cipher) throws IOException {

        ByteArrayOutputStream bos = new ByteArrayOutputStream();

        CipherInputStream cis = new CipherInputStream(fis, cipher);

        byte data[] = new byte[16];
        int read;
        while ((read = cis.read(data)) != -1) {
            bos.write(data, 0, read);
            bos.flush();
        }

        if (bos != null) {
            bos.flush();
            bos.close();
        }

        if (fis != null) {
            fis.close();
        }
        if (cis != null) {
            cis.close();
        }

        return bos.toByteArray();
    }

    private byte[] getByteArrayFromFile(InputStream fileInput) throws IOException {

        ByteArrayOutputStream bos = new ByteArrayOutputStream();

        while (fileInput.available() > 0) {
            bos.write(fileInput.read());
        }

        if (bos != null) {
            bos.flush();
            bos.close();
        }

        if (fileInput != null) {
            fileInput.close();
        }

        return bos.toByteArray();
    }

    private byte[] getByteArrayFromFile(File fileInput) throws IOException {

        InputStream fis = new BufferedInputStream(new FileInputStream(fileInput));
        ByteArrayOutputStream bos = new ByteArrayOutputStream();


        while (fis.available() > 0) {
            bos.write(fis.read());
        }

        if (bos != null) {
            bos.flush();
            bos.close();
        }

        if (fis != null) {
            fis.close();
        }

        return bos.toByteArray();
    }

    private byte[] getEncryptInputStream(InputStream fis, Cipher cipher) throws IOException {

        Log.d(TAG, "AES InputStream " + fis.available());

        ByteArrayOutputStream bos = new ByteArrayOutputStream();

        CipherOutputStream cos = new CipherOutputStream(bos, cipher);

        Log.d(TAG, String.format("AES Starting Reading InputStream available=> %d", (fis.available())));

        byte[] data = new byte[16];
        int read;
        while ((read = fis.read(data)) != -1) {
            cos.write(data, 0, read);
            cos.flush();
        }

        if (cos != null) {
            cos.close();
        }

        if (bos != null) {
            bos.close();
        }

        if (fis != null) {
            fis.close();
        }

        return bos.toByteArray();
    }

}

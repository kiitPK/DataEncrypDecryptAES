package aes.decrypt.encrypt.com.dataencrypdecryptaes;

import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.widget.Toast;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;

public class MainActivity extends AppCompatActivity {

    private static final String ENCRYPTION_ALGORITHM = "AES/CBC/PKCS5Padding";
    private static final String PBE_ALGORITHM = "PBEwithSHA256and128BITAES-CBC-BC";
    private static final int SALT_BYTES = 8;
    private static final int PBK_ITERATIONS = 1000;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        try {
            String password = "pass3241";
            byte[] data = "Data encryption plain text...".getBytes("UTF-8");
            EncryptedData encData = encryptData(password, data);
            byte[] decryptedData = decryptData(password, encData.salt, encData.iv, encData.encryptedData);
            String decDataAsString = new String(decryptedData, "UTF-8");
            Toast.makeText(this, decryptedData.toString(), Toast.LENGTH_LONG).show();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private EncryptedData encryptData(String password, byte[] data) throws NoSuchPaddingException,
            NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, BadPaddingException,
            IllegalBlockSizeException, InvalidAlgorithmParameterException {
        EncryptedData encData = new EncryptedData();
        SecureRandom rnd = new SecureRandom();
        encData.salt = new byte[SALT_BYTES];
        encData.iv = new byte[16]; // AES block size
        rnd.nextBytes(encData.salt);
        rnd.nextBytes(encData.iv);
        PBEKeySpec keySpec = new PBEKeySpec(password.toCharArray(), encData.salt, PBK_ITERATIONS);
        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance(PBE_ALGORITHM);
        Key key = secretKeyFactory.generateSecret(keySpec);
        Cipher cipher = Cipher.getInstance(ENCRYPTION_ALGORITHM);
        IvParameterSpec ivSpec = new IvParameterSpec(encData.iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
        encData.encryptedData = cipher.doFinal(data);
        return encData;
    }
    private byte[] decryptData(String password, byte[] salt, byte[] iv, byte[] encryptedData) throws
            NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException,
            BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException {
        PBEKeySpec keySpec = new PBEKeySpec(password.toCharArray(), salt, PBK_ITERATIONS);
        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance(PBE_ALGORITHM);
        Key key = secretKeyFactory.generateSecret(keySpec);
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
        return cipher.doFinal(encryptedData);
    }
    private static class EncryptedData {
        public byte[] salt;
        public byte[] iv;
        public byte[] encryptedData;
    }

}

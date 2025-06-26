package ru.egoie.util;

import ru.egoie.util.crypt.AESUtils;

import javax.crypto.SecretKey;

public class DecodeAES {
    public static void main(String[] args) {
        if (args.length < 3) {
            System.err.println("Usage: java -jar decrypt-aes.jar [password] [salt] <encrypted>");
            System.exit(1);
        }
        try {
            final String password = args[0];
            final byte[] salt = args[1].getBytes();
            final String encrypted = args[2];
            final SecretKey key = AESUtils.generateKey(password.toCharArray(), salt);
            System.out.println(AESUtils.decrypt(encrypted, key, AESUtils.generateIv(salt)));
        } catch (Exception e) {
            e.printStackTrace(System.err);
        }
    }
}
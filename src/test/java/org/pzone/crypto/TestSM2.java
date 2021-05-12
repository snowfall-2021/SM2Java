package org.pzone.crypto;

import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.util.Scanner;

public class TestSM2 {

    public static void main(String[] args) {
        SM2 x = new SM2();
        Scanner scan= new Scanner(System.in);
        SM2KeyPair keys = x.generateKeyPair();
        ECPoint publicKey = keys.getPublicKey();
        BigInteger privateKey = keys.getPrivateKey();
        System.out.println("Public key: " + publicKey.toString());
        System.out.println("Private key: " + privateKey.toString());
        System.out.print("Enter your Cleartext: ");
        byte[] data = x.encrypt(scan.nextLine(), publicKey);
        System.out.print("Ciphertext: ");
        System.out.println(x.bytesToHex(data));
        String origin = x.decrypt(data, privateKey);
        System.out.println("Decipher: " + origin);
    }
}

package org.pzone.crypto;

import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.util.Scanner;

public class SM2JAVA {

    public static void main(String[] args) {

        Scanner scan= new Scanner(System.in);
        while (true) {
            System.out.print("sm2java# ");
            String command = scan.nextLine();
            switch (getCommand(command)) {
                case 1 -> generateKeyPair();
                case 2 -> encryptCommand();
                case 3 -> decryptCommand();
                case 4 -> help();
                case 5 -> { return; }
                case 0 -> { }
                default -> cnf(command);
            }
        }
    }

    private static void generateKeyPair() {
        SM2 x = new SM2();
        SM2KeyPair keys = x.generateKeyPair();
        ECPoint publicKey = keys.getPublicKey();
        BigInteger privateKey = keys.getPrivateKey();
        System.out.println("Public key: " + publicKey.getXCoord().toString() + publicKey.getYCoord().toString());
        System.out.println("Private key: " + x.bytesToHex(privateKey.toByteArray()));
    }

    private static void encryptCommand() {
        Scanner scan= new Scanner(System.in);
        System.out.print("Enter cleartext: ");
        String cleartext = scan.nextLine();
        System.out.print("Enter public key: ");
        String publicKey = scan.nextLine();
        if (checkPublicKey(publicKey)) {
            String ciphertext = encrypt(cleartext, publicKey);
            System.out.println("Result: " + ciphertext);
        } else {
            System.out.println("Invalid public key.");
        }
    }

    private static String encrypt(String cleartext, String publicKey) {
        SM2 x = new SM2();
        return x.bytesToHex(x.encrypt(cleartext, x.hexToECPoint(publicKey)));
    }

    private static void decryptCommand() {
        Scanner scan= new Scanner(System.in);
        System.out.print("Enter ciphertext: ");
        String ciphertext = scan.nextLine();
        System.out.print("Enter private key: ");
        String privateKey = scan.nextLine();
        if (checkPrivateKey(privateKey)) {
            String cleartext = decrypt(ciphertext, privateKey);
            System.out.println("Result: " + cleartext);
        } else {
            System.out.println("Invalid private key.");
        }
    }

    private static String decrypt(String ciphertext, String privateKey) {
        SM2 x = new SM2();
        return x.decrypt(SM2.hexStringToByteArray(ciphertext), new BigInteger(SM2.hexStringToByteArray(privateKey)));
    }

    private static void help() {
        System.out.println("These commands are defined internally. Type `help' to see this list:\n");
        System.out.println("\tget key-pair\t generate a random SM2 key-pair.");
        System.out.println("\tencrypt\t\t\t encrypt with your SM2 public key.");
        System.out.println("\tdecrypt\t\t\t decrypt with your SM2 private key.");
        System.out.println("\thelp\t\t\t display information about commands.");
        System.out.println("\texit\t\t\t exit sm2java.");
    }

    private static void cnf(String command) {
        System.out.println(command + ": command not found");
    }


    private static int getCommand(String commandString) {
        return switch (commandString) {
            case "get key-pair" -> 1;
            case "encrypt" -> 2;
            case "decrypt" -> 3;
            case "help" -> 4;
            case "exit" -> 5;
            case "" -> 0;
            default -> Integer.MAX_VALUE;
        };
    }

    private static boolean checkPublicKey(String publicKey) { return publicKey.length() == 128; }

    private static boolean checkPrivateKey(String privateKey) { return privateKey.length() == 64; }
}

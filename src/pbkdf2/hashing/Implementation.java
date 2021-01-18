/*
 * Copyright (c) 2021, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package pbkdf2.hashing;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Scanner;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/**
 * This class contains the implementation for PBKDF2 hashing for the passwords and salt read from a external file.
 */
public class Implementation {

    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeySpecException, IOException {

        try {
            int count;
            BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
            System.out.println("Length of the passwords");
            String passwordLength = reader.readLine();
            System.out.println("file name of salt");
            String saltFilename = reader.readLine();
            System.out.println("Enter the iteration count: ");
            int iterations = Integer.parseInt(reader.readLine());
            System.out.println("Enter the derived key length you want (bits): ");
            int keyLength = Integer.parseInt(reader.readLine());
            reader.close();

            ArrayList<String> mySalts =
                    readSaltValuesFromFile("Resources/Salts/" + saltFilename + ".txt");
            ArrayList<char[]> passwordCharArray =
                    passwordArrayInCharArray("Resources/Passwords/" + passwordLength + "letterpasswords.txt");

            for (count = 0; count < 100; count++) { // TODO: 202
                // TODO: 2021-01-12 exception throwing reasons specify.
                //  create a seperate method since it duplicating
                String generatedSecuredPasswordHash = generateStrongPasswordHash(passwordCharArray.get(count),
                        mySalts.get(count), iterations, keyLength);
            }
            long start = System.currentTimeMillis();
            for (count = 0; count < 10000; count++) {
                String generatedSecuredPasswordHash = generateStrongPasswordHash(passwordCharArray.get(count),
                        mySalts.get(count), iterations, keyLength);
            }
            long end = System.currentTimeMillis();
            double averageElapsedTime = Long.valueOf(end - start).doubleValue() / count;

            System.out.println(averageElapsedTime);
        } catch (FileNotFoundException e) {
            System.out.println("An error occurred.");
            e.printStackTrace();
        }
    }

    /**
     * This method is responsible for calculating the PBKDF2 hash value and the time taken for PBKDF2 hashing functions.
     *
     * @param password   the password which needs to be hashed.
     * @param salt       the salt which is used for this hashing.
     * @param iterations iteration count which indicates the number which hashing used iteratively.
     * @param keyLength  the expected length of password hash in bits.
     * @return the string array which contains the hash value and the time taken for the particular PBKDF2 hashing.
     * @throws NoSuchAlgorithmException This is thrown if there were no any algorithm named PBKDF2WithHmacSHA1 in
     * Secret Factory class.
     * @throws InvalidKeySpecException
     */
    private static String generateStrongPasswordHash(char[] password, String salt,
                                                     int iterations, int keyLength) throws NoSuchAlgorithmException,
            InvalidKeySpecException {

        PBEKeySpec spec = new PBEKeySpec(password, hexStringToByteArray(salt), iterations, keyLength);
        SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        byte[] hash = skf.generateSecret(spec).getEncoded();
        return toHex(hash);
    }

    /**
     * This method responsible for converting the resultant hash of byte array to hexadecimal.
     *
     * @param array resultant hash in byte array.
     * @return hexadecimal hash value in string.
     */
    private static String toHex(byte[] array) {

        BigInteger bi = new BigInteger(1, array);
        String hex = bi.toString(16);
        int paddingLength = (array.length * 2) - hex.length();

        if (paddingLength > 0) {
            return String.format("%0" + paddingLength + "d", 0) + hex;
        } else {
            return hex;
        }
    }

    /**
     * This method is responsible for reading the salt value from a file which contains the salt in each line.
     * @param filename the filename which has the sats.
     * @return String array list which contains all the salt values.
     */
    private static ArrayList<String> readSaltValuesFromFile(String filename) {

        ArrayList<String> salt = new ArrayList<>();

        try {
            File myObj = new File(filename);
            Scanner myReader = new Scanner(myObj);
            while (myReader.hasNextLine()) {
                String saltString = myReader.nextLine();
                salt.add(saltString);
            }
            myReader.close();
        } catch (FileNotFoundException e) {
            System.out.println("An error occurred.");
            e.printStackTrace(); // TODO: 2021-01-07 end the flow while FileNotFoundException
        }
        return salt;
    }

    /**
     * this method is responsible for converting the hexadecimal string value to byte array.
     *
     * @param s the hexadecimal string which needs to be converted to byteArray.
     * @return respective byteArray for the hexadecimal string.
     */
    private static byte[] hexStringToByteArray(String s) {

        int len = s.length();
        byte[] data = new byte[len / 2];

        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }

    /**
     * This class is responsible for creating a password array in char[] with the passwords read from the file.
     *
     * @param filename the filename which has the passwords.
     * @return returns the char[] of array which contains all the char [] for respective passwords read from the file.
     * @throws FileNotFoundException This exception is thrown when there is no file in the name given for filename.
     */
    private static ArrayList<char[]> passwordArrayInCharArray(String filename) throws FileNotFoundException {

        ArrayList<char[]> passwordArray = new ArrayList<>();
        File myObj = new File(filename);
        Scanner myReader = new Scanner(myObj);

        while (myReader.hasNextLine()) {
            String password = myReader.nextLine();
            char[] chars = password.toCharArray();
            passwordArray.add(chars);
        }
        myReader.close();
        return passwordArray;
    }
}

// TODO: 2021-01-13 recommended derived key length
// TODO: 2021-01-13 recommended salt length

/*
 * CryptoSuite.java
 *
 * Created on November 14, 2007, 4:38 PM
 *
 * To change this template, choose Tools | Options and locate the template under
 * the Source Creation and Management node. Right-click the template and choose
 * Open. You can then make changes to the template in the Source Editor.
 */

/**
 *
 * @author Balaji Subramanian (UFID:9145-9791)
 */

import java.math.BigInteger;
import java.util.Vector;
import javax.crypto.Cipher;
import java.security.Key;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.NoSuchPaddingException;
import java.security.NoSuchAlgorithmException;
import java.security.InvalidKeyException;

public class CryptoSuite {
    
    public static enum CRYPTO_SUITE{
        NONE,
        DES_CFB,
        DES3_PCBC,
        DES3_CBC,
        RC4
    };
    
    public static final int MAX_OCTET = 256; 
    public static final int MAX_SIZE = 500;
    //public static final String KEY = "RC4 KEY: Ignorance is bliss!";
    public static String KEY = "Wiki";
    
    // Server's public/private key info
    public static final int D = 147;
    public static final int E = 3;
    public static final int N = 253;
    
    // CA's public/private key info.
    public static final int CA_D = 173;
    public static final int CA_E = 5;
    public static final int CA_N = 247;
    
    // DES KEY shared secret.
    public static String DES_KEY_STR1 = "12345678";
    public static String DES_KEY_STR2 = "23456789";
    public static final byte INITIALIZATION_VECTOR = 127;
    public static final int SHARED_SECRET = 8563;
    
    public static final String END_BLK = "!@#$%";
    public static SecretKey desKey1, desKey2;
    public static CRYPTO_SUITE cryptoType = CRYPTO_SUITE.NONE;
    
    /**
     * Creates a new instance of CryptoSuite
     */
    public CryptoSuite() {
    }
    
    public static void initDESKeys(String sessionKey) {
        try {
            // Generate the DES Key based on the given session id.
            if (sessionKey.length() >= 10) {
                //DES_KEY_STR1 = sessionKey.substring(0, 8);
                //DES_KEY_STR2 = sessionKey.substring(1, 9);
            }
            //System.out.println("The 2 DES keys used are:" + DES_KEY_STR1 + " and " + DES_KEY_STR2);
            desKey1 = new SecretKeySpec(DES_KEY_STR1.getBytes(), "DES");
            desKey2 = new SecretKeySpec(DES_KEY_STR2.getBytes(), "DES");
            // Used for calculating the MAC.
            KEY = sessionKey;
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    /**
     * This function is used to encrypt the message block using 3DES.
     */
    public static byte[] encrypt3DES(byte plainTextByte[]) {
        try {
            byte[] firstPassText = encryptDES(plainTextByte, desKey1);
            if (firstPassText == null)
                return null;
            System.out.println("firstPassText:" + firstPassText);
            byte[] secondPassText = decryptDES(firstPassText, desKey2);
            if (secondPassText == null)
                return null;            
            byte[] cipherText = encryptDES(secondPassText, desKey1);
            return (cipherText);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return (null);
    }
    
    /**
     * This function is used to decrypt the cipher text message to
     * plaintext using 3DES algorithm.
     */
    public static byte[] decrypt3DES(byte[] cipherTextByte) {
        try {
            byte[] firstPassText = decryptDES(cipherTextByte, desKey1);
            if (firstPassText == null)
                return null;
            byte[] secondPassText = encryptDES(firstPassText, desKey2);
            if (secondPassText == null)
                return null;
            byte[] plainText = decryptDES(secondPassText, desKey1);
            return (plainText);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return (null);
    }
    
    /**
     * This method is used for decrypting the cipherText with DES.
     * Returns the plainText string.
     */
    /*
    public static byte[] decryptDES(byte[] cipherTextByte, SecretKey desKey) {
        try {
            Cipher dcipher = Cipher.getInstance("DES");
            dcipher.init(Cipher.DECRYPT_MODE, desKey);            
            byte [] plainTextByte = dcipher.doFinal(cipherTextByte);            
            return plainTextByte;
        } catch (InvalidKeyException ike) {
            ike.printStackTrace();
        } catch (NoSuchAlgorithmException nsa) {
            nsa.printStackTrace();
        } catch (NoSuchPaddingException npe) {
            npe.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    } */
    public static byte[] decryptDES(byte[] cipherByte, SecretKey desKey) {
        try {
            Cipher dcipher = Cipher.getInstance("DES/ECB/NoPadding");
            dcipher.init(Cipher.DECRYPT_MODE, desKey);
            //System.out.println("cipherbyte len:" + cipherByte.length);
            if (cipherByte.length % 8 != 0) {                
                byte []tmpByte = new byte[cipherByte.length];
                for (int i = 0; i < cipherByte.length; i++)
                     tmpByte[i] = cipherByte[i];
                cipherByte = new byte[cipherByte.length + (8 - cipherByte.length % 8)];
                for (int i = 0; i < tmpByte.length; i++)
                    cipherByte[i] = tmpByte[i];
                for (int i = tmpByte.length; i < cipherByte.length; i++)
                    cipherByte[i] = 0;
            }
            //System.out.println("cipherbyte len:" + cipherByte.length);            
            byte[] plainTextByte = dcipher.doFinal(cipherByte);
            return plainTextByte;
        } catch (InvalidKeyException ike) {
            ike.printStackTrace();
        } catch (NoSuchAlgorithmException nsa) {
            nsa.printStackTrace();
        } catch (NoSuchPaddingException npe) {
            npe.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }    
    
    /**
     * This method is used for encrypting the plaintext with DES.
     * Returns the encrypted string.
     */
    /*
    public static byte[] encryptDES(byte[] plainTextByte, SecretKey desKey) {
        try {
            Cipher ecipher = Cipher.getInstance("DES");
            ecipher.init(Cipher.ENCRYPT_MODE, desKey);
            byte [] cipherTextByte = ecipher.doFinal(plainTextByte);
            return cipherTextByte;
        } catch (InvalidKeyException ike) {
            ike.printStackTrace();
        } catch (NoSuchAlgorithmException nsa) {
            nsa.printStackTrace();
        } catch (NoSuchPaddingException npe) {
            npe.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }*/
    public static byte[] encryptDES(byte[] utfByte, SecretKey desKey) {
        try {
            Cipher ecipher = Cipher.getInstance("DES/ECB/NoPadding");
            ecipher.init(Cipher.ENCRYPT_MODE, desKey);            
            if (utfByte.length % 8 != 0) {
                byte []tmpByte = new byte[utfByte.length];
                for (int i = 0; i < tmpByte.length; i++)
                     tmpByte[i] = utfByte[i];
                utfByte = new byte[utfByte.length + (8 - utfByte.length % 8)];
                for (int i = 0; i < tmpByte.length; i++)
                    utfByte[i] = tmpByte[i];
                for (int i = tmpByte.length; i < utfByte.length; i++)
                    utfByte[i] = 0;
            }
            //System.out.println("utfByte len: " + utfByte.length);
            byte[] encText = ecipher.doFinal(utfByte);
            return encText;
        } catch (InvalidKeyException ike) {
            ike.printStackTrace();
        } catch (NoSuchAlgorithmException nsa) {
            nsa.printStackTrace();
        } catch (NoSuchPaddingException npe) {
            npe.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }    
    
    /**
     * This method is used to encrypt the block of plaintext using
     * Cipher Feedback (CFB). Encryption is done by the following operation:
     * C{i} = E{k} (C{i - 1}) XOR P{i}
     * C{0} = IV
     */
    public static byte[] encryptCFB(byte[] plainText) {
        try {
            int N = plainText.length;
            byte cipherTextByte[] = new byte[N + 1];
            // CipherText[N] is initialized to the IV for making implementation simpler.
            cipherTextByte[0] = INITIALIZATION_VECTOR;            
            for (int i = 1; i <= N; i++) {
                byte[] tmpByte = new byte[1];
                tmpByte[0] = cipherTextByte[i - 1];
                byte encText[] = encryptDES(tmpByte, desKey1);
                //System.out.println("encText:" +encText[0]);                
                cipherTextByte[i]  = (byte)(encText[0] ^ plainText[i - 1]);
            }
            return (cipherTextByte); 
        } catch (Exception e) {
            e.printStackTrace();
        }
        return (null);
    }
     
    /**
     * This method is used to decrypt the block of ciphertext using
     * Cipher Feedback (CFB). Decryption is done by the following operation:
     * P{i} = E{k} (P{i - 1}) XOR C{i}
     * P{0} = IV
     */
    public static byte[] decryptCFB(byte[] cipherText) {
        try {
            int N = cipherText.length;
            byte plainTextByte[] = new byte[N - 1];
            
            for (int i = 1; i < N; i++) {
                byte[] tmpByte = new byte[1];
                tmpByte[0] = cipherText[i - 1];                
                byte encText[] = encryptDES(tmpByte, desKey1);
                //System.out.println("decText:" +encText[0]);           
                plainTextByte[i - 1]  = (byte)(encText[0] ^ cipherText[i]);
            }
            return (plainTextByte); 
        } catch (Exception e) {
            e.printStackTrace();
        }
        return (null);
    }
    
    /**
     * This method is used for generating the CBC on inside. 
     */
    public static byte[] encryptICBC(byte[] plainTextBytes) {
        try {
            int N = plainTextBytes.length;
            byte[] cipherBytes = new byte[N];
            byte[] interBytes = new byte[N + 1];
            // Store the initialization vector.
            interBytes[0] = INITIALIZATION_VECTOR;
            for (int i = 1; i < N; i++) {
                byte xorResult1 = (byte) (interBytes[i] ^ plainTextBytes[i]);
                byte[] tmp1 = new byte[1];
                tmp1[0] = xorResult1;
                byte[] tmp2 = encryptDES(tmp1, desKey1);
                interBytes[i + 1] = tmp2[0];
                byte[] tmp3 = decryptDES(tmp2, desKey2);
                if (i != 0) {
                    byte xorResult2 = (byte) (interBytes[i] ^ cipherBytes[i] ^ tmp3[0]);
                    byte[] tmp4 = new byte[1];
                    tmp4[0] = xorResult2;
                    byte[] tmp5 = encryptDES(tmp4, desKey1);
                    cipherBytes[i] = tmp5[0];
                } else {
                    byte[] tmp4 = encryptDES(tmp3, desKey1);
                    cipherBytes[i] = tmp4[0];
                }
            }            
        } catch (Exception e) {
            e.printStackTrace();
        }
        return (null);
    }
    
    /**
     * This method is used for generating the CBC cipher for the given
     * plaintext message. It uses the 3DES/CBC algorithm to perform
     * encryption.
     * C[i] = E[k](P[i] XOR C[i -1]), C[0] = IV
     */
    public static byte[] encryptCBC(byte[] plainTextBytes) {
        try {
            int N = plainTextBytes.length;
            byte xorResult;
            byte[] cipherBytes = new byte[N * 8];
            byte[] encResult = new byte[8];
            // Store the initialization vector.
            //cipherBytes[0] = INITIALIZATION_VECTOR;
            for (int i = 0, j  = 0; i < N; i++, j+=8) {
                if (i != 0)
                    encResult[0] = (byte) (plainTextBytes[i] ^ cipherBytes[j -8]);
                 else 
                    encResult[0] = (byte) (plainTextBytes[i] ^ INITIALIZATION_VECTOR);
                
                //System.out.println("xor result in CBC encryption:" + xorResult);
                //byte[] tmp = new byte[1];
                //tmp[0] = xorResult;
                //encResult[0] = xorResult;
                for (int k = 1; k < 8; k++)
                    encResult[k] = cipherBytes[j+k];
                encResult = encrypt3DES(encResult);
                for ( int k = 0; k < 8; k++)
                    cipherBytes[j + k] = encResult[k];
                //cipherBytes[i] = encResult[i - 1];
                //byte[] encResult = encryptDES(tmp, desKey1);
                /*
                for (int j = 0; j < encResult.length; j++)
                    System.out.println("encResult:" + encResult[j]);
                byte[] decResult = decryptDES(encResult, desKey1);
                for (int j = 0; j < decResult.length; j++)
                    System.out.println("decResult:" + decResult[j]);
                System.out.println("after xor:" + (((int) decResult[0]) ^ ((int) cipherBytes[i - 1])));*/
                //cipherBytes[i] = encResult[0];
                //cipherBytes[i] = xorResult;
            }
            //for (int i = 1; i <= N; i++)
              //  cipherBytes[i] = encResult[i - 1];
            return (cipherBytes);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return (null);
    }
    
    /**
     * This method is used for decrypting the CBC cipher into plaintext
     * message using CBC/3DES algorithm.
     * P[i] = D[k](C[i]) XOR C[i - 1], C[0] = IV
     */
    public static byte[] decryptCBC(byte[] cipherBytes) {
        try {
            int N = cipherBytes.length / 8;
            byte[] plainTextBytes = new byte[N];
            byte[] decResult = new byte[8];
            //plainTextBytes = cipherBytes;
            // Store the initialization vector.
            //cipherBytes[0] = INITIALIZATION_VECTOR;
            for (int i = 0; i < N; i++) {
                //byte[] tmp = new byte[1];
                //tmp[0] = cipherBytes[i];
                //System.out.println("cip:" + tmp[0]);
                //plainTextBytes[i] = cipherBytes[i];
                for (int k = 0; k < 8; k++)
                    decResult[k] = cipherBytes[8 * i + k];
                decResult = decrypt3DES(decResult);
                if (i != 0)
                    plainTextBytes[i] = (byte) (decResult[0] ^ cipherBytes[8 * (i - 1)]);
                else
                    plainTextBytes[i] = (byte) (decResult[0] ^ INITIALIZATION_VECTOR);
                //System.out.println("dec:" + (plainTextBytes[i] ^ cipherBytes[i - 1]));
                //plainTextBytes[i - 1] = (byte) (plainTextBytes[i -1] ^ cipherBytes[i - 1]);
                //plainTextBytes[i - 1] = (byte) (cipherBytes[i] ^ cipherBytes[i - 1]);
            }
            return (plainTextBytes);          
        } catch (Exception e) {
            e.printStackTrace();
        }
        return (null);
    }
    
    /**
     * This method is used for encrypting the plaintext into PCBC cipher
     * using PCBC/3DES algorithm. The algorithm is given by:
     * C[i] = E{k} (P[i] XOR P[i -1] XOR C[i -1]), P[0] XOR C[0] = IV
     * P[i] XOR C[i] can be substituted by B[i],
     * C[i] = E{k} (P[i] XOR B[i - 1]}, where B[0] = IV;
     */
    public static byte[] encryptPCBC(byte[] plainTextBytes) {
        try {
            int N = plainTextBytes.length;
            byte[] cipherBytes = new byte[N];
            // intermediateCipher is represented as B[i]
            byte[] intermediateCipher = new byte[ N + 1];
            // Initialize the intermediateCipher
            intermediateCipher[0] = INITIALIZATION_VECTOR;
            for (int i = 0; i < N; i++) {
                byte xorResult = (byte) (plainTextBytes[i] ^
                        intermediateCipher[i]);
                byte[] tmp = new byte[1];
                tmp[0] = xorResult;
                byte[] encResult = encrypt3DES(tmp);
                //cipherBytes[i] = encResult[0];
                cipherBytes[i] = xorResult;
                // Calculate the intermediate cipher for the next iteration.
                intermediateCipher[i + 1] = (byte) (plainTextBytes[i] ^
                        cipherBytes[i]);                
            }
            return (cipherBytes);   
            
        } catch (Exception e) {
            e.printStackTrace();
        }
        return (null);
    }
    
    /**
     * This method is used for decrypting the PCBC cipher into plaintext message.
     * The algorithm is given by:
     * P[i] = D{k} (C[i]) XOR P[i -1] XOR C[i -1], P[0] XOR C[0] = IV
     * P[i] XOR C[i] can be substituted by B[i],
     * P[i] = D{k} (C[i]) XOR B[i - 1]
     */
    public static byte[] decryptPCBC(byte[] cipherTextBytes) {
        try {
            int N = cipherTextBytes.length;
            byte[] plainTextBytes = new byte[N];
            // intermediateCipher is represented as B[i]
            byte[] intermediateCipher = new byte[ N + 1];
            // Initialize the intermediateCipher
            intermediateCipher[0] = INITIALIZATION_VECTOR;
            for (int i = 0; i < N; i++) {
                byte[] tmp = new byte[1];
                tmp[0] = cipherTextBytes[i];
                byte[] decResult = decrypt3DES(tmp);                
                //plainTextBytes[i] = (byte) (decResult[0] ^
                //        intermediateCipher[i]);
                plainTextBytes[i] = (byte) (cipherTextBytes[i] ^
                        intermediateCipher[i]);
                // Calculate the intermediate cipher for the next iteration.
                intermediateCipher[i + 1] = (byte) (plainTextBytes[i] ^
                        cipherTextBytes[i]);
            }
            return (plainTextBytes);            
        } catch (Exception e) {
            e.printStackTrace();
        }
        return (null);
    }    
    
    /**
     * This method is used for encrypting the plainText with the RSA
     * public key. This function returns a cipher text, which is the
     * RSA encrypted text for given plain text.
     */
    public static byte[] encodeRSACipher(byte[] plainTextBytes, int eKey, int nVal) { 
        try {
            int len = plainTextBytes.length;
            byte cipherTextBytes[] = new byte[len];
            
            for (int i = 0; i < len; i++) {
                // Encryprtion: c = ( p ^ eKey) mod nVal
                BigInteger p = BigInteger.valueOf(plainTextBytes[i]);
                BigInteger c = p.modPow(BigInteger.valueOf(eKey),
                        BigInteger.valueOf(nVal));
                cipherTextBytes[i] = c.byteValue();                
            }            
            return (cipherTextBytes);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return (null);
    }
    
    /**
     * This function is used for decrypting the cipher text to plaintext
     * using RSA private key. This function takes a RSA encrypted text as input.
     * It returns plaintext message.
     */
    public static byte[] decodeRSACipher(byte[] cipherTextBytes, int dKey, int nVal) {
        try {
            int len = cipherTextBytes.length;
            byte[] plainTextBytes = new byte[len];
            for (int i = 0; i < len; i++) {
                // Decryption: p = ( c ^ dKey) mod nVal
                BigInteger c = BigInteger.valueOf(cipherTextBytes[i]);
                BigInteger p = c.modPow(BigInteger.valueOf(dKey),
                        BigInteger.valueOf(nVal));
                plainTextBytes[i] = p.byteValue();
            }
            return (plainTextBytes);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return (null);
    }
    
    /**
     * This method is used to generate the RC4 cipher.
     */
    public static String getRC4Cipher(String plainText) {
            int S[] = new int[MAX_OCTET];
            StringBuffer output = new StringBuffer("");           
        try {            
            if (plainText == null)
                return output.toString();
            
            for (int i = 0; i < MAX_OCTET; i++)
                S[i] = i;            
            for (int j = 0, i = 0; i < MAX_OCTET; i++) {
                j = ( j + S[i] + KEY.codePointAt(i % KEY.length())) %
                  MAX_OCTET;
                // Exchange the state info at i and j.
                S[i] += S[j];
                S[j] = S[i] - S[j];
                S[i] = S[i] - S[j];
            }
            
            for ( int i = 0, j = 0, k = 0; k < plainText.length(); k++) {
                i += 1 &  0xFF;
                j = (( j + S[i]) % MAX_OCTET) & 0xFF;
                // Exchange the state info at i and j.
                S[i] += S[j];
                S[j] = S[i] - S[j];
                S[i] = S[i] - S[j];
                int r  = S[(S[i] + S[j])% MAX_OCTET];
                output.append(plainText.codePointAt(k) ^ S[r]);
                //output.append(Integer.toHexString((S[i] + S[j])% MAX_OCTET));
            }
            if (output.toString().length() > 16)
                return output.toString().substring(0, 16);
            else
                return output.toString();
        } catch (Exception e) {
                e.printStackTrace();
        }
        return output.toString();
    }
    
    /**
     * This function is used by the MTM attacker to modify the cipher block or
     * to swap the cipher blocks.
     * Input: input bytes,
     * Return: output bytes
     */
    public static byte[] mtmChangeCipherBlock(byte[] inputBytes) {
        try {
            // 2 types of attack possible: i) Modifying Cipher Blocks
            // ii) Rearranging cipher blocks
            int inputByteLen = inputBytes.length;
            boolean modCipherBlk = true;
            byte[] outputBytes = new byte[inputByteLen];
            int randVal = (int)(Math.random() * 100);
            if (inputByteLen > 1)
                 modCipherBlk = (randVal % 2) == 0 ? true: false;
            if (modCipherBlk) {                
                // Changing the first byte to garbage value.
                outputBytes[0] = (byte) randVal;
                for (int i = 1; i < inputByteLen; i++)
                    outputBytes[i] = inputBytes[i];
            } else {
                // Rearrange the first and second block.
                for (int i = 0; i < inputByteLen; i++)
                    outputBytes[i] = inputBytes[i];                
                byte tmpByte = outputBytes[0];
                outputBytes[0] = outputBytes[1];
                outputBytes[1] = tmpByte;
            }
            // Return the output bytes.
            return (outputBytes);      
        } catch (Exception e) {
            e.printStackTrace();
        }
        return (null);
    }
    
    /**
     * This function is used to write the output into the socket.
     * Input: socket, String
     * Return: Success/Failure
     */
    public static boolean writeSocket(Socket sock, String oString, CRYPTO_SUITE type) {
        try {
            String outString = oString + END_BLK;
            DataOutputStream out = new DataOutputStream(sock.getOutputStream());
            byte[] writeBytes = outString.getBytes();
            switch (type) {
                case DES_CFB: {
                    // If DES/CFB is used for encryption, encrypt using the
                    // des/CFB encryption algorithm.
                    byte[] cipherBytes = encryptCFB(writeBytes);
                    out.write(cipherBytes);
                    break;
                }
                case DES3_CBC: {
                    // If 3DES/CBC is used for encryption, call the 3DES/CBC enc. function
                    byte[] cipherBytes = encryptCBC(writeBytes);
                    out.write(cipherBytes);
                    break;
                }
                case DES3_PCBC: {
                    // If 3DES/PCBC is used for encryption and integrity protection, call the
                    // 3DES/PCBC encryption algorithm.
                    byte[] cipherBytes = encryptPCBC(writeBytes);
                    out.write(cipherBytes);
                    break;
                }
                case RC4:
                    // Calculate the RC4 hash. append it with the message and send it.
                    String rc4Hash = getRC4Cipher(oString);
                    String writeText = oString + "###" + rc4Hash + END_BLK;
                    out.write(writeText.getBytes());
                    break;
                case NONE:
                default:
                    // If no encryption is used (for plaintext transmission)
                    // write the output directly.
                    out.write(writeBytes);
                    break;
            }
            // Return success.
            return true;
        } catch (Exception e) {
            e.printStackTrace();
        }
        // Return failure
        return false;
    }
    
    /**
     * This function is used by the MTM to read from the socket.
     * Input: socket
     * Return: byte array
     */
    public static byte[] mtmReadFromSocket(Socket sock) {
        try {
            sock.setSoTimeout(10000);
            DataInputStream in = new DataInputStream(sock.getInputStream());
            byte[] readBytes = new byte[MAX_SIZE];
            int numBytesRead = in.read(readBytes);
            return (readBytes);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return (null);
    }
    
    /**
     * This function is used by MTM to send the data packet.
     * Input: socket, bytes
     * output: Success/Failure.
     */
    public static boolean mtmWriteSocket(Socket sock, byte[] outBytes) {
        try {
            DataOutputStream out = new DataOutputStream(sock.getOutputStream());
            out.write(outBytes);
            // Return Success
            return true;
        } catch (Exception e) {
            e.printStackTrace();
        }
        // return failure
        return false;
    }
    
    /**
     * This function is used to read the input from the Socket.
     * Input:  socket.
     * Return: string.
     */
    public static String readFromSocket(Socket sock, CRYPTO_SUITE type) {
        String retString = "";
        try {            
            sock.setSoTimeout(10000);
            DataInputStream in = new DataInputStream(sock.getInputStream());
            byte[] readBytes = new byte[MAX_SIZE];            
            int numBytesRead = in.read(readBytes);
            switch (type) {
                case DES_CFB: {
                    // If DES/CFB is used for encryption, decrypt using the
                    // des/CFB decryption algorithm.
                    byte[] plainTextBytes = decryptCFB(readBytes);
                    retString = new String(plainTextBytes);
                    if (retString != null && (retString.indexOf(END_BLK) != -1))
                        retString = retString.substring(0, retString.indexOf(END_BLK));
                    break;
                }    
                case DES3_CBC: {
                    // If 3DES/CBC is used for encryption, decrypt using the 3DES/CBC
                    // decryption algorithm.
                    byte[] plainTextBytes = decryptCBC(readBytes);
                    retString = new String(plainTextBytes);
                    if (retString != null && (retString.indexOf(END_BLK) != -1))
                        retString = retString.substring(0, retString.indexOf(END_BLK));
                    break;
                }
                case DES3_PCBC: {
                    // If 3DES/PCBC is used for encryption and integrity protection, decrypt
                    // using the PCBC decryption algorithm.
                    byte[] plainTextBytes = decryptPCBC(readBytes);
                    retString = new String(plainTextBytes);
                    if (retString != null && (retString.indexOf(END_BLK) != -1))
                        retString = retString.substring(0, retString.indexOf(END_BLK));                    
                    break;
                }
                case RC4:
                    // IF RC4 is used for integrity protection, get the hash value for the
                    // given string.
                    retString = new String(readBytes);
                    if (retString != null && (retString.indexOf(END_BLK) != -1))
                        retString = retString.substring(0, retString.indexOf(END_BLK));                    
                    String retStringSubstr[] = retString.split("###");
                    String compHashVal = getRC4Cipher(retStringSubstr[0]);
                    System.out.println("Computed hash value:" + compHashVal);
                    System.out.println("Received hash value:" + retStringSubstr[1]);
                    retString = retStringSubstr[0];
                    //retString = .getRC4Cipher()
                    break;
                case NONE:
                default: 
                    // If no encryption is used for plaintext transmission,
                    // get the string directly.
                    retString = new String(readBytes);
                    if (retString != null && (retString.indexOf(END_BLK) != -1))
                        retString = retString.substring(0, retString.indexOf(END_BLK));
                    break;
            }
            return (retString.trim());
        } catch (SocketTimeoutException ste) {
            retString = END_BLK;
            //System.out.println("Socket timeout exception raised." + retString);
            return (retString);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return (null);
    }
    
    /**
     * This function is used to get the server certificate.
     * The certificate is: server's public key signed by CA's digital signature.
     * Returns the signed certificate.
     */
    public static byte[] getServerCertificate() {
        try {
            byte[] serverBytes = new byte[1];
            serverBytes[0] = E;
            // Sign the certificate with CA's private key.
            byte[] certBytes = encodeRSACipher(serverBytes, CA_D, CA_N);
            return (certBytes);
        } catch (Exception e) {
            e.printStackTrace();
        }        
        return (null);
    }
    
    /**
     * This function is used to verify the server certificate.
     * It is validated by decrypting the server certificate with known
     * CA's public key.
     * Returns the server public key.
     */
    public static int verifyCertificate(byte[] servCert) {
        try {
            // Verify the server certificate.
            byte[] servKey = decodeRSACipher(servCert, CA_E, CA_N);
            return ((int)servKey[0]);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return 0;
    }
    
    /**
     * This function is used to calculate the Key.
     * It is calculated by using the client's random number, server random
     * number, the Server's secret.
     */
    public static String calculateKey(int secret, int randClient, int randServer) {
        try {
            int xorVal = (randClient ^ randServer ^ secret);
            // Perform RC4 hash on the secret.
            String rc4Val = getRC4Cipher(String.valueOf(xorVal));
            return (rc4Val);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return (null);
    }
    
    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        try {
        // TODO code application logic here
            System.out.println("RC4 cipher");
            String cipherText = getRC4Cipher("helper");
            System.out.println(cipherText.toUpperCase());
            //byte[] tmp = new byte[1]; 
            /*byte[] tmp = String.valueOf(27).getBytes();
            for (int i = 0; i < tmp.length; i++)
                System.out.println(" plain:" + tmp[i]);
            byte[] encVec = encodeRSACipher("108653".getBytes(), E, N);            
            for(int i = 0; i < encVec.length; i++)
                System.out.println("RSA plain:" + encVec[i]);
            byte[] decText = decodeRSACipher(encVec, D, N);
            for(int i = 0; i < decText.length; i++)
                System.out.println("RSA cipher:" + decText[i]);            
            System.out.println("RSA plainText:" + new String(decText));*/
            initDESKeys("1234567890");

            /*byte[] des3encByte = encrypt3DES("Lets get it started..".getBytes());
            for (int i = 0; i < des3encByte.length; i++)
                System.out.println("desEncByte:" + des3encByte[i]);
            byte[] des3decByte = decrypt3DES(des3encByte);
            for (int i = 0; i < des3decByte.length; i++)
                System.out.println("desDecByte:" + des3decByte[i]);
            System.out.println("3DES decrypt:" + new String(des3decByte));*/
            
            /*byte desEncByte[] = encryptDES("ZZ".getBytes(), desKey1);
            for (int i = 0; i < desEncByte.length; i++)
                System.out.println("desEncByte:" + desEncByte[i]);
            
            byte desDecByte[] = decryptDES(desEncByte, desKey1);
            for (int i = 0; i < desDecByte.length; i++)
                System.out.println("desDecByte:" + desDecByte[i]);
            System.out.println("After decryption:" + new String(desDecByte));*/
            
            byte cfbEncByte[] = encryptPCBC("I know what u did last".getBytes());
            for (int i = 0; i < cfbEncByte.length; i++)
                System.out.println("cfbEncByte:" + cfbEncByte[i]);
            System.out.println("After PCBC encryption:" + new String(cfbEncByte));
            
            byte cfbDecByte[] = decryptPCBC(cfbEncByte);
            for (int i = 0; i < cfbDecByte.length; i++)
                System.out.println("cfbDecByte:" + cfbDecByte[i]);
            System.out.println("After PCBC decryption:" + new String(cfbDecByte));
            /*byte[] servCert = getServerCertificate();
            for(int i =0 ; i < servCert.length; i++)
                System.out.println("serv cert:" + servCert[i]);
            int servKey = verifyCertificate(servCert);            
            System.out.println("server cert. key:" + servKey);*/
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
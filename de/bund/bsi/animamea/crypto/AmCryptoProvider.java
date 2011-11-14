package de.bund.bsi.animamea.crypto;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Security;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.AESFastEngine;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public abstract class AmCryptoProvider {
	
	public AmCryptoProvider() {
		Security.addProvider(new BouncyCastleProvider());
	}
	
	public abstract void decrypt(InputStream in, OutputStream out) throws ShortBufferException, IllegalBlockSizeException, BadPaddingException, DataLengthException, IllegalStateException, InvalidCipherTextException, IOException;
	public abstract byte[] encrypt(byte[] in) throws ShortBufferException, IllegalBlockSizeException, BadPaddingException, DataLengthException, IllegalStateException, InvalidCipherTextException, IOException;

	/**
	 * Diese Methode füllt ein Byte-Array mit dem Wert 0x80 und mehreren 0x00
	 * bis die Länge des übergebenen Byte-Array ein Vielfaches von 8 ist. Dies
	 * ist die ISO9797-1 Padding-Methode 2.
	 * 
	 * @param data
	 *            Das Byte-Array welches aufgefüllt werden soll.
	 * @return Das gefüllte Byte-Array.
	 */
	public byte[] addPadding(byte[] data) {

		int i = 0;
		byte[] tempdata = new byte[data.length + 8];

		for (i = 0; i < data.length; i++) {
			tempdata[i] = data[i];
		}

		tempdata[i] = (byte) 0x80;

		for (i = i + 1; ((i) % 8) != 0; i++) {
			tempdata[i] = (byte) 0;
		}

		byte[] filledArray = new byte[i];
		System.arraycopy(tempdata, 0, filledArray, 0, i);
		return filledArray;
	}

	/**
	 * Entfernt aus dem übergebenen Byte-Array das Padding nach ISO9797-1
	 * Padding-Methode 2. Dazu werden aus dem übergebenen Byte-Array von hinten
	 * beginnend Bytes mit dem Wert 0x00 gelöscht, sowie die der Wert 0x80 der
	 * das Padding markiert.
	 * 
	 * @param Byte
	 *            -Array aus dem das Padding entfernt werden soll
	 * @return bereinigtes Byte-Array
	 */
	public byte[] removePadding(byte[] b) {
		byte[] rd = null;
		int i = b.length - 1;
		do {
			i--;
		} while (b[i] == (byte) 0x00);

		if (b[i] == (byte) 0x80) {
			rd = new byte[i];
			System.arraycopy(b, 0, rd, 0, rd.length);
			return rd;
		}
		return b;
	}

	/**
	 * Berechnet die XOR-Verknüpfung von zwei Bytes-Arrays der selben Länge
	 * 
	 * @param a
	 *            Byte-Array A
	 * @param b
	 *            Byte-Array B
	 * @return XOR-Verknüpfung von a und b
	 * @throws IllegalArgumentException
	 *             falls die beiden Byte-Arrays nicht die gleiche Länge haben
	 */
	public static byte[] xorArray(byte[] a, byte[] b)
			throws IllegalArgumentException {
		if (b.length < a.length)
			throw new IllegalArgumentException(
					"length of byte [] b must be >= byte [] a");
		byte[] c = new byte[a.length];
		for (int i = 0; i < a.length; i++) {
			c[i] = (byte) (a[i] ^ b[i]);
		}
		return c;
	}

	/**
	 * Verschlüsselt oder Entschlüsselt das übergebene Byte-Array 'plaintext'
	 * mit Hilfe des Triple-DES Algorithmus. Der Schlüssel wird in der Variable
	 * 'key' erwartet. IV = 0
	 * 
	 * @param encrypt
	 *            Wenn 'true' werden die Daten in data verschlüsselt, ansonsten
	 *            entschlüsselt.
	 * @param key
	 *            Der 3DES-Schlüssel als Byte-Array.
	 * @param data
	 *            Das zu verschlüsselnde Byte-Array
	 * @return Chiffre
	 * @throws NoSuchPaddingException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidAlgorithmParameterException
	 * @throws InvalidKeyException
	 * @throws BadPaddingException
	 * @throws IllegalBlockSizeException
	 */
	public static byte[] tripleDES(boolean encrypt, byte[] key, byte[] data)
			throws NoSuchAlgorithmException, NoSuchPaddingException,
			InvalidKeyException, InvalidAlgorithmParameterException,
			IllegalBlockSizeException, BadPaddingException {
		Cipher des;
		byte[] result = null;
		IvParameterSpec iv = new IvParameterSpec(new byte[] { (byte) 0,
				(byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0,
				(byte) 0 });
		SecretKeySpec skey = new SecretKeySpec(key, "DESede");

		des = Cipher.getInstance("DESede/CBC/NoPadding");
		if (encrypt) {
			des.init(Cipher.ENCRYPT_MODE, skey, iv);
		} else {
			des.init(Cipher.DECRYPT_MODE, skey, iv);
		}
		result = des.doFinal(data);

		return result;
	}

	/**
	 * Berechnet die Prüfsumme der Variable 'plaintext' mit Hilfe des Schlüssels
	 * 'key' nach ISO/IEC 9797-1 MAC-Algorithmus 3 mit Block Chiffre DES, IV=0
	 * (8 Bytes) und ISO9797-1 Padding-Methode 2. Die Länge der MAC-Prüfsumme
	 * ist 8 Bytes.
	 * 
	 * @param key
	 *            Der Schlüssel K_mac
	 * @param plaintext
	 *            Die Nachricht über die die Prüfsummer gebildet werden soll.
	 * @return Byte-Array der Länge 8 mit der berechneten MAC
	 * @throws NoSuchPaddingException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeyException
	 * @throws BadPaddingException
	 * @throws IllegalBlockSizeException
	 */
	public static byte[] computeMAC(byte[] key, byte[] plaintext)
			throws NoSuchAlgorithmException, NoSuchPaddingException,
			InvalidKeyException, IllegalBlockSizeException, BadPaddingException {

		Cipher des;
		byte[] ka = new byte[8];
		byte[] kb = new byte[8];
		System.arraycopy(key, 0, ka, 0, 8);
		System.arraycopy(key, 8, kb, 0, 8);

		SecretKeySpec skeya = new SecretKeySpec(ka, "DES");
		SecretKeySpec skeyb = new SecretKeySpec(kb, "DES");
		byte[] current = new byte[8];
		byte[] mac = new byte[] { (byte) 0, (byte) 0, (byte) 0, (byte) 0,
				(byte) 0, (byte) 0, (byte) 0, (byte) 0 };

		plaintext = padByteArray(plaintext);

		for (int i = 0; i < plaintext.length; i += 8) {
			System.arraycopy(plaintext, i, current, 0, 8);
			mac = xorArray(current, mac);
			des = Cipher.getInstance("DES/ECB/NoPadding");
			des.init(Cipher.ENCRYPT_MODE, skeya);
			mac = des.update(mac);
		}
		des = Cipher.getInstance("DES/ECB/NoPadding");
		des.init(Cipher.DECRYPT_MODE, skeyb);
		mac = des.update(mac);

		des.init(Cipher.ENCRYPT_MODE, skeya);
		mac = des.doFinal(mac);
		return mac;
	}

	/**
	 * Dekodiert einen Block mit AES
	 * 
	 * @param key
	 *            Byte-Array enthält den AES-Schlüssel
	 * @param z
	 *            decrypted block
	 * @return encrypted block
	 */
	public static byte[] decryptAESblock(byte[] key, byte[] z) {
		byte[] s = new byte[16];
		KeyParameter encKey = new KeyParameter(key);
		BlockCipher cipher = new AESFastEngine();
		cipher.init(false, encKey);
		cipher.processBlock(z, 0, s, 0);
		return s;
	}

	/**
	 * Berechnet den SHA1-Wert des ÃŒbergebenen Bytes-Array
	 * 
	 * @param input
	 *            Byte-Array des SHA1-Wert berechnet werden soll
	 * @return SHA1-Wert vom ÃŒbergebenen Byte-Array
	 */
	public static byte[] calculateSHA1(byte[] input) {
		MessageDigest md = null;
		try {
			md = MessageDigest.getInstance("SHA");
		} catch (NoSuchAlgorithmException ex) {
		}

		md.update(input);
		return md.digest();
	}

}

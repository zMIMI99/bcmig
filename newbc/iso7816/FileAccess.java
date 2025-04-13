

package org.zmimi.webapp.orginNEL.iso7816;

import org.zmimi.webapp.orginNEL.CatCardHandler;
import org.zmimi.webapp.orginNEL.tools.HexString;

import javax.smartcardio.CardException;
import javax.smartcardio.ResponseAPDU;
import java.io.ByteArrayInputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;

import static org.zmimi.webapp.orgin.iso7816.CatScCommands.readBinary;
import static org.zmimi.webapp.orgin.iso7816.CatScCommands.selectEF;

/**
 * FileSystem includes methods to access EFs and DFs
 * ISO7816 compatible smart card
 * 
 * @author  (Standardanvändare)
 * 
 */
public class FileAccess {

	CatCardHandler ch = null;

	public FileAccess(CatCardHandler cardHandler) {
		ch = cardHandler;
	}

	/**
	 * Reads the content of an elementary transparent file (EF). If the file is
	 * bigger then 255 byte this function uses multiply READ BINARY command to
	 * get the whole file.
	 * 
	 * @param sfid
	 *            Short File Identififier of the EF to read. Must be between
	 *            0x01 and 0x1F.
	 * @return Returns the content of the EF with the given SFID
	 * @throws CardException 
	 * @throws SecureMessagingException
	 */
	public byte[] getFile(byte sfid) throws SecureMessagingException, CardException{
		
		if (sfid > 0x1F) throw new IllegalArgumentException("Invalid Short File Identifier!");

		ResponseAPDU resp = ch.transfer(readBinary(sfid, (byte) 0x08));
		if (resp.getSW1() != 0x90) return null;
		
		int fileLength = 0;
		byte[] data = null;
		
		try {
			fileLength = getLength(resp.getData());
			data = readFile(fileLength);
		} catch (IOException e) {
			return null;
		} 
		return data;
	}

	/**
	 * Reads the content of an elementary transparent file (EF). If the file is
	 * bigger then 255 byte this function uses multiply READ BINARY command to
	 * get the whole file.
	 * 
	 * @param fid
	 *            A 2 byte array which contains the FID of the EF to read.
	 * @param autoDetectingFileLength 
	 * 			  determine automaticly the length of the selected EF by 
	 * 			  reading the first bytes of the EF which contains TLV  
	 * @return Returns the content of the EF with the given SFID
	 * @throws CardException 
	 * @throws SecureMessagingException
	 * @throws IOException 
	 */
	public byte[] getFile(byte[] fid, boolean autoDetectingFileLength) throws SecureMessagingException, CardException, IOException  {
		
		int fileLength;
		
		if (fid.length != 2)
			throw new IllegalArgumentException("Length of FID must be 2.");
		//Denna ICAO kontroll gör att man inte kan läsa B001 då det är 1011 0001. I ICAO avvänds dem biten för att sätta AID. (tror jag)
	//	if ((fid[0] & (byte) 0x10) == (byte) 0x10)
	//		throw new IllegalArgumentException("Bit 8 of P1 must be 0 if READ BINARY with FID is used");
		ResponseAPDU resp = ch.transfer(selectEF(fid));
		if (resp.getSW1() != 0x90) throw new CardException("Couldn't select EF with FID "+ HexString.bufferToHex(fid)+", RAPDU was "+ HexString.bufferToHex(resp.getBytes()));
		
		if (autoDetectingFileLength) {
			resp = ch.transfer(readBinary((byte) 0, (byte) 0, (byte) 0x8));
			if (resp.getSW1() != 0x90) throw new CardException("Couldn't read EF with FID "+ HexString.bufferToHex(fid)+", RAPDU was "+ HexString.bufferToHex(resp.getBytes()));
			fileLength = getLength(resp.getData());
		} else {
			fileLength = 0xFF; //TODO Maybe increase the maximum number of bytes to read
		}			
		return readFile(fileLength);
	}
	
	public byte[] getFile(byte[] fid) throws SecureMessagingException, CardException, IOException  {
		return getFile(fid,true);
	}
	
	/**
	 * Reads whole data from EF which has been selected before. 
	 * 
	 * @param maxLength
	 *            maximum numbers of bytes to read of the selected file
	 * @return file content
	 * @throws CardException 
	 * @throws SecureMessagingException
	 */
	private byte[] readFile(int maxLength) throws SecureMessagingException, CardException {
		int remainingBytes = maxLength;
		int readDataLength=0;
		ResponseAPDU resp;
		byte[] dataBuffer = new byte[maxLength];

		int maxSingleReadLength = 0xDF; //limit of 223 Byte per READ BINARY command for some cards
		int i = 0;

		do {
			int offset = i * maxSingleReadLength;
			byte off1 = (byte) ((offset & 0x0000FF00) >> 8);
			byte off2 = (byte) (offset & 0x000000FF);

			if (remainingBytes <= maxSingleReadLength) {
				resp = ch.transfer(readBinary(off1, off2,	(byte) remainingBytes));
				remainingBytes = 0;
				readDataLength += resp.getData().length;
			} else {
				resp = ch.transfer(readBinary(off1, off2,	(byte) maxSingleReadLength));
				remainingBytes -= maxSingleReadLength;
				readDataLength += resp.getData().length;
			}
			System.arraycopy(resp.getData(), 0, dataBuffer, i * maxSingleReadLength,
					resp.getData().length);
			i++;

		} while (remainingBytes > 0);
		
		byte[] dataBytes = new byte[readDataLength];
		System.arraycopy(dataBuffer, 0, dataBytes, 0, readDataLength);
		return dataBytes;
	}


//	/**
//	 * Reads x bytes from EF which has been selected before. 
//	 * 
//	 * @param length
//	 *            Length of the file to read
//	 * @return file content
//	 * @throws CardException 
//	 * @throws SecureMessagingException 
//	 */
//	private byte[] readFile(int length) throws SecureMessagingException, CardException {
//		int remainingBytes = length;
//		ResponseAPDU resp;
//		byte[] fileData = new byte[length];
//
//		int maxReadLength = 0xFF;
//		int i = 0;
//
//		do {
//			int offset = i * maxReadLength;
//			byte off1 = (byte) ((offset & 0x0000FF00) >> 8);
//			byte off2 = (byte) (offset & 0x000000FF);
//
//			if (remainingBytes <= maxReadLength) {
//				resp = ch.transfer(readBinary(off1, off2,	(byte) remainingBytes));
//				remainingBytes = 0;
//			} else {
//				resp = ch.transfer(readBinary(off1, off2,	(byte) maxReadLength));
//				remainingBytes -= maxReadLength;
//			}
//			System.arraycopy(resp.getData(), 0, fileData, i * maxReadLength,
//					resp.getData().length);
//			i++;
//
//		} while (remainingBytes > 0);
//		return fileData;
//	}

	/**
	 * Get the length value from a TLV coded byte array. This function is adapted
	 * from bouncycastle
	 * 
	 * @see org.bouncycastle.asn1.ASN1InputStream#readLength(InputStream s, int
	 *      limit)
	 * 
	 * @param b
	 *            TLV coded byte array that contains at least the tag and the
	 *            length value. The data value is not necessary.
	 * @return
	 * @throws IOException
	 */
	private int getLength(byte[] b) throws IOException {
		ByteArrayInputStream s = new ByteArrayInputStream(b);
		int size = 0;
		s.read(); // Skip the fhe first byte which contains the Tag value
		int length = s.read();
		if (length < 0)
			throw new EOFException("EOF found when length expected");

		if (length == 0x80)
			return -1; // indefinite-length encoding

		if (length > 127) {
			size = length & 0x7f;

			// Note: The invalid long form "0xff" (see X.690 8.1.3.5c) will be
			// caught here
			if (size > 4)
				throw new IOException("DER length more than 4 bytes: " + size);

			length = 0;
			for (int i = 0; i < size; i++) {
				int next = s.read();
				if (next < 0)
					throw new EOFException("EOF found reading length");
				length = (length << 8) + next;
			}

			if (length < 0)
				throw new IOException("corrupted stream - negative length found");

		}
		return length + size + 2; // +1 Tag, +1 Length
	}

}

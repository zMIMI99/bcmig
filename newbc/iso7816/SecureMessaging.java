

package org.zmimi.webapp.orginNEL.iso7816;

import org.bouncycastle.asn1.ASN1InputStream;
import org.zmimi.webapp.orginNEL.crypto.AmCryptoException;
import org.zmimi.webapp.orginNEL.crypto.AmCryptoProvider;
import org.zmimi.webapp.orginNEL.tools.HexString;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

/**
 * Packs unprotected CAPDU in SecureMessaging and unpacks SM-protected ones
 * RAPDU.
 * 
 * @author  (Standardanvändare)
 *
 */
public class SecureMessaging {

	private byte[] ks_enc = null;
	private byte[] ks_mac = null;
	private byte[] ssc = null;
	private AmCryptoProvider crypto = null;
	private boolean useExtendLengthAPDUs = true;

	enum apdutype {
		case1, case2s, case2e, case3s, case3e, case4s, case4e
	};

	/**
	 * @param acp
	 * AmDESCrypto or AmAESCrypto instance
	 * @param ksenc
	 * Session key for encryption (K_enc)
	 * @param ksmac
	 * Session key for checksum calculation (K_mac)
	 * @param initialSSC
	 * Initial value of the send sequence counter
	 * @param useExtendLengthAPDUs
	 * by default APDU with extended length will be used, if your
	 * card doesn't support EL set this parameter to false
	 */
	public SecureMessaging(AmCryptoProvider acp, byte[] ksenc, byte[] ksmac, byte[] initialSSC, boolean useExtendLengthAPDUs) {
		this.crypto = acp;
		this.ks_enc = ksenc.clone();
		this.ks_mac = ksmac.clone();
		this.ssc = initialSSC.clone();
		this.useExtendLengthAPDUs = useExtendLengthAPDUs;
	}

	/**
	 * Constructor
	 *
	 * @param acp
	 * AmDESCrypto or AmAESCrypto instance
	 * @param ksenc
	 * Session key for encryption (K_enc)
	 * @param ksmac
	 * Session key for checksum calculation (K_mac)
	 * @param initsc
	 * Initial value of the send sequence counter
	 */
	public SecureMessaging(AmCryptoProvider acp, byte[] ksenc, byte[] ksmac, byte[] initialSSC) {
		this(acp, ksenc, ksmac, initialSSC, true);
	}

	/**
	 * Creates one from a plain command APDU without secure messaging
	 * Command APDU with Secure Messaging.
	 *
	 * @param capdu
	 * plain Command APDU
	 * @return CommandAPDU with SM
	 * @throws SecureMessagingException
	 */
	public CommandAPDU wrap(CommandAPDU capdu) throws SecureMessagingException {
		// Track secure messaging sequence counter
		incrementAtIndex(ssc, ssc.length - 1);

		// Initialize header and data objects
		byte[] header = new byte[4];
		System.arraycopy(capdu.getBytes(), 0, header, 0, 4);

		// Set secure messaging bits in CLA byte (0x0C = 1100 in binary)
		// This indicates:
		// - Bit 3 (0x08): Command header not processed
		// - Bit 2 (0x04): Response shall be processed
		// Or mask whole original CLA byte and set Bit 3 and Bit 2 to true
		header[0] = (byte) (header[0] | (byte) 0x0C);

		// Determine APDU type to handle different cases:
		// Case 1: No data field, no expected response
		// Case 2s/2e: No data field, expected response
		// Case 3s/3e: Data field present, no expected response
		// Case 4s/4e: Data field present, expected response
		// (s = short, e = extended length)
		apdutype atype = getAPDUStructure(capdu);

		DO97 do97 = null;  // Expected length (Le)
		DO85 do85 = null;  // Padding-content indicator + cryptogram (odd INS)
		DO87 do87 = null;  // Padding-content indicator + cryptogram (even INS)
		DO8E do8E = null;  // MAC over padded command header

		// Handle command data field if present (Case 3 or 4)
		if (atype == apdutype.case3s || atype == apdutype.case4s ||
				atype == apdutype.case3e || atype == apdutype.case4e) {
			// Check if INS byte is odd or even to determine DO type
			if ((header[1] & 0xff) % 2 == 1) {
				do85 = buildDO85(capdu.getData().clone());
			} else {
				do87 = buildDO87(capdu.getData().clone());
			}
		}

		// Handle expected response length if present (Case 2 or 4)
		if (atype == apdutype.case2s || atype == apdutype.case4s ||
				atype == apdutype.case2e || atype == apdutype.case4e) {
			do97 = buildDO97(capdu.getNe());
		}

		// Build MAC over command header and other DOs
		do8E = buildDO8E(header, (do85 != null) ? do85 : do87, do97);

		// Construct protected APDU by concatenating all present DOs
		ByteArrayOutputStream bOut = new ByteArrayOutputStream();
		try {
			if (do85 != null) bOut.write(do85.getEncoded());
			if (do87 != null) bOut.write(do87.getEncoded());
			if (do97 != null) bOut.write(do97.getEncoded());
			bOut.write(do8E.getEncoded());
		} catch (IOException e) {
			throw new SecureMessagingException(e);
		}

		// Create new CommandAPDU with protected payload
		// Use extended length if configured (max 65536) otherwise standard (max 256)
		return new CommandAPDU(
				header[0], header[1], header[2], header[3],
				bOut.toByteArray(),
				useExtendLengthAPDUs ? 65536 : 256
		);
	}
	/**
	 * Creates a plain response APDU from an SM protected response APDU
	 * without secure messaging.
	 *
	 * @param rapdu
	 * SM protected RAPDU
	 * @return plain RAPDU
	 * @throws SecureMessagingException
	 */

	public ResponseAPDU unwrap(ResponseAPDU rapdu) throws SecureMessagingException {

		DO87 do87 = null;
		DO99 do99 = null;
		DO8E do8E = null;

		incrementAtIndex(ssc, ssc.length - 1);

		int pointer = 0;
		byte[] rapduBytes = rapdu.getData();
		byte[] subArray = new byte[rapduBytes.length];

		while (pointer < rapduBytes.length) {
			System.arraycopy(rapduBytes, pointer, subArray, 0, rapduBytes.length - pointer);
			ASN1InputStream asn1sp = new ASN1InputStream(subArray);
			byte[] encodedBytes = null;
			try {
				encodedBytes = asn1sp.readObject().getEncoded();
				asn1sp.close();
			} catch (IOException e) {
				throw new SecureMessagingException(e);
			}

			ASN1InputStream asn1in = new ASN1InputStream(encodedBytes);
			try {
				switch (encodedBytes[0]) {
				case (byte) 0x87:
					do87 = new DO87();
					do87.fromByteArray(asn1in.readObject().getEncoded());
					break;
				case (byte) 0x99:
					do99 = new DO99();
					do99.fromByteArray(asn1in.readObject().getEncoded());
					break;
				case (byte) 0x8E:
					do8E = new DO8E();
					do8E.fromByteArray(asn1in.readObject().getEncoded());
				}
				asn1in.close();
			} catch (IOException e) {
				throw new SecureMessagingException(e);
			}

			pointer += encodedBytes.length;
		}

		if (do99 == null)
			throw new SecureMessagingException("Secure Messaging error: mandatory DO99 not found"); // DO99
																									// is
																									// mandatory
		// and only absent
		// if SM error
		// occurs

		// Construct K (SSC||DO87||DO99)
		ByteArrayOutputStream bout = new ByteArrayOutputStream();
		try {
			if (do87 != null)
				bout.write(do87.getEncoded());
			bout.write(do99.getEncoded());
		} catch (IOException e) {
			throw new SecureMessagingException(e);
		}

		crypto.init(ks_mac, ssc);
		byte[] cc = crypto.getMAC(bout.toByteArray());

		byte[] do8eData = do8E.getData();

		if (!java.util.Arrays.equals(cc, do8eData))
			throw new SecureMessagingException("Checksum is incorrect!\n Calculated CC: " + HexString.bufferToHex(cc) + "\nCC in DO8E: "
					+ HexString.bufferToHex(do8eData));

		// Decrypt DO87
		byte[] data = null;
		byte[] unwrappedAPDUBytes = null;

		if (do87 != null) {
			crypto.init(ks_enc, ssc);
			byte[] do87Data = do87.getData();
			try {
				data = crypto.decrypt(do87Data);
			} catch (AmCryptoException e) {
				throw new SecureMessagingException(e);
			}
			// Build unwrapped RAPDU
			unwrappedAPDUBytes = new byte[data.length + 2];
			System.arraycopy(data, 0, unwrappedAPDUBytes, 0, data.length);
			byte[] do99Data = do99.getData();
			System.arraycopy(do99Data, 0, unwrappedAPDUBytes, data.length, do99Data.length);
		} else
			unwrappedAPDUBytes = do99.getData().clone();

		return new ResponseAPDU(unwrappedAPDUBytes);
	}

	public void setExtendLengthSupport(boolean useExtendLengthAPDUs) {
		this.useExtendLengthAPDUs = useExtendLengthAPDUs;
	}

	/**
	 * encrypt data with KS.ENC and build DO85
	 * 
	 * @param data
	 * @return
	 * @throws SecureMessagingException
	 */
	private DO85 buildDO85(byte[] data) throws SecureMessagingException {
		crypto.init(ks_enc, ssc);
		byte[] enc_data;
		try {
			enc_data = crypto.encrypt(data);
		} catch (AmCryptoException e) {
			throw new SecureMessagingException(e);
		}
		return new DO85(enc_data);
	}

	/**
	 * encrypt data with KS.ENC and build DO87
	 * 
	 * @param data
	 * @return
	 * @throws SecureMessagingException
	 */
	private DO87 buildDO87(byte[] data) throws SecureMessagingException {

		crypto.init(ks_enc, ssc);
		byte[] enc_data;
		try {
			enc_data = crypto.encrypt(data);
		} catch (AmCryptoException e) {
			throw new SecureMessagingException(e);
		}

		return new DO87(enc_data);

	}

	private DO8E buildDO8E(byte[] header, DO85 do85, DO97 do97) throws SecureMessagingException {

		ByteArrayOutputStream m = new ByteArrayOutputStream();

		/**
		 * Prevents double padding of the header: Only if do87 or do97
		 * are present, the header is padded. Otherwise it will only happen when
		 * Calculate MAC padded.
		 */
		try {
			if (do85 != null || do97 != null)
				m.write(crypto.addPadding(header));

			else
				m.write(header);

			if (do85 != null)
				m.write(do85.getEncoded());
			if (do97 != null)
				m.write(do97.getEncoded());
		} catch (IOException e) {
			throw new SecureMessagingException(e);
		}

		crypto.init(ks_mac, ssc);

		return new DO8E(crypto.getMAC(m.toByteArray()));
	}

	private DO97 buildDO97(int le) {
		return new DO97(le);
	}

	/**
	 * Determines which case the CAPDU corresponds to. (See ISO/IEC 7816-3 chapter
	 * 12.1)
	 *
	 * @return apdutype
	 */
	private apdutype getAPDUStructure(CommandAPDU capdu) {
		byte[] cardcmd = capdu.getBytes();

		if (cardcmd.length == 4)
			return apdutype.case1;
		if (cardcmd.length == 5)
			return apdutype.case2s;
		if (cardcmd.length == (5 + (cardcmd[4] & 0xff)) && cardcmd[4] != 0)
			return apdutype.case3s;
		if (cardcmd.length == (6 + (cardcmd[4] & 0xff)) && cardcmd[4] != 0)
			return apdutype.case4s;
		if (cardcmd.length == 7 && cardcmd[4] == 0)
			return apdutype.case2e;
		if (cardcmd.length == (7 + (cardcmd[5] & 0xff) * 256 + (cardcmd[6] & 0xff)) && cardcmd[4] == 0 && (cardcmd[5] != 0 || cardcmd[6] != 0))
			return apdutype.case3e;
		if (cardcmd.length == (9 + (cardcmd[5] & 0xff) * 256 + (cardcmd[6] & 0xff)) && cardcmd[4] == 0 && (cardcmd[5] != 0 || cardcmd[6] != 0))
			return apdutype.case4e;
		return null;
	}

	private void incrementAtIndex(byte[] array, int index) {
		if ((array[index] & 0xff) == 0xff) {
			array[index] = 0;
			if (index > 0)
				incrementAtIndex(array, index - 1);
		} else {
			array[index]++;
		}
	}
}

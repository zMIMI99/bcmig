

package org.zmimi.webapp.orginNEL.iso7816;

import org.bouncycastle.asn1.*;
import org.zmimi.webapp.orginNEL.asn1.CertificateHolderAuthorizationTemplate;

import javax.smartcardio.CommandAPDU;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

/**
 * The MSESetAT class is used to construct an "MSE:Set id_AT" APDU
 * 
 * @author  (Standardanvändare)
 * 
 */
public class MSESetAT {

	public static final int setAT_PACE = 1;
	public static final int setAT_CA = 2;
	public static final int setAT_TA = 3;

	public static final int KeyReference_MRZ = 1;
	public static final int KeyReference_CAN = 2;
	public static final int KeyReference_PIN = 3;
	public static final int KeyReference_PUK = 4;

	private final byte CLASS = (byte) 0x00;
	private final byte INS = (byte) 0x22; // Instruction Byte: Message Security
											// Environment
	private byte P1=0;
	private final byte P2=(byte)0xA4;
	private byte[] do80CMR = null;
	private byte[] do83KeyReference = null;
	private byte[] do83KeyName = null;
	private byte[] do84PrivateKeyReference = null;
	private byte[] do7F4C_CHAT = null;
	private byte[] do91EphemeralPublicKEy = null;

	public MSESetAT() {}

	/**
	 * Sets the authentication template to be used (id_PACE, id_CA or id_TA)
	 *
	 * @param at
	 * {@link pace.MSECommand.setAT_PACE},
	 * {@link pace.MSECommand.setAT_CA},
	 * {@link pace.MSECommand.setAT_TA}
	 */
	public void setAT(int at) {
		if (at == setAT_PACE) P1 = (byte) 0xC1;			
		if (at == setAT_CA)	P1 = (byte) 0x41;
		if (at == setAT_TA)	P1 = (byte) 0x81;
	}

	/**
	 * Sets the OID of the protocol to use
	 *
	 * @param protocol
	 * The protocol to use
	 */
	public void setProtocol(String protocol) {
		ASN1ObjectIdentifier oid = new ASN1ObjectIdentifier(protocol);
		DERTaggedObject to = new DERTaggedObject(false, 0x00, oid);
		try {
			do80CMR = to.getEncoded(ASN1Encoding.DER);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

	}

	/**
	 * Sets tag 0x83 (Reference of public / secret key) for id_PACE
	 *
	 * @param kr
	 * References the password used: 1: MRZ 2: CAN 3: PIN 4:
	 *PUK
	 */
	public void setKeyReference(int kr) {
		DERTaggedObject to = new DERTaggedObject(false, 0x03, new ASN1Integer(kr));
		try {
			do83KeyReference = to.getEncoded(ASN1Encoding.DER);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

	}

	/**
	 * Sets tag 0x83 (Reference of public / secret key) for Terminal
	 * Authentication
	 *
	 * @param kr
	 * String containing the name of the public key of the terminal
	 * (ISO 8859-1 coded)
	 */
	public void setKeyReference(String kr) {
		DERTaggedObject to = new DERTaggedObject(false, 0x03, new DEROctetString(kr.getBytes()));
		try {
			do83KeyName = to.getEncoded(ASN1Encoding.DER);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

	}

	/**
	 * Sets the tag 0x84 (Reference of a private key / Reference for computing
	 * a session key)
	 *
	 * @param pkr
	 * With id_PACE the index of the domain to be used is parameter
	 * specified at id_CA is the index of the private to be used
	 * Keys specified With id_RI, the index of the key to be used is specified
	 * Private keys specified
	 */
	public void setPrivateKeyReference(int pkr) {
		DERTaggedObject to = new DERTaggedObject(false, 0x04, new ASN1Integer(pkr));
		try {
			do84PrivateKeyReference = to.getEncoded(ASN1Encoding.DER);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

	}

	public void setAuxiliaryAuthenticatedData() throws UnsupportedOperationException {
		// TODO still to be implemented, Tag 0x67
		throw new UnsupportedOperationException("setAuxiliaryAuthenticationData not yet implemented!");
	}

	/**
	 * Sets tag 0x91 (Ephemeral Public Key). The PK must already be compressed
	 * (see comp() function in TR-03110).
	 * @param pubKey comp(ephemeral PK_PCD) -> TR-03110 A.2.2.3
	 */
	public void setEphemeralPublicKey(byte[] pubKey) {
		DERTaggedObject to = new DERTaggedObject(false, 0x11, new DEROctetString(pubKey));
		try {
			do91EphemeralPublicKEy = to.getEncoded(ASN1Encoding.DER);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	/**
	 * @param chat
	 */
	public void setCHAT(CertificateHolderAuthorizationTemplate chat) {
		try {
			do7F4C_CHAT = chat.getEncoded(ASN1Encoding.DER);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	/**
	 * Constructs an MSE Command APDU from the set objects
	 * @return ByteArray with MSE:SetAT APDU
	 */
	public CommandAPDU getCommandAPDU() {
		ByteArrayOutputStream bos = new ByteArrayOutputStream();

		if (do80CMR != null)
			bos.write(do80CMR, 0, do80CMR.length);
		if (do83KeyReference != null)
			bos.write(do83KeyReference, 0, do83KeyReference.length);
		if (do83KeyName != null)
			bos.write(do83KeyName, 0, do83KeyName.length);
		if (do84PrivateKeyReference != null)
			bos.write(do84PrivateKeyReference, 0, do84PrivateKeyReference.length);
		if (do91EphemeralPublicKEy != null) 
			bos.write(do91EphemeralPublicKEy, 0 , do91EphemeralPublicKEy.length);
		if (do7F4C_CHAT != null)
			bos.write(do7F4C_CHAT, 0, do7F4C_CHAT.length);
		byte[] data = bos.toByteArray();

		return new CommandAPDU(CLASS, INS, P1, P2, data);
	}

}

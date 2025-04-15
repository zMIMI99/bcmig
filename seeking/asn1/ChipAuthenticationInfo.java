

package org.zmimi.webapp.orginNEL.asn1;

import org.bouncycastle.asn1.*;

/**
 * @author  (Standardanvändare)
 * 
 */
public class ChipAuthenticationInfo extends ASN1Object{

	private ASN1ObjectIdentifier protocol = null;
	private ASN1Integer version = null;
	private ASN1Integer keyId = null;

	public ChipAuthenticationInfo(ASN1Sequence seq) {
		protocol = (ASN1ObjectIdentifier) seq.getObjectAt(0);
		version = (ASN1Integer) seq.getObjectAt(1);

		if (seq.size() > 2) {
			keyId = (ASN1Integer) seq.getObjectAt(2);
		}
	}

	public String getProtocolOID() {
		return protocol.toString();
	}

	public int getVersion() {
		return version.getValue().intValue();
	}

	public int getKeyId() {
		if (keyId == null)
			return -1; // optionally field keyId
		else
			return keyId.getPositiveValue().intValue();
	}


	@Override
	public String toString() {
		return "ChipAuthenticationInfo \n\tOID: " + getProtocolOID()
				+ "\n\tVersion: " + getVersion() + 
				(keyId!=null?"\n\tKeyId " + keyId.getPositiveValue().intValue() + "\n":"\n");
	}

	/**
	 * The definition of ChipAuthenticationInfo is
     * <pre>
     * ChipAuthenticationInfo ::= SEQUENCE {
     *      protocol	OBJECT IDENTIFIER(
	 *					id-id_CA-DH-3DES-CBC-CBC |
	 *					id-id_CA-DH-AES-CBC-CMAC-128 |
	 *					id-id_CA-DH-AES-CBC-CMAC-192 |
	 *					id-id_CA-DH-AES-CBC-CMAC-256 |
	 *					id-id_CA-ECDH-3DES-CBC-CBC |
	 *					id-id_CA-ECDH-AES-CBC-CMAC-128 |
	 *					id-id_CA-ECDH-AES-CBC-CMAC-192 |
	 *					id-id_CA-ECDH-AES-CBC-CMAC-256),
     *      version		INTEGER, -- MUST be 1 or 2
     *      keyID		INTEGER OPTIONAL
     * }
     * </pre>
	 */
	@Override
	public ASN1Primitive toASN1Primitive() {
		ASN1EncodableVector v = new ASN1EncodableVector();
		v.add(protocol);
		v.add(version); 
		if (keyId!=null) v.add(keyId);
		
		return ASN1Sequence.getInstance(v);
	}

}

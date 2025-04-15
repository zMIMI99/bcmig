
package org.zmimi.webapp.orginNEL.asn1;

import org.bouncycastle.asn1.*;
import org.zmimi.webapp.orginNEL.tools.HexString;

/**
 * @author  (Standardanvändare)
 *
 * The ChipAuthenticationPublicKeyInfo object.
 * <pre>
 * ChipAuthenticationPublicKeyInfo ::= SEQUENCE {
 *   protocol						OBJECT IDENTIFIER{id-PK-DH | id-PK-ECDH},
 *   chipAuthenticationPublicKey    SubjectPublicKeyInfo,
 *   keyID							INTEGER OPTIONAL
 * }
 * </pre>
 */
public class ChipAuthenticationPublicKeyInfo extends ASN1Object{
	
	private ASN1ObjectIdentifier protocol = null;
	private SubjectPublicKeyInfo capk = null;
	private ASN1Integer keyId = null;
	
	public ChipAuthenticationPublicKeyInfo(ASN1Sequence seq) {
		protocol = (ASN1ObjectIdentifier) seq.getObjectAt(0);
		capk = new SubjectPublicKeyInfo((ASN1Sequence)seq.getObjectAt(1));
		if (seq.size()==3) {
			keyId = (ASN1Integer)seq.getObjectAt(2);
		}	
	}
	
	public ASN1ObjectIdentifier getProtocol() {
		return protocol;
	}
	
	public SubjectPublicKeyInfo getPublicKey() {
		return capk;
	}
	
	public int getKeyId() {
		if (keyId == null)
			return -1; // optionally field keyId
		else
			return keyId.getPositiveValue().intValue();
	}
	
	@Override
	public String toString() {
		return "ChipAuthenticationPublicKeyInfo \n\tprotocol: "
				+ getProtocol() + "\n\tSubjectPublicKeyInfo: \n\t\t"
				+ "Algorithm: "+ getPublicKey().getAlgorithm().getAlgorithm() + "\n\t\t"
				+ "AmPublicKey:" + HexString.bufferToHex(getPublicKey().getPublicKey()) +
				(keyId!=null?"\n\tKeyId " + keyId.getPositiveValue().intValue() + "\n":"\n");
	}
	
	
	/**
	 * The definition of ChipAuthenticationPublicKeyInfo is
     * <pre>
     * ChipAuthenticationPublicKeyInfo ::= SEQUENCE {
     *      protocol					OBJECT IDENTIFIER(id-PK-DH | id-PK-ECDH),
     *      chipAuthenticationPublicKey	SubjectPublicKeyInfo,
     *      keyID						INTEGER OPTIONAL
     * }
     * </pre>
	 */
	@Override
	public ASN1Primitive toASN1Primitive() {
		ASN1EncodableVector vec = new ASN1EncodableVector();
		vec.add(protocol);
		vec.add(capk);
		if (keyId!=null) {
			vec.add(keyId);
		}
		return ASN1Sequence.getInstance(vec);
	}
	
	

}

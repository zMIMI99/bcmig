

package org.zmimi.webapp.orginNEL.asn1;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

/**
 * @author  (Standardanvändare)
 * 
 */
public class ChipAuthenticationDomainParameterInfo extends ASN1Object{

	private ASN1ObjectIdentifier protocol = null;
	private AlgorithmIdentifier domainParameter = null;
	private ASN1Integer keyId = null;

	/**
	 * @param seq
	 */
	public ChipAuthenticationDomainParameterInfo(ASN1Sequence seq) {
		protocol = (ASN1ObjectIdentifier) seq.getObjectAt(0);
		domainParameter = AlgorithmIdentifier.getInstance(seq.getObjectAt(1));

		if (seq.size() > 2) {
			keyId = (ASN1Integer) seq.getObjectAt(2);
		}
	}

	public String getProtocolOID() {
		return protocol.toString();
	}

	public AlgorithmIdentifier getDomainParameter() {
		return domainParameter;
	}

	public int getKeyId() {
		if (keyId == null)
			return -1; // optionally field keyId
		else
			return keyId.getPositiveValue().intValue();
	}

	@Override
	public String toString() {
		return "ChipAuthenticationDomainParameterInfo \n\tOID: "
				+ getProtocolOID() + "\n\tDomainParameter: \n\t\t"
				+ getDomainParameter().getAlgorithm() + "\n\t\t"
				+ getDomainParameter().getParameters() + 
				(keyId!=null?"\n\tKeyId " + keyId.getPositiveValue().intValue() + "\n":"\n");
	}

	/**
	 * The definition of ChipAuthenticationDomainParameterInfo is
     * <pre>
     * ChipAuthenticationDomainParameterInfo ::= SEQUENCE {
     *      protocol   			OBJECT IDENTIFIER(id-id_CA-DH | id-id_CA-ECDH),
     *      domainParameter		AlgorithmIdentifier,
     *      keyID				INTEGER OPTIONAL
     * }
     * </pre>
	 */
	@Override
	public ASN1Primitive toASN1Primitive() {
		ASN1EncodableVector v = new ASN1EncodableVector();
		v.add(protocol);
		v.add(domainParameter); 
		if (keyId!=null) v.add(keyId);
		
		return ASN1Sequence.getInstance(v);
	}

}

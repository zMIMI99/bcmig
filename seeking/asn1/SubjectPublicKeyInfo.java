
package org.zmimi.webapp.orginNEL.asn1;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

/**
 * @author  (Standardanvändare)
 *
 */
public class SubjectPublicKeyInfo extends ASN1Object {
	
	private AlgorithmIdentifier algorithm = null;
	private ASN1BitString subjectPublicKey = null;

	/**
	 * @param seq
	 */
	public SubjectPublicKeyInfo(ASN1Sequence seq) {
		algorithm = AlgorithmIdentifier.getInstance(seq.getObjectAt(0));
		subjectPublicKey = DERBitString.getInstance((seq.getObjectAt(1)));
	}
	
	public AlgorithmIdentifier getAlgorithm() {
		return algorithm;
	}
	
	public byte[] getPublicKey() {
		return subjectPublicKey.getBytes();
	}

	/** 
	 * The SubjectPublicKeyInfo object.
	 * <pre>
	 * SubjectPublicKeyInfo ::= SEQUENCE {
	 *   algorithm			AlgorithmIdentifier,
	 *   subjectPublicKey	BIT STRING
	 * }
	 * </pre>
	 * 
	 */
	@Override
	public ASN1Primitive toASN1Primitive() {
		ASN1EncodableVector vec = new ASN1EncodableVector();
		vec.add(algorithm);
		vec.add(subjectPublicKey);
		return ASN1Sequence.getInstance(vec);
	}

}

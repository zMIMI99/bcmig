

package org.zmimi.webapp.orginNEL.asn1;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

/**
 * @author  (Standardanvändare)
 * 
 */
public class PaceDomainParameterInfo extends ASN1Object {

	private ASN1ObjectIdentifier protocol = null;
	private AlgorithmIdentifier domainParameter = null;
	private ASN1Integer parameterId = null;

	public PaceDomainParameterInfo(ASN1Sequence seq) {
		protocol = (ASN1ObjectIdentifier) seq.getObjectAt(0);
		domainParameter = AlgorithmIdentifier.getInstance(seq.getObjectAt(1));

		if (seq.size() > 2) {
			parameterId = (ASN1Integer) seq.getObjectAt(2);
		}
	}

	public ASN1ObjectIdentifier getProtocol() {
		return protocol;
	}

	public AlgorithmIdentifier getDomainParameter() {
		return domainParameter;
	}

	public int getParameterId() {
		if (parameterId == null)
			return -1; // optionally field parameterId
		else
			return parameterId.getValue().intValue();
	}

	@Override
	public String toString() {
		return "PaceDomainParameterInfo\n\tOID: " + getProtocol()
				+ "\n\tDomainParameter: \n\t\t"
				+ getDomainParameter().getAlgorithm() + "\n\t\t"
				+ getDomainParameter().getParameters() + 
				(parameterId!=null?"\n\tParameterId: " + getParameterId() + "\n":"\n");
	}

	/**
	 * The definition of PaceDomainParameterInfo is
     * <pre>
     * PaceDomainParameterInfo ::= SEQUENCE {
     *      protocol		OBJECT IDENTIFIER(,
     *      				id-id_PACE-DH-GM |
     *      				id-id_PACE-ECDH-GM |
     *      				id-id_PACE-DH-IM |
     *      				id-id_PACE-ECDH-IM),
     *      domainParameter	AlgorithmIdentifier,
     *      parameterId		INTEGER OPTIONAL
     * }
     * </pre>
	 */
	@Override
	public ASN1Primitive toASN1Primitive() {
		ASN1EncodableVector v = new ASN1EncodableVector();
		v.add(protocol);
		v.add(domainParameter);
		if (parameterId!=null) v.add(parameterId);
		
		return ASN1Sequence.getInstance(v);
	}
}

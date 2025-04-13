

package org.zmimi.webapp.orginNEL.asn1;

import org.bouncycastle.asn1.*;

/**
 * 
 * @author  (Standardanvändare)
 */
public class PaceInfo extends ASN1Object{

	private ASN1ObjectIdentifier protocol = null;
	private ASN1Integer version = null;
	private ASN1Integer parameterId = null;
	
	public PaceInfo(ASN1Sequence seq) {
		protocol = (ASN1ObjectIdentifier) seq.getObjectAt(0);
		version = (ASN1Integer) seq.getObjectAt(1);

		if (seq.size() > 2) {
			parameterId = (ASN1Integer) seq.getObjectAt(2);
		}
	}
	
	public PaceInfo(String oid, int version, int parameterId) {
		this.protocol = new ASN1ObjectIdentifier(oid);
		this.version = new ASN1Integer(version);
		this.parameterId = new ASN1Integer(parameterId);
	}

	public String getProtocolOID() {
		return protocol.toString();
	}

	public int getVersion() {
		return version.getValue().intValue();
	}

	public Integer getParameterId() {
		if (parameterId == null)
			return null;
		else
			return parameterId.getValue().intValue();
	}

	@Override
	public String toString() {
		return "PaceInfo\n\tOID: " + getProtocolOID() + "\n\tVersion: "
				+ getVersion() + 
				(parameterId!=null?"\n\tParameterId: " + getParameterId() + "\n":"\n");
	}

	/**
	 * The definition of PaceInfo is
     * <pre>
     * PaceInfo ::= SEQUENCE {
     *      protocol	OBJECT IDENTIFIER(
	 *					id-id_PACE-DH-GM-3DES-CBC-CBC |
	 *					id-id_PACE-DH-GM-AES-CBC-CMAC-128 |
	 *					id-id_PACE-DH-GM-AES-CBC-CMAC-192 |
	 *					id-id_PACE-DH-GM-AES-CBC-CMAC-256 |
	 *					id-id_PACE-ECDH-GM-3DES-CBC-CBC |
	 *					id-id_PACE-ECDH-GM-AES-CBC-CMAC-128 |
	 *					id-id_PACE-ECDH-GM-AES-CBC-CMAC-192 |
	 *					id-id_PACE-ECDH-GM-AES-CBC-CMAC-256,
	 *					id-id_PACE-DH-IM-3DES-CBC-CBC |
	 *					id-id_PACE-DH-IM-AES-CBC-CMAC-128 |
	 *					id-id_PACE-DH-IM-AES-CBC-CMAC-192 |
	 *					id-id_PACE-DH-IM-AES-CBC-CMAC-256 |
	 *					id-id_PACE-ECDH-IM-3DES-CBC-CBC |
	 *					id-id_PACE-ECDH-IM-AES-CBC-CMAC-128 |
	 *					id-id_PACE-ECDH-IM-AES-CBC-CMAC-192 |
	 *					id-id_PACE-ECDH-IM-AES-CBC-CMAC-256),
     *      version		INTEGER, -- SHOULD be 2
     *      parameterId	INTEGER OPTIONAL
     * }
     * </pre>
	 */
	@Override
	public ASN1Primitive toASN1Primitive() {
		ASN1EncodableVector v = new ASN1EncodableVector();
		v.add(protocol);
		v.add(version); 
		if (parameterId!=null) v.add(parameterId);
		
		return ASN1Sequence.getInstance(v);
	}
}

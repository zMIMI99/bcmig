

package org.zmimi.webapp.orginNEL.asn1;

import org.bouncycastle.asn1.*;

import java.io.IOException;

/**
 * @author  (Standardanvändare)
 * 
 */
public class PrivilegedTerminalInfo extends ASN1Object{

	private ASN1ObjectIdentifier protocol = null;
	private SecurityInfos secinfos = null;

	public PrivilegedTerminalInfo(ASN1Sequence seq) throws IOException {
		protocol = (ASN1ObjectIdentifier) seq.getObjectAt(0);

		ASN1Set ASN1Set = (ASN1Set) seq.getObjectAt(1);

		SecurityInfos si = new SecurityInfos();
		si.decode(ASN1Set.getEncoded());

		secinfos = (si);
	}

	public String getProtocolOID() {
		return protocol.getId();
	}

	public SecurityInfos getSecurityInfos() {
		return secinfos;
	}

	@Override
	public String toString() {
		return "PrivilegedTerminalInfo\n\tOID: " + getProtocolOID()
				+ "\n\tSecurityInfos: " + getSecurityInfos() + "\n";
	}

	/**
	 * The definition of PrivilegedTerminalInfo is
     * <pre>
     * PrivilegedTerminalInfo ::= SEQUENCE {
     *      protocol				OBJECT IDENTIFIER(id-PT),
     *      privilegedTerminalInfos	SecurityInfos
     * }
     * </pre>
	 */
	@Override
	public ASN1Primitive toASN1Primitive() {
		ASN1EncodableVector v = new ASN1EncodableVector();
		v.add(protocol);
		v.add(secinfos);
		
		return ASN1Sequence.getInstance(v);
	}

}

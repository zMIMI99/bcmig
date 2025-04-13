

package org.zmimi.webapp.orginNEL.asn1;

import org.bouncycastle.asn1.*;

/**
 * @author  (Standardanvändare)
 * 
 */
public class TerminalAuthenticationInfo extends ASN1Object{

	private ASN1ObjectIdentifier protocol = null;
	private ASN1Integer version = null;
	private ASN1Sequence fileID = null;

	/**
	 * @param ASN1Sequence
	 */
	public TerminalAuthenticationInfo(ASN1Sequence seq) {
		protocol = (ASN1ObjectIdentifier) seq.getObjectAt(0);
		version = (ASN1Integer) seq.getObjectAt(1);
		if (seq.size() > 2) {
			fileID = (ASN1Sequence) seq.getObjectAt(2);
		}
		if (version.getValue().intValue() == 2 && fileID != null)
			throw new IllegalArgumentException("FileID MUST NOT be used for version 2!");
	}

	public String getProtocolOID() {
		return protocol.toString();
	}

	public int getVersion() {
		return version.getValue().intValue();
	}

	public FileID getEFCVCA() {
		if (fileID == null)
			return null; // optionally field FileID
		else
			return new FileID(fileID);
	}

	
	@Override
	public String toString() {
		return "TerminalAuthenticationInfo\n\tOID: " + getProtocolOID()
				+ "\n\tVersion: " + getVersion() + 
				(fileID!=null?"\n\tEF.CVCA: " + getEFCVCA() + "\n":"\n");
	}

	/**
	 * The definition of TerminalAuthenticationInfo is
     * <pre>
     * TerminalAuthenticationInfo ::= SEQUENCE {
     *      protocol	OBJECT IDENTIFIER(id-id_TA),
     *      version		INTEGER, -- MUST be 1 or 2
     *      efCVCA		FileID OPTIONAL -- MUST NOT be used for version 2
     * }
     * </pre>
	 */
	@Override
	public ASN1Primitive toASN1Primitive() {
		ASN1EncodableVector v = new ASN1EncodableVector();
		v.add(protocol);
		v.add(version);
		if (fileID!=null) v.add(fileID);
		
		return ASN1Sequence.getInstance(v);
	}

}



package org.zmimi.webapp.orginNEL.asn1;

import org.bouncycastle.asn1.*;
import org.zmimi.webapp.orginNEL.tools.HexString;

/**
 * 
 * @author  (Standardanvändare)
 */
public class FileID extends ASN1Object{

	private DEROctetString fid = null;
	private DEROctetString sfid = null;

	public FileID(ASN1Sequence seq) {
		fid = (DEROctetString) seq.getObjectAt(0);
		if (seq.size() > 1) {
			sfid = (DEROctetString) seq.getObjectAt(1);
		}
	}

	public byte[] getFID() {
		return fid.getOctets();
	}

	public byte getSFID() {
		if (sfid != null)
			return (sfid.getOctets()[0]);
		else
			return -1; // optionally field sfid
	}

	@Override
	public String toString() {
		return "FileID \n\tFID: " + HexString.bufferToHex(getFID())
				+ "\n\tSFID: " + getSFID() + "\n";
	}

	/**
	 * The definition of FileID is
     * <pre>
     * FileID ::= SEQUENCE {
     *      fid		OCTET STRING (SIZE(2)),
     *      sfid	OCTET STRING (SIZE(1)) OPTIONAL
     * }
     * </pre>
	 */
	@Override
	public ASN1Primitive toASN1Primitive() {
		ASN1EncodableVector v = new ASN1EncodableVector();
		v.add(fid);
		if (sfid!=null) v.add(sfid);
		
		return ASN1Sequence.getInstance(v);
	}

}

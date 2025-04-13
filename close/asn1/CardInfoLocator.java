

package org.zmimi.webapp.orginNEL.asn1;

import org.bouncycastle.asn1.*;

;

/**
 * 
 * @author  (Standardanvändare)
 */
public class CardInfoLocator extends ASN1Object{

	private ASN1ObjectIdentifier protocol = null;
	private DERIA5String url = null;
	private ASN1Sequence fileID = null;

	public CardInfoLocator(ASN1Sequence seq) {
		protocol = (ASN1ObjectIdentifier) seq.getObjectAt(0);
		url = (DERIA5String) seq.getObjectAt(1);
		if (seq.size() > 2) {
			fileID = (ASN1Sequence) seq.getObjectAt(2);
		}
	}

	public ASN1ObjectIdentifier getProtocol() {
		return protocol;
	}

	public String getUrl() {
		return url.getString();
	}

	public FileID getFileID() {
		if (fileID == null)
			return null;
		else
			return new FileID(fileID);
	}

	@Override
	public String toString() {
		return "CardInfoLocator \n\tOID: " + getProtocol() + "\n\tURL: " + getUrl()+
				(fileID!=null?"\n\tFileId: " + getFileID() + "\n":"\n");

	}

	/**
	 * The definition of CardInfoLocator is
     * <pre>
     * CardInfoLocator ::= SEQUENCE {
     *      protocol	OBJECT IDENTIFIER(id-CI),
     *      url			IA5String,
     *      efCardInfo	FileID OPTIONAL
     * }
     * </pre>
	 */
	@Override
	public ASN1Primitive toASN1Primitive() {
		ASN1EncodableVector v = new ASN1EncodableVector();
		v.add(protocol);
		v.add(url);
		if (fileID!=null) v.add(fileID);
		return ASN1Sequence.getInstance(v);
	}

}

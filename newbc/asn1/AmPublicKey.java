
package org.zmimi.webapp.orginNEL.asn1;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.BERTags;


import java.io.IOException;


/**
 * Public Key Data Objects
 * BSI TR-03110 V2.05 Kapitel D.3.
 * 
 * @author  (Standardanvändare)
 *
 */

public class AmPublicKey extends ASN1Object {

	private ASN1ObjectIdentifier oid06 = null;
	protected ASN1EncodableVector vec = new ASN1EncodableVector();

	/**
	 *
	 * @param oidString
	 *            Algorithm Identifier
	 */
	public AmPublicKey(String oidString) {
		oid06 = new ASN1ObjectIdentifier(oidString);
		vec.add(oid06);
	}

	/**
	 * @param seq ASN1 Sequence Public Key Structure.
	 */
	public AmPublicKey(ASN1Sequence seq) {
		oid06 = ASN1ObjectIdentifier.getInstance(seq.getObjectAt(0));
		vec.add(oid06);
	}

    /**
     * DERSequence Public Keys Objects.
     *
     * @param seq
     */
    protected void decode(ASN1Sequence seq) {

    }

    /* (non-Javadoc)
	 * @see org.bouncycastle.asn1.ASN1Encodable#toASN1Object()
	 */
	@Override
	public ASN1Primitive toASN1Primitive() {
		return new DERTaggedObject(BERTags.APPLICATION, 0x49, new DERSequence(vec));
	}

	public String getOID() {
		return oid06.toString();
	}
}

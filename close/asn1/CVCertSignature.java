
package org.zmimi.webapp.orginNEL.asn1;


import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.*;

import java.io.IOException;

/**
 * @author  (Standardanvändare)
 *
 */
public class CVCertSignature extends ASN1Object {

	ASN1TaggedObject cvcsig = null;

	public CVCertSignature(byte[] signatureContent) {
		cvcsig = new DERTaggedObject(BERTags.APPLICATION, 0x37, new DEROctetString(signatureContent));
	}

	public CVCertSignature(ASN1TaggedObject taggedObj) throws IllegalArgumentException {
		if (taggedObj.getTagNo() != 0x37) {
			throw new IllegalArgumentException("Contains no Signature with tag 0x5F37");
		}
		cvcsig = taggedObj;
	}

	// Override the getEncoded method from ASN1Object to handle String encoding
	@Override
	public byte[] getEncoded(String encoding) throws IOException {
		return cvcsig.getEncoded(encoding);
	}

	// Add a method to handle the integer constant ASN1Encoding.DER
	public byte[] getEncoded(int encoding) throws IOException {
		// For ASN1Encoding.DER, use "DER" string encoding
		return getEncoded("DER");
	}

	public byte[] getSignature() {
		ASN1OctetString octetString = ASN1OctetString.getInstance(cvcsig.getBaseObject());
		return octetString.getOctets();
	}

	@Override
	public ASN1Primitive toASN1Primitive() {
		return cvcsig;
	}
}
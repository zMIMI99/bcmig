
package org.zmimi.webapp.orginNEL.asn1;

import org.bouncycastle.asn1.*;

import java.io.IOException;

/**
 * @author  (Standardanvändare)
 *
 */
public class CVCertificate extends ASN1Object {

	private CVCertBody certBody = null;
	private CVCertSignature certSignature = null;

	public CVCertificate(byte[] in) throws IllegalArgumentException, IOException {
		ASN1InputStream asn1InputStream = new ASN1InputStream(in);

		ASN1TaggedObject cvcert = ASN1TaggedObject.getInstance(asn1InputStream.readObject());
		asn1InputStream.close();

		if (cvcert.getTagNo() != 0x21) {
			throw new IllegalArgumentException("Can't find a CV Certificate");
		}

		ASN1Sequence derCert = ASN1Sequence.getInstance(cvcert.getBaseObject()); // The CV Certificate is a sequence

		ASN1TaggedObject body = ASN1TaggedObject.getInstance(derCert.getObjectAt(0)); // The first object of the Certificate is the Cert-Body
		if (body.getTagNo() != 0x4E) {
			throw new IllegalArgumentException("Can't find a Body in the CV Certificate");
		}

		certBody = new CVCertBody(body);

		ASN1TaggedObject signature = ASN1TaggedObject.getInstance(derCert.getObjectAt(1)); // The second object of the Certificate is the Signature
		if (signature.getTagNo() != 0x37) {
			throw new IllegalArgumentException("Can't find a Signature in the CV Certificate");
		}

		// Get the signature contents by extracting the octet string from the tagged object
		ASN1OctetString signatureOctets = ASN1OctetString.getInstance(signature.getBaseObject());
		certSignature = new CVCertSignature(signatureOctets.getOctets());
	}

	/**
	 * Get the signature object of this certificate
	 *
	 * @return The signature object
	 */
	public CVCertSignature getSignature() {
		return certSignature;
	}

	/**
	 * Get the body of this certificate
	 *
	 * @return The certificate body object
	 */
	public CVCertBody getBody() {
		return certBody;
	}

	/**
	 * The definition of CVCertificate is
	 * <pre>
	 * CVCertificate ::=  SEQUENCE {
	 *      body     	CVCertBody
	 *      signature	CVCertSignature
	 * }
	 * </pre>
	 */
	@Override
	public ASN1Primitive toASN1Primitive() {
		ASN1EncodableVector v = new ASN1EncodableVector();

		v.add(certBody);
		v.add(certSignature);

		return new DERTaggedObject(BERTags.APPLICATION, 0x21, new DERSequence(v));
	}
}

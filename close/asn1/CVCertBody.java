
package org.zmimi.webapp.orginNEL.asn1;

import org.bouncycastle.asn1.*;
import org.zmimi.webapp.orginNEL.tools.Converter;

import java.io.IOException;
import java.util.Date;

/**
 * @author  (Standardanvändare)
 *
 */
public class CVCertBody extends ASN1Object{

	private ASN1TaggedObject cvcbody = null;

	private ASN1Integer profileIdentifier = null;
	private ASN1IA5String authorityReference = null;
	private AmPublicKey publicKey = null;
	private ASN1IA5String chr = null;
	private CertificateHolderAuthorizationTemplate chat = null;
	private ASN1OctetString effectiveDate = null;
	private ASN1OctetString expirationDate = null;
	private ASN1Sequence extensions = null;


	public CVCertBody(ASN1Sequence derSeq) {
		// Implementation if needed
	}

	public CVCertBody(ASN1TaggedObject taggedObj) throws IllegalArgumentException, IOException {
		if (taggedObj.getTagNo() != 0x4E) {
			throw new IllegalArgumentException("contains no Certificate Body with tag 0x7F4E");
		}
		cvcbody = taggedObj;

		ASN1Sequence bodySeq = ASN1Sequence.getInstance(taggedObj.getBaseObject());

		// Parse profile identifier
		ASN1TaggedObject profileTag = ASN1TaggedObject.getInstance(bodySeq.getObjectAt(0));
		profileIdentifier = ASN1Integer.getInstance(profileTag.getBaseObject());

		// Parse authority reference
		ASN1TaggedObject authRefTag = ASN1TaggedObject.getInstance(bodySeq.getObjectAt(1));
		authorityReference = ASN1IA5String.getInstance(authRefTag.getBaseObject());

		// Parse public key
		ASN1Sequence pkSeq = ASN1Sequence.getInstance(
				ASN1TaggedObject.getInstance(bodySeq.getObjectAt(2)).getBaseObject());
		ASN1ObjectIdentifier pkOid = ASN1ObjectIdentifier.getInstance(pkSeq.getObjectAt(0));
		if (pkOid.toString().startsWith("0.4.0.127.0.7.2.2.2.2")) {
			publicKey = new AmECPublicKey(pkSeq);
		}
		else if (pkOid.toString().startsWith("0.4.0.127.0.7.2.2.2.1")) {
			publicKey = new AmRSAPublicKey(pkSeq);
		}

		// Parse CHR
		ASN1TaggedObject chrTag = ASN1TaggedObject.getInstance(bodySeq.getObjectAt(3));
		chr = ASN1IA5String.getInstance(chrTag.getBaseObject());

		// Parse CHAT
		ASN1TaggedObject chatTag = ASN1TaggedObject.getInstance(bodySeq.getObjectAt(4));
		ASN1Sequence chatSeq = ASN1Sequence.getInstance(chatTag.getBaseObject());
		chat = new CertificateHolderAuthorizationTemplate(chatSeq);

		// Parse effective date
		ASN1TaggedObject effDateTag = ASN1TaggedObject.getInstance(bodySeq.getObjectAt(5));
		effectiveDate = ASN1OctetString.getInstance(effDateTag.getBaseObject());

		// Parse expiration date
		ASN1TaggedObject expDateTag = ASN1TaggedObject.getInstance(bodySeq.getObjectAt(6));
		expirationDate = ASN1OctetString.getInstance(expDateTag.getBaseObject());

		// Parse extensions if present
		if (bodySeq.size() > 7) {
			ASN1TaggedObject extTag = ASN1TaggedObject.getInstance(bodySeq.getObjectAt(7));
			extensions = ASN1Sequence.getInstance(extTag.getBaseObject());
		}
	}

	@Override
	public byte[] getEncoded(String encoding) throws IOException {
		return cvcbody.getEncoded(encoding);
	}

	public int getProfileIdentifier() {
		return profileIdentifier.getPositiveValue().intValue();
	}

	public String getCAR() {
		return authorityReference.getString();
	}

	public AmPublicKey getPublicKey() {
		return publicKey;
	}

	public String getCHR() {
		return chr.getString();
	}

	public CertificateHolderAuthorizationTemplate getCHAT() {
		return chat;
	}

	public Date getEffectiveDateDate() {
		return Converter.BCDtoDate(effectiveDate.getOctets());
	}

	public Date getExpirationDate() {
		return Converter.BCDtoDate(expirationDate.getOctets());
	}

	public CVExtensions getExtensions() {
		CVExtensions ext = null;
		try {
			ext = CVExtensions.getInstance(extensions);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return ext;
	}

	public byte[] getEncoded(int encoding) throws IOException {
		// For ASN1Encoding.DER, use "DER" string encoding
		return getEncoded("DER");
	}

	@Override
	public String toString() {
		return new String("Certificate Body\n" +
				"\tProfile Identifier: "+profileIdentifier+"\n" +
				"\tAuthority Reference: "+authorityReference.getString()+"\n" +
				"\tPublic Key: "+publicKey.getOID()+"\n" +
				"\tHolder Reference: "+chr.getString()+"\n" +
				"\tCHAT (Role): "+ chat.getRole()+"\n" +
				"\teffective Date: "+getEffectiveDateDate()+"\n" +
				"\texpiration Date: "+getExpirationDate());
	}


	/**
	 * CVCertBody contains:
	 * - Certificate Profile Identifier
	 * - Certificate Authority Reference
	 * - Public Key
	 * - Certificate Holder Reference
	 * - Certificate Holder Authorization Template
	 * - Certificate Effective Date
	 * - Certificate Expiration Date
	 * - Certificate Extensions (OPTIONAL)
	 *
	 */
	@Override
	public ASN1Primitive toASN1Primitive() {
		ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(new DERTaggedObject(BERTags.APPLICATION, 0x29, profileIdentifier));
        v.add(new DERTaggedObject(BERTags.APPLICATION, 0x02, authorityReference));
        v.add(publicKey);
        v.add(new DERTaggedObject(BERTags.APPLICATION, 0x20, chr));
        v.add(chat);
        v.add(new DERTaggedObject(BERTags.APPLICATION, 0x25, effectiveDate));
        v.add(new DERTaggedObject(BERTags.APPLICATION, 0x24, expirationDate));
        if (extensions != null) {
            v.add(new DERTaggedObject(BERTags.APPLICATION, 0x05, extensions));
        }

        return new DERTaggedObject(BERTags.APPLICATION, 0x4E, new DERSequence(v));
	}
}
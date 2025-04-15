package org.zmimi.webapp.orginNEL.iso7816;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.BERTags;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DEROctetString;

import java.io.IOException;

/**
 * Data object with tag 85 contains a cryptogram (used for odd instruction bytes)
 *
 * @author  (Standardanvändare)
 *
 */
public class DO85 {
	protected byte[] data = null;
	protected ASN1TaggedObject to = null;

	public DO85() {
	}

	public DO85(byte[] data) {
		this.data = data.clone();
		// Changed to use explicit tagging (false as first parameter)
		to = new DERTaggedObject(false, 5, new DEROctetString(data));
	}

	public void fromByteArray(byte[] encodedData) {
		ASN1InputStream asn1in = new ASN1InputStream(encodedData);
		try {
			to = ASN1TaggedObject.getInstance(asn1in.readObject());
			asn1in.close();

			// Changed from getObject() to getBaseObject()
			ASN1OctetString ocs = ASN1OctetString.getInstance(to.getBaseObject());
			data = ocs.getOctets();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	public byte[] getEncoded() throws IOException {
		return to.getEncoded();
	}

	public byte[] getData() {
		return data;
	}
}
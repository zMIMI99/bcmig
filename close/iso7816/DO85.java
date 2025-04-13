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
		// In BC 1.78, the first parameter should be explicit tagging (false) instead of the tag class
		to = new DERTaggedObject(false, 5, new DEROctetString(data));
	}

	public void fromByteArray(byte[] encodedData) {
		ASN1InputStream asn1in = new ASN1InputStream(encodedData);
		try {
			to = ASN1TaggedObject.getInstance(asn1in.readObject());
			asn1in.close();

			// Handle the base object properly in BC 1.78
			ASN1OctetString ocs = DEROctetString.getInstance(to.getBaseObject());
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
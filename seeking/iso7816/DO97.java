package org.zmimi.webapp.orginNEL.iso7816;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.BERTags;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DEROctetString;

import java.io.IOException;

/**
 * Data Object with tag 97 contains the "length expected" bytes of the unprotected CAPDU
 *
 * @author  (Standardanvändare)
 *
 */
public class DO97 {
	private byte[] data = null;
	private ASN1TaggedObject to = null;

	public DO97() {
	}

	public DO97(byte[] le) {
		data = le.clone();
		// In BC 1.78, use explicit tagging (false) instead of context-specific class
		to = new DERTaggedObject(false, 0x17, new DEROctetString(data));
	}

	public DO97(int le) {
		data = new byte[1];
		data[0] = (byte) le;
		// In BC 1.78, use explicit tagging (false) instead of context-specific class
		to = new DERTaggedObject(false, 0x17, new DEROctetString(data));
	}

	public void fromByteArray(byte[] encodedData) {
		ASN1InputStream asn1in = new ASN1InputStream(encodedData);
		try {
			to = ASN1TaggedObject.getInstance(asn1in.readObject());
			asn1in.close();

			// Properly get the base object in BC 1.78
			ASN1OctetString ocs = ASN1OctetString.getInstance(to.getBaseObject());
			data = ocs.getOctets();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	public byte[] getEncoded() {
		try {
			return to.getEncoded();
		} catch (IOException e) {
			e.printStackTrace();
		}
		return null;
	}

	public byte[] getData() {
		return data;
	}
}
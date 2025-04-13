

package org.zmimi.webapp.orginNEL.iso7816;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.*;


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
		to = new DERTaggedObject(BERTags.CONTEXT_SPECIFIC, 0x17, new DEROctetString(data));
		//to = new DERTaggedObject(false, 0x17, new DEROctetString(data));
	}

	public DO97(int le) {
		data = new byte[1];
		data[0] = (byte) le;
		to = new DERTaggedObject(BERTags.CONTEXT_SPECIFIC, 0x17, new DEROctetString(data));
		//to = new DERTaggedObject(false, 0x17, new DEROctetString(data));
	}

	public void fromByteArray(byte[] encodedData) {
		ASN1InputStream asn1in = new ASN1InputStream(encodedData);
		try {
			to = ASN1TaggedObject.getInstance(asn1in.readObject());
			asn1in.close();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		ASN1OctetString ocs = ASN1OctetString.getInstance(to.getBaseObject());
		data = ocs.getOctets();
	}

	public byte[] getEncoded() {
		try {
			return to.getEncoded();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}

	public byte[] getData() {
		return data;
	}
}

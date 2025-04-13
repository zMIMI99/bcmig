

package org.zmimi.webapp.orginNEL.iso7816;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.*;

import java.io.IOException;

/**
 * Data Object with tag 8E contains the MAC (cryptographic checksum)
 *
 * @author (default author)
 *
 */

public class DO8E {
	private byte[] data = null;
	private ASN1TaggedObject to = null;

	public DO8E() {
	}

	public DO8E(byte[] checksum) {
		data = checksum.clone();
		to = new DERTaggedObject(BERTags.CONTEXT_SPECIFIC, 0x0E, new DEROctetString(checksum));
		//to = new DERTaggedObject(false, 0x0E, new DEROctetString(checksum));

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
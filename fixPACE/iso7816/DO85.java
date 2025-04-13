

package org.zmimi.webapp.orginNEL.iso7816;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DLTaggedObject;
import org.bouncycastle.asn1.*;
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
		//to = new DLTaggedObject(BERTags.CONTEXT_SPECIFIC, 5, new DEROctetString(data));
		to = new DERTaggedObject(BERTags.CONTEXT_SPECIFIC, 5, new DEROctetString(data));
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

	public byte[] getEncoded() throws IOException {
		return to.getEncoded();
	}

	public byte[] getData() {
		return data;
	}
}


package org.zmimi.webapp.orginNEL.iso7816;

import org.bouncycastle.asn1.*;

import java.io.IOException;

/**
 * Data Object with tag 87 contains a padding indicator followed by the cryptogram
 * 
 * @author  (Standardanvändare)
 *
 */
public class DO87 extends DO85 {

	private byte[] value_ = null;

	public DO87() {
	}

	public DO87(byte[] data) {
		this.data = data.clone();
		value_ = addPaddingIndicator(data);
		//super.to = new DLTaggedObject(BERTags.CONTEXT_SPECIFIC, 7, new DEROctetString(value_));
		super.to = new DERTaggedObject(BERTags.CONTEXT_SPECIFIC, 7, new DEROctetString(value_));
	}

	private byte[] addPaddingIndicator(byte[] data) {
		byte[] ret = new byte[data.length + 1];
		System.arraycopy(data, 0, ret, 1, data.length);
		ret[0] = 1;
		return ret;
	}

	private byte[] removePaddingIndicator(byte[] value) {
		byte[] ret = new byte[value.length - 1];
		System.arraycopy(value, 1, ret, 0, ret.length);
		return ret;
	}

	@Override
	public void fromByteArray(byte[] encodedData) {
		ASN1InputStream asn1in = new ASN1InputStream(encodedData);
		try {
			ASN1Primitive readObject = asn1in.readObject();

			// Get tagged object regardless of specific implementation
			super.to = ASN1TaggedObject.getInstance(readObject);

			asn1in.close();
		} catch (IOException e) {
			e.printStackTrace();
			throw new RuntimeException("Error reading ASN.1 input", e);
		}

		// Get the content
		ASN1OctetString ocs = ASN1OctetString.getInstance(to.getBaseObject());
		value_ = ocs.getOctets();
		super.data = removePaddingIndicator(value_);
	}
}


package org.zmimi.webapp.orginNEL.asn1;

import org.bouncycastle.asn1.*;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/**
 * ASN1-Structure for id_PACE and id_CA (General Authenticate)
 *
 * @author 
 * 
 */

public class DynamicAuthenticationData extends ASN1Object{

	private final List<ASN1TaggedObject> objects = new ArrayList<ASN1TaggedObject>(3);


	/**
	 * Constructor for encoding
	 */
	public DynamicAuthenticationData() {
	}


	/**
	 * Constructor for decoding
	 * @param data
	 */
	public DynamicAuthenticationData(byte[] data) {
		ASN1TaggedObject das = null;
		ASN1Sequence seq = null;

		try {
			das = ASN1TaggedObject.getInstance(ASN1Primitive.fromByteArray(data));
			seq = ASN1Sequence.getInstance(das.getBaseObject());
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		for (int i = 0; i < seq.size(); i++) {
			ASN1TaggedObject temp = ASN1TaggedObject.getInstance(seq.getObjectAt(i));
			objects.add(temp);
		}
	}

	/**
	 * Tag (0x80 & tagno)
	 * @param tagno
	 * @param data
	 */
	public void addDataObject(int tagno, byte[] data) {
		objects.add(new DERTaggedObject(BERTags.CONTEXT_SPECIFIC, tagno, new DEROctetString(data)));
	}

	/**
	 * Tagged Objects Tag (0x80 & tagno)
	 * @param tagno
	 * @return
	 */
	public byte[] getDataObject(int tagno) {
		for (ASN1TaggedObject item : objects) {
			if (item.getTagNo() == tagno) {
				ASN1OctetString ostr = ASN1OctetString.getInstance(item.getBaseObject());
				return ostr.getOctets();
			}
		}
		return null;
	}


	/* (non-Javadoc)
	 * @see org.bouncycastle.asn1.ASN1Object#toASN1Primitive()
	 */
	@Override
	public ASN1Primitive toASN1Primitive() {
		ASN1EncodableVector asn1vec = new ASN1EncodableVector();

		for (ASN1TaggedObject item : objects) {
			asn1vec.add(item);
		}

		return new DERTaggedObject(BERTags.APPLICATION, 0x1C, new DERSequence(asn1vec));
	}
}
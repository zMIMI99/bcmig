

package org.zmimi.webapp.orginNEL.asn1;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.DEROctetString;

import java.io.IOException;

/**
 * As described in BSI TR-03110 chpater D.2. Data Objects
 * @author  (Standardanvändare)
 * 
 */
public class DiscretionaryData extends ASN1Object{

	private DEROctetString data = null;
	
	/** Constructor for Encoding
	 * @param data
	 */
	public DiscretionaryData(byte[] data) {
		this.data = new DEROctetString(data);
	}

	/** Constructor for Encoding
	 * @param data
	 */
	public DiscretionaryData(byte data) {
		this.data = new DEROctetString(new byte[]{data});
	}


	/* (non-Javadoc)
	 * @see org.bouncycastle.asn1.ASN1Encodable#toASN1Object()
	 */
	@Override
	public ASN1Primitive toASN1Primitive() {
		try {
			return new DERTaggedObject(BERTags.APPLICATION, 0x13, data);
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}
	
	public byte[] getData() {
		return data.getOctets();
	}
	

}

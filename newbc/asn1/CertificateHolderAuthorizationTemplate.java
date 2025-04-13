

package org.zmimi.webapp.orginNEL.asn1;

import org.bouncycastle.asn1.*;

import java.io.IOException;

public class CertificateHolderAuthorizationTemplate extends ASN1Object{

	private ASN1ObjectIdentifier terminalType = null;
	private DiscretionaryData auth = null;
	private byte role;
	
	/** Constructor for Encoding a CHAT
	 * @param terminalType OID for the terminal type to use
	 * @param disData
	 */
	public CertificateHolderAuthorizationTemplate(ASN1ObjectIdentifier terminalType,	DiscretionaryData disData) {
		this.terminalType = terminalType;
		this.auth = disData;		 
	}
	
	/** Constructor for Decoding CHAT from SEQUENCE
	 * @param chatSeq
	 * @throws IOException
	 */
	public CertificateHolderAuthorizationTemplate(ASN1Sequence chatSeq) throws IOException {
		this.terminalType = ASN1ObjectIdentifier.getInstance(chatSeq.getObjectAt(0));

		ASN1TaggedObject taggedObj = ASN1TaggedObject.getInstance(chatSeq.getObjectAt(1));
		ASN1OctetString oct = ASN1OctetString.getInstance(taggedObj.getBaseObject());
		this.auth = new DiscretionaryData(oct.getOctets());
	}


	
	public byte getRole(){
		this.role = (byte) (auth.getData()[0] & 0xc0);
		return role;
	}

	/* (non-Javadoc)
	 * @see org.bouncycastle.asn1.ASN1Object#toASN1Primitive()
	 */
	@Override
	public ASN1Primitive toASN1Primitive() {
		ASN1EncodableVector v = new ASN1EncodableVector();
		v.add(terminalType);
		v.add(auth);

		return new DERTaggedObject(BERTags.APPLICATION, 0x4c, new DERSequence(v));
	}


}

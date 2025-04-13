package org.zmimi.webapp.orginNEL.asn1;

import org.bouncycastle.asn1.*;

import java.io.IOException;
import java.math.BigInteger;
import java.security.interfaces.RSAPublicKey;

/**
 * @author  (Standardanvändare)
 *
 */
public class AmRSAPublicKey extends AmPublicKey implements RSAPublicKey{

	private static final long serialVersionUID = -7184069684377504157L;

	private final String algorithm = "RSA";
	private final String format = "CVC";

	private DERTaggedObject n = null;
	private DERTaggedObject e = null;

	/**
	 * @param seq
	 */
	public AmRSAPublicKey(ASN1Sequence seq) {
		super(seq);
		decode(seq);
	}

	public AmRSAPublicKey(String oidString, BigInteger n, BigInteger e) {
		super(oidString);
		this.n = new DERTaggedObject(false, 1, new ASN1Integer(n));
		this.e = new DERTaggedObject(false, 2, new ASN1Integer(e));
		vec.add(this.n);
		vec.add(this.e);
	}

	/* (non-Javadoc)
	 * @see java.security.Key#getAlgorithm()
	 */
	@Override
	public String getAlgorithm() {
		return algorithm;
	}

	/* (non-Javadoc)
	 * @see java.security.Key#getEncoded()
	 */
	@Override
	public byte[] getEncoded() {
		vec.add(this.n);
		vec.add(this.e);
		try {
			return super.getEncoded(ASN1Encoding.DER);
		} catch (IOException e1) {
			return null;
		}
	}

	/* (non-Javadoc)
	 * @see java.security.Key#getFormat()
	 */
	@Override
	public String getFormat() {
		return format;
	}

	/* (non-Javadoc)
	 * @see org.zmimi.webapp.orgin.asn1.AmPublicKey#decode(org.bouncycastle.asn1.ASN1Sequence)
	 */
	@Override
	protected void decode(ASN1Sequence seq) {
		for (int i = 1; i<seq.size(); i++) {
			DERTaggedObject to = (DERTaggedObject) seq.getObjectAt(i);
			switch(to.getTagNo()) {
				case 1: n = to; break;
				case 2: e = to; break;
			}
		}
	}

	/* (non-Javadoc)
	 * @see java.security.interfaces.RSAKey#getModulus()
	 */
	@Override
	public BigInteger getModulus() {
		if (n==null) return null;
		ASN1Integer derInt;
		try {
			// Updated for BC 1.78
			derInt = ASN1Integer.getInstance(n.getBaseObject());
		} catch (Exception ex) {
			throw new RuntimeException(ex);
		}
		return derInt.getPositiveValue();
	}

	/* (non-Javadoc)
	 * @see java.security.interfaces.RSAPublicKey#getPublicExponent()
	 */
	@Override
	public BigInteger getPublicExponent() {
		if (e==null) return null;
		ASN1Integer derInt;
		try {
			// Updated for BC 1.78
			derInt = ASN1Integer.getInstance(e.getBaseObject());
		} catch (Exception ex) {
			throw new RuntimeException(ex);
		}
		return derInt.getPositiveValue();
	}
}
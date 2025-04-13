package org.zmimi.webapp.orginNEL.asn1;

import org.bouncycastle.asn1.*;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

import java.io.IOException;
import java.math.BigInteger;

import static org.zmimi.webapp.orgin.tools.Converter.byteArrayToECPoint;

/**
 * Class for Public Key Data Objects
 * BSI TR-03110 V2.05 Kapitel D.3.3.
 * @author  (Standardanvändare)
 *
 */

public class AmECPublicKey extends AmPublicKey implements ECPublicKey {

	private static final long serialVersionUID = 3574151885727849955L;

	private final String algorithm = "EC";
	private final String format = "CVC";

	private DERTaggedObject p = null;
	private DERTaggedObject a = null;
	private DERTaggedObject b = null;
	private DERTaggedObject G = null;
	private DERTaggedObject r = null;
	private DERTaggedObject Y = null;
	private DERTaggedObject f = null;

	/**
	 * @param seq
	 */
	public AmECPublicKey(ASN1Sequence seq) {
		super(seq);
		decode(seq);
	}

	public AmECPublicKey(String oidString, BigInteger p, BigInteger a, BigInteger b, ECPoint G, BigInteger r, ECPoint Y, BigInteger f) {
		super(oidString);
		this.p = new DERTaggedObject(false, 1, new ASN1Integer(p));
		this.a = new DERTaggedObject(false, 2, new ASN1Integer(a));
		this.b = new DERTaggedObject(false, 3, new ASN1Integer(b));
		this.G = new DERTaggedObject(false, 4, new DEROctetString(G.getEncoded(false)));
		this.r = new DERTaggedObject(false, 5, new ASN1Integer(r));
		this.Y = new DERTaggedObject(false, 6, new DEROctetString(Y.getEncoded(false)));
		this.f = new DERTaggedObject(false, 7, new ASN1Integer(f));
		vec.add(this.p);
		vec.add(this.a);
		vec.add(this.b);
		vec.add(this.G);
		vec.add(this.r);
		vec.add(this.Y);
		vec.add(this.f);
	}


	/**
	 * Ephemeral Public Keys (TR-03110 V2.05 D.3.4)
	 * @param oidString OID String
	 * @param Y public point
	 */
	public AmECPublicKey(String oidString, ECPoint Y) {
		super(oidString);
		this.Y = new DERTaggedObject(false, 6, new DEROctetString(Y.getEncoded(false)));
		vec.add(this.Y);
	}

	/* (non-Javadoc)
	 * @see java.security.Key#getAlgorithm()
	 */
	@Override
	public String getAlgorithm() {
		return algorithm;
	}

	/* (non-Javadoc)
	 * @see java.security.Key#getFormat()
	 */
	@Override
	public String getFormat() {
		return format;
	}


	/** Returns prime modulus p
	 * @return
	 */
	public BigInteger getP() {
		if (p == null) return null;
		ASN1Integer derInt = ASN1Integer.getInstance(p.getBaseObject());
		return derInt.getPositiveValue();
	}

	/** Returns first coefficient a
	 * @return
	 */
	public BigInteger getA() {
		if (a == null) return null;
		ASN1Integer derInt = ASN1Integer.getInstance(a.getBaseObject());
		return derInt.getPositiveValue();
	}

	/** Returns second coefficient b
	 * @return
	 */
	public BigInteger getB() {
		if (b == null) return null;
		ASN1Integer derInt = ASN1Integer.getInstance(b.getBaseObject());
		return derInt.getPositiveValue();
	}

	/** Returns base point G
	 * @return
	 */
	public byte[] getG() {
		if (G == null) return null;
		DEROctetString ostr = (DEROctetString) DEROctetString.getInstance(G.getBaseObject());
		return ostr.getOctets();
	}

	/** Returns order of the base point r
	 * @return
	 */
	public BigInteger getR() {
		if (r == null) return null;
		ASN1Integer derInt = ASN1Integer.getInstance(r.getBaseObject());
		return derInt.getPositiveValue();
	}

	/** Returns public point Y
	 * @return
	 */
	public byte[] getY() {
		if (Y == null) return null;
		DEROctetString ostr = (DEROctetString) DEROctetString.getInstance(Y.getBaseObject());
		return ostr.getOctets();
	}

	/** Returns cofactor f
	 * @return
	 */
	public BigInteger getF() {
		if (f == null) return null;
		ASN1Integer derInt = ASN1Integer.getInstance(f.getBaseObject());
		return derInt.getPositiveValue();
	}


	/* (non-Javadoc)
	 * @see java.security.Key#getEncoded()
	 */
	@Override
	public byte[] getEncoded() {
		try {
			return super.getEncoded(ASN1Encoding.DER);
		} catch (IOException e) {
			return null;
		}
	}

	/* (non-Javadoc)
	 * @see org.zmimi.webapp.orgin.asn1.AmPublicKey#decode(org.bouncycastle.asn1.DERSequence)
	 */
	@Override
	protected void decode(ASN1Sequence seq) {
		for (int i = 1; i < seq.size(); i++) {
			DERTaggedObject to = (DERTaggedObject) seq.getObjectAt(i);
			switch(to.getTagNo()) {
				case 1: p = to; vec.add(p); break;
				case 2: a = to; vec.add(a); break;
				case 3: b = to; vec.add(b); break;
				case 4: G = to; vec.add(G); break;
				case 5: r = to; vec.add(r); break;
				case 6: Y = to; vec.add(Y); break;
				case 7: f = to; vec.add(f); break;
			}
		}
	}

	/* (non-Javadoc)
	 * @see org.bouncycastle.jce.interfaces.ECKey#getParameters()
	 */
	@Override
	public ECParameterSpec getParameters() {
		ECCurve.Fp curve = new ECCurve.Fp(getP(), getA(), getB());
		ECPoint pointG = byteArrayToECPoint(getG(), curve);
		ECParameterSpec ecParameterSpec = new ECParameterSpec(curve, pointG, getR(), getF());
		return ecParameterSpec;
	}

	/*
	 * Returns Public Point (named Y in BSI TR-03110)
	 *
	 * @see org.bouncycastle.jce.interfaces.ECPublicKey#getQ()
	 */
	@Override
	public ECPoint getQ() {
		ECCurve.Fp curve = new ECCurve.Fp(getP(), getA(), getB());
		ECPoint pointY = byteArrayToECPoint(getY(), curve);
		return pointY;
	}

	public static AmECPublicKey getInstance(byte[] bytes) throws IOException {
		try {
			// Try to parse as a tagged object first
			ASN1TaggedObject taggedObj = (ASN1TaggedObject)ASN1Primitive.fromByteArray(bytes);
			ASN1Sequence sequence = ASN1Sequence.getInstance(taggedObj.getBaseObject());
			return new AmECPublicKey(sequence);
		} catch (Exception e) {
			// Fall back to direct sequence parsing
			ASN1Sequence sequence = ASN1Sequence.getInstance(ASN1Primitive.fromByteArray(bytes));
			return new AmECPublicKey(sequence);
		}
	}
}
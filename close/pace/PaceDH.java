

package org.zmimi.webapp.orginNEL.pace;

import org.bouncycastle.crypto.params.DHParameters;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Random;

import static org.zmimi.webapp.orgin.tools.Converter.bigIntToByteArray;

/**
 * id_PACE with Diffie Hellman
 * 
 * @author  (Standardanvändare)
 * 
 */
public class PaceDH extends Pace {

	private final SecureRandom randomGenerator = new SecureRandom();
	private BigInteger g = null;
	private BigInteger p = null;

	private BigInteger PCD_SK_x1 = null;
	private BigInteger PCD_SK_x2 = null;

	private byte[] nonce_s = null;

	public PaceDH(DHParameters dhParameters) {
		g = dhParameters.getG();
		p = dhParameters.getP();
		Random rnd = new Random();
		randomGenerator.setSeed(rnd.nextLong());
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.zmimi.webapp.orgin.pace.Pace#getX1()
	 */
	@Override
	public byte[] getX1(byte[] s) {
		nonce_s  = s.clone();
		
		byte[] x1 = new byte[g.bitLength() / 8];
		randomGenerator.nextBytes(x1);
		PCD_SK_x1 = new BigInteger(1, x1);
		
		BigInteger PCD_PK_X1 = g.modPow(PCD_SK_x1, p);
		
		return bigIntToByteArray(PCD_PK_X1);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.zmimi.webapp.orgin.pace.Pace#getX2(byte[])
	 */
	@Override
	public byte[] getX2(byte[] Y1) {
		BigInteger PICC_PK_Y1 = new BigInteger(1, Y1);
		
		BigInteger SharedSecret_P = PICC_PK_Y1.modPow(PCD_SK_x1, p);
		
		BigInteger g_strich = g.modPow(new BigInteger(1, nonce_s), p).multiply(SharedSecret_P).mod(p);
		
		byte[] x2 = new byte[g.bitLength() / 8];
		randomGenerator.nextBytes(x2);
		PCD_SK_x2 = new BigInteger(1, x2);
		
		BigInteger PCD_PK_X2 = g_strich.modPow(PCD_SK_x2, p);
		
		return bigIntToByteArray(PCD_PK_X2);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.zmimi.webapp.orgin.pace.Pace#getK(byte[])
	 */
	@Override
	public byte[] getSharedSecret_K(byte[] Y2) {
		BigInteger PICC_PK_Y2 = new BigInteger(1, Y2);
		BigInteger SharedSecret_K = PICC_PK_Y2.modPow(PCD_SK_x2, p);
		return bigIntToByteArray(SharedSecret_K);
	}

}

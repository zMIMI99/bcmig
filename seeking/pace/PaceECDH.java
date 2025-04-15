

package org.zmimi.webapp.orginNEL.pace;

import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.ECPoint.Fp;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.zmimi.webapp.LogService;
import org.zmimi.webapp.orginNEL.tools.HexString;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Random;

import static org.zmimi.webapp.orgin.tools.Converter.byteArrayToECPoint;

/**
 * id_PACE with Elliptic Curve Diffie Hellman
 * 
 * @author  (Standardanvändare)
 * 
 */

public class PaceECDH extends Pace {

	private ECPoint pointG = null;
	private ECCurve.Fp curve = null;
	private BigInteger nonce_s = null;
	
	private final SecureRandom randomGenerator = new SecureRandom();

	private BigInteger PCD_SK_x1 = null;
	private BigInteger PCD_SK_x2 = null;
	
	private static final Logger logger = LoggerFactory.getLogger(PaceECDH.class);

	private final LogService logService;

	public PaceECDH(ECParameterSpec ecParameterSpec, LogService logService) {

		pointG = ecParameterSpec.getG();
		this.logService = logService;
		logger.debug("Point G:\n"+ HexString.bufferToHex(pointG.getEncoded(false)));
		logService.logDebug("Point G:\n"+ HexString.bufferToHex(pointG.getEncoded(false)));
		
		curve = (ECCurve.Fp) ecParameterSpec.getCurve();
		Random rnd = new Random();
		randomGenerator.setSeed(rnd.nextLong());

	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.zmimi.webapp.orgin.pace.Pace#getX1(byte[])
	 */
	@Override
	public byte[] getX1(byte[] s) {
		nonce_s = new BigInteger(1, s);
		
		byte[] x1 = new byte[(curve.getFieldSize() / 8)];
		randomGenerator.nextBytes(x1);
		PCD_SK_x1 = new BigInteger(1, x1);
		logger.debug("PCD private key(x1):\n"+ HexString.bufferToHex(x1));
		logService.logDebug("PCD private key(x1):\n"+ HexString.bufferToHex(x1));
				
		ECPoint PCD_PK_X1 = pointG.multiply(PCD_SK_x1).normalize();
		logger.debug("PCD public key(X1):\n"+ HexString.bufferToHex(PCD_PK_X1.getEncoded(false)));
		logService.logDebug("PCD public key(X1):\n"+ HexString.bufferToHex(PCD_PK_X1.getEncoded(false)));
		
		return PCD_PK_X1.getEncoded(false);
	}


	/**
	 * Calculates the first using the card's public key
	 * Shared Secret P, the new point G', and the second public one
	 * Key of the terminal (X2 = x2 * G').
	 *
	 * @param Y1
	 * First public key of the card
	 * @return Second public key X2 of the terminal.
	 */
	private ECPoint getX2(Fp Y1) {
		
		Fp SharedSecret_P = (Fp) Y1.multiply(PCD_SK_x1).normalize();
		logger.debug("Shared Secret (P bzw. H):\n"+ HexString.bufferToHex(SharedSecret_P.getEncoded(false)));
		logService.logDebug("Shared Secret (P bzw. H):\n"+ HexString.bufferToHex(SharedSecret_P.getEncoded(false)));
		ECPoint pointG_strich = pointG.multiply(nonce_s).add(SharedSecret_P).normalize();
		logger.debug("G_strich:\n"+ HexString.bufferToHex(pointG_strich.getEncoded(false)));
		logService.logDebug("G_strich:\n"+ HexString.bufferToHex(pointG_strich.getEncoded(false)));
		
		byte[] x2 = new byte[(curve.getFieldSize() / 8)];
		randomGenerator.nextBytes(x2);
		PCD_SK_x2 = new BigInteger(1, x2);
		logger.debug("PCD private key(x2):\n"+ HexString.bufferToHex(x2));
		logService.logDebug("PCD private key(x2):\n"+ HexString.bufferToHex(x2));
		
		ECPoint PCD_PK_X2 = pointG_strich.multiply(PCD_SK_x2).normalize();
		logger.debug("PCD public key(X2):\n"+ HexString.bufferToHex(PCD_PK_X2.getEncoded(false)));
		logService.logDebug("PCD public key(X2):\n"+ HexString.bufferToHex(PCD_PK_X2.getEncoded(false)));
		
		return PCD_PK_X2;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.zmimi.webapp.orgin.pace.Pace#getX2(byte[])
	 */
	@Override
	public byte[] getX2(byte[] Y1Bytes) {
		
		Fp Y1 = null;
		Y1 = (Fp) byteArrayToECPoint(Y1Bytes, curve).normalize();

		return getX2(Y1).getEncoded(false);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.zmimi.webapp.orgin.pace.Pace#getSharedSecret_K(byte[])
	 */
	@Override
	public byte[] getSharedSecret_K(byte[] Y2) {
		ECPoint PICC_PK_Y2 = byteArrayToECPoint(Y2, curve).normalize();
		Fp K = (Fp) PICC_PK_Y2.multiply(PCD_SK_x2).normalize();
		return K.getXCoord().getEncoded();
	}

}

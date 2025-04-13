

package org.zmimi.webapp.orginNEL.pace;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.ECCurve.Fp;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.Arrays;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.zmimi.webapp.LogService;
import org.zmimi.webapp.orginNEL.CatCardHandler;
import org.zmimi.webapp.orginNEL.asn1.*;
import org.zmimi.webapp.orginNEL.crypto.*;
import org.zmimi.webapp.orginNEL.iso7816.MSESetAT;
import org.zmimi.webapp.orginNEL.iso7816.SecureMessaging;
import org.zmimi.webapp.orginNEL.iso7816.SecureMessagingException;
import org.zmimi.webapp.orginNEL.tools.Converter;
import org.zmimi.webapp.orginNEL.tools.HexString;

import javax.crypto.spec.DHPublicKeySpec;
import javax.smartcardio.CardException;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

import static org.zmimi.webapp.orgin.asn1.BSIObjectIdentifiers.*;

/**
 * PaceOperator provides methods to perform the id_PACE protocol
 * 
 * @author  (Standardanvändare)
 * 
 */

public class PaceOperator {

	private Pace pace = null;
	private AmCryptoProvider crypto = null;
	private CatCardHandler cardHandler = null;
	private int passwordRef = 0;
	private byte[] passwordBytes = null;
	private String protocolOIDString = null;
	private int keyLength = 0;
	private int terminalType = 0;
	private byte[] pk_picc = null;
	private DomainParameter dp = null;
	private byte[] kenc, kmac = null;
	
	private String car, car2 = null;
	private byte[] encCAdata = null;
	private byte[] pk_mapic = null;
	
	public static final byte[] defaultChatBytes_IS = new byte[] { (byte) 0x23};
	public static final byte[] defaultChatBytes_AT = new byte[] { (byte) 0x3F, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xF7 };
	public static final byte[] defaultChatBytes_ST = new byte[] { (byte) 0x03};
	
	//static Logger logger = Logger.getLogger(PaceOperator.class);
	private static final Logger logger = LoggerFactory.getLogger(PaceOperator.class);
	private final LogService logService;
	/**
	 * Constructor
	 *
	 * @param ch         CatCardHandler instance via which the card commands are sent.
	 * @param logService
	 */
	public PaceOperator(CatCardHandler ch, LogService logService) {
		cardHandler = ch;
		this.logService = logService;
	}

	/**
	 * Initializes PACE with standardized domain parameters.
	 *
	 * @param pi PACEInfo contains the crypto information to perform id_PACE
	 * @param password The password to be used for PACE
	 * @param pwRef Type of password (1=MRZ, 2=CAN, 3=PIN, 4=PUK). MRZ must encoded as: (SerialNumber||Date of Birth+Checksum||Date of Expiry+Checksum)
	 * @param terminalRef Role of the terminal according to BSI TR-03110 (1=id_IS, 2=id_AT, 3=id_ST, 0=unauthenticated terminal)
	 */
	public void setAuthTemplate(PaceInfo pi, String password, int pwRef, int terminalRef) {

		protocolOIDString = pi.getProtocolOID();
		passwordRef = pwRef;
		terminalType = terminalRef;

		if (passwordRef == 1)
			passwordBytes = calcSHA1(password.getBytes());
		else
			passwordBytes = password.getBytes();
		
		logger.info("K from password "+password+" is: "+ HexString.bufferToHex(passwordBytes));
		logService.logInfo("K from password "+password+" is: "+ HexString.bufferToHex(passwordBytes));

		dp = new DomainParameter(pi.getParameterId());

		if (protocolOIDString.startsWith(id_PACE_DH_GM.toString())
				|| protocolOIDString.startsWith(id_PACE_DH_IM.toString()))
			pace = new PaceDH(dp.getDHParameter());
		else if (protocolOIDString.startsWith(id_PACE_ECDH_GM.toString())
				|| protocolOIDString.startsWith(id_PACE_ECDH_IM.toString())
				|| protocolOIDString.startsWith(id_PACE_ECDH_CAM.toString()))
			pace = new PaceECDH(dp.getECParameter(), logService);

		getCryptoInformation(pi);
	}

	/**
	 * Initializes PACE with proprietary domain parameters.
	 *
	 * @param pi PACEInfo contains all crypto information to perform id_PACE
	 * @param pdpi Contains the proprietary domain parameters for id_PACE
	 * @param password The password to be used for PACE
	 * @param pwRef Type of password (1=MRZ, 2=CAN, 3=PIN, 4=PUK). MRZ must encoded as: (SerialNumber||Date of Birth+Checksum||Date of Expiry+Checksum)
	 * @param terminalRef Role of the terminal according to BSI TR-03110 (1=id_IS, 2=id_AT, 3=id_ST)
	 * @throws PaceException
	 */
	public void setAuthTemplate(PaceInfo pi, PaceDomainParameterInfo pdpi, String password, int pwRef, int terminalRef) throws PaceException {

		protocolOIDString = pi.getProtocolOID();
		passwordRef = pwRef;
		terminalType = terminalRef;

		if (pi.getParameterId() >= 0 && pi.getParameterId() <= 31)
			throw new IllegalArgumentException("ParameterID number 0 to 31 is used for standardized domain parameters!");
		if (pi.getParameterId() != pdpi.getParameterId())
			throw new IllegalArgumentException("PaceInfo doesn't match the PaceDomainParameterInfo");

		if (pwRef == 1)
			passwordBytes = calcSHA1(password.getBytes());
		else
			passwordBytes = password.getBytes();

		getProprietaryDomainParameters(pdpi);

		if (protocolOIDString.startsWith(id_PACE_DH_GM.toString())
				|| protocolOIDString.startsWith(id_PACE_DH_IM.toString()))
			pace = new PaceDH(dp.getDHParameter());
		else if (protocolOIDString.startsWith(id_PACE_ECDH_GM.toString())
				|| protocolOIDString.startsWith(id_PACE_ECDH_IM.toString()))
			pace = new PaceECDH(dp.getECParameter(), logService);

		getCryptoInformation(pi);
	}


	/**
	 * Performs all steps of the id_PACE protocol and delivers on success
	 * Returns a SecureMessaging instance initialized with the negotiated keys.
	 * Uses a standard CHAT of the respective terminal type. Should PACE be executed without CHAT
	 * must use <code>perfomPace(null)</code>.
	 *
	 * If <code>null</code> is passed, PACE will be carried out without CHAT in the MSE:Set id_AT.
	 * @return If PACE is successful, a with the negotiated keys is returned
	 * returned initialized SecureMessaging instance. Otherwise <code>null</code>.
	 * @throws PaceException
	 * @throws CardException
	 * @throws SecureMessagingException
	 */

	public SecureMessaging performPace() throws PaceException, SecureMessagingException, CardException {
		switch(terminalType) {
		case 1:
			return performPace(defaultChatBytes_IS);
		case 2:
			return performPace(defaultChatBytes_AT);
		case 3:
			return performPace(defaultChatBytes_ST);
		default:
			return performPace(null);
		}
	}

	/**
	 * Performs all steps of the id_PACE protocol and delivers on success
	 * Returns a SecureMessaging instance initialized with the negotiated keys.
	 *
	 * @param optCHAT optionally a CHAT can be specified. Must match the terminal type.
	 * CHAT with only one byte must be passed as a byte array of length 1.
	 * If <code>null</code> is passed, PACE will be carried out without CHAT in the MSE:Set id_AT.
	 * @return If PACE is successful, a with the negotiated keys is returned
	 * returned initialized SecureMessaging instance. Otherwise <code>null</code>.
	 * @throws PaceException
	 * @throws CardException
	 * @throws SecureMessagingException
	 */

	public SecureMessaging performPace(byte[] optCHAT) throws PaceException, SecureMessagingException, CardException {

		// send MSE:SetAT
		int resp = sendMSESetAT(terminalType, optCHAT).getSW();
		if (resp != 0x9000)	throw new PaceException("MSE:Set id_AT failed. SW: " + Integer.toHexString(resp));

		// send first GA and get nonce
		byte[] nonce_z = getNonce().getDataObject(0);

		logger.debug("encrypted nonce z: "+ HexString.bufferToHex(nonce_z));
		logService.logDebug("encrypted nonce z: "+ HexString.bufferToHex(nonce_z));
		byte[] nonce_s = decryptNonce(nonce_z);
		logger.debug("decrypted nonce s: "+ HexString.bufferToHex(nonce_s));
		logService.logDebug("decrypted nonce s: "+ HexString.bufferToHex(nonce_s));
		byte[] X1 = pace.getX1(nonce_s);

		// Send X1 to the card and receive Y1
		byte[] Y1 = mapNonce(X1).getDataObject(2);

		//Y1 is PK_MapIc for id_PACE-CAM
		pk_mapic  = Y1.clone();

		byte[] X2 = pace.getX2(Y1);
		// Send X2 to the card and receive Y2.
		byte[] Y2 = performKeyAgreement(X2).getDataObject(4);

		// Y2 is PK_Picc which is needed for the id_TA.
		pk_picc = Y2.clone();

		byte[] S = pace.getSharedSecret_K(Y2);
		kenc = getKenc(S);
		kmac = getKmac(S);
		logger.debug("shared secret (K bzw S): "+ HexString.bufferToHex(S));
		logService.logDebug("shared secret (K bzw S): "+ HexString.bufferToHex(S));
		logger.debug("Kenc: "+ HexString.bufferToHex(kenc));
		logService.logDebug("Kenc: "+ HexString.bufferToHex(kenc));
		logger.debug("Kmac: "+ HexString.bufferToHex(kmac));
		logService.logDebug("Kmac: "+ HexString.bufferToHex(kmac));
		// Calculate authentication token T_PCD
		byte[] tpcd = calcAuthToken(kmac, Y2);

		// Send authentication token T_PCD to the card and receive authentication token T_PICC
		DynamicAuthenticationData dad = performMutualAuthentication(tpcd);
		byte[] tpicc = dad.getDataObject(6);
		if (dad.getDataObject(7)!= null) {
			car = new String(dad.getDataObject(7));
			logger.info("CAR: "+car);
			logService.logInfo("CAR: "+car);
		}
		if (dad.getDataObject(8)!= null) {
			car2 = new String(dad.getDataObject(8));
			logger.info("CAR2: "+ car2);
			logService.logInfo("CAR2: "+ car2);
		}
		if (dad.getDataObject(0x0A)!= null) {
			encCAdata = dad.getDataObject(0x0A);
			logger.info("Encrypted id_CA Data: "+ HexString.bufferToHex(encCAdata));
			logService.logInfo("Encrypted id_CA Data: "+ HexString.bufferToHex(encCAdata));
			
		}

		// Authentication Token T_PICC' berechnen
		byte[] tpicc_strich = calcAuthToken(kmac, X2);
		logger.debug("tpicc': "+ HexString.bufferToHex(tpicc_strich));
		logService.logDebug("tpicc': "+ HexString.bufferToHex(tpicc_strich));

		// T_PICC = T_PICC'
		if (!Arrays.areEqual(tpicc, tpicc_strich)) throw new PaceException("Authentication Tokens are different");
		
		return new SecureMessaging(crypto, kenc, kmac, new byte[crypto.getBlockSize()]);
	}



	/**
	 * Returns the chip's ephemeral public key. This one is for Terminal
	 * Authentication according to V.2 required.
	 * @return
	 */
	public PublicKey getPKpicc() {
		
		KeyFactory fact = null;
		PublicKey pubKey = null;
		KeySpec pubKeySpec = null;
		
		if (dp.getDPType().equals("ECDH")) {
			ECPoint q = Converter.byteArrayToECPoint(pk_picc, (Fp) dp.getECParameter().getCurve()).normalize();
			pubKeySpec = new ECPublicKeySpec(q, dp.getECParameter());	
			
		} else if (dp.getDPType().equals("DH")) {
			BigInteger y = new BigInteger(1, pk_picc);
			pubKeySpec = new DHPublicKeySpec(y, dp.getDHParameter().getP(), dp.getDHParameter().getG());
		}
		
		try {
			fact = KeyFactory.getInstance(dp.getDPType(), "BC");
			pubKey = fact.generatePublic(pubKeySpec);
		} catch (NoSuchAlgorithmException e) {
			logger.warn("Couldn't generate ephemeral public key.", e);
			logService.logWarn("Couldn't generate ephemeral public key.", e);
		} catch (NoSuchProviderException e) {
			logger.warn("Couldn't generate ephemeral public key.", e);
			logService.logWarn("Couldn't generate ephemeral public key.", e);
		} catch (InvalidKeySpecException e) {
			logger.warn("Couldn't generate ephemeral public key.", e);
			logService.logWarn("Couldn't generate ephemeral public key.", e);
		}
		
		return pubKey;
	}

	/** Returns the Certificate Authority Reference returned by the chip after PACE
	 * for terminal authentication.
	 * @return current Certificate Authority Reference
	 */
	public String getCAR() {
		return car;
	}

	/** Returns the alternative Certificate Authority Reference returned by the chip after PACE
	 * for terminal authentication.
	 * @return alternative Certificate Authority Reference
	 */
	public String getCAR2() {
		return car2;
	}

	/** Returns the chip authentication data returned and decrypted by the chip according to id_PACE-CAM.
	 * @return Decrypted Chip Authentication Data
	 */

	public byte[] getCAData() {
		byte[] iv = new byte[16];
		for (int i=0;i<16;i++) iv[i] = (byte)0xFF;
		logger.info("IV: "+ HexString.bufferToHex(iv));
		logService.logInfo("IV: "+ HexString.bufferToHex(iv));
		logger.info("Kenc: "+ HexString.bufferToHex(kenc));
		logService.logInfo("Kenc: "+ HexString.bufferToHex(kenc));
		crypto.init(kenc, iv);
		try {
			return crypto.decrypt(encCAdata);
		} catch (AmCryptoException e) {
			logger.error(e.getLocalizedMessage());
			logService.logError(e.getLocalizedMessage());
		}
		return null;
	}
	
	public PublicKey getPKmapic() {
		
		KeyFactory fact = null;
		PublicKey pubKey = null;
		
		ECPoint q = Converter.byteArrayToECPoint(pk_mapic, (Fp) dp.getECParameter().getCurve()).normalize();
		ECPublicKeySpec pubKeySpec = new ECPublicKeySpec(q, dp.getECParameter());
		try {
			fact = KeyFactory.getInstance(dp.getDPType(), "BC");
			pubKey = fact.generatePublic(pubKeySpec);
		} catch (NoSuchAlgorithmException e) {
			logger.warn("Couldn't generate ephemeral public key.", e);
			logService.logWarn("Couldn't generate ephemeral public key.", e);
		} catch (NoSuchProviderException e) {
			logger.warn("Couldn't generate ephemeral public key.", e);
			logService.logWarn("Couldn't generate ephemeral public key.", e);
		} catch (InvalidKeySpecException e) {
			logger.warn("Couldn't generate ephemeral public key.", e);
			logService.logWarn("Couldn't generate ephemeral public key.", e);
		}
		
		return pubKey;
	}


	/**
	 * The authentication token is calculated from the MAC (with key kmac).
	 * an AmPublicKey which contains the object identifier of the protocol used and the
	 * from the received ephemeral public key (Y2).
	 * See TR-03110 V2.05 chapters A.2.4 and D.3.4
	 * Note: In older versions of the id_PACE protocol, additional parameters were added
	 * Calculation of the authentication token used.
	 *
	 * @param data Byte array containing a DO84 (Ephemeral Public Key).
	 * @param kmac Key K_mac for calculating the MAC
	 * @return authentication token
	 */

	private byte[] calcAuthToken(byte[] kmac, byte[] data) {
		byte[] tpcd = null;
		if (pace instanceof PaceECDH) {
			Fp curve = (Fp) dp.getECParameter().getCurve();
			ECPoint pointY = Converter.byteArrayToECPoint(data, curve).normalize();
			AmECPublicKey pkpcd = new AmECPublicKey(protocolOIDString, pointY);
			tpcd = crypto.getMAC(kmac, pkpcd.getEncoded());
		}
		else if (pace instanceof PaceDH) {
			BigInteger y = new BigInteger(1, data);
			AmDHPublicKey pkpcd = new AmDHPublicKey(protocolOIDString, y);
			tpcd = crypto.getMAC(kmac, pkpcd.getEncoded());
		}
		return tpcd;
	}
	
	private DynamicAuthenticationData sendGeneralAuthenticate(boolean chaining, byte[] data) throws SecureMessagingException, CardException, PaceException {
		
		CommandAPDU capdu = new CommandAPDU(chaining?0x10:0x00, 0x86, 0x00, 0x00, data, 0xFF);
				
		ResponseAPDU resp = cardHandler.transfer(capdu);
		
		if (!(resp.getSW() == 0x9000 || resp.getSW() == 0x6282))
			throw new PaceException("General Authentication returns: " + HexString.bufferToHex(resp.getBytes()));

		DynamicAuthenticationData dad = new DynamicAuthenticationData(resp.getData());
		return dad;
	}

	private DynamicAuthenticationData performMutualAuthentication(byte[] authToken) throws SecureMessagingException, CardException, PaceException {

		DynamicAuthenticationData dad85 = new DynamicAuthenticationData();
		DynamicAuthenticationData rspdad = null;
		dad85.addDataObject(5, authToken);
		
		try {
			rspdad = sendGeneralAuthenticate(false, dad85.getEncoded(ASN1Encoding.DER));
		} catch (IOException e) {
			logger.error(e.getLocalizedMessage());
			logService.logError(e.getLocalizedMessage());
		}
		
		return rspdad;
	}


	private DynamicAuthenticationData performKeyAgreement(byte[] ephemeralPK) throws PaceException, CardException, SecureMessagingException {

		DynamicAuthenticationData dad83 = new DynamicAuthenticationData();
		DynamicAuthenticationData rspdad = null;
		dad83.addDataObject(3, ephemeralPK);
		
		try {
			rspdad =  sendGeneralAuthenticate(true, dad83.getEncoded(ASN1Encoding.DER));
		} catch (IOException e) {
			logger.error(e.getLocalizedMessage());
			logService.logError(e.getLocalizedMessage());
		}
		
		return rspdad;
	}


	private DynamicAuthenticationData mapNonce(byte[] mappingData) throws SecureMessagingException, CardException, PaceException {

		DynamicAuthenticationData dad81 = new DynamicAuthenticationData();
		DynamicAuthenticationData rspdad = null;
		dad81.addDataObject(1, mappingData);

		try {
			rspdad = sendGeneralAuthenticate(true, dad81.getEncoded(ASN1Encoding.DER));
		} catch (IOException e) {
			logger.error(e.getLocalizedMessage());
			logService.logError(e.getLocalizedMessage());
		}
		
		return rspdad;
	}

	private ResponseAPDU sendMSESetAT(int terminalType, byte[] chatBytes ) throws PaceException, SecureMessagingException, CardException {
		MSESetAT mse = new MSESetAT();
		mse.setAT(MSESetAT.setAT_PACE);
		mse.setProtocol(protocolOIDString);
		mse.setKeyReference(passwordRef);
		DiscretionaryData disData = null;
		CertificateHolderAuthorizationTemplate chat = null;
			
		switch (terminalType) {
		case 0:
			break;
		case 1: 
			if (chatBytes!=null) {
				disData = new DiscretionaryData(chatBytes);
				chat = new CertificateHolderAuthorizationTemplate(BSIObjectIdentifiers.id_IS, disData);
				mse.setCHAT(chat);
			}			
			break;
		case 2:
			if (chatBytes!=null) {
				disData = new DiscretionaryData(chatBytes);
				chat = new CertificateHolderAuthorizationTemplate(BSIObjectIdentifiers.id_AT, disData);
				mse.setCHAT(chat);
			}			
			break;
		case 3:
			if (chatBytes!=null) {
				disData = new DiscretionaryData(chatBytes);
				chat = new CertificateHolderAuthorizationTemplate(BSIObjectIdentifiers.id_ST, disData);
				mse.setCHAT(chat);
			}
			break;
		default:
			throw new PaceException("Unknown Terminal Reference: " + terminalType);
		}
		return cardHandler.transfer(mse.getCommandAPDU());
	}


	private DynamicAuthenticationData getNonce() throws PaceException, SecureMessagingException, CardException {
		byte[] data = new byte[]{0x7C,0x00};

		DynamicAuthenticationData result = sendGeneralAuthenticate(true, data);

		// Add debugging
		byte[] nonce = result.getDataObject(0);
		System.out.println("getNonce result: " + (nonce != null ? HexString.bufferToHex(nonce) : "NULL"));

		return result;
	}


	/**
	 * @param z
	 * @return
	 */
	private byte[] decryptNonce(byte[] z) {
		byte[] derivatedPassword = getKey(keyLength, passwordBytes, 3);
		logger.debug("derivatedPassword K_pi: "+ HexString.bufferToHex(derivatedPassword));
		logService.logDebug("derivatedPassword K_pi: "+ HexString.bufferToHex(derivatedPassword));

		return crypto.decryptBlock(derivatedPassword, z);
	}

	/**
	 * @param sharedSecret_S
	 * @return
	 */
	private byte[] getKenc(byte[] sharedSecret_S) {
		return getKey(keyLength, sharedSecret_S, 1);
	}

	/**
	 * @param sharedSecret_S
	 * @return
	 */
	private byte[] getKmac(byte[] sharedSecret_S) {
		return getKey(keyLength, sharedSecret_S, 2);
	}

	/**
	 * @param keyLength
	 * @param K
	 * @param c
	 * @return
	 */
	private byte[] getKey(int keyLength, byte[] K, int c)  {

		byte[] key = null;

		KeyDerivationFunction kdf = new KeyDerivationFunction(K, c);

		switch (keyLength) {
		case 112:
			key = kdf.getDESedeKey();
			break;
		case 128:
			key = kdf.getAES128Key();
			break;
		case 192:
			key = kdf.getAES192Key();
			break;
		case 256:
			key = kdf.getAES256Key();
			break;
		}
		return key;
	}

	
	private void getProprietaryDomainParameters(PaceDomainParameterInfo pdpi) throws PaceException {
		if (pdpi.getDomainParameter().getAlgorithm().toString().contains(BSIObjectIdentifiers.id_ecc.toString())) {
			dp = new DomainParameter(pdpi.getDomainParameter());
		} else
			throw new PaceException("Can't decode properietary domain parameters in PaceDomainParameterInfo!");
	}


	/**
	 * Calculates the SHA1 value of the passed bytes array
	 *
	 * @param input
	 * Byte array of SHA1 value to be calculated
	 * @return SHA1 value from the passed byte array
	 */
	private byte[] calcSHA1(byte[] input) {
		MessageDigest md = null;
		try {
			md = MessageDigest.getInstance("SHA");
		} catch (NoSuchAlgorithmException ex) {} 

		md.update(input);
		return md.digest();
	}

	/**
	 * Determines the algorithm and key length based on the ProtocolOID
	 * for id_PACE
	 */
	private void getCryptoInformation(PaceInfo pi) {
		String protocolOIDString = pi.getProtocolOID();
		if (protocolOIDString.equals(id_PACE_DH_GM_3DES_CBC_CBC.toString())
				|| protocolOIDString.equals(id_PACE_DH_IM_3DES_CBC_CBC.toString())
				|| protocolOIDString.equals(id_PACE_ECDH_GM_3DES_CBC_CBC.toString())
				|| protocolOIDString.equals(id_PACE_ECDH_IM_3DES_CBC_CBC.toString())) {
			keyLength = 112;
			crypto = new AmDESCrypto();
		} else if (protocolOIDString.equals(id_PACE_DH_GM_AES_CBC_CMAC_128.toString())
				|| protocolOIDString.equals(id_PACE_DH_IM_AES_CBC_CMAC_128.toString())
				|| protocolOIDString.equals(id_PACE_ECDH_GM_AES_CBC_CMAC_128.toString())
				|| protocolOIDString.equals(id_PACE_ECDH_IM_AES_CBC_CMAC_128.toString())
				|| protocolOIDString.equals(id_PACE_ECDH_CAM_AES_CBC_CMAC_128.toString())) {
			keyLength = 128;
			crypto = new AmAESCrypto();
		} else if (protocolOIDString.equals(id_PACE_DH_GM_AES_CBC_CMAC_192.toString())
				|| protocolOIDString.equals(id_PACE_DH_IM_AES_CBC_CMAC_192.toString())
				|| protocolOIDString.equals(id_PACE_ECDH_GM_AES_CBC_CMAC_192.toString())
				|| protocolOIDString.equals(id_PACE_ECDH_IM_AES_CBC_CMAC_192.toString())
				|| protocolOIDString.equals(id_PACE_ECDH_CAM_AES_CBC_CMAC_192.toString())) {
			keyLength = 192;
			crypto = new AmAESCrypto();
		} else if (protocolOIDString.equals(id_PACE_DH_GM_AES_CBC_CMAC_256.toString())
				|| protocolOIDString.equals(id_PACE_DH_IM_AES_CBC_CMAC_256.toString())
				|| protocolOIDString.equals(id_PACE_ECDH_GM_AES_CBC_CMAC_256.toString())
				|| protocolOIDString.equals(id_PACE_ECDH_IM_AES_CBC_CMAC_256.toString())
				|| protocolOIDString.equals(id_PACE_ECDH_CAM_AES_CBC_CMAC_256.toString())) {
			keyLength = 256;
			crypto = new AmAESCrypto();
		}
	}

}

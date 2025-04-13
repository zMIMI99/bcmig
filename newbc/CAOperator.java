
package org.zmimi.webapp.orginNEL.ca;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.provider.JCEDHPublicKey;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.Arrays;
import org.zmimi.webapp.orginNEL.CatCardHandler;
import org.zmimi.webapp.orginNEL.asn1.*;
import org.zmimi.webapp.orginNEL.crypto.AmAESCrypto;
import org.zmimi.webapp.orginNEL.crypto.AmCryptoProvider;
import org.zmimi.webapp.orginNEL.crypto.AmDESCrypto;
import org.zmimi.webapp.orginNEL.crypto.KeyDerivationFunction;
import org.zmimi.webapp.orginNEL.iso7816.MSESetAT;
import org.zmimi.webapp.orginNEL.iso7816.SecureMessaging;
import org.zmimi.webapp.orginNEL.iso7816.SecureMessagingException;
import org.zmimi.webapp.orginNEL.tools.HexString;

import javax.smartcardio.CardException;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * @author  (Standardanvändare)
 *
 */
public class CAOperator {
	
	private CatCardHandler ch = null;
	private PrivateKey ephSKPCD = null;
	private PublicKey ephPKPCD = null;
	private byte[] caPK = null;
	private DomainParameter dp = null;
	private int caPKref;
	private String protocol = null;
	private ChipAuthentication ca = null;
	private int keyLength;
	private AmCryptoProvider crypto = null;
	
	/**
	 * Constructor
	 * @param ch CardHandler 
	 */
	public CAOperator(CatCardHandler ch) {
		this.ch = ch;
	}
	
	public void initialize(ChipAuthenticationInfo caInfo, ChipAuthenticationPublicKeyInfo caPKInfo, KeyPair ephPCDKeyPair) throws CAException {
		this.protocol = caInfo.getProtocolOID().toString();
				
		this.caPK = caPKInfo.getPublicKey().getPublicKey();
		
		this.caPKref = caInfo.getKeyId();
		if (caPKref != caPKInfo.getKeyId()) throw new CAException("Key Identifier in ChipAuthenticationInfo and ChipAuthenticationPublicKeyInfo doesn't match");
		
		this.dp = new DomainParameter(caPKInfo.getPublicKey().getAlgorithm());
		
		if (dp.getDPType().equals("ECDH")) {
			ca = new ChipAuthenticationECDH(dp.getECParameter());
		} else if (dp.getDPType().equals("DH")) {
			ca = new ChipAuthenticationDH(dp.getDHParameter());
		}
		
		this.ephSKPCD = ephPCDKeyPair.getPrivate();
		this.ephPKPCD = ephPCDKeyPair.getPublic();
				
		getCryptoInformation(caInfo);
	}
	
	public SecureMessaging performCA() throws SecureMessagingException, CardException, CAException {
		//send MSE:Set id_AT
		MSESetAT mse = new MSESetAT();
		mse.setAT(MSESetAT.setAT_CA);
		mse.setProtocol(protocol);
		mse.setPrivateKeyReference(caPKref);
		ch.transfer(mse.getCommandAPDU());
		
		// General Authenticate
		DynamicAuthenticationData dad = sendGA(); //TODO check return of the card (e.g. SW != 9000)

		//Calculate key for secure messaging
		byte[] rnd_picc = dad.getDataObject(1);
		
		byte[] K = ca.getSharedSecret_K(ephSKPCD, caPK);
		
		byte[] kenc = null;
		byte[] kmac = null;
				
		switch (keyLength) {
		case 112: 	kenc = new KeyDerivationFunction(K, rnd_picc, 1).getDESedeKey();
					kmac = new KeyDerivationFunction(K, rnd_picc, 2).getDESedeKey();
					break;
		case 128:	kenc = new KeyDerivationFunction(K, rnd_picc, 1).getAES128Key();
					kmac = new KeyDerivationFunction(K, rnd_picc, 2).getAES128Key();
					break;
		case 192:	kenc = new KeyDerivationFunction(K, rnd_picc, 1).getAES192Key();
					kmac = new KeyDerivationFunction(K, rnd_picc, 2).getAES192Key();
					break;
		case 256:	kenc = new KeyDerivationFunction(K, rnd_picc, 1).getAES256Key();
					kmac = new KeyDerivationFunction(K, rnd_picc, 2).getAES256Key();
					break;
		}

		//Compare authentication tokens
		byte[] tpcd = calcToken(kmac, ephPKPCD);
		if (!Arrays.areEqual(tpcd, dad.getDataObject(2))) throw new CAException("Authentication Tokens are different. Cards Token:\n"+
		HexString.bufferToHex(dad.getDataObject(2))+"calculated Token:\n"+ HexString.bufferToHex(tpcd));
				
		return new SecureMessaging(crypto, kenc, kmac, new byte[crypto.getBlockSize()]);
	}
	
	private byte[] calcToken(byte[] kmac, PublicKey data) {
		byte[] tpcd = null;
		if (ca instanceof ChipAuthenticationECDH) {
			ECPoint point = ((ECPublicKey)data).getQ();
			AmECPublicKey pk = new AmECPublicKey(protocol, point);
			tpcd = crypto.getMAC(kmac, pk.getEncoded());
		}
		else if (ca instanceof ChipAuthenticationDH) {
			BigInteger y = ((JCEDHPublicKey)data).getY();
			AmDHPublicKey pk = new AmDHPublicKey(protocol, y);
			tpcd = crypto.getMAC(kmac, pk.getEncoded());
		}
		return tpcd;
	}
	
	private DynamicAuthenticationData sendGA() throws SecureMessagingException, CardException {
		DynamicAuthenticationData dad80 = new DynamicAuthenticationData();
		dad80.addDataObject(0, ((ECPublicKey)ephPKPCD).getQ().getEncoded(true));
		
		byte[] dadBytes = null;
		try {
			dadBytes = dad80.getEncoded(ASN1Encoding.DER);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		//TODO Length Expected is set to 0xFF here because CommandAPDU does not take the value 0x00 into account.
		ResponseAPDU resp = ch.transfer(new CommandAPDU(0x00, 0x86, 00, 00, dadBytes, 0xFF));
		
		DynamicAuthenticationData dad = new DynamicAuthenticationData(resp.getData());
		
		return dad;
	}

	/**
	 * Determines the algorithm and key length based on the ProtocolOID
	 * for chip authentication
	 */
	private void getCryptoInformation(ChipAuthenticationInfo cai) {
		String protocolOIDString = cai.getProtocolOID();
		if (protocolOIDString.equals(BSIObjectIdentifiers.id_CA_DH_3DES_CBC_CBC.toString())
				|| protocolOIDString.equals(BSIObjectIdentifiers.id_CA_ECDH_3DES_CBC_CBC.toString())) {
			keyLength = 112;
			crypto = new AmDESCrypto();
		} else if (protocolOIDString.equals(BSIObjectIdentifiers.id_CA_DH_AES_CBC_CMAC_128.toString())
				|| protocolOIDString.equals(BSIObjectIdentifiers.id_CA_ECDH_AES_CBC_CMAC_128.toString())) {
			keyLength = 128;
			crypto = new AmAESCrypto();
		} else if (protocolOIDString.equals(BSIObjectIdentifiers.id_CA_DH_AES_CBC_CMAC_192.toString())
				|| protocolOIDString.equals(BSIObjectIdentifiers.id_CA_ECDH_AES_CBC_CMAC_192.toString())) {
			keyLength = 192;
			crypto = new AmAESCrypto();
		} else if (protocolOIDString.equals(BSIObjectIdentifiers.id_CA_DH_AES_CBC_CMAC_256.toString())
				|| protocolOIDString.equals(BSIObjectIdentifiers.id_CA_ECDH_AES_CBC_CMAC_256.toString())) {
			keyLength = 256;
			crypto = new AmAESCrypto();
		}
	}

}

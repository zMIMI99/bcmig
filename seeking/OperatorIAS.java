package org.zmimi.webapp.orginNEL;

import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.operator.OperatorCreationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;
import org.zmimi.webapp.LogService;
import org.zmimi.webapp.orginNEL.SCP03.ByteUtilsSCP03;
import org.zmimi.webapp.orginNEL.SCP03.HostChallenge;
import org.zmimi.webapp.orginNEL.asn1.SecurityInfos;
import org.zmimi.webapp.orginNEL.bac.BACOperator;
import org.zmimi.webapp.orginNEL.diversification.ByteUtils;
import org.zmimi.webapp.orginNEL.diversification.KeyDiversification;
import org.zmimi.webapp.orginNEL.dss.DssCadesSigner;
import org.zmimi.webapp.orginNEL.iso7816.CatScCommandsIAS;
import org.zmimi.webapp.orginNEL.iso7816.FileAccess;
import org.zmimi.webapp.orginNEL.iso7816.SecureMessaging;
import org.zmimi.webapp.orginNEL.iso7816.SecureMessagingException;
import org.zmimi.webapp.orginNEL.myASN1.ASN1HexParser;
import org.zmimi.webapp.orginNEL.myASN1.RobustASN1Parser;
import org.zmimi.webapp.orginNEL.pace.PaceException;
import org.zmimi.webapp.orginNEL.pace.PaceOperator;
import org.zmimi.webapp.orginNEL.tools.*;

import javax.smartcardio.CardException;
import javax.smartcardio.ResponseAPDU;
import java.io.ByteArrayOutputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Map;

import static org.zmimi.webapp.orginNEL.tools.HexString.bufferToHex;


/**
 * @author Standardanvändare
 */
@Service
@Component("OperatorNEL")
public class OperatorIAS {

	//MODIFY this value to your actual Password (eg. PIN, CAN, etc) see also pwRef
	private String password;

	//MODIFY Password Reference to set which PW shall be used for PACE (1=MRZ, 2=CAN, 3=PIN, 4=PUK). MRZ must encoded as: (SerialNumber||Date of Birth+Checksum||Date of Expiry+Checksum)
	private int pwRef = 2;

	//MODIFY role of the terminal shall be used for PACE (1=id_IS, 2=id_AT, 3=id_ST, 0=unauthenticated terminal)
	private final int terminalRef = 0;

	//MODIFY this value to the slotID where your card (or simulator) is insert
	//private final int slotID = 1;
	private final int slotID = 0;

	static final byte[] FID_MF = new byte[]{(byte) 0x3F, (byte) 0x00};

	static final byte[] FID_CIA = new byte[]{(byte) 0x50, (byte) 0x00};

	static final byte[] FID_CIA_INFO = new byte[]{(byte) 0x50, (byte) 0x32};

	static final byte[] FID_EFCardAccess = new byte[]{(byte) 0x01, (byte) 0x1C};
	static final byte[] FID_DIR = new byte[]{(byte) 0x2F, (byte) 0x00};
	static final byte[] FID_ATR = new byte[]{(byte) 0x2F, (byte) 0x01};
	static final byte[] FID_EFCardSec = new byte[]{(byte) 0x01, (byte) 0x1D};
	static final byte[] FID_DG14 = new byte[]{(byte) 0x01, (byte) 0x0E};
	static final byte[] FID_EFChipSec = new byte[]{(byte) 0x01, (byte) 0x1B};
	static final byte SFID_EFCA = (byte) 0x1C;

	static final byte[] FID_SOD = new byte[]{(byte) 0x01, (byte) 0x1D};
	static final byte[] FID_DG1 = new byte[]{(byte) 0x01, (byte) 0x01};

	static final byte[] EID_APP_ID_ClassicOld = new byte[]{(byte) 0xE8, 0x07, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x03, 0x02};

	static final byte[] EID_APP_ID = new byte[]{(byte) 0xA0, 0x00, 0x00, 0x00, 0x18, 0x40, 0x00, 0x00, 0x01, 0x63, 0x42, 0x00 };
	static final byte[] EID_APP_ID_Classic = new byte[]{(byte) 0xE8, 0x28, (byte)0xBD, 0x08, 0x0F, 0x01, 0x47, 0x65, 0x6D, 0x20, 0x50, 0x31, 0x35};






	static final byte[] LDS_APP_ID = new byte[]{(byte) 0xa0, 0x00, 0x00, 0x02, 0x47, 0x10, 0x01};

	static final byte[] PIN1 = new byte[]{0x31, 0x32, 0x33, 0x34, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
	static final byte[] PIN2 = new byte[]{0x31, 0x32, 0x33, 0x34, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
	static final byte[] FID_CardSN = new byte[]{(byte) 0x00, (byte) 0x01};

	static final byte[] EF_PRKD = new byte[]{(byte) 0x50, (byte) 0x01};

    static final byte CERTIFICATE_DO_FID_PREFIX = (byte) 0xB0;

	boolean ExtendedAnalyze = false;
	boolean DSS = false;




	//static Logger logger = Logger.getLogger(OperatorIAS.class);
	private static final Logger logger = LoggerFactory.getLogger(OperatorIAS.class);

	private final LogService logService;

	private CatCardHandler ch = null;
	private FileAccess facs = null;

	private boolean useBAC = false;

	public OperatorIAS(LogService logService) {
		this.logService = logService;
	}

	public void setUseBAC(boolean useBAC) {
		this.useBAC = useBAC;
	}

	public void runOperator() throws Exception {
		logger.info("Entering application.");
		logService.logInfo("Entering application.");

		if (connectCard()) {
			runCompleteProcedure();
		}
	}

	private void runCompleteProcedure() throws Exception {
		if (useBAC) {
			performBAC();
		} else {
			SecurityInfos cardAccess = getEFCardAccess();
			PublicKey ephPacePublicKey = performPACE(cardAccess); //ephPacePuclicKey kommer behövas om man går vidare med TA.

			byte[] efcsBytes = facs.getFile(FID_EFCardSec, true);
			logger.info("EF.CardSecurity read");
			logService.logInfo("EF.CardSecurity read");

			SecurityInfos efcs = decodeEFCardSecurity(efcsBytes);

			logger.debug("EF.CardSecurity \n: " + efcs);
			logger.info("EF.CardSecurity decoded");
			logService.logDebug("EF.CardSecurity \n: " + efcs);
			logService.logInfo("EF.CardSecurity decoded");



			...and more.

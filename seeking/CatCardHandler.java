package org.zmimi.webapp.orginNEL;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.zmimi.webapp.LogService;
import org.zmimi.webapp.orginNEL.iso7816.SecureMessaging;
import org.zmimi.webapp.orginNEL.iso7816.SecureMessagingException;
import org.zmimi.webapp.orginNEL.tools.HexString;

import javax.smartcardio.*;

/**
 * @author  (Standardanvändare)
 * 
 */
public class CatCardHandler {

	private Card card = null;;
	private CardChannel channel = null;
	private SecureMessaging sm = null;
	private boolean connected = false;
	private String proto = "T=1";


	private static final Logger logger = LoggerFactory.getLogger(CatCardHandler.class);

	private final LogService logService;

	public CatCardHandler(LogService logService) {
		this.logService = logService;
	}

	/**
	 * @param capdu Plain Command-APDU
	 * @return plain Response-APDU
	 * @throws SecureMessagingException
	 * @throws CardException
	 */
	public ResponseAPDU transfer(CommandAPDU capdu) throws SecureMessagingException, CardException  {

		logger.debug("plain C-APDU:\n" + HexString.bufferToHex(capdu.getBytes()));
		logService.logDebug("plain C-APDU:\n" + HexString.bufferToHex(capdu.getBytes()));

		if (sm != null)	{
			capdu = sm.wrap(capdu);
			logger.debug("protected C-APDU:\n"+ HexString.bufferToHex(capdu.getBytes()));
			logService.logDebug("protected C-APDU:\n"+ HexString.bufferToHex(capdu.getBytes()));
		}

		ResponseAPDU resp = channel.transmit(capdu);

		if (sm != null) {
			logger.debug("protected R-APDU:\n"+ HexString.bufferToHex(resp.getBytes()));
			logService.logDebug("protected R-APDU:\n"+ HexString.bufferToHex(resp.getBytes()));
			resp = sm.unwrap(resp);
		}

		logger.debug("plain R-APDU:\n"+ HexString.bufferToHex(resp.getBytes()));
		logService.logDebug("plain R-APDU:\n"+ HexString.bufferToHex(resp.getBytes()));

		return resp;
	}


	/**
	 * @param sm initialize SecureMessaging-Object
	 */
	public void setSecureMessaging(SecureMessaging sm) {
		this.sm = sm;
	}

	/**
	 * Establish connection to terminal and card on terminal.
	 * 
	 * @param index
	 *            Number of the terminal to use
	 * @return connect Connection successfull ?
	 * @throws CardException
	 */
	public boolean connect(int index) throws CardException {
		
		/* Is a Reader connected we can access? */
		if (TerminalFactory.getDefault().terminals().list().size() == 0) {
			logger.error("No reader available");
			logService.logError("No reader available");
			throw new CardException("No reader available");
		}

		/* Terminal we are working on */
		CardTerminal terminal = TerminalFactory.getDefault().terminals().list().get(index);

		/* Is a card present? */
		if (!terminal.isCardPresent()) {
			logger.error("No card available");
			logService.logError("No card available");
			throw new CardException("No card available");
		}

		card = terminal.connect(proto);
		logger.info("Protocol used: " + proto);
		logService.logInfo("Protocol used: " + proto);
		channel = card.getBasicChannel();
		connected = true;
		return connected;

	}

	public void disconnect() throws CardException {
		channel.close();
		card.disconnect(true);
		connected = false;
		
	}

	public byte[] getATR() {
		return card.getATR().getBytes();
	}

}

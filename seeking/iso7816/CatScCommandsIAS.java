/*
package org.zmimi.webapp.orginNEL.iso7816;

import javax.smartcardio.CommandAPDU;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
*/

/**
 * CatScCommand provides some standard ISO7816 CommandAPDU.
 * @author  (Standardanvändare)
 *
 */

/*
public class CatScCommandsIAS {

	private CatScCommandsIAS() {
	}

	public static CommandAPDU readBinary(byte sfid, byte readlength) {
		if (sfid > 0x1F)
			throw new IllegalArgumentException("Invalid Short File Identifier!");
		byte P1 = (byte) 0x80;
		P1 = (byte) (P1 | sfid);
		return new CommandAPDU(new byte[] { 0, (byte) 0xB0, P1, 0, readlength });
	}

	public static CommandAPDU readBinary(byte high_offset, byte low_offset,
			byte le) {
		byte[] command = { (byte) 0x00, (byte) 0xB0, high_offset, low_offset,
				le };
		return new CommandAPDU(command);
	}

	public static CommandAPDU selectApp(byte[] aid) {
		byte[] selectCmd = new byte[] { (byte) 0x00, (byte) 0xA4, (byte) 0x04,
				(byte) 0x0C };
		ByteArrayOutputStream command = new ByteArrayOutputStream();
		try {
			command.write(selectCmd);
			command.write(aid.length);
			command.write(aid);
		} catch (IOException e) {
			e.printStackTrace();
			return null;
		}
		return new CommandAPDU(command.toByteArray());
	}

	public static CommandAPDU selectEF(byte[] fid) {
		byte[] selectCmd = new byte[] { (byte) 0x00, (byte) 0xA4, (byte) 0x02,
				(byte) 0x0C };
		ByteArrayOutputStream command = new ByteArrayOutputStream();
		try {
			command.write(selectCmd);
			command.write(fid.length);
			command.write(fid);
		} catch (IOException e) {
			e.printStackTrace();
			return null;
		}
		return new CommandAPDU(command.toByteArray());
	}

}
*/


package org.zmimi.webapp.orginNEL.iso7816;

import org.zmimi.webapp.orginNEL.CatCardHandler;

import javax.smartcardio.CardException;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

/**
 * CatScCommand provides some standard ISO7816 CommandAPDU.
 * @author  (Standardanvändare)
 *
 */
public class CatScCommandsIAS {

	private CatScCommandsIAS() {
	}

	public static CommandAPDU readBinary(byte sfid, byte readlength) {
		if (sfid > 0x1F)
			throw new IllegalArgumentException("Invalid Short File Identifier!");
		byte P1 = (byte) 0x80;
		P1 = (byte) (P1 | sfid);
		return new CommandAPDU(new byte[] { 0, (byte) 0xB0, P1, 0, readlength });
	}

	public static CommandAPDU readBinary(byte high_offset, byte low_offset,
										 byte le) {
		byte[] command = { (byte) 0x00, (byte) 0xB0, high_offset, low_offset,
				le };
		return new CommandAPDU(command);
	}

	public static CommandAPDU selectApp(byte[] aid) {
		byte[] selectCmd = new byte[] { (byte) 0x00, (byte) 0xA4, (byte) 0x04,
				(byte) 0x0C };
		ByteArrayOutputStream command = new ByteArrayOutputStream();
		try {
			command.write(selectCmd);
			command.write(aid.length);
			command.write(aid);
		} catch (IOException e) {
			e.printStackTrace();
			return null;
		}
		return new CommandAPDU(command.toByteArray());
	}

	public static CommandAPDU selectEF(byte[] fid) {
		byte[] selectCmd = new byte[] { (byte) 0x00, (byte) 0xA4, (byte) 0x02,
				(byte) 0x0C };
		ByteArrayOutputStream command = new ByteArrayOutputStream();
		try {
			command.write(selectCmd);
			command.write(fid.length);
			command.write(fid);
		} catch (IOException e) {
			e.printStackTrace();
			return null;
		}
		return new CommandAPDU(command.toByteArray());
	}

	public static CommandAPDU selectDF(byte[] fid) {
		byte[] selectCmd = new byte[] { (byte) 0x00, (byte) 0xA4, (byte) 0x00,
				(byte) 0x0C };
		ByteArrayOutputStream command = new ByteArrayOutputStream();
		try {
			command.write(selectCmd);
			command.write(fid.length);
			command.write(fid);
		} catch (IOException e) {
			e.printStackTrace();
			return null;
		}
		return new CommandAPDU(command.toByteArray());
	}

	/**
	 * Creates a Verify PIN command APDU
	 * @param pinFormat PIN reference format (usually 0x00 for format ID)
	 * @param pinReference PIN reference (key reference, usually 0x01 or 0x02)
	 * @param pinData The PIN data to verify, or null for PIN status check
	 * @return The command APDU
	 */
	public static CommandAPDU verifyPin(byte pinFormat, byte pinReference, byte[] pinData) {
		byte p1 = pinFormat;
		byte p2 = pinReference;
		byte[] command;

		if (pinData == null) {
			// PIN status check (no data field)
			command = new byte[] { (byte) 0x00, (byte) 0x20, p1, p2, 0x00 };
			return new CommandAPDU(command);
		} else {
			ByteArrayOutputStream commandStream = new ByteArrayOutputStream();
			try {
				commandStream.write(new byte[] { (byte) 0x00, (byte) 0x20, p1, p2, (byte) pinData.length });
				commandStream.write(pinData);
			} catch (IOException e) {
				e.printStackTrace();
				return null;
			}
			return new CommandAPDU(commandStream.toByteArray());
		}
	}

	/**
	 * Creates a Manage Security Environment (MSE) command APDU
	 * @param p1Control P1 control parameter (Set/Store/Restore)
	 * @param p2Control P2 control parameter (AT/KAT/DST/CT/CCT/ST)
	 * @param data Control reference data objects
	 * @return The command APDU
	 */
	public static CommandAPDU setMSE(byte p1Control, byte p2Control, byte[] data) {
		ByteArrayOutputStream command = new ByteArrayOutputStream();
		try {
			command.write(new byte[] { (byte) 0x00, (byte) 0x22, p1Control, p2Control });
			if (data != null && data.length > 0) {
				command.write(data.length);
				command.write(data);
			} else {
				command.write(0x00); // Lc = 0 if no data
			}
		} catch (IOException e) {
			e.printStackTrace();
			return null;
		}
		return new CommandAPDU(command.toByteArray());
	}

	public static CommandAPDU setMSEExt(byte p1Control, byte p2Control, byte[] data) {
		ByteArrayOutputStream command = new ByteArrayOutputStream();
		try {
			command.write(new byte[] { (byte) 0x00, (byte) 0x22, p1Control, p2Control });

			if (data != null && data.length > 0) {
				if (data.length <= 255) {
					// Standard length
					command.write(data.length);
					command.write(data);
				} else {
					// Extended length (data > 255 bytes)
					command.write(0x00); // First byte of extended length
					command.write((data.length >> 8) & 0xFF); // High byte
					command.write(data.length & 0xFF); // Low byte
					command.write(data);
				}
			} else {
				command.write(0x00); // Lc = 0 if no data
			}
		} catch (IOException e) {
			e.printStackTrace();
			return null;
		}
		return new CommandAPDU(command.toByteArray());
	}

	public static CommandAPDU setMSENOData(byte p1Control, byte p2Control) {
		ByteArrayOutputStream command = new ByteArrayOutputStream();
		try {
			command.write(new byte[] { (byte) 0x00, (byte) 0x22, p1Control, p2Control });
		//	command.write(0x00); // Lc = 0, ingen data
		} catch (IOException e) {
			e.printStackTrace();
			return null;
		}
		return new CommandAPDU(command.toByteArray());
	}

	/**
	 * Creates a common MSE Set command for digital signature (DST)
	 * @param keyReference The key reference to use
	 * @return The command APDU
	 */
	public static CommandAPDU setMSEForDigitalSignature(byte keyReference) {
		// Typical values:
		// P1 = 0x41 (Set for computation)
		// P2 = 0xB6 (Digital Signature Template)
		byte[] data = new byte[] { (byte) 0x84, 0x01, keyReference }; // Tag 0x84 for key reference
		return setMSE((byte) 0x41, (byte) 0xB6, data);
	}

	/**
	 * Creates a Perform Security Operation (PSO) command APDU
	 * @param p1 P1 parameter (operation to perform)
	 * @param p2 P2 parameter (algorithm/reference to use)
	 * @param data Command data
	 * @param le Expected response length (0 for unknown)
	 * @return The command APDU
	 */
	public static CommandAPDU performSecurityOperation(byte p1, byte p2, byte[] data, int le) {
		ByteArrayOutputStream command = new ByteArrayOutputStream();
		try {
			command.write(new byte[] { (byte) 0x00, (byte) 0x2A, p1, p2 });
			if (data != null && data.length > 0) {
				command.write(data.length);
				command.write(data);
			} else {
				command.write(0x00); // Lc = 0 if no data
			}
		} catch (IOException e) {
			e.printStackTrace();
			return null;
		}

		byte[] commandBytes = command.toByteArray();
		if (le > 0) {
			// Add Le byte if required
			byte[] finalCommand = new byte[commandBytes.length + 1];
			System.arraycopy(commandBytes, 0, finalCommand, 0, commandBytes.length);
			finalCommand[finalCommand.length - 1] = (byte) le;
			return new CommandAPDU(finalCommand);
		} else {
			return new CommandAPDU(commandBytes);
		}
	}

	public static CommandAPDU performSecurityOperationHashToCard(byte p1, byte p2, byte[] data) {
		ByteArrayOutputStream command = new ByteArrayOutputStream();
		try {
			command.write(new byte[] { (byte) 0x00, (byte) 0x2A, p1, p2 });
			if (data != null && data.length > 0) {
				command.write(data.length);
				command.write(data);
			} else {
				command.write(0x00); // Lc = 0 if no data
			}
		} catch (IOException e) {
			e.printStackTrace();
			return null;
		}

		return new CommandAPDU(command.toByteArray());
	}


	/*public static CommandAPDU performSecurityOperationDataOnCard(byte p1, byte p2, int le) {
		ByteArrayOutputStream command = new ByteArrayOutputStream();
		try {
			command.write(new byte[] { (byte) 0x00, (byte) 0x2A, p1, p2 });
			// No Lc byte is added since there is no data
		} catch (IOException e) {
			e.printStackTrace();
			return null;
		}

		byte[] commandBytes = command.toByteArray();
		if (le > 0) {
			// Add Le byte
			byte[] finalCommand = new byte[commandBytes.length + 1];
			System.arraycopy(commandBytes, 0, finalCommand, 0, commandBytes.length);
			finalCommand[finalCommand.length - 1] = (byte) le;
			return new CommandAPDU(finalCommand);
		} else {
			return new CommandAPDU(commandBytes);
		}
	}

	 */

	/**
	 * Creates a Perform Security Operation command APDU with no data but with response expected
	 * @param p1 P1 parameter (operation to perform)
	 * @param p2 P2 parameter (algorithm/reference to use)
	 * @param le Expected response length (0 for maximum available data)
	 * @return The command APDU
	 */
	public static CommandAPDU performSecurityOperationDataOnCard(byte p1, byte p2, int le) {
		ByteArrayOutputStream command = new ByteArrayOutputStream();

		try {
			// Header (CLA, INS, P1, P2)
			command.write(new byte[] { (byte) 0x00, (byte) 0x2A, p1, p2 });

			// Handle Le parameter based on expected length
			if (le == 0) {
				// For maximum length in short APDU format
				command.write(0x00);
			} else if (le <= 256) {
				// For specific length up to 256
				command.write(le == 256 ? 0x00 : le);
			} else {
				// For extended APDUs (lengths > 256)
				command.write(0x00); // Extended APDU marker
				command.write((le >> 8) & 0xFF); // MSB of Le
				command.write(le & 0xFF); // LSB of Le (0x00 means 65536 bytes)
			}
		} catch (IOException e) {
			e.printStackTrace();
			return null;
		}

		return new CommandAPDU(command.toByteArray());
	}

	public static CommandAPDU performSecurityOperationExt(byte p1, byte p2, byte[] data, int le) {
		ByteArrayOutputStream command = new ByteArrayOutputStream();
		try {
			command.write(new byte[] { (byte) 0x00, (byte) 0x2A, p1, p2 });

			if (data != null && data.length > 0) {
				if (data.length <= 255) {
					// Standard length for data field
					command.write(data.length);
					command.write(data);
				} else {
					// Extended length for data field (data > 255 bytes)
					command.write(0x00); // First byte indicating extended length
					command.write((data.length >> 8) & 0xFF); // High byte of length
					command.write(data.length & 0xFF); // Low byte of length
					command.write(data);
				}
			} else {
				command.write(0x00); // Lc = 0 if no data
			}

			// Handle Le (expected length of response)
			if (le > 0) {
				if (le <= 256) {  // Note: le=256 is encoded as 0x00 in standard format
					// Standard Le format
					command.write((le == 256) ? 0x00 : (byte) le);
				} else {
					// Extended Le format
					command.write(0x00); // First byte indicating extended length
					command.write((le >> 8) & 0xFF); // High byte
					command.write(le & 0xFF); // Low byte
				}
			}

		} catch (IOException e) {
			e.printStackTrace();
			return null;
		}

		return new CommandAPDU(command.toByteArray());
	}


	/**
	 * Creates a PSO Compute Digital Signature command
	 * @param dataToSign The data to sign
	 * @param maxSignatureLength Expected signature length
	 * @return The command APDU
	 */

	public static CommandAPDU internalAuthenticate(byte[] challenge) {
		if (challenge == null || challenge.length == 0) {
			throw new IllegalArgumentException("Challenge data cannot be null or empty!");
		}

		return new CommandAPDU(
				(byte) 0x00,(byte) 0x88,(byte) 0x00,(byte) 0x00, challenge	);
	}



	public static CommandAPDU computeDigitalSignature(byte[] dataToSign, int maxSignatureLength) {
		// P1 = 0x9E, P2 = 0x9A for Compute Digital Signature
		return performSecurityOperation((byte) 0x9E, (byte) 0x9A, dataToSign, maxSignatureLength);
	}

	public static CommandAPDU createAPDU(byte cla, byte ins, byte p1, byte p2, byte[] data) {
		ByteArrayOutputStream command = new ByteArrayOutputStream();
		try {
			command.write(new byte[]{cla, ins, p1, p2});
			if (data != null) {
				command.write(data.length);
				command.write(data);
			}
		} catch (IOException e) {
			e.printStackTrace();
			return null;
		}
		return new CommandAPDU(command.toByteArray());
	}

	public static CommandAPDU getCommand(byte[] hostChallenge) {
		return new CommandAPDU((byte) 0x80, (byte) 0x50, (byte) 0x00, (byte) 0x00, hostChallenge);
	}

	/**
	 * Creates a GET DATA command APDU to request supported hash algorithms from the smart card.
	 * @return The command APDU
	 */
	public static CommandAPDU getSupportedHashAlgorithms() {
		byte[] getDataCmd = new byte[] { (byte) 0x80, (byte) 0xCA, (byte) 0x00, (byte) 0x00, (byte) 0x00 };

		return new CommandAPDU(getDataCmd);
	}
	/**
	 * Retrieves a complete response that might be split across multiple APDUs
	 * @param ch The card channel to communicate with
	 * @param initialResponse The initial response APDU
	 * @return The complete combined data
	 */
	public static byte[] getCompleteResponse(CatCardHandler ch, ResponseAPDU initialResponse)
			throws CardException, SecureMessagingException {
		ByteArrayOutputStream completeData = new ByteArrayOutputStream();

		// Add initial response data
		if (initialResponse.getData().length > 0) {
			completeData.write(initialResponse.getData(), 0, initialResponse.getData().length);
		}

		ResponseAPDU currentResponse = initialResponse;

		// Continue getting data as long as we receive 61xx status words
		while (currentResponse.getSW1() == 0x61) {
			CommandAPDU getResponseCmd = new CommandAPDU(new byte[] {
					(byte) 0x00, (byte) 0xC0, (byte) 0x00, (byte) 0x00, (byte) currentResponse.getSW2()
			});

			currentResponse = ch.transfer(getResponseCmd);

			// Add this response data
			if (currentResponse.getData().length > 0) {
				completeData.write(currentResponse.getData(), 0, currentResponse.getData().length);
			}

			// Exit if we get a final status word
			if (currentResponse.getSW1() != 0x61) {
				break;
			}
		}

		// Check if the final operation was successful
		if (currentResponse.getSW() != 0x9000) {
			throw new CardException("Final operation failed with status: " +
					String.format("0x%04X", currentResponse.getSW()));
		}

		return completeData.toByteArray();
	}

	/**
	 * Creates a Manage Security Environment (MSE) command APDU with optional Le parameter
	 * @param p1Control P1 control parameter (Set/Store/Restore)
	 * @param p2Control P2 control parameter (AT/KAT/DST/CT/CCT/ST)
	 * @param data Control reference data objects
	 * @param le Expected response length (0 for no Le field, positive value for expected length)
	 * @return The command APDU
	 */
	public static CommandAPDU setMSE(byte p1Control, byte p2Control, byte[] data, int le) {
		ByteArrayOutputStream command = new ByteArrayOutputStream();
		try {
			command.write(new byte[] { (byte) 0x00, (byte) 0x22, p1Control, p2Control });
			if (data != null && data.length > 0) {
				command.write(data.length);
				command.write(data);
			} else {
				command.write(0x00); // Lc = 0 if no data
			}
		} catch (IOException e) {
			e.printStackTrace();
			return null;
		}

		byte[] commandBytes = command.toByteArray();

		// Add Le byte if required
		if (le > 0) {
			byte[] finalCommand = new byte[commandBytes.length + 1];
			System.arraycopy(commandBytes, 0, finalCommand, 0, commandBytes.length);
			finalCommand[finalCommand.length - 1] = (byte)(le == 256 ? 0x00 : le);
			return new CommandAPDU(finalCommand);
		} else {
			return new CommandAPDU(commandBytes);
		}
	}

	/**
	 * Creates a Manage Security Environment (MSE) command APDU without Le parameter
	 * Overloaded method for backward compatibility
	 * @param p1Control P1 control parameter (Set/Store/Restore)
	 * @param p2Control P2 control parameter (AT/KAT/DST/CT/CCT/ST)
	 * @param data Control reference data objects
	 * @return The command APDU
	 */
	public static CommandAPDU setMSE2(byte p1Control, byte p2Control, byte[] data) {
		return setMSE(p1Control, p2Control, data, 0);
	}

	/**
	 * Creates a Manage Security Environment (MSE) command APDU with extended length support and optional Le
	 * @param p1Control P1 control parameter (Set/Store/Restore)
	 * @param p2Control P2 control parameter (AT/KAT/DST/CT/CCT/ST)
	 * @param data Control reference data objects (can be larger than 255 bytes)
	 * @param le Expected response length (0 for no Le field, positive value for expected length)
	 * @return The command APDU
	 */
	public static CommandAPDU setMSEExtended(byte p1Control, byte p2Control, byte[] data, int le) {
		ByteArrayOutputStream command = new ByteArrayOutputStream();
		try {
			command.write(new byte[] { (byte) 0x00, (byte) 0x22, p1Control, p2Control });

			if (data != null && data.length > 0) {
				if (data.length <= 255) {
					// Standard length
					command.write(data.length);
					command.write(data);
				} else {
					// Extended length (data > 255 bytes)
					command.write(0x00); // First byte of extended length
					command.write((data.length >> 8) & 0xFF); // High byte
					command.write(data.length & 0xFF); // Low byte
					command.write(data);
				}
			} else {
				command.write(0x00); // Lc = 0 if no data
			}

			// Add Le field if required
			if (le > 0) {
				if (le <= 256) {  // le=256 is encoded as 0x00
					command.write(le == 256 ? 0x00 : (byte)le);
				} else {
					command.write(0x00);
					command.write((le >> 8) & 0xFF);
					command.write(le & 0xFF);
				}
			}

		} catch (IOException e) {
			e.printStackTrace();
			return null;
		}

		return new CommandAPDU(command.toByteArray());
	}

	/**
	 * Creates a Perform Security Operation (PSO) command APDU with optional Le and extended length support
	 * @param p1 P1 parameter (operation to perform)
	 * @param p2 P2 parameter (algorithm/reference to use)
	 * @param data Command data (can be null, or larger than 255 bytes)
	 * @param le Expected response length (0 for no Le, positive value for expected length)
	 * @return The command APDU
	 */
	public static CommandAPDU performSecurityOperation2(byte p1, byte p2, byte[] data, int le) {
		ByteArrayOutputStream command = new ByteArrayOutputStream();
		boolean isExtendedLength = (data != null && data.length > 255) || le > 256;

		try {
			// Header (CLA, INS, P1, P2)
			command.write(new byte[] { (byte) 0x00, (byte) 0x2A, p1, p2 });

			// Data field (if present)
			if (data != null && data.length > 0) {
				if (data.length <= 255 && !isExtendedLength) {
					// Standard length format
					command.write(data.length);
					command.write(data);
				} else {
					// Extended length format
					command.write(0x00); // Extended length marker
					command.write((data.length >> 8) & 0xFF); // High byte
					command.write(data.length & 0xFF); // Low byte
					command.write(data);
				}
			} else {
				// No data
				if (!isExtendedLength) {
					command.write(0x00); // Standard length Lc=0
				} else {
					command.write(0x00); // Extended length marker
					command.write(0x00); // High byte = 0
					command.write(0x00); // Low byte = 0
				}
			}

			// Le field (if required)
			if (le > 0) {
				if (le <= 256 && !isExtendedLength) {
					// Standard Le format (0x00 represents 256)
					command.write(le == 256 ? 0x00 : (byte)le);
				} else {
					// Extended Le format
					if (data == null || data.length == 0) {
						// If no data field, need to add extended length marker for Lc first
						if (!isExtendedLength) {
							command.write(0x00);
							command.write(0x00);
							command.write(0x00);
						}
					}

					command.write(0x00); // Extended length marker for Le
					command.write((le >> 8) & 0xFF); // High byte
					command.write(le & 0xFF); // Low byte (0x00 means 65536 bytes)
				}
			}

		} catch (IOException e) {
			e.printStackTrace();
			return null;
		}

		return new CommandAPDU(command.toByteArray());
	}

	/**
	 * Creates a PSO Compute Digital Signature command with extended length support
	 * @param dataToSign The data to sign (can be larger than 255 bytes)
	 * @param maxSignatureLength Expected signature length (can be larger than 256 bytes)
	 * @return The command APDU
	 */
	public static CommandAPDU computeDigitalSignature2(byte[] dataToSign, int maxSignatureLength) {
		// P1 = 0x9E, P2 = 0x9A for Compute Digital Signature
		return performSecurityOperation((byte) 0x9E, (byte) 0x9A, dataToSign, maxSignatureLength);
	}

	/**
	 * Creates a PSO Hash command with extended length support
	 * @param hashData The hash data to send to the card (can be larger than 255 bytes)
	 * @param expectedResponseLength Expected length of response (0 for no response data)
	 * @return The command APDU
	 */
	public static CommandAPDU hashOperation(byte[] hashData, int expectedResponseLength) {
		// P1 = 0x90, P2 = 0xA0 for Hash operation
		return performSecurityOperation((byte) 0x90, (byte) 0xA0, hashData, expectedResponseLength);
	}
}
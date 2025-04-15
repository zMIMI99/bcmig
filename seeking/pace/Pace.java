

package org.zmimi.webapp.orginNEL.pace;

/**
 * @author  (Standardanvändare)
 * 
 */
public abstract class Pace {

	/**
	 * Calculates the first KeyPair. x1: private key (random number) and X1:
	 * public key.
	 *
	 * @param s
	 * The decrypted nonce s of the card
	 * @return The first public key X1 of the terminal.
	 */
	public abstract byte[] getX1(byte[] s);

	/**
	 * Calculates the first using the card's public key
	 * Shared Secret P and the second public key of the terminal
	 *
	 * @param Y1
	 * First public key of the card.
	 * @return Second public key X2 of the terminal.
	 */
	public abstract byte[] getX2(byte[] Y1);

	/**
	 * Generates the final shared secret K
	 *
	 * @param Y2
	 * Second public key Y2 of the card
	 *
	 */
	public abstract byte[] getSharedSecret_K(byte[] Y2);

}

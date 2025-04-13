

package org.zmimi.webapp.orginNEL.asn1;

import org.bouncycastle.asn1.*;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/**
 * 
 * @author  (Standardanvändare)
 */

public class SecurityInfos extends ASN1Object {

	List<TerminalAuthenticationInfo> terminalAuthenticationInfoList = new ArrayList<TerminalAuthenticationInfo>(3);
	List<ChipAuthenticationInfo> chipAuthenticationInfoList = new ArrayList<ChipAuthenticationInfo>(3);
	List<PaceInfo> paceInfoList = new ArrayList<PaceInfo>(3);
	List<PaceDomainParameterInfo> paceDomainParameterInfoList = new ArrayList<PaceDomainParameterInfo>(3);
	List<ChipAuthenticationDomainParameterInfo> chipAuthenticationDomainParameterInfoList = new ArrayList<ChipAuthenticationDomainParameterInfo>(3);
	List<CardInfoLocator> cardInfoLocatorList = new ArrayList<CardInfoLocator>(1);
	List<PrivilegedTerminalInfo> privilegedTerminalInfoList = new ArrayList<PrivilegedTerminalInfo>(1);
	List<ChipAuthenticationPublicKeyInfo> chipAuthenticationPublicKeyInfoList = new ArrayList<ChipAuthenticationPublicKeyInfo>(3);

	private byte[] encodedData = null;

	public SecurityInfos() {
	}

	/**
	 * Decodes the byte array passed as argument. The decoded values are stored
	 * in the member variables of this class that represent the components of
	 * the corresponding ASN.1 type.
	 * 
	 * @param encodedData DOCUMENT ME!
	 * 
	 * @throws IOException DOCUMENT ME!
	 */
	public void decode(byte[] encodedData) throws IOException {
		this.encodedData = encodedData;
		ASN1Set securityInfos = (ASN1Set) ASN1Primitive.fromByteArray(encodedData);
		int anzahlObjekte = securityInfos.size();
		ASN1Sequence securityInfo[] = new ASN1Sequence[anzahlObjekte];

		for (int i = 0; i < anzahlObjekte; i++) {
			securityInfo[i] = (ASN1Sequence) securityInfos.getObjectAt(i);
			ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier) securityInfo[i].getObjectAt(0);

			switch (oid.toString().charAt(18)) {
			case '1': 
				chipAuthenticationPublicKeyInfoList.add(new ChipAuthenticationPublicKeyInfo(securityInfo[i]));
				break;
			case '2':
				terminalAuthenticationInfoList.add(new TerminalAuthenticationInfo(securityInfo[i]));
				break;
			case '3':
				if (oid.toString().length() == 23)
					chipAuthenticationInfoList.add(new ChipAuthenticationInfo(securityInfo[i]));
				else
					chipAuthenticationDomainParameterInfoList.add(new ChipAuthenticationDomainParameterInfo(securityInfo[i]));
				break;
			case '4':
				if (oid.toString().length() == 23)
					paceInfoList.add(new PaceInfo(securityInfo[i]));
				else
					paceDomainParameterInfoList.add(new PaceDomainParameterInfo(securityInfo[i]));
				break;
			case '6':
				cardInfoLocatorList.add(new CardInfoLocator(securityInfo[i]));
				break;
			case '8':
				privilegedTerminalInfoList.add(new PrivilegedTerminalInfo(securityInfo[i]));
				break;
			} // SWITCH

		} // IF

	}

	@Override
	public String toString() {
		String summary = null;
		summary = "------------------\nSecurityInfos object contains\n"
				+ terminalAuthenticationInfoList.size()
				+ " TerminalAuthenticationInfo objects \n"
				+ chipAuthenticationInfoList.size()
				+ " ChipAuthenticationInfo objects \n"
				+ chipAuthenticationDomainParameterInfoList.size()
				+ " ChipAuthenticationDomainParameterInfo objects \n"
				+ chipAuthenticationPublicKeyInfoList.size()
				+ " ChipAuthenticationPublicKeyInfo objects \n"
				+ paceInfoList.size() + " PaceInfo objects \n"
				+ paceDomainParameterInfoList.size()
				+ " PaceDomainParameterInfo objects \n"
				+ cardInfoLocatorList.size() + " CardInfoLocator objects \n"
				+ privilegedTerminalInfoList.size()
				+ " PrivilegedTerminalInfo objects\n------------------\n";

		for (TerminalAuthenticationInfo item : terminalAuthenticationInfoList) {
			summary = summary + item.toString();
		}
		for (ChipAuthenticationInfo item : chipAuthenticationInfoList) {
			summary = summary + item.toString();
		}
		for (ChipAuthenticationDomainParameterInfo item : chipAuthenticationDomainParameterInfoList) {
			summary = summary + item.toString();
		}
		for (ChipAuthenticationPublicKeyInfo item : chipAuthenticationPublicKeyInfoList) {
			summary = summary + item.toString();
		}
		for (PaceInfo item : paceInfoList) {
			summary = summary + item.toString();
		}
		for (PaceDomainParameterInfo item : paceDomainParameterInfoList) {
			summary = summary + item.toString();
		}
		for (CardInfoLocator item : cardInfoLocatorList) {
			summary = summary + item.toString();
		}
		for (PrivilegedTerminalInfo item : privilegedTerminalInfoList) {
			summary = summary + item.toString();
		}

		return summary;
	}

	public byte[] getBytes() {
		return encodedData;
	}

	public List<PaceInfo> getPaceInfoList() {
		return paceInfoList;
	}

	public List<TerminalAuthenticationInfo> getTerminalAuthenticationInfoList() {
		return terminalAuthenticationInfoList;
	}

	public List<ChipAuthenticationInfo> getChipAuthenticationInfoList() {
		return chipAuthenticationInfoList;
	}

	public List<CardInfoLocator> getCardInfoLocatorList() {
		return cardInfoLocatorList;
	}

	public List<ChipAuthenticationDomainParameterInfo> getChipAuthenticationDomainParameterInfoList() {
		return chipAuthenticationDomainParameterInfoList;
	}

	public List<PaceDomainParameterInfo> getPaceDomainParameterInfoList() {
		return paceDomainParameterInfoList;
	}
	
	public List<ChipAuthenticationPublicKeyInfo> getChipAuthenticationPublicKeyInfoList() {
		return chipAuthenticationPublicKeyInfoList;
	}

	/**
	 * The definition of SecurityInfos is
     * <pre>
     * SecurityInfos ::= SET OF SecurityInfo
     * 
     * SecurityInfo ::= SEQUENCE {
     * 		protocol		OBJECT IDENTIFIER,
     * 		requiredData	ANY DEFINED BY protocol,
     * 		optionalData	ANY DEFINED BY protocol OPTIONAL
     * }
     * </pre>
	 */
	@Override
	public ASN1Primitive toASN1Primitive() {
		ASN1EncodableVector v = new ASN1EncodableVector();
		
		for (TerminalAuthenticationInfo item : terminalAuthenticationInfoList) {
			v.add(item);
		}
		for (ChipAuthenticationInfo item : chipAuthenticationInfoList) {
			v.add(item);
		}
		for (ChipAuthenticationDomainParameterInfo item : chipAuthenticationDomainParameterInfoList) {
			v.add(item);
		}
		for (ChipAuthenticationPublicKeyInfo item : chipAuthenticationPublicKeyInfoList) {
			v.add(item);
		}
		for (PaceInfo item : paceInfoList) {
			v.add(item);
		}
		for (PaceDomainParameterInfo item : paceDomainParameterInfoList) {
			v.add(item);
		}
		for (CardInfoLocator item : cardInfoLocatorList) {
			v.add(item);
		}
		for (PrivilegedTerminalInfo item : privilegedTerminalInfoList) {
			v.add(item);
		}
		
		return ASN1Set.getInstance(v);
	}

}


package org.zmimi.webapp.orginNEL.asn1;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.params.DHParameters;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECParameterSpec;

import static org.zmimi.webapp.orgin.crypto.DHStandardizedDomainParameters.*;

/**
 * @author  (Standardanvändare)
 *
 */
public class DomainParameter {
	
	private DHParameters dhParameters = null;
	private ECParameterSpec ecSpec = null;
	
	/**
	 * AlogorithmIdentifier standarlized Parameter for DH order ECDH.
	 * @param ref of standardized Domain Parameters
	 */
	public DomainParameter(int ref) {
		if (ref<0||ref>18) throw new UnsupportedOperationException("unsupported standardized Domain Parameters");
		else getParameters(ref);	
	}
	
	/**
	 * AlogorithmIdentifier Parameter for DH order ECDH.
	 * @param aid OID
	 */
	public DomainParameter(AlgorithmIdentifier aid) {
		if (aid.getAlgorithm().toString().equals(BSIObjectIdentifiers.standardizedDomainParameters.toString())) {
			int dpref = ((ASN1Integer)aid.getParameters()).getPositiveValue().intValue(); 
			getParameters(dpref);	
		} 
		
		else if (aid.getAlgorithm().toString().equals("1.2.840.10045.2.1")) {
			X9ECParameters x9ecp = X9ECParameters.getInstance(aid.getParameters());
			ecSpec = new ECParameterSpec(x9ecp.getCurve(), x9ecp.getG(), x9ecp.getN());
		} 
		
		//TODO prop. DH Domain Parameter
		
		else throw new UnsupportedOperationException("unsupported Domain Parameters. Algorithm OID: "+aid.getAlgorithm().toString());
	}

	/**
	 * @param dpref
	 */
	private void getParameters(int dpref) {
		switch (dpref) {
		case 0:
			dhParameters = modp1024_160();
			break;
		case 1:
			dhParameters = modp2048_224();
			break;
		case 3:
			dhParameters = modp2048_256();
			break;
		case 8:
			ecSpec = ECNamedCurveTable.getParameterSpec("secp192r1");
			break;
		case 9:
			ecSpec = ECNamedCurveTable.getParameterSpec("secp192r1");
			break;
		case 10:;
			ecSpec = ECNamedCurveTable.getParameterSpec("secp224r1");
			break;
		case 11:
			ecSpec = ECNamedCurveTable.getParameterSpec("brainpoolp224r1");
			break;
		case 12:
			ecSpec = ECNamedCurveTable.getParameterSpec("secp256r1");
			break;
		case 13:
			ecSpec = ECNamedCurveTable.getParameterSpec("brainpoolp256r1");
			break;
		case 14:
			ecSpec = ECNamedCurveTable.getParameterSpec("brainpoolp320r1");
			break;
		case 15:
			ecSpec = ECNamedCurveTable.getParameterSpec("secp384r1");
			break;
		case 16:
			ecSpec = ECNamedCurveTable.getParameterSpec("brainpoolp384r1");
			break;
		case 17:
			ecSpec = ECNamedCurveTable.getParameterSpec("brainpoolp512r1");
			break;
		case 18:
			ecSpec = ECNamedCurveTable.getParameterSpec("secp521r1");
			break;
		}
	}
	
	public String getDPType() {
		if (ecSpec!=null) return "ECDH";
		else if (dhParameters!=null) return "DH";
		return null;
	}
	
	public ECParameterSpec getECParameter() {
		return ecSpec;
	}
	
	public DHParameters getDHParameter() {
		return dhParameters;
	}

}

package org.zmimi.webapp.orginNEL.asn1;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.eac.BidirectionalMap;

import java.io.IOException;

public class DiscretionaryDataTemplate extends ASN1Object {

	private ASN1ObjectIdentifier oid;
	private byte[] dataContent;

	static BidirectionalMap ExtensionType = new BidirectionalMap();
	static
	{
		ExtensionType.put(BSIObjectIdentifiers.id_AT_eIDAccess, "id_AT eID Access");
		ExtensionType.put(BSIObjectIdentifiers.id_AT_specialFunctions, "id_AT Special Functions");
		ExtensionType.put(BSIObjectIdentifiers.id_AT_eID_Biometrics, "id_AT eID Biometrics");
		ExtensionType.put(BSIObjectIdentifiers.description, "Hash of Certificate Description");
		ExtensionType.put(BSIObjectIdentifiers.sector, "Terminal Sector for id_RI");
		ExtensionType.put(BSIObjectIdentifiers.PS_sector, "Terminal Sector for Pseudonymous Signatures");
	}

	public DiscretionaryDataTemplate(ASN1ObjectIdentifier oid, byte[] data) {
		this.oid = oid;
		this.dataContent = data;
	}

	private DiscretionaryDataTemplate(ASN1TaggedObject appSpe) throws IOException {
		setDiscretionaryData(appSpe);
	}

	private void setDiscretionaryData(ASN1TaggedObject appSpe) throws IOException {
		if (appSpe.getTagNo() == EACTags.DISCRETIONARY_DATA_TEMPLATE) {
			ASN1InputStream content = new ASN1InputStream(ASN1OctetString.getInstance(appSpe.getBaseObject()).getOctets());
			ASN1Primitive tmpObj;

			while ((tmpObj = content.readObject()) != null) {
				if (tmpObj instanceof ASN1ObjectIdentifier)
					oid = ASN1ObjectIdentifier.getInstance(tmpObj);
				else if (tmpObj instanceof ASN1TaggedObject) {
					ASN1TaggedObject aSpe = ASN1TaggedObject.getInstance(tmpObj);
					if (aSpe.getTagNo() == EACTags.DISCRETIONARY_DATA) {
						dataContent = ASN1OctetString.getInstance(aSpe.getBaseObject()).getOctets();
					} else {
						content.close();
						throw new IOException("Invalid Object, no discretionary data");
					}
				}
				else if (tmpObj instanceof DERTaggedObject) {
					DERTaggedObject aSpe = (DERTaggedObject) tmpObj;
					//Tag 0x80 and 0x81 are valid tags here
					if (aSpe.getTagNo() == 0x00 || aSpe.getTagNo() == 0x01) {
						dataContent = ASN1OctetString.getInstance(aSpe.getBaseObject()).getOctets();
					} else {
						content.close();
						throw new IOException("Invalid Object, no valid data");
					}
				}
			}
			content.close();
		} else
			throw new IOException("not a DISCRETIONARY DATA TEMPLATE :" + appSpe.getTagNo());
	}

	public byte[] getDataContent() {
		return dataContent;
	}

	public ASN1ObjectIdentifier getOid() {
		return oid;
	}

	public String getExtensionDescription() {
		String extDescriptionString = (String)ExtensionType.get(this.oid);
		if(extDescriptionString==null) extDescriptionString = "unknown Extension (OID: "+this.oid.toString()+")";
		return extDescriptionString;
	}

	public static DiscretionaryDataTemplate getInstance(Object obj) throws IOException {
		if (obj instanceof DiscretionaryDataTemplate) {
			return (DiscretionaryDataTemplate) obj;
		} else if (obj != null) {
			return new DiscretionaryDataTemplate(ASN1TaggedObject.getInstance(obj));
		}

		return null;
	}

	@Override
	public ASN1Primitive toASN1Primitive() {
		ASN1EncodableVector v = new ASN1EncodableVector();
		v.add(oid);
		v.add(new DERTaggedObject(BERTags.APPLICATION, EACTags.DISCRETIONARY_DATA, new DEROctetString(dataContent)));
		try {
			return new DERTaggedObject(BERTags.APPLICATION, EACTags.DISCRETIONARY_DATA_TEMPLATE, new DERSequence(v));
		} catch (Exception e) {
			throw new IllegalStateException("unable to convert Discretionary Data Template");
		}
	}
}

package org.zmimi.webapp.orginNEL.asn1;

import org.bouncycastle.asn1.*;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class CVExtensions extends ASN1Object {

	private final List<DiscretionaryDataTemplate> DiscretionaryDataTemplateList = new ArrayList<DiscretionaryDataTemplate>(5);

	public CVExtensions() {

	}

	public CVExtensions(DiscretionaryDataTemplate ddt) {
		this.DiscretionaryDataTemplateList.add(ddt);
	}

	private CVExtensions(ASN1TaggedObject appSpe)
			throws IOException
	{
		setCertificateExtensions(appSpe);
	}

	private void setCertificateExtensions(ASN1TaggedObject appSpe) throws IOException {
		byte[] content;
		if (appSpe.getTagNo() == EACTags.CERTIFICATE_EXTENSIONS)
		{
			content = ASN1OctetString.getInstance(appSpe.getBaseObject()).getOctets();
		}
		else
		{
			throw new IOException("Bad tag : not CERTIFICATE_EXTENSIONS");
		}
		ASN1InputStream aIS = new ASN1InputStream(content);
		ASN1Primitive obj;
		while ((obj = aIS.readObject()) != null) {
			ASN1TaggedObject aSpe;

			if (obj instanceof ASN1TaggedObject)
			{
				aSpe = (ASN1TaggedObject)obj;
			}
			else
			{
				aIS.close();
				throw new IOException("Not a valid iso7816 content : not a ASN1TaggedObject Object :" + EACTags.encodeTag(appSpe) + obj.getClass());
			}
			if (aSpe.getTagNo() == EACTags.DISCRETIONARY_DATA_TEMPLATE) {
				addDiscretionaryDataTemplate(DiscretionaryDataTemplate.getInstance(aSpe));
			}
			else {
				aIS.close();
				throw new IOException("Not a valid Discretionary Data Template, instead found tag: " + aSpe.getTagNo());
			}
		}
		aIS.close();

	}

	public void addDiscretionaryDataTemplate(DiscretionaryDataTemplate ddt) throws IOException {
		DiscretionaryDataTemplateList.add(ddt);
	}

	public List<DiscretionaryDataTemplate> getDiscretionaryDataTemplateList() {
		return DiscretionaryDataTemplateList;
	}

	@Override
	public ASN1Primitive toASN1Primitive() {
		ASN1EncodableVector v = new ASN1EncodableVector();

		for (DiscretionaryDataTemplate item : DiscretionaryDataTemplateList) {
			v.add(item);
		}

		try {
			return new DERTaggedObject(BERTags.APPLICATION, EACTags.CERTIFICATE_EXTENSIONS, new DERSequence(v));
		} catch (Exception e) {
			throw new IllegalStateException("unable to convert Certificate Extensions");
		}
	}

	public static CVExtensions getInstance(Object appSpe)
			throws IOException
	{
		if (appSpe instanceof CVExtensions)
		{
			return (CVExtensions)appSpe;
		}
		else if (appSpe != null)
		{
			return new CVExtensions(ASN1TaggedObject.getInstance(appSpe));
		}

		return null;
	}
}

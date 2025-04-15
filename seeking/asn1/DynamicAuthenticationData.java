package org.zmimi.webapp.orginNEL.asn1;

import org.bouncycastle.asn1.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.zmimi.webapp.orginNEL.tools.HexString;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/**
 * ASN1-Structure for id_PACE and id_CA (General Authenticate)
 */
public class DynamicAuthenticationData {
	private final List<TaggedData> objects = new ArrayList<>();

	private static class TaggedData {
		int tagNo;
		byte[] content;

		TaggedData(int tagNo, byte[] content) {
			this.tagNo = tagNo;
			this.content = content;
		}
	}

	public DynamicAuthenticationData() {
	}

	public DynamicAuthenticationData(byte[] data) {
		// Direct TLV parsing for PACE protocol data
		if (data == null || data.length == 0) return;

		try {
			if (data[0] == (byte)0x7C) {
				int index = 1;
				int length = 0;

				// Parse length
				if ((data[index] & 0x80) == 0) {
					length = data[index++] & 0xFF;
				} else {
					int numBytes = data[index++] & 0x7F;
					length = 0;
					for (int i = 0; i < numBytes; i++) {
						length = (length << 8) | (data[index++] & 0xFF);
					}
				}

				// Parse each tagged data object within the 7C container
				int endIndex = index + length;
				while (index < endIndex) {
					// Each tag expected to be 80-8F range (context-specific tags 0-15)
					int tag = data[index++] & 0xFF;
					int tagNumber = tag & 0x0F;

					// Parse tag data length
					int dataLength = data[index++] & 0xFF;

					// Extract content
					byte[] content = new byte[dataLength];
					System.arraycopy(data, index, content, 0, dataLength);
					index += dataLength;

					// Store the tagged data
					objects.add(new TaggedData(tagNumber, content));
				}
			}
		} catch (Exception e) {
			// Log error but don't crash on parse errors
			System.err.println("Error parsing DynamicAuthenticationData: " + e.getMessage());
		}
	}

	public void addDataObject(int tagno, byte[] data) {
		objects.add(new TaggedData(tagno, data.clone()));
	}

	public byte[] getDataObject(int tagno) {
		for (TaggedData item : objects) {
			if (item.tagNo == tagno) {
				return item.content.clone();
			}
		}
		return null;
	}

	public byte[] getEncoded() throws IOException {
		ByteArrayOutputStream bOut = new ByteArrayOutputStream();

		// Collect all tagged data first to determine total length
		ByteArrayOutputStream dataOut = new ByteArrayOutputStream();
		for (TaggedData item : objects) {
			// Write tag (0x80 + tag number)
			dataOut.write(0x80 | item.tagNo);
			// Write length
			dataOut.write(item.content.length);
			// Write content
			dataOut.write(item.content);
		}

		byte[] innerData = dataOut.toByteArray();

		// Write outer tag 0x7C
		bOut.write(0x7C);

		// Write length
		if (innerData.length < 128) {
			bOut.write(innerData.length);
		} else {
			byte[] lengthBytes = new byte[4];
			int lengthSize = 0;
			int temp = innerData.length;

			// Convert length to bytes
			while (temp > 0) {
				lengthBytes[lengthSize++] = (byte)(temp & 0xFF);
				temp >>= 8;
			}

			// Write length bytes in reverse order (big-endian)
			bOut.write(0x80 | lengthSize);
			for (int i = lengthSize - 1; i >= 0; i--) {
				bOut.write(lengthBytes[i]);
			}
		}

		// Write inner data
		bOut.write(innerData);

		return bOut.toByteArray();
	}
}
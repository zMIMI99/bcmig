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
public class DynamicAuthenticationData extends ASN1Object {

	private static final Logger logger = LoggerFactory.getLogger(DynamicAuthenticationData.class);

	// Store tag number and raw data
	private static class TaggedData {
		int tagNo;
		byte[] content;

		TaggedData(int tagNo, byte[] content) {
			this.tagNo = tagNo;
			this.content = content;
		}
	}

	private final List<TaggedData> objects = new ArrayList<>();

	public DynamicAuthenticationData() {
	}

	public DynamicAuthenticationData(byte[] data) {
		logger.debug("Parsing DynamicAuthenticationData: " + HexString.bufferToHex(data));

		// Very direct manual TLV parsing for PACE protocol
		try {
			if (data.length > 0 && (data[0] & 0xFF) == 0x7C) {
				// Skip the tag byte and determine the length
				int offset = 1;
				int length = 0;

				// Check if length is in short or long form
				if ((data[offset] & 0x80) == 0) {
					// Short form
					length = data[offset] & 0xFF;
					offset++;
				} else {
					// Long form
					int numBytes = data[offset] & 0x7F;
					offset++;
					for (int i = 0; i < numBytes; i++) {
						length = (length << 8) | (data[offset] & 0xFF);
						offset++;
					}
				}

				// Now parse the content which consists of tagged data objects
				int endOffset = offset + length;
				while (offset < endOffset) {
					// Each item starts with a tag byte (0x80 + tag number)
					int tag = data[offset] & 0xFF;
					int tagNo = tag & 0x1F; // Get the tag number (last 5 bits)
					offset++;

					// Get the length
					int itemLength = 0;
					if ((data[offset] & 0x80) == 0) {
						// Short form
						itemLength = data[offset] & 0xFF;
						offset++;
					} else {
						// Long form
						int numBytes = data[offset] & 0x7F;
						offset++;
						for (int i = 0; i < numBytes; i++) {
							itemLength = (itemLength << 8) | (data[offset] & 0xFF);
							offset++;
						}
					}

					// Extract the content
					byte[] content = new byte[itemLength];
					System.arraycopy(data, offset, content, 0, itemLength);
					offset += itemLength;

					// Store the tag and content
					objects.add(new TaggedData(tagNo, content));
					logger.debug("Found tag 0x" + Integer.toHexString(tagNo) + " content: " +
							HexString.bufferToHex(content));
				}
			}
		} catch (Exception e) {
			logger.error("Error parsing DynamicAuthenticationData", e);
		}
	}

	public void addDataObject(int tagno, byte[] data) {
		objects.add(new TaggedData(tagno, data));
		logger.debug("Added data object with tag 0x" + Integer.toHexString(tagno) +
				": " + HexString.bufferToHex(data));
	}

	public byte[] getDataObject(int tagno) {
		for (TaggedData item : objects) {
			if (item.tagNo == tagno) {
				logger.debug("Retrieved tag 0x" + Integer.toHexString(tagno) +
						": " + HexString.bufferToHex(item.content));
				return item.content;
			}
		}
		logger.debug("Tag 0x" + Integer.toHexString(tagno) + " not found");
		return null;
	}

	@Override
	public byte[] getEncoded() throws IOException {
		ByteArrayOutputStream bOut = new ByteArrayOutputStream();

		// Write the 7C tag
		bOut.write(0x7C);

		// Build the inner content first
		ByteArrayOutputStream contentBOut = new ByteArrayOutputStream();
		for (TaggedData item : objects) {
			// Add the tag (0x80 + tag number)
			contentBOut.write(0x80 | item.tagNo);

			// Write content length
			if (item.content.length < 128) {
				contentBOut.write(item.content.length);
			} else {
				// Calculate bytes needed
				int bytesNeeded = 0;
				int temp = item.content.length;
				while (temp > 0) {
					bytesNeeded++;
					temp >>= 8;
				}

				contentBOut.write(0x80 | bytesNeeded);
				for (int i = bytesNeeded - 1; i >= 0; i--) {
					contentBOut.write((item.content.length >> (i * 8)) & 0xFF);
				}
			}

			// Write content
			contentBOut.write(item.content);
		}

		byte[] content = contentBOut.toByteArray();

		// Write content length
		if (content.length < 128) {
			bOut.write(content.length);
		} else {
			// Calculate bytes needed
			int bytesNeeded = 0;
			int temp = content.length;
			while (temp > 0) {
				bytesNeeded++;
				temp >>= 8;
			}

			bOut.write(0x80 | bytesNeeded);
			for (int i = bytesNeeded - 1; i >= 0; i--) {
				bOut.write((content.length >> (i * 8)) & 0xFF);
			}
		}

		// Write content
		bOut.write(content);

		byte[] result = bOut.toByteArray();
		logger.debug("Encoded data: " + HexString.bufferToHex(result));
		return result;
	}

	@Override
	public ASN1Primitive toASN1Primitive() {
		ASN1EncodableVector vector = new ASN1EncodableVector();

		for (TaggedData item : objects) {
			vector.add(new DERTaggedObject(false, item.tagNo, new DEROctetString(item.content)));
		}

		// Create a sequence of all the tagged objects
		ASN1Sequence seq = new DERSequence(vector);

		// Wrap it with the 0x7C tag (which is 0x1C in BER tagging)
		return new DERTaggedObject(false, 0x1C, seq);
	}
}
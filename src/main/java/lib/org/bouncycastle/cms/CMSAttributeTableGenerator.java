package lib.org.bouncycastle.cms;


import java.util.Map;

import lib.org.bouncycastle.asn1.cms.AttributeTable;

/**
 * Note: The SIGNATURE parameter is only available when generating unsigned attributes.
 */
public interface CMSAttributeTableGenerator
{
    static final String CONTENT_TYPE = "contentType";
    static final String DIGEST = "digest";
    static final String SIGNATURE = "encryptedDigest";
    static final String DIGEST_ALGORITHM_IDENTIFIER = "digestAlgID";

    AttributeTable getAttributes(Map parameters)
        throws CMSAttributeTableGenerationException;
}

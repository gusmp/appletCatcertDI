package lib.org.bouncycastle.sasn1.cms;


import java.io.IOException;

import lib.org.bouncycastle.sasn1.Asn1Object;
import lib.org.bouncycastle.sasn1.Asn1ObjectIdentifier;
import lib.org.bouncycastle.sasn1.Asn1Sequence;
import lib.org.bouncycastle.sasn1.Asn1TaggedObject;

/**
 * Produce an object suitable for an ASN1OutputStream.
 * <pre>
 * ContentInfo ::= SEQUENCE {
 *          contentType ContentType,
 *          content
 *          [0] EXPLICIT ANY DEFINED BY contentType OPTIONAL }
 * </pre>
 * @deprecated use corresponding class in org.bouncycastle.asn1.cms
 */
public class ContentInfoParser
{
    private Asn1ObjectIdentifier contentType;
    private Asn1TaggedObject     content;

    public ContentInfoParser(
        Asn1Sequence  seq) 
        throws IOException
    {
        contentType = (Asn1ObjectIdentifier)seq.readObject();
        content = (Asn1TaggedObject)seq.readObject();
    }

    public Asn1ObjectIdentifier getContentType()
    {
        return contentType;
    }

    public Asn1Object getContent(
        int  tag) 
        throws IOException
    {
        if (content != null)
        {
            return content.getObject(tag, true);
        }
        
        return null;
    }
}

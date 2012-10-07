package lib.org.bouncycastle.sasn1.cms;


import java.io.IOException;

import lib.org.bouncycastle.asn1.ASN1InputStream;
import lib.org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import lib.org.bouncycastle.sasn1.Asn1Object;
import lib.org.bouncycastle.sasn1.Asn1ObjectIdentifier;
import lib.org.bouncycastle.sasn1.Asn1Sequence;
import lib.org.bouncycastle.sasn1.Asn1TaggedObject;
import lib.org.bouncycastle.sasn1.DerSequence;

/**
 * <pre>
 * EncryptedContentInfo ::= SEQUENCE {
 *     contentType ContentType,
 *     contentEncryptionAlgorithm ContentEncryptionAlgorithmIdentifier,
 *     encryptedContent [0] IMPLICIT EncryptedContent OPTIONAL 
 * }
 * </pre>
 * @deprecated use corresponding class in org.bouncycastle.asn1.cms
 */
public class EncryptedContentInfoParser
{
    private Asn1ObjectIdentifier _contentType;
    private AlgorithmIdentifier  _contentEncryptionAlgorithm;
    private Asn1TaggedObject     _encryptedContent;

    public EncryptedContentInfoParser(
        Asn1Sequence  seq) 
        throws IOException
    {
        _contentType = (Asn1ObjectIdentifier)seq.readObject();
        _contentEncryptionAlgorithm = AlgorithmIdentifier.getInstance(new ASN1InputStream(((DerSequence)seq.readObject()).getEncoded()).readObject());
        _encryptedContent = (Asn1TaggedObject)seq.readObject();
    }
    
    public Asn1ObjectIdentifier getContentType()
    {
        return _contentType;
    }
    
    public AlgorithmIdentifier getContentEncryptionAlgorithm()
    {
        return _contentEncryptionAlgorithm;
    }

    public Asn1Object getEncryptedContent(
        int  tag) 
        throws IOException
    {
        return _encryptedContent.getObject(tag, false);
    }
}

package lib.org.bouncycastle.sasn1;

import java.io.IOException;

/**
 * @deprecated use corresponsding classes in org.bouncycastle.asn1.
 */
public interface Asn1Sequence
{
    Asn1Object readObject() 
        throws IOException;
}

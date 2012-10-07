package lib.org.bouncycastle.crypto.tls;

import lib.org.bouncycastle.crypto.encodings.PKCS1Encoding;
import lib.org.bouncycastle.crypto.engines.RSABlindedEngine;
import lib.org.bouncycastle.crypto.signers.GenericSigner;

class TlsRSASigner
    extends GenericSigner
{
    TlsRSASigner()
    {
        super(new PKCS1Encoding(new RSABlindedEngine()), new CombinedHash());
    }
}

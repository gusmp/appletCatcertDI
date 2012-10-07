package lib.org.bouncycastle.crypto.tls;

import lib.org.bouncycastle.crypto.digests.SHA1Digest;
import lib.org.bouncycastle.crypto.signers.DSADigestSigner;
import lib.org.bouncycastle.crypto.signers.DSASigner;

class TlsDSSSigner
    extends DSADigestSigner
{
    TlsDSSSigner()
    {
        super(new DSASigner(), new SHA1Digest());
    }
}

package lib.org.bouncycastle.jce.provider.symmetric;

import lib.org.bouncycastle.crypto.CipherKeyGenerator;
import lib.org.bouncycastle.crypto.engines.Grain128Engine;
import lib.org.bouncycastle.jce.provider.JCEKeyGenerator;
import lib.org.bouncycastle.jce.provider.JCEStreamCipher;

public final class Grain128
{
    private Grain128()
    {
    }
    
    public static class Base
        extends JCEStreamCipher
    {
        public Base()
        {
            super(new Grain128Engine(), 12);
        }
    }

    public static class KeyGen
        extends JCEKeyGenerator
    {
        public KeyGen()
        {
            super("Grain128", 128, new CipherKeyGenerator());
        }
    }
}

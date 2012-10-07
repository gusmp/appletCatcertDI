package lib.org.bouncycastle.jce.provider.symmetric;

import java.util.HashMap;

public class NoekeonMappings
    extends HashMap
{
    public NoekeonMappings()
    {
        put("AlgorithmParameters.NOEKEON", "lib.org.bouncycastle.jce.provider.symmetric.Noekeon$AlgParams");

        put("AlgorithmParameterGenerator.NOEKEON", "lib.org.bouncycastle.jce.provider.symmetric.Noekeon$AlgParamGen");
        
        put("Cipher.NOEKEON", "lib.org.bouncycastle.jce.provider.symmetric.Noekeon$ECB");

        put("KeyGenerator.NOEKEON", "lib.org.bouncycastle.jce.provider.symmetric.Noekeon$KeyGen");
    }
}

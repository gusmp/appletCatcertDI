package lib.org.bouncycastle.jce.provider.symmetric;

import java.util.HashMap;

public class Grain128Mappings
    extends HashMap
{
    public Grain128Mappings()
    {
        put("Cipher.Grain128", "lib.org.bouncycastle.jce.provider.symmetric.Grain128$Base");
        put("KeyGenerator.Grain128", "lib.org.bouncycastle.jce.provider.symmetric.Grain128$KeyGen");
    }
}

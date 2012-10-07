package lib.org.bouncycastle.jce.provider.symmetric;

import java.util.HashMap;

public class Grainv1Mappings
    extends HashMap
{
    public Grainv1Mappings()
    {
        put("Cipher.Grainv1", "lib.org.bouncycastle.jce.provider.symmetric.Grainv1$Base");
        put("KeyGenerator.Grainv1", "lib.org.bouncycastle.jce.provider.symmetric.Grainv1$KeyGen");
    }
}

package lib.org.bouncycastle.jce.provider.symmetric;


import java.util.HashMap;

import lib.org.bouncycastle.asn1.kisa.KISAObjectIdentifiers;

public class SEEDMappings
    extends HashMap
{
    public SEEDMappings()
    {
        put("AlgorithmParameters.SEED", "lib.org.bouncycastle.jce.provider.symmetric.SEED$AlgParams");
        put("Alg.Alias.AlgorithmParameters." + KISAObjectIdentifiers.id_seedCBC, "SEED");

        put("AlgorithmParameterGenerator.SEED", "lib.org.bouncycastle.jce.provider.symmetric.SEED$AlgParamGen");
        put("Alg.Alias.AlgorithmParameterGenerator." + KISAObjectIdentifiers.id_seedCBC, "SEED");

        put("Cipher.SEED", "lib.org.bouncycastle.jce.provider.symmetric.SEED$ECB");
        put("Cipher." + KISAObjectIdentifiers.id_seedCBC, "lib.org.bouncycastle.jce.provider.symmetric.SEED$CBC");

        put("Cipher.SEEDWRAP", "lib.org.bouncycastle.jce.provider.symmetric.SEED$Wrap");
        put("Alg.Alias.Cipher." + KISAObjectIdentifiers.id_npki_app_cmsSeed_wrap, "SEEDWRAP");

        put("KeyGenerator.SEED", "lib.org.bouncycastle.jce.provider.symmetric.SEED$KeyGen");
        put("KeyGenerator." + KISAObjectIdentifiers.id_seedCBC, "lib.org.bouncycastle.jce.provider.symmetric.SEED$KeyGen");
        put("KeyGenerator." + KISAObjectIdentifiers.id_npki_app_cmsSeed_wrap, "lib.org.bouncycastle.jce.provider.symmetric.SEED$KeyGen");
    }
}

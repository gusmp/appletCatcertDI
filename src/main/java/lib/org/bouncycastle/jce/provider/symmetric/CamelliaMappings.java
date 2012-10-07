package lib.org.bouncycastle.jce.provider.symmetric;


import java.util.HashMap;

import lib.org.bouncycastle.asn1.ntt.NTTObjectIdentifiers;

public class CamelliaMappings
    extends HashMap
{
    public CamelliaMappings()
    {
        put("AlgorithmParameters.CAMELLIA", "lib.org.bouncycastle.jce.provider.symmetric.Camellia$AlgParams");
        put("Alg.Alias.AlgorithmParameters." + NTTObjectIdentifiers.id_camellia128_cbc, "CAMELLIA");
        put("Alg.Alias.AlgorithmParameters." + NTTObjectIdentifiers.id_camellia192_cbc, "CAMELLIA");
        put("Alg.Alias.AlgorithmParameters." + NTTObjectIdentifiers.id_camellia256_cbc, "CAMELLIA");

        put("AlgorithmParameterGenerator.CAMELLIA", "lib.org.bouncycastle.jce.provider.symmetric.Camellia$AlgParamGen");
        put("Alg.Alias.AlgorithmParameterGenerator." + NTTObjectIdentifiers.id_camellia128_cbc, "CAMELLIA");
        put("Alg.Alias.AlgorithmParameterGenerator." + NTTObjectIdentifiers.id_camellia192_cbc, "CAMELLIA");
        put("Alg.Alias.AlgorithmParameterGenerator." + NTTObjectIdentifiers.id_camellia256_cbc, "CAMELLIA");

        put("Cipher.CAMELLIA", "lib.org.bouncycastle.jce.provider.symmetric.Camellia$ECB");
        put("Cipher." + NTTObjectIdentifiers.id_camellia128_cbc, "lib.org.bouncycastle.jce.provider.symmetric.Camellia$CBC");
        put("Cipher." + NTTObjectIdentifiers.id_camellia192_cbc, "lib.org.bouncycastle.jce.provider.symmetric.Camellia$CBC");
        put("Cipher." + NTTObjectIdentifiers.id_camellia256_cbc, "lib.org.bouncycastle.jce.provider.symmetric.Camellia$CBC");

        put("Cipher.CAMELLIARFC3211WRAP", "lib.org.bouncycastle.jce.provider.symmetric.Camellia$RFC3211Wrap");
        put("Cipher.CAMELLIAWRAP", "lib.org.bouncycastle.jce.provider.symmetric.Camellia$Wrap");
        put("Alg.Alias.Cipher." + NTTObjectIdentifiers.id_camellia128_wrap, "CAMELLIAWRAP");
        put("Alg.Alias.Cipher." + NTTObjectIdentifiers.id_camellia192_wrap, "CAMELLIAWRAP");
        put("Alg.Alias.Cipher." + NTTObjectIdentifiers.id_camellia256_wrap, "CAMELLIAWRAP");

        put("KeyGenerator.CAMELLIA", "lib.org.bouncycastle.jce.provider.symmetric.Camellia$KeyGen");
        put("KeyGenerator." + NTTObjectIdentifiers.id_camellia128_wrap, "lib.org.bouncycastle.jce.provider.symmetric.Camellia$KeyGen128");
        put("KeyGenerator." + NTTObjectIdentifiers.id_camellia192_wrap, "lib.org.bouncycastle.jce.provider.symmetric.Camellia$KeyGen192");
        put("KeyGenerator." + NTTObjectIdentifiers.id_camellia256_wrap, "lib.org.bouncycastle.jce.provider.symmetric.Camellia$KeyGen256");
        put("KeyGenerator." + NTTObjectIdentifiers.id_camellia128_cbc, "lib.org.bouncycastle.jce.provider.symmetric.Camellia$KeyGen128");
        put("KeyGenerator." + NTTObjectIdentifiers.id_camellia192_cbc, "lib.org.bouncycastle.jce.provider.symmetric.Camellia$KeyGen192");
        put("KeyGenerator." + NTTObjectIdentifiers.id_camellia256_cbc, "lib.org.bouncycastle.jce.provider.symmetric.Camellia$KeyGen256");
    }
}

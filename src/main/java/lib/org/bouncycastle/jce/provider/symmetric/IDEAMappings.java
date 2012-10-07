package lib.org.bouncycastle.jce.provider.symmetric;

import java.util.HashMap;

public class IDEAMappings
    extends HashMap
{
    public IDEAMappings()
    {
        put("AlgorithmParameterGenerator.IDEA", "lib.org.bouncycastle.jce.provider.symmetric.IDEA$AlgParamGen");
        put("AlgorithmParameterGenerator.1.3.6.1.4.1.188.7.1.1.2", "lib.org.bouncycastle.jce.provider.symmetric.IDEA$AlgParamGen");
        put("AlgorithmParameters.IDEA", "lib.org.bouncycastle.jce.provider.symmetric.IDEA$AlgParams");
        put("AlgorithmParameters.1.3.6.1.4.1.188.7.1.1.2", "lib.org.bouncycastle.jce.provider.symmetric.IDEA$AlgParams");
        put("Alg.Alias.AlgorithmParameters.PBEWITHSHAANDIDEA", "PKCS12PBE");
        put("Alg.Alias.AlgorithmParameters.PBEWITHSHAANDIDEA", "PKCS12PBE");
        put("Alg.Alias.AlgorithmParameters.PBEWITHSHAANDIDEA-CBC", "PKCS12PBE");
        put("Cipher.IDEA", "lib.org.bouncycastle.jce.provider.symmetric.IDEA$ECB");
        put("Cipher.1.3.6.1.4.1.188.7.1.1.2", "lib.org.bouncycastle.jce.provider.symmetric.IDEA$CBC");
        put("Cipher.PBEWITHSHAANDIDEA-CBC", "lib.org.bouncycastle.jce.provider.symmetric.IDEA$PBEWithSHAAndIDEA");
        put("KeyGenerator.IDEA", "lib.org.bouncycastle.jce.provider.symmetric.IDEA$KeyGen");
        put("KeyGenerator.1.3.6.1.4.1.188.7.1.1.2", "lib.org.bouncycastle.jce.provider.symmetric.IDEA$KeyGen");
        put("SecretKeyFactory.PBEWITHSHAANDIDEA-CBC", "lib.org.bouncycastle.jce.provider.symmetric.IDEA$PBEWithSHAAndIDEAKeyGen");
        put("Mac.IDEAMAC", "lib.org.bouncycastle.jce.provider.symmetric.IDEA$Mac");
        put("Alg.Alias.Mac.IDEA", "IDEAMAC");
        put("Mac.IDEAMAC/CFB8", "lib.org.bouncycastle.jce.provider.symmetric.IDEA$CFB8Mac");
        put("Alg.Alias.Mac.IDEA/CFB8", "IDEAMAC/CFB8");
    }
}

package lib.org.bouncycastle.cms;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;

import lib.org.bouncycastle.asn1.ASN1Object;
import lib.org.bouncycastle.asn1.ASN1OctetString;
import lib.org.bouncycastle.asn1.DEROctetString;
import lib.org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
import lib.org.bouncycastle.asn1.cms.KeyTransRecipientInfo;
import lib.org.bouncycastle.asn1.cms.RecipientIdentifier;
import lib.org.bouncycastle.asn1.cms.RecipientInfo;
import lib.org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import lib.org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import lib.org.bouncycastle.asn1.x509.TBSCertificateStructure;


class KeyTransRecipientInfoGenerator
    implements RecipientInfoGenerator
{
    // TODO Pass recipId, keyEncAlg instead?
    private TBSCertificateStructure recipientTBSCert;
    private PublicKey recipientPublicKey;
    private ASN1OctetString subjectKeyIdentifier;

    // Derived fields
    private SubjectPublicKeyInfo info;

    KeyTransRecipientInfoGenerator()
    {
    }

    void setRecipientCert(X509Certificate recipientCert)
    {
        try
        {
            this.recipientTBSCert = CMSUtils.getTBSCertificateStructure(recipientCert);
        }
        catch (CertificateEncodingException e)
        {
            throw new IllegalArgumentException(
                    "can't extract TBS structure from this cert");
        }

        this.recipientPublicKey = recipientCert.getPublicKey();
        this.info = recipientTBSCert.getSubjectPublicKeyInfo();
    }

    void setRecipientPublicKey(PublicKey recipientPublicKey)
    {
        this.recipientPublicKey = recipientPublicKey;

        try
        {
            info = SubjectPublicKeyInfo.getInstance(ASN1Object
                    .fromByteArray(recipientPublicKey.getEncoded()));
        }
        catch (IOException e)
        {
            throw new IllegalArgumentException(
                    "can't extract key algorithm from this key");
        }
    }

    void setSubjectKeyIdentifier(ASN1OctetString subjectKeyIdentifier)
    {
        this.subjectKeyIdentifier = subjectKeyIdentifier;
    }

    public RecipientInfo generate(SecretKey key, SecureRandom random,
            Provider prov) throws GeneralSecurityException
    {
        AlgorithmIdentifier keyEncAlg = info.getAlgorithmId();

        ASN1OctetString encKey;

        Cipher keyCipher = CMSEnvelopedHelper.INSTANCE.createAsymmetricCipher(
                keyEncAlg.getObjectId().getId(), prov);
        try
        {
            keyCipher.init(Cipher.WRAP_MODE, recipientPublicKey, random);

            encKey = new DEROctetString(keyCipher.wrap(key));
        }
        catch (GeneralSecurityException e) // some providers do not support
        // wrap
        {
            keyCipher.init(Cipher.ENCRYPT_MODE, recipientPublicKey, random);

            encKey = new DEROctetString(keyCipher.doFinal(key.getEncoded()));
        }
        catch (IllegalStateException e) // some providers do not support wrap
        {
            keyCipher.init(Cipher.ENCRYPT_MODE, recipientPublicKey, random);

            encKey = new DEROctetString(keyCipher.doFinal(key.getEncoded()));
        }
        catch (UnsupportedOperationException e) // some providers do not
        // support wrap
        {
            keyCipher.init(Cipher.ENCRYPT_MODE, recipientPublicKey, random);

            encKey = new DEROctetString(keyCipher.doFinal(key.getEncoded()));
        }

        RecipientIdentifier recipId;
        if (recipientTBSCert != null)
        {
            IssuerAndSerialNumber issuerAndSerial = new IssuerAndSerialNumber(
                    recipientTBSCert.getIssuer(), recipientTBSCert
                            .getSerialNumber().getValue());
            recipId = new RecipientIdentifier(issuerAndSerial);
        }
        else
        {
            recipId = new RecipientIdentifier(subjectKeyIdentifier);
        }

        return new RecipientInfo(new KeyTransRecipientInfo(recipId, keyEncAlg,
                encKey));
    }
}

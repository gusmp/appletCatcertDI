package lib.org.bouncycastle.cms;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.List;

import javax.crypto.Cipher;

import lib.org.bouncycastle.asn1.ASN1Encodable;
import lib.org.bouncycastle.asn1.ASN1EncodableVector;
import lib.org.bouncycastle.asn1.ASN1InputStream;
import lib.org.bouncycastle.asn1.ASN1Null;
import lib.org.bouncycastle.asn1.ASN1OctetString;
import lib.org.bouncycastle.asn1.ASN1Sequence;
import lib.org.bouncycastle.asn1.ASN1Set;
import lib.org.bouncycastle.asn1.DEREncodable;
import lib.org.bouncycastle.asn1.DERObject;
import lib.org.bouncycastle.asn1.DERObjectIdentifier;
import lib.org.bouncycastle.asn1.DERSet;
import lib.org.bouncycastle.asn1.DERTags;
import lib.org.bouncycastle.asn1.cms.Attribute;
import lib.org.bouncycastle.asn1.cms.AttributeTable;
import lib.org.bouncycastle.asn1.cms.CMSAttributes;
import lib.org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
import lib.org.bouncycastle.asn1.cms.SignerIdentifier;
import lib.org.bouncycastle.asn1.cms.SignerInfo;
import lib.org.bouncycastle.asn1.cms.Time;
import lib.org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import lib.org.bouncycastle.asn1.x509.DigestInfo;
import lib.org.bouncycastle.util.Arrays;


/**
 * an expanded SignerInfo block from a CMS Signed message
 */
public class SignerInformation
{
    private SignerId                sid;
    private SignerInfo              info;
    private AlgorithmIdentifier     digestAlgorithm;
    private AlgorithmIdentifier     encryptionAlgorithm;
    private final ASN1Set           signedAttributeSet;
    private final ASN1Set           unsignedAttributeSet;
    private CMSProcessable          content;
    private byte[]                  signature;
    private DERObjectIdentifier     contentType;
    private DigestCalculator        digestCalculator;
    private byte[]                  resultDigest;

    // Derived
    private AttributeTable          signedAttributeValues;
    private AttributeTable          unsignedAttributeValues;

    SignerInformation(
        SignerInfo          info,
        DERObjectIdentifier contentType,
        CMSProcessable      content,
        DigestCalculator digestCalculator)
    {
        this.info = info;
        this.sid = new SignerId();
        this.contentType = contentType;

        try
        {
            SignerIdentifier   s = info.getSID();

            if (s.isTagged())
            {
                ASN1OctetString octs = ASN1OctetString.getInstance(s.getId());

                sid.setSubjectKeyIdentifier(octs.getEncoded());
            }
            else
            {
                IssuerAndSerialNumber   iAnds = IssuerAndSerialNumber.getInstance(s.getId());

                sid.setIssuer(iAnds.getName().getEncoded());
                sid.setSerialNumber(iAnds.getSerialNumber().getValue());
            }
        }
        catch (IOException e)
        {
            throw new IllegalArgumentException("invalid sid in SignerInfo");
        }

        this.digestAlgorithm = info.getDigestAlgorithm();
        this.signedAttributeSet = info.getAuthenticatedAttributes();
        this.unsignedAttributeSet = info.getUnauthenticatedAttributes();
        this.encryptionAlgorithm = info.getDigestEncryptionAlgorithm();
        this.signature = info.getEncryptedDigest().getOctets();

        this.content = content;
        this.digestCalculator = digestCalculator;
    }

    private byte[] encodeObj(
        DEREncodable    obj)
        throws IOException
    {
        if (obj != null)
        {
            return obj.getDERObject().getEncoded();
        }

        return null;
    }

    public SignerId getSID()
    {
        return sid;
    }

    /**
     * return the version number for this objects underlying SignerInfo structure.
     */
    public int getVersion()
    {
        return info.getVersion().getValue().intValue();
    }

    public AlgorithmIdentifier getDigestAlgorithmID()
    {
        return digestAlgorithm;
    }

    /**
     * return the object identifier for the signature.
     */
    public String getDigestAlgOID()
    {
        return digestAlgorithm.getObjectId().getId();
    }

    /**
     * return the signature parameters, or null if there aren't any.
     */
    public byte[] getDigestAlgParams()
    {
        try
        {
            return encodeObj(digestAlgorithm.getParameters());
        }
        catch (Exception e)
        {
            throw new RuntimeException("exception getting digest parameters " + e);
        }
    }

    /**
     * return the content digest that was calculated during verification.
     */
    public byte[] getContentDigest()
    {
        if (resultDigest == null)
        {
            throw new IllegalStateException("method can only be called after verify.");
        }
        
        return (byte[])resultDigest.clone();
    }
    
    /**
     * return the object identifier for the signature.
     */
    public String getEncryptionAlgOID()
    {
        return encryptionAlgorithm.getObjectId().getId();
    }

    /**
     * return the signature/encryption algorithm parameters, or null if
     * there aren't any.
     */
    public byte[] getEncryptionAlgParams()
    {
        try
        {
            return encodeObj(encryptionAlgorithm.getParameters());
        }
        catch (Exception e)
        {
            throw new RuntimeException("exception getting encryption parameters " + e);
        }
    }  

    /**
     * return a table of the signed attributes - indexed by
     * the OID of the attribute.
     */
    public AttributeTable getSignedAttributes()
    {
        if (signedAttributeSet != null && signedAttributeValues == null)
        {
            signedAttributeValues = new AttributeTable(signedAttributeSet);
        }

        return signedAttributeValues;
    }

    /**
     * return a table of the unsigned attributes indexed by
     * the OID of the attribute.
     */
    public AttributeTable getUnsignedAttributes()
    {
        if (unsignedAttributeSet != null && unsignedAttributeValues == null)
        {
            unsignedAttributeValues = new AttributeTable(unsignedAttributeSet);
        }

        return unsignedAttributeValues;
    }

    /**
     * return the encoded signature
     */
    public byte[] getSignature()
    {
        return (byte[])signature.clone();
    }

    /**
     * Return a SignerInformationStore containing the counter signatures attached to this
     * signer. If no counter signatures are present an empty store is returned.
     */
    public SignerInformationStore getCounterSignatures()
    {
        // TODO There are several checks implied by the RFC3852 comments that are missing

        /*
        The countersignature attribute MUST be an unsigned attribute; it MUST
        NOT be a signed attribute, an authenticated attribute, an
        unauthenticated attribute, or an unprotected attribute.
        */        
        AttributeTable unsignedAttributeTable = getUnsignedAttributes();
        if (unsignedAttributeTable == null)
        {
            return new SignerInformationStore(new ArrayList(0));
        }

        List counterSignatures = new ArrayList();

        /*
        The UnsignedAttributes syntax is defined as a SET OF Attributes.  The
        UnsignedAttributes in a signerInfo may include multiple instances of
        the countersignature attribute.
        */
        ASN1EncodableVector allCSAttrs = unsignedAttributeTable.getAll(CMSAttributes.counterSignature);

        for (int i = 0; i < allCSAttrs.size(); ++i)
        {
            Attribute counterSignatureAttribute = (Attribute)allCSAttrs.get(i);            

            /*
            A countersignature attribute can have multiple attribute values.  The
            syntax is defined as a SET OF AttributeValue, and there MUST be one
            or more instances of AttributeValue present.
            */
            ASN1Set values = counterSignatureAttribute.getAttrValues();
            if (values.size() < 1)
            {
                // TODO Throw an appropriate exception?
            }

            for (Enumeration en = values.getObjects(); en.hasMoreElements();)
            {
                /*
                Countersignature values have the same meaning as SignerInfo values
                for ordinary signatures, except that:

                   1. The signedAttributes field MUST NOT contain a content-type
                      attribute; there is no content type for countersignatures.

                   2. The signedAttributes field MUST contain a message-digest
                      attribute if it contains any other attributes.

                   3. The input to the message-digesting process is the contents
                      octets of the DER encoding of the signatureValue field of the
                      SignerInfo value with which the attribute is associated.
                */
                SignerInfo si = SignerInfo.getInstance(en.nextElement());

                String          digestName = CMSSignedHelper.INSTANCE.getDigestAlgName(si.getDigestAlgorithm().getObjectId().getId());
                
                counterSignatures.add(new SignerInformation(si, CMSAttributes.counterSignature, null, new CounterSignatureDigestCalculator(digestName, null, getSignature())));
            }
        }

        return new SignerInformationStore(counterSignatures);
    }
    
    /**
     * return the DER encoding of the signed attributes.
     * @throws IOException if an encoding error occurs.
     */
    public byte[] getEncodedSignedAttributes()
        throws IOException
    {
        if (signedAttributeSet != null)
        {
            return signedAttributeSet.getEncoded(ASN1Encodable.DER);
        }

        return null;
    }
    
    private boolean doVerify(
        PublicKey       key,
        Provider        sigProvider)
        throws CMSException, NoSuchAlgorithmException
    {
        String          digestName = CMSSignedHelper.INSTANCE.getDigestAlgName(this.getDigestAlgOID());
        String          signatureName = digestName + "with" + CMSSignedHelper.INSTANCE.getEncryptionAlgName(this.getEncryptionAlgOID());
        Signature       sig = CMSSignedHelper.INSTANCE.getSignatureInstance(signatureName, sigProvider);
        MessageDigest   digest = CMSSignedHelper.INSTANCE.getDigestInstance(digestName, sigProvider); 

        // TODO [BJA-109] Note: PSSParameterSpec requires JDK1.4+ 
/*
        try
        {
            DERObjectIdentifier sigAlgOID = encryptionAlgorithm.getObjectId();
            DEREncodable sigParams = this.encryptionAlgorithm.getParameters();
            if (sigAlgOID.equals(PKCSObjectIdentifiers.id_RSASSA_PSS))
            {
                // RFC 4056
                // When the id-RSASSA-PSS algorithm identifier is used for a signature,
                // the AlgorithmIdentifier parameters field MUST contain RSASSA-PSS-params.
                if (sigParams == null)
                {
                    throw new CMSException(
                        "RSASSA-PSS signature must specify algorithm parameters");
                }

                AlgorithmParameters params = AlgorithmParameters.getInstance(
                    sigAlgOID.getId(), sig.getProvider().getName());
                params.init(sigParams.getDERObject().getEncoded(), "ASN.1");

                PSSParameterSpec spec = (PSSParameterSpec)params.getParameterSpec(PSSParameterSpec.class);
                sig.setParameter(spec);
            }
            else
            {
                // TODO Are there other signature algorithms that provide parameters?
                if (sigParams != null)
                {
                    throw new CMSException("unrecognised signature parameters provided");
                }
            }
        }
        catch (IOException e)
        {
            throw new CMSException("error encoding signature parameters.", e);
        }
        catch (InvalidAlgorithmParameterException e)
        {
            throw new CMSException("error setting signature parameters.", e);
        }
        catch (InvalidParameterSpecException e)
        {
            throw new CMSException("error processing signature parameters.", e);
        }
*/

        try
        {
            if (digestCalculator != null)
            {
                resultDigest = digestCalculator.getDigest();
            }
            else
            {
                if (content != null)
                {
                    content.write(new CMSSignedGenerator.DigOutputStream(digest));
                }
                else if (signedAttributeSet == null)
                {
                    // TODO Get rid of this exception and just treat content==null as empty not missing?
                    throw new CMSException("data not encapsulated in signature - use detached constructor.");
                }

                resultDigest = digest.digest();
            }
        }
        catch (IOException e)
        {
            throw new CMSException("can't process mime object to create signature.", e);
        }

        // TODO Shouldn't be using attribute OID as contentType (should be null)
        boolean isCounterSignature = contentType.equals(
            CMSAttributes.counterSignature);

        // RFC 3852 11.1 Check the content-type attribute is correct
        {
            DERObject validContentType = getSingleValuedSignedAttribute(
                CMSAttributes.contentType, "content-type");
            if (validContentType == null)
            {
                if (!isCounterSignature && signedAttributeSet != null)
                {
                    throw new CMSException("The content-type attribute type MUST be present whenever signed attributes are present in signed-data");
                }
            }
            else
            {
                if (isCounterSignature)
                {
                    throw new CMSException("[For counter signatures,] the signedAttributes field MUST NOT contain a content-type attribute");
                }
    
                if (!(validContentType instanceof DERObjectIdentifier))
                {
                    throw new CMSException("content-type attribute value not of ASN.1 type 'OBJECT IDENTIFIER'");
                }
    
                DERObjectIdentifier signedContentType = (DERObjectIdentifier)validContentType;
    
                if (!signedContentType.equals(contentType))
                {
                    throw new CMSException("content-type attribute value does not match eContentType");
                }
            }
        }

        // RFC 3852 11.2 Check the message-digest attribute is correct
        {
            DERObject validMessageDigest = getSingleValuedSignedAttribute(
                CMSAttributes.messageDigest, "message-digest");
            if (validMessageDigest == null)
            {
                if (signedAttributeSet != null)
                {
                    throw new CMSException("the message-digest signed attribute type MUST be present when there are any signed attributes present");
                }
            }
            else
            {
                if (!(validMessageDigest instanceof ASN1OctetString))
                {
                    throw new CMSException("message-digest attribute value not of ASN.1 type 'OCTET STRING'");
                }
    
                ASN1OctetString signedMessageDigest = (ASN1OctetString)validMessageDigest;
    
                if (!Arrays.constantTimeAreEqual(resultDigest, signedMessageDigest.getOctets()))
                {
                    throw new CMSException("message-digest attribute value does not match calculated value");
                }
            }
        }

        // RFC 3852 11.4 Validate countersignature attribute(s)
        {
            AttributeTable signedAttrTable = this.getSignedAttributes();
            if (signedAttrTable != null
                && signedAttrTable.getAll(CMSAttributes.counterSignature).size() > 0)
            {
                throw new CMSException("A countersignature attribute MUST NOT be a signed attribute");
            }

            AttributeTable unsignedAttrTable = this.getUnsignedAttributes();
            if (unsignedAttrTable != null)
            {
                ASN1EncodableVector csAttrs = unsignedAttrTable.getAll(CMSAttributes.counterSignature);
                for (int i = 0; i < csAttrs.size(); ++i)
                {
                    Attribute csAttr = (Attribute)csAttrs.get(i);            
                    if (csAttr.getAttrValues().size() < 1)
                    {
                        throw new CMSException("A countersignature attribute MUST contain at least one AttributeValue");
                    }

                    // Note: We don't recursively validate the countersignature value
                }
            }
        }

        try
        {
            sig.initVerify(key);

            if (signedAttributeSet == null)
            {
                if (digestCalculator != null)
                {
                    // need to decrypt signature and check message bytes
                    return verifyDigest(resultDigest, key, this.getSignature(), sigProvider);
                }
                else if (content != null)
                {
                    // TODO Use raw signature of the hash value instead
                    content.write(new CMSSignedGenerator.SigOutputStream(sig));
                }
            }
            else
            {
                sig.update(this.getEncodedSignedAttributes());
            }

            return sig.verify(this.getSignature());
        }
        catch (InvalidKeyException e)
        {
            throw new CMSException("key not appropriate to signature in message.", e);
        }
        catch (IOException e)
        {
            throw new CMSException("can't process mime object to create signature.", e);
        }
        catch (SignatureException e)
        {
            throw new CMSException("invalid signature format in message: " + e.getMessage(), e);
        }
    }

    private boolean isNull(
        DEREncodable    o)
    {
        return (o instanceof ASN1Null) || (o == null);
    }
    
    private DigestInfo derDecode(
        byte[]  encoding)
        throws IOException, CMSException
    {
        if (encoding[0] != (DERTags.CONSTRUCTED | DERTags.SEQUENCE))
        {
            throw new IOException("not a digest info object");
        }
        
        ASN1InputStream         aIn = new ASN1InputStream(encoding);

        DigestInfo digInfo = new DigestInfo((ASN1Sequence)aIn.readObject());

        // length check to avoid Bleichenbacher vulnerability

        if (digInfo.getEncoded().length != encoding.length)
        {
            throw new CMSException("malformed RSA signature");
        }

        return digInfo;
    }
    
    private boolean verifyDigest(
        byte[]    digest, 
        PublicKey key,
        byte[]    signature,
        Provider  sigProvider)
        throws NoSuchAlgorithmException, CMSException
    {
        String algorithm = CMSSignedHelper.INSTANCE.getEncryptionAlgName(this.getEncryptionAlgOID());
        
        try
        {
            if (algorithm.equals("RSA"))
            {
                Cipher c = CMSEnvelopedHelper.INSTANCE.getCipherInstance("RSA/ECB/PKCS1Padding", sigProvider);

                c.init(Cipher.DECRYPT_MODE, key);
                
                DigestInfo digInfo = derDecode(c.doFinal(signature));

                if (!digInfo.getAlgorithmId().getObjectId().equals(digestAlgorithm.getObjectId()))
                {
                    return false;
                }
             
                if (!isNull(digInfo.getAlgorithmId().getParameters()))
                {
                    return false;
                }

                byte[]  sigHash = digInfo.getDigest();

                return Arrays.constantTimeAreEqual(digest, sigHash);
            }
            else if (algorithm.equals("DSA"))
            {
                Signature sig = CMSSignedHelper.INSTANCE.getSignatureInstance("NONEwithDSA", sigProvider);

                sig.initVerify(key);
                
                sig.update(digest);
                
                return sig.verify(signature);
            }
            else
            {
                throw new CMSException("algorithm: " + algorithm + " not supported in base signatures.");
            }
        }
        catch (GeneralSecurityException e)
        {
            throw new CMSException("Exception processing signature: " + e, e);
        }
        catch (IOException e)
        {
            throw new CMSException("Exception decoding signature: " + e, e);
        }
    }

    /**
     * verify that the given public key successfully handles and confirms the
     * signature associated with this signer.
     */
    public boolean verify(
        PublicKey   key,
        String      sigProvider)
        throws NoSuchAlgorithmException, NoSuchProviderException, CMSException
    {
        return verify(key, CMSUtils.getProvider(sigProvider));
    }

    /**
     * verify that the given public key successfully handles and confirms the
     * signature associated with this signer.
     */
    public boolean verify(
        PublicKey   key,
        Provider    sigProvider)
        throws NoSuchAlgorithmException, NoSuchProviderException, CMSException
    {
        // Optional, but still need to validate if present
        getSigningTime();

        return doVerify(key, sigProvider);
    }

    /**
     * verify that the given certificate successfully handles and confirms
     * the signature associated with this signer and, if a signingTime
     * attribute is available, that the certificate was valid at the time the
     * signature was generated.
     */
    public boolean verify(
        X509Certificate cert,
        String          sigProvider)
        throws NoSuchAlgorithmException, NoSuchProviderException,
            CertificateExpiredException, CertificateNotYetValidException,
            CMSException
    {
        return verify(cert, CMSUtils.getProvider(sigProvider));
    }

    /**
     * verify that the given certificate successfully handles and confirms
     * the signature associated with this signer and, if a signingTime
     * attribute is available, that the certificate was valid at the time the
     * signature was generated.
     */
    public boolean verify(
        X509Certificate cert,
        Provider        sigProvider)
        throws NoSuchAlgorithmException,
            CertificateExpiredException, CertificateNotYetValidException,
            CMSException
    {
        Time signingTime = getSigningTime();
        if (signingTime != null)
        {
            cert.checkValidity(signingTime.getDate());
        }

        return doVerify(cert.getPublicKey(), sigProvider); 
    }
    
    /**
     * Return the base ASN.1 CMS structure that this object contains.
     * 
     * @return an object containing a CMS SignerInfo structure.
     */
    public SignerInfo toSignerInfo()
    {
        return info;
    }

    private DERObject getSingleValuedSignedAttribute(
        DERObjectIdentifier attrOID, String printableName)
        throws CMSException
    {
        AttributeTable unsignedAttrTable = this.getUnsignedAttributes();
        if (unsignedAttrTable != null
            && unsignedAttrTable.getAll(attrOID).size() > 0)
        {
            throw new CMSException("The " + printableName
                + " attribute MUST NOT be an unsigned attribute");
        }

        AttributeTable signedAttrTable = this.getSignedAttributes();
        if (signedAttrTable == null)
        {
            return null;
        }

        ASN1EncodableVector v = signedAttrTable.getAll(attrOID);
        switch (v.size())
        {
            case 0:
                return null;
            case 1:
            {
                Attribute t = (Attribute)v.get(0);
                ASN1Set attrValues = t.getAttrValues();
                if (attrValues.size() != 1)
                {
                    throw new CMSException("A " + printableName
                        + " attribute MUST have a single attribute value");
                }

                return attrValues.getObjectAt(0).getDERObject();
            }
            default:
                throw new CMSException("The SignedAttributes in a signerInfo MUST NOT include multiple instances of the "
                    + printableName + " attribute");
        }
    }

    private Time getSigningTime() throws CMSException
    {
        DERObject validSigningTime = getSingleValuedSignedAttribute(
            CMSAttributes.signingTime, "signing-time");

        if (validSigningTime == null)
        {
            return null;
        }

        try
        {
            return Time.getInstance(validSigningTime);
        }
        catch (IllegalArgumentException e)
        {
            throw new CMSException("signing-time attribute value not a valid 'Time' structure");
        }
    }

    /**
     * Return a signer information object with the passed in unsigned
     * attributes replacing the ones that are current associated with
     * the object passed in.
     * 
     * @param signerInformation the signerInfo to be used as the basis.
     * @param unsignedAttributes the unsigned attributes to add.
     * @return a copy of the original SignerInformationObject with the changed attributes.
     */
    public static SignerInformation replaceUnsignedAttributes(
        SignerInformation   signerInformation,
        AttributeTable      unsignedAttributes)
    {
        SignerInfo  sInfo = signerInformation.info;
        ASN1Set     unsignedAttr = null;
        
        if (unsignedAttributes != null)
        {
            unsignedAttr = new DERSet(unsignedAttributes.toASN1EncodableVector());
        }
        
        return new SignerInformation(
                new SignerInfo(sInfo.getSID(), sInfo.getDigestAlgorithm(),
                    sInfo.getAuthenticatedAttributes(), sInfo.getDigestEncryptionAlgorithm(), sInfo.getEncryptedDigest(), unsignedAttr),
                    signerInformation.contentType, signerInformation.content, null);
    }

    /**
     * Return a signer information object with passed in SignerInformationStore representing counter
     * signatures attached as an unsigned attribute.
     *
     * @param signerInformation the signerInfo to be used as the basis.
     * @param counterSigners signer info objects carrying counter signature.
     * @return a copy of the original SignerInformationObject with the changed attributes.
     */
    public static SignerInformation addCounterSigners(
        SignerInformation        signerInformation,
        SignerInformationStore   counterSigners)
    {
        // TODO Perform checks from RFC 3852 11.4

        SignerInfo          sInfo = signerInformation.info;
        AttributeTable      unsignedAttr = signerInformation.getUnsignedAttributes();
        ASN1EncodableVector v;

        if (unsignedAttr != null)
        {
            v = unsignedAttr.toASN1EncodableVector();
        }
        else
        {
            v = new ASN1EncodableVector();
        }

        ASN1EncodableVector sigs = new ASN1EncodableVector();

        for (Iterator it = counterSigners.getSigners().iterator(); it.hasNext();)
        {
            sigs.add(((SignerInformation)it.next()).toSignerInfo());
        }

        v.add(new Attribute(CMSAttributes.counterSignature, new DERSet(sigs)));

        return new SignerInformation(
                new SignerInfo(sInfo.getSID(), sInfo.getDigestAlgorithm(),
                    sInfo.getAuthenticatedAttributes(), sInfo.getDigestEncryptionAlgorithm(), sInfo.getEncryptedDigest(), new DERSet(v)),
                    signerInformation.contentType, signerInformation.content, null);
    }
}
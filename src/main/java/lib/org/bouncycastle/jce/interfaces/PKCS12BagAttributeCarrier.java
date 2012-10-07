package lib.org.bouncycastle.jce.interfaces;

import java.util.Enumeration;

import lib.org.bouncycastle.asn1.DEREncodable;
import lib.org.bouncycastle.asn1.DERObjectIdentifier;


/**
 * allow us to set attributes on objects that can go into a PKCS12 store.
 */
public interface PKCS12BagAttributeCarrier
{
    void setBagAttribute(
        DERObjectIdentifier oid,
        DEREncodable        attribute);

    DEREncodable getBagAttribute(
        DERObjectIdentifier oid);

    Enumeration getBagAttributeKeys();
}

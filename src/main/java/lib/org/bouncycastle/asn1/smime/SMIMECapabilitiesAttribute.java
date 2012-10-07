package lib.org.bouncycastle.asn1.smime;

import lib.org.bouncycastle.asn1.DERSequence;
import lib.org.bouncycastle.asn1.DERSet;
import lib.org.bouncycastle.asn1.cms.Attribute;

public class SMIMECapabilitiesAttribute
    extends Attribute
{
    public SMIMECapabilitiesAttribute(
        SMIMECapabilityVector capabilities)
    {
        super(SMIMEAttributes.smimeCapabilities,
                new DERSet(new DERSequence(capabilities.toDEREncodableVector())));
    }
}

package eu.europa.esig.dss.xades.signature.prettyprint;

import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.signature.XAdESLevelBEnvelopedWithKeyInfoReferenceTest;

public class XAdESLevelBEnvelopedPrettyPrintTest extends XAdESLevelBEnvelopedWithKeyInfoReferenceTest {

	@Override
	protected XAdESSignatureParameters getSignatureParameters() {
		XAdESSignatureParameters signatureParameters = super.getSignatureParameters();
		signatureParameters.setPrettyPrint(true);
		return signatureParameters;
	}

}

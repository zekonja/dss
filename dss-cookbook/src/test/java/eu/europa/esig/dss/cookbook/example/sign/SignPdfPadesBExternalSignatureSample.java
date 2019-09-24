/**
 * Krunoslav Hrnjak

 * krunoslav@yottabyate.hr
 */

package hr.ccr.sign;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Scanner;

import javax.xml.bind.DatatypeConverter;

import org.junit.Test;

import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.SignatureAlgorithm;
import eu.europa.esig.dss.cookbook.example.CookbookTools;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.SignatureTokenConnection;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.x509.CertificateToken;

/**
 * How to sign PDF Document with PAdES-BASELINE-B using external signature produced by smart card
 * 
 * Certificate and signature values are hard coded. Used for illustration purpose.
 * 
 * 
 */



public class SignPdfPadesBExternalSignatureSample extends CookbookTools {

	@Test
	public void signPAdESBaselineB() throws Exception {

		// GET document to be signed -
		// Return DSSDocument toSignDocument
		preparePdfDoc();

			// Preparing parameters for the PAdES signature
			PAdESSignatureParameters parameters = new PAdESSignatureParameters();
			// We choose the level of the signature (-B, -T, -LT, -LTA).
			parameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);
			// We set the digest algorithm to use with the signature algorithm. You must use the
			// same parameter when you invoke the method sign on the token. The default value is
			// SHA256
			parameters.setDigestAlgorithm(DigestAlgorithm.SHA256);
			
			//Load certificate "MIIGUzCCBDugAwIBA...gRTh8hjVI3etVRNBbf6fvViz";
			String certicifateBase64 = "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";
			byte[] certicifateBytes = Base64.getDecoder().decode(certicifateBase64);
			InputStream certicifateStream = new ByteArrayInputStream(certicifateBytes);
			CertificateFactory fact = CertificateFactory.getInstance("X.509");
			X509Certificate certificate = (X509Certificate) fact.generateCertificate(certicifateStream);
			CertificateToken certificateToken = new CertificateToken(certificate);
			
			// We set the signing certificate
			parameters.setSigningCertificate(certificateToken);
			
			List<CertificateToken> certificateChain = null;
			// We set the certificate chain
			parameters.setCertificateChain(certificateChain );		
			
			//Fix the date to get the same message digest every time 
	        SimpleDateFormat formatter = new SimpleDateFormat("dd.MM.yyyy.");
	        String dateInString = "01.01.2019.";		
			Date signingDate = formatter.parse(dateInString);
			parameters.bLevel().setSigningDate(signingDate);	


			// Create common certificate verifier
			CommonCertificateVerifier commonCertificateVerifier = new CommonCertificateVerifier();
			// Create PAdESService for signature
			PAdESService service = new PAdESService(commonCertificateVerifier);

			// Get the SignedInfo segment that need to be signed and calculate message digest
			ToBeSigned dataToSign = service.getDataToSign(toSignDocument, parameters);
			byte[] dataToSignBytes = dataToSign.getBytes();			
			byte[] pdfMessageDigest = DSSUtils.digest(parameters.getDigestAlgorithm(), dataToSignBytes);
			String pdfMessageDigestHex = DatatypeConverter.printHexBinary(pdfMessageDigest);				
			System.out.println("Message digest hex.");
			//It should correspond to "686BBA0CC07E7663A255C5A53A6D9649C409EDDC70A0EC37CCEE81593FCAF16B";
			System.out.println(pdfMessageDigestHex);			
			
			
			//Load the signature 
		    String signatureInHex = "3CE7A9C225C34DF3BBC8BFCEC14451E497B18E18957A979F1C8996419D5537F94A6C0602518FE9482D45ED4A912731EFE9DE5387B4D93A8A708213C2FA2A474F3A4AF24FAF9E1365B1771A90588469B446ECCF8F3AAC46D7A1E0ACB0E66D2509F175E6996B6F6E242A2B5B2EA4C304971E47F6D5B754D715D96805FEFF134D419A9972B9536590111EEB068479AD9B0092E41CCD18C2C1927004BF6BEEA98A0710B7DD1AECE8902B20810859AE45C7CE5F8DE66B189F3EED67D8070A819AED9C104C8CB255B0F94E7F1F8D2E3C8628D116E33ADC9D7BF6C58C8736B632E96C7D3217110DCDA7C71408DC583C0B486265548A5363836EA940753A0705963B668F";
			byte[] signatureBytes = DatatypeConverter.parseHexBinary(signatureInHex);			
			SignatureValue signatureValue = new SignatureValue(parameters.getSignatureAlgorithm(), signatureBytes);
			//Apply the signature to the document
			DSSDocument signedDocument = service.signDocument(toSignDocument, parameters, signatureValue);
			
			//Optional save and examine document
			//signedDocument.save("c:/hello-world-signed.pdf");


			testFinalDocument(signedDocument);
		}
	}
}

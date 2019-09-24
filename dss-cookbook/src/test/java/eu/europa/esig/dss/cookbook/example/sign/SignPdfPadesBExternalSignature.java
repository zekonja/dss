/**
 * Krunoslav Hrnjak
 * krunoslav@yottabyate.hr
 */

package eu.europa.esig.dss.cookbook.example.sign;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;
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
 * For testing purpose one can obtain certificate from smart card and sign hash using https://hwcrypto.github.io/demo/
 * 
 * First step is to get certificate. Press sign and abort signing after certificate is shown.
 * Second step is to start SignPdfPadesBTest test
 * Third step is to copy certificate as one line into command prompt
 * Forth step is to copy given hash into hwcrypto demo
 * Fifth step is to press sign() button
 * Select smart card certificate
 * Enter pin
 * Copy signature into command prompt
 * 
 */



public class SignPdfPadesBExternalSignature extends CookbookTools {

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
			System.out.println("Enter base 64 encoded certificate as a one line entry: ");
		    Scanner scanner = new Scanner(System.in);
			String certicifateBase64 = scanner.next().replace("\"", ""); 
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


			// Create common certificate verifier
			CommonCertificateVerifier commonCertificateVerifier = new CommonCertificateVerifier();
			// Create PAdESService for signature
			PAdESService service = new PAdESService(commonCertificateVerifier);

			// Get the SignedInfo segment that need to be signed and calculate message digest
			ToBeSigned dataToSign = service.getDataToSign(toSignDocument, parameters);
			byte[] dataToSignBytes = dataToSign.getBytes();			
			byte[] pdfMessageDigest = DSSUtils.digest(parameters.getDigestAlgorithm(), dataToSignBytes);
			String pdfMessageDigestHex = DatatypeConverter.printHexBinary(pdfMessageDigest);				
			System.out.println("Input message digest hex string into external signer!");
			System.out.println(pdfMessageDigestHex);			
			
			
			//Load the signature "7F07.....4511E"
		    scanner = new Scanner(System.in);
		    System.out.print("Enter signature in hex (as one line): ");
		    String signatureInHex = scanner.next().replace("\"", "");
			byte[] signatureBytes = DatatypeConverter.parseHexBinary(signatureInHex);			
			SignatureValue signatureValue = new SignatureValue(parameters.getSignatureAlgorithm(), signatureBytes);
			//Apply the signature to the document
			DSSDocument signedDocument = service.signDocument(toSignDocument, parameters, signatureValue);


			testFinalDocument(signedDocument);
		}
	}
}

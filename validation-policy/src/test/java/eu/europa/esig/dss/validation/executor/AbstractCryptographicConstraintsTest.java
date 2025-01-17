package eu.europa.esig.dss.validation.executor;

import static org.junit.Assert.assertNotNull;

import java.io.File;
import java.util.Iterator;
import java.util.List;

import eu.europa.esig.dss.detailedreport.DetailedReport;
import eu.europa.esig.dss.diagnostic.DiagnosticDataFacade;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDiagnosticData;
import eu.europa.esig.dss.policy.EtsiValidationPolicy;
import eu.europa.esig.dss.policy.ValidationPolicy;
import eu.europa.esig.dss.policy.ValidationPolicyFacade;
import eu.europa.esig.dss.policy.jaxb.Algo;
import eu.europa.esig.dss.policy.jaxb.AlgoExpirationDate;
import eu.europa.esig.dss.policy.jaxb.BasicSignatureConstraints;
import eu.europa.esig.dss.policy.jaxb.CertificateConstraints;
import eu.europa.esig.dss.policy.jaxb.ConstraintsParameters;
import eu.europa.esig.dss.policy.jaxb.CryptographicConstraint;
import eu.europa.esig.dss.policy.jaxb.RevocationConstraints;
import eu.europa.esig.dss.policy.jaxb.SignatureConstraints;
import eu.europa.esig.dss.policy.jaxb.TimestampConstraints;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.validation.reports.Reports;

public abstract class AbstractCryptographicConstraintsTest extends AbstractValidationExecutorTest {

	protected ConstraintsParameters constraintsParameters = null;
	protected DefaultSignatureProcessExecutor executor = null;
	protected ValidationPolicy validationPolicy = null;

	protected static final String ALGORITHM_DSA = "DSA";
	protected static final String ALGORITHM_RSA = "RSA";
	protected static final String ALGORITHM_RSA2048 = "RSA2048";
	protected static final String ALGORITHM_RSA4096 = "RSA4096";
	protected static final String ALGORITHM_SHA1 = "SHA1";
	protected static final String ALGORITHM_SHA256 = "SHA256";
	
	protected static final String BIT_SIZE_4096 = "4096";
	
	protected File validationPolicyFile = null;
	
	protected XmlDiagnosticData initializeExecutor(String diagnosticDataFile) throws Exception {

		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File(diagnosticDataFile));
		assertNotNull(diagnosticData);

		executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setCurrentTime(diagnosticData.getValidationDate());
		return diagnosticData;
	}

	protected ConstraintsParameters loadConstraintsParameters() throws Exception {
		ConstraintsParameters constraintsParameters = ValidationPolicyFacade.newFacade().unmarshall(validationPolicyFile);
		this.constraintsParameters = constraintsParameters;
		return constraintsParameters;
	}
	
	protected void setValidationPolicy(ConstraintsParameters constraintsParameters) {
		validationPolicy = new EtsiValidationPolicy(constraintsParameters);
	}
	
	protected Reports createReports() {
		executor.setValidationPolicy(validationPolicy);
		return executor.execute();
	}
	
	protected CryptographicConstraint getSignatureCryptographicConstraint(ConstraintsParameters constraintsParameters) {
		SignatureConstraints sigConstraint = constraintsParameters.getSignatureConstraints();
		return sigConstraint.getBasicSignatureConstraints().getCryptographic();
	}
	
	protected void setSignatureCryptographicConstraint(ConstraintsParameters constraintsParameters, CryptographicConstraint cryptographicConstraint) {
		SignatureConstraints sigConstraint = constraintsParameters.getSignatureConstraints();
		BasicSignatureConstraints basicSignatureConstraints = sigConstraint.getBasicSignatureConstraints();
		basicSignatureConstraints.setCryptographic(cryptographicConstraint);
		sigConstraint.setBasicSignatureConstraints(basicSignatureConstraints);
		constraintsParameters.setSignatureConstraints(sigConstraint);
	}
	
	protected CertificateConstraints getSigningCertificateConstraints(ConstraintsParameters constraintsParameters) {
		return constraintsParameters.getSignatureConstraints().getBasicSignatureConstraints().getSigningCertificate();
	}
	
	protected void setSigningCertificateConstraints(ConstraintsParameters constraintsParameters, CryptographicConstraint cryptographicConstraint) {
		SignatureConstraints signatureConstraints = constraintsParameters.getSignatureConstraints();
		BasicSignatureConstraints basicSignatureConstraints = signatureConstraints.getBasicSignatureConstraints();
		CertificateConstraints certificateConstraints = basicSignatureConstraints.getSigningCertificate();
		certificateConstraints.setCryptographic(cryptographicConstraint);
		basicSignatureConstraints.setSigningCertificate(certificateConstraints);
		signatureConstraints.setBasicSignatureConstraints(basicSignatureConstraints);
	}
	
	protected CertificateConstraints getCACertificateConstraints(ConstraintsParameters constraintsParameters) {
		return constraintsParameters.getSignatureConstraints().getBasicSignatureConstraints().getCACertificate();
	}
	
	protected void setCACertificateConstraints(ConstraintsParameters constraintsParameters, CryptographicConstraint cryptographicConstraint) {
		SignatureConstraints signatureConstraints = constraintsParameters.getSignatureConstraints();
		BasicSignatureConstraints basicSignatureConstraints = signatureConstraints.getBasicSignatureConstraints();
		CertificateConstraints certificateConstraints = basicSignatureConstraints.getCACertificate();
		certificateConstraints.setCryptographic(cryptographicConstraint);
		basicSignatureConstraints.setCACertificate(certificateConstraints);
		signatureConstraints.setBasicSignatureConstraints(basicSignatureConstraints);
	}
	
	protected CryptographicConstraint getRevocationCryptographicConstraint(ConstraintsParameters constraintsParameters) {
		RevocationConstraints revocationConstraints = constraintsParameters.getRevocation();
		return revocationConstraints.getBasicSignatureConstraints().getCryptographic();
	}
	
	protected RevocationConstraints setRevocationCryptographicConstraint(ConstraintsParameters constraintsParameters, CryptographicConstraint cryptographicConstraint) {
		RevocationConstraints revocationConstraints = constraintsParameters.getRevocation();
		BasicSignatureConstraints basicSignatureConstraints = revocationConstraints.getBasicSignatureConstraints();
		basicSignatureConstraints.setCryptographic(cryptographicConstraint);
		revocationConstraints.setBasicSignatureConstraints(basicSignatureConstraints);
		constraintsParameters.setRevocation(revocationConstraints);
		return revocationConstraints;
	}
	
	protected CryptographicConstraint getTimestampCryptographicConstraint(ConstraintsParameters constraintsParameters) {
		TimestampConstraints timestampConstraints = constraintsParameters.getTimestamp();
		return timestampConstraints.getBasicSignatureConstraints().getCryptographic();
	}
	
	protected TimestampConstraints setTimestampCryptographicConstraints(ConstraintsParameters constraintsParameters, CryptographicConstraint cryptographicConstraint) {
		TimestampConstraints timestampConstraints = constraintsParameters.getTimestamp();
		BasicSignatureConstraints basicSignatureConstraints = timestampConstraints.getBasicSignatureConstraints();
		basicSignatureConstraints.setCryptographic(cryptographicConstraint);
		timestampConstraints.setBasicSignatureConstraints(basicSignatureConstraints);
		constraintsParameters.setTimestamp(timestampConstraints);
		return timestampConstraints;
	}
	
	protected SimpleReport createSimpleReport() {
		Reports reports = createReports();
		return reports.getSimpleReport();
	}
	
	protected DetailedReport createDetailedReport() {
		Reports reports = createReports();
		return reports.getDetailedReport();
	}
	
	protected void setAlgoExpirationDate(CryptographicConstraint cryptographicConstraint, String algorithmName, String expirationDate) {
		
		AlgoExpirationDate algoExpirationDate = cryptographicConstraint.getAlgoExpirationDate();
		List<Algo> algorithms = algoExpirationDate.getAlgo();
		boolean listContainsAlgorithms = false;
		for (Algo algorithm : algorithms) {
			if (algorithm.getValue().equals(algorithmName)) {
				algorithm.setDate(expirationDate);
				listContainsAlgorithms = true;
			}
		}
		if (!listContainsAlgorithms) {
			Algo algo = new Algo();
			algo.setValue(algorithmName);
			algo.setDate(expirationDate);
			algorithms.add(algo);
		}
		
	}
	
	protected void removeAlgorithm(List<Algo> algorithms, String algorithmName) {
		Iterator<Algo> iterator = algorithms.iterator();
		while(iterator.hasNext()) {
			Algo algo = iterator.next();
			if (algo.getValue().equals(algorithmName)) {
				iterator.remove();
			}
		}
	}
	
	protected void setAlgorithmSize(List<Algo> algorithms, String algorithm, String size) {
		for (Algo algo : algorithms) {
			if (algo.getValue().equals(algorithm)) {
				algo.setSize(BIT_SIZE_4096);
				return;
			}
		}
	}

}

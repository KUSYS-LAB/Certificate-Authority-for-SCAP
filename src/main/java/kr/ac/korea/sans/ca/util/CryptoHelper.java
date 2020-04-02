package kr.ac.korea.sans.ca.util;

import kr.ac.korea.sans.ca.config.GlobalConfig;
import kr.ac.korea.sans.ca.constant.Constants;
import kr.ac.korea.sans.ca.dto.CrlDto;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.X509ExtensionUtils;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.FixedSecureRandom;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import java.io.*;
import java.math.BigInteger;
import java.nio.file.Files;
import java.security.*;
import java.security.cert.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.*;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.List;

@Component
public class CryptoHelper {
	
	private Logger logger = LoggerFactory.getLogger(CryptoHelper.class); 
	
	private static  CryptoHelper cryptoHelper = new CryptoHelper(); 

	
	public CryptoHelper() {
		
	}
	
	public static CryptoHelper getInstance() {
		return cryptoHelper;
	}

	@PostConstruct
	public void init() {
		Security.addProvider(new BouncyCastleProvider());
	}
	
	public X509Certificate getX509Certificate(
			PublicKey publicKey, X509Certificate caCert, PrivateKey caPrivateKey,
			String CN, String SN, String C, BigInteger serialNumber) throws Exception {
		X509Certificate x509cert = null;
			
		// this parameters should be programmable after all.
		// at this time, I assigned the arbitrary values for each parameter.
		// you should correct these values in valid after getting properties of parameters.
//		BigInteger serialNumber = new BigInteger("1");
		Calendar cal = Calendar.getInstance();
		Date notBefore = cal.getTime();
		cal.add(Calendar.YEAR, 1);
		Date notAfter = cal.getTime();
		X500Name subjectName = new X500Name("CN=" + CN + ",SN=" + SN + ",C=" + C);
		
		String signatureAlgorithm = GlobalConfig.getInstance().getCertConfig().getSignatureAlgorithm();
		String hashAlgorithm = GlobalConfig.getInstance().getCertConfig().getSignatureHashAlgorithm();
		String signatureSpec = hashAlgorithm + "with" + signatureAlgorithm.split(hashAlgorithm)[1];
//		ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256withECDSA").build(caPrivateKey);
		ContentSigner contentSigner = new JcaContentSignerBuilder(signatureSpec).build(caPrivateKey);
		
		DistributionPointName distributionPoint = new DistributionPointName(
				new GeneralNames(
						new GeneralName(GeneralName.uniformResourceIdentifier, Constants.CA_BASE_URL + Constants.CA_CRL_URL)));
		DistributionPoint[] distPoints = new DistributionPoint[1];
		distPoints[0] = new DistributionPoint(distributionPoint, null, null);
		
		X509v3CertificateBuilder cert = new JcaX509v3CertificateBuilder(
				caCert, serialNumber, notBefore, notAfter, subjectName, publicKey)
				.addExtension(Extension.subjectKeyIdentifier, false, this.createSubjectKeyId(publicKey))
				.addExtension(Extension.authorityKeyIdentifier, false, this.createAuthorityKeyId(caCert.getPublicKey()))
				.addExtension(Extension.basicConstraints, true, new BasicConstraints(true))
				.addExtension(Extension.cRLDistributionPoints, false, new CRLDistPoint(distPoints))
				.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature))
				.addExtension(Extension.extendedKeyUsage, true, new ExtendedKeyUsage(KeyPurposeId.id_kp_clientAuth));
		x509cert = new JcaX509CertificateConverter().getCertificate(cert.build(contentSigner));
//		this.writeToFile(new File("KeyPair/Cert.der"), x509cert.getEncoded());
		logger.info("successfully generated x509 certificate!");
		return x509cert;
	}
	
	
	public X509Certificate getSelfSignedX509Certificate(BigInteger serialNumber) throws Exception {
		X509Certificate x509cert = null;
		String cryptoType = GlobalConfig.getInstance().getCertConfig().getCryptoType();
		if (!new File("CA-KeyPair").exists()) new File("CA-KeyPair").mkdir();
		if (!new File("CA-KeyPair/CA-Cert.der").exists()) {
			if (!new File("CA-KeyPair/CA-PublicKey").exists() || !new File("CA-KeyPair/CA-PrivateKey").exists()) {
				KeyPair keyPair = null;
				if (cryptoType.equals("RSA")) keyPair = this.generateRsaKeyPair();
				else if (cryptoType.equals("EC")) keyPair = this.generateEcKeyPair();
//				KeyPair keyPair = this.generateEcKeyPair();
				this.writeToFile(new File("CA-KeyPair/CA-PublicKey"), keyPair.getPublic().getEncoded());
				this.writeToFile(new File("CA-KeyPair/CA-PrivateKey"), keyPair.getPrivate().getEncoded());
			}
			PublicKey publicKey = this.getPublic("CA-KeyPair/CA-PublicKey", cryptoType);
			PrivateKey privateKey = this.getPrivate("CA-KeyPair/CA-PrivateKey", cryptoType);
			
			// this parameters should be programmable after all.
			// at this time, I assigned the arbitrary values for each parameter.
			// you should correct these values in valid after getting properties of parameters.
			X500Name issuerX500Name = new X500Name("CN=" + Constants.CA_CN);
//			BigInteger serialNumber = new BigInteger("1");
			Calendar cal = Calendar.getInstance();
			Date notBefore = cal.getTime();
			cal.add(Calendar.YEAR, 1);
			Date notAfter = cal.getTime();
//			ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256withECDSA").build(privateKey);
			String signatureAlgorithm = GlobalConfig.getInstance().getCertConfig().getSignatureAlgorithm();
			String hashAlgorithm = GlobalConfig.getInstance().getCertConfig().getSignatureHashAlgorithm();
			String signatureSpec = hashAlgorithm + "with" + signatureAlgorithm.split(hashAlgorithm)[1];
			ContentSigner contentSigner = new JcaContentSignerBuilder(signatureSpec).build(privateKey);
			
			DistributionPointName distributionPoint = new DistributionPointName(
					new GeneralNames(
							new GeneralName(GeneralName.uniformResourceIdentifier, Constants.CA_BASE_URL + Constants.CA_CRL_URL)));
			DistributionPoint[] distPoints = new DistributionPoint[1];
			distPoints[0] = new DistributionPoint(distributionPoint, null, null);
			
			X509v3CertificateBuilder cert = new JcaX509v3CertificateBuilder(
					issuerX500Name, serialNumber, notBefore, notAfter, issuerX500Name, publicKey)
					.addExtension(Extension.subjectKeyIdentifier, false, this.createSubjectKeyId(publicKey))
					.addExtension(Extension.authorityKeyIdentifier, false, this.createAuthorityKeyId(publicKey))
					.addExtension(Extension.basicConstraints, true, new BasicConstraints(true))
					.addExtension(Extension.cRLDistributionPoints, false, new CRLDistPoint(distPoints))
					.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature))
					.addExtension(Extension.extendedKeyUsage, true, new ExtendedKeyUsage(KeyPurposeId.id_kp_serverAuth));
			x509cert = new JcaX509CertificateConverter().getCertificate(cert.build(contentSigner));
			this.writeToFile(new File("CA-KeyPair/CA-Cert.der"), x509cert.getEncoded());
			logger.info("successfully generated self-signed x509 certificate!");
		} else {
			CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
			x509cert = (X509Certificate) certFactory.generateCertificate(new FileInputStream(new File("CA-KeyPair/CA-Cert.der")));
		}
		
		logger.info("generated Self-signed X.509 certificate");
		
		return x509cert;
	}
	
	private SubjectKeyIdentifier createSubjectKeyId (PublicKey publicKey) throws OperatorCreationException {
		SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());
		DigestCalculator digCalc = new BcDigestCalculatorProvider().get(new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1));
		return new X509ExtensionUtils(digCalc).createSubjectKeyIdentifier(publicKeyInfo);
	}
	
	private AuthorityKeyIdentifier createAuthorityKeyId (PublicKey publicKey) throws OperatorCreationException {
		SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());
		DigestCalculator digCalc = new BcDigestCalculatorProvider().get(new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1));
		return new X509ExtensionUtils(digCalc).createAuthorityKeyIdentifier(publicKeyInfo);
	}
	
	private KeyPair generateEcKeyPair() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
//		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
//		keyPairGenerator.initialize(256);
//		KeyPair keyPair = keyPairGenerator.genKeyPair();
		Security.addProvider(new BouncyCastleProvider());
//    	ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("prime256v1");
		ECGenParameterSpec ecSpec = new ECGenParameterSpec("secp256r1");
    	SecureRandom random = new SecureRandom();
    	KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("ECDSA");
    	keyPairGenerator.initialize(ecSpec, random);
    	KeyPair keyPair = keyPairGenerator.generateKeyPair();
		return keyPair;
	}
	
	private KeyPair generateRsaKeyPair() throws NoSuchAlgorithmException {
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
		keyPairGenerator.initialize(2048);
		KeyPair keyPair = keyPairGenerator.genKeyPair();
		return keyPair;
	}
	
	private void writeToFile(File output, byte[] toWrite)
			throws IllegalBlockSizeException, BadPaddingException, IOException {
		FileOutputStream fos = new FileOutputStream(output);
		fos.write(toWrite);
		fos.flush();
		fos.close();
	}
	
	public PrivateKey getPrivate(String filename, String cryptoType) throws Exception {
		// cryptoType {RSA, EC}
		byte[] keyBytes = Files.readAllBytes(new File(filename).toPath());
		PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
		KeyFactory kf = KeyFactory.getInstance(cryptoType);
		return kf.generatePrivate(spec);
	}
	
	public PublicKey getPublic(String filename, String cryptoType) throws Exception {
		// cryptoType {RSA, EC}
		byte[] keyBytes = Files.readAllBytes(new File(filename).toPath());
		X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
		KeyFactory kf = KeyFactory.getInstance(cryptoType);
		return kf.generatePublic(spec);
	}
	
	public PublicKey restorePublicKeyFromPem(String pem) throws NoSuchAlgorithmException, InvalidKeySpecException, IOException {
		Reader reader = new StringReader(pem);
		SubjectPublicKeyInfo parser = (SubjectPublicKeyInfo) new PEMParser(reader).readObject();
		return new JcaPEMKeyConverter().getPublicKey(parser);
	}
	
	private X509CRL generateCrl(PrivateKey caPrivateKey, List<CrlDto> crlEntries) throws OperatorCreationException, CRLException, ParseException {
		Calendar cal = Calendar.getInstance();
		SimpleDateFormat formatter = new SimpleDateFormat(Constants.CA_DATE_FORMAT);
		X500Name issuer = new X500Name("CN=" + Constants.CA_CN);
		Date thisUpdate = cal.getTime();
		cal.setTime(thisUpdate);
		cal.add(Calendar.DATE, 10);
		Date nextUpdate = cal.getTime();
		
		X509v2CRLBuilder crlBuilder = new X509v2CRLBuilder(issuer, thisUpdate);
		crlBuilder.setNextUpdate(nextUpdate);
		for (CrlDto crlEntry : crlEntries) {
			BigInteger serialNumber = new BigInteger(crlEntry.getSerialNumber(), 16);
			Date revocationDate = formatter.parse(crlEntry.getRevokedDate());
			int reason = crlEntry.getReason();
			crlBuilder.addCRLEntry(serialNumber, revocationDate, reason);
		}
		
		String signatureAlgorithm = GlobalConfig.getInstance().getCertConfig().getSignatureAlgorithm();
		String hashAlgorithm = GlobalConfig.getInstance().getCertConfig().getSignatureHashAlgorithm();
		String signatureSpec = hashAlgorithm + "with" + signatureAlgorithm.split(hashAlgorithm)[1];
		
		ContentSigner crlSigner = new JcaContentSignerBuilder(signatureSpec).build(caPrivateKey);
		X509CRL crl = new JcaX509CRLConverter().getCRL(crlBuilder.build(crlSigner));
		return crl;
	}
	
	public X509CRL getCrl(PrivateKey caPrivateKey, String savePath, List<CrlDto> crlEntries) throws OperatorCreationException, CRLException, IllegalBlockSizeException, BadPaddingException, IOException, CertificateException, ParseException {
		X509CRL crl = null;
		
		if (!new File(savePath).exists()) {
			crl = this.generateCrl(caPrivateKey, crlEntries);
			this.writeToFile(new File(savePath), crl.getEncoded());
		} else {
			Calendar cal = Calendar.getInstance();
			CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
			crl = (X509CRL) certFactory.generateCRL(new FileInputStream(new File(savePath)));
			Date now = cal.getTime();
			
			int cmp = crl.getNextUpdate().compareTo(now);
			if (cmp < 0) {
				crl = this.generateCrl(caPrivateKey, crlEntries);
				this.writeToFile(new File(savePath), crl.getEncoded());
			}
		}
		
		return crl;
		
	}
	
	public HashMap<String, String> testEcdsa(String msg, String namedCurve, String prv, String kVal, String rVal, String sVal) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeySpecException, InvalidKeyException, SignatureException, NoSuchProviderException {
//		byte[] input = new BigInteger("5905238877c77421f73e43ee3da6f2d9e2ccad5fc942dcec0cbd25482935faaf416983fe165b1a045ee2bcd2e6dca3bdf46c4310a7461f9a37960ca672d3feb5473e253605fb1ddfd28065b53cb5858a8ad28175bf9bd386a5e471ea7a65c17cc934a9d791e91491eb3754d03799790fe2d308d16146d5c9b0d0debd97d79ce8", 16).toByteArray();
		byte[] input = new BigInteger(msg, 16).toByteArray();
		
		KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
//		ECGenParameterSpec kpgparams = new ECGenParameterSpec("secp256r1");
		ECGenParameterSpec kpgparams = new ECGenParameterSpec(namedCurve);
		kpg.initialize(kpgparams);
		java.security.spec.ECParameterSpec params = ((ECPublicKey) kpg.generateKeyPair().getPublic()).getParams();

		//Create the static private key W from the Test Vector
//		ECPrivateKeySpec static_privates = new ECPrivateKeySpec(new BigInteger("519b423d715f8b581f4fa8ee59f4771a5b44c8130b4e3eacca54a56dda72b464", 16), params);
		ECPrivateKeySpec static_privates = new ECPrivateKeySpec(new BigInteger(prv, 16), params);
		KeyFactory kf = KeyFactory.getInstance("EC");
		ECPrivateKey spriv = (ECPrivateKey) kf.generatePrivate(static_privates);
		
		Signature dsa = Signature.getInstance("SHA256withECDSA", "BC");
//		FixedSecureRandom k = new FixedSecureRandom(Hex.decode("94a1bbb14b906a61a280f245f9e93c7f3b4a6247824f5d33b9670787642a68de"));
		FixedSecureRandom k = new FixedSecureRandom(Hex.decode(kVal));
		dsa.initSign(spriv, k);
		dsa.update(input);
		byte[] output = dsa.sign();
		
		ASN1Sequence sequence = ASN1Sequence.getInstance(output);
		ASN1Integer r = (ASN1Integer) sequence.getObjectAt(0);
		ASN1Integer s = (ASN1Integer) sequence.getObjectAt(1);
		logger.info("msg: " + msg);
		logger.info("ncurve: " + namedCurve);
		logger.info("private key: " + prv);
		logger.info("k: " + kVal);
		logger.info("r(prd): " + r.getValue().toString(16));
		logger.info("s(prd): " + s.getValue().toString(16));
		logger.info("r(cor): " + rVal);
		logger.info("s(cor): " + sVal);
		HashMap<String, String> map = new HashMap<String, String>();
		map.put("msg", msg);
		map.put("ncurve", namedCurve);
		map.put("private-key", prv);
		map.put("k", kVal);
		map.put("r-get", r.getValue().toString(16));
		map.put("s-get", s.getValue().toString(16));
		map.put("r-cor", rVal);
		map.put("s-cor", sVal);
		map.put("signature", Hex.toHexString(output));
		return map;
	}
	
	public HashMap<String, String> testRsaPss(String msg, String nVal, String dVal, String sig) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, SignatureException, InvalidAlgorithmParameterException {
//		byte[] input = new BigInteger("5af283b1b76ab2a695d794c23b35ca7371fc779e92ebf589e304c7f923d8cf976304c19818fcd89d6f07c8d8e08bf371068bdf28ae6ee83b2e02328af8c0e2f96e528e16f852f1fc5455e4772e288a68f159ca6bdcf902b858a1f94789b3163823e2d0717ff56689eec7d0e54d93f520d96e1eb04515abc70ae90578ff38d31b", 16).toByteArray();
		byte[] input = new BigInteger(msg, 16).toByteArray();
//		KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
		KeyFactory kf = KeyFactory.getInstance("RSA");
//		RSAPrivateKeySpec static_privates = new RSAPrivateKeySpec(
//				new BigInteger("cea80475324c1dc8347827818da58bac069d3419c614a6ea1ac6a3b510dcd72cc516954905e9fef908d45e13006adf27d467a7d83c111d1a5df15ef293771aefb920032a5bb989f8e4f5e1b05093d3f130f984c07a772a3683f4dc6fb28a96815b32123ccdd13954f19d5b8b24a103e771a34c328755c65ed64e1924ffd04d30b2142cc262f6e0048fef6dbc652f21479ea1c4b1d66d28f4d46ef7185e390cbfa2e02380582f3188bb94ebbf05d31487a09aff01fcbb4cd4bfd1f0a833b38c11813c84360bb53c7d4481031c40bad8713bb6b835cb08098ed15ba31ee4ba728a8c8e10f7294e1b4163b7aee57277bfd881a6f9d43e02c6925aa3a043fb7fb78d", 16), 
//				new BigInteger("0997634c477c1a039d44c810b2aaa3c7862b0b88d3708272e1e15f66fc9389709f8a11f3ea6a5af7effa2d01c189c50f0d5bcbe3fa272e56cfc4a4e1d388a9dcd65df8628902556c8b6bb6a641709b5a35dd2622c73d4640bfa1359d0e76e1f219f8e33eb9bd0b59ec198eb2fccaae0346bd8b401e12e3c67cb629569c185a2e0f35a2f741644c1cca5ebb139d77a89a2953fc5e30048c0e619f07c8d21d1e56b8af07193d0fdf3f49cd49f2ef3138b5138862f1470bd2d16e34a2b9e7777a6c8c8d4cb94b4e8b5d616cd5393753e7b0f31cc7da559ba8e98d888914e334773baf498ad88d9631eb5fe32e53a4145bf0ba548bf2b0a50c63f67b14e398a34b0d", 16));
		RSAPrivateKeySpec static_privates = new RSAPrivateKeySpec(
				new BigInteger(nVal, 16), 
				new BigInteger(dVal, 16));
		
		PrivateKey spriv = kf.generatePrivate(static_privates);
		Signature dsa = Signature.getInstance("SHA256withRSA");
		dsa.initSign(spriv);
		dsa.update(input);
		byte[] output = dsa.sign();
		logger.info("msg: " + Hex.toHexString(output));
		logger.info("n: " + nVal);
		logger.info("d: " + dVal);
		logger.info("sig-cor: " + sig);
		logger.info("sig-get: " + Hex.toHexString(output));
		
		HashMap<String, String> map = new HashMap<String, String>();
		map.put("msg", msg);
		map.put("n", nVal);
		map.put("d", dVal);
		map.put("sig-cor", sig);
		map.put("sig-get", Hex.toHexString(output));
		
		return map;
	}
}

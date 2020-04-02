package kr.ac.korea.sans.ca.controller;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.dataformat.xml.XmlMapper;
import kr.ac.korea.sans.ca.config.GlobalConfig;
import kr.ac.korea.sans.ca.constant.Constants;
import kr.ac.korea.sans.ca.dto.CertDto;
import kr.ac.korea.sans.ca.dto.CrlDto;
import kr.ac.korea.sans.ca.response.CaAppResponse;
import kr.ac.korea.sans.ca.service.CertService;
import kr.ac.korea.sans.ca.service.CrlService;
import kr.ac.korea.sans.ca.util.CryptoHelper;
import org.apache.commons.codec.binary.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.InputStreamResource;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import javax.annotation.PostConstruct;
import javax.servlet.http.HttpServletRequest;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@CrossOrigin("*")
@RestController
public class CaAppController {
	/*
	 * note for fixing it.
	 * getting the latest serial number.
	 * directory name -> constants
	 * decide the rest api response format.
	 */
	
	@Autowired private ResourceLoader resourceLoader;
	@Autowired private CertService certSerivce;
	@Autowired private CrlService crlService;

	private GlobalConfig globalConfig;
	
	private static final Logger logger = LoggerFactory.getLogger(CaAppController.class);
	
	@PostConstruct
	public void init() throws Exception {
//		logger.info(this.name + ", " + this.age);
		
		XmlMapper xmlMapper = new XmlMapper();
		GlobalConfig.setInstance(xmlMapper.readValue(this.resourceLoader.getResource("classpath:config/config.xml").getFile(), new TypeReference<GlobalConfig>() {}));
		this.globalConfig = GlobalConfig.getInstance();
		
		if (!new File("CA-KeyPair/CA-Cert.der").exists()) {
			CryptoHelper cryptoHelper = CryptoHelper.getInstance();
			BigInteger serialNumber = new BigInteger(this.certSerivce.getOne().getSerialNumber(), 16).add(new BigInteger("1"));
			X509Certificate caCert = cryptoHelper.getSelfSignedX509Certificate(serialNumber);		
			
			String serialNumberHex = String.format("%040x",caCert.getSerialNumber());
			SimpleDateFormat formatter = new SimpleDateFormat(Constants.CA_DATE_FORMAT);
			String issuedDate = formatter.format(Calendar.getInstance().getTime());
			
			String notBefore = formatter.format(caCert.getNotBefore());
			String notAfter = formatter.format(caCert.getNotAfter());
			
			this.certSerivce.insertOne(new CertDto(serialNumberHex, issuedDate, notBefore, notAfter));
		}
		
	}
	
	
	@RequestMapping(value="/", method=RequestMethod.GET)
	public CaAppResponse<String> home (HttpServletRequest request) throws Exception {
		logger.info("home");
		CaAppResponse<String> response = new CaAppResponse<String>();
		response.setData("hello world");
		return response;
	}

	@RequestMapping(value="/get-cert", method=RequestMethod.POST)
	public synchronized CaAppResponse<String> getCertificate(@RequestBody Map<String, String> json) throws Exception {
		logger.info("getCertificate");
		String firstName = json.get(Constants.CA_FIRST_NAME);
		String lastName = json.get(Constants.CA_LAST_NAME);
		String countryCode = json.get(Constants.CA_COUNTRY_CODE);
		String encodedPublicKey = json.get(Constants.CA_PUB);
		logger.info(firstName + lastName + countryCode + encodedPublicKey);

		String cryptoType = GlobalConfig.getInstance().getCertConfig().getCryptoType();
		
		CryptoHelper cryptoHelper = CryptoHelper.getInstance();
		PublicKey publicKey = cryptoHelper.restorePublicKeyFromPem(encodedPublicKey);
		
		BigInteger serialNumber = new BigInteger(this.certSerivce.getOne().getSerialNumber(), 16).add(new BigInteger("1"));
		PrivateKey caPrivateKey = cryptoHelper.getPrivate(Constants.CA_CERT_DIR + Constants.CA_PRIVATE_KEY_DIR, cryptoType);
		X509Certificate caCert = cryptoHelper.getSelfSignedX509Certificate(serialNumber);
		
		serialNumber = new BigInteger(this.certSerivce.getOne().getSerialNumber(), 16).add(new BigInteger("1"));
		X509Certificate cert = cryptoHelper.getX509Certificate(publicKey, caCert, caPrivateKey, firstName, lastName, countryCode, serialNumber);
		
		String serialNumberHex = String.format("%040x",cert.getSerialNumber());
		SimpleDateFormat formatter = new SimpleDateFormat(Constants.CA_DATE_FORMAT);
		String issuedDate = formatter.format(Calendar.getInstance().getTime());
		
		String notBefore = formatter.format(cert.getNotBefore());
		String notAfter = formatter.format(cert.getNotAfter());
		
		this.certSerivce.insertOne(new CertDto(serialNumberHex, issuedDate, notBefore, notAfter));
		
		CaAppResponse<String> response = new CaAppResponse<String>();
		response.setData(Base64.encodeBase64String(cert.getEncoded()));
		return response;
	}
	
	@RequestMapping(value="/get-crl", method=RequestMethod.GET)
	public ResponseEntity<Resource> getCrl(HttpServletRequest request) throws Exception {
		CryptoHelper cryptoHelper = CryptoHelper.getInstance();
		String cryptoType = GlobalConfig.getInstance().getCertConfig().getCryptoType();
		List<CrlDto> crlEntries = this.crlService.getAll();
		
		PrivateKey caPrivateKey = cryptoHelper.getPrivate(Constants.CA_CERT_DIR + Constants.CA_PRIVATE_KEY_DIR, cryptoType);
		if (!new File("CRL").exists()) new File("CRL").mkdir();
		X509CRL crl = cryptoHelper.getCrl(caPrivateKey, "CRL/" + Constants.CA_CN + ".crl", crlEntries);
		logger.info(crl.toString());
		
		return ResponseEntity.ok()
				.contentType(MediaType.parseMediaType(Constants.CA_HTTP_HEADER_CONTENT_TYPE_FILE))
				.contentLength(crl.getEncoded().length)
				.header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + Constants.CA_CRL_FILENAME + "\"")
				.body(new InputStreamResource(new ByteArrayInputStream(crl.getEncoded())));
	}
	
	@RequestMapping(value="/add-crl", method=RequestMethod.POST)
	public CaAppResponse<String> addToCrl(HttpServletRequest request) throws Exception {
		// through admin page
		CaAppResponse<String> response = new CaAppResponse<String>();
		
		try {
			String bs64Cert = request.getParameter(Constants.CA_BASE64_CERT);
			int reason = Integer.parseInt(request.getParameter(Constants.CA_CERT_REVOKE_REASON));
			byte[] certEnc = Base64.decodeBase64(bs64Cert);
			CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
			X509Certificate cert = (X509Certificate) certFactory.generateCertificate(new ByteArrayInputStream(certEnc));
			
			String serialNumberHex = String.format("%040x",cert.getSerialNumber());
			SimpleDateFormat formatter = new SimpleDateFormat(Constants.CA_DATE_FORMAT);
			String issuedDate = formatter.format(Calendar.getInstance().getTime());
			this.crlService.insertOne(new CrlDto(serialNumberHex, issuedDate, reason));
			
			response.setData("ok");
		} catch (Exception e) {
			response.setData("error");
		}
//		
		return response;
	}
	
	@RequestMapping(value="/test-ecdsa", method=RequestMethod.GET)
	public CaAppResponse<HashMap<String, String>> testEcdsa(HttpServletRequest request) throws InvalidKeyException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeySpecException, SignatureException, NoSuchProviderException {
		String msg = request.getParameter("msg");
		String namedCurve = request.getParameter("ncurve");
		String prv = request.getParameter("prv");
		String kVal = request.getParameter("k");
		String rVal = request.getParameter("r");
		String sVal = request.getParameter("s");
		HashMap<String, String> map = CryptoHelper.getInstance().testEcdsa(msg, namedCurve, prv, kVal, rVal, sVal);
		
		CaAppResponse<HashMap<String, String>> response = new CaAppResponse<HashMap<String, String>>();
		response.setData(map);
		return response;
	}
	
	@RequestMapping(value="/test-rsa15", method=RequestMethod.GET)
	public CaAppResponse<HashMap<String, String>> testRsa(HttpServletRequest request) throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, SignatureException, InvalidAlgorithmParameterException {
		String msg = request.getParameter("msg");
		String nVal = request.getParameter("n");
		String dVal = request.getParameter("d");
		String sig = request.getParameter("s");
		
		HashMap<String, String> map = CryptoHelper.getInstance().testRsaPss(msg, nVal, dVal, sig);
		
		CaAppResponse<HashMap<String, String>> response = new CaAppResponse<HashMap<String, String>>();
		response.setData(map);
		return response;
	}
	
}

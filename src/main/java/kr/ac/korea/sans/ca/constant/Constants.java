package kr.ac.korea.sans.ca.constant;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class Constants {

	public static final String CA_ID = "id";
	public static final String CA_PUB = "pub";
	public static final String CA_FIRST_NAME = "firstName";
	public static final String CA_LAST_NAME = "lastName";
	public static final String CA_COUNTRY_CODE = "countryCode";
	public static final String CA_BASE64_CERT = "bs64Cert";
	public static final String CA_CERT_REVOKE_REASON = "reason";
	public static final String CA_CN = "Korea University";
	
	public static final String CA_CERT_DIR = "CA-KeyPair/";
	public static final String CA_PRIVATE_KEY_DIR = "CA-PrivateKey";
	public static final String CA_PUBLIC_KEY_DIR = "CA-PublicKey";
	
	public static final String CA_DATE_FORMAT = "yyyy-MM-dd HH:mm:ss";
	public static final String CA_HTTP_HEADER_CONTENT_TYPE_FILE = "application/octet-stream";
	
//	public static final String CA_BASE_URL = "http://localhost:9080";
	public static final String CA_CRL_URL = "/get-crl";
	public static final String CA_CRL_FILENAME = "kouivcrl.crl";
	public static String CA_BASE_URL;

	@Value("${ca.domain}")
	public void setCaBaseUrl(String url) { CA_BASE_URL = url; }
}

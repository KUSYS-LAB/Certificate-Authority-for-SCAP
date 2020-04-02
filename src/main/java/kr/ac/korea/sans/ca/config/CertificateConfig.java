package kr.ac.korea.sans.ca.config;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;

@JsonPropertyOrder({"crypto-type", "signature", "signature-hash"})
public class CertificateConfig {
	@JsonProperty("crypto-type") private String cryptoType;
	@JsonProperty("signature") private String signatureAlgorithm;
	@JsonProperty("signature-hash") private String signatureHashAlgorithm;
	
	public CertificateConfig() {
		
	}
	
	public String getSignatureAlgorithm() {
		return signatureAlgorithm;
	}

	public void setSignatureAlgorithm(String signatureAlgorithm) {
		this.signatureAlgorithm = signatureAlgorithm;
	}

	public String getSignatureHashAlgorithm() {
		return signatureHashAlgorithm;
	}

	public void setSignatureHashAlgorithm(String signatureHashAlgorithm) {
		this.signatureHashAlgorithm = signatureHashAlgorithm;
	}

	public String getCryptoType() {
		return cryptoType;
	}

	public void setCryptoType(String cryptoType) {
		this.cryptoType = cryptoType;
	}

	@Override
	public String toString() {
		return "CertificateConfig [cryptoType=" + cryptoType + ", signatureAlgorithm=" + signatureAlgorithm
				+ ", signatureHashAlgorithm=" + signatureHashAlgorithm + "]";
	}
}

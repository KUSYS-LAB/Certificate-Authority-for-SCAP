package kr.ac.korea.sans.ca.config;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;

@JsonPropertyOrder({"certificate"})
public class GlobalConfig {
	@JsonIgnore private static GlobalConfig globalConfig;
	@JsonProperty("certificate") private CertificateConfig certConfig;
	
	public GlobalConfig () {
		
	}
	
	public static GlobalConfig getInstance() {
		return globalConfig;
	}
	
	public static void setInstance(GlobalConfig config) {
		if (globalConfig == null) globalConfig = config;
	}

	public CertificateConfig getCertConfig() {
		return certConfig;
	}

	public void setCertConfig(CertificateConfig certConfig) {
		this.certConfig = certConfig;
	}
	
}

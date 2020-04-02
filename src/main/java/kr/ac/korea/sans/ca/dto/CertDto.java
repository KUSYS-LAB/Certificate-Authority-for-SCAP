package kr.ac.korea.sans.ca.dto;

public class CertDto {
	private String serialNumber;
	private String issuedDate;
	private String notBefore;
	private String notAfter;
	
	public CertDto() {
		this(null, null, null, null);
	}
	
	public CertDto(String serialNumber, String issuedDate, String notBefore, String notAfter) {
		this.serialNumber = serialNumber;
		this.issuedDate = issuedDate;
		this.notBefore = notBefore;
		this.notAfter = notAfter;
	}

	public String getSerialNumber() {
		return serialNumber;
	}

	public void setSerialNumber(String serialNumber) {
		this.serialNumber = serialNumber;
	}

	public String getIssuedDate() {
		return issuedDate;
	}

	public void setIssuedDate(String issuedDate) {
		this.issuedDate = issuedDate;
	}

	public String getNotBefore() {
		return notBefore;
	}

	public void setNotBefore(String notBefore) {
		this.notBefore = notBefore;
	}

	public String getNotAfter() {
		return notAfter;
	}

	public void setNotAfter(String notAfter) {
		this.notAfter = notAfter;
	}

	@Override
	public String toString() {
		return "CertDto [serialNumber=" + serialNumber + ", issuedDate=" + issuedDate + ", notBefore=" + notBefore
				+ ", notAfter=" + notAfter + "]";
	}

}

package kr.ac.korea.sans.ca.dto;

public class CrlDto {
	private String serialNumber;
	private String revokedDate;
	private int reason;
	
	public CrlDto() {
		this(null, null, 0);
	}
	
	public CrlDto(String serialNumber, String revokedDate, int reason) {
		this.serialNumber = serialNumber;
		this.revokedDate = revokedDate;
		this.reason = reason;
	}

	public String getSerialNumber() {
		return serialNumber;
	}

	public void setSerialNumber(String serialNumber) {
		this.serialNumber = serialNumber;
	}

	public String getRevokedDate() {
		return revokedDate;
	}

	public void setRevokedDate(String revokedDate) {
		this.revokedDate = revokedDate;
	}

	public int getReason() {
		return reason;
	}

	public void setReason(int reason) {
		this.reason = reason;
	}

	@Override
	public String toString() {
		return "CrlDto [serialNumber=" + serialNumber + ", revokedDate=" + revokedDate + ", reason=" + reason + "]";
	}
	
}

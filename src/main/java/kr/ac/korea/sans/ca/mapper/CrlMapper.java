package kr.ac.korea.sans.ca.mapper;

import kr.ac.korea.sans.ca.dto.CrlDto;

import java.util.List;

public interface CrlMapper {
	public void insertOne(CrlDto crlDto);
	public List<CrlDto> getAll();
	public void insertExpiredCerts(List<CrlDto> expiredCerts);
}

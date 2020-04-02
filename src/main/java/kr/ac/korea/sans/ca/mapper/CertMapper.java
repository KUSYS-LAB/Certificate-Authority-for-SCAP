package kr.ac.korea.sans.ca.mapper;

import kr.ac.korea.sans.ca.dto.CertDto;

import java.util.List;

public interface CertMapper {
	public void insertOne(CertDto certDto);
	public CertDto getOne();
	public List<CertDto> getAll();
	public List<CertDto> getAllNotInCrl();
}

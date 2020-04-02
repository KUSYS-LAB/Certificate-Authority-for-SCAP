package kr.ac.korea.sans.ca.service;

import kr.ac.korea.sans.ca.dto.CertDto;
import kr.ac.korea.sans.ca.mapper.CertMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

@Service
public class CertService {

	@Autowired
	private CertMapper certMapper;
	
	private Logger logger = LoggerFactory.getLogger(CertService.class);
	
	public void insertOne(CertDto certDto) {
		this.certMapper.insertOne(certDto);
	}
	
	public CertDto getOne() {
		CertDto certDto = this.certMapper.getOne();
		if (certDto == null) return new CertDto(String.format("%040x", new BigInteger("0")), null, null, null);
		else return certDto;
	}
	
	public List<CertDto> getAll() {
		return this.certMapper.getAll();
	}

	public List<CertDto> getAllNotInCrl(){
		List<CertDto> certs = this.certMapper.getAllNotInCrl();
		if (certs == null) certs = new ArrayList<CertDto>();
		return certs;
	}
}

package kr.ac.korea.sans.ca.service;

import kr.ac.korea.sans.ca.dto.CrlDto;
import kr.ac.korea.sans.ca.mapper.CrlMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class CrlService {

	@Autowired
	private CrlMapper crlMapper;
	
	private Logger logger = LoggerFactory.getLogger(CrlService.class);
	
	public void insertOne(CrlDto crlDto) {
		this.crlMapper.insertOne(crlDto);
	}
	
	public List<CrlDto> getAll() {
		return this.crlMapper.getAll();
	}
	
	public void insertExpiredCerts(List<CrlDto> expiredCerts) {
		if (expiredCerts.size() > 0) this.crlMapper.insertExpiredCerts(expiredCerts);
	}
}

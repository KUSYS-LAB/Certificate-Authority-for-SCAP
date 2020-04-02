package kr.ac.korea.sans.ca.scheduler;

import kr.ac.korea.sans.ca.constant.Constants;
import kr.ac.korea.sans.ca.dto.CertDto;
import kr.ac.korea.sans.ca.dto.CrlDto;
import kr.ac.korea.sans.ca.service.CertService;
import kr.ac.korea.sans.ca.service.CrlService;
import org.bouncycastle.asn1.x509.CRLReason;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.List;

@Component
public class CrlScheduler {
	
	@Autowired private CertService certService;
	@Autowired private CrlService crlService;
	
	private Logger logger = LoggerFactory.getLogger(CrlScheduler.class);

	@Scheduled(cron = "0 5 * ? * ?")
	public synchronized void updateCrl() throws ParseException {
		List<CertDto> certs = this.certService.getAllNotInCrl();
		SimpleDateFormat formatter = new SimpleDateFormat(Constants.CA_DATE_FORMAT);
		Date now = Calendar.getInstance().getTime();
		List<CrlDto> expiredCerts = new ArrayList<CrlDto>();
		
		for (CertDto cert : certs) {
			Date notAfter = formatter.parse(cert.getNotAfter());
			int cmp = notAfter.compareTo(now);
			if (cmp < 0) {
				CrlDto expiredCert = new CrlDto(cert.getSerialNumber(), cert.getNotAfter(), CRLReason.superseded);
				expiredCerts.add(expiredCert);
			}
		}
		
		this.crlService.insertExpiredCerts(expiredCerts);
	}
}

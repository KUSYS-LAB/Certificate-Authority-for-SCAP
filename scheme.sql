CREATE TABLE cert (
	serial_number VARCHAR(40),
	issued_date VARCHAR(19) NOT NULL,
	not_before VARCHAR(19) NOT NULL,
	not_after VARCHAR(19) NOT NULL,
	CONSTRAINT csn_pk PRIMARY KEY(serial_number)
);


CREATE TABLE crl(
	serial_number VARCHAR(40),
	revoked_date VARCHAR(19) NOT NULL,
	reason INTEGER NOT NULL,
	CONSTRAINT crl_pk PRIMARY KEY(serial_number),
	CONSTRAINT crl_fk1 FOREIGN KEY (serial_number) REFERENCES cert(serial_number)
);
# Certificate-Authority-for-SCAP
The Certificate Authority for SCAP project.

The project is under development with the support of KHIDI(https://www.khidi.or.kr/kps).
All description you need will be added soon.

## Set up
 Currently we use the mariadb for dbms, so you have to install the mariadb first. If you have installed the mariadb, you have to create the db and the account. By default, we use the following db and account. If you want to other account and db, you have to modify application.properties.
 ```
 DB: ca_web
 ID: ca_web_admin
 PW: ca_web_admin
 ```
 Next, the table schemas should be defined. we provide the current version of table scheme(`scheme.sql`). Execute the sql scripts by your self.
 Finally, the base url(ca.domain) for ca must be set up at `application.properties`.
 Now, all set up.

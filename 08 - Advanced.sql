-- manage certificate permissions by database role
USE pubs
CREATE LOGIN recievable WITH PASSWORD = 'Password1!abcdef12345!@#$%^'
CREATE LOGIN payable WITH PASSWORD = 'Password1!abcdef12345!@#$%^'
CREATE LOGIN bic WITH PASSWORD = 'Password1!abcdef12345!@#$%^'
CREATE USER recievable
CREATE USER payable
CREATE USER bic
CREATE ROLE beancounter AUTHORIZATION dbo
EXEC sp_addrolemember 'beancounter', 'recievable'
EXEC sp_addrolemember 'beancounter', 'payable'
EXEC sp_addrolemember 'beancounter', 'bic'
-- in order to use a certificate the user/role needs to have VIEW DEFINITION and CONTROL permissions
GRANT VIEW DEFINITION ON CERTIFICATE::acct_cert TO beancounter
GRANT CONTROL ON CERTIFICATE::acct_cert TO beancounter
GRANT VIEW DEFINITION ON SYMMETRIC KEY::acct_key TO beancounter

-- simulate logging in as the beancounter in charge. I can see the SSN but not the bat phone
EXECUTE AS LOGIN = 'bic'
exec dbo.ListAuthors
REVERT

--  multi tenant solution with each customer having their own encryption key
CREATE CERTIFICATE multi_cust AUTHORIZATION acct WITH SUBJECT = 'Multi Customer Cert'
CREATE SYMMETRIC KEY customer_a WITH ALGORITHM = AES_256 ENCRYPTION BY CERTIFICATE multi_cust
CREATE SYMMETRIC KEY customer_b WITH ALGORITHM = AES_256 ENCRYPTION BY CERTIFICATE multi_cust
CREATE SYMMETRIC KEY customer_c WITH ALGORITHM = AES_256 ENCRYPTION BY CERTIFICATE multi_cust

-- customer A 
OPEN SYMMETRIC KEY customer_a DECRYPTION BY certificate multi_cust
INSERT INTO authors (au_id, au_lname, au_fname, phone, 
	contract, enc_ssn)
	VALUES ('333-33-3333', 'Smith', 'Bob', '999 999-9999', 1,  
	ENCRYPTBYKEY(Key_GUID('customer_a'),'AAA-AA-AAA1'))
INSERT INTO authors (au_id, au_lname, au_fname, phone, 
	contract, enc_ssn)
	VALUES ('444-44-4444', 'Smith2', 'Bob', '999 999-9999', 1,  
	ENCRYPTBYKEY(Key_GUID('customer_a'),'AAA-AA-AAA2'))
CLOSE ALL SYMMETRIC KEYS

-- customer B 
OPEN SYMMETRIC KEY customer_b DECRYPTION BY certificate multi_cust
INSERT INTO authors (au_id, au_lname, au_fname, phone, 
	contract, enc_ssn)
	VALUES ('555-55-5555', 'Doe', 'Jane', '999 999-9999', 1,  
	ENCRYPTBYKEY(Key_GUID('customer_b'),'BBB-BB-BBB1'))
INSERT INTO authors (au_id, au_lname, au_fname, phone, 
	contract, enc_ssn)
	VALUES ('666-66-6666', 'Doe2', 'Jane', '999 999-9999', 1,  
	ENCRYPTBYKEY(Key_GUID('customer_b'),'BBB-BB-BBB2'))
CLOSE ALL SYMMETRIC KEYS

-- customer C 
OPEN SYMMETRIC KEY customer_c DECRYPTION BY certificate multi_cust
INSERT INTO authors (au_id, au_lname, au_fname, phone, 
	contract, enc_ssn)
	VALUES ('777-77-7777', 'Jones', 'John', '999 999-9999', 1,  
	ENCRYPTBYKEY(Key_GUID('customer_c'),'CCC-CC-CCC1'))
INSERT INTO authors (au_id, au_lname, au_fname, phone, 
	contract, enc_ssn)
	VALUES ('888-88-8888', 'Jones2', 'John', '999 999-9999', 1,  
	ENCRYPTBYKEY(Key_GUID('customer_c'),'CCC-CC-CCC2'))
CLOSE ALL SYMMETRIC KEYS

exec dbo.ListAuthors


-- high security (paranoid) customer 
declare @password nvarchar(255) = N'fd83f&(*&#FUIKJH'
declare @cmd nvarchar(max) = N'CREATE CERTIFICATE paranoid_cust_p ENCRYPTION BY PASSWORD = ''' + @password + N''' WITH SUBJECT = ''Paranoid Customer P'''
-- create the certificate protected with the user entered password
exec sp_executesql @cmd
GRANT VIEW DEFINITION ON CERTIFICATE::paranoid_cust_p TO acct
GRANT CONTROL ON CERTIFICATE::paranoid_cust_p TO acct
CREATE SYMMETRIC KEY customer_p WITH ALGORITHM = AES_256 ENCRYPTION BY CERTIFICATE paranoid_cust_p
GRANT VIEW DEFINITION ON SYMMETRIC KEY::customer_p TO acct
GO

-- open the keys using the password and create some data
declare @password nvarchar(255) = N'fd83f&(*&#FUIKJH'
declare @cmd nvarchar(max) = N'OPEN SYMMETRIC KEY customer_p DECRYPTION BY certificate paranoid_cust_p WITH PASSWORD = ''' + @password + ''''
exec sp_executesql @cmd
GO
INSERT INTO authors (au_id, au_lname, au_fname, phone, 
	contract, enc_ssn)
	VALUES ('999-99-9999', 'Zeta', 'Max', '999 999-9999', 1,  
	ENCRYPTBYKEY(Key_GUID('customer_p'),'PPP-PP-PPP1'))
CLOSE ALL SYMMETRIC KEYS
GO

-- now read the data back out by including the certificate password to DECRYPTBYKEYAUTOCERT
declare @password nvarchar(255) = N'fd83f&(*&#FUIKJH'
declare @cmd nvarchar(max) = N'SELECT au_id, enc_ssn, CONVERT(varchar, DECRYPTBYKEYAUTOCERT(CERT_ID(''paranoid_cust_p''),N''' + @password + ''',enc_ssn)) AS plain_ssn FROM dbo.authors WHERE au_id = ''999-99-9999'''
exec sp_executesql @cmd
GO

CLOSE ALL SYMMETRIC KEYS

-- when run without the password no data is available
SELECT au_id, enc_ssn, CONVERT(varchar, DECRYPTBYKEYAUTOCERT(CERT_ID('paranoid_cust_p'),null,enc_ssn)) AS ssn FROM dbo.authors WHERE au_id = '999-99-9999'


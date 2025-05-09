USE pubs
GO

ALTER PROCEDURE dbo.ListAuthors
AS
	OPEN SYMMETRIC KEY sales_key DECRYPTION BY CERTIFICATE sales_cert
	OPEN SYMMETRIC KEY acct_key DECRYPTION BY certificate acct_cert
	SELECT au_id, au_fname, au_lname, address, city, state, zip, phone, 
		CONVERT(varchar, DECRYPTBYKEY(enc_bat_phone)) AS bat_phone, 
		CONVERT(varchar, DECRYPTBYKEY(enc_ssn)) AS ssn, 		
		CONVERT(numeric(10,4), CONVERT(varchar(max), DECRYPTBYKEY(enc_commission,1,au_id))) AS commission
		FROM dbo.authors
	CLOSE ALL SYMMETRIC KEYS
GO

exec dbo.ListAuthors

-- simulate logging in as sales & trying to see ssn

EXECUTE AS LOGIN = 'sales'

exec dbo.ListAuthors
-- error due to not being able to access acct keys

SELECT * FROM sys.openkeys

OPEN SYMMETRIC KEY sales_key DECRYPTION BY CERTIFICATE sales_cert

OPEN SYMMETRIC KEY acct_key DECRYPTION BY certificate acct_cert
-- we don't have permisison to open the accounting certificate

SELECT * FROM sys.openkeys

-- read our data

SELECT au_id, ssn, bat_phone, enc_ssn, CONVERT(varchar, DECRYPTBYKEY(enc_ssn)) AS plain_ssn,
	enc_bat_phone, CONVERT(varchar, DECRYPTBYKEY(enc_bat_phone)) AS plain_bat_phone,
	CONVERT(numeric(10,4), CONVERT(varchar(max), DECRYPTBYKEY(enc_commission,1,au_id))) AS commission
	FROM dbo.authors 
-- note that since we cannot access the accounting key the decrypted data is null

CLOSE ALL SYMMETRIC KEYS

-- back to dbo now
REVERT

-- we can again open all keys
OPEN SYMMETRIC KEY sales_key DECRYPTION BY CERTIFICATE sales_cert

OPEN SYMMETRIC KEY acct_key DECRYPTION BY certificate acct_cert

SELECT * FROM sys.openkeys

CLOSE ALL SYMMETRIC KEYS

-- now we log in as accounting

EXECUTE AS LOGIN = 'acct'

exec dbo.ListAuthors

OPEN SYMMETRIC KEY acct_key DECRYPTION BY certificate acct_cert

OPEN SYMMETRIC KEY sales_key DECRYPTION BY CERTIFICATE sales_cert

-- we don't have permisison to open the sales certificate

SELECT * FROM sys.openkeys

-- read our data

SELECT au_id, ssn, bat_phone, enc_ssn, CONVERT(varchar, DECRYPTBYKEY(enc_ssn)) AS plain_ssn,
	enc_bat_phone, CONVERT(varchar, DECRYPTBYKEY(enc_bat_phone)) AS plain_bat_phone,
	CONVERT(numeric(10,4), CONVERT(varchar(max), DECRYPTBYKEY(enc_commission,1,au_id))) AS commission
	FROM dbo.authors 
-- note that since we cannot access the sales key the decrypted data is null

CLOSE ALL SYMMETRIC KEYS

REVERT

-- that's great but do I have to do all that?

-- no, do it in a view
-- use DECRYPTBYKEYAUTOCERT with CERT_ID and the name of the certificate that encrypts the symmetric key
CREATE VIEW v_authors_sales 
	AS 
	SELECT au_id, ssn, bat_phone, enc_ssn, CONVERT(varchar, DECRYPTBYKEYAUTOCERT(CERT_ID('acct_cert'),null,enc_ssn)) AS plain_ssn,
	enc_bat_phone, CONVERT(varchar, DECRYPTBYKEYAUTOCERT(CERT_ID('sales_cert'),null,enc_bat_phone)) AS plain_bat_phone,
	CONVERT(numeric(10,4), CONVERT(varchar(max), DECRYPTBYKEYAUTOCERT(CERT_ID('acct_cert'),null,enc_commission,1,au_id))) AS commission
	FROM dbo.authors 
GO

CREATE VIEW v_authors_acct
	AS 
	SELECT au_id, ssn, bat_phone, enc_ssn, CONVERT(varchar, DECRYPTBYKEYAUTOCERT(CERT_ID('acct_cert'),null,enc_ssn)) AS plain_ssn,
	enc_bat_phone, CONVERT(varchar, DECRYPTBYKEYAUTOCERT(CERT_ID('sales_cert'),null,enc_bat_phone)) AS plain_bat_phone,
	CONVERT(numeric(10,4), CONVERT(varchar(max), DECRYPTBYKEYAUTOCERT(CERT_ID('acct_cert'),null,enc_commission,1,au_id))) AS commission
	FROM dbo.authors 
GO

select * from sys.openkeys

SELECT * FROM v_authors_sales
SELECT * FROM v_authors_acct

GRANT SELECT ON v_authors_sales TO sales
GRANT SELECT ON v_authors_acct TO acct

/*
	for purposes of the demo, even if you run the next 2 GRANT's the 
	user will still be unable to see the encrypted data due to not having 
	permission on the underlying symmetric keys
*/
GRANT SELECT ON v_authors_sales TO acct
GRANT SELECT ON v_authors_acct TO sales

-- simulate connecting as sales
EXECUTE AS LOGIN = 'sales'

SELECT * FROM sys.openkeys


SELECT * FROM v_authors_sales
SELECT * FROM v_authors_acct

SELECT * FROM sys.openkeys

REVERT

EXECUTE AS LOGIN = 'acct'

SELECT * FROM sys.openkeys

SELECT * FROM v_authors_sales
SELECT * FROM v_authors_acct

SELECT * FROM sys.openkeys

REVERT
GO

-- We can now simplify our stored procedure to aotomatically find the right keys
ALTER PROCEDURE dbo.ListAuthors
AS
	SELECT au_id, au_fname, au_lname, address, city, state, zip, phone,
	CONVERT(varchar, DECRYPTBYKEYAUTOCERT(CERT_ID('sales_cert'),null,enc_bat_phone)) AS bat_phone,
	CONVERT(varchar, DECRYPTBYKEYAUTOCERT(CERT_ID('acct_cert'),null,enc_ssn)) AS ssn,
	CONVERT(numeric(10,4), CONVERT(varchar, 
		DECRYPTBYKEYAUTOCERT(CERT_ID('acct_cert'),null,enc_commission,1,au_id))) AS commission
	FROM dbo.authors 
GO

ALTER PROCEDURE dbo.GetAuthor
	@au_id varchar(11)
AS
BEGIN
	SELECT au_id, au_fname, au_lname,
		CONVERT(varchar, DECRYPTBYKEYAUTOCERT(CERT_ID('sales_cert'),null,enc_bat_phone)) AS bat_phone,
		CONVERT(varchar, DECRYPTBYKEYAUTOCERT(CERT_ID('acct_cert'),null,enc_ssn)) AS ssn
		FROM dbo.authors
		WHERE au_id = @au_id
END
GO

EXECUTE AS LOGIN = 'acct'

exec dbo.ListAuthors

REVERT

EXECUTE AS LOGIN = 'sales'

exec dbo.ListAuthors

REVERT

/*
	Suppose sales has the ability to update data, even if they cannot decrypt it they can
	still swap around encrypted values unless authenticators are used to prevent tampering
*/

GRANT UPDATE ON dbo.authors TO sales

exec dbo.ListAuthors

EXECUTE AS LOGIN = 'sales'

UPDATE dbo.authors SET enc_bat_phone = 
	(SELECT TOP 1 enc_bat_phone FROM dbo.authors WHERE au_id = '527-72-3246')
	WHERE au_id = '486-29-1786'

REVERT

exec dbo.ListAuthors

SELECT * FROM v_authors_acct WHERE au_id IN ('527-72-3246', '486-29-1786')

/*
	now that we know we can swap around phone numbers let's go ahead and give ourselves
	more commission
*/

EXECUTE AS LOGIN = 'sales'

SELECT au_id, enc_commission FROM dbo.authors WHERE au_id IN ('527-72-3246', '486-29-1786')

UPDATE dbo.authors SET enc_commission = 
	(SELECT TOP 1 enc_commission FROM dbo.authors WHERE au_id = '527-72-3246')
	WHERE au_id = '486-29-1786'

REVERT

SELECT * FROM v_authors_sales WHERE au_id IN ('527-72-3246', '486-29-1786')

exec dbo.ListAuthors


USE pubs

-- connected as dbo which has access to all keys
SELECT * from sys.openkeys

OPEN SYMMETRIC KEY acct_key DECRYPTION BY certificate acct_cert

OPEN SYMMETRIC KEY sales_key DECRYPTION BY CERTIFICATE sales_cert

SELECT * from sys.openkeys

-- update the encrypted columns

-- use Key_GUID to obtain the GUID of the friendlyname of the encryption key
-- use ENCRYPTBYKEY to return a varbinary of the encrypted data
-- note that all encryption is nondeterministic, encrypting the same data with the same key multiple times returns multiple results due to SQL Server maintiaining a random IV for each execution
UPDATE dbo.authors SET enc_ssn = ENCRYPTBYKEY(Key_GUID('acct_key'),ssn),
	enc_bat_phone = ENCRYPTBYKEY(Key_GUID('sales_key'),bat_phone)
	
SELECT au_id,ssn, bat_phone, enc_ssn, enc_bat_phone, commission, enc_commission from authors

-- Encrypt the commission rate with the accounting key and use the @add_authenticator parameter to 
-- ensure that the encrypted data cannot be easily tampered with
UPDATE dbo.authors SET enc_commission = ENCRYPTBYKEY(Key_GUID('acct_key'),
	CONVERT(varchar(max), commission), 1, CONVERT(varbinary(8000), au_id))

SELECT au_id, ssn, bat_phone, enc_ssn, CONVERT(varchar, DECRYPTBYKEY(enc_ssn)) AS plain_ssn,
	enc_bat_phone, CONVERT(varchar, DECRYPTBYKEY(enc_bat_phone)) AS plain_bat_phone,
	enc_commission, 
	CONVERT(numeric(10,2), CONVERT(varchar(max), 
		DECRYPTBYKEY(enc_commission,1,CONVERT(varbinary(8000),au_id)))) as plain_commssion
	FROM dbo.authors 

-- Always Encrypted data must either be updated from a client with access to the mey material 
-- or from SSMS with paramaterization & access to key 
SELECT au_id, ae_ssn, ae_bat_phone FROM authors

-- Vault encrypted data must be updated from a client with access to the vault 
SELECT au_id, ext_ssn, ext_bat_phone FROM authors


-- clean up by closing keys for this session
CLOSE ALL SYMMETRIC KEYS

SELECT * FROM sys.openkeys

-- rerun the query with the keys closed
SELECT au_id, ssn, bat_phone, enc_ssn, CONVERT(varchar, DECRYPTBYKEY(enc_ssn)) AS plain_ssn,
	enc_bat_phone, CONVERT(varchar, DECRYPTBYKEY(enc_bat_phone)) AS plain_bat_phone, 
	enc_commission, 
		CONVERT(numeric(10,2), CONVERT(varchar(max), 
		DECRYPTBYKEY(enc_commission,1,CONVERT(varbinary(8000),au_id)))) as plain_commssion
	FROM dbo.authors 


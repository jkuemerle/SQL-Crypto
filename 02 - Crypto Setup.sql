USE pubs

-- system views show no existing keys
SELECT * FROM sys.certificates
SELECT * FROM sys.key_encryptions
SELECT * FROM sys.symmetric_keys

-- create the master key for the database, this will be used to encrypt every other key in the DB and is in turn encrypted by the service master key
CREATE MASTER KEY ENCRYPTION BY password = 'MasterKey1$ABCDEF12345!@#$%'
--ALTER MASTER KEY ENCRYPTION password = 'foo!0Test'

-- create certificates for each user to be used to protect their own symmetric keys
-- symmetric keys are created to encrypt data because they are faster and do not have inherient data size limitations based on key size
CREATE CERTIFICATE acct_cert AUTHORIZATION acct WITH SUBJECT = 'Accounting Cert'

CREATE CERTIFICATE sales_cert AUTHORIZATION sales WITH SUBJECT = 'Sales Certificate'

SELECT * FROM sys.certificates

-- create symmetric keys for each user to protect thier data
CREATE SYMMETRIC KEY acct_key WITH ALGORITHM = AES_256 ENCRYPTION BY CERTIFICATE acct_cert

CREATE SYMMETRIC KEY sales_key WITH ALGORITHM = AES_256 ENCRYPTION BY CERTIFICATE sales_cert

-- grant permissions to the symmetric keys so that only the correct user can access them
GRANT VIEW DEFINITION ON SYMMETRIC KEY::acct_key TO acct
GRANT VIEW DEFINITION ON SYMMETRIC KEY::sales_key TO sales

SELECT * FROM sys.symmetric_keys

--A column encryption key is used to encrypt the data within an encrypted column.
--A column master key is a key-protecting key that encrypts one or more column encryption keys.
-- create the AlwaysEncrypted Column Master Key from the local certificate store

CREATE COLUMN MASTER KEY [SQLSaturdayNYC]
WITH
(
	KEY_STORE_PROVIDER_NAME = N'MSSQL_CERTIFICATE_STORE',
	KEY_PATH = N'CurrentUser/My/D68D3CAC979B869BCF6FD725D88A788952F6DBF0'
)
GO

-- CEKs can have 1 or 2 values, multiple values are used to support key rotation
CREATE COLUMN ENCRYPTION KEY [ExternalKey1]
WITH VALUES
(
	COLUMN_MASTER_KEY = [SQLSaturdayNYC],
	ALGORITHM = 'RSA_OAEP',
	ENCRYPTED_VALUE = 0x016E000002630075007200720065006E00740075007300650072002F006D0079002F0064003600380064003300630061006300390037003900620038003600390062006300660036006600640037003200350064003800380061003700380038003900350032006600360064006200660030005ACA31717444F4A2B25A83C6154870787FF7EDEFB6A4625E70BE1274E5C65FA226BA3F4ACC4CD3CFA7B5CCC71C792685D10920551861C6908D3E2A37D290FF9A8724183160BF4A4A76D6CCE163F30C553E50D4FD9149B1E5DDDF19C6BC6B97381FFC0E01209B06A721A8B63BE0DA2910524365EFD53CAECB45650C2C587A2F04F2FC0BDAC21654DEA9D795A8037C44192294C07484F201BF491498577AC98677E31BEA445EF674A9E1BCFFDD7EE72296E4FC895FCB1F81EEDF96514D5452FE78B9C8B755EC15F72B02DF546FC6CB2C353FA5146234C0DA6D28A02DAEFA21ABB4FCCBCAAD6E499E8B78A84382FE2A17C105E0728FBFAA3B7BCA9A5EABD7E4741C9A6FE66DABABF12C344F706C930A79E02CFB27A953D292CB321703A405FDD49187E98D7880A74D4C19C60FE5AAF00F290D52DA52930D6D1F3FA1B112A47DC6801914C69EB40A0AD4F0AC4D8936EFA5EF8440F16C8E6C21DBDDB4959F6807846359185A2CDAC126C6D3412A6E5965C0C20426692A6AA822D566BABADFF9FCEB82E0B451A2FABBFA9FE30E5D34E7ABFED0A755A6349AA7B2BDF7564D62887C7D811FB8EF304D7C75E2C370B11F0C06067A228C15E7898D60D1828360F5C371D76F663E495436CAB28B6B6D3E11CBF69505F406C2B47FBE487EE3A4F28123469141D20673706CD6D7C3958695DFCCB5163EFACA32CCF066C00624522908030CD1DD6528BE9D26D8AFB0FF7F470F04F8931F3ACA4C5015F1A7F78BC72DAD178BDF1881DE6581F17304C465786CA12AB278B67B390D53ACEC63CB9A3A0CEEBA6A545E3C67B3D8527C0CFA8AC6DB68DB313DD4A6C08C4C5B91C2AC2FC650136C8FCA066E1B2FA528AF3432BD1A4A77A3A852A4F942AF5F3C40E5355DA961F0479B796D7C2A12FA633C987DA7EB093B5903FD3328D8B5B49D123929FCBDE28254D48E618D83DFC9C8781033A592E9801D0FF8DF7C5FA71479EF9911B3426A5441BD1303157143E82DB370AE5BAF668A6FC8580B07C4076B4B80A191F1FB1CDCF4F484F2E9C41D17B67A8021FC12890ABE62F70DBC858F7142EB90EE81F0A56220728D0D79616223FCEE9CED5EF6873E9954087B5F224E836F0095B4CF1A8D1A73DD3C5003699958A96D0F7AB754DC79ED7B7F68B5ECB20408A1DF457A2BADF65D22B4B96FA62C46809BE938A02745C900A03E8DF404850FC75267F0BA1FC2E6586EACF0D5F45D4EE2DF3DDB5ACE96477DFB0F427C3E1C68CB41AA0915A81CF54065DA30E23233F4AA486F3CC843C7F8843F83B070D4C5792F33CC92A9356DE358B5FD82D63BBF92A1808192658D9056825DD608AB6151604C26AF9DFE56CDF8005B171C941F8876121F00B1F484314D8AC2450C45B96BC11657412B13D7D058520DB891DA275B676855F6757F8F0B57D949B89BA77A66C8FCDBF3E482247B56318DEE13
)
GO

-- now add the columns to contain encrypted data
ALTER TABLE dbo.authors ADD enc_ssn varbinary(max)
ALTER TABLE dbo.authors ADD enc_bat_phone varbinary(max)
ALTER TABLE dbo.authors ADD enc_commission varbinary(max)
ALTER TABLE dbo.authors ADD password_salt uniqueidentifier DEFAULT NEWID()
ALTER TABLE dbo.authors ADD password_hash varbinary(max)
--deterministic encryption is less secure but allows grouping, filter by equality, and joining tables on encrypted columns. Deterministic Encryption produces the same encrypted value for any given plaintext value
ALTER TABLE dbo.authors ADD ae_ssn nvarchar(11) COLLATE Latin1_General_BIN2 ENCRYPTED WITH ( COLUMN_ENCRYPTION_KEY = ExternalKey1, ENCRYPTION_TYPE = RANDOMIZED,
       ALGORITHM = 'AEAD_AES_256_CBC_HMAC_SHA_256')
ALTER TABLE dbo.authors ADD ae_bat_phone nvarchar(12) COLLATE Latin1_General_BIN2 ENCRYPTED WITH ( COLUMN_ENCRYPTION_KEY = ExternalKey1, ENCRYPTION_TYPE = DETERMINISTIC,
       ALGORITHM = 'AEAD_AES_256_CBC_HMAC_SHA_256') 
ALTER TABLE dbo.authors ADD ext_ssn nvarchar(max) NULL
ALTER TABLE dbo.authors ADD ext_bat_phone nvarchar(max) NULL


--drop table dbo.author_draft 
-- add a table for storing encrypted rough drafts by author
CREATE TABLE dbo.author_draft (
	draft_id int NOT NULL IDENTITY(1,1) PRIMARY KEY,
	au_id varchar(11) NOT NULL REFERENCES dbo.authors(au_id), 
	title varchar(100) NOT NULL,
	data varbinary(max)	NULL
)
GO

CREATE PROCEDURE dbo.ListDrafts
	@au_id varchar(11)
AS
BEGIN
	SELECT draft_id, title from dbo.author_draft WHERE au_id = @au_id
END
GO

GRANT EXECUTE ON dbo.ListDrafts TO web
GO


CREATE PROCEDURE dbo.UpdateExtData
	@id varchar(11), @ssn nvarchar(11), @phone nvarchar(12)
AS
BEGIN
	UPDATE authors SET ae_ssn = @ssn, ae_bat_phone = @phone WHERE au_id = @id
END
GO

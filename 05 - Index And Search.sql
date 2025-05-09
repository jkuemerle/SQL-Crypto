USE pubs

-- since encryption is non-deterministric due to SQL using a nonce as an IV 
-- traditional indexing will not work, we can use a simple hash but that is prone to 
-- dictionary attacks, try an HMAC instead

-- add a new column to be indexable
ALTER TABLE dbo.authors ADD phone_mac varbinary(max)

-- create a table to hold the MAC's for use with multiple tables
CREATE TABLE t_MacIndexKeys( table_id int PRIMARY KEY, Mac_key varbinary(100) not null )

-- create the encryption keys for the MAC data

CREATE CERTIFICATE cert_ProtectIndexingKeys WITH SUBJECT = 'Data indexing key protection'

CREATE SYMMETRIC KEY key_Indexing WITH ALGORITHM = AES_256 ENCRYPTION BY CERTIFICATE cert_ProtectIndexingKeys
GO

-- Create the function to return the MAC value for a data to be stored in a specific table
CREATE FUNCTION dbo.MAC( @Message nvarchar(4000), @Table_id int )
RETURNS varbinary(24)
WITH EXECUTE AS OWNER 
AS
BEGIN
        declare @RetVal varbinary(24)
        declare @Key   varbinary(100)
        SET @RetVal = null
        SET @key    = null
        SELECT @Key = DecryptByKeyAutoCert( cert_id('cert_ProtectIndexingKeys'), null, Mac_key) FROM t_MacIndexKeys WHERE table_id = @Table_id
        if( @Key is not null )
               SELECT @RetVal = HashBytes( N'SHA1', convert(varbinary(8000), @Message) + @Key )
        RETURN @RetVal
END
GO

-- create the sproc to generate a random seed for a table and store it in the MAC table
CREATE PROC dbo.AddMacForTable @Table_id int 
WITH EXECUTE AS OWNER
AS
        declare @Key    varbinary(100)
        declare @KeyGuid uniqueidentifier 
        SET @KeyGuid = key_guid('key_Indexing')
        -- Open the encryption key
        -- Make sure the key is closed before doing any operation 
		-- that may end the module, otherwise the key will	
		-- remain opened after the store-procedure execution ends
        OPEN SYMMETRIC KEY key_Indexing DECRYPTION BY CERTIFICATE cert_ProtectIndexingKeys
        -- The new MAC key is derived from an encryption 
		-- of a newly created GUID. As the encryption function 
		-- is not deterministic, the output is random 
        -- After getting this cipher, we calculate a SHA1 Hash for it.
        SELECT @Key = HashBytes( N'SHA1', ENCRYPTBYKEY( @KeyGuid, convert(varbinary(100), newid())) )
		-- Protect the new MAC key 
        SET @KEY = ENCRYPTBYKEY( @KeyGuid, @Key )
        -- Closing the encryption key
        CLOSE SYMMETRIC KEY key_Indexing 
        -- As we have closed the key we opened, 
        -- it is safe to return from the SP at any time
        if @Key is null
        BEGIN
               RAISERROR( 'Failed to create new key.', 16, 1)
        END
        INSERT INTO t_MacIndexKeys VALUES( @Table_id, @Key )
GO

--- Create a new MAC key for the authors table
DECLARE @objid int
SET @objid = object_id('authors') 
EXEC AddMacForTable @objid
GO

SELECT * FROM t_MacIndexKeys
GO

-- update the existing data to be indexible on Phone MAC
UPDATE dbo.authors set phone_mac = dbo.MAC(phone,object_id('authors'))
GO

SELECT au_id, phone, phone_mac FROM authors
GO

-- Intercept the inserts and make sure the inserted data is properly generated
CREATE TRIGGER trig_ProtectPhone on dbo.authors
INSTEAD OF INSERT 
AS
        declare @mac varbinary(max)
        declare @KeyGuid uniqueidentifier
        declare @Cipher nvarchar(60)
        if( select count(*) from inserted where phone is null ) > 0
               RAISERROR( 'Cannot store null as protected data. ', 16, 1)
        ELSE
           BEGIN
			OPEN SYMMETRIC KEY acct_key DECRYPTION BY certificate acct_cert
			OPEN SYMMETRIC KEY sales_key DECRYPTION BY certificate sales_cert
			SET @KeyGuid = key_guid('acct_key')
           -- get the MAC for the phone
           SELECT @mac = dbo.MAC( phone,object_id('authors') ) from inserted
           if( @mac is null OR @KeyGuid is null OR ENCRYPTBYKEY(Key_GUID('acct_key'),'test') is null )
                   BEGIN
					CLOSE SYMMETRIC KEY acct_key 
		            CLOSE SYMMETRIC KEY sales_key 
		            RAISERROR( 'Cannot Insert protected data. Either the encryption or indexing keys are not available or the indexing key is not valid for MAC generation.', 16, 1)
                   END
           ELSE
                   INSERT INTO dbo.authors select au_id, au_lname, au_fname,
					phone, address, city, state, zip, contract, ssn, login_name,
					login_password, bat_phone, commission, 
					encryptbykey(key_guid('acct_key'),ssn),
					encryptbykey(key_guid('sales_key'),bat_phone), 
					encryptbykey(key_guid('acct_key'),CONVERT(varchar(max),commission), 1, au_id),
					password_salt, password_hash, ae_ssn, ae_bat_phone, ext_ssn, ext_bat_phone,
					@mac FROM inserted
					CLOSE SYMMETRIC KEY acct_key 
		            CLOSE SYMMETRIC KEY sales_key 
        END
GO

SELECT * FROM authors WHERE au_lname = 'Adams'

INSERT INTO authors (au_id, au_lname, au_fname, phone, address, city, state, zip, 
	contract, ssn, login_name, login_password, bat_phone, commission)
	VALUES ('111-11-1111', 'Adams', 'Douglas', '999 999-9999', 'Somewhere', 
	'The Universe', '', '11111', 1, '111-11-1111', 'iasimov', 'password', 
	'888 888-8888',10)

SELECT * FROM authors WHERE au_lname = 'Adams'
	
INSERT INTO authors (au_id, au_lname, au_fname, phone, address, city, state, zip, 
	contract, ssn, login_name, login_password, bat_phone,commission)
	VALUES ('222-22-2222', 'Adams', 'Douglas', '999 999-9999', 'Somewhere', 
	'The Universe', '', '11111', 1, '111-11-1111', 'iasimov', 'password', 
	'888 888-8888',10)

/*
	note that the encrypted phone is different in both rows due to nondeterministic 
	encryption but that the MAC value is deterministic
*/
SELECT * FROM authors WHERE au_lname = 'Adams'

exec dbo.SearchForAuthor '999 999-9999'


GO

-- alter the search sproc to search on the MAC
ALTER  PROCEDURE dbo.SearchForAuthor
	@phone varchar(20)
AS
	SELECT au_fname, au_lname, address, city, state, zip, phone, 
		CONVERT(varchar, DECRYPTBYKEYAUTOCERT(CERT_ID('sales_cert'),null,enc_bat_phone)) AS bat_phone,
		CONVERT(varchar, DECRYPTBYKEYAUTOCERT(CERT_ID('acct_cert'),null,enc_ssn)) AS ssn
		FROM dbo.authors
		WHERE phone_mac = dbo.MAC(@phone,object_id('authors'))
GO

exec dbo.SearchForAuthor '999 999-9999'

	
-- now we can drop the unencrypted columns
ALTER TABLE dbo.authors DROP COLUMN ssn
ALTER TABLE dbo.authors DROP COLUMN bat_phone
ALTER TABLE dbo.authors DROP COLUMN commission
GO
-- and update our trigger to account for the dropped columns
ALTER TRIGGER trig_ProtectPhone on dbo.authors
INSTEAD OF INSERT 
AS
        declare @mac varbinary(max)
        declare @KeyGuid uniqueidentifier
        declare @Cipher nvarchar(60)
        if( select count(*) from inserted where phone is null ) > 0
               RAISERROR( 'Cannot store null as protected data. ', 16, 1)
        ELSE
           BEGIN
			OPEN SYMMETRIC KEY acct_key DECRYPTION BY certificate acct_cert
			OPEN SYMMETRIC KEY sales_key DECRYPTION BY certificate sales_cert
			SET @KeyGuid = key_guid('acct_key')
           -- get the MAC for the phone
           SELECT @mac = dbo.MAC( phone,object_id('authors') ) from inserted
           if( @mac is null OR @KeyGuid is null OR ENCRYPTBYKEY(Key_GUID('acct_key'),'test') is null )
                   BEGIN
					CLOSE SYMMETRIC KEY acct_key 
		            CLOSE SYMMETRIC KEY sales_key 
		            RAISERROR( 'Cannot Insert protected data. Either the encryption or indexing keys are not available or the indexing key is not valid for MAC generation.', 16, 1)
                   END
           ELSE
                   INSERT INTO dbo.authors select au_id, au_lname, au_fname,
					phone, address, city, state, zip, contract, login_name,
					login_password, 
					enc_ssn,
					enc_bat_phone, 
					enc_commission,
					password_salt, password_hash, ae_ssn, ae_bat_phone, ext_ssn, ext_bat_phone,
					@mac FROM inserted
					CLOSE SYMMETRIC KEY acct_key 
		            CLOSE SYMMETRIC KEY sales_key 
        END
GO

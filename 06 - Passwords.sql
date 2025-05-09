USE pubs

select * from authors

-- since we are going to salt the password values we need to generate a unique salt value per row
UPDATE authors set password_salt = NEWID()

select * from authors
GO
--DROP FUNCTION dbo.StretchedHash

CREATE FUNCTION dbo.StretchedHash(@data nvarchar(max), @salt nvarchar(max))
	RETURNS varbinary(max)
AS
BEGIN
	DECLARE @ret varbinary(max)
	DECLARE @stretch int = 1000
	SET @ret = HashBytes(N'SHA2_512', convert(varbinary(8000), @salt + @data))
	DECLARE @loop int = 0
	WHILE @loop < @stretch
	BEGIN 
		SET @ret = HashBytes(N'SHA2_512', @ret)
		SET @loop = @loop + 1
	END
	RETURN @ret
END
GO

-- store the salted and stretched hash of a password, it is used to store proof that a user knows a password without storing the password in a reversible form
-- stretching the hash (running the results through multiple hashing steps) is a recommended practice
UPDATE authors SET password_hash =  dbo.StretchedHash(login_password, CONVERT(char(36), password_salt))

PRINT HashBytes(N'SHA2_512', convert(varbinary(8000), 'test'))
PRINT HashBytes(N'SHA2_512', convert(varbinary(8000), 'test'))

-- note that due to the salt even identical passwords hash to different values
select * from authors

GO


-- now add the managed function

EXEC sp_configure 'show advanced options' , '1';
go
reconfigure;
go
EXEC sp_configure 'clr enabled' , '1'
go
reconfigure;
-- Turn advanced options back off
EXEC sp_configure 'show advanced options' , '0';
go

CREATE ASSEMBLY ManagedCrypto FROM 'C:\src\sqlcrypto\CryptoApplications\ManagedCrypto\bin\Debug\ManagedCrypto.dll';
GO

CREATE FUNCTION dbo.SecureHash(@value nvarchar(max), @salt nvarchar(max), @HashType nvarchar(max)) 
	RETURNS varbinary(max)
	AS EXTERNAL NAME ManagedCrypto.UserDefinedFunctions.SecureHash; 
GO

CREATE FUNCTION dbo.VerifyHash(@value nvarchar(max), @salt nvarchar(max), @HashType nvarchar(max), @hashValue varbinary(max))
	RETURNS bit
	AS EXTERNAL NAME ManagedCrypto.UserDefinedFunctions.VerifyHash
GO

UPDATE authors SET password_hash =  dbo.SecureHash(login_password, CONVERT(nvarchar(max), password_salt), 'BCRYPT')
GO

SELECT * FROM authors
GO

ALTER FUNCTION dbo.LoginAuthor(@username varchar(255),	@password varchar(255))
RETURNS bit
AS
BEGIN
	DECLARE @retval bit
	SELECT @retval = COUNT(*) FROM dbo.authors WHERE login_name = @username AND 
		dbo.VerifyHash(@password, CONVERT(nvarchar(max), password_salt), 'BCRYPT', password_hash) = 1
	RETURN @retval
END
GO

select * from authors

ALTER TABLE dbo.Authors DROP COLUMN login_password
GO

print dbo.LoginAuthor('jwhite', 'test')
print dbo.LoginAuthor('jwhite', 'password')
print dbo.LoginAuthor('jwhe', 'test')

select * from authors

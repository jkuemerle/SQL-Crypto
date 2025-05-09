USE pubs

-- DMV for TDE keys
select * from sys.dm_database_encryption_keys

-- this will not work, we don't yet have the proper keys in place to allow it to function
ALTER DATABASE pubs SET ENCRYPTION ON

USE master
-- create a certificate here to be used to encrypt the database encryption key (DBEK) below, TDE requires a master key in the master database
CREATE MASTER KEY ENCRYPTION BY password = 'Master_MasterKey1$abcdefg12345!@#$%^'
select * from sys.symmetric_keys

-- the usual, create a certificate to encrypt the symmetric DBEK
CREATE CERTIFICATE dbek_cert AUTHORIZATION dbo WITH SUBJECT = 'pubs DBEK cert'

-- back up the certificate
BACKUP CERTIFICATE dbek_cert TO FILE = 'c:\temp\cert' WITH PRIVATE KEY (FILE = 'c:\temp\key', ENCRYPTION BY PASSWORD = 'Password1!abcd1234#')

USE pubs

-- now we can create the DBEK which will be stored in the database but protected by the certificate in master
CREATE DATABASE ENCRYPTION KEY WITH ALGORITHM = AES_256 
	ENCRYPTION BY SERVER CERTIFICATE dbek_cert

 
select * from sys.dm_database_encryption_keys

-- once we execute the next line all data pages and log files will be encrypted, if a database is encrypted then tempdb will also be encrypted.  
ALTER DATABASE pubs SET ENCRYPTION ON

	
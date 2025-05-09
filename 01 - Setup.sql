
USE pubs
GO

-- update pubs to have some more sensitive information

ALTER TABLE dbo.authors ADD ssn varchar(12)
GO

ALTER TABLE dbo.authors ADD login_name nvarchar(20)
GO 

ALTER TABLE dbo.authors ADD login_password varchar(20)
GO

ALTER TABLE dbo.authors ADD bat_phone varchar(20)
GO 

ALTER TABLE dbo.authors ADD commission numeric(10,4) 
GO

UPDATE dbo.authors SET ssn = au_id, bat_phone = phone,
	login_name = LOWER(SUBSTRING(au_fname,1,1)) + LOWER(au_lname),
	login_password = 'test', commission = 5
GO

UPDATE dbo.authors SET commission = 7 where au_id in ('527-72-3246')

-- create accounts that have access to sensitive data
CREATE LOGIN acct WITH PASSWORD = 'Password1!ABCDEF123456!@#$%'

CREATE LOGIN sales WITH PASSWORD = 'Password2!ABCDEF123456!@#$%'

CREATE LOGIN web WITH PASSWORD = 'Password3!ABCDEF123456!@#$%'

CREATE USER acct

CREATE USER sales

CREATE USER web

GRANT SELECT, INSERT ON authors TO acct, sales, web
GO

-- add the sprocs that our applications will use
CREATE PROCEDURE dbo.ListAuthors
AS
	SELECT au_fname, au_lname, address, city, state, zip, phone, bat_phone, ssn, commission FROM dbo.authors
GO

GRANT EXECUTE ON dbo.ListAuthors TO acct, sales
GO


CREATE PROCEDURE dbo.SearchForAuthor
	@phone varchar(12)
AS
	SELECT au_fname, au_lname, address, city, state, zip, phone, bat_phone, ssn, commission FROM dbo.authors
		WHERE phone = @phone
GO

GRANT EXECUTE ON dbo.SearchForAuthor TO acct
GO


CREATE FUNCTION dbo.LoginAuthor(@username varchar(255),	@password varchar(255))
RETURNS bit
AS
BEGIN
	DECLARE @ret bit
	SELECT @ret = COUNT(*) FROM dbo.authors WHERE login_name = @username AND login_password = @password
	RETURN @ret
END
GO

GRANT EXECUTE ON dbo.LoginAuthor TO web
GO

CREATE FUNCTION dbo.GetAuthorID(@login_name varchar(255))
RETURNS varchar(11)
AS
BEGIN
	DECLARE @ret varchar(11)
	SELECT TOP 1 @ret = au.au_id FROM dbo.authors AS au WHERE au.login_name = @login_name 
	RETURN @ret
END
GO

GRANT EXECUTE ON dbo.GetAuthorID TO web
GO

CREATE PROCEDURE SalesByAuthor 
	@au_id varchar(11)
AS
BEGIN
	SELECT t.title, SUM(s.qty) AS sold
		FROM sales AS s 
		INNER JOIN titles AS t on s.title_id = t.title_id
		INNER JOIN titleauthor AS ta on ta.title_id = t.title_id
		WHERE ta.au_id = @au_id
		GROUP BY s.title_id, t.title
END
GO

GRANT EXECUTE ON dbo.SalesByAuthor TO web
GO

CREATE PROCEDURE dbo.GetAuthor 
	@au_id varchar(11)
AS
BEGIN
	SELECT au_id, au_fname, au_lname
	--, bat_phone
	FROM dbo.authors
	WHERE au_id = @au_id
END
GO

GRANT EXECUTE ON dbo.GetAuthor TO web
GO

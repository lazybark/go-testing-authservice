# go-testing-authservice

Many things i would've done in different way if it was real project ( for example: proper logger, more complicated user models and ORM).

Also, tests are little bit slow as i can't run them in parallel due to function name placeholders being replaced in some tests. Didn't had time to make more complicated structure: in real-world app it would be done in more flexible way.

How it works:

`make` or `make RUN`: start service with 8080 HTTP and 9090 RPC.

`make TEST`: run tests (current coverage ~93.2% overall).

## Endpoints

.proto file: `./pkg/api/grpc/user_reg.proto`

### Register user
```
http://localhost:8080/api/users/register

{
    "login":string,
    "password":string,
    "first_name":string,
    "last_name":string (optional),
    "email":string
}
```
### Login
```
http://localhost:8080/api/users/login
{
    "login":"login1",
    "password":"password"
}
```
Returns:
```
{
  "success":bool,
  "status":int,
  "response":
    {
      "auth_token":string,
      "refresh_token":string
    }
}
```  

`auth_token` can not be used to refresh, only `refresh_token`

### Check token
http://localhost:8080/api/users/check_token/{token}
```
{
  "success":bool,
  "status":int,
  "response":string
}
```  
### Get new auth token
http://localhost:8080/api/users/get_token
```
http://localhost:8080/api/users/login
{
    "token":string (should be only refresh token)
}
```

Response
```
{
  "success":bool,
  "status":int,
  "response":
    {
      "auth_token":string,
      "refresh_token":string
    }
}
```  

## Regarding datastorage

There was generally two ways to go without ORM:
* using string builder like github.com/huandu/go-sqlbuilder + struct tags
* or using simple hardcoded SQL code

I did both, but as it was requested, leaving just hardcoded SQL in the migrator.

How would it look with tags:
* using tag named default + struct field type & name
* then using sqlbuilder to convert this data into actual SQL code
* lots of pain, waste of time and not readable code guaranteed

Just leaving not finished example here:

```
type sqlField struct {
	name         string
	valueType    string
	defaultValue string
}

func getStructSQLParameters(model any) []sqlField {
	t := reflect.TypeOf(model)

	var fields []sqlField // Can't know how many fields will be exported and non-empty, so no defined size
	var f sqlField

	for i := 0; i < t.NumField(); i++ {
		tagDefault := t.Field(i).Tag.Get("default")

		if !t.Field(i).IsExported() {
			continue
		}

		f = sqlField{
			name:      stringy.New(t.Field(i).Name).SnakeCase("?", "").ToLower(), // Convert from Camel to Snake
			valueType: t.Field(i).Type.String(),
		}

		if tagDefault != "" && tagDefault != "-" {
			f.defaultValue = tagDefault
		}
		fields = append(fields, f)

	}

	return fields
}
```


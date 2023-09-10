# go-testing-authservice

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




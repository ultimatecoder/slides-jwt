class: middle, center

#Token Based Authentication system using JWT
By Jaysinh Shukla


---
### Speacker Description

  .center[![Speaker Image](images/jaysinh_shukla.jpg)]

  * **Role:** Fullstack developer

  * **Github:** http://github.com/ultimatecoder, http://github.com/jsh-odoo

  * **Twitter:** [@jaysinhp](https://twitter.com/jaysinhp)

  * **Emai:** [jaysinhp@gmail.com](mailto:jaysinhp@gmail.com)

  * **IRC:** thebigj


---
background-image: url(images/me.gif)
### My Expression after describing info


---
## Types of Authentication

  * **Session / Cookie Authentication**

  * **Token Authentication**


---

background-image: url(images/session_authentication_multiple_user.svg)
### Session Authentication for Multiple User


---

background-image: url(images/poor_session_authentication.gif)
### Session authentication at high load


---
### Disadvantages of Session Authentication

  * Difficult to handle with
  [Load balancer][1]

  * Required high amount of resource(RAM without mass-storage) for maintaining
  huge amount of user session parallaly.

  [1]: https://en.wikipedia.org/wiki/Load_balancing_(computing)

  * [CORS](https://developer.mozilla.org/en-US/docs/Web/HTTP/Access_control_CORS)
  doesn't work well with cookies


---
### Birth of Token Authentication

  * Token based authentication are most popular authentication system for APIs.

  * Comparatively puts less load than **Session authentication**.

  * Best for

    * Scaling

    * Load balancer

  * No **cookie**, No [CSRF](https://en.wikipedia.org/wiki/Cross-site_request_forgery)
  protection.

  * Same API, Authentication will be used for Mobile and Front end app.


---

background-image: url(images/Normal_token_authentication.svg)


---
### Example of authentication at Djnago Rest Framework

```python
from rest_framework.authtoken.models import Token

token = Token.objects.create(user=...)
print token.key
```

Above code is used at authentication view where that **token.key** is returned
if credentials are right.

Assuming random output **9944b09199c62bcf9418ad846dd0e4bbdfc6ee4b**

**Example of Client request using [curl](https://curl.haxx.se/)**

```bash
curl -X GET http://127.0.0.1:8000/api/example/ -H 'Authorization: Token 9944b09199c62bcf9418ad846dd0e4bbdfc6ee4b'
```


---
### Example of Token Authentication at Django Rest Framework


```python
@python_2_unicode_compatible
class Token(models.Model):
    """
    The default authorization token model.
    """
    key = models.CharField(_("Key"), max_length=40, primary_key=True)
    user = models.OneToOneField(
        settings.AUTH_USER_MODEL, related_name='auth_token',
        on_delete=models.CASCADE, verbose_name=_("User")
    )
    created = models.DateTimeField(_("Created"), auto_now_add=True)

    class Meta:
        verbose_name = _("Token")
        verbose_name_plural = _("Tokens")

    def save(self, *args, **kwargs):
        if not self.key:
            self.key = self.generate_key()
        return super(Token, self).save(*args, **kwargs)

    def generate_key(self):
        return binascii.hexlify(os.urandom(20)).decode()
```


---
background-image: url(images/token_authentication_after_code.gif)
### Is it right solution?


---

#Problems, Problems every where...


---
### Solution is awesome JWT!

  * Suggested pronunciation is "jot".

  * JSON Web Token is JSON based Web Authentication Token.

  * The token is a combination of three parts. Header, Claim set and Signature.

  * Each part of authentication token is encoded with
  [base64url](https://en.wikipedia.org/wiki/Base64) encoding and seperated with **"."**


---
background-image: url(images/JWT_token_authentication.svg)


---
### Structure Of JSON Web Token


  ```base
  eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4
  MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K2
  7uhbUJU1p1r_wW1gFWFOEjXk
  ```

  * The token is containing three different part seperated with **"."**

  * Each part is encoded with [base64url](https://en.wikipedia.org/wiki/Base64) encoding.

  * The first part the .red[Red Part] is **JOSE Header**

  * The second part the .blue[Blue Part] is **JWT Claim set**

  * The third part the .green[Green Part] is **JWT Signature**

  * **Base64URL(JOSE Header).Base64URL(JWT Claims).Base64URL(JWT Signatuer)**


---
### JOSE Header

  ```base
  eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9
  ```

  * Decoded with Base64 encoding:

  ```json
    {
      "typ":"JWT",
      "alg":"HS256"
    }
  ```

  * Here,
    * **typ** defines type of the JSON Web Token. It is not optional.

    * **alg** represents type of algorithm used for signing the claim set.


---
### JWT Claim-set

  ```bash
  eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ
  ```

  * Decoding with Base64 encoding:

  ```json
    {
      "iss":"joe",
      "exp":1300819380,
      "is_root":true
    }
  ```

  * Here,

    * **iss** is registered claim. It represents the name of Issuer of the token

    * **exp** is registered claim. It represents expiration time in format of
    [Unix time](https://en.wikipedia.org/wiki/Unix_time)

    * **is_root** is unregistred claim. User defined claim which can be presumed
    that it is considring user as root user.


---
### JWT Signature

  ```bash
  dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk
  ```

  * Signature is MAC of encoded JOSE Header and encoded JWS Payload
   with the HMAC SHA-256 algorithm.

  * And then base64url encoding of that HMAC value.

  * This signature helps to verify the authenticity of the **Token**.


---
background-image: url(images/introduction_jwt.gif)
### How JWT looks


---
# Demo


---
### JWT Authentication at Django

```python
from django.contrib.auth import authenticate


class Login(View):

    def post(self, request, *args, **kwargs):
        username = request.POST.get('username')
        password = request.POST.get('password')
        user = authenticate(username=username, password=password)

        if user:
            payload = {
                'id': user.pk,
                'username': user.username,
                'staff': user.is_staff,
                'exp': datetime.utcnow() + EXPIRY_TIME
            }
            token = {'token': jwt.encode(payload, SECRET)}
            return HttpResponse(
              json.dumps(token),
              content_type="application/json"
            )
        else:
            return HttpResponse(
              json.dumps({'Error': "Invalid credentials"}),
              status=400,
              content_type="application/json"
            )
```


---
### JWT Token Verification at Django

```python
class JWT_AuthMiddleware(object):

    def _get_token(request=None):
        return request.META.get('HTTP_AUTHORIZATION') or request.GET.get('token')

    def process_request(self, request):
        token = self._get_token(request)
        try:
            payload = jwt.decode(token, SECRET)
            request.user = User.objects.get(
                username=payload.get('username'),
                pk=payload.get('id'),
                is_active=True
            )
        except jwt.ExpiredSignature, jwt.DecodeError, jwt.InvalidTokenError:
            return HttpResponse({'Error': "Token is invalid"}, status="403")
        except User.DoesNotExist:
            return HttpResponse({'Error': "Internal server error"}, status="500")
```


---
### Still it is not over!

  * If user is logged out, then also the token will be accepted until it is
  expired by time.

  * For Example, We assigned the token to "X" user and assigned the expire time
  to next 3 days and user is logged out after 1 day, that token can be
  used by attacker for that unused 2 days and API will consider **Token** as
  valid.

  * As a best practice, set expiry time not longer than **10 minutes**!

  * As a good practice keep less values in claim. Adding many claims may
  increase size of token which takes time to transfer the token.

  * Change your **Secret key** periodically and Black list tokens if possible.


---
### What we are doing with JWT

  * Creating JWT token

  * Validating **Token** at every request.

  * Allowing user to **refresh token** if given **Token** is valid.

  * If user is logging out then creating entry of token to **Black list** table

  * Advantage:

    * Token will not be used further if it is **Black listed** even in the
    valid time frame.


---

background-image: url(images/Our_token_authentication.svg)


---
### JWT Claims

  * Types of Claims

    1 Registered Claim Names

    2 Public Claim Names

    3 Private Claim Names


---
### JWT Registered Claim names

  * **iss:** Dipicting Issuer of the token

  * **sub:** Subject of the Token

  * **aud:** Audiance for which token is given for

  * **exp:** Expiration time in Unix time.

  * **nbf:** Token should not be accepted before this value. In Unix time format

  * **iat:** Representing age of the token

  * **jti:** Dipicting ID of the token


---
### JWT Public Claim names

  * It can be defined by fellows using JWT on condition that they have to
  register this claim at [IANA "JSON Web Token Claims" registry](http://www.iana.org/assignments/jwt/jwt.xhtml)


---
### JWT Private Claim names

  * Custom claims which are not publicly used but represented as claims in JWT.

  * This custom claims should be considered as private claims.


---
### Similar Technologies

1 [Simple Web Token](https://msdn.microsoft.com/library/azure/hh781551.aspx)

2 [JSON Simple Singh](https://jsonenc.info/jss/1.0/)


---
# Why not to go with Oauth 2.0?


---
### References

  * https://en.wikipedia.org/wiki/Session_(computer_science)

  * https://tools.ietf.org/html/rfc7519

  * https://auth0.com/blog/2014/01/07/angularjs-authentication-with-cookies-vs-token/

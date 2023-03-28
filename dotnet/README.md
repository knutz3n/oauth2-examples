# OAuth2 .NET examples

This demonstrate how a client assertion can be created with .NET Framework 4.8
in order to authenticate a client according to https://www.rfc-editor.org/rfc/rfc7521#section-4.2.

It is only show the bare minimum and proper key handling should be
implemented in any production system.

## .NET Framework 4.8 example

Generate a private key and a pfx certificate file as follows:

```
# 1. Generate private key and a dummy certificate
openssl req -newkey rsa:4096 -keyout private.key -x509 -days 3650 -out certificate.crt

# 2. Export the private key and certificate to a pfx file
openssl pkcs12 -inkey private.key -in certificate.crt -export -out certificate.pfx
```

On Linux, this example can be run using Microsoft's .NET on Linux (https://learn.microsoft.com/en-us/dotnet/core/install/linux) and run the following command:
```
$ dotnet run
```

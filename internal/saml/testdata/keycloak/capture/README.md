# Recording Keycloak responses

The files beside this directory are SAML responses from a real Keycloak,
answering requests Quilzo made. `keycloak_test.go` checks them on every test
run; this is how to record them again. Docker, Node with `playwright-core`
and a Chromium are needed; nothing here runs during a build.

1. Start Keycloak (a fresh admin password each time; it is never kept):

       docker run -d --name qz-keycloak -p 127.0.0.1:8080:8080 \
         -e KC_BOOTSTRAP_ADMIN_USERNAME=admin -e KC_BOOTSTRAP_ADMIN_PASSWORD=... \
         quay.io/keycloak/keycloak:26.8.0 start-dev

2. With `kcadm.sh` inside the container: a realm `northwind`; a user `dana`
   with the email `dana.reyes@northwind.example` and a password; and one
   SAML client per way of signing, with client ID
   `http://127.0.0.1:18780/saml/kc-NAME`, assertion consumer URL
   `http://127.0.0.1:18780/saml/kc-NAME/acs`, `saml.client.signature=false`,
   name ID format `email`, exclusive canonicalisation, and:

   | NAME   | saml.server.signature | saml.assertion.signature | algorithm  |
   |--------|-----------------------|--------------------------|------------|
   | doc    | true                  | false                    | RSA_SHA256 |
   | assert | false                 | true                     | RSA_SHA256 |
   | both   | true                  | true                     | RSA_SHA256 |
   | rsa512 | false                 | true                     | RSA_SHA512 |

   Keycloak 26.8 cannot sign SAML with ECDSA (its SignatureAlgorithm enum
   has no ECDSA entry); the JDK fixtures in `internal/xmldsig/testdata`
   cover ECDSA instead.

3. Record:

       curl -s http://127.0.0.1:8080/realms/northwind/protocol/saml/descriptor > ../descriptor.xml
       go run ./internal/saml/testdata/keycloak/capture ../descriptor.xml > requests.txt
       CHROMIUM=/path/to/chrome node capture.js requests.txt password-file ..

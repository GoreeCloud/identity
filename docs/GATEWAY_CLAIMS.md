GoreeCloud Identity — Gateway CI Claims

This document describes a test-only Keycloak authorization-code client that checks the signed access-token claims expected by the GoreeCloud Gateway read-only API. It does not configure or deploy Gateway.

The test creates one temporary CI user and limited client scope. It requires the signed audience goreecloud-gateway-console, scope gateway:read, realm role gateway-reader, and tenant family. The checked-in realm stays unchanged. Run status must be verified before claiming success.

Remaining requirements are production authorization review, online revocation, independent application acceptance, and browser/Android integration. See GoreeCloud/identity issue 2 and GoreeCloud/gateway issue 14.

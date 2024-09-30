# CSC-IP Client

This package provides a `cscip-client` command line tool to interface with
Copernicus Space Component Interface delivery Points, which are web api
services based on a limited implementation of the OData standard.

Although formally not a CSC-IP interface, this client can also be used for the
[CDSE OData API](https://documentation.dataspace.copernicus.eu/APIs/OData.html).

Some example invocations of `cscip-client`:

    cscip-client query cdse -n S1A_AUX_PP2

    cscip-client download cdse -n S1A_AUX_PP2_V20140908T000000_G20240612T131553.SAFE

    cscip-client query cdse -f "startswith(Name,'S5P_OFFL_L2__NO2__') and ContentDate/Start ge 2023-01-01T00:00:00.000Z and ContentDate/Start lt 2023-01-02T00:00:00.000Z"

    cscip-client download cdse -i 992456e2-c6f5-597f-b2fe-c4cb5a5ffff9

    cscip-client query cdse -n S2A_MSIL1C_20240318T082651_N0510_R021_T37UFS_20240318T091415 -m
    cscip-client query cdse -i a65f39fa-78c9-41b2-a9d1-447612cec132 -m -a


The tool requires a json configuration file that contains the end point urls
and authentication information for each interface that you want to use.
The format of this file is based on the [muninn](https://github.com/stcorp/muninn>)
credentials file format. For example:

    {
      "https://catalogue.dataspace.copernicus.eu/odata/v1/": {
        "id": "cdse",
        "auth_type": "oauth2",
        "grant_type": "ResourceOwnerPasswordCredentialsGrant",
        "username": "XXXXXXXX",
        "password": "XXXXXXXX",
        "client_id": "cdse-public",
        "client_secret": "",
        "token_url": "https://identity.dataspace.copernicus.eu/auth/realms/CDSE/protocol/openid-connect/token",
        "reuse_auth_on_redirect": true
      },
      "https://public-service.example.com/odata/v1/": {
        "id": "example1"
      }
      "https://basic-auth-service.example.com/odata/v1/": {
        "id": "example2",
        "username": "XXXXXXXX",
        "password": "XXXXXXXX"
      }
      "https://oauth2-service.example.com/odata/v1/": {
        "id": "example3",
        "auth_type": "oauth2",
        "grant_type": "ResourceOwnerPasswordCredentialsGrant",
        "username": "XXXXXXXX",
        "password": "XXXXXXXX",
        "client_id": "XXXXXXXX",
        "client_secret": "XXXXXXXX",
        "token_url": "https://oauth2-service.example.com/getAuthToken"
      }
    }

The `id` field in each entry is the id that should be passed as `interface`
argument to `cscip-client`.

The `reuse_auth_on_redirect` option is a CSCS-IP client specific option that
will force a reuse of the authentication settings when a download request
results in a redirect to a different domain (this is specifically needed for
the CDSE interface).

A reference to the credentials file can be set with the `CSCIP_CLIENT_CONFIG`
environment variable or passed via the command line via the `-c` option.

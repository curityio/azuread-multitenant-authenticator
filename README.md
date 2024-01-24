## Azure Multitenant OIDC Plugin


This plugin is a variation of the OIDC plugin provided with the Curity Identity Server, allowing to connect with Azure AD with multiple tenants. 
The configuration is similar but simplified to only accommodate the Microsoft's requirements. 
Namely, there is no support for encrypted ID Tokens and signed Userinfo responses. 
Also, there are several configuration options that are omitted because they are static when federating to Azure.


### Compiling the Plug-in from Source

To compile the plugin use the following command `./gradlew jar`

The resulting JAR file will be located in the ``build/libs`` directory and be named ``azure-multitenant-authenticator-X.X.X.jar``.

The plugin has one extra dependency that needs to be installed, `jose4j-0.9.3.jar`.  

### Installation

To install this plug-in, either download a binary version available from the [releases](https://github.com/curityio/azuread-multitenant-authenticator/releases) section of this project's GitHub repository or compile it from source (as described above).

Copy the JAR and its dependencies in the directory ``${IDSVR_HOME}/usr/share/plugins/azuread-multitenant`` on each Curity node. (The name of the last directory, ``azuread-multitenant``, which is the plug-in group, is arbitrary and can be anything.) After doing so, the plug-in will become available as soon as the node is restarted.

The `jose4j` JAR can be either copied from  ``${IDSVR_HOME}/lib/`` or you can run `./gradlew copyDependencies` to have it located in the ``build/libs`` directory.


> [!IMPORTANT]
> The JAR and its dependencies needs to be deployed to each run-time node and the admin node.

### Configuration Reference

- allowed-tenant-ids: List of Azure Tenant IDs that are accepted for login[^1] 
- client-id: The OAuth 2 client ID that is registered at the OP
- client-secret: The OAuth 2 client secret that is registered at the OP
- clock-skew: The allowed clock-skew in seconds when validating the JWT from the OP
- scope: The scopes to ask the OP for as a space-separated list
- fetch-user-info The authenticator can be configured to fetch additional claims from the Userinfo endpoint of the OpenID provider.
- prompt-login: Setting controlling sending of prompt=login parameter. By default, it is not sent.
- use-subject-for-login-hint: If enabled and there is a previously authenticated subject, pass the subject as login_hint to the OpenID Server.

[^1]: This option will be replaced with an API call in the next release of the plugin.

### License

This plugin and its associated documentation is listed under the `Apache 2 license <LICENSE>`_.

### More Information

Please visit [curity.io](https://curity.io/) for more information about the Curity Identity Server.

Copyright (C) 2024 Curity AB.
/*
 *  Copyright 2024 Curity AB
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package io.curity.azuread.config;

import se.curity.identityserver.sdk.config.Configuration;
import se.curity.identityserver.sdk.config.annotation.*;
import se.curity.identityserver.sdk.service.Json;
import se.curity.identityserver.sdk.service.SessionManager;
import se.curity.identityserver.sdk.service.WebServiceClientFactory;
import se.curity.identityserver.sdk.service.authentication.AuthenticatorExceptionFactory;
import se.curity.identityserver.sdk.service.authentication.AuthenticatorInformationProvider;

import java.util.List;
import java.util.Optional;

@SuppressWarnings("InterfaceNeverImplemented")
public interface AzureAdMultitenantAuthenticatorAuthenticatorPluginConfig extends Configuration
{
    @Description("The client-id, registered at the OpenID server")
    String getClientId();

    @Description("The client-secret (client-secret-post), registered at the OpenID server")
    String getClientSecret();

    @DefaultBoolean(false)
    @Description("Fetch claims from the userinfo endpoint")
    Boolean fetchUserInfo();

    @DefaultBoolean(false)
    @Description("If there is a previously authenticated subject, pass the subject as login_hint to the OpenID Server.")
    Boolean useSubjectForLoginHint();

    @DefaultEnum("NEVER")
    PromptLogin getPromptLogin();

    enum PromptLogin
    {
        ALWAYS, IF_REQUESTED, NEVER
    }

    @Description("The Authentication Context Class Reference (ACR) or authentication method that should be sent in the request to the OpenID Server")
    @Name("authentication-context-class-reference")
    Optional<String> getAcr();

    @DefaultString("openid")
    @Description("Scope to ask the OpenID server for, space separated")
    String getScope();

    @DefaultInteger(60)
    @Description("The allowed clock-skew in seconds when validating the JWT from the OpenID Server")
    Integer getClockSkew();

    SessionManager getSessionManager();

    AuthenticatorExceptionFactory getExceptionFactory();

    AuthenticatorInformationProvider getAuthenticatorInformationProvider();

    WebServiceClientFactory getWebServiceClientFactory();

    @Description("List of Tenant IDs that the users are allowed to authenticate with. " +
            "To be replaced with a call to an external API")
    List<String> getAllowedTenantIds();

    Json getJson();
}

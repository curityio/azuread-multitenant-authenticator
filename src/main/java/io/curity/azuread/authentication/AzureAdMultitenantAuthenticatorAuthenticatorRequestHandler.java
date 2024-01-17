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

package io.curity.azuread.authentication;

import io.curity.azuread.config.AzureAdMultitenantAuthenticatorAuthenticatorPluginConfig;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import se.curity.identityserver.sdk.attribute.Attribute;
import se.curity.identityserver.sdk.authentication.AuthenticatedState;
import se.curity.identityserver.sdk.authentication.AuthenticationResult;
import se.curity.identityserver.sdk.authentication.AuthenticatorRequestHandler;
import se.curity.identityserver.sdk.http.RedirectStatusCode;
import se.curity.identityserver.sdk.service.ExceptionFactory;
import se.curity.identityserver.sdk.service.authentication.AuthenticationRequirements;
import se.curity.identityserver.sdk.service.authentication.AuthenticatorInformationProvider;
import se.curity.identityserver.sdk.web.Request;
import se.curity.identityserver.sdk.web.Response;

import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import static io.curity.azuread.authentication.RedirectUriUtil.createRedirectUri;

public final class AzureAdMultitenantAuthenticatorAuthenticatorRequestHandler implements AuthenticatorRequestHandler<Request>
{
    private static final Logger _logger = LoggerFactory.getLogger(AzureAdMultitenantAuthenticatorAuthenticatorRequestHandler.class);
    private static final String AUTHORIZATION_ENDPOINT = "https://login.microsoftonline.com/organizations/oauth2/v2.0/authorize";
    private final AzureAdMultitenantAuthenticatorAuthenticatorPluginConfig _config;
    private final AuthenticatorInformationProvider _authenticatorInformationProvider;
    private final ExceptionFactory _exceptionFactory;
    private final AuthenticatedState _authenticatedState;
    private final AuthenticationRequirements _authenticationRequirements;

    public AzureAdMultitenantAuthenticatorAuthenticatorRequestHandler(AzureAdMultitenantAuthenticatorAuthenticatorPluginConfig config,
                                                                      AuthenticatedState authenticatedState,
                                                                      AuthenticationRequirements authenticationRequirements)
    {
        _config = config;
        _exceptionFactory = config.getExceptionFactory();
        _authenticatorInformationProvider = config.getAuthenticatorInformationProvider();
        _authenticatedState = authenticatedState;
        _authenticationRequirements = authenticationRequirements;
    }

    @Override
    public Optional<AuthenticationResult> get(Request request, Response response)
    {
        _logger.debug("GET request received for authentication");

        String redirectUri = createRedirectUri(_authenticatorInformationProvider, _exceptionFactory);
        String state = UUID.randomUUID().toString();
        Map<String, Collection<String>> queryStringArguments = new LinkedHashMap<>(5);

        if (_authenticatedState.isAuthenticated() &&
                _config.useSubjectForLoginHint())
        {
            queryStringArguments.put("login_hint", Collections.singleton(_authenticatedState.getUsername()));
        }

        boolean forceAuthentication = switch (_config.getPromptLogin())
        {
            case ALWAYS -> true;
            case IF_REQUESTED -> _authenticationRequirements.shouldForceAuthentication();
            case NEVER -> false;
        };

        if (forceAuthentication)
        {
            queryStringArguments.put("prompt", Collections.singleton("login"));
        }

        if (_authenticationRequirements.getMaximumAuthenticationAge().isPresent())
        {
            queryStringArguments.put("max_age", Collections.singleton(_authenticationRequirements
                    .getMaximumAuthenticationAge().get().toString()));
        }

        _config.getAcr().ifPresent(acr -> queryStringArguments.put("acr_values", Collections.singleton(acr)));

        _config.getSessionManager().put(Attribute.of("state", state));
        queryStringArguments.put("client_id", Collections.singleton(_config.getClientId()));
        queryStringArguments.put("redirect_uri", Collections.singleton(redirectUri));
        queryStringArguments.put("state", Collections.singleton(state));
        queryStringArguments.put("response_type", Collections.singleton("code"));
        queryStringArguments.put("scope", Collections.singleton(_config.getScope()));

        _logger.debug("Redirecting to {} with query string arguments {}", AUTHORIZATION_ENDPOINT,
                queryStringArguments);

        throw _exceptionFactory.redirectException(AUTHORIZATION_ENDPOINT,
                RedirectStatusCode.MOVED_TEMPORARILY, queryStringArguments, false);
    }

    @Override
    public Optional<AuthenticationResult> post(Request request, Response response)
    {
        throw _exceptionFactory.methodNotAllowed();
    }

    @Override
    public Request preProcess(Request request, Response response)
    {
        return request;
    }
}

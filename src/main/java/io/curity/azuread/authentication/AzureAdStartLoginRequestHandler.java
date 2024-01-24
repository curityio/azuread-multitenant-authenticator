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
import se.curity.identityserver.sdk.service.SessionManager;
import se.curity.identityserver.sdk.service.authentication.AuthenticationRequirements;
import se.curity.identityserver.sdk.service.authentication.AuthenticatorInformationProvider;
import se.curity.identityserver.sdk.web.Request;
import se.curity.identityserver.sdk.web.Response;

import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.Random;
import java.util.UUID;

import static io.curity.azuread.authentication.RedirectUriUtil.createRedirectUri;
import static java.nio.charset.StandardCharsets.US_ASCII;
import static org.jose4j.lang.HashUtil.SHA_256;
import static org.jose4j.lang.HashUtil.getMessageDigest;

public final class AzureAdStartLoginRequestHandler
        implements AuthenticatorRequestHandler<AzureAdStartLoginRequestHandler.RequestModel>
{
    private static final Logger _logger = LoggerFactory.getLogger(AzureAdStartLoginRequestHandler.class);
    private static final String AUTHORIZATION_ENDPOINT = "https://login.microsoftonline.com/organizations/oauth2/v2.0/authorize";
    private final AzureAdMultitenantAuthenticatorAuthenticatorPluginConfig _config;
    private final AuthenticatorInformationProvider _authenticatorInformationProvider;
    private final ExceptionFactory _exceptionFactory;
    private final AuthenticatedState _authenticatedState;
    private final AuthenticationRequirements _authenticationRequirements;
    private final SessionManager _sessionManager;

    public AzureAdStartLoginRequestHandler(AzureAdMultitenantAuthenticatorAuthenticatorPluginConfig config,
                                           AuthenticatedState authenticatedState,
                                           AuthenticationRequirements authenticationRequirements)
    {
        _config = config;
        _exceptionFactory = config.getExceptionFactory();
        _authenticatorInformationProvider = config.getAuthenticatorInformationProvider();
        _authenticatedState = authenticatedState;
        _authenticationRequirements = authenticationRequirements;
        _sessionManager = config.getSessionManager();
    }

    @Override
    public Optional<AuthenticationResult> get(RequestModel request, Response response)
    {
        _logger.debug("GET request received for authentication");

        String redirectUri = createRedirectUri(_authenticatorInformationProvider, _exceptionFactory);
        String state = UUID.randomUUID().toString();
        String nonce = UUID.randomUUID().toString();
        String codeVerifier = generateCodeVerifier();
        String codeChallenge = challengeFromVerifier(codeVerifier);
        _sessionManager.put(Attribute.of("code_verifier", codeVerifier));
        _sessionManager.put(Attribute.of("nonce", nonce));
        _config.getSessionManager().put(Attribute.of("state", state));

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

        if (forceAuthentication || request.getModel().withRetry())
        {
            queryStringArguments.put("prompt", Collections.singleton("login"));
        }

        if (_authenticationRequirements.getMaximumAuthenticationAge().isPresent())
        {
            queryStringArguments.put("max_age", Collections.singleton(_authenticationRequirements
                    .getMaximumAuthenticationAge().get().toString()));
        }

        String extraScopes =_config.getScope().isPresent() ? " " + _config.getScope().get() : "";

        queryStringArguments.put("client_id", Collections.singleton(_config.getClientId()));
        queryStringArguments.put("redirect_uri", Collections.singleton(redirectUri));
        queryStringArguments.put("state", Collections.singleton(state));
        queryStringArguments.put("code_challenge", Collections.singleton(codeChallenge));
        queryStringArguments.put("code_challenge_method", Collections.singleton("S256"));
        queryStringArguments.put("response_type", Collections.singleton("code"));
        queryStringArguments.put("scope", Collections.singleton("openid" + extraScopes));
        queryStringArguments.put("nonce", Collections.singleton(nonce));

        _logger.debug("Redirecting to {} with query string arguments {}", AUTHORIZATION_ENDPOINT,
                queryStringArguments);

        throw _exceptionFactory.redirectException(AUTHORIZATION_ENDPOINT,
                RedirectStatusCode.MOVED_TEMPORARILY, queryStringArguments, false);
    }

    private static String challengeFromVerifier(String codeVerifier)
    {
        MessageDigest messageDigest = getMessageDigest(SHA_256);
        byte[] digest = messageDigest.digest(codeVerifier.getBytes(US_ASCII));

        return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
    }

    private String generateCodeVerifier()
    {
        int codeVerifierLength = 128;
        char[] allAllowed = "abcdefghijklmnopqrstuvwxyzABCDEFGJKLMNPRSTUVWXYZ0123456789.-_~".toCharArray();
        int allAllowedLength = allAllowed.length;
        Random random = new SecureRandom();
        StringBuilder codeVerifier = new StringBuilder();

        for (int i = 0; i < codeVerifierLength; i++)
        {
            codeVerifier.append(allAllowed[random.nextInt(allAllowedLength)]);
        }

        return codeVerifier.toString();
    }

    @Override
    public Optional<AuthenticationResult> post(RequestModel request, Response response)
    {
        throw _exceptionFactory.methodNotAllowed();
    }

    @Override
    public RequestModel preProcess(Request request, Response response)
    {
        return new RequestModel(request);
    }

    public static final class RequestModel
    {
        private final Get _getRequestModel;

        public RequestModel(Request request)
        {
            _getRequestModel = request.isGetRequest() ? new Get(request) : null;
        }

        Get getModel()
        {
            return _getRequestModel;
        }

        private static final class Get
        {
            private final boolean _retry;

            public Get(Request request)
            {
                _retry = request.getQueryParameterNames().contains("retry");
            }

            boolean withRetry()
            {
                return _retry;
            }
        }
    }
}

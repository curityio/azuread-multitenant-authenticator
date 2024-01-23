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
import org.jose4j.jwk.HttpsJwks;
import org.jose4j.jwt.MalformedClaimException;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.keys.resolvers.HttpsJwksVerificationKeyResolver;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import se.curity.identityserver.sdk.Nullable;
import se.curity.identityserver.sdk.attribute.Attribute;
import se.curity.identityserver.sdk.attribute.AttributeValue;
import se.curity.identityserver.sdk.attribute.Attributes;
import se.curity.identityserver.sdk.attribute.AuthenticationAttributes;
import se.curity.identityserver.sdk.attribute.ContextAttributes;
import se.curity.identityserver.sdk.attribute.ListAttributeValue;
import se.curity.identityserver.sdk.attribute.PrimitiveAttributeValue;
import se.curity.identityserver.sdk.attribute.SubjectAttributes;
import se.curity.identityserver.sdk.authentication.AuthenticationResult;
import se.curity.identityserver.sdk.authentication.AuthenticatorRequestHandler;
import se.curity.identityserver.sdk.errors.ErrorCode;
import se.curity.identityserver.sdk.http.HttpRequest;
import se.curity.identityserver.sdk.http.HttpResponse;
import se.curity.identityserver.sdk.service.ExceptionFactory;
import org.jose4j.jwt.JwtClaims;
import se.curity.identityserver.sdk.service.Json;
import se.curity.identityserver.sdk.service.WebServiceClientFactory;
import se.curity.identityserver.sdk.service.authentication.AuthenticatorInformationProvider;
import se.curity.identityserver.sdk.web.Request;
import se.curity.identityserver.sdk.web.Response;
import se.curity.identityserver.sdk.web.alerts.ErrorMessage;

import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import static io.curity.azuread.authentication.RedirectUriUtil.createRedirectUri;
import static se.curity.identityserver.sdk.web.Response.ResponseModelScope.FAILURE;
import static se.curity.identityserver.sdk.web.ResponseModel.templateResponseModel;

public final class CallbackRequestHandler implements AuthenticatorRequestHandler<CallbackRequestModel>
{
    private final static Logger _logger = LoggerFactory.getLogger(CallbackRequestHandler.class);

    private static final String USERINFO_ENDPOINT = "https://graph.microsoft.com/oidc/userinfo";
    private static final String TOKEN_ENDPOINT = "https://login.microsoftonline.com/organizations/oauth2/v2.0/token";
    private static final HttpsJwks jwks = new HttpsJwks("https://login.microsoftonline.com/organizations/discovery/v2.0/keys");
    private static final String AUTHENTICATION_FAILED_MSG = "Authentication failed";
    private static final Set<String> FILTERED_CLAIMS = new HashSet<>(Collections.singleton("nonce"));
    private static final Set<String> AUTHENTICATION_CONTEXT_CLAIM_NAMES = new HashSet<>(Arrays.asList("iss", "aud",
            "exp", "iat", "acr", "amr", "auth_time", "azp"));
    private final ExceptionFactory _exceptionFactory;
    private final AzureAdMultitenantAuthenticatorAuthenticatorPluginConfig _config;
    private final Json _json;
    private final AuthenticatorInformationProvider _authenticatorInformationProvider;
    private final WebServiceClientFactory _webServiceClientFactory;
    private final JwtConsumer _noIssuerVerificationJwtConsumer;

    public CallbackRequestHandler(AzureAdMultitenantAuthenticatorAuthenticatorPluginConfig config)
    {
        _exceptionFactory = config.getExceptionFactory();
        _config = config;
        _json = config.getJson();
        _webServiceClientFactory = config.getWebServiceClientFactory();
        _authenticatorInformationProvider = config.getAuthenticatorInformationProvider();
        _noIssuerVerificationJwtConsumer = new JwtConsumerBuilder()
                .setSkipSignatureVerification()
                .setVerificationKeyResolver(new HttpsJwksVerificationKeyResolver(jwks))
                .setExpectedIssuers(false)
                .setExpectedAudience(_config.getClientId())
                .setAllowedClockSkewInSeconds(_config.getClockSkew())
                .build();
    }

    @Override
    public CallbackRequestModel preProcess(Request request, Response response)
    {
        if (request.isGetRequest())
        {
            return new CallbackRequestModel(request);
        }
        else
        {
            throw _exceptionFactory.methodNotAllowed();
        }
    }

    @Override
    public Optional<AuthenticationResult> post(CallbackRequestModel requestModel, Response response)
    {
        throw _exceptionFactory.methodNotAllowed();
    }

    @Override
    public Optional<AuthenticationResult> get(CallbackRequestModel requestModel, Response response)
    {
        validateState(requestModel.getState());
        handleError(requestModel);

        Map<String, Object> tokenResponseData = redeemCodeForTokens(requestModel);
        String accessToken = tokenResponseData.get("access_token").toString();
        String idToken = tokenResponseData.get("id_token").toString();

        JwtClaims idTokenClaims = validateIdToken(idToken);

        @Nullable String idTokenIssuer = idTokenClaims.getClaimValueAsString("iss");
        @Nullable String tenantId = idTokenClaims.getClaimValueAsString("tid");

        if (!idTokenIssuer.contains(tenantId))
        {
            _logger.warn("ID token issuer `{}` doesn't contain the `tid` `{}` ", idTokenIssuer, tenantId);
        }

        //todo call external API instead of relying on statically configured allowed Tenant IDs
        if (!_config.getAllowedTenantIds().contains(tenantId))
        {
            response.addErrorMessage(ErrorMessage.withMessage("tenant.disallowed"));
            response.setResponseModel(templateResponseModel(Collections.singletonMap("_restartUrl",
                            _authenticatorInformationProvider.getAuthenticationBaseUri()), "error/get"),
                    FAILURE);
            return Optional.empty();
        }

        JwtClaims userinfoClaims = null;
        if (_config.fetchUserInfo())
        {
            userinfoClaims = callUserInfo(accessToken);
        }

        AuthenticationAttributes authenticationAttributes = authenticationAttributesFromClaims(idTokenClaims,
                userinfoClaims).withContextAttribute(Attribute.of("op_access_token", accessToken));

        return Optional.of(new AuthenticationResult(authenticationAttributes));
    }

    private JwtClaims validateIdToken(String idToken)
    {
        try
        {
            return _noIssuerVerificationJwtConsumer.processToClaims(idToken);
        }
        catch (InvalidJwtException e)
        {
            if (_logger.isDebugEnabled())
            {
                _logger.debug("Could not verify Id token: {}", e.getOriginalMessage());
            }

            throw _exceptionFactory.forbiddenException(ErrorCode.AUTHENTICATION_FAILED, AUTHENTICATION_FAILED_MSG);
        }
    }

    private JwtClaims callUserInfo(String accessToken)
    {
        HttpResponse userInfoResponse = _webServiceClientFactory.create(URI.create(USERINFO_ENDPOINT))
                .request()
                .header("Authorization", "Bearer " + accessToken)
                .method("GET")
                .response();

        int statusCode = userInfoResponse.statusCode();
        if (statusCode != 200)
        {
            if (_logger.isInfoEnabled())
            {
                _logger.info("Got error response from userinfo endpoint: error = {}, {}", statusCode,
                        userInfoResponse.body(HttpResponse.asString()));
            }

            throw _exceptionFactory.internalServerException(ErrorCode.EXTERNAL_SERVICE_ERROR);
        }
        try
        {
            return JwtClaims.parse(userInfoResponse.body(HttpResponse.asString()));
        }
        catch (InvalidJwtException e)
        {
            throw _exceptionFactory.internalServerException(ErrorCode.EXTERNAL_SERVICE_ERROR);
        }
    }

    private Map<String, Object> redeemCodeForTokens(CallbackRequestModel requestModel)
    {
        String redirectUri = createRedirectUri(_authenticatorInformationProvider, _exceptionFactory);

        HttpResponse tokenResponse = _webServiceClientFactory.create(URI.create(TOKEN_ENDPOINT))
                .request().contentType("application/x-www-form-urlencoded")
                .body(getFormEncodedBodyFrom(createPostData(_config.getClientId(), _config.getClientSecret(),
                        requestModel.getCode(), redirectUri)))
                .method("POST")
                .response();
        int statusCode = tokenResponse.statusCode();

        if (statusCode != 200)
        {
            if (_logger.isInfoEnabled())
            {
                _logger.info("Got error response from token endpoint: error = {}, {}", statusCode,
                        tokenResponse.body(HttpResponse.asString()));
            }

            throw _exceptionFactory.internalServerException(ErrorCode.EXTERNAL_SERVICE_ERROR);
        }

        return _json.fromJson(tokenResponse.body(HttpResponse.asString()));
    }

    private void handleError(CallbackRequestModel requestModel)
    {
        if (!Objects.isNull(requestModel.getError()))
        {
            if ("access_denied".equals(requestModel.getError()))
            {
                _logger.debug("Got an error from AzureAdMultitenantAuthenticator: {} - {}", requestModel.getError(), requestModel.getErrorDescription());

                throw _exceptionFactory.redirectException(_authenticatorInformationProvider.getAuthenticationBaseUri().toASCIIString());
            }

            _logger.warn("Got an error from AzureAdMultitenantAuthenticator: {} - {}", requestModel.getError(), requestModel.getErrorDescription());

            throw _exceptionFactory.externalServiceException("Login with AzureAdMultitenantAuthenticator failed");
        }
    }

    private static Map<String, String> createPostData(String clientId, String clientSecret, String code, String callbackUri)
    {
        Map<String, String> data = new HashMap<>(5);

        data.put("client_id", clientId);
        data.put("client_secret", clientSecret);
        data.put("code", code);
        data.put("grant_type", "authorization_code");
        data.put("redirect_uri", callbackUri);

        return data;
    }

    private static HttpRequest.BodyProcessor getFormEncodedBodyFrom(Map<String, String> data)
    {
        StringBuilder stringBuilder = new StringBuilder();

        data.entrySet().forEach(e -> appendParameter(stringBuilder, e));

        return HttpRequest.fromString(stringBuilder.toString(), StandardCharsets.UTF_8);
    }

    private static void appendParameter(StringBuilder stringBuilder, Map.Entry<String, String> entry)
    {
        String key = entry.getKey();
        String value = entry.getValue();
        String encodedKey = urlEncodeString(key);
        stringBuilder.append(encodedKey);

        if (!Objects.isNull(value))
        {
            String encodedValue = urlEncodeString(value);
            stringBuilder.append("=").append(encodedValue);
        }

        stringBuilder.append("&");
    }

    private static String urlEncodeString(String unencodedString)
    {
        try
        {
            return URLEncoder.encode(unencodedString, StandardCharsets.UTF_8.name());
        }
        catch (UnsupportedEncodingException e)
        {
            throw new RuntimeException("This server cannot support UTF-8!", e);
        }
    }

    private void validateState(String state)
    {
        @Nullable Attribute sessionAttribute = _config.getSessionManager().get("state");

        if (sessionAttribute != null && state.equals(sessionAttribute.getValueOfType(String.class)))
        {
            _logger.debug("State matches session");
        }
        else
        {
            _logger.debug("State did not match session");

            throw _exceptionFactory.badRequestException(ErrorCode.INVALID_SERVER_STATE, "Bad state provided");
        }
    }

    private AuthenticationAttributes authenticationAttributesFromClaims(JwtClaims idTokenClaims,
                                                                        @Nullable JwtClaims userinfoClaims)
    {
        List<Attribute> subjectAttributeList = new ArrayList<>();
        List<Attribute> contextAttributeList = new ArrayList<>();

        filterClaimsSet(idTokenClaims, subjectAttributeList, contextAttributeList);
        String subject = getSubject(idTokenClaims);
        if (userinfoClaims != null)
        {
            filterClaimsSet(userinfoClaims, subjectAttributeList, contextAttributeList);
            // Overwrite subject if returned from the userinfo. IdToken sub will be in subject attributes.
            subject = getSubject(userinfoClaims);
        }

        return AuthenticationAttributes.of(
                SubjectAttributes.of(subject, Attributes.of(subjectAttributeList)),
                ContextAttributes.of(Attributes.of(contextAttributeList), true));
    }

    private static void filterClaimsSet(JwtClaims idTokenClaims, List<Attribute> subjectAttributeList,
                                        List<Attribute> contextAttributeList)
    {
        for (Map.Entry<String, List<Object>> claim : idTokenClaims.flattenClaims(FILTERED_CLAIMS).entrySet())
        {
            @Nullable Attribute attribute = fromClaim(claim.getKey(), claim.getValue());

            if (attribute != null)
            {
                if (AUTHENTICATION_CONTEXT_CLAIM_NAMES.contains(claim.getKey()))
                {
                    contextAttributeList.add(attribute);
                }
                else
                {
                    subjectAttributeList.add(attribute);
                }
            }
        }
    }

    private String getSubject(JwtClaims claims)
    {
        String subject;

        try
        {
            subject = claims.getSubject();
        }
        catch (MalformedClaimException e)
        {
            if (_logger.isInfoEnabled())
            {
                _logger.info("Could not extract subject from id_token: {}", e.getMessage());
            }

            throw _exceptionFactory.forbiddenException(ErrorCode.AUTHENTICATION_FAILED, AUTHENTICATION_FAILED_MSG);
        }

        return subject;
    }

    @Nullable
    private static Attribute fromClaim(String key, List<Object> claimValue)
    {
        @Nullable Attribute attribute;

        if (claimValue.isEmpty())
        {
            _logger.trace("The claim {} was received without any value, adding as flag", key);

            attribute = Attribute.ofFlag(key);
        }
        else if (claimValue.size() == 1)
        {
            Object value = claimValue.get(0);
            if (value instanceof Comparable<?>)
            {
                attribute = Attribute.of(key, PrimitiveAttributeValue.of((Comparable<?>) value));
            }
            else
            {
                if (_logger.isDebugEnabled())
                {
                    _logger.debug("The claim {} has an incompatible type: {}", key, value.getClass().getCanonicalName());
                }

                attribute = null;
            }
        }
        else // claimValue.size() > 1
        {
            // Writing this using streams hits an issue with typing from Object; for loop doesn't have that.
            List<AttributeValue> attributeValues = claimValue.stream()
                    .filter(it -> it instanceof Comparable)
                    .map(it -> PrimitiveAttributeValue.of((Comparable<?>) it))
                    .collect(Collectors.toList());

            attribute = Attribute.of(key, ListAttributeValue.of(attributeValues));
        }

        return attribute;
    }
}

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

package io.curity.azuread.descriptor;

import io.curity.azuread.authentication.AzureAdCallbackRequestHandler;
import io.curity.azuread.authentication.AzureAdStartLoginRequestHandler;
import io.curity.azuread.config.AzureAdMultitenantAuthenticatorAuthenticatorPluginConfig;
import se.curity.identityserver.sdk.authentication.AuthenticatorRequestHandler;
import se.curity.identityserver.sdk.plugin.descriptor.AuthenticatorPluginDescriptor;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

public final class AzureAdMultitenantAuthenticatorAuthenticatorPluginDescriptor
        implements AuthenticatorPluginDescriptor<AzureAdMultitenantAuthenticatorAuthenticatorPluginConfig>
{
    public final static String CALLBACK = "callback";

    @Override
    public String getPluginImplementationType()
    {
        return "azuread-multitenant";
    }

    @Override
    public Class<? extends AzureAdMultitenantAuthenticatorAuthenticatorPluginConfig> getConfigurationType()
    {
        return AzureAdMultitenantAuthenticatorAuthenticatorPluginConfig.class;
    }

    @Override
    public Map<String, Class<? extends AuthenticatorRequestHandler<?>>> getAuthenticationRequestHandlerTypes()
    {
        Map<String, Class<? extends AuthenticatorRequestHandler<?>>> handlers = new LinkedHashMap<>(2);
        handlers.put("index", AzureAdStartLoginRequestHandler.class);
        handlers.put(CALLBACK, AzureAdCallbackRequestHandler.class);

        return Collections.unmodifiableMap(handlers);
    }
}

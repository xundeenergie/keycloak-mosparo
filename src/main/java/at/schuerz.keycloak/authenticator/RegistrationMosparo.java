/*
 * Copyright 2016 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package at.schuerz.keycloak.authenticator;

import org.apache.http.NameValuePair;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.message.BasicNameValuePair;
import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.authentication.FormAction;
import org.keycloak.authentication.FormActionFactory;
import org.keycloak.authentication.FormContext;
import org.keycloak.authentication.ValidationContext;
import org.keycloak.connections.httpclient.HttpClientProvider;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.FormMessage;
import org.keycloak.provider.ConfiguredProvider;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.services.ServicesLogger;
import org.keycloak.services.messages.Messages;
import org.keycloak.services.validation.Validation;
import org.keycloak.util.JsonSerialization;

import java.io.InputStream;
import jakarta.ws.rs.core.MultivaluedMap;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.util.EntityUtils;

/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * Changes for mosparo from
 * @author <a href="mailto:jakob@schuerz.at">Jakobus Schürz</a>
 * @version $Revision: 1 $
 */
public class RegistrationMosparo implements FormAction, FormActionFactory {
    public static final String MOSPARO_RESPONSE = "mosparo-response";
    public static final String MOSPARO_REFERENCE_CATEGORY = "mosparo";
    public static final String SITE_PUBKEY = "mosparo-public-key";
    public static final String SITE_UUID = "uuid";
    public static final String MOSPARO_HOST = "hostname";
    private static final Logger logger = Logger.getLogger(RegistrationMosparo.class);

    public static final String PROVIDER_ID = "registration-mosparo-action";

    @Override
    public String getDisplayType() {
        return "mosparo";
    }

    @Override
    public String getReferenceCategory() {
        return MOSPARO_REFERENCE_CATEGORY;
    }

    @Override
    public boolean isConfigurable() {
        return true;
    }

    private static AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOICES = {
            AuthenticationExecutionModel.Requirement.REQUIRED,
            AuthenticationExecutionModel.Requirement.DISABLED
    };
    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return REQUIREMENT_CHOICES;
    }
    @Override
    public void buildPage(FormContext context, LoginFormsProvider form) {
        AuthenticatorConfigModel captchaConfig = context.getAuthenticatorConfig();
        String userLanguageTag = context.getSession().getContext().resolveLocale(context.getUser()).toLanguageTag();
        if (captchaConfig == null || captchaConfig.getConfig() == null
                || captchaConfig.getConfig().get(SITE_UUID) == null
                || captchaConfig.getConfig().get(SITE_PUBKEY) == null
                || captchaConfig.getConfig().get(MOSPARO_HOST) == null
                ) {
            form.addError(new FormMessage(null, "Mosparo not configured properly."));
            return;
        }
        String siteUUID = captchaConfig.getConfig().get(SITE_UUID);
        form.addScript("https://" + getMosparoHostname(captchaConfig) + "/build/mosparo-frontend.js");
        form.addScript( "var m; " +
                "window.onload = function(){ " +
                "m = new mosparo( " +
                "'mosparo-box'," +
                " captchaConfig.getConfig().get(MOSPARO_HOST)," +
                " captchaConfig.getConfig().get(SITE_UUID)," +
                " captchaConfig.getConfig().get(SITE_PUBKEY)); };");
    }

    @Override
    public void validate(ValidationContext context) {
        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        List<FormMessage> errors = new ArrayList<>();
        boolean success = false;
        context.getEvent().detail(Details.REGISTER_METHOD, "form");

        String captcha = formData.getFirst(MOSPARO_RESPONSE);
        if (!Validation.isBlank(captcha)) {
            AuthenticatorConfigModel captchaConfig = context.getAuthenticatorConfig();
            String pubkey = captchaConfig.getConfig().get(SITE_PUBKEY);

            success = validateMosparo(context, success, captcha, pubkey);
        }
        if (success) {
            context.success();
        } else {
            errors.add(new FormMessage(null, "Mosparo verification failed."));
            formData.remove(MOSPARO_RESPONSE);
            context.error(Errors.INVALID_REGISTRATION);
            context.validationError(formData, errors);
            context.excludeOtherErrors();
            return;


        }
    }

    private String getMosparoHostname(AuthenticatorConfigModel config) {
			
				System.out.println(MOSPARO_HOST);
				return config.getConfig().get(MOSPARO_HOST);
    }

    protected boolean validateMosparo(ValidationContext context, boolean success, String captcha, String pubkey) {
        CloseableHttpClient httpClient = context.getSession().getProvider(HttpClientProvider.class).getHttpClient();
        HttpPost post = new HttpPost("https://" + getMosparoHostname(context.getAuthenticatorConfig()) + "/api/v1/frontend/verification/verify");
        List<NameValuePair> formparams = new LinkedList<>();
        formparams.add(new BasicNameValuePair("pubkey", pubkey));
        formparams.add(new BasicNameValuePair("response", captcha));
        formparams.add(new BasicNameValuePair("remoteip", context.getConnection().getRemoteAddr()));
        try {
            UrlEncodedFormEntity form = new UrlEncodedFormEntity(formparams, "UTF-8");
            post.setEntity(form);
            try (CloseableHttpResponse response = httpClient.execute(post)) {
                InputStream content = response.getEntity().getContent();
                try {
                    Map json = JsonSerialization.readValue(content, Map.class);
                    Object val = json.get("success");
                    success = Boolean.TRUE.equals(val);
                } finally {
                    EntityUtils.consumeQuietly(response.getEntity());
                }
            }
        } catch (Exception e) {
            ServicesLogger.LOGGER.recaptchaFailed(e);
        }
        return success;
    }

    @Override
    public void success(FormContext context) {

    }

    @Override
    public boolean requiresUser() {
        return false;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {

    }

    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }


    @Override
    public void close() {

    }

    @Override
    public FormAction create(KeycloakSession session) {
        return this;
    }

    @Override
    public void init(Config.Scope config) {

    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {

    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getHelpText() {
        return "Adds mosparo button.  mosparo verify that the entity that is registering is a human.  This can only be used on the internet and must be configured after you add it.";
    }

    private static final List<ProviderConfigProperty> CONFIG_PROPERTIES = new ArrayList<ProviderConfigProperty>();

    static {
        ProviderConfigProperty property;
        property = new ProviderConfigProperty();
        property.setName(SITE_UUID);
        property.setLabel("UUID");
        property.setType(ProviderConfigProperty.STRING_TYPE);
        property.setHelpText("UUID");
        CONFIG_PROPERTIES.add(property);
        property = new ProviderConfigProperty();
        property.setName(SITE_PUBKEY);
        property.setLabel("Mosparo Public Key");
        property.setType(ProviderConfigProperty.STRING_TYPE);
        property.setHelpText("Mosparo Public Key (Site Key)");
        CONFIG_PROPERTIES.add(property);

        property = new ProviderConfigProperty();
        property.setName(MOSPARO_HOST);
        property.setLabel("Hostname");
        property.setType(ProviderConfigProperty.STRING_TYPE);
        property.setHelpText("Hostname mosparo-host");
        CONFIG_PROPERTIES.add(property);
    }


    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return CONFIG_PROPERTIES;
    }
}

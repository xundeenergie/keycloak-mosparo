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

import com.fasterxml.jackson.databind.JsonNode;
import jakarta.ws.rs.core.MultivaluedHashMap;
import org.apache.commons.codec.binary.Hex;
import org.apache.http.HeaderElement;
import org.apache.http.NameValuePair;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.ssl.SSLContextBuilder;
import org.apache.http.ssl.TrustStrategy;
import org.apache.http.util.EntityUtils;
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
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.util.JsonSerialization;

import java.io.IOException;
import jakarta.ws.rs.core.MultivaluedMap;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.*;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * Changes for mosparo from
 * @author <a href="mailto:jakob@schuerz.at">Jakobus Schürz</a>
 * @version $Revision: 1 $
 */
public class RegistrationMosparo implements FormAction, FormActionFactory {
    public static final String MOSPARO_RESPONSE = "mosparo-response";
    public static final String MOSPARO_REFERENCE_CATEGORY = "mosparo";

    public static final String MOSPARO_HOST = "hostname";
    public static final String MOSPARO_UUID = "uuid";
    public static final String MOSPARO_PUBLIC_KEY = "mosparo-public-key";
    public static final String MOSPARO_PRIVATE_KEY = "mosparo-private-key";
    public static final String MOSPARO_VERIFY_SSL = "mosparo-verify-ssl";

    private static final Logger logger = Logger.getLogger(RegistrationMosparo.class);

    public static final String PROVIDER_ID = "registration-mosparo-action";

    private Mac mHmacSha256;

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
        if (captchaConfig == null || captchaConfig.getConfig() == null
                || captchaConfig.getConfig().get(MOSPARO_HOST) == null
                || captchaConfig.getConfig().get(MOSPARO_UUID) == null
                || captchaConfig.getConfig().get(MOSPARO_PUBLIC_KEY) == null
                || captchaConfig.getConfig().get(MOSPARO_PRIVATE_KEY) == null
                ) {
            form.addError(new FormMessage(null, "mosparo not configured properly."));
            return;
        }

        form.setAttribute("mosparoRequired", true);
        form.setAttribute("mosparoHost", captchaConfig.getConfig().get(MOSPARO_HOST));
        form.setAttribute("mosparoUuid", captchaConfig.getConfig().get(MOSPARO_UUID));
        form.setAttribute("mosparoPublicKey", captchaConfig.getConfig().get(MOSPARO_PUBLIC_KEY));

        // The hostname should always start with https://
        form.addScript(getMosparoHostname(captchaConfig) + "/build/mosparo-frontend.js");
    }

    @Override
    public void validate(ValidationContext context) {
        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        List<FormMessage> errors = new ArrayList<>();
        boolean success = false;
        context.getEvent().detail(Details.REGISTER_METHOD, "form");

        try {
            success = verifyFormData(context, formData);
        } catch (NoSuchAlgorithmException | IOException | InvalidKeyException e) {
            throw new RuntimeException(e);
        }

        if (success) {
            context.success();
        } else {
            errors.add(new FormMessage(null, "mosparo verification failed."));
            formData.remove(MOSPARO_RESPONSE);
            context.error(Errors.INVALID_REGISTRATION);
            context.validationError(formData, errors);
            context.excludeOtherErrors();
        }
    }

    private String getMosparoHostname(AuthenticatorConfigModel config) {
        return config.getConfig().get(MOSPARO_HOST);
    }

    protected boolean verifyFormData(ValidationContext context, MultivaluedMap<String, String> formData) throws NoSuchAlgorithmException, IOException, InvalidKeyException {
        boolean success = false;

        AuthenticatorConfigModel captchaConfig = context.getAuthenticatorConfig();
        String publicKey = captchaConfig.getConfig().get(MOSPARO_PUBLIC_KEY);
        String privateKey = captchaConfig.getConfig().get(MOSPARO_PRIVATE_KEY);

        // 1. Remove the ignored fields from the form data
        formData.remove("password");
        formData.remove("password-confirm");

        // 2. Extract the submit and validation token from the form data
        String mosparoSubmitToken = formData.getFirst("_mosparo_submitToken");
        String mosparoValidationToken = formData.getFirst("_mosparo_validationToken");

        // 3. Prepare the form data
        Map<String, String> preparedFormData = new HashMap<String, String>();
        for (Map.Entry<String, List<String>> entry : formData.entrySet()) {
            if (entry.getKey().startsWith("_mosparo_")) {
                continue;
            }

            String value = entry.getValue().getFirst();
            preparedFormData.put(entry.getKey(), value.replace("\r\n", "\n"));
        }

        // 4. Generate the hashes
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        Map<String, String> hashedFormData = new HashMap<String, String>();

        // Since the data must be sorted by keys, we sort the keys and then generate the
        // SHA256 hash for all the values
        List<String> keylist = new ArrayList<>(preparedFormData.keySet());
        Collections.sort(keylist);
        for (String key : keylist) {
            String value = preparedFormData.get(key);
            byte[] hashedValue = digest.digest(value.getBytes(StandardCharsets.UTF_8));
            hashedFormData.put(key, convertBytesToHex(hashedValue));
        }

        // 5. Generate the form data signature
        String jsonHashedFormData = JsonSerialization.writeValueAsString(hashedFormData);
        String formDataSignature = calculateHmacSignature(jsonHashedFormData, privateKey);

        // 6. Generate the validation signature
        String validationSignature = calculateHmacSignature(mosparoValidationToken, privateKey);

        // 7. Prepare the verification signature
        String combinedSignatures = validationSignature + formDataSignature;
        String verificationSignature = calculateHmacSignature(combinedSignatures, privateKey);

        // 8. Collect the request data
        String apiEndpoint = "/api/v1/verification/verify";
        Map<String, Object> requestData = new HashMap<String, Object>();
        requestData.put("submitToken", mosparoSubmitToken);
        requestData.put("validationSignature", validationSignature);
        requestData.put("formSignature", formDataSignature);
        requestData.put("formData", hashedFormData);

        // 9. Generate the request signature
        String jsonRequestData = JsonSerialization.writeValueAsString(requestData);
        String combinedApiEndpointJsonRequestData = apiEndpoint + jsonRequestData;
        String requestSignature = calculateHmacSignature(combinedApiEndpointJsonRequestData, privateKey);

        // 10. Send the API request
        CloseableHttpClient httpClient = context.getSession().getProvider(HttpClientProvider.class).getHttpClient();
        if (captchaConfig.getConfig().get(MOSPARO_VERIFY_SSL) == null) {
            try {
                httpClient = HttpClients
                    .custom()
                    .setSSLHostnameVerifier(NoopHostnameVerifier.INSTANCE)
                    .setSSLContext(new SSLContextBuilder().loadTrustMaterial(null, new TrustStrategy() {
                        public boolean isTrusted(X509Certificate[] arg0, String arg1) throws CertificateException {
                            return true;
                        }
                    }).build()).build();
            } catch (KeyManagementException e) {
                logger.error("KeyManagementException for HttpClient without SSL verification");
            } catch (NoSuchAlgorithmException e) {
                logger.error("NoSuchAlgorithmException for HttpClient without SSL verification");
            } catch (KeyStoreException e) {
                logger.error("KeyStoreException for HttpClient without SSL verification");
            }
        }

        HttpPost post = new HttpPost(getMosparoHostname(context.getAuthenticatorConfig()) + apiEndpoint);

        boolean valid = false;
        String mosparoVerificationSignature = null;
        JsonNode verifiedFields = null;
        JsonNode issues = null;

        try {
            UrlEncodedFormEntity form = new UrlEncodedFormEntity(convertToNameValuePar(requestData), "UTF-8");
            post.setEntity(form);

            String authHeader = publicKey + ":" + requestSignature;
            String authHeaderEncoded = Base64.getEncoder().encodeToString(authHeader.getBytes(StandardCharsets.UTF_8));
            post.setHeader("Authorization", "Basic " + authHeaderEncoded);

            try (CloseableHttpResponse response = httpClient.execute(post)) {
                InputStream content = response.getEntity().getContent();

                try {
                    Map responseData = JsonSerialization.readValue(content, Map.class);
                    valid = Boolean.TRUE.equals(responseData.get("valid"));
                    mosparoVerificationSignature = JsonSerialization.mapper.convertValue(responseData.get("verificationSignature"), String.class);
                    verifiedFields = JsonSerialization.mapper.convertValue(responseData.get("verifiedFields"), JsonNode.class);
                    issues = JsonSerialization.mapper.convertValue(responseData.get("issues"), JsonNode.class);
                } finally {
                    EntityUtils.consumeQuietly(response.getEntity());
                }
            }
        } catch (Exception e) {
            logger.error(e.getMessage());
            return false;
        }

        // 11. Check the response
        if (valid && verificationSignature.equals(mosparoVerificationSignature) && verifiedFields != null) {
            Set<String> verifiedFieldKeys = new HashSet<>();
            for (Iterator<String> it = verifiedFields.fieldNames(); it.hasNext(); ) {
                verifiedFieldKeys.add(it.next());
            }

            Set<String> diffHashedFormData = new HashSet<>(hashedFormData.keySet());
            diffHashedFormData.removeAll(verifiedFieldKeys);
            verifiedFieldKeys.removeAll(hashedFormData.keySet());

            if (!diffHashedFormData.isEmpty() || !verifiedFieldKeys.isEmpty()) {
                return false;
            }

            return true;
        }

        return false;
    }

    private static String convertBytesToHex(byte[] hash) {
        StringBuilder hexString = new StringBuilder(2 * hash.length);
        for (int i = 0; i < hash.length; i++) {
            String hex = Integer.toHexString(0xff & hash[i]);

            if (hex.length() == 1) {
                hexString.append('0');
            }

            hexString.append(hex);
        }

        return hexString.toString();
    }

    private String calculateHmacSignature(String data, String privateKey) throws NoSuchAlgorithmException, InvalidKeyException {
        if (mHmacSha256 == null) {
            SecretKeySpec key = new SecretKeySpec(privateKey.getBytes(StandardCharsets.UTF_8), "HmacSHA256");
            mHmacSha256 = Mac.getInstance("HmacSHA256");
            mHmacSha256.init(key);
        }

        return Hex.encodeHexString(mHmacSha256.doFinal(data.getBytes(StandardCharsets.UTF_8)));
    }

    private List<NameValuePair> convertToNameValuePar(Map<String, Object> requestData) {
        List<NameValuePair> data = new LinkedList<>();
        for (String key : requestData.keySet()) {
            Object value = requestData.get(key);

            if (Objects.equals(key, "formData") && value instanceof HashMap) {
                Map<String, String> list = (HashMap<String, String>) value;
                for (String subKey : list.keySet()) {
                    String subValue = list.get(subKey);
                    data.add(new BasicNameValuePair(key + "[" + subKey + "]", subValue));
                }
            } else {
                data.add(new BasicNameValuePair(key, (String) value));
            }
        }

        return data;
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
        property.setName(MOSPARO_HOST);
        property.setLabel("Hostname");
        property.setType(ProviderConfigProperty.STRING_TYPE);
        property.setHelpText("Hostname mosparo-host");
        CONFIG_PROPERTIES.add(property);

        property = new ProviderConfigProperty();
        property.setName(MOSPARO_UUID);
        property.setLabel("UUID");
        property.setType(ProviderConfigProperty.STRING_TYPE);
        property.setHelpText("UUID");
        CONFIG_PROPERTIES.add(property);

        property = new ProviderConfigProperty();
        property.setName(MOSPARO_PUBLIC_KEY);
        property.setLabel("mosparo Public Key");
        property.setType(ProviderConfigProperty.STRING_TYPE);
        property.setHelpText("Mosparo Public Key (Site Key)");
        CONFIG_PROPERTIES.add(property);

        property = new ProviderConfigProperty();
        property.setName(MOSPARO_PRIVATE_KEY);
        property.setLabel("mosparo Private Key");
        property.setType(ProviderConfigProperty.STRING_TYPE);
        property.setHelpText("mosparo Private Key");
        CONFIG_PROPERTIES.add(property);

        property = new ProviderConfigProperty();
        property.setName(MOSPARO_VERIFY_SSL);
        property.setLabel("mosparo Verify SSL");
        property.setType(ProviderConfigProperty.BOOLEAN_TYPE);
        property.setHelpText("mosparo Verify SSL");
        CONFIG_PROPERTIES.add(property);
    }


    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return CONFIG_PROPERTIES;
    }
}

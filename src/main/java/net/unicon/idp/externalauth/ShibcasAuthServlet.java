package net.unicon.idp.externalauth;

import com.google.gson.*;
import net.shibboleth.idp.attribute.IdPAttribute;
import net.shibboleth.idp.attribute.StringAttributeValue;
import net.shibboleth.idp.authn.AuthnEventIds;
import net.shibboleth.idp.authn.ExternalAuthentication;
import net.shibboleth.idp.authn.ExternalAuthenticationException;
import net.shibboleth.idp.authn.principal.IdPAttributePrincipal;
import net.shibboleth.idp.authn.principal.UsernamePrincipal;
import net.unicon.idp.authn.provider.extra.IParameterBuilder;
import org.apache.commons.lang.StringUtils;
import org.apache.http.HttpResponse;
import org.apache.http.NameValuePair;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.message.BasicNameValuePair;
import org.jasig.cas.client.util.CommonUtils;
import org.jasig.cas.client.util.IOUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.core.env.Environment;
import org.springframework.web.context.WebApplicationContext;

import javax.security.auth.Subject;
import javax.servlet.RequestDispatcher;
import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.Principal;
import java.util.*;
import java.util.Map.Entry;


/**
 * A Servlet that validates the CAS ticket and then pushes the authenticated principal name into the correct location before
 * handing back control to Shib
 *
 * @author chasegawa@unicon.net
 * @author jgasper@unicon.net
 * @author aremmes (GitHub)
 */
@WebServlet(name = "ShibcasAuthServlet", urlPatterns = {"/Authn/External/*"})
public class ShibcasAuthServlet extends HttpServlet {
    private final Logger logger = LoggerFactory.getLogger(ShibcasAuthServlet.class);
    private static final long serialVersionUID = 1L;
    private static final String artifactParameterName = "code";
    private static final String stateParameterName = "state";
    private static final String ACCESS_TOKEN_KEY = "access_token";

    private String oauth2LoginUrl;
    private String serverName;
    private String oauth2TokenUrl;
    private String oauth2ResourceUrl;
    private String client_id;
    private String client_secret;
    private String redirect_uri;

    //Added
    private String principal_name;
    //Added End

    private final Set<IParameterBuilder> parameterBuilders = new HashSet<>();


    @Override
    protected void doGet(final HttpServletRequest request, final HttpServletResponse response) throws ServletException, IOException {
        // TODO: We have the opportunity to give back more to Shib than just the PRINCIPAL_NAME_KEY. Identify additional information
        try {
            final String ticket = CommonUtils.safeGetParameter(request, artifactParameterName);

            //Added
            final String conversationId = CommonUtils.safeGetParameter(request, ExternalAuthentication.CONVERSATION_KEY);
            // Added End

            // fast leave OAuth2 Server site & conversation restore
            final String state = CommonUtils.safeGetParameter(request, stateParameterName);
            if (!StringUtils.isEmpty(state) && !StringUtils.isEmpty(ticket)) {
                String redirectUrl = String.format(
                        "%s?%s=%s&%s=%s",
                        this.redirect_uri,
                        ExternalAuthentication.CONVERSATION_KEY, state,
                        ShibcasAuthServlet.artifactParameterName, ticket
                );
                response.setContentType("text/html");
                response.getWriter().format("<meta http-equiv=\"refresh\" content=\"0;url=%s\"><h5>Waiting for RichCtrl IdP...</h5>", redirectUrl);
                return;
            }

            final String gatewayAttempted = CommonUtils.safeGetParameter(request, "gatewayAttempted");
            final String authenticationKey = ExternalAuthentication.startExternalAuthentication(request);
            final boolean force = Boolean.parseBoolean(request.getAttribute(ExternalAuthentication.FORCE_AUTHN_PARAM).toString());
            final boolean passive = Boolean.parseBoolean(request.getAttribute(ExternalAuthentication.PASSIVE_AUTHN_PARAM).toString());

            if ((ticket == null || ticket.isEmpty()) && (gatewayAttempted == null || gatewayAttempted.isEmpty())) {
                logger.debug("ticket and gatewayAttempted are not set; initiating oauth2 login redirect");

                // Added
                //startLoginRequest(request, response, force, passive, authenticationKey);
                startLoginRequest(request, response, force, passive, authenticationKey, conversationId);
                //Added End

                return;
            }

            if (ticket == null || ticket.isEmpty()) {
                logger.debug("Gateway/Passive returned no ticket, returning NoPassive.");
                request.setAttribute(ExternalAuthentication.AUTHENTICATION_ERROR_KEY, AuthnEventIds.NO_PASSIVE);
                ExternalAuthentication.finishExternalAuthentication(authenticationKey, request, response);
                return;
            }

            authenticateByOAuth2(request, response, ticket, authenticationKey);
        } catch (final ExternalAuthenticationException e) {
            logger.warn("Error processing oauth2 authentication request", e);
            loadErrorPage(request, response);

        } catch (final Exception e) {
            logger.error("Something unexpected happened", e);
            request.setAttribute(ExternalAuthentication.AUTHENTICATION_ERROR_KEY, AuthnEventIds.AUTHN_EXCEPTION);
        }
    }

    private void authenticateByOAuth2(
            final HttpServletRequest request, final HttpServletResponse response,
            final String ticket, final String authenticationKey) throws Exception {

        String accessToken = fetchAccessToken(ticket);

        List<NameValuePair> params = Collections.singletonList(new BasicNameValuePair("access_token", accessToken));
        JsonObject json = fetchJSON(this.oauth2ResourceUrl, params);
        if(!json.has(this.principal_name) || !json.get(this.principal_name).isJsonPrimitive()) {
            throw new ExternalAuthenticationException(String.format(
                "unable to locate principal_name as `%s` in oauth resource_url `%s` response: \n%s",
                this.principal_name, this.oauth2ResourceUrl, json.toString()
            ));
        }

        String principleName = json.get(this.principal_name).getAsString();

        Map<String, Object> attributes = new HashMap<>();
        for(Entry<String, JsonElement> entry : json.entrySet()) {
            if(entry.getValue().isJsonPrimitive()) {
                String value = entry.getValue().getAsJsonPrimitive().getAsString();
                if (!value.isEmpty()) {
                    attributes.put(entry.getKey(), value);
                }
            }
        }

        Collection<IdPAttributePrincipal> assertionAttributes = produceIdpAttributePrincipal(attributes);

        if (!assertionAttributes.isEmpty()) {
            Set<Principal> principals = new HashSet<>();
            principals.addAll(assertionAttributes);
            principals.add(new UsernamePrincipal(principleName));
            request.setAttribute(ExternalAuthentication.SUBJECT_KEY, new Subject(false, principals, Collections.emptySet(), Collections.emptySet()));
        } else {
            request.setAttribute(ExternalAuthentication.PRINCIPAL_NAME_KEY, principleName);
        }

        ExternalAuthentication.finishExternalAuthentication(authenticationKey, request, response);
    }

    private String fetchAccessToken(String code) throws Exception {
        List<NameValuePair> params = new ArrayList<>(5);
        params.add(new BasicNameValuePair("grant_type", "authorization_code"));
        params.add(new BasicNameValuePair("code", code));
        params.add(new BasicNameValuePair("client_id", client_id));
        params.add(new BasicNameValuePair("client_secret", client_secret));
        params.add(new BasicNameValuePair("redirect_uri", redirect_uri));

        JsonObject json = fetchJSON(this.oauth2TokenUrl, params);
        if(!json.has(ShibcasAuthServlet.ACCESS_TOKEN_KEY) || !json.get(ShibcasAuthServlet.ACCESS_TOKEN_KEY).isJsonPrimitive()) {
            throw new ExternalAuthenticationException(String.format(
                    "unable to locate access_token as `%s` in oauth2tokenurl `%s` response: \n%s",
                    ShibcasAuthServlet.ACCESS_TOKEN_KEY, this.oauth2TokenUrl, json.toString()
            ));
        }

        return json.get(ShibcasAuthServlet.ACCESS_TOKEN_KEY).getAsString();
    }

    private JsonObject fetchJSON(String url, List<NameValuePair> params) throws Exception {
        try (CloseableHttpClient client = HttpClientBuilder.create().build()) {
            HttpPost conn = new HttpPost(url);
            conn.setHeader("User-Agent", "Mozilla/4.0 (compatible; MSIE 5.0; Windows NT; DigExt)");
            conn.setEntity(new UrlEncodedFormEntity(params));

            HttpResponse response = client.execute(conn);
            String result = IOUtils.readString(response.getEntity().getContent());
            logger.info("original response: {} {} {}", oauth2TokenUrl, params, result);

            return JsonParser.parseString(result).getAsJsonObject();
        } catch (Exception e) {
            this.logger.error("fetchJSON failed [{}], {}, {}", url, e.getMessage(), e);
            throw e;
        }
    }

    private Collection<IdPAttributePrincipal> produceIdpAttributePrincipal(final Map<String, Object> casAttributes) {
        final Set<IdPAttributePrincipal> principals = new HashSet<>();
        for (final Map.Entry<String, Object> entry : casAttributes.entrySet()) {
            final IdPAttribute attr = new IdPAttribute(entry.getKey());

            final List<StringAttributeValue> attributeValues = new ArrayList<>();
            if (entry.getValue() instanceof Collection) {
                for (final Object value : (Collection) entry.getValue()) {
                    attributeValues.add(new StringAttributeValue(value.toString()));
                }
            } else {
                attributeValues.add(new StringAttributeValue(entry.getValue().toString()));
            }
            if (!attributeValues.isEmpty()) {
                attr.setValues(attributeValues);
                logger.debug("Added attribute {} with values {}", entry.getKey(), entry.getValue());
                principals.add(new IdPAttributePrincipal(attr));
            } else {
                logger.warn("Skipped attribute {} since it contains no values", entry.getKey());
            }
        }
        return principals;
    }


    protected void startLoginRequest(final HttpServletRequest request, final HttpServletResponse response,
                                     final Boolean force, final Boolean passive, String authenticationKey, final String conversationId) {
        //Added End

        // CAS Protocol - http://www.jasig.org/cas/protocol indicates not setting gateway if renew has been set.
        // we will set both and let CAS sort it out, but log a warning
        if (Boolean.TRUE.equals(passive) && Boolean.TRUE.equals(force)) {
            logger.warn("Both FORCE AUTHN and PASSIVE AUTHN were set to true, please verify that the requesting system has been properly configured.");
        }
        try {
            String serviceUrl = constructServiceUrl(request, response);
            if (passive) {
                serviceUrl += "&gatewayAttempted=true";
            }

            String loginUrl = constructRedirectUrl(serviceUrl, force, passive) + getAdditionalParameters(request, authenticationKey);
            loginUrl += "&" + stateParameterName + "=" + conversationId;

            logger.debug("loginUrl: {}", loginUrl);
            response.sendRedirect(loginUrl);
        } catch (final IOException e) {
            logger.error("Unable to redirect to CAS from ShibCas", e);
        }
    }

    /**
     * Uses the CAS CommonUtils to build the CAS Redirect URL.
     */
    private String constructRedirectUrl(final String serviceUrl, final boolean renew, final boolean gateway) {
        return CommonUtils.constructRedirectUrl(oauth2LoginUrl, "redirect_uri", serviceUrl, renew, gateway, null);
    }

    /**
     * Build addition querystring parameters
     *
     * @param request The original servlet request
     * @return an ampersand delimited list of querystring parameters
     */
    private String getAdditionalParameters(final HttpServletRequest request, final String authenticationKey) {
        final StringBuilder builder = new StringBuilder();
        for (final IParameterBuilder paramBuilder : parameterBuilders) {
            builder.append(paramBuilder.getParameterString(request, authenticationKey));
        }
        return builder.toString();
    }

    @Override
    public void init(final ServletConfig config) throws ServletException {
        super.init(config);

        final ApplicationContext ac = (ApplicationContext) config.getServletContext().getAttribute(WebApplicationContext.ROOT_WEB_APPLICATION_CONTEXT_ATTRIBUTE);
        parseProperties(ac.getEnvironment());

        buildParameterBuilders(ac);
    }

    /**
     * Check the idp's idp.properties file for the configuration
     *
     * @param environment a Spring Application Context's Environment object (tied to the IdP's root context)
     */
    private void parseProperties(final Environment environment) {
        logger.debug("reading properties from the idp.properties file");

        oauth2LoginUrl = environment.getRequiredProperty("shibcas.oauth2LoginUrl");
        logger.debug("shibcas.oauth2LoginUrl: {}", oauth2LoginUrl);

        serverName = environment.getRequiredProperty("shibcas.serverName");
        logger.debug("shibcas.serverName: {}", serverName);

        oauth2TokenUrl = environment.getRequiredProperty("shibcas.oauth2TokenUrl");
        logger.debug("shibcas.oauth2TokenUrl: {}", oauth2TokenUrl);

        oauth2ResourceUrl = environment.getRequiredProperty("shibcas.oauth2ResourceUrl");
        logger.debug("shibcas.oauth2ResourceUrl: {}", oauth2ResourceUrl);

        client_id = environment.getRequiredProperty("shibcas.oauth2clientid");
        logger.debug("shibcas.oauth2clientid: {}", client_id);

        client_secret = environment.getRequiredProperty("shibcas.oauth2clientsecret");
        logger.debug("shibcas.oauth2clientsecret: {}", client_secret);

        redirect_uri = environment.getRequiredProperty("shibcas.oauth2redirecturi");
        logger.debug("shibcas.oauth2redirecturi: {}", redirect_uri);

        principal_name = environment.getRequiredProperty("shibcas.oauth2principalname");
        logger.debug("shibcas.oauth2principalname: {}", principal_name);
        //Added End

    }

    private void buildParameterBuilders(final ApplicationContext applicationContext) {
        final Environment environment = applicationContext.getEnvironment();
        final String builders = StringUtils.defaultString(environment.getProperty("shibcas.parameterBuilders", ""));
        for (final String parameterBuilder : StringUtils.split(builders, ";")) {
            try {
                logger.debug("Loading parameter builder class {}", parameterBuilder);
                final Class clazz = Class.forName(parameterBuilder);
                final IParameterBuilder builder = IParameterBuilder.class.cast(clazz.newInstance());
                if (builder instanceof ApplicationContextAware) {
                    ((ApplicationContextAware) builder).setApplicationContext(applicationContext);
                }
                this.parameterBuilders.add(builder);
                logger.debug("Added parameter builder {}", parameterBuilder);
            } catch (final Throwable e) {
                logger.error("Error building parameter builder with name: " + parameterBuilder, e);
            }
        }
    }


    /**
     * Use the CAS CommonUtils to build the CAS Service URL.
     */
    protected String constructServiceUrl(final HttpServletRequest request, final HttpServletResponse response) {
        String serviceUrl = CommonUtils.constructServiceUrl(request, response, null, serverName,
                ExternalAuthentication.CONVERSATION_KEY, artifactParameterName, true);

/*        if ("embed".equalsIgnoreCase(entityIdLocation)) {
            serviceUrl += (new EntityIdParameterBuilder().getParameterString(request, false));
        }*/
        return serviceUrl;
    }

    /**
     * Like the above, but with a flag indicating whether we're validating a service ticket,
     * in which case we should not modify the service URL returned by CAS CommonUtils; this
     * avoids appending the entity ID twice when entityIdLocation=embed, since the ID is already
     * embedded in the string during validation.
     */
    protected String constructServiceUrl(final HttpServletRequest request, final HttpServletResponse response, final boolean isValidatingTicket) {
        return isValidatingTicket
                ? CommonUtils.constructServiceUrl(request, response, null, serverName, ExternalAuthentication.CONVERSATION_KEY, artifactParameterName, true)
                : constructServiceUrl(request, response);
    }

    private void loadErrorPage(final HttpServletRequest request, final HttpServletResponse response) {
        final RequestDispatcher requestDispatcher = request.getRequestDispatcher("/no-conversation-state.jsp");
        try {
            requestDispatcher.forward(request, response);
        } catch (final Exception e) {
            logger.error("Error rendering the empty conversation state (shib-cas-authn3) error view.");
            response.resetBuffer();
            response.setStatus(404);
        }
    }
}


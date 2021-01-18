package net.unicon.idp.externalauth;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
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
import java.util.regex.Matcher;
import java.util.regex.Pattern;


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

    private String casLoginUrl;
    private String serverName;
    private String casServerPrefix;
    private String oauth2tokenurl;
    private String resourceurl;
    private String client_id;
    private String client_secret;
    private String redirect_uri;

    //Added
    private String principal_name;
    private String redirect_uri_base;
    //Added End

    private final Set<IParameterBuilder> parameterBuilders = new HashSet<>();


    @Override
    protected void doGet(final HttpServletRequest request, final HttpServletResponse response) throws ServletException {
        // TODO: We have the opportunity to give back more to Shib than just the PRINCIPAL_NAME_KEY. Identify additional information
        try {
            final String ticket = CommonUtils.safeGetParameter(request, artifactParameterName);

            //Added
            final String redirect_uri_conversation = CommonUtils.safeGetParameter(request, ExternalAuthentication.CONVERSATION_KEY);
            final String redirect_uri_part = "?conversation=" + redirect_uri_conversation;
            final String redirect_uri_in = redirect_uri_base + redirect_uri_part;
            // Added End

            final String gatewayAttempted = CommonUtils.safeGetParameter(request, "gatewayAttempted");
            final String authenticationKey = ExternalAuthentication.startExternalAuthentication(request);
            final boolean force = Boolean.parseBoolean(request.getAttribute(ExternalAuthentication.FORCE_AUTHN_PARAM).toString());
            final boolean passive = Boolean.parseBoolean(request.getAttribute(ExternalAuthentication.PASSIVE_AUTHN_PARAM).toString());


            if ((ticket == null || ticket.isEmpty()) && (gatewayAttempted == null || gatewayAttempted.isEmpty())) {
                logger.debug("ticket and gatewayAttempted are not set; initiating oauth2 login redirect");

                // Added
                //startLoginRequest(request, response, force, passive, authenticationKey);
                startLoginRequest(request, response, force, passive, authenticationKey, redirect_uri_part);
                //Added End

                return;
            }

            if (ticket == null || ticket.isEmpty()) {
                logger.debug("Gateway/Passive returned no ticket, returning NoPassive.");
                request.setAttribute(ExternalAuthentication.AUTHENTICATION_ERROR_KEY, AuthnEventIds.NO_PASSIVE);
                ExternalAuthentication.finishExternalAuthentication(authenticationKey, request, response);
                return;
            }
            validatevalidateoauth2(request, response, redirect_uri_in, ticket, authenticationKey, force);

        } catch (final ExternalAuthenticationException e) {
            logger.warn("Error processing oauth2 authentication request", e);
            loadErrorPage(request, response);

        } catch (final Exception e) {
            logger.error("Something unexpected happened", e);
            request.setAttribute(ExternalAuthentication.AUTHENTICATION_ERROR_KEY, AuthnEventIds.AUTHN_EXCEPTION);
        }
    }

    private void validatevalidateoauth2(final HttpServletRequest request, final HttpServletResponse response, final String redirect_uri_in, final String ticket, final String authenticationKey, final boolean force) throws ExternalAuthenticationException, IOException {
        String uid = "";

        Map<String, Object> attributes = new HashMap<>();

        // Added
        // String token = getToken(ticket);
        String token = getToken(redirect_uri_in, ticket);
        //Added END

        try (CloseableHttpClient client = HttpClientBuilder.create().build()) {
            HttpPost conn = new HttpPost(resourceurl);
            conn.setHeader("User-Agent", "Mozilla/4.0 (compatible; MSIE 5.0; Windows NT; DigExt)");
            List<NameValuePair> params = new ArrayList<NameValuePair>(2);
            params.add(new BasicNameValuePair("access_token", token));
            conn.setEntity(new UrlEncodedFormEntity(params));
            HttpResponse respon = client.execute(conn);

            String result = IOUtils.readString(respon.getEntity().getContent());
            JsonObject json = JsonParser.parseString(result).getAsJsonObject();
            if(!json.has(this.principal_name) || !json.get(this.principal_name).isJsonPrimitive()) {
                throw new Exception(String.format(
                    "unable to locate principal_name as `%s` in oauth resource_url `%s` response: \n%s",
                    this.principal_name, this.resourceurl, result
                ));
            }

            uid = json.get(this.principal_name).getAsString();

            for(Entry<String, JsonElement> entry : json.entrySet()) {
                if(entry.getValue().isJsonPrimitive()) {
                    String value = entry.getValue().getAsJsonPrimitive().getAsString();
                    if (!value.isEmpty()) {
                        attributes.put(entry.getKey(), value);
                    }
                }
            }
        } catch (Exception e) {
            this.logger.error("error in wapaction,and e is " + e.getMessage(), e);
        }
        Collection<IdPAttributePrincipal> assertionAttributes = produceIdpAttributePrincipal(attributes);

        if (!assertionAttributes.isEmpty()) {
            Set<Principal> principals = new HashSet<>();
            principals.addAll(assertionAttributes);
            principals.add(new UsernamePrincipal(uid));
            request.setAttribute(ExternalAuthentication.SUBJECT_KEY, new Subject(false, principals, Collections.emptySet(), Collections.emptySet()));
        } else {
            request.setAttribute(ExternalAuthentication.PRINCIPAL_NAME_KEY, uid);
        }

        ExternalAuthentication.finishExternalAuthentication(authenticationKey, request, response);
    }


    private String getToken(String redirect_uri_in, String code) {
        String token = "";
        try (CloseableHttpClient client = HttpClientBuilder.create().build()) {
            HttpPost conn = new HttpPost(oauth2tokenurl);
            conn.setHeader("User-Agent", "Mozilla/4.0 (compatible; MSIE 5.0; Windows NT; DigExt)");
            List<NameValuePair> params = new ArrayList<NameValuePair>(2);
            params.add(new BasicNameValuePair("grant_type", "authorization_code"));
            params.add(new BasicNameValuePair("code", code));
            params.add(new BasicNameValuePair("client_id", client_id));
            params.add(new BasicNameValuePair("client_secret", client_secret));

            //Added
            // params.add(new BasicNameValuePair("redirect_uri", redirect_uri));
            params.add(new BasicNameValuePair("redirect_uri", redirect_uri_in));
            //Added END

            conn.setEntity(new UrlEncodedFormEntity(params));
            HttpResponse response = client.execute(conn);
            String result = IOUtils.readString(response.getEntity().getContent());

            logger.warn("original response: {} {} {}", oauth2tokenurl, params, result);
            Pattern p = Pattern.compile("\"(.*?)\"");
            Matcher m = p.matcher(result);
            int count = 0;
            while (m.find()) {
                if (count == 1) {
                    token = m.group(1);
                    count = 0;
                }
                if (m.group(1).equals("access_token")) {
                    count = 1;
                }
            }
        } catch (Exception e) {
            this.logger.error("error in wapaction,and e is " + e.getMessage(), e);
        }

        return token;

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

                                     //Added
                                     //final Boolean force, final Boolean passive, String authenticationKey) {
                                     final Boolean force, final Boolean passive, String authenticationKey, final String redirect_uri_part) {
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

            //Added
            //final String loginUrl = constructRedirectUrl(serviceUrl, force, passive) + getAdditionalParameters(request, authenticationKey);
            final String loginUrl = constructRedirectUrl(serviceUrl, force, passive) + getAdditionalParameters(request, authenticationKey) + redirect_uri_part;
            //Added End

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
        return CommonUtils.constructRedirectUrl(casLoginUrl, "redirect_uri", serviceUrl, renew, gateway, null);
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

        casServerPrefix = environment.getRequiredProperty("shibcas.oauth2UrlPrefix");
        logger.debug("shibcas.oauth2UrlPrefix: {}", casServerPrefix);

        casLoginUrl = environment.getRequiredProperty("shibcas.oauth2LoginUrl");
        logger.debug("shibcas.oauth2LoginUrl: {}", casLoginUrl);

        serverName = environment.getRequiredProperty("shibcas.serverName");
        logger.debug("shibcas.serverName: {}", serverName);

        oauth2tokenurl = environment.getRequiredProperty("shibcas.oauth2TokenUrl");
        logger.debug("shibcas.oauth2TokenUrl: {}", oauth2tokenurl);

        resourceurl = environment.getRequiredProperty("shibcas.oauth2ResourceUrl");
        logger.debug("shibcas.oauth2ResourceUrl: {}", resourceurl);

        client_id = environment.getRequiredProperty("shibcas.oauth2clientid");
        logger.debug("shibcas.oauth2clientid: {}", client_id);

        client_secret = environment.getRequiredProperty("shibcas.oauth2clientsecret");
        logger.debug("shibcas.oauth2clientsecret: {}", client_secret);

        redirect_uri = environment.getRequiredProperty("shibcas.oauth2redirecturi");
        logger.debug("shibcas.oauth2redirecturi: {}", redirect_uri);

        //Added
        redirect_uri_base = environment.getRequiredProperty("shibcas.oauth2redirecturiBase");
        logger.debug("shibcas.oauth2redirecturiBase: {}", redirect_uri_base);

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


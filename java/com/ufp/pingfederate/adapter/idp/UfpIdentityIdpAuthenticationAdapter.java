package com.ufp.pingfederate.adapter.idp;

import java.io.File;
import java.io.IOException;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.util.Enumeration;
import java.util.List;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.sourceid.common.ResponseTemplateRenderer;
import org.sourceid.saml20.adapter.AuthnAdapterException;
import org.sourceid.saml20.adapter.attribute.AttributeValue;
import org.sourceid.saml20.adapter.conf.Configuration;
import org.sourceid.saml20.adapter.conf.Field;
import org.sourceid.saml20.adapter.gui.AdapterConfigurationGuiDescriptor;
import org.sourceid.saml20.adapter.gui.ClientCertKeypairFieldDescriptor;
import org.sourceid.saml20.adapter.gui.TextFieldDescriptor;
import org.sourceid.saml20.adapter.gui.TrustedCAFieldDescriptor;

import org.sourceid.saml20.adapter.gui.validation.FieldValidator;
import org.sourceid.saml20.adapter.gui.validation.ValidationException;
import org.sourceid.saml20.adapter.idp.authn.AuthnPolicy;
import org.sourceid.saml20.adapter.idp.authn.IdpAuthenticationAdapter;
import org.sourceid.saml20.adapter.idp.authn.IdpAuthnAdapterDescriptor;

import com.pingidentity.sdk.AuthnAdapterResponse;
import com.pingidentity.sdk.AuthnAdapterResponse.AUTHN_STATUS;
import com.pingidentity.sdk.IdpAuthenticationAdapterV2;
import com.pingidentity.sdk.template.TemplateRendererUtil;

import com.ufp.identity4j.data.AuthenticationContext;
import com.ufp.identity4j.data.AuthenticationPretext;
import com.ufp.identity4j.data.DisplayItem;

import com.ufp.identity4j.provider.IdentityServiceProvider;
import com.ufp.identity4j.truststore.KeyManagerFactoryBuilder;
import com.ufp.identity4j.truststore.TrustManagerFactoryBuilder;
import com.ufp.identity4j.truststore.IdentityHostnameVerifier;
import com.ufp.identity4j.resolver.StaticIdentityResolver;

/**
 * <p>
 * This class is an example of an IdP authentication adapter that uses the client's (or last proxy that sent the
 * request) IPv4 address to identify the user. If authenticated, the user will be assigned a guest role by default. In
 * order to be have a corporate role, this adapter needs to be chained to another adapter via a Composite Adapter.
 * </p>
 * <p>
 * For simplicity sake, if the client has a non-loopback IPv6 address the authentication will fail.
 * </p>
 * This adapter is simply a sample, and in production (at a minimum) would likely be chained with another adapter to
 * further identify and authenticate the end user.
 */
public class UfpIdentityIdpAuthenticationAdapter implements IdpAuthenticationAdapterV2
{
    private static final String ATTR_NAME = "name"; // use the IP address to get to identify the user
    private static final String ATTR_ROLE = "role"; // identify the role of the user, i.e. guest, corp_user
    private static final String CHAINED_ATTR_USERNAME = "username";
    private static final String ROLE_GUEST = "GUEST";
    private static final String ROLE_CORP_USER = "CORP_USER";
    private static final String CONFIG_KEY_PASSWORD = "Private Key Password";
    private static final String CONFIG_KEY_FILENAME = "Private Key File Name";
    private static final String CONFIG_CLIENT_CERT = "Client Certificate Name";
    private static final String CONFIG_TRUSTED_CERT = "Trusted Certificate Name";

    private final IdpAuthnAdapterDescriptor descriptor;
    private IdentityServiceProvider identityServiceProvider;
    private Log log = LogFactory.getLog(this.getClass());
    /**
     * Constructor for the Sample Subnet Adapter. Initializes the authentication adapter descriptor so PingFederate can
     * generate the proper configuration GUI
     */
    public UfpIdentityIdpAuthenticationAdapter()
    {
        // Create text field to represent the private key password
        TextFieldDescriptor privateKeyPasswordField = new TextFieldDescriptor(CONFIG_KEY_PASSWORD,
                "Enter the private key password", true);

        TextFieldDescriptor privateKeyFileNameField = new TextFieldDescriptor(CONFIG_KEY_FILENAME,
                "Enter the private key filename");
        /*
        ClientCertKeypairFieldDescriptor clientCertKeypairField = new ClientCertKeypairFieldDescriptor(CONFIG_CLIENT_CERT,
                "Choose the client certificate");
        TrustedCAFieldDescriptor trustedCAField = new TrustedCAFieldDescriptor(CONFIG_TRUSTED_CERT,
                "Choose the trusted certificate");
        */

        // Create a GUI descriptor
        AdapterConfigurationGuiDescriptor guiDescriptor = new AdapterConfigurationGuiDescriptor(
                "Set the details to enable UFP Identity");
        guiDescriptor.addField(privateKeyPasswordField);
        guiDescriptor.addField(privateKeyFileNameField);
        /*
        guiDescriptor.addField(clientCertKeypairField);
        guiDescriptor.addField(trustedCAField);
        */

        // Create the Idp authentication adapter descriptor
        Set<String> contract = new HashSet<String>();
        contract.add(ATTR_NAME);
        contract.add(ATTR_ROLE);
        descriptor = new IdpAuthnAdapterDescriptor(this, "UFP Identity IdP Adapter", contract, false, guiDescriptor, false, "1.0");
    }

    /**
     * The PingFederate server will invoke this method on your adapter implementation to discover metadata about the
     * implementation. This included the adapter's attribute contract and a description of what configuration fields to
     * render in the GUI. <br/>
     * <br/>
     * Your implementation of this method should return the same IdpAuthnAdapterDescriptor object from call to call -
     * behaviour of the system is undefined if this convention is not followed.
     *
     * @return an IdpAuthnAdapterDescriptor object that describes this IdP adapter implementation.
     */
    public IdpAuthnAdapterDescriptor getAdapterDescriptor()  {
        return descriptor;
    }

    /**
     * This is the method that the PingFederate server will invoke during processing of a single logout to terminate a
     * security context for a user at the external application or authentication provider service.
     * <p>
     * If your implementation of this method needs to operate asynchronously, it just needs to write to the
     * HttpServletResponse as appropriate and commit it. Right after invoking this method the PingFederate server checks
     * to see if the response has been committed. If the response has been committed, PingFederate saves the state it
     * needs and discontinues processing for the current transaction. Processing of the transaction is continued when
     * the user agent returns to the <code>resumePath</code> at the PingFederate server at which point the server
     * invokes this method again. This series of events will be repeated until this method returns without committing
     * the response. When that happens (which could be the first invocation) PingFederate will complete the protocol
     * transaction processing with the return result of this method.
     * </p>
     * <p>
     * Note that if the response is committed, then PingFederate ignores the return value. Only the return value of an
     * invocation that does not commit the response will be used. Accessing the HttpSession from the request is not
     * recommended and doing so is deprecated. Use {@link org.sourceid.saml20.adapter.state.SessionStateSupport} as an
     * alternative.
     * </p>
     * <p>
     *
     * <b>Note on SOAP logout:</b> If this logout is being invoked as the result of a back channel protocol request, the
     * request, response and resumePath parameters will all be null as they have no meaning in such a context where the
     * user agent is inaccessible.
     * </p>
     * <p>
     * In this example, no extra action is needed to logout so simply return true.
     * </p>
     *
     * @param authnIdentifiers
     *            the map of authentication identifiers originally returned to the PingFederate server by the
     *            {@link #lookupAuthN} method. This enables the adapter to associate a security context or session
     *            returned by lookupAuthN with the invocation of this logout method.
     * @param req
     *            the HttpServletRequest can be used to read cookies, parameters, headers, etc. It can also be used to
     *            find out more about the request like the full URL the request was made to.
     * @param resp
     *            the HttpServletResponse. The response can be used to facilitate an asynchronous interaction. Sending a
     *            client side redirect or writing (and flushing) custom content to the response are two ways that an
     *            invocation of this method allows for the adapter to take control of the user agent. Note that if
     *            control of the user agent is taken in this way, then the agent must eventually be returned to the
     *            <code>resumePath</code> endpoint at the PingFederate server to complete the protocol transaction.
     * @param resumePath
     *            the relative URL that the user agent needs to return to, if the implementation of this method
     *            invocation needs to operate asynchronously. If this method operates synchronously, this parameter can
     *            be ignored. The resumePath is the full path portion of the URL - everything after hostname and port.
     *            If the hostname, port, or protocol are needed, they can be derived using the HttpServletRequest.
     * @return a boolean indicating if the logout was successful.
     * @throws AuthnAdapterException
     *             for any unexpected runtime problem that the implementation cannot handle.
     * @throws IOException
     *             for any problem with I/O (typically any operation that writes to the HttpServletResponse will throw
     *             an IOException.
     *
     * @see IdpAuthenticationAdapter#logoutAuthN(Map, HttpServletRequest, HttpServletResponse, String)
     */
    @SuppressWarnings("rawtypes")
    public boolean logoutAuthN(Map authnIdentifiers, HttpServletRequest req, HttpServletResponse resp, String resumePath) throws AuthnAdapterException, IOException {
        return true;
    }

    /**
     * This method is called by the PingFederate server to push configuration values entered by the administrator via
     * the dynamically rendered GUI configuration screen in the PingFederate administration console. Your implementation
     * should use the {@link Configuration} parameter to configure its own internal state as needed. The tables and
     * fields available in the Configuration object will correspond to the tables and fields defined on the
     * {@link org.sourceid.saml20.adapter.gui.AdapterConfigurationGuiDescriptor} on the AuthnAdapterDescriptor returned
     * by the {@link #getAdapterDescriptor()} method of this class. <br/>
     * <br/>
     * Each time the PingFederate server creates a new instance of your adapter implementation this method will be
     * invoked with the proper configuration. All concurrency issues are handled in the server so you don't need to
     * worry about them here. The server doesn't allow access to your adapter implementation instance until after
     * creation and configuration is completed.
     *
     * @param configuration
     *            the Configuration object constructed from the values entered by the user via the GUI.
     */
    public void configure(Configuration configuration) {
        identityServiceProvider = new IdentityServiceProvider();

        // setup the key manager factory
        String defaultDirectory = System.getProperty("pf.server.default.dir");
        log.info("current pf_server_default is " + defaultDirectory);

        KeyManagerFactoryBuilder keyManagerFactoryBuilder = new KeyManagerFactoryBuilder();
        String keyStoreFileName = configuration.getFieldValue(CONFIG_KEY_FILENAME);
        if (StringUtils.isEmpty(keyStoreFileName))
            keyStoreFileName = "example.com.p12";
        log.info("keystore filename is " + keyStoreFileName);
        keyManagerFactoryBuilder.setStore(new File(defaultDirectory + "/conf/ufp-identity/" + keyStoreFileName));
        String password = configuration.getFieldValue(CONFIG_KEY_PASSWORD);
        log.info("got configuration password of " + password);
        keyManagerFactoryBuilder.setPassphrase(password);

        // setup the trust store
        TrustManagerFactoryBuilder trustManagerFactoryBuilder = new TrustManagerFactoryBuilder();
        trustManagerFactoryBuilder.setStore(new File(defaultDirectory + "/conf/ufp-identity/truststore.jks"));
        trustManagerFactoryBuilder.setPassphrase("pSnHa(3QDixmi%\\");

        // set provider properties
        identityServiceProvider.setKeyManagerFactoryBuilder(keyManagerFactoryBuilder);
        identityServiceProvider.setTrustManagerFactoryBuilder(trustManagerFactoryBuilder);

        identityServiceProvider.setHostnameVerifier(new IdentityHostnameVerifier("ufp.com"));
        identityServiceProvider.setIdentityResolver(new StaticIdentityResolver("https://identity.ufp.com/identity-services/services/"));
        // must call this
        identityServiceProvider.afterPropertiesSet();
    }

    /**
     * This method is used to retrieve information about the adapter (e.g. AuthnContext).
     * <p>
     * In this example the method not used, return null
     * </p>
     *
     * @return a map
     */
    public Map<String, Object> getAdapterInfo() {
        return null;
    }

    private boolean hasAttribute(HttpSession httpSession, String attributeName) {
        return (httpSession.getAttribute(attributeName) != null);
    }

    /**
     * This is an extended method that the PingFederate server will invoke during processing of a single sign-on
     * transaction to lookup information about an authenticated security context or session for a user at the external
     * application or authentication provider service.
     * <p>
     * If your implementation of this method needs to operate asynchronously, it just needs to write to the
     * HttpServletResponse as appropriate and commit it. Right after invoking this method the PingFederate server checks
     * to see if the response has been committed. If the response has been committed, PingFederate saves the state it
     * needs and discontinues processing for the current transaction. Processing of the transaction is continued when
     * the user agent returns to the <code>resumePath</code> at the PingFederate server at which point the server
     * invokes this method again. This series of events will be repeated until this method returns without committing
     * the response. When that happens (which could be the first invocation) PingFederate will complete the protocol
     * transaction processing with the return result of this method.
     * </p>
     * <p>
     * Note that if the response is committed, then PingFederate ignores the return value. Only the return value of an
     * invocation that does not commit the response will be used.
     * </p>
     * <p>
     * If this adapter is implemented asynchronously, it's recommended that the user agent always returns to the <code>
     * resumePath</code> in order to be compatible with Composite Adapter's "Sufficent" adapter chaining policy. The
     * Composite Adapter allows an Administrator to "chain" a selection of available adapter instances for a connection.
     * At runtime, adapter chaining means that SSO requests are passed sequentially through each adapter instance
     * specified until one or more authentication results are found for the user. If the user agent does not return
     * control to PingFederate for failed authentication scenarios, then the authentication chain will break and should
     * not be used with Composite Adapter's "Sufficient" chaining policy.
     * </p>
     * <p>
     * In this example, we determine if the client (or the last proxy) is on the configured subnet. If the client has an
     * IPv6 address that's not ::1, fail immediately. If the user was previously authenticated by another adapter assign
     * it a corporate role, otherwise use the guest role.
     * </p>
     *
     * @param req
     *            the HttpServletRequest can be used to read cookies, parameters, headers, etc. It can also be used to
     *            find out more about the request like the full URL the request was made to. Accessing the HttpSession
     *            from the request is not recommended and doing so is deprecated. Use
     *            {@link org.sourceid.saml20.adapter.state.SessionStateSupport} as an alternative.
     * @param resp
     *            the HttpServletResponse. The response can be used to facilitate an asynchronous interaction. Sending a
     *            client side redirect or writing (and flushing) custom content to the response are two ways that an
     *            invocation of this method allows for the adapter to take control of the user agent. Note that if
     *            control of the user agent is taken in this way, then the agent must eventually be returned to the
     *            <code>resumePath</code> endpoint at the PingFederate server to complete the protocol transaction.
     * @param inParameters
     *            A map that contains a set of input parameters. The input parameters provided are detailed in
     *            {@link IdpAuthenticationAdapterV2}, prefixed with <code>IN_PARAMETER_NAME_*</code> i.e.
     *            {@link IdpAuthenticationAdapterV2#IN_PARAMETER_NAME_RESUME_PATH}.
     * @return {@link AuthnAdapterResponse} The return value should not be null.
     * @throws AuthnAdapterException
     *             for any unexpected runtime problem that the implementation cannot handle.
     * @throws IOException
     *             for any problem with I/O (typically any operation that writes to the HttpServletResponse).
     */
    @SuppressWarnings("unchecked")
    public AuthnAdapterResponse lookupAuthN(HttpServletRequest req, HttpServletResponse resp, Map<String, Object> inParameters) throws AuthnAdapterException, IOException {
        String spEntityId = (String) inParameters.get(IN_PARAMETER_NAME_PARTNER_ENTITYID);
        Map<String, AttributeValue> chainedAttributes = (Map<String, AttributeValue>) inParameters.get(IN_PARAMETER_NAME_CHAINED_ATTRIBUTES);

        AuthnAdapterResponse authnAdapterResponse = new AuthnAdapterResponse();

        // Get the client's IP address
        String remoteAddressStr = req.getRemoteAddr();

        // log authentication... in this case print to system out
        log.info("Client '" + remoteAddressStr + "' is trying to sign on to SP '" + spEntityId + "'");

        Map<String, Object> attributes = new HashMap<String, Object>();
        Map<String, Object> responseParams = new HashMap<String, Object>();

        log.info("inParameters:");
        for (Map.Entry<String, Object> e : inParameters.entrySet()) {
            StringBuffer sb = new StringBuffer();
            sb.append(" " + e.getKey());
            if (e.getValue() != null)
                sb.append(" : " + e.getValue().toString());
            log.info(sb.toString());
        }
        log.info("request Parameters:");
        for (Map.Entry<String, String[]> reqParam : req.getParameterMap().entrySet()) {
            log.info(" " + reqParam.getKey() + " : " + reqParam.getValue()[0].toString());
        }

        log.info("request session parameters");
        HttpSession httpSession = req.getSession();
        for (Enumeration<String> e = httpSession.getAttributeNames() ; e.hasMoreElements() ;) {
            String key = e.nextElement();
            log.info(" " +  key + " : " + httpSession.getAttribute(key));
        }

        /**
         * Because the AbstractPasswordIdpAuthnAdapter.form.template.html seems to indicate a successful POST by setting $var5 to 'clicked'
         * thats what key off for further processing.
         */
        boolean error = false;
        if (StringUtils.equals(req.getParameter("$var5"), "clicked")) {
            /**
             * UFP Identity is two-pass so we have to maintain state indicating where we are. The typical way we do this is with session variables.
             * Since Velocity template don't seem to be able to access the session, we have to propagate that state into the template.
             */
            error = true; // if were clicked, only a few cases are non-error
            if(!hasAttribute(httpSession, "IDENTITY_USERNAME") && !hasAttribute(httpSession, "IDENTITY_DISPLAY_ITEMS")) {
                // we either dont have state
                String postedUsername = req.getParameter("username");

                if (StringUtils.isNotEmpty(postedUsername)) {
                    AuthenticationPretext authenticationPretext = identityServiceProvider.preAuthenticate(postedUsername, req);
                    if (authenticationPretext != null) {
                        if (authenticationPretext.getResult().getValue().equals("SUCCESS")) {
                            httpSession.setAttribute("IDENTITY_USERNAME", authenticationPretext.getName());
                            httpSession.setAttribute("IDENTITY_DISPLAY_ITEMS", authenticationPretext.getDisplayItem());
                            error = false;
                        } else {
                            log.error(authenticationPretext.getResult().getMessage());
                        }
                    } else {
                        log.error("no authentication pretext for " + postedUsername);
                    }
                } else {
                    log.error("no posted username");
                }
            } else if (hasAttribute(httpSession, "IDENTITY_DISPLAY_ITEMS") && hasAttribute(httpSession, "IDENTITY_USERNAME")) {
                // or we do
                Map<String, String[]> responseMap = new HashMap<String, String[]>();
                List<DisplayItem> displayItems = (List<DisplayItem>)httpSession.getAttribute("IDENTITY_DISPLAY_ITEMS");
                for (DisplayItem displayItem : displayItems) {
                     log.info("found display item named " + displayItem.getDisplayName() + " with input named " + displayItem.getName());
                     String parameter = req.getParameter(displayItem.getName());
                     if (parameter != null)
                         responseMap.put(displayItem.getName(), new String [] { parameter } );
                }
                Object response = identityServiceProvider.authenticate((String)httpSession.getAttribute("IDENTITY_USERNAME"), req, responseMap);
                if (response != null) {
                    if (response instanceof AuthenticationPretext) {
                        AuthenticationPretext authenticationPretext = (AuthenticationPretext)response;
                        if (authenticationPretext.getResult().getValue().equals("CONTINUE")) {
                            httpSession.setAttribute("IDENTITY_DISPLAY_ITEMS", authenticationPretext.getDisplayItem());
                            responseParams.put("message", authenticationPretext.getResult().getMessage());
                            error = false;
                        }
                    } else if (response instanceof AuthenticationContext) {
                        AuthenticationContext authenticationContext =  (AuthenticationContext)response;
                        if (authenticationContext.getResult().getValue().equals("SUCCESS")) {
                            httpSession.removeAttribute("IDENTITY_USERNAME");
                            httpSession.removeAttribute("IDENTITY_DISPLAY_ITEMS");
                            // we return directly from here since we are completely done
                            attributes.put(ATTR_NAME, authenticationContext.getName());
                            attributes.put(ATTR_ROLE, ROLE_GUEST);
                            authnAdapterResponse.setAttributeMap(attributes);
                            authnAdapterResponse.setAuthnStatus(AUTHN_STATUS.SUCCESS);
                            return authnAdapterResponse;
                        } else if (authenticationContext.getResult().getValue().equals("RESET")) {
                            httpSession.removeAttribute("IDENTITY_USERNAME");
                            httpSession.removeAttribute("IDENTITY_DISPLAY_ITEMS");
                            error = false;
                        } else
                            log.info("returned result " + authenticationContext.getResult().getValue() + ", and message " + authenticationContext.getResult().getMessage());
                    } else
                        log.info("unknown response object: " + response.toString());
                } else
                    log.info("no response");
            }

        }
        if (error) {
            responseParams.put("showError", true);
        }

        String username = (String)httpSession.getAttribute("IDENTITY_USERNAME");
        if (username != null)
            responseParams.put("username", username);

        List<DisplayItem> displayItems = (List<DisplayItem>)httpSession.getAttribute("IDENTITY_DISPLAY_ITEMS");
        if ((displayItems != null) && !displayItems.isEmpty())
            responseParams.put("displayItems", displayItems);

        responseParams.put("action", inParameters.get("com.pingidentity.adapter.input.parameter.resume.path").toString());

        TemplateRendererUtil.render(req, resp, "html.form.ufpidentity.template.html", responseParams);
        authnAdapterResponse.setAuthnStatus(AUTHN_STATUS.IN_PROGRESS);
        return authnAdapterResponse;
    }

    /**
     * This method is deprecated. It is not called when IdpAuthenticationAdapterV2 is implemented. It is replaced by
     * {@link #lookupAuthN(HttpServletRequest, HttpServletResponse, Map)}
     *
     * @deprecated
     */
    @SuppressWarnings(value = { "rawtypes" })
    public Map lookupAuthN(HttpServletRequest req, HttpServletResponse resp, String partnerSpEntityId, AuthnPolicy authnPolicy, String resumePath) throws AuthnAdapterException, IOException {
        throw new UnsupportedOperationException();
    }
}

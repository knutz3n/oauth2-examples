import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.apache.hc.client5.http.classic.methods.HttpPost;
import org.apache.hc.client5.http.entity.UrlEncodedFormEntity;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.CloseableHttpResponse;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.core5.http.NameValuePair;
import org.apache.hc.core5.http.ParseException;
import org.apache.hc.core5.http.io.entity.EntityUtils;
import org.apache.hc.core5.http.message.BasicNameValuePair;
import org.apache.hc.core5.net.URIBuilder;

import java.awt.Desktop;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.interfaces.RSAPrivateKey;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.stream.Stream;

import static java.lang.String.join;
import static java.nio.charset.StandardCharsets.UTF_8;
import static java.time.temporal.ChronoUnit.SECONDS;
import static java.util.Arrays.stream;
import static java.util.stream.Collectors.toList;

public class OAuth2Client {

    private static final String CLIENT_ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
    private static final String GRANT_TYPE_RFC8693 = "urn:ietf:params:oauth:grant-type:token-exchange";
    private static final String REQUESTED_TOKEN_TYPE_ACCESS_TOKEN = "urn:ietf:params:oauth:token-type:access_token";
    private static final String REQUESTED_TOKEN_TYPE_REFRESH_TOKEN = "urn:ietf:params:oauth:token-type:refresh_token";

    private static final String DEFAULT_CALLBACK_SERVER_HOST = "localhost";
    private static final int DEFAULT_CALLBACK_SERVER_PORT = 8000;

    private final Clock clock;
    private final RSAPrivateKey privateKey;
    private final int callbackServerPort;
    private final String authEndpoint;
    private final String tokenEndpoint;
    private final String clientId;
    private final String clientAssertionAudience;
    private final String redirectUri;
    private final CloseableHttpClient httpClient;
    private final ObjectMapper mapper;

    public OAuth2Client(
            int callbackServerPort,
            String authEndpoint,
            String tokenEndpoint,
            String clientId,
            RSAPrivateKey privateKey,
            String clientAssertionAudience
    ) {
        this.clock = Clock.systemUTC();
        this.privateKey = privateKey;
        this.callbackServerPort = callbackServerPort;
        this.redirectUri = "http://" + DEFAULT_CALLBACK_SERVER_HOST + ":" + callbackServerPort + "/";
        this.authEndpoint = authEndpoint;
        this.tokenEndpoint = tokenEndpoint;
        this.clientId = clientId;
        this.clientAssertionAudience = clientAssertionAudience;
        this.httpClient = HttpClients.createDefault();
        this.mapper = new ObjectMapper();
    }

    public OAuth2Client(int callbackServerPort, String authEndpoint, String tokenEndpoint, String clientId) {
        this(callbackServerPort, authEndpoint, tokenEndpoint, clientId, null, null);
    }

    public OAuth2Client(String authEndpoint, String tokenEndpoint, String clientId) {
        this(DEFAULT_CALLBACK_SERVER_PORT, authEndpoint, tokenEndpoint, clientId, null, null);
    }

    /**
     * Example of a complete OAuth2 Authorization Code Flow.
     * <p>
     * 1. Start a HTTP server on localhost
     * 2. Build a authorization URL with the localhost HTTP server as redirect URI parameter
     * 3. Open the authorization URL in the default browser
     * 4. Exchange the authorization code in tokens at the token endpoint
     * <p>
     * This method is synchronous and will block until the authorization code flow is completed.
     * It also requires the client to have http://localhost:8000/ configured as a valid redirect URI.
     *
     * @param scope Scope parameter for the authorization request
     * @return A response entity from the token exchange
     */
    public TokenResponseEntity authorizationCodeFlow(String... scope) {
        final String state = UUID.randomUUID().toString();
        final URI authorizationUri;
        try {
            authorizationUri = new URIBuilder(authEndpoint)
                    .addParameter("client_id", clientId)
                    .addParameter("redirect_uri", redirectUri)
                    .addParameter("state", state)
                    .addParameter("scope", "openid " + join(" ", scope))
                    .addParameter("response_type", "code")
                    .addParameter("response_mode", "query")
                    .build();
        } catch (URISyntaxException e) {
            throw new RuntimeException("Unable to build authenticate URI", e);
        }

        final HttpServer server;
        try {
            server = HttpServer.create(new InetSocketAddress(DEFAULT_CALLBACK_SERVER_HOST, callbackServerPort), 0);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        final CompletableFuture<TokenResponseEntity> authTokenFuture = new CompletableFuture<>();
        server.createContext("/", exchange -> {
            final String authorizationCode = extractQueryParameter(exchange.getRequestURI().getQuery(), "code");
            final String responseState = extractQueryParameter(exchange.getRequestURI().getQuery(), "state");

            if (!state.equals(responseState)) {
                sendPlainTextResponse(exchange, 500, "Unexpected state parameter. Expected: " + state);
                authTokenFuture.completeExceptionally(new ErrorResponseException(0, "Unexpected state response parameter"));
            }

            try {
                final TokenResponseEntity response = codeToToken(authorizationCode);
                sendPlainTextResponse(exchange, 200,
                        "Expires In: " + response.getExpiresIn() + "\n"
                                + "Refresh Expires In: " + response.getRefreshExpiresIn() + "\n"
                                + "Session State: " + response.getSessionState() + "\n"
                                + "Not Before Policy: " + response.getNotBeforePolicy() + "\n"
                                + "Token Type: " + response.getTokenType() + "\n"
                                + "Scope: " + (response.getScope() == null ? null : join(", ", response.getScope())) + "\n\n"
                                + "Access Token:\n" + response.getRawAccessToken() + "\n" + response.getParsedAccessToken() + "\n\n"
                                + "ID Token:\n" + response.getRawIdToken() + "\n" + response.getParsedIdToken() + "\n\n"
                                + "Refresh Token:\n" + response.getRawRefreshToken()
                );
                authTokenFuture.complete(response);

            } catch (ErrorResponseException e) {
                final String htmlResponse = "Status: " + e.getStatusCode() + "\n" + "Error:\n" + e.getErrorPayload();
                sendPlainTextResponse(exchange, 500, htmlResponse);
                authTokenFuture.completeExceptionally(e);
            }

        });

        try {
            server.start();
            if (Desktop.isDesktopSupported() && Desktop.getDesktop().isSupported(Desktop.Action.BROWSE)) {
                System.out.println("Open browser:\n" + authorizationUri);
                Desktop.getDesktop().browse(authorizationUri);
            }
            return authTokenFuture.get(60, TimeUnit.SECONDS);
        } catch (IOException | InterruptedException | ExecutionException | TimeoutException e) {
            throw new RuntimeException("Unable to get authorization code", e);
        } finally {
            server.stop(1);
        }
    }

    /**
     * Exchange an authorization code to tokens
     *
     * @param authorizationCode The authorization code flow from the authorization request
     * @return A token response entity from the exchange request
     */
    public TokenResponseEntity codeToToken(String authorizationCode) {
        final String clientAssertion = createClientAssertion();

        final List<BasicNameValuePair> formParameters = new ArrayList<>();
        if (clientAssertion == null) {
            formParameters.add(new BasicNameValuePair("client_id", clientId));
        } else {
            formParameters.add(new BasicNameValuePair("client_assertion_type", CLIENT_ASSERTION_TYPE));
            formParameters.add(new BasicNameValuePair("client_assertion", clientAssertion));
        }

        formParameters.add(new BasicNameValuePair("redirect_uri", redirectUri));
        formParameters.add(new BasicNameValuePair("grant_type", "authorization_code"));
        formParameters.add(new BasicNameValuePair("code", authorizationCode));

        final HttpPost request = new HttpPost(tokenEndpoint);
        request.setEntity(new UrlEncodedFormEntity(formParameters, UTF_8));

        try (CloseableHttpResponse response = httpClient.execute(request)) {
            return getTokenResponseEntity(response);
        } catch (ParseException | IOException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Example of a token exchange according to RFC8693.
     * Note that the implementation details of a token exchange is very dependent on the authorization server,
     * and this is just a basic example which provides a subject token and expect a token back for some defined audience.
     *
     * @param subjectToken The subject token for the exchange.
     * @param scope        desired scope for the exchange
     * @return the response entity from the token exchange
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc8693">RFC8693</a>
     */
    public TokenResponseEntity exchangeToken(String subjectToken, String... scope) {
        final String clientAssertion = createClientAssertion();
        final HttpPost httpPost = new HttpPost(tokenEndpoint);
        httpPost.setEntity(new UrlEncodedFormEntity(List.of(
                new BasicNameValuePair("client_assertion_type", CLIENT_ASSERTION_TYPE),
                new BasicNameValuePair("client_assertion", clientAssertion),
                new BasicNameValuePair("grant_type", GRANT_TYPE_RFC8693),
                new BasicNameValuePair("subject_token", subjectToken),
                new BasicNameValuePair("requested_token_type", REQUESTED_TOKEN_TYPE_REFRESH_TOKEN),
                new BasicNameValuePair("scope", join(" ", scope)),
                new BasicNameValuePair("audience", clientId)
        ), UTF_8));

        try (final CloseableHttpResponse response = httpClient.execute(httpPost)) {
            return getTokenResponseEntity(response);
        } catch (IOException | ParseException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Client Credentials Flow using Client Assertion as defined by RFC7523
     *
     * @param scope desired scope for the request
     * @return the response entity from the token request
     */
    public TokenResponseEntity clientCredentialsGrantFlow(String... scope) {
        final String clientAssertion = createClientAssertion();
        final HttpPost request = new HttpPost(tokenEndpoint);
        request.setEntity(new UrlEncodedFormEntity(List.of(
                new BasicNameValuePair("client_assertion_type", CLIENT_ASSERTION_TYPE),
                new BasicNameValuePair("client_assertion", clientAssertion),
                new BasicNameValuePair("grant_type", "client_credentials"),
                new BasicNameValuePair("scope", String.join(" ", scope))
        ), UTF_8));
        try (CloseableHttpResponse response = httpClient.execute(request)) {
            return getTokenResponseEntity(response);
        } catch (IOException | ParseException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Example on how to refresh a token using client assertion with a signed JWT
     *
     * @param refreshToken the refresh token from a previous authorization request
     * @return the response entity from the token request
     */
    public TokenResponseEntity refreshTokenFlow(String refreshToken) {
        final String clientAssertion = createClientAssertion();
        final HttpPost request = new HttpPost(tokenEndpoint);
        request.setEntity(new UrlEncodedFormEntity(List.of(
                new BasicNameValuePair("client_assertion_type", CLIENT_ASSERTION_TYPE),
                new BasicNameValuePair("client_assertion", clientAssertion),
                new BasicNameValuePair("client_id", clientId),
                new BasicNameValuePair("grant_type", "refresh_token"),
                new BasicNameValuePair("refresh_token", refreshToken)
        ), UTF_8));
        try (CloseableHttpResponse response = httpClient.execute(request)) {
            return getTokenResponseEntity(response);
        } catch (IOException | ParseException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * OAuth2 Password Grant example with JWT as client assertion.
     * <p>
     * Notice that this flow is a legacy flow and should typically not be used except for specific edge cases.
     *
     * @param username    User's username
     * @param password    User's password
     * @param extraFields Extra parameters passed to the token HTTP request
     * @return the response entity from the token request
     */
    public TokenResponseEntity password(String username, String password, NameValuePair... extraFields) {
        final String clientAssertion = createClientAssertion();
        final HttpPost request = new HttpPost(tokenEndpoint);
        request.setEntity(new UrlEncodedFormEntity(
                Stream.concat(Stream.of(
                                new BasicNameValuePair("client_assertion_type", CLIENT_ASSERTION_TYPE),
                                new BasicNameValuePair("client_assertion", clientAssertion),
                                new BasicNameValuePair("client_id", clientId),
                                new BasicNameValuePair("grant_type", "password"),
                                new BasicNameValuePair("username", username),
                                new BasicNameValuePair("password", password)
                        ), stream(extraFields)
                ).collect(toList()))
        );
        try (CloseableHttpResponse response = httpClient.execute(request)) {
            return getTokenResponseEntity(response);
        } catch (IOException | ParseException e) {
            throw new RuntimeException(e);
        }
    }

    private TokenResponseEntity getTokenResponseEntity(CloseableHttpResponse response) throws IOException, ParseException {
        if (response.getCode() == 200) {
            return mapper.readerFor(TokenResponseEntity.class).readValue(response.getEntity().getContent());
        } else {
            throw new ErrorResponseException(response.getCode(), EntityUtils.toString(response.getEntity()));
        }
    }

    /**
     * This build a signed JWT used for Client Assertion according RFC7523
     *
     * @return a JWT client assertion string
     */
    private String createClientAssertion() {
        if (privateKey == null) {
            return null;
        }
        final Instant now = clock.instant();
        return Jwts.builder()
                .setId(UUID.randomUUID().toString())
                .setIssuer(clientId)
                .setSubject(clientId)
                .setAudience(clientAssertionAudience)
                .setIssuedAt(Date.from(now))
                .setExpiration(Date.from(now.plus(60, SECONDS)))
                .setNotBefore(Date.from(now.minus(60, SECONDS)))
                .signWith(privateKey, SignatureAlgorithm.RS256).compact();
    }

    private String extractQueryParameter(String query, String parameterName) {
        return Stream.of(query.split("&"))
                .map(v -> v.split("="))
                .filter(v -> parameterName.equals(v[0]))
                .map(v -> v[1])
                .findAny()
                .orElseThrow(() -> new RuntimeException("Unable to get authorization code"));
    }

    private void sendPlainTextResponse(HttpExchange exchange, int code, String plainResponseBody) throws IOException {
        exchange.sendResponseHeaders(code, plainResponseBody.length());
        exchange.getResponseHeaders().add("Content-Type", "text/plain");
        try (final OutputStream responseBodyStream = exchange.getResponseBody()) {
            responseBodyStream.write(plainResponseBody.getBytes());
        }
    }

}

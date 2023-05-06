import org.junit.jupiter.api.Test;

import java.security.interfaces.RSAPrivateKey;

public class OAuth2ClientTest {

    public static final String AUTH_SCOPE = "openid";
    private static final String AUTH_ENDPOINT_URL = "<auth endpoint url>";
    private static final String TOKEN_ENDPOINT_URL = "<token endpoint url>";
    private static final String CLIENT_ID = "<client_id>";
    private static final String CLIENT_ASSERTION_AUDIENCE = "<client assertion JWT audience>";

    private final RSAPrivateKey privateKey = null;
    // OR:
    // private final RSAPrivateKey privateKey = ClientAssertionKeyHelper.readPrivateKey(new File("../../keys/private.pkcs8.pem"));

    private final OAuth2Client oauth2Client = new OAuth2Client(
            8000, AUTH_ENDPOINT_URL, TOKEN_ENDPOINT_URL, CLIENT_ID, privateKey, CLIENT_ASSERTION_AUDIENCE
    );

    @Test
    void fetchToken() {
        try {
            final TokenResponseEntity response = oauth2Client.authorizationCodeFlow(AUTH_SCOPE);
            System.out.println("Access token:");
            System.out.println(response.getRawAccessToken());
            System.out.println();
            System.out.println("Parsed Access token body:");
            System.out.println(response.getParsedAccessToken());
            System.out.println("Parsed ID token body:");
            System.out.println(response.getParsedIdToken());
            System.out.println("Refresh token:");
            System.out.println(response.getRawRefreshToken());
        } catch (ErrorResponseException e) {
            System.out.println("Response code:");
            System.out.println(e.getStatusCode());
            System.out.println("Error:");
            System.out.println(e.getErrorPayload());
        }
    }

    @Test
    void clientCredentials() {
        try {
            final TokenResponseEntity response = oauth2Client.clientCredentialsGrantFlow("<scope>");
            System.out.println("Access token:");
            System.out.println(response.getRawAccessToken());
            System.out.println();
            System.out.println("Parsed Access token body:");
            System.out.println(response.getParsedAccessToken());
            System.out.println("Parsed ID token body:");
            System.out.println(response.getParsedIdToken());
            System.out.println("Refresh token:");
            System.out.println(response.getRawRefreshToken());
        } catch (ErrorResponseException e) {
            System.out.println("Response code:");
            System.out.println(e.getStatusCode());
            System.out.println("Error:");
            System.out.println(e.getErrorPayload());
        }
    }

    @Test
    void doExampleExchange() throws Exception {
        final TokenResponseEntity accessToken = oauth2Client.authorizationCodeFlow(
                AUTH_SCOPE
        );

        System.out.println("Access token to exchange:");
        System.out.println(accessToken.getParsedAccessToken());

        final OAuth2Client tokenExchangeClient = new OAuth2Client(
                8000, AUTH_ENDPOINT_URL, TOKEN_ENDPOINT_URL, CLIENT_ID, privateKey, CLIENT_ASSERTION_AUDIENCE
        );
        final TokenResponseEntity result = tokenExchangeClient.exchangeToken(
                accessToken.getRawAccessToken(),
                "<scope_1>", "<scope_2>"
        );

        System.out.println("Access token from token exchange:");
        System.out.println(result.getParsedAccessToken());
    }

}

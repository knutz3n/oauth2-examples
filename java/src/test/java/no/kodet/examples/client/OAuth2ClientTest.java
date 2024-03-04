package no.kodet.examples.client;

import org.junit.jupiter.api.Test;

import java.security.interfaces.RSAPrivateKey;

public class OAuth2ClientTest {

    public static final String AUTH_SCOPE = "openid";
    private static final String WELL_KNOWN_CONFIGURATION_ENDPOINT_URL = "<well known endpoint url>";
    private static final String CLIENT_ID = "<client_id>";

    private final RSAPrivateKey privateKey = null;
    // OR:
    // private final RSAPrivateKey privateKey = ClientAssertionKeyHelper.readPrivateKey(new File("../../keys/private.pkcs8.pem"));

    private final OAuth2Client oauth2Client = OAuth2Client.fromWellKnownConfiguration(
            WELL_KNOWN_CONFIGURATION_ENDPOINT_URL,
            8000, CLIENT_ID, privateKey
    );

    @Test
    void fetchToken() {
        try {
            final TokenResponseEntity response = oauth2Client.authorizationCodeFlow(AUTH_SCOPE);
            System.out.println("Access token:");
            System.out.println(response.rawAccessToken());
            System.out.println();
            System.out.println("Parsed Access token body:");
            System.out.println(response.parsedAccessToken());
            System.out.println("Parsed ID token body:");
            System.out.println(response.parsedIdToken());
            System.out.println("Refresh token:");
            System.out.println(response.rawRefreshToken());
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
            System.out.println(response.rawAccessToken());
            System.out.println();
            System.out.println("Parsed Access token body:");
            System.out.println(response.parsedAccessToken());
            System.out.println("Parsed ID token body:");
            System.out.println(response.parsedIdToken());
            System.out.println("Refresh token:");
            System.out.println(response.rawRefreshToken());
        } catch (ErrorResponseException e) {
            System.out.println("Response code:");
            System.out.println(e.getStatusCode());
            System.out.println("Error:");
            System.out.println(e.getErrorPayload());
        }
    }

    @Test
    void doExampleExchange() {
        final TokenResponseEntity accessToken = oauth2Client.authorizationCodeFlow(
                AUTH_SCOPE
        );

        System.out.println("Access token to exchange:");
        System.out.println(accessToken.parsedAccessToken());

        final OAuth2Client tokenExchangeClient = OAuth2Client.fromWellKnownConfiguration(
                WELL_KNOWN_CONFIGURATION_ENDPOINT_URL,
                8000, CLIENT_ID, privateKey
        );
        final TokenResponseEntity result = tokenExchangeClient.exchangeToken(
                accessToken.rawAccessToken(),
                "<scope_1>", "<scope_2>"
        );

        System.out.println("Access token from token exchange:");
        System.out.println(result.parsedAccessToken());
    }

}

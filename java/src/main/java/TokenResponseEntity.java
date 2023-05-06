import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Objects;

@JsonIgnoreProperties(ignoreUnknown = true)
public class TokenResponseEntity {
    private static final ObjectMapper objectMapper = new ObjectMapper();

    private final String rawAccessToken;
    private final String rawIdToken;
    private final String rawRefreshToken;
    private final int expiresIn;
    private final int refreshExpiresIn;
    private final List<String> scope;
    private final String tokenType;
    private final String notBeforePolicy;
    private final String sessionState;

    @JsonCreator
    public TokenResponseEntity(
            @JsonProperty("access_token") String rawAccessToken,
            @JsonProperty("id_token") String rawIdToken,
            @JsonProperty("refresh_token") String rawRefreshToken,
            @JsonProperty("expires_in") int expiresIn,
            @JsonProperty("refresh_expires_in") int refreshExpiresIn,
            @JsonProperty("scope") String scope,
            @JsonProperty("token_type") String tokenType,
            @JsonProperty("not-before-policy") String notBeforePolicy,
            @JsonProperty("session_state") String sessionState
    ) {
        this.rawAccessToken = rawAccessToken;
        this.rawIdToken = rawIdToken;
        this.rawRefreshToken = rawRefreshToken;
        this.expiresIn = expiresIn;
        this.refreshExpiresIn = refreshExpiresIn;
        this.scope = scope == null ? null : List.of(scope.split(" "));
        this.tokenType = tokenType;
        this.notBeforePolicy = notBeforePolicy;
        this.sessionState = sessionState;
    }

    public int getExpiresIn() {
        return expiresIn;
    }

    public int getRefreshExpiresIn() {
        return refreshExpiresIn;
    }

    public List<String> getScope() {
        return scope;
    }

    public String getRawAccessToken() {
        return rawAccessToken;
    }

    public String getRawIdToken() {
        return rawIdToken;
    }

    public String getRawRefreshToken() {
        return rawRefreshToken;
    }

    public String getTokenType() {
        return tokenType;
    }

    public String getNotBeforePolicy() {
        return notBeforePolicy;
    }

    public String getSessionState() {
        return sessionState;
    }

    public String getParsedAccessToken() {
        return prettyPrintJwtBody(getRawAccessToken());
    }

    public String getParsedIdToken() {
        return prettyPrintJwtBody(getRawIdToken());
    }

    public String getParsedRefreshToken() {
        return prettyPrintJwtBody(getRawRefreshToken());
    }

    @Override
    public String toString() {
        return "TokenResponseEntity{" +
                "rawAccessToken='" + rawAccessToken + '\'' +
                ", rawIdToken='" + rawIdToken + '\'' +
                ", rawRefreshToken='" + rawRefreshToken + '\'' +
                ", expiresIn=" + expiresIn +
                ", refreshExpiresIn=" + refreshExpiresIn +
                ", scope=" + scope +
                ", tokenType='" + tokenType + '\'' +
                ", notBeforePolicy='" + notBeforePolicy + '\'' +
                ", sessionState='" + sessionState + '\'' +
                '}';
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        TokenResponseEntity that = (TokenResponseEntity) o;
        return expiresIn == that.expiresIn && refreshExpiresIn == that.refreshExpiresIn && Objects.equals(rawAccessToken, that.rawAccessToken) && Objects.equals(rawIdToken, that.rawIdToken) && Objects.equals(rawRefreshToken, that.rawRefreshToken) && Objects.equals(scope, that.scope) && Objects.equals(tokenType, that.tokenType) && Objects.equals(notBeforePolicy, that.notBeforePolicy) && Objects.equals(sessionState, that.sessionState);
    }

    @Override
    public int hashCode() {
        return Objects.hash(rawAccessToken, rawIdToken, rawRefreshToken, expiresIn, refreshExpiresIn, scope, tokenType, notBeforePolicy, sessionState);
    }

    private static String prettyPrintJwtBody(String rawValue) {
        if (rawValue == null) {
            return null;
        }
        final byte[] unvalidatedTokenBody = Base64.getUrlDecoder().decode(
                rawValue.split("\\.")[1].getBytes(StandardCharsets.UTF_8)
        );
        try {
            return objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(
                    objectMapper.readValue(unvalidatedTokenBody, Map.class)
            );
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}

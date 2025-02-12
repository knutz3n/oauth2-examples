import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.Map;

@JsonIgnoreProperties(ignoreUnknown = true)
public record TokenResponseEntity(
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
    private static final ObjectMapper objectMapper = new ObjectMapper();


    public List<String> scopeAsList() {
        return scope == null ? List.of() : List.of(scope.split(" "));
    }

    public String parsedAccessToken() {
        return prettyPrintJwtBody(rawAccessToken());
    }

    public String parsedIdToken() {
        return prettyPrintJwtBody(rawIdToken());
    }

    public String parsedRefreshToken() {
        return prettyPrintJwtBody(rawRefreshToken());
    }

    @Override
    public String toString() {
        return """
                TokenResponseEntity{
                    rawAccessToken=%s
                    rawIdToken=%s
                    rawRefreshToken=%s
                    expiresIn=%s
                    refreshExpiresIn=%s
                    scope=%s
                    tokenType=%s
                    notBeforePolicy=%s
                    sessionState=%s
                }""".formatted(
                rawAccessToken,
                rawIdToken,
                rawRefreshToken,
                expiresIn,
                refreshExpiresIn,
                scope,
                tokenType,
                notBeforePolicy,
                sessionState
        );
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

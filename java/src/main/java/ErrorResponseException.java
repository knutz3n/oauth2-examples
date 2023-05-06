public class ErrorResponseException extends RuntimeException {
    private final int statusCode;
    private final String errorPayload;

    public ErrorResponseException(int code, String errorPayload) {
        this.statusCode = code;
        this.errorPayload = errorPayload;
    }

    public int getStatusCode() {
        return statusCode;
    }

    public String getErrorPayload() {
        return errorPayload;
    }

    @Override
    public String toString() {
        return "ErrorResponseException{" +
                "statusCode=" + statusCode +
                ", errorPayload='" + errorPayload + '\'' +
                '}';
    }
}

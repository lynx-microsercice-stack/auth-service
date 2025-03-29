package lynx.auth.logging;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.util.StreamUtils;

import lombok.NonNull;

public class BufferingClientHttpResponseWrapper implements ClientHttpResponse {
    private final ClientHttpResponse response;
    private byte[] body;

    BufferingClientHttpResponseWrapper(ClientHttpResponse response) {
        this.response = response;
    }

    public byte[] getBodyBytes() throws IOException {
        if (body == null) {
            body = StreamUtils.copyToByteArray(response.getBody());
        }
        return body;
    }

    @SuppressWarnings("null")
    @Override
    @NonNull
    public InputStream getBody() throws IOException {
        return new ByteArrayInputStream(getBodyBytes());
    }

    @SuppressWarnings("null")
    @Override
    @NonNull
    public HttpHeaders getHeaders() {
        return response.getHeaders();
    }

    @SuppressWarnings("null")
    @Override
    @NonNull
    public HttpStatusCode getStatusCode() throws IOException {
        return response.getStatusCode();
    }

    @SuppressWarnings("null")
    @Override
    @NonNull
    public String getStatusText() throws IOException {
        return response.getStatusText();
    }

    @Override
    public void close() {
        response.close();
    }
}
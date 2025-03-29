package lynx.auth.logging;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.UUID;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpRequest;
import org.springframework.http.client.ClientHttpRequestExecution;
import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.http.client.ClientHttpResponse;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;

import lombok.NonNull;

@SuppressWarnings("null")
public class LoggingInterceptor implements ClientHttpRequestInterceptor {

    private static final Logger LOGGER = LoggerFactory.getLogger("lynx.auth.logging.RestTemplate");
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper()
            .enable(SerializationFeature.INDENT_OUTPUT);

    @Override
    public @NonNull ClientHttpResponse intercept(
            HttpRequest request, byte [] body, @NonNull ClientHttpRequestExecution execution) throws IOException {
        
        String requestId = UUID.randomUUID().toString();
        LOGGER.debug("[{}] ====== Request Start ======", requestId);
        
        // Log request details
        LOGGER.debug("[{}] Request URL: {}", requestId, request.getURI());
        LOGGER.debug("[{}] Request Method: {}", requestId, request.getMethod());
        LOGGER.debug("[{}] Request Headers: {}", requestId, request.getHeaders());
        
        // Log request body if present
        if (body.length > 0) {
            String requestBody = new String(body, StandardCharsets.UTF_8);
            try {
                // Try to format as JSON if it's JSON content
                Object jsonObject = OBJECT_MAPPER.readValue(requestBody, Object.class);
                String prettyJson = OBJECT_MAPPER.writeValueAsString(jsonObject);
                LOGGER.debug("[{}] Request Body (JSON):\n{}", requestId, prettyJson);
            } catch (JsonProcessingException e) {
                // If not JSON, log as plain text
                LOGGER.debug("[{}] Request Body (Plain): {}", requestId, requestBody);
            }
        }

        // Execute the request
        ClientHttpResponse response = execution.execute(request, body);

        // Log response details
        LOGGER.debug("[{}] Response Status: {}", requestId, response.getStatusCode());
        LOGGER.debug("[{}] Response Headers: {}", requestId, response.getHeaders());
        // Log response body
        // Create a buffered response wrapper to allow reading the body multiple times
        BufferingClientHttpResponseWrapper bufferedResponse = new BufferingClientHttpResponseWrapper(response);
        try {
            byte[] responseBodyBytes = bufferedResponse.getBodyBytes();
            if (responseBodyBytes.length > 0) {
                String responseBody = new String(responseBodyBytes, StandardCharsets.UTF_8);
                try {
                    // Try to format as JSON if it's JSON content
                    Object jsonObject = OBJECT_MAPPER.readValue(responseBody, Object.class);
                    String prettyJson = OBJECT_MAPPER.writeValueAsString(jsonObject);
                    LOGGER.debug("[{}] Response Body (JSON):\n{}", requestId, prettyJson);
                } catch (JsonProcessingException e) {
                    // If not JSON, log as plain text
                    LOGGER.debug("[{}] Response Body (Plain): {}", requestId, responseBody);
                }
            }
        } catch (IOException e) {
            LOGGER.warn("[{}] Failed to log response body: {}", requestId, e.getMessage());
        }
        LOGGER.debug("[{}] ====== Request End ======", requestId);
        return bufferedResponse;
    }
}
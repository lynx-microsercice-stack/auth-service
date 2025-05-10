package lynx.auth.common;

import com.fasterxml.jackson.annotation.JsonInclude;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
@Schema(description = "Base response wrapper for all API responses")
public class BaseResponse<T> {
    
    @Schema(description = "Response data/payload")
    private T data;
    
    @Schema(description = "Response status code")
    private int code;
    
    @Schema(description = "Response timestamp")
    private LocalDateTime time;
    
    @Schema(description = "Response message")
    private String message;
    
    public static <T> BaseResponse<T> success(T data) {
        return BaseResponse.<T>builder()
                .data(data)
                .code(200)
                .time(LocalDateTime.now())
                .message("Success")
                .build();
    }
    
    public static <T> BaseResponse<T> success(T data, String message) {
        return BaseResponse.<T>builder()
                .data(data)
                .code(200)
                .time(LocalDateTime.now())
                .message(message)
                .build();
    }
    
    public static <T> BaseResponse<T> error(int code, String message) {
        return BaseResponse.<T>builder()
                .code(code)
                .time(LocalDateTime.now())
                .message(message)
                .build();
    }
    
    public static <T> BaseResponse<T> error(int code, String message, T data) {
        return BaseResponse.<T>builder()
                .code(code)
                .time(LocalDateTime.now())
                .message(message)
                .data(data)
                .build();
    }
} 
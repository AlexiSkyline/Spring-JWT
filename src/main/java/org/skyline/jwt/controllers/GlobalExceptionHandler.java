package org.skyline.jwt.controllers;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import lombok.AllArgsConstructor;
import lombok.NonNull;
import org.skyline.jwt.dto.output.ErrorField;
import org.skyline.jwt.dto.output.ErrorResponse;
import org.skyline.jwt.models.exception.EmailAlreadyExistsException;
import org.skyline.jwt.models.exception.InvalidCredentialsException;
import org.skyline.jwt.models.exception.RefreshTokenNotFoundException;
import org.skyline.jwt.models.exception.UserNotFoundException;
import org.springframework.context.MessageSource;
import org.springframework.http.*;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

import javax.naming.AuthenticationException;
import java.nio.file.AccessDeniedException;
import java.security.SignatureException;
import java.time.LocalDateTime;
import java.util.*;

@AllArgsConstructor
@RestControllerAdvice
@RequestMapping(produces = MediaType.APPLICATION_JSON_VALUE)
public class GlobalExceptionHandler extends ResponseEntityExceptionHandler {

    private final MessageSource messageSource;

    @Override
    protected ResponseEntity<Object> handleMethodArgumentNotValid(@NonNull MethodArgumentNotValidException ex, @NonNull HttpHeaders headers, @NonNull HttpStatusCode status, @NonNull WebRequest request) {
        BindingResult result =  ex.getBindingResult();

        List<ErrorField> errors = new ArrayList<>();
        result.getFieldErrors().forEach(error -> {
            String message = messageSource.getMessage(error, Locale.forLanguageTag("US"));
            errors.add(new ErrorField(message, error.getField(), "body"));
        });

        ErrorResponse<List<ErrorField>> errorResponse = buildErrorResponse(
                status.value(),
                status.toString(),
                errors,
                request.getDescription(false)
        );

        return new ResponseEntity<>(errorResponse, status);
    }

    @ResponseStatus(code = HttpStatus.CONFLICT)
    @ExceptionHandler(EmailAlreadyExistsException.class)
    public ResponseEntity<ErrorResponse<String>> handleEmailAlreadyExistsException(EmailAlreadyExistsException ex, WebRequest request) {
        ErrorResponse<String> errorResponse = buildErrorResponse(
                HttpStatus.CONFLICT.value(),
                HttpStatus.CONFLICT.toString(),
                ex.getMessage(),
                request.getDescription(false)
        );
        return ResponseEntity.status(HttpStatus.CONFLICT).body(errorResponse);
    }

    @ResponseStatus(code = HttpStatus.CONFLICT)
    @ExceptionHandler(UserNotFoundException.class)
    public ResponseEntity<ErrorResponse<String>> handleUserNotFoundException(UserNotFoundException ex, WebRequest request) {
        ErrorResponse<String> errorResponse = buildErrorResponse(
                HttpStatus.CONFLICT.value(),
                HttpStatus.CONFLICT.toString(),
                ex.getMessage(),
                request.getDescription(false)
        );
        return ResponseEntity.status(HttpStatus.CONFLICT).body(errorResponse);
    }

    @ResponseStatus(code = HttpStatus.UNAUTHORIZED)
    @ExceptionHandler(InvalidCredentialsException.class)
    public ResponseEntity<ErrorResponse<String>> handleInvalidCredentialsException(InvalidCredentialsException ex, WebRequest request) {
        ErrorResponse<String> errorResponse = buildErrorResponse(
                HttpStatus.UNAUTHORIZED.value(),
                HttpStatus.UNAUTHORIZED.toString(),
                ex.getMessage(),
                request.getDescription(false)
        );

        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(errorResponse);
    }

    @ResponseStatus(code = HttpStatus.NOT_FOUND)
    @ExceptionHandler(RefreshTokenNotFoundException.class)
    public ResponseEntity<ErrorResponse<String>> handleRefreshTokenNotFoundException(RefreshTokenNotFoundException ex, WebRequest request) {
        ErrorResponse<String> errorResponse = buildErrorResponse(
                HttpStatus.NOT_FOUND.value(),
                HttpStatus.NOT_FOUND.toString(),
                ex.getMessage(),
                request.getDescription(false)
        );
        return ResponseEntity.status(HttpStatus.NOT_FOUND).body(errorResponse);
    }

    @ExceptionHandler(ExpiredJwtException.class)
    @ResponseStatus(code = HttpStatus.UNAUTHORIZED)
    public ResponseEntity<ErrorResponse<String>> handleExpiredJwtException(ExpiredJwtException ex, WebRequest request) {
        ErrorResponse<String> errorResponse = buildErrorResponse(
                HttpStatus.UNAUTHORIZED.value(),
                HttpStatus.UNAUTHORIZED.toString(),
                ex.getMessage(),
                request.getDescription(false)
        );
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(errorResponse);
    }

    @ExceptionHandler(SignatureException.class)
    @ResponseStatus(code = HttpStatus.UNAUTHORIZED)
    public ResponseEntity<ErrorResponse<String>> handleSignatureException(SignatureException ex, WebRequest request) {
        ErrorResponse<String> errorResponse = buildErrorResponse(
                HttpStatus.UNAUTHORIZED.value(),
                HttpStatus.UNAUTHORIZED.toString(),
                ex.getMessage(),
                request.getDescription(false)
        );
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(errorResponse);
    }

    @ExceptionHandler(MalformedJwtException.class)
    @ResponseStatus(code = HttpStatus.UNAUTHORIZED)
    public ResponseEntity<ErrorResponse<String>> handleMalformedJwtException(MalformedJwtException ex, WebRequest request) {
        ErrorResponse<String> errorResponse = buildErrorResponse(
                HttpStatus.UNAUTHORIZED.value(),
                HttpStatus.UNAUTHORIZED.toString(),
                ex.getMessage(),
                request.getDescription(false)
        );
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(errorResponse);
    }

    @ExceptionHandler(Exception.class)
    @ResponseStatus(code = HttpStatus.INTERNAL_SERVER_ERROR)
    public ResponseEntity<ErrorResponse<String>> handleGenericException(Exception ex, WebRequest request) {
        ErrorResponse<String> errorResponse = buildErrorResponse(
                HttpStatus.INTERNAL_SERVER_ERROR.value(),
                HttpStatus.INTERNAL_SERVER_ERROR.toString(),
                ex.getMessage(),
                request.getDescription(false)
        );
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(errorResponse);
    }

    @ResponseStatus(code = HttpStatus.FORBIDDEN)
    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<ErrorResponse<String>> handleAccessDeniedException(AccessDeniedException ex, WebRequest request) {
        ErrorResponse<String> errorResponse = buildErrorResponse(
                HttpStatus.FORBIDDEN.value(),
                HttpStatus.FORBIDDEN.toString(),
                ex.getMessage(),
                request.getDescription(false)
        );
        return ResponseEntity.status(HttpStatus.FORBIDDEN).body(errorResponse);
    }

    @ResponseStatus(code = HttpStatus.UNAUTHORIZED)
    @ExceptionHandler(AuthenticationException.class)
    public ResponseEntity<ErrorResponse<String>> handleAuthenticationException(AuthenticationException ex, WebRequest request) {
        ErrorResponse<String> errorResponse = buildErrorResponse(
                HttpStatus.UNAUTHORIZED.value(),
                HttpStatus.UNAUTHORIZED.toString(),
                ex.getMessage(),
                request.getDescription(false)
        );
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(errorResponse);
    }

    private <T> ErrorResponse<T> buildErrorResponse(int status, String httpError, T message, String path) {
        return new ErrorResponse<>(
                LocalDateTime.now(),
                status,
                httpError,
                message,
                path
        );
    }
}

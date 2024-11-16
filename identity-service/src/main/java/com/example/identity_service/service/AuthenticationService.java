package com.example.identity_service.service;

import com.example.identity_service.dto.request.AuthenticationRequest;
import com.example.identity_service.dto.request.ClientExchangeTokenRequest;
import com.example.identity_service.dto.request.UserExchangeTokenRequest;
import com.example.identity_service.dto.response.AuthenticationResponse;
import com.example.identity_service.entity.InvalidatedToken;
import com.example.identity_service.entity.User;
import com.example.identity_service.exception.AppException;
import com.example.identity_service.exception.ErrorCode;
import com.example.identity_service.exception.ErrorNormalizer;
import com.example.identity_service.repository.IdentityClient;
import com.example.identity_service.repository.InvalidatedTokenRepository;
import com.example.identity_service.repository.UserRepository;
import feign.FeignException;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import lombok.experimental.NonFinal;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
@Slf4j
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
public class AuthenticationService {
    UserRepository userRepository;
    InvalidatedTokenRepository invalidatedTokenRepository;
    IdentityClient identityClient;
    ErrorNormalizer errorNormalizer;
    @NonFinal
    @Value("${google.clientId}")
    protected String CLIENT_ID;

    @Value("${idp.client-id}")
    @NonFinal
    String clientId;

    @Value("${idp.client-secret}")
    @NonFinal
    String clientSecret;


    @NonFinal
    @Value("${google.clientSecret}")
    protected String CLIENT_SECRET;

    @NonFinal
    @Value("${google.redirectUri}")
    protected String REDIRECT_URI;

    public AuthenticationResponse authenticate(AuthenticationRequest request) {
        try {
            User user = userRepository.findByUsername(request.getUsername())
                    .orElseThrow(() -> new AppException(ErrorCode.USER_NOT_EXISTED));

            UserExchangeTokenRequest TokenRequest = UserExchangeTokenRequest.builder()
                    .client_id(clientId)
                    .client_secret(clientSecret)
                    .grant_type("password")
                    .scope("openid")
                    .username(request.getUsername())
                    .password(request.getPassword())
                    .build();

            var token = identityClient.exchangeUserToken(TokenRequest);
            log.info("Token: {}", token);
            return AuthenticationResponse.builder()
                    .token(token.getAccessToken()).authenticated(true)
                    .build();
        } catch (FeignException exception) {
            throw errorNormalizer.handleKeyCloakException(exception);
        }


    }
}

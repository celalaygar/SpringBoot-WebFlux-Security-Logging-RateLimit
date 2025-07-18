package com.security.securityProject.filter;

import com.security.securityProject.config.JwtUtil;
import com.security.securityProject.entity.ApiLog;
import com.security.securityProject.entity.User;
import com.security.securityProject.repository.ApiLogRepository; // ApiLogRepository'ye doğrudan erişim yerine LoggingService kullanılacak

import com.security.securityProject.repository.UserRepository;
import com.security.securityProject.service.LoggingService; // Yeni LoggingService'i import et
import lombok.RequiredArgsConstructor;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.core.io.buffer.DataBufferFactory;
import org.springframework.core.io.buffer.DataBufferUtils;
import org.springframework.http.HttpHeaders;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpRequestDecorator;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.http.server.reactive.ServerHttpResponseDecorator;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;

@Component
@RequiredArgsConstructor
public class RequestResponseLoggingFilter implements WebFilter {

    private static final String TRACE_ID_HEADER = "X-Trace-ID"; // Trace ID için özel header adı

    private final LoggingService loggingService; // Yeni LoggingService
    private final JwtUtil jwtUtil; // Token'dan email almak için
    private final UserRepository userRepository;

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        long startTime = System.currentTimeMillis();
        String requestId = UUID.randomUUID().toString();
        String traceId = UUID.randomUUID().toString(); // Yeni: Trace ID oluştur

        ServerHttpRequest request = exchange.getRequest();
        ServerHttpResponse response = exchange.getResponse();
        DataBufferFactory bufferFactory = response.bufferFactory();

        // Yanıt header'ına Trace ID ekle
        response.getHeaders().add(TRACE_ID_HEADER, traceId);

        ApiLog apiLog = new ApiLog();
        apiLog.setRequestId(requestId);
        apiLog.setTraceId(traceId); // ApiLog'a Trace ID'yi set et
        apiLog.setRequestTime(LocalDateTime.now()); // İstek zamanını set et
        apiLog.setMethod(request.getMethod().name());
        apiLog.setPath(request.getPath().value());
        apiLog.setClientIp(request.getRemoteAddress() != null ? request.getRemoteAddress().getHostString() : "unknown");
        apiLog.setRequestHeaders(request.getHeaders().toSingleValueMap());

        // Token ve Email bilgilerini al (eğer varsa)
        String authorizationHeader = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
            String token = authorizationHeader.substring(7);
            apiLog.setToken(token); // Token'ı kaydet
            try {
                // Token geçerliyse email'i al
                if (jwtUtil.validateToken(token)) {
                    String email = jwtUtil.getUsernameFromToken(token);
                    apiLog.setEmail(email); // Email'i kaydet
                    apiLog.setAuthenticatedUser(email); // AuthenticatedUser olarak email'i kullan
                } else {
                    apiLog.setAuthenticatedUser("invalid_token");
                }
            } catch (Exception e) {
                // Token parse edilirken hata oluşursa
                apiLog.setAuthenticatedUser("token_error");
                System.err.println("Token işlenirken hata: " + e.getMessage());
            }
        } else {
            apiLog.setAuthenticatedUser("anonymous"); // Token yoksa anonim
        }


        // İstek gövdesini yakala ve yeniden hazırla
        return DataBufferUtils.join(request.getBody())
                .defaultIfEmpty(bufferFactory.wrap(new byte[0])) // İstek gövdesi yoksa boş DataBuffer sağla
                .flatMap(requestDataBuffer -> {
                    // İstek gövdesini kopyala ve byte[]'e oku
                    // DataBufferUtils.retain() çağrısı, DataBuffer'ın referans sayısını artırır.
                    // Bu, okuma işlemi sırasında buffer'ın tüketilmesini önler.
                    DataBuffer retainedRequestDataBuffer = DataBufferUtils.retain(requestDataBuffer);
                    byte[] requestBodyBytes = new byte[retainedRequestDataBuffer.readableByteCount()];
                    retainedRequestDataBuffer.read(requestBodyBytes);
                    DataBufferUtils.release(retainedRequestDataBuffer); // Okuma bittikten sonra serbest bırak

                    String requestBody = new String(requestBodyBytes, StandardCharsets.UTF_8);
                    apiLog.setRequestBody(requestBody);

                    // İstek gövdesini yeniden akışa veren bir ServerHttpRequestDecorator oluşturulur.
                    // ÖNEMLİ DEĞİŞİKLİK: getBody() metodu, cached byte[]'den YENİ bir DataBuffer oluşturur.
                    ServerHttpRequest decoratedRequest = new ServerHttpRequestDecorator(request) {
                        @Override
                        public Flux<DataBuffer> getBody() {
                            // Yeni bir DataBuffer oluşturup okunan byte dizisini sarmalarız.
                            // Bu, orijinal akışı bozmadan gövdenin yeniden okunmasını sağlar.
                            return Flux.just(bufferFactory.wrap(requestBodyBytes));
                        }
                    };

                    // Yanıt gövdesini yakalayacak bir ServerHttpResponseDecorator oluşturulur.
                    ServerHttpResponseDecorator decoratedResponse = new ServerHttpResponseDecorator(response) {
                        @Override
                        public Mono<Void> writeWith(org.reactivestreams.Publisher<? extends DataBuffer> body) {
                            if (body instanceof Flux) {
                                Flux<? extends DataBuffer> fluxBody = (Flux<? extends DataBuffer>) body;
                                // Yanıt gövdesindeki tüm DataBuffer'ları birleştir.
                                return DataBufferUtils.join(fluxBody)
                                        .flatMap(responseDataBuffer -> {
                                            // Yanıt gövdesini kopyala/retain et ve byte[]'e oku
                                            DataBuffer retainedResponseDataBuffer = DataBufferUtils.retain(responseDataBuffer);
                                            byte[] responseBodyBytes = new byte[retainedResponseDataBuffer.readableByteCount()];
                                            retainedResponseDataBuffer.read(responseBodyBytes);
                                            DataBufferUtils.release(retainedResponseDataBuffer); // Okuma bittikten sonra serbest bırak

                                            String responseBody = new String(responseBodyBytes, StandardCharsets.UTF_8);
                                            apiLog.setResponseBody(responseBody);

                                            // Orijinal yanıt akışını devam ettir.
                                            return super.writeWith(Mono.just(bufferFactory.wrap(responseBodyBytes)));
                                        });
                            }
                            return super.writeWith(body);
                        }
                    };

                    // Filtre zincirini devam ettir ve tamamlandığında loglama işlemini yap.
                    return chain.filter(exchange.mutate().request(decoratedRequest).response(decoratedResponse).build())
                            .doFinally(signalType -> {
                                // İstek tamamlandığında loglama işlemini bitir
                                apiLog.setResponseTime(LocalDateTime.now()); // Yanıt zamanını set et
                                apiLog.setStatusCode(response.getStatusCode() != null ? response.getStatusCode().value() : 0);
                                apiLog.setResponseHeaders(response.getHeaders().toSingleValueMap());
                                apiLog.setDurationMillis(System.currentTimeMillis() - startTime);
                                // LoggingService aracılığıyla logu kaydet
                                loggingService.saveApiLog(apiLog).subscribe();

                                // Orijinal requestDataBuffer'ı serbest bırakın (flatMap'ten sonra başka referansı kalmamalı)
                                DataBufferUtils.release(requestDataBuffer);
                            });
                })
                .onErrorResume(e -> {
                    // Filtreleme sırasında herhangi bir hata oluşursa yakala, logla ve akışı hatayla bitir.
                    System.err.println("RequestResponseLoggingFilter sırasında hata oluştu: " + e.getMessage());
                    apiLog.setResponseTime(LocalDateTime.now()); // Hata anında da yanıt zamanını set et
                    //apiLog.setAuthenticatedUser(authenticatedUserRef.get());
                    apiLog.setResponseBody("Filtre işleme sırasında hata oluştu: " + e.getMessage());
                    apiLog.setStatusCode(response.getStatusCode() != null ? response.getStatusCode().value() : 500);
                    apiLog.setDurationMillis(System.currentTimeMillis() - startTime);
                    loggingService.saveApiLog(apiLog).subscribe(); // Hatayı logla
                    return Mono.error(e); // Orijinal hatayı akışta yay
                });
    }

    public Mono<User> getAuthUser() {
        return ReactiveSecurityContextHolder.getContext()
                .map(securityContext -> {
                    String email = securityContext.getAuthentication().getName();
                    return userRepository.findByEmail(email); // Bu, Mono<User> döndürüyor
                })
                .flatMap(userMono -> userMono); // Mono<User> döndürüyor
    }
}

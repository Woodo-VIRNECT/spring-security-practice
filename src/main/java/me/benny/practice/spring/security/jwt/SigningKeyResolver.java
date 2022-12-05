package me.benny.practice.spring.security.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwsHeader;
import io.jsonwebtoken.SigningKeyResolverAdapter;

import java.security.Key;

/**
 * JwsHeader 를 통해 Signature 검증에 필요한 Key 를 가져오는 코드를 구현합니다.
 * JWT 의 헤더에서 kid 를 찾아서 Key(SecretKey + 알고리즘)를 찾아옵니다.
 * Signature 를 검증할 때 사용합니다.
 */
public class SigningKeyResolver extends SigningKeyResolverAdapter {
    public static SigningKeyResolver instance = new SigningKeyResolver();

    @Override
    public Key resolveSigningKey(JwsHeader jwsHeader, Claims claims) {
        String kid = jwsHeader.getKeyId();
        if (kid == null) return null;
        return JwtKey.getKey(kid);
    }
}
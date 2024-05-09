/*
 * (C) Copyright 2022. All Rights Reserved.
 *
 * @author DongTHD
 * @date Mar 10, 2022
*/
package vn.fs.config;

import java.util.Arrays;
import java.util.Date;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.SignatureException;
import io.jsonwebtoken.UnsupportedJwtException;

import vn.fs.service.implement.UserDetailsImpl;

@Component
public class JwtUtils {
	private static final Logger logger = LoggerFactory.getLogger(JwtUtils.class);

	@Value("${bezkoder.app.jwtSecret}")
	private String jwtSecrect;

	@Value("${bezkoder.app.jwtExpirationMs}")
	private int jwtExpirationMs;

	public String generateJwtToken(Authentication authentication) {

		UserDetailsImpl userPrincipal = (UserDetailsImpl) authentication.getPrincipal();

		Date dateJwtDate = new Date();
		dateJwtDate.getTime();

		return Jwts.builder().setSubject((userPrincipal.getEmail())).setIssuedAt(new Date())
				.setExpiration(new Date((new Date()).getTime() + jwtExpirationMs))
				.signWith(SignatureAlgorithm.HS512, jwtSecrect).compact();
	}

	public String doGenerateToken(String email) {
		Claims claims = Jwts.claims().setSubject(email);
		// scopes được sử dụng để xác định quyền hạn của người dùng.
		//Đối tượng SimpleGrantedAuthority có thể được sử dụng để:

		//SimpleGrantedAuthority :Xác định quyền hạn của người dùng cấp quyền truy cập vào

		claims.put("scopes", Arrays.asList(new SimpleGrantedAuthority("ROLE_ADMIN")));

		return Jwts.builder().setClaims(claims).setIssuer("http://devglan.com")
				.setIssuedAt(new Date(System.currentTimeMillis()))
				.setExpiration(new Date(System.currentTimeMillis() + 5 * 60 * 60 * 1000))
				.signWith(SignatureAlgorithm.HS256, jwtSecrect).compact();
	}
	// giải mã token sau đó vào body để lấy email
	public String getEmailFromJwtToken(String token) {
		return Jwts.parser().setSigningKey(jwtSecrect).parseClaimsJws(token).getBody().getSubject();
	}

	//xác thực tính hợp lệ của một token JWT.
	public boolean validateJwtToken(String authToken) {
		try {
			//Jwts.parser() là phương thức khởi tạo một bộ giải mã token JWT
			//Khởi tạo bộ giải mã token JWT.
			// Cài đặt khóa bí mật jwtSecrect.
			//Giải mã token JWT authToken
			Jwts.parser().setSigningKey(jwtSecrect).parseClaimsJws(authToken);
			return true;  //Nếu giải mã thành công, token được coi là hợp lệ và hàm trả về true
		} catch (SignatureException e) {
			logger.error("Invalid JWT signature: {}", e.getMessage());// Chữ ký token không hợp lệ.
		} catch (MalformedJwtException e) {
			logger.error("Invalid JWT token: {}", e.getMessage());//Token JWT bị lỗi định dạng.
		} catch (ExpiredJwtException e) {
			logger.error("JWT token is expired: {}", e.getMessage());// Token JWT đã hết hạn.
		} catch (UnsupportedJwtException e) {
			logger.error("JWT token is usnupported: {}", e.getMessage());//Loại token JWT không được hỗ trợ.
		} catch (IllegalArgumentException e) {
			logger.error("JWT claims string is empty: {}", e.getMessage());// Nội dung claim của token rỗng.
		}

		return false;
	}

}

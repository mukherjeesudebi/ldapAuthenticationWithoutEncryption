package com.example.application.security;

import java.util.ArrayList;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.ldap.core.LdapTemplate;
import org.springframework.ldap.filter.EqualsFilter;
import org.springframework.ldap.filter.Filter;
import org.springframework.ldap.support.LdapUtils;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Component;

import com.example.application.data.entity.User;

@Component
public class LdapAuthenticationProvider implements AuthenticationProvider {

	
	@Autowired AuthenticationManager authenticationManager;
	
	/*
	 * @Autowired BindAuthenticator bindAuthenticator;
	 */
	
	@Autowired
	LdapTemplate ldapTemplate;

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {

		Filter filter = new EqualsFilter("uid", authentication.getName());

		Boolean authenticate = ldapTemplate.authenticate(LdapUtils.emptyLdapName(), filter.encode(),
				authentication.getCredentials().toString());
	
		 //DirContextOperations authAdapter = bindAuthenticator.authenticate(authentication);
		if (authenticate) {
			/*
			 * UserDetails userDetails = new User(authentication.getName(),
			 * authentication.getCredentials().toString(), new ArrayList<>());
			 */
			User user = new User();
			user.setName(authentication.getName());
			
			Authentication auth = new UsernamePasswordAuthenticationToken(user,
					authentication.getCredentials().toString(), new ArrayList<>());
			return auth;
		} else {
			return null;
		}

	}

	@Override
	public boolean supports(Class<?> authentication) {
		return authentication.equals(UsernamePasswordAuthenticationToken.class);
	}

}

package com.algaworks.algafood.auth.core;

import java.util.Arrays;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.CompositeTokenGranter;
import org.springframework.security.oauth2.provider.TokenGranter;
import org.springframework.security.oauth2.provider.approval.ApprovalStore;
import org.springframework.security.oauth2.provider.approval.TokenApprovalStore;
import org.springframework.security.oauth2.provider.token.TokenEnhancerChain;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.KeyStoreKeyFactory;
import org.springframework.security.oauth2.provider.token.store.redis.RedisTokenStore;

@Configuration
@EnableAuthorizationServer
public class AuthorizationServerConfig extends AuthorizationServerConfigurerAdapter {
	
	@Autowired
	private RedisConnectionFactory redisConnectionFactory;
	
	@Autowired
	private PasswordEncoder passwordEncoder;
	
	@Autowired
	private UserDetailsService userDetailsService;
	
	/**
	 * Somente o o fluxo do passoword necessita desse AuthenticationManager
	 * authorizedGrantTypes("password")
	 */
	@Autowired
	private AuthenticationManager authenticationManager;
	
	@Autowired
	private JwtKeyStoreProperties jwtKeyStoreProperties;    
	
	@Override
	public void configure(ClientDetailsServiceConfigurer clients) throws Exception { //
		clients
			.inMemory()
				.withClient("algafood-web")
				.secret(passwordEncoder.encode("web123"))
				.authorizedGrantTypes("password", "refresh_token")
				.scopes("write", "read")
				.accessTokenValiditySeconds(6 * 60 * 60)// 6 horas
				.refreshTokenValiditySeconds(60 * 24 * 60 * 60)// 60 dias
			
			.and()
				.withClient("foodanalytics")
				.secret(passwordEncoder.encode(""))//"food123"
				.authorizedGrantTypes("authorization_code")				
				.scopes("write", "read")	
				.redirectUris("http://www.algafood.local:8000")

			.and()
				.withClient("webadmin")
				.authorizedGrantTypes("implicit")				
				.scopes("write", "read")	
				.redirectUris("http://aplicacao-cliente")
			
			.and()
				.withClient("checktoken")
				.secret(passwordEncoder.encode("check123"))
			
			.and()
				.withClient("backgroud")
				.secret(passwordEncoder.encode("backgroud123"))
				.authorizedGrantTypes("client_credentials")
				.scopes("write", "read");
			
	}
	
	@Override
	public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
		//security.checkTokenAccess("isAuthenticated()");
		security.checkTokenAccess("permitAll()")
			.tokenKeyAccess("permitAll()") //gerar chave publica, aula 23.11
			.allowFormAuthenticationForClients();//colocando isso permite que eu não passe o authorization (basic auth)
		//client_id
	}
	
	
	@Override
	public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
		// O que foi criado costumizado precisa ser o primeiro na lista
		var enhancerChain = new TokenEnhancerChain();
		enhancerChain.setTokenEnhancers(
				List.of(new JwtCustomClaimsTokenEnhancer(), jwtAccessTokenConverter()));
		
		endpoints
			.authenticationManager(authenticationManager)
			.userDetailsService(userDetailsService)
			.reuseRefreshTokens(false)
			.tokenGranter(tokenGranter(endpoints))			
			.accessTokenConverter(jwtAccessTokenConverter())
			.tokenEnhancer(enhancerChain)
			.approvalStore(approvalStore(endpoints.getTokenStore())); //tem que chamar depois do accessTokenConverter
			//.tokenStore(redisTokenStore()); // salvar tokens no redis
	}
	
	/**
	 * Vai permitir a aprovação granular na tela do authorization_code
	 * @param tokenStore
	 * @return
	 */
	private ApprovalStore approvalStore(TokenStore tokenStore) {
		var approvalStore = new TokenApprovalStore();
		approvalStore.setTokenStore(tokenStore);
		
		return approvalStore;
	}
	
	@Bean
	public JwtAccessTokenConverter jwtAccessTokenConverter() {
		var jwtAccessTokenConverter = new JwtAccessTokenConverter();		
		//jwtAccessTokenConverter.setSigningKey("jasjdadkadabdakdhadha544555544564sadada5d4ad5ad4ad"); chave fixa assimetrica
	    
	    var jksResource = new ClassPathResource(jwtKeyStoreProperties.getPath());
	    var keyStorePass = jwtKeyStoreProperties.getPassword();
	    var keyPairAlias = jwtKeyStoreProperties.getKeypairAlias();
	    
	    var keyStoreKeyFactory = new KeyStoreKeyFactory(jksResource, keyStorePass.toCharArray());
	    var keyPair = keyStoreKeyFactory.getKeyPair(keyPairAlias);
	    
	    jwtAccessTokenConverter.setKeyPair(keyPair);
	    
	    return jwtAccessTokenConverter;
	}
	
	
	private RedisTokenStore redisTokenStore() {
		return new RedisTokenStore(redisConnectionFactory);
	}
	
	private TokenGranter tokenGranter(AuthorizationServerEndpointsConfigurer endpoints) {
		var pkceAuthorizationCodeTokenGranter = new PkceAuthorizationCodeTokenGranter(endpoints.getTokenServices(),
				endpoints.getAuthorizationCodeServices(), endpoints.getClientDetailsService(),
				endpoints.getOAuth2RequestFactory());
		
		var granters = Arrays.asList(
				pkceAuthorizationCodeTokenGranter, endpoints.getTokenGranter());
		
		return new CompositeTokenGranter(granters);
	}
	
}

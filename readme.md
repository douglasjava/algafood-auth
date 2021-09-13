## Projeto Especialista Rest

#### Build and run

#### Configurations


-- Modulo Segurança
URL: authorization code grant
http://localhost:8081/oauth/authorize?response_type=code&client_id=foodanalytics&state=abc&redirect_uri=http://www.algafood.local:8000
Resposta: http://www.algafood.local:8000/?code=W0kei8&state=MC41NzQ1NTAzMzQ4MTY0MDc0


Fluxo authorization code com PKCE no minimo 43 até 128 caracteres

no fluxo do plain o code_Verifier é o mesmo do  code_challenge
code_Verifier: teste123
code_challenge: teste123

http://localhost:8081/oauth/authorize?response_type=code&client_id=foodanalytics&redirect_uri=http://www.algafood.local:8000&code_challenge=teste123&code_challenge_method=plain

no fluxo do s256 o code_challenge é o code_Verifier codigo em sha-256 e codificado em base64url
code_Verifier: teste123
code_challenge: KJFg2w2fOfmuF1TE7JwW-QtQ4y4JxftUga5kKz09GjY

a senha secret foi removida para não ser enviada  (Segurança)

http://localhost:8081/oauth/authorize?response_type=code&client_id=foodanalytics&redirect_uri=http://www.algafood.local:8000&code_challenge=KJFg2w2fOfmuF1TE7JwW-QtQ4y4JxftUga5kKz09GjY&code_challenge_method=s256


URL: implicit grant
http://localhost:8081/oauth/authorize?response_type=token&client_id=webadmin&state=abc&redirect_uri=http://aplicacao-cliente
resposta: 
http://aplicacao-cliente/#access_token=a447ebb2-f360-47a2-bc95-85e63c14232f&token_type=bearer&state=abc&expires_in=43199&scope=read%20write
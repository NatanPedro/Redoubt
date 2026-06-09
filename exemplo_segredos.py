# DEMONSTRACAO do Redoubt — a Sentinela de Segredos em acao.
# Tudo aqui e FALSO (so para teste). Atalhos: Ctrl+Shift+R tarja os segredos,
# F8 pula entre eles, Ctrl+Shift+E abre o relatorio.

import hashlib

# ===== BENIGNO: nada abaixo deve ser marcado =====
def saudacao(nome):
    return f"Ola, {nome}!"

PI = 3.14159
COMMIT = "da39a3ee5e6b4b0d3255bfef95601890afd80709"   # hash git (40 hex)
DIGEST = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"  # sha256
SESSION_ID = "550e8400-e29b-41d4-a716-446655440000"   # UUID
API_KEY_EXEMPLO = "your-api-key-here"                  # placeholder

# ===== SEGREDOS: tudo abaixo DEVE ficar vermelho =====
AWS_ACCESS_KEY = "AKIA3FK7XQ2MNP8RTUVW"
GITHUB_TOKEN = "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789"
STRIPE_KEY = "sk_live_51HCk2pLfAkLmNoPqRsTuVwXy"
DATABASE_URL = "postgres://admin:S3nh4Sup3r@db.interno.local:5432/prod"
DB_PASSWORD = "Pg_S3nh4_Forte_2024"          # senha em atribuicao (estilo .env)
JWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTYifQ.SflKxwRJSMeKKF2QT4f"
cartao = "4111 1111 1111 1111"               # Visa de teste (Luhn valido)

# PII brasileira: com e SEM mascara
cpf_mascarado = "529.982.247-25"
cpf_cru = "52998224725"
cnpj = "11.222.333/0001-81"

print(saudacao("Natan"))

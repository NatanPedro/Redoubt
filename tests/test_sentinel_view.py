"""Testes do modelo de exibicao (notepy/sentinel_view.py) — sem Qt.

O painel da Sentinela fica NA TELA, e a tela e o que se compartilha: estes testes garantem que
a previa nunca entrega o segredo (nem o fim dele, nem o comprimento)."""

from notepy import sentinel_view as sv


def test_categoria_separa_pii_de_credencial():
    for k in ("CPF", "CPF (sem mascara)", "CNPJ", "CNPJ (sem mascara)", "Cartao de credito"):
        assert sv.category(k) == "pii"
    for k in ("Chave de acesso AWS", "Token do GitHub", "Segredo em atribuicao",
              "Possivel segredo (alta entropia)", "segredo registrado"):
        assert sv.category(k) == "credencial"


def test_mascara_mostra_so_o_prefixo_publico_do_provedor():
    aws = "AKIA3FK7XQ2MNP8RTUVW"
    m = sv.mask(aws, "Chave de acesso AWS")
    assert m.startswith("AKIA") and "•" in m
    assert "RTUVW" not in m and "3FK7" not in m          # nada alem do prefixo publico
    gh = "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789"
    assert sv.mask(gh, "Token do GitHub") == "ghp_" + "•" * 8


def test_prefixo_dos_provedores_novos_e_o_mais_especifico():
    """Achados REAIS da Sentinela: cada provedor novo mostra o proprio prefixo, e a Anthropic nao
    cai no 'sk-' generico da OpenAI (o especifico vem antes na lista)."""
    import random
    import string

    from notepy import secrets

    rng = random.Random(7)
    body = "".join(rng.choice(string.ascii_letters + string.digits) for _ in range(93))
    hexs = "".join(rng.choice("0123456789abcdef") for _ in range(40))
    for token, prefix in (("sk-ant-" + "api03-" + body + "AA", "sk-ant-"),
                          ("hf_" + body[:34], "hf_"),
                          ("sbp_" + hexs, "sbp_"),
                          ("ya29." + body[:60], "ya29.")):
        (hit,) = secrets.scan(f"x {token} y")
        assert sv.mask(hit.snippet, hit.kind) == prefix + "•" * 8, hit.kind


def test_mascara_da_assinatura_sas_e_so_pontos():
    """No SAS do Azure o achado e so a assinatura: nao ha prefixo publico a mostrar."""
    assert sv.mask("aB3dEfGh1jKlMn0pQrStUvWxYz0123456789abcdE%3D", "Assinatura SAS do Azure") == "•" * 8


def test_mascara_de_senha_pii_e_cartao_e_so_pontos():
    for snippet, kind in (("Pg_S3nh4_Forte_2024", "Segredo em atribuicao"),
                          ("529.982.247-25", "CPF"),
                          ("4111 1111 1111 1111", "Cartao de credito"),
                          ("batata123", "segredo registrado"),
                          ("sk_live_parece_prefixo_mas_e_senha", "Segredo em atribuicao")):
        assert sv.mask(snippet, kind) == "•" * 8, kind


def test_mascara_nao_entrega_o_comprimento():
    curto = sv.mask("AKIA3FK7XQ2MNP8RTUVW", "Chave de acesso AWS")
    longo = sv.mask("AKIA" + "X" * 60, "Chave de acesso AWS")
    assert curto == longo


def test_prefixo_nao_aparece_se_o_segredo_e_quase_so_prefixo():
    assert sv.mask("ghp_abc", "Token do GitHub") == "•" * 8


def test_rotulos_com_acento_para_a_tela():
    assert sv.display("Cartao de credito") == "Cartão de crédito"
    assert sv.display("CPF (sem mascara)") == "CPF (sem máscara)"
    assert sv.display("Chave de acesso AWS") == "Chave de acesso AWS"      # desconhecido: igual


def test_forca_de_senha():
    assert sv.password_strength("").level == 0
    assert sv.password_strength("abc1").level == 1
    forte = sv.password_strength("correct horse battery staple")
    assert forte.level >= 3 and forte.bits > 60
    # repeticao nao vale como entropia
    assert sv.password_strength("a" * 16).bits < sv.password_strength("abcdefghijklmnop").bits

# Relay do ARASAKA HOLO em PHP

Para hospedagens compartilhadas (como a Hostinger), que não rodam o servidor em Python. É o mesmo relay
cego do `arasaka_holo/server.py`, por HTTP: o HOLO entra numa espera longa de até 20 s ("long polling") e
as mensagens chegam em 1 a 2 segundos.

## Subir no site

1. No painel da hospedagem, abra o **Gerenciador de arquivos** do domínio (ex.: `public_html` do piphin.online).
2. Envie o `index.php` desta pasta para a raiz do site (troque o `index.php` que mostra a página "HOLO RELAY").
3. Abra `https://seu-dominio/` no navegador: tem que aparecer **ONLINE**. Se aparecer o erro da extensão
   sodium, ative a extensão `sodium` no painel (PHP Configuration > Extensions).
4. No HOLO, use `https://seu-dominio/` em CONFIG > SERVIDOR (o padrão já é `https://piphin.online/`).

O relay cria sozinho a pasta `holo-data/` (com um `.htaccess` que bloqueia o acesso pelo navegador).

## O que fica no servidor

| | |
|---|---|
| `holo-data/nicks/` | nick → chave pública e o mês do registro (um arquivo por nick) |
| `holo-data/sessions/`, `queues/`, `rooms/` | quem está online, em quais salas (só o hash do id) e as mensagens **cifradas** em trânsito. Tudo some quando a pessoa sai (60 s sem resposta) |
| Logs | o relay não grava nada. Os logs de acesso da hospedagem são do painel dela: desligue em "Logs" se quiser |

Diferença para o servidor em Python: lá as mensagens em trânsito ficam só na memória; aqui ficam alguns
segundos em arquivos (cifradas), até o destinatário buscar.

## Testar no seu PC

```bash
php -S 127.0.0.1:8099 -t relay-php
```

No HOLO, use `http://127.0.0.1:8099/`.

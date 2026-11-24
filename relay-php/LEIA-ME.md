# Relay do ARASAKA HOLO na Hostinger

Para hospedagem compartilhada, que não roda o servidor em Python. É o mesmo relay cego, por HTTP: o HOLO espera
até 20 s por mensagens em cada requisição ("long polling") e elas chegam em menos de 1 segundo, mais o tempo da rede.

Precisa de **PHP 8.0 ou mais novo** com a extensão **sodium** e de **SSL** no domínio.

## Instalar ou atualizar

1. No hPanel: **Sites > Gerenciar > Gerenciador de arquivos** e abra o `public_html` do domínio.
2. **Atualizando:** baixe uma cópia da pasta `holo-data/`, se ela existir. Ela guarda a quem pertence cada nick.
   Não a apague.
3. Envie o `holo-hostinger.zip` e extraia **dentro** do `public_html`, trocando os arquivos antigos. Devem ficar lá:
   `index.php`, `.htaccess` e `holo-config.exemplo.php`. Se o site já tiver um `.htaccess` seu, junte os dois.
4. Opcional: renomeie `holo-config.exemplo.php` para `holo-config.php` e edite. As atualizações não mexem nele.
5. Abra `https://seu-dominio/?check`. Todos os itens devem estar com ✔ (menos os opcionais).
6. No HOLO: CONFIG > SERVIDOR > `https://seu-dominio/`.

| Se o `?check` mostrar ✖ em | Faça |
|---|---|
| PHP 8.0 | Avançado > Configuração do PHP > escolha 8.2 ou 8.3 |
| sodium | Configuração do PHP > Extensões > marque `sodium` |
| HTTPS | Segurança > SSL > instale o certificado |
| pasta de dados grava | Gerenciador de arquivos > permissão 755 na pasta do site |
| dados fora da área pública | funciona assim mesmo: confira se `https://seu-dominio/holo-data/secret.php` dá erro 403 |

**Na primeira abertura**, a versão 1.2 move a `holo-data/` para fora da área pública do site (uma pasta
`holo-data` ao lado do `public_html`), quando a hospedagem deixa.

## Calls e compartilhamento de tela

O relay só entrega a sinalização, que é cifrada. **Áudio e vídeo vão direto entre os PCs**, então não gastam a banda
nem o processador da hospedagem.

Em algumas redes (CGNAT, Wi-Fi de empresa) os dois PCs não conseguem se conectar direto. Para esses casos, e para
quem marca "Esconder meu IP", é preciso um servidor **TURN**. Ele **não roda em hospedagem compartilhada**: use uma
VPS com coturn ou um serviço de TURN, e preencha `turn` no `holo-config.php`.

coturn numa VPS (Ubuntu/Debian), em `/etc/turnserver.conf`:

```
listening-port=3478
fingerprint
use-auth-secret
static-auth-secret=TROQUE-POR-UM-SEGREDO-LONGO
realm=turn.seu-dominio.com
no-cli
no-multicast-peers
denied-peer-ip=10.0.0.0-10.255.255.255
denied-peer-ip=172.16.0.0-172.31.255.255
denied-peer-ip=192.168.0.0-192.168.255.255
denied-peer-ip=127.0.0.0-127.255.255.255
```

Libere as portas 3478 (UDP e TCP) e 49152-65535 (UDP). No `holo-config.php`:

```php
'turn' => ['url' => 'turn:turn.seu-dominio.com:3478?transport=udp', 'secret' => 'TROQUE-POR-UM-SEGREDO-LONGO'],
```

## Quantas pessoas cabem

Cada pessoa online ocupa um processo PHP enquanto espera mensagens. Os planos compartilhados limitam isso (o painel
mostra como "Entry Processes" ou "PHP Workers"). Se bater no limite, diminua `poll_wait` no `holo-config.php`
(ex.: 5) ou mude o relay para uma VPS com `./install.sh --so-servidor`.

## O que fica no servidor

| | |
|---|---|
| `nicks/` | nick → chave pública e o mês do registro (um arquivo por nick). **Faça backup desta pasta** |
| `sessions/`, `queues/`, `rooms/` | quem está online, em quais salas (pelo id, que é um hash) e as mensagens **cifradas** em trânsito. Tudo some quando a pessoa sai, ou após 60 s sem resposta |
| `secret.php`, `challenges/` | segredo do servidor e desafios de login já usados (2 min) |
| Logs | o relay não grava nada. Os logs de acesso da hospedagem são do painel dela: desligue-os se puder |

A limpeza roda em qualquer visita. Sem nenhum acesso ao site, sobras cifradas podem esperar até a próxima visita.

## Testar no seu PC

```bash
php -S 127.0.0.1:8099 -t relay-php                    # no HOLO: http://127.0.0.1:8099/
python tests/test_http_relay.py --php                 # testes automáticos contra o PHP de verdade
```

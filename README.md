# ARASAKA HOLO

Chat com tema Arasaka e **privacidade máxima**, para Linux e Windows.

- **Não tem:** conta, login, e-mail, telefone ou senha de usuário.
- **Seu nick:** um nick único, derivado do **MAC da sua placa de rede**. Você é sempre a mesma pessoa
  naquele computador.

## Como o nick eterno funciona

```
MAC da placa (nunca sai do seu PC)
  └─ scrypt(MAC, sal do HOLO)            ← hash lento: dificulta descobrir o MAC a partir do nick
       └─ palavra + palavra + 4 hex      ← ex.: KuroiRonin-7F3A
```

O nick é escolhido sempre do mesmo jeito: a placa **cabeada** tem prioridade, depois o endereço de
fábrica. Endereços "aleatórios" de Wi-Fi e placas virtuais (VPN, VirtualBox, Hyper-V, Docker) são
ignorados, porque mudam com o tempo.

**Importante: o MAC não é segredo.** Ele aparece para qualquer um na mesma rede. Por isso o nick
**não** funciona como senha. A posse do nick é provada por uma **chave Ed25519** gerada no seu
computador:

1. Na primeira conexão, o servidor vincula `nick → sua chave pública`, para sempre.
2. Outro computador com o mesmo nick é **recusado**. Isso foi testado com um MAC idêntico e outra chave.
3. **Faça backup da chave** em CONFIG > EXPORTAR CHAVE. Se reinstalar o sistema, importe a chave e o
   nick continua sendo seu.

Para ver seu nick no terminal: `arasaka-holo --nick`.

## O que é protegido

| | |
|---|---|
| **Salas** | Chave = Argon2id(senha, nome da sala). O servidor recebe só um **hash** da chave como id: não sabe o nome nem a senha. Mensagens cifradas com XSalsa20-Poly1305 |
| **Mensagens diretas** | Curve25519 + XSalsa20-Poly1305 (crypto_box): só o destinatário abre |
| **Autenticidade** | Toda mensagem é **assinada** (Ed25519). O HOLO confere a assinatura com a chave registrada do nick e **fixa a chave localmente**. Se ela mudar depois, você recebe um aviso. Isso protege inclusive contra um servidor mal-intencionado |
| **Sem histórico** | Nada é guardado: nem no servidor, nem no seu disco. Quem está offline não recebe. Fechar o app apaga tudo |
| **Autodestruição** | 30 s, 5 min ou 1 h, com contagem regressiva na mensagem |
| **PÂNICO** (`Ctrl+Shift+X`) | Sai de todas as salas e limpa a tela, a memória e a área de transferência |
| **Sem rastreio no app** | Sem telemetria, sem cabeçalho de user-agent e sem prévias automáticas de links |

### O que o servidor sabe (e o que não sabe)

| O servidor | |
|---|---|
| **Guarda em disco** | só `nick → chave pública` e o mês do registro |
| **Vê na memória enquanto você está online** | seu nick, os **ids (hashes)** das salas em que você está, o nick do destinatário de uma mensagem direta, o tamanho e o horário dos pacotes |
| **Nunca vê** | o conteúdo das mensagens, nomes e senhas das salas, seu MAC |
| **Logs** | não registra IPs nem conexões |

### Limites (leia)

- **IP:** como em qualquer serviço de rede, o servidor recebe o seu IP no momento da conexão. O HOLO
  não registra o IP, mas, para escondê-lo da rede, use VPN ou Tor.
- **Salas sem senha:** são públicas. Quem souber o nome da sala consegue ler.
- **Sigilo de mensagens passadas:** as chaves são fixas, então não há *forward secrecy*. Se alguém
  roubar sua chave e tiver gravado o tráfego antigo, consegue abrir as mensagens diretas antigas. Para
  conversas sensíveis, use autodestruição e guarde bem a chave.
- **Primeiro contato:** confira a **impressão digital** da chave da outra pessoa por outro meio (ela
  aparece no painel da direita).
- **Quando o nick muda:**
  - trocando a placa de rede;
  - usando outro computador;
  - rodando dentro de uma máquina virtual (cada VM tem seu próprio MAC).
- **Auditoria:** a criptografia é a da libsodium, uma biblioteca auditada, mas o protocolo do HOLO em
  si não passou por auditoria independente.

## Instalar

| Sistema | Como |
|---|---|
| **Windows** | extraia o `.zip` e dê dois cliques em **`install.bat`** |
| **Linux** (só o chat) | `./install.sh` |
| **Linux** (chat + servidor como serviço, porta 7077) | `./install.sh --servidor` |
| **VPS** (só o servidor, sem interface) | `./install.sh --so-servidor` |

## Servidor

O servidor é um "relay cego": só repassa blobs cifrados. Escolha onde ele roda:

| Onde | Como |
|---|---|
| **Na sua rede local (LAN)** | Abra CONFIG > **INICIAR SERVIDOR** num dos PCs. Os outros usam `ws://IP-DESSE-PC:7077` |
| **Pela internet** | Rode `arasaka-holo-server` numa VPS, ou no seu PC com a porta 7077 liberada no roteador. Os outros usam `ws://SEU-IP:7077` |
| **Com TLS** (recomendado na internet) | `arasaka-holo-server --cert fullchain.pem --key privkey.pem`. Os clientes usam `wss://seu-dominio:7077`. Também funciona atrás de um proxy reverso (Caddy ou nginx) com WebSocket |

Opções do servidor: `--host`, `--port`, `--data` (pasta do diretório de nicks) e `--motd` (mensagem de
boas-vindas).

## Usar

| Ação | Como |
|---|---|
| Entrar em sala | **+ em SALAS** (`Ctrl+J`): nome e senha opcional. Todos que usarem o mesmo nome e a mesma senha se encontram |
| Mensagem direta | **+ em DIRETAS** (`Ctrl+D`) com o nick, ou duplo clique num nick da lista de online |
| Enviar | `Enter` envia, `Shift+Enter` quebra a linha |
| Autodestruição | escolha o tempo ao lado do campo de mensagem |

## Desinstalar

| Sistema | Comando |
|---|---|
| Linux | `./uninstall.sh` |
| Windows | `powershell -ExecutionPolicy Bypass -File uninstall.ps1` |

A sua **chave é mantida** (`~/.config/arasaka-holo` ou `%APPDATA%\arasaka-holo`). Sem ela você perde o
nick.

---

Arasaka é marca da CD PROJEKT RED, e a fonte cedge1 usa a licença FontStruct Non-Commercial. Este é
um projeto pessoal de fã, sem fins comerciais.

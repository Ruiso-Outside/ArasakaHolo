# ARASAKA HOLO

Chat com tema Arasaka e **privacidade máxima**, com **call de voz** e **compartilhamento de tela**, para Linux e
Windows.

- **Não tem:** conta, login, e-mail, telefone ou senha de usuário.
- **Seu nick:** um nick único, derivado do **MAC da sua placa de rede**. Você é sempre a mesma pessoa
  naquele computador, mesmo se trocar a placa.

## Como o nick eterno funciona

```
MAC da placa (nunca sai do seu PC)
  └─ scrypt(MAC, sal do HOLO)            ← hash lento: dificulta descobrir o MAC a partir do nick
       └─ palavra + palavra + 4 hex      ← ex.: KuroiRonin-7F3A
```

O nick é escolhido sempre do mesmo jeito: a placa **cabeada** tem prioridade, depois o endereço de
fábrica. Endereços "aleatórios" de Wi-Fi e placas virtuais (VPN, VirtualBox, Hyper-V, Docker) são
ignorados, porque mudam com o tempo. O MAC só decide o nick na **primeira vez**: depois vale a identidade salva,
e uma chave existente nunca é sobrescrita (a anterior fica guardada como `identity-*.key` na mesma pasta).

**Importante: o MAC não é segredo.** Ele aparece para qualquer um na mesma rede. Por isso o nick
**não** funciona como senha. A posse do nick é provada por uma **chave Ed25519** gerada no seu
computador:

1. Na primeira conexão, o servidor vincula `nick → sua chave pública`, para sempre.
2. Outro computador com o mesmo nick é **recusado**. Isso foi testado com um MAC idêntico e outra chave.
3. **Faça backup da chave** em CONFIG > EXPORTAR CHAVE. O arquivo é protegido por uma senha que você cria
   (Argon2id + XSalsa20-Poly1305), e o HOLO lembra de fazer o backup enquanto ele não existir. Em outro PC, ou
   depois de reinstalar, importe a chave com a senha e o nick continua sendo seu.

Para ver seu nick no terminal: `arasaka-holo --nick`.

## O que é protegido

| | |
|---|---|
| **Salas** | Chave = Argon2id(senha, nome da sala). O servidor recebe só um **hash** da chave como id: não sabe o nome nem a senha. Mensagens cifradas com XSalsa20-Poly1305 |
| **Mensagens diretas** | Curve25519 + XSalsa20-Poly1305 (crypto_box): só o destinatário abre |
| **Autenticidade** | Toda mensagem é **assinada** (Ed25519). O HOLO confere a assinatura com a chave registrada do nick e **fixa a chave localmente**. Se ela mudar depois, você recebe um aviso. Isso protege inclusive contra um servidor mal-intencionado |
| **Contexto e repetição** | A assinatura inclui a sala (ou as duas chaves da conversa): ninguém consegue levar uma mensagem sua para outro lugar. Mensagens repetidas são ignoradas, e as com hora estranha aparecem marcadas |
| **Login** | A assinatura do login inclui o endereço do servidor: um servidor mal-intencionado não consegue usá-la para entrar em outro com o seu nick |
| **Calls e tela** | WebRTC par a par, cifrado com DTLS-SRTP. A impressão digital da conexão viaja numa mensagem direta assinada, então o servidor não consegue entrar no meio. Nada é gravado |
| **Sem histórico** | Nada de conversa é guardado no seu disco. No servidor, só o que está em trânsito. Quem está offline não recebe |
| **Autodestruição** | 30 s, 5 min ou 1 h, com contagem regressiva na mensagem. Quem apaga é o app de quem recebe: não impede um print ou um app modificado |
| **PÂNICO** (`Ctrl+Shift+X`) | Sai da call e de todas as salas, fecha microfone e tela, limpa as conversas e a área de transferência e apaga as senhas de "Lembrar as salas". A memória do processo só é limpa de verdade ao fechar o app |
| **Sem rastreio no app** | Sem telemetria e sem prévias automáticas de links. Nenhum dado do sistema no user-agent (por HTTP vai só um `ARASAKA-HOLO` fixo, igual para todos) |

### O que o servidor sabe (e o que não sabe)

| O servidor | |
|---|---|
| **Guarda em disco** | `nick → chave pública` e o mês do registro. No relay PHP também: sessões de quem está online e mensagens **cifradas** em trânsito, por segundos (no máximo cerca de 2 min) |
| **Vê enquanto você está online** | seu nick, os **ids (hashes)** das salas em que você está, o nick do destinatário de uma mensagem direta, o tamanho e o horário dos pacotes |
| **Nas calls** | vê que duas pessoas trocaram mensagens diretas. Áudio e vídeo não passam por ele |
| **Nunca recebe** | o conteúdo das mensagens, nomes e senhas das salas, seu MAC |
| **Logs** | não registra IPs nem conexões (os logs de acesso da hospedagem ficam no painel dela) |

### Limites (leia)

- **IP:** como em qualquer serviço de rede, o servidor recebe o seu IP no momento da conexão. O HOLO
  não registra o IP, mas, para escondê-lo da rede, use VPN ou Tor.
- **IP nas calls:** a call é direta, então quem está nela vê o seu IP, e o servidor STUN também. Para esconder,
  ligue CONFIG > "Esconder meu IP" (precisa de TURN no servidor) ou use VPN. Seu IP só vai para quem já está na call.
- **Calls e roteadores:** sem TURN, algumas redes (CGNAT, Wi-Fi de empresa) não conseguem se conectar direto.
- **Eco:** não há cancelamento de eco. Use fone.
- **Nick inventado:** o servidor não tem como conferir o MAC. Um cliente modificado pode registrar qualquer nick
  **livre** (nunca um que já tem dono). O que prova quem é a pessoa é a impressão digital da chave.
- **Salas sem senha:** são públicas. Quem souber o nome da sala consegue ler.
- **Senhas fracas:** quem controla o servidor consegue testar senhas comuns contra o id da sala. Use o botão GERAR.
- **Sigilo de mensagens passadas:** as chaves são fixas, então não há *forward secrecy*. Se alguém
  roubar sua chave e tiver gravado o tráfego antigo, consegue abrir as mensagens diretas antigas. Para
  conversas sensíveis, use autodestruição e guarde bem a chave.
- **Primeiro contato:** confira a **impressão digital** da chave da outra pessoa por outro meio (ela
  aparece no painel da direita).
- **Quando o nick muda:**
  - usando outro computador sem importar a chave;
  - apagando a pasta de configuração.
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

O servidor é um "relay cego": só repassa blobs cifrados. Por padrão o HOLO conecta na **rede oficial**, `https://piphin.online/`. Para usar outro servidor, troque em CONFIG > SERVIDOR. Escolha onde ele roda:

| Onde | Como |
|---|---|
| **Hospedagem compartilhada (Hostinger)** | Envie o conteúdo de `relay-php/` para o site. Passo a passo em [relay-php/LEIA-ME.md](relay-php/LEIA-ME.md) |
| **Na sua rede local (LAN)** | Abra CONFIG > **INICIAR SERVIDOR** num dos PCs. Os outros usam `ws://IP-DESSE-PC:7077` |
| **Pela internet** | Rode `arasaka-holo-server` numa VPS, ou no seu PC com a porta 7077 liberada no roteador. Os outros usam `ws://SEU-IP:7077` |
| **Com TLS** (recomendado na internet) | `arasaka-holo-server --cert fullchain.pem --key privkey.pem`. Os clientes usam `wss://seu-dominio:7077`. Também funciona atrás de um proxy reverso (Caddy ou nginx) com WebSocket |

Opções do servidor: `--host`, `--port`, `--data` (pasta do diretório de nicks), `--motd` (mensagem de boas-vindas),
`--public-host` (endereço público, se o proxy trocar o cabeçalho Host), `--no-legacy` (recusa o HOLO 1.1) e, para as
calls, `--stun`, `--turn` e `--turn-secret`.

**Ao atualizar da 1.1:** atualize o servidor **antes** dos clientes. O servidor novo aceita clientes antigos, mas o
cliente novo recusa servidores antigos. As mensagens da 1.1 também são recusadas: todos precisam atualizar.

## Usar

| Ação | Como |
|---|---|
| Entrar em sala | **+ em SALAS** (`Ctrl+J`): nome e senha opcional. Todos que usarem o mesmo nome e a mesma senha se encontram |
| Mensagem direta | **+ em DIRETAS** (`Ctrl+D`) com o nick, ou duplo clique num nick da lista de online |
| Enviar | `Enter` envia, `Shift+Enter` quebra a linha |
| Autodestruição | escolha o tempo ao lado do campo de mensagem |
| Call de voz | **CALL** (`Ctrl+K`) na conversa direta ou na sala (até 6 pessoas). `Ctrl+M` liga e desliga o microfone |
| Volume | **SOM** durante a call (ou clique no nick): volume de 0 a 200% e silenciar por pessoa, volume geral e do seu microfone. O ajuste de cada pessoa vale só no seu PC, ela não fica sabendo, e é lembrado nas próximas calls |
| Compartilhar tela | **TELA** durante a call: escolha o monitor e a qualidade. Os outros clicam em VER TELA (duplo clique: tela cheia) |
| Não conecta | o motivo fica numa barra no topo. **DIAGNOSTICAR** testa cada passo e copia um relatório sem nick, IP ou chave |
| Quem pode ligar | CONFIG > CALLS > RECEBER DE (padrão: só quem já conversou com você) |

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

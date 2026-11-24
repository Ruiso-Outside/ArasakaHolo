<?php
/*
 * ARASAKA HOLO // opcoes do relay. Renomeie para holo-config.php (as atualizacoes nao mexem nele).
 * Tudo aqui e opcional: sem este arquivo, o relay usa estes mesmos valores.
 */
return [
    // mensagem mostrada a quem conecta
    'motd' => 'Rede oficial ARASAKA HOLO',

    // pasta dos dados. Vazio = escolhe sozinho (fora da area publica do site, quando a hospedagem deixa)
    'data' => '',

    // endereco que as pessoas usam. So preencha se um proxy ou CDN trocar o cabecalho Host
    'host' => '',

    // recusa conexoes sem https
    'require_https' => true,

    // aceita o login do HOLO 1.1. Depois que todos atualizarem, troque para false
    'legacy' => true,

    // segundos que cada cliente espera por mensagens numa requisicao. Cada pessoa online ocupa um processo PHP:
    // se o painel acusar "entry processes" no limite, diminua (ex.: 5)
    'poll_wait' => 20,

    // ---------------------------------------------------------------- calls e compartilhamento de tela
    // STUN: diz a cada PC qual e o proprio endereco na internet. '' desliga (calls so na mesma rede)
    'stun' => 'stun:stun.cloudflare.com:3478',

    // TURN: repassa o audio e o video quando os dois PCs nao conseguem se conectar direto (e para quem marca
    // "esconder meu IP"). Nao roda em hospedagem compartilhada: use uma VPS com coturn ou um servico de TURN.
    'turn' => null,
    // coturn com use-auth-secret (a senha expira sozinha):
    // 'turn' => ['url' => 'turn:turn.seu-dominio.com:3478?transport=udp', 'secret' => 'o-static-auth-secret'],
    // usuario e senha fixos:
    // 'turn' => ['url' => 'turn:host:3478?transport=udp', 'user' => 'usuario', 'pass' => 'senha'],
];

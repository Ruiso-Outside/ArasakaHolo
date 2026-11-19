<?php
/*
 * ARASAKA HOLO // relay cego em PHP (para hospedagens compartilhadas, como a Hostinger)
 *
 * O mesmo protocolo do servidor em Python (arasaka_holo/server.py), por HTTP:
 *   POST /  {"op":"hello"}                          -> desafio para a autenticacao
 *   POST /  {"op":"auth", ...}                      -> token da sessao
 *   POST /  {"op":"send","token":..,"msgs":[...]}   -> join, leave, msg, dm, whois, ping
 *   POST /  {"op":"poll","token":..}                -> espera ate 20 s por eventos
 *   GET  /                                          -> pagina de status
 *
 * Guarda em disco: o diretorio nick -> chave publica e, so enquanto estao em transito (segundos), as
 * mensagens cifradas de quem esta online. Sessoes sem "poll" por 60 s saem (e as filas sao apagadas).
 * Nao registra IP, nao guarda historico e nao ve o conteudo (cifrado no cliente).
 */

declare(strict_types=1);

const PROTO = 1;
const POW_BITS = 18;
const MAX_FRAME = 32768;
const MAX_ROOMS = 64;
const RATE_N = 30;
const RATE_WINDOW = 10.0;
const SESSION_TTL = 60;      // s sem poll = offline
const POLL_WAIT = 20;        // s de espera do poll
const CHALLENGE_TTL = 120;
const NICK_RE = '/^[A-Z][A-Za-z]{2,24}[A-Z][A-Za-z]{1,24}-[0-9A-F]{4}$/';   // o mesmo do identity.py
const MOTD = 'Rede oficial ARASAKA HOLO · piphin.online';

$DATA = getenv('HOLO_DATA') ?: __DIR__ . '/holo-data';

// ----------------------------------------------------------------------------- utilitarios
function data_dir(string $sub = ''): string {
    global $DATA;
    $d = $sub === '' ? $DATA : "$DATA/$sub";
    if (!is_dir($d)) {
        @mkdir($d, 0700, true);
        if ($sub === '') {
            @file_put_contents("$DATA/.htaccess", "Require all denied\nDeny from all\n");
            @file_put_contents("$DATA/index.html", '');
        }
    }
    return $d;
}

function out(array $data, int $code = 200): void {
    http_response_code($code);
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: no-store');
    echo json_encode($data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    exit;
}

function fail(string $code, string $msg, int $http = 200): void {
    out(['op' => 'error', 'code' => $code, 'msg' => $msg], $http);
}

// leitura e escrita de JSON com trava (varias requisicoes ao mesmo tempo)
function with_json(string $file, callable $fn, $default = []) {
    $h = fopen($file, 'c+');
    if (!$h) return null;
    flock($h, LOCK_EX);
    $raw = stream_get_contents($h);
    $data = $raw ? json_decode($raw, true) : null;
    if (!is_array($data)) $data = $default;
    [$new, $ret] = $fn($data);
    if ($new !== null) {
        ftruncate($h, 0);
        rewind($h);
        fwrite($h, json_encode($new, JSON_UNESCAPED_SLASHES));
        fflush($h);
    }
    flock($h, LOCK_UN);
    fclose($h);
    return $ret;
}

function read_json(string $file, $default = []) {
    if (!is_file($file)) return $default;
    $h = fopen($file, 'r');
    if (!$h) return $default;
    flock($h, LOCK_SH);
    $raw = stream_get_contents($h);
    flock($h, LOCK_UN);
    fclose($h);
    $d = $raw ? json_decode($raw, true) : null;
    return is_array($d) ? $d : $default;
}

function safe_id(string $s): string { return hash('sha256', $s); }      // nome de arquivo seguro

function sess_file(string $token): string { return data_dir('sessions') . '/' . safe_id($token) . '.json'; }
function queue_file(string $token): string { return data_dir('queues') . '/' . safe_id($token) . '.q'; }
function room_file(string $rid): string { return data_dir('rooms') . '/' . safe_id($rid) . '.json'; }
function nick_file(string $nick): string { return data_dir('nicks') . '/' . safe_id($nick) . '.json'; }

// entrega um evento para uma sessao (fila em JSON por linha)
function push(string $token, array $ev): void {
    $f = queue_file($token);
    if (!is_file(sess_file($token))) return;
    file_put_contents($f, json_encode($ev, JSON_UNESCAPED_SLASHES) . "\n", FILE_APPEND | LOCK_EX);
}

function b64d(string $s): string { $r = base64_decode($s, true); return $r === false ? '' : $r; }

function pow_ok(string $challenge, string $nick, string $pk, int $nonce, int $bits = POW_BITS): bool {
    $h = hash('sha256', "$challenge|$nick|$pk|$nonce", true);
    $full = intdiv($bits, 8);
    for ($i = 0; $i < $full; $i++) if (ord($h[$i]) !== 0) return false;
    $rest = $bits % 8;
    return $rest === 0 || (ord($h[$full]) >> (8 - $rest)) === 0;
}

function check_auth(string $pk, string $challenge, string $nick, string $sig): bool {
    $pkb = b64d($pk);
    $sigb = b64d($sig);
    if (strlen($pkb) !== SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES || strlen($sigb) !== SODIUM_CRYPTO_SIGN_BYTES) return false;
    return sodium_crypto_sign_verify_detached($sigb, "HOLO-AUTH|$challenge|$nick", $pkb);
}

// diretorio de nicks: um arquivo por nick (nick -> chave publica e o mes do registro)
function dir_get(string $nick): ?string {
    $d = read_json(nick_file($nick), null);
    return is_array($d) ? ($d['pk'] ?? null) : null;
}

function dir_register(string $nick, string $pk): bool {
    return (bool) with_json(nick_file($nick), function ($d) use ($nick, $pk) {
        if (!empty($d['pk']) && $d['pk'] !== $pk) return [null, false];
        if (!empty($d['pk'])) return [null, true];
        return [['nick' => $nick, 'pk' => $pk, 'since' => date('Y-m')], true];
    });
}

function nick_count(): int { return count(glob(data_dir('nicks') . '/*.json') ?: []); }

// ----------------------------------------------------------------------------- sessoes e salas
function load_session(string $token): ?array {
    if (!preg_match('/^[0-9a-f]{64}$/', $token)) return null;
    $s = read_json(sess_file($token), null);
    if (!is_array($s) || time() - ($s['seen'] ?? 0) > SESSION_TTL) return null;
    return $s;
}

function online_nicks(): array {
    $out = [];
    foreach (glob(data_dir('sessions') . '/*.json') ?: [] as $f) {
        $s = read_json($f, null);
        if (is_array($s) && time() - ($s['seen'] ?? 0) <= SESSION_TTL) $out[$s['nick']][] = $s['token'];
    }
    return $out;
}

function room_members(string $rid): array {      // token -> nick (so sessoes vivas)
    $m = read_json(room_file($rid), []);
    $live = [];
    foreach ($m as $tok => $nick) if (load_session((string) $tok)) $live[$tok] = $nick;
    return $live;
}

function presence(string $rid, string $nick, bool $on, ?string $skip = null): void {
    $members = room_members($rid);
    foreach ($members as $tok => $_) {
        if ($tok !== $skip) push((string) $tok, ['op' => 'presence', 'room' => $rid, 'nick' => $nick, 'on' => $on, 'count' => count($members)]);
    }
}

function leave_room(array $s, string $rid): void {
    $token = $s['token'];
    $left = with_json(room_file($rid), function ($m) use ($token) {
        if (!isset($m[$token])) return [null, false];
        unset($m[$token]);
        return [$m, true];
    });
    if ($left) {
        $still = in_array($s['nick'], room_members($rid), true);
        if (!$still) presence($rid, $s['nick'], false);
    }
}

// limpa sessoes expiradas (e avisa as salas), de vez em quando
function gc(): void {
    if (mt_rand(1, 20) !== 1) return;
    foreach (glob(data_dir('sessions') . '/*.json') ?: [] as $f) {
        $s = read_json($f, null);
        if (is_array($s) && time() - ($s['seen'] ?? 0) <= SESSION_TTL) continue;
        @unlink($f);
        if (is_array($s)) {
            @unlink(queue_file($s['token']));
            foreach ($s['rooms'] ?? [] as $rid) leave_room($s, (string) $rid);
        }
    }
    foreach (glob(data_dir('challenges') . '/*') ?: [] as $f) if (time() - filemtime($f) > CHALLENGE_TTL) @unlink($f);
    foreach (glob(data_dir('rooms') . '/*.json') ?: [] as $f) if (!read_json($f, [])) @unlink($f);
}

function rate_ok(string $token): bool {
    return (bool) with_json(sess_file($token), function ($s) {
        $now = microtime(true);
        $t = array_values(array_filter($s['times'] ?? [], fn($x) => $now - $x < RATE_WINDOW));
        if (count($t) >= RATE_N) return [null, false];
        $t[] = $now;
        $s['times'] = $t;
        return [$s, true];
    }, null);
}

// ----------------------------------------------------------------------------- operacoes
function op_hello(): void {
    $ch = bin2hex(random_bytes(16));
    file_put_contents(data_dir('challenges') . '/' . $ch, '');
    out(['op' => 'hello', 'proto' => PROTO, 'challenge' => $ch, 'pow' => POW_BITS, 'motd' => MOTD, 'transport' => 'http']);
}

function op_auth(array $m): void {
    $ch = (string) ($m['challenge'] ?? '');
    $chf = data_dir('challenges') . '/' . (preg_match('/^[0-9a-f]{32}$/', $ch) ? $ch : 'x');
    if (!is_file($chf) || time() - filemtime($chf) > CHALLENGE_TTL) fail('bad_auth', 'desafio expirado: conecte de novo');
    @unlink($chf);                                              // cada desafio vale uma vez
    $nick = (string) ($m['nick'] ?? '');
    $pk = (string) ($m['pk'] ?? '');
    if (!preg_match(NICK_RE, $nick) || strlen($pk) > 64) fail('bad_auth', 'autenticacao invalida');
    $known = dir_get($nick);
    if ($known && $known !== $pk) fail('nick_taken', 'este nick ja pertence a outra chave');
    if (!check_auth($pk, $ch, $nick, (string) ($m['sig'] ?? ''))) fail('bad_sig', 'assinatura invalida');
    $new = !$known;
    if ($new) {
        if (!pow_ok($ch, $nick, $pk, (int) ($m['pow'] ?? -1))) fail('pow', 'prova de trabalho invalida');
        if (!dir_register($nick, $pk)) fail('nick_taken', 'este nick ja pertence a outra chave');
    }
    $token = bin2hex(random_bytes(32));
    file_put_contents(sess_file($token), json_encode(['token' => $token, 'nick' => $nick, 'pk' => $pk, 'rooms' => [], 'seen' => time(), 'times' => []]), LOCK_EX);
    out(['op' => 'welcome', 'nick' => $nick, 'new' => $new, 'online' => count(online_nicks()), 'token' => $token]);
}

function op_send(array $m): void {
    $s = load_session((string) ($m['token'] ?? ''));
    if (!$s) fail('session', 'sessao expirada: conecte de novo');
    $token = $s['token'];
    $replies = [];
    foreach (array_slice((array) ($m['msgs'] ?? []), 0, 50) as $x) {
        if (!is_array($x)) continue;
        if (strlen(json_encode($x)) > MAX_FRAME) { $replies[] = ['op' => 'error', 'code' => 'too_big', 'msg' => 'mensagem grande demais']; continue; }
        $op = $x['op'] ?? '';
        if (($op === 'msg' || $op === 'dm') && !rate_ok($token)) { $replies[] = ['op' => 'error', 'code' => 'rate', 'msg' => 'devagar: limite de mensagens']; continue; }
        if ($op === 'join') {
            $rid = substr((string) ($x['room'] ?? ''), 0, 64);
            $s = load_session($token);
            if ($rid === '' || count($s['rooms']) >= MAX_ROOMS) continue;
            with_json(room_file($rid), function ($mm) use ($token, $s) { $mm[$token] = $s['nick']; return [$mm, true]; });
            with_json(sess_file($token), function ($ss) use ($rid) { $ss['rooms'] = array_values(array_unique(array_merge($ss['rooms'] ?? [], [$rid]))); return [$ss, true]; }, null);
            $names = array_values(array_unique(array_values(room_members($rid))));
            sort($names);
            $replies[] = ['op' => 'joined', 'room' => $rid, 'members' => $names];
            presence($rid, $s['nick'], true, $token);
        } elseif ($op === 'leave') {
            $rid = (string) ($x['room'] ?? '');
            with_json(sess_file($token), function ($ss) use ($rid) { $ss['rooms'] = array_values(array_diff($ss['rooms'] ?? [], [$rid])); return [$ss, true]; }, null);
            leave_room($s, $rid);
        } elseif ($op === 'msg') {
            $rid = (string) ($x['room'] ?? '');
            $members = room_members($rid);
            if (!isset($members[$token])) continue;
            $ev = ['op' => 'msg', 'room' => $rid, 'blob' => (string) ($x['blob'] ?? '')];
            foreach ($members as $tok => $_) push((string) $tok, $ev);
        } elseif ($op === 'dm') {
            $to = (string) ($x['to'] ?? '');
            $targets = online_nicks()[$to] ?? [];
            if (!$targets) { $replies[] = ['op' => 'error', 'code' => 'offline', 'to' => $to, 'msg' => "$to esta offline (nada e guardado no servidor)"]; continue; }
            $ev = ['op' => 'dm', 'from' => $s['nick'], 'from_pk' => $s['pk'], 'blob' => (string) ($x['blob'] ?? '')];
            foreach ($targets as $tok) push($tok, $ev);
            $replies[] = ['op' => 'dm_ok', 'to' => $to, 'ref' => $x['ref'] ?? null];
        } elseif ($op === 'whois') {
            $n = (string) ($x['nick'] ?? '');
            $replies[] = ['op' => 'whois', 'nick' => $n, 'pk' => preg_match(NICK_RE, $n) ? dir_get($n) : null, 'online' => isset(online_nicks()[$n])];
        } elseif ($op === 'ping') {
            $replies[] = ['op' => 'pong', 't' => $x['t'] ?? null];
        }
    }
    out(['op' => 'sent', 'events' => $replies]);
}

function op_poll(array $m): void {
    $token = (string) ($m['token'] ?? '');
    if (!load_session($token)) fail('session', 'sessao expirada: conecte de novo');
    @set_time_limit(POLL_WAIT + 15);
    ignore_user_abort(false);
    $until = microtime(true) + POLL_WAIT;
    $qf = queue_file($token);
    $touched = 0;
    do {
        if (time() - $touched >= 5) {   // "ainda online" (a cada 5 s, para nao travar o arquivo da sessao)
            with_json(sess_file($token), function ($s) { $s['seen'] = time(); return [$s, true]; }, null);
            $touched = time();
        }
        clearstatcache(true, $qf);
        if (is_file($qf) && filesize($qf) > 0) {
            $h = fopen($qf, 'c+');
            flock($h, LOCK_EX);
            $raw = stream_get_contents($h);
            ftruncate($h, 0);
            flock($h, LOCK_UN);
            fclose($h);
            $events = [];
            foreach (explode("\n", trim((string) $raw)) as $line) {
                $e = json_decode($line, true);
                if (is_array($e)) $events[] = $e;
            }
            if ($events) out(['op' => 'events', 'events' => $events]);
        }
        if (connection_aborted()) exit;
        usleep(400000);
    } while (microtime(true) < $until);
    out(['op' => 'events', 'events' => []]);
}

// ----------------------------------------------------------------------------- entrada
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    header('X-Robots-Tag: noindex');
    $raw = file_get_contents('php://input', false, null, 0, MAX_FRAME * 4);
    $m = json_decode((string) $raw, true);
    if (!is_array($m)) fail('bad_request', 'requisicao invalida', 400);
    if (!function_exists('sodium_crypto_sign_verify_detached')) fail('server', 'o PHP do servidor nao tem a extensao sodium', 500);
    data_dir();
    gc();
    switch ($m['op'] ?? '') {
        case 'hello': op_hello();
        case 'auth': op_auth($m);
        case 'send': op_send($m);
        case 'poll': op_poll($m);
        case 'info': out(['holo' => PROTO, 'transport' => 'http', 'online' => count(online_nicks()), 'nicks' => nick_count()]);
        default: fail('bad_request', 'operacao desconhecida', 400);
    }
}

// GET: pagina de status
$online = is_dir($DATA) ? count(online_nicks()) : 0;
$sodium = function_exists('sodium_crypto_sign_verify_detached');
header('Content-Type: text/html; charset=utf-8');
header('Referrer-Policy: no-referrer');
?><!doctype html>
<html lang="pt-br"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow"><title>ARASAKA HOLO</title>
<style>
:root{--red:#e3121f;--bg:#050506;--fg:#ececf0;--mute:#8c8c96}
body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.6 "Bahnschrift","Rajdhani",system-ui,sans-serif;display:grid;place-items:center;min-height:100vh;
background-image:linear-gradient(rgba(227,18,31,.06) 1px,transparent 1px),linear-gradient(90deg,rgba(227,18,31,.06) 1px,transparent 1px);background-size:48px 48px}
main{max-width:560px;margin:16px;padding:32px;border:1px solid #2a0a0d;background:#0a0a0c;clip-path:polygon(18px 0,100% 0,100% calc(100% - 18px),calc(100% - 18px) 100%,0 100%,0 18px)}
h1{margin:0;letter-spacing:.2em;color:var(--red);font-size:28px}small{color:var(--mute);letter-spacing:.3em}
code{background:#16161a;padding:2px 8px;color:var(--fg)}.ok{color:#3ddc84}.bad{color:var(--red)}p{color:#c8c8d0}
</style></head><body><main>
<small>ARASAKA // SECURE COMMS</small>
<h1>HOLO RELAY</h1>
<p class="<?= $sodium ? 'ok' : 'bad' ?>"><?= $sodium ? 'ONLINE' : 'ERRO: o PHP deste servidor nao tem a extensao sodium' ?>. Relay cego: so repassa mensagens cifradas.<?= $sodium ? " · $online online agora" : '' ?></p>
<p>No ARASAKA HOLO, va em CONFIG &gt; SERVIDOR e use:<br><code>https://<?= htmlspecialchars($_SERVER['HTTP_HOST'] ?? 'piphin.online') ?>/</code></p>
<p>Sem contas. Sem historico. As mensagens sao cifradas no seu computador antes de sair.</p>
</main></body></html>

<?php
/*
 * ARASAKA HOLO // relay cego em PHP (para hospedagens compartilhadas, como a Hostinger). PHP 8.0+ com sodium.
 *
 * O mesmo protocolo do servidor em Python (arasaka_holo/server.py), por HTTP:
 *   POST /  {"op":"hello"}                          -> desafio para a autenticacao
 *   POST /  {"op":"auth", ...}                      -> token da sessao + servidores STUN/TURN das calls
 *   POST /  {"op":"send","token":..,"msgs":[...]}   -> join, leave, msg, dm, whois, ice, ping
 *   POST /  {"op":"poll","token":..}                -> espera por eventos
 *   POST /  {"op":"bye","token":..}                 -> encerra a sessao na hora
 *   GET  /                                          -> pagina de status
 *   GET  /?check                                    -> diagnostico da instalacao
 *
 * Calls e compartilhamento de tela: o relay so entrega a sinalizacao (mensagens diretas cifradas). Audio e video
 * vao direto entre os PCs (WebRTC) ou por um servidor TURN configurado no holo-config.php.
 *
 * Guarda em disco: o diretorio nick -> chave publica e, so enquanto estao em transito (segundos), as mensagens
 * cifradas de quem esta online. Nao registra IP, nao guarda historico e nao ve o conteudo.
 *
 * Nao edite este arquivo: as opcoes ficam no holo-config.php (que as atualizacoes nao tocam).
 */

declare(strict_types=1);

const VERSION = '1.2.0';
const PROTO = 1;
const AUTH = 2;              // assinatura presa ao endereco do servidor
const POW_BITS = 18;
const MAX_FRAME = 32768;
const MAX_ROOMS = 64;
const MAX_PER_NICK = 8;
const RATE_N = 30;
const RATE_WINDOW = 10.0;
const OPS_N = 120;           // operacoes de qualquer tipo por janela
const SESSION_TTL = 60;      // s sem poll = offline
const EVENT_TTL = 60;        // s: evento que ninguem buscou e descartado
const MAX_QUEUE = 2097152;   // bytes na fila de uma sessao
const CHALLENGE_TTL = 120;
const GC_EVERY = 10;
const NICK_RE = '/\A[A-Z][A-Za-z]{2,24}[A-Z][A-Za-z]{1,24}-[0-9A-F]{4}\z/';   // o mesmo do identity.py

ini_set('display_errors', '0');

// ----------------------------------------------------------------------------- configuracao
function cfg(string $k) {
    static $c = null;
    if ($c === null) {
        $c = ['motd' => 'Rede ARASAKA HOLO', 'data' => '', 'host' => '', 'require_https' => true, 'legacy' => true,
              'poll_wait' => 20, 'stun' => 'stun:stun.cloudflare.com:3478', 'turn' => null];
        $f = __DIR__ . '/holo-config.php';
        if (is_file($f)) {
            $u = include $f;
            if (is_array($u)) $c = array_merge($c, $u);
        }
    }
    return $c[$k];
}

// Pasta dos dados: fora da area publica do site, quando da. Uma holo-data antiga (dentro do site) e movida sozinha.
function data_root(): string {
    static $root = null;
    if ($root !== null) return $root;
    $fixed = getenv('HOLO_DATA') ?: (string) cfg('data');
    if ($fixed !== '') return $root = rtrim($fixed, '/');
    $old = __DIR__ . '/holo-data';
    $doc = rtrim(str_replace(chr(92), '/', (string) realpath((string) ($_SERVER['DOCUMENT_ROOT'] ?? ''))), '/');
    $here = str_replace(chr(92), '/', (string) realpath(__DIR__));
    $up = $doc === '' ? '' : dirname($doc);
    // so vale se a pasta de cima nao for, ela mesma, parte de um site (ex.: subdominio dentro do public_html)
    if ($up === '' || $up === $doc || strpos("$here/", "$doc/") !== 0
        || preg_match('#/(public_html|www|htdocs)(/|$)#i', $up)) return $root = $old;
    $rel = substr($here, strlen($doc));                 // numa subpasta, o nome muda: cada instalacao tem os seus dados
    $new = "$up/holo-data" . ($rel === '' ? '' : '-' . substr(hash('sha256', $rel), 0, 8));
    if (@is_dir($new)) return $root = $new;
    if (@is_writable($up)) {
        if (is_dir($old)) @rename($old, $new);
        else @mkdir($new, 0700);
    }
    clearstatcache();
    return $root = @is_dir($new) ? $new : $old;         // outra visita pode ter movido neste instante
}

function data_dir(string $sub = ''): string {
    $base = data_root();
    if (!is_dir($base)) @mkdir($base, 0700, true);
    if (!is_file("$base/.htaccess")) {
        @file_put_contents("$base/.htaccess", "<IfModule mod_authz_core.c>\nRequire all denied\n</IfModule>\n"
            . "<IfModule !mod_authz_core.c>\nDeny from all\n</IfModule>\n");
        @file_put_contents("$base/index.html", '');
    }
    if ($sub === '') return $base;
    if (!is_dir("$base/$sub")) @mkdir("$base/$sub", 0700, true);
    return "$base/$sub";
}

// segredo do servidor, para os desafios sem estado
function secret(): string {
    $f = data_dir() . '/secret.php';
    $h = @fopen($f, 'c+');           // com trava: a primeira visita pode vir de duas pessoas ao mesmo tempo
    if (!$h) fail('server', 'a pasta de dados nao aceita gravacao', 500);
    flock($h, LOCK_EX);
    $raw = (string) stream_get_contents($h);
    if (preg_match("/'([0-9a-f]{64})'/", $raw, $m)) {
        $s = $m[1];
    } else {
        $s = bin2hex(random_bytes(32));
        ftruncate($h, 0);
        rewind($h);
        fwrite($h, "<?php return '$s';\n");
        fflush($h);
    }
    flock($h, LOCK_UN);
    fclose($h);
    @chmod($f, 0600);
    return $s;
}

// ----------------------------------------------------------------------------- utilitarios
function out(array $data, int $code = 200): void {
    http_response_code($code);
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: no-store');
    echo json_encode($data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE);
    exit;
}

function fail(string $code, string $msg, int $http = 200): void {
    out(['op' => 'error', 'code' => $code, 'msg' => $msg], $http);
}

function str_of($v): string { return is_string($v) || is_int($v) ? (string) $v : ''; }

// Le e grava JSON com trava (varias requisicoes ao mesmo tempo). $create = false: se o arquivo nao existe mais,
// nao faz nada (uma sessao encerrada nao pode renascer vazia).
function with_json(string $file, callable $fn, bool $create = true) {
    $h = @fopen($file, $create ? 'c+' : 'r+');
    if (!$h) return null;
    flock($h, LOCK_EX);
    $raw = stream_get_contents($h);
    $data = $raw ? json_decode($raw, true) : null;
    $ret = null;
    if (is_array($data) || $create) {
        [$new, $ret] = $fn(is_array($data) ? $data : []);
        if ($new !== null) {
            ftruncate($h, 0);
            rewind($h);
            fwrite($h, json_encode($new, JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE));
            fflush($h);
        }
    }
    flock($h, LOCK_UN);
    fclose($h);
    return $ret;
}

function read_json(string $file): ?array {
    $h = @fopen($file, 'r');
    if (!$h) return null;
    flock($h, LOCK_SH);
    $raw = stream_get_contents($h);
    flock($h, LOCK_UN);
    fclose($h);
    $d = $raw ? json_decode($raw, true) : null;
    return is_array($d) ? $d : null;
}

function safe_id(string $s): string { return hash('sha256', $s); }      // nome de arquivo seguro

function sess_file(string $token): string { return data_dir('sessions') . '/' . safe_id($token) . '.json'; }
function queue_file(string $token): string { return data_dir('queues') . '/' . safe_id($token) . '.q'; }
function room_file(string $rid): string { return data_dir('rooms') . '/' . safe_id($rid) . '.json'; }
function nick_file(string $nick): string { return data_dir('nicks') . '/' . safe_id($nick) . '.json'; }

// entrega um evento para uma sessao (um JSON por linha, com a hora para expirar)
function push(string $token, array $ev): void {
    if (!is_file(sess_file($token))) return;
    $f = queue_file($token);
    clearstatcache(true, $f);
    if (is_file($f) && filesize($f) > MAX_QUEUE) return;
    @file_put_contents($f, json_encode([time(), $ev], JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE) . "\n", FILE_APPEND | LOCK_EX);
}

function b64d(string $s): string { $r = base64_decode($s, true); return $r === false ? '' : $r; }

// ----------------------------------------------------------------------------- autenticacao
function new_challenge(): string {
    $body = sprintf('%08x', time()) . bin2hex(random_bytes(12));
    return $body . substr(hash_hmac('sha256', $body, secret()), 0, 32);
}

function challenge_ok(string $ch): bool {
    if (!preg_match('/\A[0-9a-f]{64}\z/', $ch)) return false;
    if (!hash_equals(substr(hash_hmac('sha256', substr($ch, 0, 32), secret()), 0, 32), substr($ch, 32))) return false;
    $age = time() - hexdec(substr($ch, 0, 8));
    return $age >= -5 && $age <= CHALLENGE_TTL;
}

function burn_challenge(string $ch): bool {             // cada desafio vale uma vez
    $h = @fopen(data_dir('challenges') . '/' . $ch, 'x');
    if (!$h) return false;
    fclose($h);
    return true;
}

function pow_ok(string $challenge, string $nick, string $pk, int $nonce, int $bits = POW_BITS): bool {
    $h = hash('sha256', "$challenge|$nick|$pk|$nonce", true);
    $full = intdiv($bits, 8);
    for ($i = 0; $i < $full; $i++) if (ord($h[$i]) !== 0) return false;
    $rest = $bits % 8;
    return $rest === 0 || (ord($h[$full]) >> (8 - $rest)) === 0;
}

// o mesmo endereco que o cliente usou (porta padrao some): entra na assinatura do login
function host_id(): string {
    $h = (string) cfg('host') ?: (string) ($_SERVER['HTTP_HOST'] ?? '');
    $p = parse_url('http://' . trim($h));
    if (!is_array($p) || empty($p['host'])) return '';
    $host = trim(strtolower($p['host']), '[]');
    $port = $p['port'] ?? 0;
    return $port && $port !== 80 && $port !== 443 ? "$host:$port" : $host;
}

function check_auth(string $pk, string $challenge, string $nick, string $sig): bool {
    $pkb = b64d($pk);
    $sigb = b64d($sig);
    if (strlen($pkb) !== SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES || strlen($sigb) !== SODIUM_CRYPTO_SIGN_BYTES) return false;
    if (sodium_crypto_sign_verify_detached($sigb, 'HOLO-AUTH2|' . host_id() . "|$challenge|$nick", $pkb)) return true;
    return cfg('legacy') && sodium_crypto_sign_verify_detached($sigb, "HOLO-AUTH|$challenge|$nick", $pkb);
}

// diretorio de nicks: um arquivo por nick (nick -> chave publica e o mes do registro)
function dir_get(string $nick): ?string {
    $d = read_json(nick_file($nick));
    return $d['pk'] ?? null;
}

function dir_register(string $nick, string $pk): bool {
    return (bool) with_json(nick_file($nick), function ($d) use ($nick, $pk) {
        if (!empty($d['pk'])) return [null, $d['pk'] === $pk];
        return [['nick' => $nick, 'pk' => $pk, 'since' => date('Y-m')], true];
    });
}

// STUN/TURN das calls. Com 'secret' (use-auth-secret do coturn) a credencial expira sozinha.
function ice_servers(): array {
    $out = [];
    if (cfg('stun')) $out[] = ['urls' => [(string) cfg('stun')]];
    $t = cfg('turn');
    if (is_array($t) && !empty($t['url'])) {
        $user = (string) ($t['user'] ?? '');
        $pass = (string) ($t['pass'] ?? '');
        if (!empty($t['secret'])) {
            $user = (time() + 86400) . ':holo';
            $pass = base64_encode(hash_hmac('sha1', $user, (string) $t['secret'], true));
        }
        $out[] = ['urls' => [(string) $t['url']], 'username' => $user, 'credential' => $pass];
    }
    return $out;
}

// ----------------------------------------------------------------------------- sessoes e salas
function alive(?array $s): bool { return $s !== null && isset($s['nick'], $s['token']) && time() - ($s['seen'] ?? 0) <= SESSION_TTL; }

function load_session(string $token): ?array {
    if (!preg_match('/\A[0-9a-f]{64}\z/', $token)) return null;
    $s = read_json(sess_file($token));
    return alive($s) ? $s : null;
}

function online_nicks(): array {
    $out = [];
    foreach (glob(data_dir('sessions') . '/*.json') ?: [] as $f) {
        $s = read_json($f);
        if (alive($s)) $out[$s['nick']][] = $s['token'];
    }
    return $out;
}

function room_members(string $rid): array {      // token -> nick (so sessoes vivas)
    $live = [];
    foreach (read_json(room_file($rid)) ?? [] as $tok => $nick) if (load_session((string) $tok)) $live[$tok] = $nick;
    return $live;
}

function presence(string $rid, string $nick, bool $on, ?string $skip = null): void {
    $members = room_members($rid);
    foreach ($members as $tok => $_) {
        if ((string) $tok !== $skip) push((string) $tok, ['op' => 'presence', 'room' => $rid, 'nick' => $nick, 'on' => $on, 'count' => count($members)]);
    }
}

function leave_room(array $s, string $rid): void {
    $token = $s['token'];
    $left = with_json(room_file($rid), function ($m) use ($token) {
        if (!isset($m[$token])) return [null, false];
        unset($m[$token]);
        return [$m, true];
    }, false);
    if ($left && !in_array($s['nick'], room_members($rid), true)) presence($rid, $s['nick'], false);
}

function end_session(array $s): void {
    @unlink(sess_file($s['token']));
    @unlink(queue_file($s['token']));
    foreach ($s['rooms'] ?? [] as $rid) leave_room($s, (string) $rid);
}

// limpa sessoes expiradas (e avisa as salas) no maximo a cada GC_EVERY segundos, em qualquer visita
function gc(): void {
    $mark = data_dir() . '/gc';
    clearstatcache(true, $mark);
    if (is_file($mark) && time() - filemtime($mark) < GC_EVERY) return;
    @touch($mark);
    foreach (glob(data_dir('sessions') . '/*.json') ?: [] as $f) {
        $s = read_json($f);
        if (alive($s)) continue;
        if ($s !== null && isset($s['token'], $s['nick'])) end_session($s);
        elseif (time() - (int) @filemtime($f) > SESSION_TTL) @unlink($f);
    }
    foreach (glob(data_dir('challenges') . '/*') ?: [] as $f) if (time() - (int) @filemtime($f) > CHALLENGE_TTL + 10) @unlink($f);
    foreach (glob(data_dir('queues') . '/*') ?: [] as $f) if (time() - (int) @filemtime($f) > SESSION_TTL * 2) @unlink($f);
    foreach (glob(data_dir('rooms') . '/*.json') ?: [] as $f) if (!read_json($f) && time() - (int) @filemtime($f) > SESSION_TTL) @unlink($f);
}

function rate_ok(string $token, string $field, int $max): bool {
    return (bool) with_json(sess_file($token), function ($s) use ($field, $max) {
        $now = microtime(true);
        $t = array_values(array_filter($s[$field] ?? [], fn($x) => $now - $x < RATE_WINDOW));
        if (count($t) >= $max) return [null, false];
        $t[] = round($now, 2);
        $s[$field] = $t;
        $s['seen'] = time();
        return [$s, true];
    }, false);
}

// ----------------------------------------------------------------------------- operacoes
function op_hello(): void {
    out(['op' => 'hello', 'proto' => PROTO, 'auth' => AUTH, 'challenge' => new_challenge(), 'pow' => POW_BITS,
         'motd' => (string) cfg('motd'), 'transport' => 'http']);
}

function op_auth(array $m): void {
    $ch = str_of($m['challenge'] ?? '');
    if (!challenge_ok($ch)) fail('challenge', 'desafio expirado: conecte de novo');
    $nick = str_of($m['nick'] ?? '');
    $pk = str_of($m['pk'] ?? '');
    if (!preg_match(NICK_RE, $nick) || strlen($pk) > 64) fail('bad_auth', 'autenticacao invalida');
    $known = dir_get($nick);
    if ($known && $known !== $pk) fail('nick_taken', 'este nick ja pertence a outra chave');
    if (!check_auth($pk, $ch, $nick, str_of($m['sig'] ?? ''))) fail('bad_sig', 'assinatura invalida');
    if (!burn_challenge($ch)) fail('challenge', 'desafio ja usado: conecte de novo');
    $new = !$known;
    if ($new) {
        $pow = $m['pow'] ?? -1;
        if (!pow_ok($ch, $nick, $pk, is_int($pow) ? $pow : -1)) fail('pow', 'prova de trabalho invalida');
        if (!dir_register($nick, $pk)) fail('nick_taken', 'este nick ja pertence a outra chave');
    }
    $online = online_nicks();
    if (count($online[$nick] ?? []) >= MAX_PER_NICK) fail('too_many', 'conexoes demais deste nick');
    $token = bin2hex(random_bytes(32));
    $ok = @file_put_contents(sess_file($token), json_encode(['token' => $token, 'nick' => $nick, 'pk' => $pk, 'rooms' => [], 'seen' => time(), 'times' => [], 'ops' => []]), LOCK_EX);
    if (!$ok) fail('server', 'o servidor nao conseguiu gravar (disco cheio ou sem permissao)', 500);
    $online[$nick] = 1;
    out(['op' => 'welcome', 'nick' => $nick, 'new' => $new, 'online' => count($online), 'ice' => ice_servers(), 'token' => $token]);
}

function op_send(array $m): void {
    $token = str_of($m['token'] ?? '');
    $s = load_session($token);
    if (!$s) fail('session', 'sessao expirada: conecte de novo');
    $replies = [];
    $msgs = is_array($m['msgs'] ?? null) ? $m['msgs'] : [];
    foreach (array_slice($msgs, 0, 50) as $x) {
        if (!is_array($x)) continue;
        if (strlen((string) json_encode($x)) > MAX_FRAME) { $replies[] = ['op' => 'error', 'code' => 'too_big', 'msg' => 'mensagem grande demais']; continue; }
        $op = $x['op'] ?? '';
        if (!rate_ok($token, 'ops', OPS_N) || (($op === 'msg' || $op === 'dm') && !rate_ok($token, 'times', RATE_N))) {
            $replies[] = ['op' => 'error', 'code' => 'rate', 'msg' => 'devagar: limite de mensagens'];
            continue;
        }
        if ($op === 'join') {
            $rid = substr(str_of($x['room'] ?? ''), 0, 64);
            if ($rid === '') continue;
            $ok = with_json(sess_file($token), function ($ss) use ($rid) {
                $rooms = $ss['rooms'] ?? [];
                if (in_array($rid, $rooms, true)) return [null, true];
                if (count($rooms) >= MAX_ROOMS) return [null, false];
                $ss['rooms'] = array_merge($rooms, [$rid]);
                return [$ss, true];
            }, false);
            if (!$ok) continue;
            with_json(room_file($rid), function ($mm) use ($token, $s) { $mm[$token] = $s['nick']; return [$mm, true]; });
            $names = array_values(array_unique(array_values(room_members($rid))));
            sort($names);
            $replies[] = ['op' => 'joined', 'room' => $rid, 'members' => $names];
            presence($rid, $s['nick'], true, $token);
        } elseif ($op === 'leave') {
            $rid = str_of($x['room'] ?? '');
            with_json(sess_file($token), function ($ss) use ($rid) { $ss['rooms'] = array_values(array_diff($ss['rooms'] ?? [], [$rid])); return [$ss, true]; }, false);
            leave_room($s, $rid);
        } elseif ($op === 'msg') {
            $rid = str_of($x['room'] ?? '');
            $members = room_members($rid);
            if (!isset($members[$token])) continue;
            $ev = ['op' => 'msg', 'room' => $rid, 'blob' => str_of($x['blob'] ?? '')];
            foreach ($members as $tok => $_) push((string) $tok, $ev);
        } elseif ($op === 'dm') {
            $to = str_of($x['to'] ?? '');
            $targets = preg_match(NICK_RE, $to) ? (online_nicks()[$to] ?? []) : [];
            if (!$targets) { $replies[] = ['op' => 'error', 'code' => 'offline', 'to' => $to, 'msg' => "$to esta offline (nada e guardado no servidor)"]; continue; }
            $ev = ['op' => 'dm', 'from' => $s['nick'], 'from_pk' => $s['pk'], 'blob' => str_of($x['blob'] ?? '')];
            foreach ($targets as $tok) push($tok, $ev);
            $replies[] = ['op' => 'dm_ok', 'to' => $to, 'ref' => $x['ref'] ?? null];
        } elseif ($op === 'whois') {
            $n = str_of($x['nick'] ?? '');
            $replies[] = ['op' => 'whois', 'nick' => $n, 'pk' => preg_match(NICK_RE, $n) ? dir_get($n) : null, 'online' => isset(online_nicks()[$n])];
        } elseif ($op === 'ice') {
            $replies[] = ['op' => 'ice', 'servers' => ice_servers()];
        } elseif ($op === 'ping') {
            $replies[] = ['op' => 'pong', 't' => $x['t'] ?? null];
        }
    }
    out(['op' => 'sent', 'events' => $replies]);
}

function op_poll(array $m): void {
    $token = str_of($m['token'] ?? '');
    if (!load_session($token)) fail('session', 'sessao expirada: conecte de novo');
    $wait = max(1, min(25, (int) cfg('poll_wait')));
    @set_time_limit($wait + 15);
    ignore_user_abort(false);
    $until = microtime(true) + $wait;
    $qf = queue_file($token);
    $touched = 0;
    do {
        if (time() - $touched >= 5) {   // "ainda online" (a cada 5 s, para nao travar o arquivo da sessao)
            if (!with_json(sess_file($token), function ($s) { $s['seen'] = time(); return [$s, true]; }, false)) fail('session', 'sessao encerrada');
            $touched = time();
            gc();
        }
        clearstatcache(true, $qf);
        if (is_file($qf) && filesize($qf) > 0 && ($h = @fopen($qf, 'r+'))) {
            flock($h, LOCK_EX);
            $raw = stream_get_contents($h);
            ftruncate($h, 0);
            flock($h, LOCK_UN);
            fclose($h);
            $events = [];
            foreach (explode("\n", trim((string) $raw)) as $line) {
                $e = json_decode($line, true);
                if (is_array($e) && is_array($e[1] ?? null) && time() - (int) $e[0] <= EVENT_TTL) $events[] = $e[1];
            }
            if ($events) out(['op' => 'events', 'events' => $events]);
        }
        if (connection_aborted()) exit;
        usleep(200000);
    } while (microtime(true) < $until);
    out(['op' => 'events', 'events' => []]);
}

function op_bye(array $m): void {
    $s = load_session(str_of($m['token'] ?? ''));
    if ($s) end_session($s);
    out(['op' => 'bye']);
}

// ----------------------------------------------------------------------------- entrada
function is_https(): bool {
    $v = strtolower((string) ($_SERVER['HTTPS'] ?? ''));
    return ($v !== '' && $v !== 'off') || (string) ($_SERVER['SERVER_PORT'] ?? '') === '443'
        || strtolower((string) ($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '')) === 'https';
}

function is_local(): bool { return in_array($_SERVER['REMOTE_ADDR'] ?? '', ['127.0.0.1', '::1'], true); }

$sodium = function_exists('sodium_crypto_sign_verify_detached');
header('X-Robots-Tag: noindex');
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: no-referrer');

if (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'POST') {
    $raw = file_get_contents('php://input', false, null, 0, MAX_FRAME * 4);
    $m = json_decode((string) $raw, true);
    if (!is_array($m)) fail('bad_request', 'requisicao invalida', 400);
    if (!$sodium) fail('server', 'o PHP do servidor nao tem a extensao sodium', 500);
    if (cfg('require_https') && !is_https() && !is_local()) fail('tls', 'use https:// no endereco do servidor');
    if (!is_writable(data_dir())) fail('server', 'a pasta de dados nao aceita gravacao: abra /?check', 500);
    gc();
    switch ($m['op'] ?? '') {
        case 'hello': op_hello();
        case 'auth': op_auth($m);
        case 'send': op_send($m);
        case 'poll': op_poll($m);
        case 'bye': op_bye($m);
        case 'info': out(['holo' => PROTO, 'version' => VERSION, 'transport' => 'http', 'online' => count(online_nicks())]);
        default: fail('bad_request', 'operacao desconhecida', 400);
    }
}

// ----------------------------------------------------------------------------- GET: status e diagnostico
header("Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'");
header('Content-Type: text/html; charset=utf-8');
$writable = is_writable(data_dir());
if ($writable) gc();
$online = $writable ? count(online_nicks()) : 0;
$ok = $sodium && $writable && PHP_VERSION_ID >= 80000;
$checks = [];
if (isset($_GET['check'])) {
    $doc = rtrim((string) ($_SERVER['DOCUMENT_ROOT'] ?? ''), '/');
    $outside = $doc === '' || strpos(data_root() . '/', $doc . '/') !== 0;
    $turn = cfg('turn');
    $exec = (int) ini_get('max_execution_time');
    $checks = [
        ['PHP 8.0 ou mais novo', PHP_VERSION_ID >= 80000, 'troque a versao do PHP no painel (Configuracao do PHP)'],
        ['extensao sodium', $sodium, 'ative sodium em Configuracao do PHP > Extensoes'],
        ['pasta de dados grava', $writable, 'de permissao de escrita na pasta do site'],
        ['dados fora da area publica', $outside, 'estao em holo-data/, protegidos pelo .htaccess: confira se o navegador da erro 403 ao abrir /holo-data/secret.php'],
        ['site em HTTPS', is_https(), 'ative o SSL do dominio no painel'],
        ['tempo de execucao', $exec === 0 || $exec >= (int) cfg('poll_wait') + 5, "max_execution_time = $exec s: diminua poll_wait no holo-config.php"],
        ['holo-config.php', is_file(__DIR__ . '/holo-config.php'), 'opcional: copie o holo-config.exemplo.php'],
        ['STUN (calls)', (bool) cfg('stun'), 'sem STUN, calls so funcionam na mesma rede'],
        ['TURN (calls)', is_array($turn) && !empty($turn['url']), 'opcional: sem TURN, algumas redes nao conseguem fazer call'],
    ];
}
?><!doctype html>
<html lang="pt-br"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow"><title>ARASAKA HOLO</title>
<style>
:root{--red:#e3121f;--bg:#050506;--fg:#ececf0;--mute:#8c8c96}
body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.6 "Bahnschrift","Rajdhani",system-ui,sans-serif;display:grid;place-items:center;min-height:100vh;
background-image:linear-gradient(rgba(227,18,31,.06) 1px,transparent 1px),linear-gradient(90deg,rgba(227,18,31,.06) 1px,transparent 1px);background-size:48px 48px}
main{max-width:600px;margin:16px;padding:32px;border:1px solid #2a0a0d;background:#0a0a0c;clip-path:polygon(18px 0,100% 0,100% calc(100% - 18px),calc(100% - 18px) 100%,0 100%,0 18px)}
h1{margin:0;letter-spacing:.2em;color:var(--red);font-size:28px}small{color:var(--mute);letter-spacing:.3em}
code{background:#16161a;padding:2px 8px;color:var(--fg)}.ok{color:#3ddc84}.bad{color:#ff5560}p,li{color:#c8c8d0}ul{padding:0;list-style:none}
</style></head><body><main>
<small>ARASAKA // SECURE COMMS</small>
<h1>HOLO RELAY</h1>
<?php if ($ok): ?>
<p class="ok">ONLINE. Relay cego: so repassa mensagens cifradas. · <?= $online ?> online agora</p>
<?php else: ?>
<p class="bad">ERRO NA INSTALACAO: abra <code>/?check</code> para ver o que falta.</p>
<?php endif; ?>
<?php if ($checks): ?>
<ul>
<?php foreach ($checks as [$name, $good, $hint]): ?>
<li><span class="<?= $good ? 'ok' : 'bad' ?>"><?= $good ? '✔' : '✖' ?></span> <?= htmlspecialchars($name) ?><?= $good ? '' : ' — ' . htmlspecialchars($hint) ?></li>
<?php endforeach; ?>
</ul>
<p>Relay <?= VERSION ?> · PHP <?= htmlspecialchars(PHP_VERSION) ?></p>
<?php else: ?>
<p>No ARASAKA HOLO, va em CONFIG &gt; SERVIDOR e use:<br><code>https://<?= htmlspecialchars((string) ($_SERVER['HTTP_HOST'] ?? '') . rtrim(strtok((string) ($_SERVER['REQUEST_URI'] ?? '/'), '?'), '/')) ?>/</code></p>
<p>Sem contas. Sem historico. As mensagens sao cifradas no seu computador antes de sair. Calls e telas vao direto entre os participantes.</p>
<?php endif; ?>
</main></body></html>

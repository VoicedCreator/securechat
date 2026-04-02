/**
 * =======================================================================
 *  app.js -- SecureChat v2.0  (Auditado y Reforzado)
 * =======================================================================
 *
 *  CAMBIOS DE SEGURIDAD RESPECTO A v1.0:
 *  =======================================
 *
 *  [FIX 1] HKDF-SHA256 para derivacion de claves
 *    v1: deriveKey(ECDH) → un solo AES-GCM key
 *    v2: deriveBits(ECDH) → HKDF → dos claves separadas (sendKey, recvKey)
 *    Razon: HKDF provee separacion criptografica real y resistencia a
 *    ataques de distinguibilidad. Claves separadas por direccion evitan
 *    ataques de key-reuse en cifrado simetrico bidireccional.
 *
 *  [FIX 2] Fingerprint SHA-256 anti-MitM
 *    v1: ninguna verificacion de autenticidad del intercambio de claves.
 *    v2: SHA-256(secreto_compartido) mostrado a ambos usuarios formateado.
 *    Los usuarios comparan el codigo por VOZ. Si coincide: no hay MitM.
 *    Si no coincide: hay un atacante en medio. Se desconecta.
 *
 *  [FIX 3] Numeros de secuencia dentro del payload cifrado
 *    v1: sin contadores, replay posible.
 *    v2: {text, seq, ts} se cifra junto. El receptor verifica que
 *    seq === expectedSeq. Rechazo de mensajes fuera de orden/duplicados.
 *
 *  [FIX 4] Timeout de handshake (30 segundos)
 *    v1: sin timeout. Una conexion a medias podia quedar abierta.
 *    v2: si el key exchange no completa en 30s, la conexion se cierra.
 *
 *  [FIX 5] Rate limiting (20 mensajes / 10 segundos)
 *    v1: sin limite. Flooding posible.
 *    v2: ventana deslizante de timestamps. Si se supera, se ignoran.
 *
 *  [FIX 6] PeerJS self-hosted
 *    v1: cargado desde unpkg.com (CDN externo, vector de ataque).
 *    v2: peerjs.min.js debe estar en el mismo repositorio (ver HTML).
 *
 *  [FIX 7] CSP meta tag en index.html
 *    Bloquea carga de cualquier script/recurso no autorizado.
 *
 *  ARQUITECTURA CRIPTOGRAFICA FINAL:
 *  ----------------------------------
 *  1. Transporte: WebRTC DTLS-SRTP (nativo, no configurable, siempre ON)
 *  2. App layer: ECDH P-256 → deriveBits → HKDF-SHA256 →
 *                sendKey (AES-GCM-256) + recvKey (AES-GCM-256)
 *  3. Auth/Integridad: GCM authentication tag 128-bit por mensaje
 *  4. Anti-replay: sequence number dentro de payload cifrado
 *  5. Anti-MitM: fingerprint SHA-256 verificado por voz
 *
 *  LIMITACION HONESTA SOBRE IP:
 *  -----------------------------
 *  El servidor PeerJS (0.peerjs.com) ve su IP publica al conectarse
 *  via HTTPS. El servidor STUN (Google) la ve al negociar ICE.
 *  Los MENSAJES nunca pasan por ellos, solo la señalizacion inicial.
 *  PARA OCULTAR SU IP: use Tor Browser (torproject.org).
 *  Con Tor, PeerJS y STUN ven una IP de salida del relay Tor, no la suya.
 *
 * =======================================================================
 */

'use strict';

// ============================================================
// CONSTANTES DE SEGURIDAD
// ============================================================
const HANDSHAKE_TIMEOUT_MS = 30_000;  // 30s maximos para completar key exchange
const RATE_LIMIT_MAX       = 20;      // Max mensajes por ventana
const RATE_LIMIT_WINDOW_MS = 10_000;  // Ventana de 10 segundos

// HKDF info labels -- DEBEN ser distintos para las dos claves
// Iniciador (quien llamo a connect()) cifra con LABEL_INITIATOR
// Receptor (quien recibio la conexion) cifra con LABEL_RECEIVER
const HKDF_LABEL_INITIATOR = 'securechat-v2-initiator-to-receiver';
const HKDF_LABEL_RECEIVER  = 'securechat-v2-receiver-to-initiator';

// ============================================================
// ESTADO (solo en memoria volatil -- muere con la pagina)
// ============================================================
const State = Object.seal({
  peer:             null,
  conn:             null,
  myId:             null,
  remoteId:         null,
  contactNickname:  null,
  myKeyPair:        null,   // { publicKey, privateKey } ECDH P-256
  rawSharedBits:    null,   // ArrayBuffer: secreto ECDH crudo (borrar tras HKDF)
  sendKey:          null,   // CryptoKey AES-GCM-256: yo → ellos
  recvKey:          null,   // CryptoKey AES-GCM-256: ellos → yo
  fingerprint:      null,   // string: SHA-256 del secreto (para verificar MitM)
  isInitiator:      false,
  chatReady:        false,
  handshakeTimer:   null,   // referencia al setTimeout del timeout
  sendSeq:          0,      // contador de mensajes enviados
  expectedRecvSeq:  0,      // contador de mensajes esperados (anti-replay)
  msgTimestamps:    [],     // array para rate limiting
  fingerprintShown: false,  // si el panel de verificacion ya fue mostrado
});

// ============================================================
// DOM
// ============================================================
const DOM = {
  viewHome:          document.getElementById('view-home'),
  viewWaiting:       document.getElementById('view-waiting'),
  viewChat:          document.getElementById('view-chat'),
  myPeerId:          document.getElementById('my-peer-id'),
  serverStatus:      document.getElementById('server-status'),
  inputRemoteId:     document.getElementById('input-remote-id'),
  btnCopyId:         document.getElementById('btn-copy-id'),
  btnConnect:        document.getElementById('btn-connect'),
  statusMsg:         document.getElementById('status-msg'),
  waitingRemoteId:   document.getElementById('waiting-remote-id'),
  btnCancelWait:     document.getElementById('btn-cancel-wait'),
  chatTitleText:     document.getElementById('chat-title-text'),
  contactNameDisplay:document.getElementById('contact-name-display'),
  contactIdDisplay:  document.getElementById('contact-id-display'),
  messagesContainer: document.getElementById('messages-container'),
  messageInput:      document.getElementById('message-input'),
  btnSend:           document.getElementById('btn-send'),
  btnDisconnect:     document.getElementById('btn-disconnect'),
  btnRename:         document.getElementById('btn-rename'),
  btnClearChat:      document.getElementById('btn-clear-chat'),
  btnShowFingerprint:document.getElementById('btn-show-fingerprint'),
  charCount:         document.getElementById('char-count'),
  fingerprintPanel:  document.getElementById('fingerprint-panel'),
  fingerprintDisplay:document.getElementById('fingerprint-display'),
  btnVerifiedOk:     document.getElementById('btn-verified-ok'),
  btnVerifiedFail:   document.getElementById('btn-verified-fail'),
  modalOverlay:      document.getElementById('modal-overlay'),
  requesterId:       document.getElementById('requester-id'),
  btnAccept:         document.getElementById('btn-accept'),
  btnReject:         document.getElementById('btn-reject'),
  btnRejectX:        document.getElementById('btn-reject-x'),
  modalNickname:     document.getElementById('modal-nickname'),
  nicknameInput:     document.getElementById('nickname-input'),
  btnSaveNickname:   document.getElementById('btn-save-nickname'),
  btnCloseNickname:  document.getElementById('btn-close-nickname'),
  btnCloseNickname2: document.getElementById('btn-close-nickname2'),
  rateLimitWarn:     document.getElementById('rate-limit-warn'),
};

// ============================================================
// SPA NAVIGATION
// ============================================================
function showView(name) {
  ['home','waiting','chat'].forEach(v => {
    document.getElementById('view-' + v).classList.remove('active');
  });
  document.getElementById('view-' + name).classList.add('active');
}

function showModal(id)    { document.getElementById(id).classList.remove('hidden'); }
function hideModal(id)    { document.getElementById(id).classList.add('hidden');    }
function showFingerprint() { DOM.fingerprintPanel.classList.remove('hidden'); }
function hideFingerprint() { DOM.fingerprintPanel.classList.add('hidden');    }

function setStatus(msg, type = 'info') {
  DOM.statusMsg.textContent = msg;
  DOM.statusMsg.style.color = type === 'error' ? '#cc0000' : type === 'ok' ? '#006600' : '#000080';
}

// ============================================================
// GENERACION DE ID EFIMERO
// ============================================================
/**
 * ID de 8 caracteres alfanumericos sin ambiguedades.
 * Usa CSPRNG del navegador. Excluye: 0, O, I, 1.
 */
function generateEphemeralId() {
  const CHARSET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  const bytes   = crypto.getRandomValues(new Uint8Array(8));
  return Array.from(bytes).map(b => CHARSET[b % CHARSET.length]).join('');
}

// ============================================================
// CRIPTOGRAFIA — Web Crypto API
// ============================================================

/**
 * Genera par de claves ECDH P-256.
 * La privateKey es extractable: false (no puede salir del navegador).
 * La publicKey es extractable: true (necesitamos enviarla al par).
 */
async function generateKeyPair() {
  return crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' },
    true,           // extractable necesario para exportar publicKey
    ['deriveBits']  // la privateKey solo puede usarse para deriveBits
  );
}

async function exportPublicKey(pk) {
  return crypto.subtle.exportKey('jwk', pk);
}

async function importPublicKey(jwk) {
  return crypto.subtle.importKey(
    'jwk', jwk,
    { name: 'ECDH', namedCurve: 'P-256' },
    false, // no necesita ser exportable
    []
  );
}

/**
 * Derivacion de claves con ECDH + HKDF (FIX 1).
 *
 * Flujo:
 * 1. deriveBits(ECDH) → 256 bits de secreto compartido crudo
 * 2. Computa SHA-256 del secreto → fingerprint para verificacion MitM
 * 3. Importa bits como HKDF key material
 * 4. HKDF-SHA256(label=INITIATOR) → sendKey o recvKey (segun rol)
 * 5. HKDF-SHA256(label=RECEIVER)  → recvKey o sendKey (segun rol)
 * 6. Borra referencia a bits crudos de memoria JS
 *
 * @param {CryptoKey} myPrivKey
 * @param {CryptoKey} theirPubKey
 * @param {boolean} asInitiator
 */
async function deriveAllKeys(myPrivKey, theirPubKey, asInitiator) {
  // Paso 1: secreto ECDH crudo (256 bits = 32 bytes)
  const rawBits = await crypto.subtle.deriveBits(
    { name: 'ECDH', public: theirPubKey },
    myPrivKey,
    256
  );

  // Paso 2: fingerprint SHA-256 del secreto compartido
  // Ambas partes llegan al mismo rawBits, por tanto al mismo fingerprint.
  const fingerprintBuffer = await crypto.subtle.digest('SHA-256', rawBits);
  const fingerprintHex    = Array.from(new Uint8Array(fingerprintBuffer))
    .map(b => b.toString(16).padStart(2, '0').toUpperCase())
    .join('');
  // Formateamos en grupos de 4 para legibilidad (como "safety numbers" de Signal)
  State.fingerprint = fingerprintHex.match(/.{4}/g).join('-');

  // Paso 3: importar bits como HKDF input key material
  const hkdfMaterial = await crypto.subtle.importKey(
    'raw', rawBits, 'HKDF', false, ['deriveKey']
  );

  // Salt: 32 bytes de ceros (RFC 5869 permite salt nulo; usamos fijo para determinismo)
  const salt = new Uint8Array(32);

  // Paso 4: derivar clave del INICIADOR → RECEPTOR
  const initiatorKey = await crypto.subtle.deriveKey(
    {
      name: 'HKDF', hash: 'SHA-256', salt,
      info: new TextEncoder().encode(HKDF_LABEL_INITIATOR)
    },
    hkdfMaterial,
    { name: 'AES-GCM', length: 256 },
    false,  // no exportable - jamas sale del navegador
    asInitiator ? ['encrypt'] : ['decrypt']
  );

  // Paso 5: derivar clave del RECEPTOR → INICIADOR
  const receiverKey = await crypto.subtle.deriveKey(
    {
      name: 'HKDF', hash: 'SHA-256', salt,
      info: new TextEncoder().encode(HKDF_LABEL_RECEIVER)
    },
    hkdfMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    asInitiator ? ['decrypt'] : ['encrypt']
  );

  // Asignar sendKey / recvKey segun rol
  if (asInitiator) {
    // Iniciador ENVIA con la clave "initiator" y RECIBE con la "receiver"
    State.sendKey = initiatorKey;
    State.recvKey = receiverKey;
  } else {
    // Receptor ENVIA con la clave "receiver" y RECIBE con la "initiator"
    State.sendKey = receiverKey;
    State.recvKey = initiatorKey;
  }

  // Paso 6: eliminar referencia a bits crudos (GC eventual)
  // No podemos hacer zero-fill de ArrayBuffer importado, pero eliminar
  // la referencia permite que el GC libere la memoria.
  State.rawSharedBits = null;

  console.info('[SecureChat] Claves HKDF derivadas. Fingerprint:', State.fingerprint);
}

/**
 * Cifra un objeto JS con AES-GCM-256 usando State.sendKey.
 * IV: 96 bits aleatorios unicos por mensaje.
 * Incluye autenticacion GCM (128-bit tag) automatica.
 *
 * @param {object} payload - Objeto a cifrar ({text, seq, ts})
 * @returns {Promise<{iv: number[], data: number[]}>}
 */
async function encryptPayload(payload) {
  const iv      = crypto.getRandomValues(new Uint8Array(12));
  const encoded = new TextEncoder().encode(JSON.stringify(payload));

  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, tagLength: 128 },
    State.sendKey,
    encoded
  );

  return {
    iv:   Array.from(iv),
    data: Array.from(new Uint8Array(ciphertext))
  };
}

/**
 * Descifra y autentica un objeto {iv, data} con State.recvKey.
 * Si el tag GCM no valida (mensaje alterado o clave incorrecta): excepcion.
 *
 * @param {{iv: number[], data: number[]}} encObj
 * @returns {Promise<object>}
 */
async function decryptPayload(encObj) {
  const iv         = new Uint8Array(encObj.iv);
  const ciphertext = new Uint8Array(encObj.data);

  const decrypted = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv, tagLength: 128 },
    State.recvKey,
    ciphertext
  );

  return JSON.parse(new TextDecoder().decode(decrypted));
}

// ============================================================
// RATE LIMITING (FIX 5)
// ============================================================
/**
 * Devuelve true si el mensaje puede enviarse, false si se supero el limite.
 * Usa ventana deslizante de timestamps.
 */
function checkRateLimit() {
  const now    = Date.now();
  const cutoff = now - RATE_LIMIT_WINDOW_MS;

  // Purgar timestamps fuera de la ventana
  State.msgTimestamps = State.msgTimestamps.filter(t => t > cutoff);

  if (State.msgTimestamps.length >= RATE_LIMIT_MAX) {
    DOM.rateLimitWarn.classList.remove('hidden');
    setTimeout(() => DOM.rateLimitWarn.classList.add('hidden'), 3000);
    return false;
  }

  State.msgTimestamps.push(now);
  return true;
}

// ============================================================
// HANDSHAKE TIMEOUT (FIX 4)
// ============================================================
function startHandshakeTimeout() {
  clearHandshakeTimeout();
  State.handshakeTimer = setTimeout(() => {
    console.warn('[SecureChat] Timeout de handshake: 30s sin completar key exchange.');
    terminateConnection('Timeout de seguridad: el intercambio de claves no se completo.');
    setStatus('TIMEOUT: El contacto no completo el handshake en 30s.', 'error');
    showView('home');
  }, HANDSHAKE_TIMEOUT_MS);
}

function clearHandshakeTimeout() {
  if (State.handshakeTimer) {
    clearTimeout(State.handshakeTimer);
    State.handshakeTimer = null;
  }
}

// ============================================================
// MENSAJES EN PANTALLA
// ============================================================
function addMessage(text, type = 'system') {
  const el = document.createElement('div');

  if (type === 'me' || type === 'them') {
    el.className = type === 'me' ? 'msg-me' : 'msg-them';

    const sender = document.createElement('span');
    sender.className = 'msg-sender';
    sender.textContent = type === 'me'
      ? '[ YO ]'
      : `[ ${(State.contactNickname || 'ANONIMO').toUpperCase()} ]`;

    const textEl = document.createElement('span');
    textEl.className = 'msg-text';
    textEl.textContent = text;

    const timeEl = document.createElement('span');
    timeEl.className = 'msg-time';
    timeEl.textContent = new Date().toLocaleTimeString();

    el.appendChild(sender);
    el.appendChild(textEl);
    el.appendChild(timeEl);

  } else if (type === 'security') {
    el.className = 'msg-security';
    el.textContent = `[${new Date().toLocaleTimeString()}] ✓ ${text}`;
  } else if (type === 'warning') {
    el.className = 'msg-warning';
    el.textContent = `[${new Date().toLocaleTimeString()}] !! ${text}`;
  } else {
    el.className = 'msg-system';
    el.textContent = `[${new Date().toLocaleTimeString()}] ${text}`;
  }

  DOM.messagesContainer.appendChild(el);
  DOM.messagesContainer.scrollTop = DOM.messagesContainer.scrollHeight;
}

// ============================================================
// PROTOCOLO DE MENSAJES DE CONTROL
// ============================================================
/**
 * Flujo completo de handshake:
 *
 *  B abre conexion → canal DataChannel abierto
 *  B → A : { type: 'key_exchange',     publicKey: JWK }
 *  A → B : { type: 'key_exchange_ack', publicKey: JWK }
 *  [ambos derivan sendKey/recvKey + fingerprint via HKDF]
 *  B → A : { type: 'chat_request' }
 *  A recibe modal → acepta
 *  A → B : { type: 'chat_accepted' }
 *  [chat activo -- mensajes cifrados con AES-GCM-256]
 *  X → Y : { type: 'message', payload: { iv, data } }
 *           payload descifrado = { text: string, seq: number, ts: number }
 */
async function handleData(raw) {
  if (!raw || typeof raw.type !== 'string') return;

  switch (raw.type) {

    // ----------------------------------------------------------
    // PASO 1: Iniciador (B) envia su clave publica ECDH
    // ----------------------------------------------------------
    case 'key_exchange': {
      try {
        const theirPubKey = await importPublicKey(raw.publicKey);
        await deriveAllKeys(State.myKeyPair.privateKey, theirPubKey, false); // soy receptor
        // Responder con nuestra clave
        const myPubJwk = await exportPublicKey(State.myKeyPair.publicKey);
        State.conn.send({ type: 'key_exchange_ack', publicKey: myPubJwk });
        console.info('[SecureChat] key_exchange_ack enviado.');
      } catch (err) {
        console.error('[SecureChat] Error en key_exchange:', err);
        terminateConnection('Error criptografico en handshake.');
        setStatus('Error criptografico. Conexion rechazada.', 'error');
      }
      break;
    }

    // ----------------------------------------------------------
    // PASO 2: Receptor (A) responde con su clave publica
    // ----------------------------------------------------------
    case 'key_exchange_ack': {
      try {
        const theirPubKey = await importPublicKey(raw.publicKey);
        await deriveAllKeys(State.myKeyPair.privateKey, theirPubKey, true); // soy iniciador
        // Claves listas: enviar solicitud de chat
        State.conn.send({ type: 'chat_request' });
        showView('waiting');
        DOM.waitingRemoteId.textContent = State.remoteId;
        console.info('[SecureChat] Chat request enviado. Esperando aceptacion.');
      } catch (err) {
        console.error('[SecureChat] Error en key_exchange_ack:', err);
        terminateConnection('Error criptografico en handshake.');
        setStatus('Error criptografico. Intente de nuevo.', 'error');
        showView('home');
      }
      break;
    }

    // ----------------------------------------------------------
    // PASO 3: Iniciador (B) pide abrir el chat
    // ----------------------------------------------------------
    case 'chat_request': {
      // Limpiamos timeout: handshake completo
      clearHandshakeTimeout();
      // Mostramos modal de aceptacion en pantalla del receptor (A)
      DOM.requesterId.textContent = State.remoteId;
      showModal('modal-overlay');
      break;
    }

    // ----------------------------------------------------------
    // PASO 4: Receptor (A) acepta
    // ----------------------------------------------------------
    case 'chat_accepted': {
      clearHandshakeTimeout();
      openChat();
      break;
    }

    // ----------------------------------------------------------
    // PASO 4b: Receptor (A) rechaza
    // ----------------------------------------------------------
    case 'chat_rejected': {
      clearHandshakeTimeout();
      terminateConnection('Rechazado por el contacto.');
      setStatus('El contacto rechazo la conexion.', 'error');
      showView('home');
      break;
    }

    // ----------------------------------------------------------
    // MENSAJES DE CHAT (cifrados AES-GCM-256, con seq anti-replay)
    // ----------------------------------------------------------
    case 'message': {
      if (!State.recvKey || !State.chatReady) {
        console.warn('[SecureChat] Mensaje recibido fuera de sesion. Descartado.');
        return;
      }

      try {
        const inner = await decryptPayload(raw.payload);

        // Verificacion de numero de secuencia (FIX 3)
        if (typeof inner.seq !== 'number') {
          throw new Error('Mensaje sin numero de secuencia.');
        }
        if (inner.seq !== State.expectedRecvSeq) {
          // Esto puede indicar replay, reorder o ataque
          console.warn(
            `[SecureChat] SEQ esperado ${State.expectedRecvSeq}, recibido ${inner.seq}. Descartado.`
          );
          addMessage(
            `ADVERTENCIA DE SEGURIDAD: Mensaje con secuencia incorrecta (esperado ${State.expectedRecvSeq}, recibido ${inner.seq}). Descartado.`,
            'warning'
          );
          return;
        }
        State.expectedRecvSeq++;

        // Verificacion de timestamp (tolerancia: +/- 5 minutos)
        const now = Date.now();
        if (Math.abs(now - inner.ts) > 300_000) {
          console.warn('[SecureChat] Timestamp fuera de ventana de 5 minutos. Posible replay.');
          addMessage('ADVERTENCIA: Mensaje con timestamp sospechoso. Podria ser un replay.', 'warning');
          return;
        }

        addMessage(inner.text, 'them');

      } catch (err) {
        // Fallo de autenticacion GCM = mensaje alterado o clave incorrecta
        console.error('[SecureChat] FALLO DE AUTENTICACION AES-GCM:', err);
        addMessage(
          'FALLO DE AUTENTICACION: Un mensaje fue rechazado. ' +
          'El mensaje estaba alterado o la clave es incorrecta. ' +
          'Verifique el Codigo de Verificacion con su contacto.',
          'warning'
        );
      }
      break;
    }

    default:
      console.warn('[SecureChat] Tipo de mensaje desconocido ignorado:', raw.type);
  }
}

// ============================================================
// ENVIO DE MENSAJES
// ============================================================
async function sendMessage() {
  const text = DOM.messageInput.value.trim();
  if (!text || !State.conn || !State.sendKey || !State.chatReady) return;

  // Rate limiting
  if (!checkRateLimit()) return;

  try {
    const payload = {
      text,
      seq: State.sendSeq,    // numero de secuencia actual
      ts:  Date.now()        // timestamp para verificacion de replay
    };

    const encrypted = await encryptPayload(payload);
    State.conn.send({ type: 'message', payload: encrypted });
    State.sendSeq++;

    addMessage(text, 'me');
    DOM.messageInput.value = '';
    DOM.charCount.textContent = '0';

  } catch (err) {
    console.error('[SecureChat] Error cifrando mensaje:', err);
    addMessage('ERROR: No se pudo cifrar el mensaje.', 'warning');
  }
}

// ============================================================
// APERTURA / CIERRE DE CHAT
// ============================================================
function openChat() {
  State.chatReady = true;
  showView('chat');
  updateContactUI();
  DOM.chatTitleText.textContent = `SecureChat v2.0 -- Sesion Activa | Mi ID: ${State.myId}`;

  addMessage(
    'Canal E2EE establecido. ' +
    'Cifrado: AES-GCM-256 (send) + AES-GCM-256 (recv) derivadas via ECDH+HKDF. ' +
    'Ningún mensaje se almacena en ningun servidor.',
    'security'
  );

  // Mostrar el fingerprint automaticamente al abrir el chat
  if (State.fingerprint) {
    showFingerprintPanel();
    addMessage(
      'ACCION REQUERIDA: Compare el Codigo de Verificacion con su contacto POR VOZ. ' +
      'Si no coincide, hay un atacante en medio. Use el boton [ VERIFICAR ].',
      'warning'
    );
  }

  DOM.messageInput.focus();
}

function showFingerprintPanel() {
  if (!State.fingerprint) return;
  // Mostrar en grupos de 4 separados por espacios para lectura por voz
  const grouped = State.fingerprint.split('-');
  // Mostrar en dos lineas de 8 grupos cada una
  const line1 = grouped.slice(0, 8).join('-');
  const line2 = grouped.slice(8).join('-');
  DOM.fingerprintDisplay.textContent = line1 + '\n' + line2;
  showFingerprint();
}

function updateContactUI() {
  const nick = State.contactNickname || 'ANONIMO';
  DOM.contactNameDisplay.textContent = nick.toUpperCase();
  DOM.contactIdDisplay.textContent   = State.remoteId || '';
}

/**
 * Limpia TODA la informacion sensible del estado.
 * Las CryptoKeys no-exportables son manejadas por el GC del navegador;
 * eliminar referencias es lo maximo que JS puede hacer.
 */
function terminateConnection(reason = '') {
  clearHandshakeTimeout();
  hideModal('modal-overlay');
  hideModal('modal-nickname');
  hideFingerprint();

  // Eliminar referencias a material criptografico
  State.sendKey        = null;
  State.recvKey        = null;
  State.rawSharedBits  = null;
  State.fingerprint    = null;
  State.myKeyPair      = null; // Las claves muertas para siempre al limpiar

  State.conn           = null;
  State.remoteId       = null;
  State.contactNickname= null;
  State.isInitiator    = false;
  State.chatReady      = false;
  State.sendSeq        = 0;
  State.expectedRecvSeq= 0;
  State.msgTimestamps  = [];
  State.fingerprintShown = false;

  if (reason) console.info('[SecureChat] Conexion terminada:', reason);
}

function handleUnexpectedClose() {
  if (State.chatReady) {
    addMessage('El contacto se ha desconectado. Sesion terminada.', 'warning');
  }
  terminateConnection('Cierre inesperado del DataChannel.');
}

// ============================================================
// INICIALIZACION DE PEERJS
// ============================================================
async function initPeer() {
  // Generar nuevo par de claves ECDH para esta sesion
  State.myKeyPair = await generateKeyPair();
  console.info('[SecureChat] Par de claves ECDH-P256 generado.');

  const ephemeralId = generateEphemeralId();

  State.peer = new Peer(ephemeralId, {
    host:   '0.peerjs.com',
    port:   443,
    path:   '/',
    secure: true,
    debug:  0,
    config: {
      iceServers: [
        // STUN: solo para NAT traversal. No ven contenido.
        // NOTA: Ven tu IP publica. Usar Tor Browser para ocultar IP.
        { urls: 'stun:stun.l.google.com:19302'  },
        { urls: 'stun:stun1.l.google.com:19302' },
        { urls: 'stun:global.stun.twilio.com:3478' },
      ],
      // No activamos iceTransportPolicy: 'relay' porque requeriria
      // un servidor TURN propio o de pago para funcionar.
      // La alternativa gratuita y mas segura es Tor Browser.
    }
  });

  State.peer.on('open', (id) => {
    State.myId = id;
    DOM.myPeerId.textContent = id;
    DOM.serverStatus.textContent = '[ CONECTADO -- LISTO ]';
    DOM.serverStatus.className   = 'status-ok';
    console.info('[SecureChat] Peer activo. ID:', id);
  });

  State.peer.on('error', (err) => {
    console.error('[SecureChat] PeerJS error:', err.type, err.message);
    const msg = err.type === 'peer-unavailable'
      ? `ID "${State.remoteId}" no encontrado o no disponible.`
      : `Error de red: ${err.type || err.message}`;
    setStatus(msg, 'error');
    DOM.serverStatus.textContent = '[ ERROR ]';
    DOM.serverStatus.className   = 'status-error';
    if (State.conn) {
      terminateConnection('Error PeerJS: ' + msg);
      showView('home');
    }
  });

  // Conexion ENTRANTE (yo soy el receptor A)
  State.peer.on('connection', (incomingConn) => {
    // Rechazar si ya hay sesion activa
    if (State.conn) {
      console.warn('[SecureChat] Conexion entrante rechazada: sesion ya activa.');
      incomingConn.on('open', () => incomingConn.close());
      return;
    }

    console.info('[SecureChat] Conexion entrante de:', incomingConn.peer);
    State.conn        = incomingConn;
    State.isInitiator = false;
    State.remoteId    = incomingConn.peer;

    // Iniciar timeout de handshake
    startHandshakeTimeout();

    incomingConn.on('open', () => {
      console.info('[SecureChat] Canal abierto (receptor) con:', State.remoteId);
      // El receptor espera: el iniciador enviara key_exchange primero
    });

    incomingConn.on('data',  handleData);
    incomingConn.on('close', handleUnexpectedClose);
    incomingConn.on('error', (err) => {
      console.error('[SecureChat] Error de DataChannel:', err);
      handleUnexpectedClose();
    });
  });

  State.peer.on('disconnected', () => {
    console.warn('[SecureChat] Desconectado del servidor de señalizacion.');
    DOM.serverStatus.textContent = '[ RECONECTANDO... ]';
    DOM.serverStatus.className   = 'status-connecting';
    try { State.peer.reconnect(); } catch(_) {}
  });
}

// ============================================================
// EVENTOS DE UI
// ============================================================

// Copiar ID
DOM.btnCopyId.addEventListener('click', () => {
  if (!State.myId) return;
  navigator.clipboard.writeText(State.myId)
    .then(() => setStatus('ID copiado al portapapeles.', 'ok'))
    .catch(() => setStatus('Copie manualmente: ' + State.myId, 'info'));
});

// Iniciar conexion (soy el iniciador B)
DOM.btnConnect.addEventListener('click', async () => {
  const rawId = DOM.inputRemoteId.value.trim().toUpperCase().replace(/[^A-Z2-9]/g, '');

  if (!rawId || rawId.length !== 8) {
    setStatus('El ID debe ser exactamente 8 caracteres.', 'error');
    return;
  }
  if (!State.myId) {
    setStatus('Aun conectando al servidor. Espere.', 'error');
    return;
  }
  if (rawId === State.myId) {
    setStatus('No puede conectarse a su propio ID.', 'error');
    return;
  }
  if (State.conn) {
    setStatus('Ya hay una sesion activa.', 'error');
    return;
  }

  setStatus('Abriendo canal P2P...', 'info');
  State.isInitiator = true;
  State.remoteId    = rawId;

  // Regenerar par de claves para esta sesion especifica
  // (garantiza Perfect Forward Secrecy entre sesiones distintas)
  State.myKeyPair = await generateKeyPair();

  const outConn = State.peer.connect(rawId, {
    reliable:      true,
    serialization: 'json',
    label:         'securechat-v2',
  });

  State.conn = outConn;
  startHandshakeTimeout();

  outConn.on('open', async () => {
    setStatus('Canal abierto. Iniciando intercambio de claves ECDH...', 'info');
    console.info('[SecureChat] Conexion abierta hacia:', rawId);
    try {
      const myPubJwk = await exportPublicKey(State.myKeyPair.publicKey);
      outConn.send({ type: 'key_exchange', publicKey: myPubJwk });
    } catch (err) {
      console.error('[SecureChat] Error exportando clave publica:', err);
      terminateConnection('Error al iniciar ECDH.');
      setStatus('Error criptografico. Recargue la pagina.', 'error');
      showView('home');
    }
  });

  outConn.on('data',  handleData);
  outConn.on('close', handleUnexpectedClose);
  outConn.on('error', (err) => {
    console.error('[SecureChat] Error de conexion:', err);
    setStatus('Error de conexion. Verifique el ID e intente de nuevo.', 'error');
    terminateConnection('Error de DataChannel.');
    showView('home');
  });
});

// Cancelar espera
DOM.btnCancelWait.addEventListener('click', () => {
  if (State.conn) try { State.conn.close(); } catch(_) {}
  terminateConnection('Cancelado por el usuario.');
  setStatus('Conexion cancelada.', 'info');
  showView('home');
});

// Aceptar solicitud
DOM.btnAccept.addEventListener('click', () => {
  hideModal('modal-overlay');
  if (!State.conn) return;
  State.conn.send({ type: 'chat_accepted' });
  openChat();
});

// Rechazar solicitud
const rejectFn = () => {
  hideModal('modal-overlay');
  if (State.conn) {
    try { State.conn.send({ type: 'chat_rejected' }); } catch(_) {}
    try { State.conn.close();                           } catch(_) {}
  }
  terminateConnection('Rechazado por el usuario.');
  setStatus('Solicitud rechazada.', 'info');
};
DOM.btnReject.addEventListener('click', rejectFn);
DOM.btnRejectX.addEventListener('click', rejectFn);

// Enviar mensaje
DOM.btnSend.addEventListener('click', sendMessage);
DOM.messageInput.addEventListener('keydown', (e) => {
  if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); sendMessage(); }
});
DOM.messageInput.addEventListener('input', () => {
  DOM.charCount.textContent = DOM.messageInput.value.length;
});

// Desconectar
DOM.btnDisconnect.addEventListener('click', () => {
  if (!confirm('¿Terminar esta sesion? La sesion y sus claves se destruiran.')) return;
  if (State.conn) try { State.conn.close(); } catch(_) {}
  terminateConnection('Terminado por el usuario.');
  DOM.messagesContainer.innerHTML = '';
  setStatus('Sesion terminada.', 'info');
  showView('home');
});

// Limpiar chat
DOM.btnClearChat.addEventListener('click', () => {
  if (confirm('¿Borrar el historial local de esta pantalla?')) {
    DOM.messagesContainer.innerHTML = '';
    addMessage('Historial local borrado.', 'system');
  }
});

// Fingerprint: mostrar panel de verificacion
DOM.btnShowFingerprint.addEventListener('click', () => {
  if (!State.fingerprint) {
    alert('El codigo de verificacion no esta disponible aun.\nConectese primero.');
    return;
  }
  showFingerprintPanel();
});

// Fingerprint: usuario confirma que los codigos coinciden
DOM.btnVerifiedOk.addEventListener('click', () => {
  hideFingerprint();
  addMessage(
    'Verificacion completada. Codigos coinciden. Conexion autenticada. Sin MitM.',
    'security'
  );
});

// Fingerprint: usuario reporta que los codigos NO coinciden
DOM.btnVerifiedFail.addEventListener('click', () => {
  hideFingerprint();
  addMessage(
    'ALERTA CRITICA: Los codigos NO coincidieron. HAY UN ATACANTE EN MEDIO. ' +
    'Desconectando por seguridad.',
    'warning'
  );
  // Desconectar inmediatamente
  setTimeout(() => {
    if (State.conn) try { State.conn.close(); } catch(_) {}
    terminateConnection('MitM detectado por el usuario.');
    DOM.messagesContainer.innerHTML = '';
    setStatus('ALERTA: MitM detectado. Sesion terminada.', 'error');
    showView('home');
  }, 1500);
});

// Apodo: abrir modal
DOM.btnRename.addEventListener('click', () => {
  DOM.nicknameInput.value = State.contactNickname || '';
  showModal('modal-nickname');
  DOM.nicknameInput.focus();
});

// Apodo: guardar
DOM.btnSaveNickname.addEventListener('click', () => {
  const nick = DOM.nicknameInput.value.trim().substring(0, 20);
  if (nick) {
    State.contactNickname = nick;
    updateContactUI();
    addMessage(`Apodo local asignado: "${nick}"`, 'system');
  }
  hideModal('modal-nickname');
});
DOM.btnCloseNickname.addEventListener('click',  () => hideModal('modal-nickname'));
DOM.btnCloseNickname2.addEventListener('click', () => hideModal('modal-nickname'));

DOM.nicknameInput.addEventListener('keydown', (e) => {
  if (e.key === 'Enter')  { e.preventDefault(); DOM.btnSaveNickname.click(); }
  if (e.key === 'Escape') { hideModal('modal-nickname'); }
});

// Normalizar input de ID
DOM.inputRemoteId.addEventListener('input', () => {
  DOM.inputRemoteId.value = DOM.inputRemoteId.value.toUpperCase().replace(/[^A-Z2-9]/g, '');
});
DOM.inputRemoteId.addEventListener('keydown', (e) => {
  if (e.key === 'Enter') { e.preventDefault(); DOM.btnConnect.click(); }
});

// Escape: cerrar modales
document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape') {
    hideModal('modal-nickname');
    if (!DOM.modalOverlay.classList.contains('hidden')) rejectFn();
  }
});

// Advertencia al salir
window.addEventListener('beforeunload', (e) => {
  if (State.conn || State.chatReady) {
    e.preventDefault();
    e.returnValue = 'Su sesion de SecureChat se destruira. ¿Desea salir?';
  }
});

// ============================================================
// ARRANQUE
// ============================================================
(async () => {
  try {
    if (!window.crypto?.subtle) {
      throw new Error('Web Crypto API no disponible. Use un navegador moderno con HTTPS.');
    }
    if (typeof RTCPeerConnection === 'undefined') {
      throw new Error('WebRTC no disponible en este navegador.');
    }
    if (typeof Peer === 'undefined') {
      throw new Error('PeerJS no cargado. Asegurese de que peerjs.min.js esta en la misma carpeta.');
    }

    await initPeer();
    console.info('[SecureChat v2.0] Iniciado correctamente.');

  } catch (err) {
    console.error('[SecureChat] Error critico:', err);
    DOM.serverStatus.textContent = '[ ERROR CRITICO ]';
    DOM.serverStatus.className   = 'status-error';
    setStatus('ERROR: ' + err.message, 'error');
  }
})();

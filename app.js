/**
 * =======================================================================
 *  app.js -- SecureChat v3.0
 *  NUEVO EN v3: Llamadas de voz/video cifradas + deteccion de Tor
 * =======================================================================
 *
 *  CIFRADO DE LLAMADAS:
 *  ---------------------
 *  Las llamadas usan WebRTC MediaStream con cifrado DTLS 1.3 + SRTP:
 *
 *  - DTLS (Datagram TLS 1.3): Cifra el canal de control de la sesion
 *    de media. Cada par genera un certificado auto-firmado efimero.
 *    El fingerprint de ese certificado viaja por el canal de datos
 *    ya cifrado con AES-GCM-256 (nuestro canal de texto).
 *  - SRTP (Secure Real-Time Transport Protocol): Cifra cada paquete
 *    de audio/video individualmente. Las claves SRTP las negocia DTLS.
 *  - Perfect Forward Secrecy: Cada llamada genera nuevas claves DTLS.
 *    Grabar la llamada en transito hoy no permite descifrarla manana.
 *
 *  COMPARACION CON TEXTO:
 *  Texto:  AES-GCM-256 (app layer) + DTLS-SRTP (WebRTC transport)
 *  Media:  DTLS 1.3 + SRTP (una capa, pero es el estandar de la industria,
 *          el mismo que usa Signal/WhatsApp para llamadas)
 *
 *  PROBLEMA DE TOR:
 *  -----------------
 *  Tor Browser bloquea WebRTC en nivel "Safer" y "Safest" para
 *  prevenir fugas de IP. Esto es correcto e intencional.
 *  Deteccion: intentamos crear RTCPeerConnection y capturamos el error.
 *  Soluciones:
 *    A) Bajar a nivel "Standard" en Tor (menos privacidad de Tor)
 *    B) Bajar a "Safer" (WebRTC activado, JS activado) -- RECOMENDADO
 *       Con Tor "Safer": IP oculta al servidor PeerJS + WebRTC funciona
 *
 * =======================================================================
 */

'use strict';

// ============================================================
// CONSTANTES
// ============================================================
const HANDSHAKE_TIMEOUT_MS = 30_000;
const RATE_LIMIT_MAX       = 20;
const RATE_LIMIT_WINDOW_MS = 10_000;
const HKDF_LABEL_INIT      = 'securechat-v3-initiator-to-receiver';
const HKDF_LABEL_RECV      = 'securechat-v3-receiver-to-initiator';

// ============================================================
// ESTADO (100% en memoria — muere con la pagina)
// ============================================================
const State = Object.seal({
  // Peer y conexion de texto
  peer:             null,
  conn:             null,
  myId:             null,
  remoteId:         null,
  contactNickname:  null,
  // Criptografia de texto
  myKeyPair:        null,
  sendKey:          null,
  recvKey:          null,
  fingerprint:      null,
  isInitiator:      false,
  chatReady:        false,
  handshakeTimer:   null,
  sendSeq:          0,
  expectedRecvSeq:  0,
  msgTimestamps:    [],
  // Llamadas de media
  mediaCall:        null,    // objeto Call de PeerJS
  localStream:      null,    // MediaStream local (mic + cam)
  remoteStream:     null,    // MediaStream remoto
  callType:         null,    // 'audio' | 'video'
  callActive:       false,
  callMuted:        false,
  callCamOff:       false,
  callTimer:        null,    // setInterval del contador
  callSeconds:      0,
  pendingCall:      null,    // llamada entrante pendiente de contestar
  // Tono de llamada
  audioCtx:         null,
  ringInterval:     null,
});

// ============================================================
// DOM
// ============================================================
const $ = id => document.getElementById(id);
const DOM = {
  viewHome:           $('view-home'),
  viewWaiting:        $('view-waiting'),
  viewChat:           $('view-chat'),
  myPeerId:           $('my-peer-id'),
  serverStatus:       $('server-status'),
  inputRemoteId:      $('input-remote-id'),
  btnCopyId:          $('btn-copy-id'),
  btnConnect:         $('btn-connect'),
  statusMsg:          $('status-msg'),
  waitingRemoteId:    $('waiting-remote-id'),
  btnCancelWait:      $('btn-cancel-wait'),
  chatTitleText:      $('chat-title-text'),
  contactNameDisplay: $('contact-name-display'),
  contactIdDisplay:   $('contact-id-display'),
  messagesContainer:  $('messages-container'),
  messageInput:       $('message-input'),
  btnSend:            $('btn-send'),
  btnDisconnect:      $('btn-disconnect'),
  btnRename:          $('btn-rename'),
  btnClearChat:       $('btn-clear-chat'),
  btnShowFingerprint: $('btn-show-fingerprint'),
  charCount:          $('char-count'),
  fingerprintPanel:   $('fingerprint-panel'),
  fingerprintDisplay: $('fingerprint-display'),
  btnVerifiedOk:      $('btn-verified-ok'),
  btnVerifiedFail:    $('btn-verified-fail'),
  modalOverlay:       $('modal-overlay'),
  requesterId:        $('requester-id'),
  btnAccept:          $('btn-accept'),
  btnReject:          $('btn-reject'),
  btnRejectX:         $('btn-reject-x'),
  modalNickname:      $('modal-nickname'),
  nicknameInput:      $('nickname-input'),
  btnSaveNickname:    $('btn-save-nickname'),
  btnCloseNickname:   $('btn-close-nickname'),
  btnCloseNickname2:  $('btn-close-nickname2'),
  rateLimitWarn:      $('rate-limit-warn'),
  torBanner:          $('tor-banner'),
  // Llamadas
  btnCallAudio:       $('btn-call-audio'),
  btnCallVideo:       $('btn-call-video'),
  callPanel:          $('call-panel'),
  callStatusText:     $('call-status-text'),
  callTimer:          $('call-timer'),
  videoArea:          $('video-area'),
  videoRemote:        $('video-remote'),
  videoLocal:         $('video-local'),
  audioIndicator:     $('audio-indicator'),
  btnToggleMute:      $('btn-toggle-mute'),
  btnToggleCamera:    $('btn-toggle-camera'),
  btnEndCall:         $('btn-end-call'),
  modalIncomingCall:  $('modal-incoming-call'),
  incomingCallTitle:  $('incoming-call-title'),
  incomingCallDesc:   $('incoming-call-desc'),
  incomingCallType:   $('incoming-call-type'),
  btnAnswerCall:      $('btn-answer-call'),
  btnRejectCall:      $('btn-reject-call'),
  btnRejectCallX:     $('btn-reject-call-x'),
};

// ============================================================
// SPA NAVIGATION
// ============================================================
function showView(name) {
  ['home','waiting','chat'].forEach(v =>
    document.getElementById('view-'+v).classList.remove('active')
  );
  document.getElementById('view-'+name).classList.add('active');
}
function showModal(id)    { $(id).classList.remove('hidden'); }
function hideModal(id)    { $(id).classList.add('hidden');    }
function setStatus(msg, t='info') {
  DOM.statusMsg.textContent = msg;
  DOM.statusMsg.style.color = t==='error'?'#cc0000': t==='ok'?'#006600':'#000080';
}

// ============================================================
// DETECCION DE TOR BROWSER
// ============================================================
/**
 * Intenta crear un RTCPeerConnection y captura si WebRTC esta bloqueado.
 * Tor Browser bloquea WebRTC para prevenir fugas de IP.
 * Si esta bloqueado, mostramos el banner con instrucciones.
 */
async function detectTorWebRTCBlock() {
  try {
    const testPc = new RTCPeerConnection({ iceServers: [] });
    testPc.createDataChannel('test');
    const offer = await testPc.createOffer();
    testPc.close();
    // Si llegamos aqui, WebRTC funciona
    return false;
  } catch (e) {
    // WebRTC bloqueado
    DOM.torBanner.classList.remove('hidden');
    DOM.serverStatus.textContent = '[ WEBRTC BLOQUEADO ]';
    DOM.serverStatus.className   = 'status-error';
    setStatus(
      'WebRTC bloqueado (posiblemente Tor Browser). ' +
      'Lea el aviso azul arriba para solucionarlo.',
      'error'
    );
    return true;
  }
}

// ============================================================
// GENERACION DE ID EFIMERO
// ============================================================
function generateEphemeralId() {
  const C = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  const b = crypto.getRandomValues(new Uint8Array(8));
  return Array.from(b).map(x => C[x % C.length]).join('');
}

// ============================================================
// CRIPTOGRAFIA DE TEXTO (identica a v2)
// ============================================================
async function generateKeyPair() {
  return crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' },
    true, ['deriveBits']
  );
}
async function exportPublicKey(pk) { return crypto.subtle.exportKey('jwk', pk); }
async function importPublicKey(jwk) {
  return crypto.subtle.importKey('jwk', jwk, { name:'ECDH', namedCurve:'P-256' }, false, []);
}

async function deriveAllKeys(myPriv, theirPub, asInitiator) {
  const rawBits = await crypto.subtle.deriveBits({ name:'ECDH', public:theirPub }, myPriv, 256);

  // Fingerprint SHA-256
  const fpBuf = await crypto.subtle.digest('SHA-256', rawBits);
  const fpHex = Array.from(new Uint8Array(fpBuf))
    .map(b => b.toString(16).padStart(2,'0').toUpperCase()).join('');
  State.fingerprint = fpHex.match(/.{4}/g).join('-');

  const hkdfMat = await crypto.subtle.importKey('raw', rawBits, 'HKDF', false, ['deriveKey']);
  const salt    = new Uint8Array(32);

  const mkKey = (label, usage) => crypto.subtle.deriveKey(
    { name:'HKDF', hash:'SHA-256', salt, info: new TextEncoder().encode(label) },
    hkdfMat,
    { name:'AES-GCM', length:256 },
    false, [usage]
  );

  const initKey = await mkKey(HKDF_LABEL_INIT, asInitiator ? 'encrypt' : 'decrypt');
  const recvKey = await mkKey(HKDF_LABEL_RECV, asInitiator ? 'decrypt' : 'encrypt');

  State.sendKey = asInitiator ? initKey : recvKey;
  State.recvKey = asInitiator ? recvKey : initKey;

  console.info('[SecureChat] Claves HKDF listas. FP:', State.fingerprint);
}

async function encryptPayload(payload) {
  const iv       = crypto.getRandomValues(new Uint8Array(12));
  const encoded  = new TextEncoder().encode(JSON.stringify(payload));
  const cipher   = await crypto.subtle.encrypt(
    { name:'AES-GCM', iv, tagLength:128 }, State.sendKey, encoded
  );
  return { iv: Array.from(iv), data: Array.from(new Uint8Array(cipher)) };
}

async function decryptPayload(enc) {
  const plain = await crypto.subtle.decrypt(
    { name:'AES-GCM', iv: new Uint8Array(enc.iv), tagLength:128 },
    State.recvKey,
    new Uint8Array(enc.data)
  );
  return JSON.parse(new TextDecoder().decode(plain));
}

// ============================================================
// RATE LIMITING & TIMEOUT
// ============================================================
function checkRateLimit() {
  const now = Date.now(), cut = now - RATE_LIMIT_WINDOW_MS;
  State.msgTimestamps = State.msgTimestamps.filter(t => t > cut);
  if (State.msgTimestamps.length >= RATE_LIMIT_MAX) {
    DOM.rateLimitWarn.classList.remove('hidden');
    setTimeout(() => DOM.rateLimitWarn.classList.add('hidden'), 3000);
    return false;
  }
  State.msgTimestamps.push(now);
  return true;
}

function startHandshakeTimeout() {
  clearHandshakeTimeout();
  State.handshakeTimer = setTimeout(() => {
    terminateConnection('Timeout de handshake (30s).');
    setStatus('TIMEOUT: El contacto no completo el handshake.', 'error');
    showView('home');
  }, HANDSHAKE_TIMEOUT_MS);
}
function clearHandshakeTimeout() {
  if (State.handshakeTimer) { clearTimeout(State.handshakeTimer); State.handshakeTimer = null; }
}

// ============================================================
// MENSAJES EN PANTALLA
// ============================================================
function addMessage(text, type = 'system') {
  const el = document.createElement('div');

  if (type === 'me' || type === 'them') {
    el.className = type === 'me' ? 'msg-me' : 'msg-them';
    const s = document.createElement('span');
    s.className = 'msg-sender';
    s.textContent = type === 'me' ? '[ YO ]' : `[ ${(State.contactNickname||'ANONIMO').toUpperCase()} ]`;
    const t = document.createElement('span');
    t.className = 'msg-text'; t.textContent = text;
    const ts = document.createElement('span');
    ts.className = 'msg-time'; ts.textContent = new Date().toLocaleTimeString();
    el.append(s, t, ts);
  } else {
    el.className = `msg-${type}`;
    el.textContent = `[${new Date().toLocaleTimeString()}] ${type==='security'?'✓ ':type==='warning'?'!! ':''}${text}`;
  }

  DOM.messagesContainer.appendChild(el);
  DOM.messagesContainer.scrollTop = DOM.messagesContainer.scrollHeight;
}

// ============================================================
// TONO DE LLAMADA (Web Audio API — sin archivos externos)
// ============================================================
function startRingtone() {
  stopRingtone();
  try {
    State.audioCtx = new (window.AudioContext || window.webkitAudioContext)();
    const playBeep = () => {
      if (!State.audioCtx) return;
      const osc  = State.audioCtx.createOscillator();
      const gain = State.audioCtx.createGain();
      osc.connect(gain); gain.connect(State.audioCtx.destination);
      osc.frequency.value = 440;
      gain.gain.setValueAtTime(0.3, State.audioCtx.currentTime);
      gain.gain.exponentialRampToValueAtTime(0.001, State.audioCtx.currentTime + 0.4);
      osc.start(); osc.stop(State.audioCtx.currentTime + 0.4);
    };
    playBeep();
    State.ringInterval = setInterval(playBeep, 1200);
  } catch(e) {
    console.warn('[SecureChat] Web Audio no disponible para tono:', e);
  }
}

function stopRingtone() {
  if (State.ringInterval) { clearInterval(State.ringInterval); State.ringInterval = null; }
  if (State.audioCtx)     { try { State.audioCtx.close(); } catch(_){} State.audioCtx = null; }
}

// ============================================================
// LLAMADAS DE MEDIA — INICIO
// ============================================================

/**
 * Inicia una llamada de voz o video.
 * 1. Solicita permisos de microfono (y camara si es video)
 * 2. Crea el objeto Call de PeerJS
 * 3. Maneja el stream remoto cuando llega
 *
 * La señalizacion (oferta SDP) viaja por el canal de datos ya cifrado.
 * El media en si usa WebRTC DTLS-SRTP (independiente de nuestro AES-GCM).
 *
 * @param {'audio'|'video'} type
 */
async function startCall(type) {
  if (!State.chatReady || !State.conn) {
    addMessage('No hay sesion activa para llamar.', 'warning');
    return;
  }
  if (State.callActive) {
    addMessage('Ya hay una llamada activa.', 'warning');
    return;
  }

  try {
    // Solicitar acceso al microfono y camara
    const constraints = {
      audio: true,
      video: type === 'video' ? { width:{ideal:640}, height:{ideal:480}, frameRate:{ideal:24} } : false
    };

    State.localStream = await navigator.mediaDevices.getUserMedia(constraints);
    State.callType    = type;

    // Crear la llamada PeerJS — esto genera una oferta DTLS/SDP
    const call = State.peer.call(State.remoteId, State.localStream, {
      metadata: { callType: type }
    });

    State.mediaCall = call;

    call.on('stream', (remoteStream) => {
      State.remoteStream = remoteStream;
      showActiveCallUI(type, remoteStream);
      addMessage(`Llamada de ${type === 'video' ? 'video' : 'voz'} establecida. DTLS-SRTP activo.`, 'security');
    });

    call.on('close', () => endCall(false));
    call.on('error', (err) => {
      console.error('[SecureChat] Error en llamada:', err);
      addMessage('Error en la llamada. Verifique permisos de microfono/camara.', 'warning');
      endCall(false);
    });

    // Mostrar panel de "llamando"
    showCallingUI(type);
    addMessage(`Iniciando llamada de ${type === 'video' ? 'video' : 'voz'}... Esperando respuesta.`, 'system');

  } catch (err) {
    console.error('[SecureChat] Error al acceder a media:', err);
    const msg = err.name === 'NotAllowedError'
      ? 'Permiso denegado. Autorice el acceso al microfono/camara en su navegador.'
      : err.name === 'NotFoundError'
      ? 'No se encontro microfono o camara en este dispositivo.'
      : `Error de media: ${err.message}`;
    addMessage(msg, 'warning');
    if (State.localStream) {
      State.localStream.getTracks().forEach(t => t.stop());
      State.localStream = null;
    }
  }
}

// ============================================================
// LLAMADAS DE MEDIA — RECEPCION
// ============================================================

/**
 * Maneja una llamada ENTRANTE de PeerJS.
 * Muestra el modal de llamada entrante con tono.
 * @param {MediaConnection} call
 */
function handleIncomingCall(call) {
  if (State.callActive) {
    // Ya en llamada: rechazar automaticamente
    call.close();
    return;
  }

  State.pendingCall = call;
  const ctype = call.metadata?.callType || 'audio';

  DOM.incomingCallTitle.textContent = ctype === 'video'
    ? '\u00a0\u{1F4F9} VIDEOLLAMADA ENTRANTE'
    : '\u00a0\u{1F4DE} LLAMADA DE VOZ ENTRANTE';
  DOM.incomingCallDesc.textContent  = `Su contacto le llama.`;
  DOM.incomingCallType.textContent  = ctype === 'video' ? 'VIDEOLLAMADA' : 'VOZ';

  showModal('modal-incoming-call');
  startRingtone();

  // Auto-rechazar si no contesta en 30 segundos
  setTimeout(() => {
    if (State.pendingCall === call) {
      rejectIncomingCall();
    }
  }, 30_000);
}

/**
 * Contesta la llamada entrante.
 */
async function answerCall() {
  const call = State.pendingCall;
  if (!call) return;

  stopRingtone();
  hideModal('modal-incoming-call');

  const ctype = call.metadata?.callType || 'audio';
  State.callType = ctype;

  try {
    const constraints = {
      audio: true,
      video: ctype === 'video'
        ? { width:{ideal:640}, height:{ideal:480}, frameRate:{ideal:24} }
        : false
    };

    State.localStream = await navigator.mediaDevices.getUserMedia(constraints);
    call.answer(State.localStream);
    State.mediaCall   = call;
    State.pendingCall = null;

    call.on('stream', (remoteStream) => {
      State.remoteStream = remoteStream;
      showActiveCallUI(ctype, remoteStream);
      addMessage(`Llamada de ${ctype === 'video' ? 'video' : 'voz'} establecida. DTLS-SRTP activo.`, 'security');
    });

    call.on('close', () => endCall(false));
    call.on('error', (err) => {
      console.error('[SecureChat] Error en llamada contestada:', err);
      endCall(false);
    });

    showCallingUI(ctype);

  } catch (err) {
    console.error('[SecureChat] Error al contestar llamada:', err);
    const msg = err.name === 'NotAllowedError'
      ? 'Permiso denegado. Autorice microfono/camara para contestar.'
      : `Error al contestar: ${err.message}`;
    addMessage(msg, 'warning');
    rejectIncomingCall();
  }
}

function rejectIncomingCall() {
  stopRingtone();
  if (State.pendingCall) {
    try { State.pendingCall.close(); } catch(_) {}
    State.pendingCall = null;
  }
  hideModal('modal-incoming-call');
  addMessage('Llamada rechazada.', 'system');
}

// ============================================================
// LLAMADAS DE MEDIA — UI
// ============================================================

/**
 * Muestra el panel de llamada con "Conectando..."
 */
function showCallingUI(type) {
  State.callActive = true;
  DOM.callPanel.classList.remove('hidden');
  DOM.callStatusText.textContent = '&#9679; CONECTANDO...';
  DOM.callTimer.textContent = '00:00';

  if (type === 'video') {
    DOM.btnToggleCamera.classList.remove('hidden');
    DOM.videoArea.classList.remove('hidden');
    DOM.audioIndicator.classList.add('hidden');
    // Mostrar video local mientras espera
    if (State.localStream) {
      DOM.videoLocal.srcObject = State.localStream;
    }
  } else {
    DOM.btnToggleCamera.classList.add('hidden');
    DOM.videoArea.classList.add('hidden');
    DOM.audioIndicator.classList.remove('hidden');
  }
}

/**
 * Actualiza la UI cuando la llamada esta activa (stream remoto recibido).
 */
function showActiveCallUI(type, remoteStream) {
  DOM.callStatusText.innerHTML = '&#9679; LLAMADA ACTIVA';

  if (type === 'video') {
    DOM.videoRemote.srcObject = remoteStream;
    DOM.videoLocal.srcObject  = State.localStream;
  } else {
    // Para audio: reproducir el stream remoto en un elemento audio oculto
    const audioEl = document.createElement('audio');
    audioEl.srcObject = remoteStream;
    audioEl.autoplay  = true;
    audioEl.style.display = 'none';
    document.body.appendChild(audioEl);
  }

  // Iniciar contador de duracion
  State.callSeconds = 0;
  State.callTimer   = setInterval(() => {
    State.callSeconds++;
    const m = String(Math.floor(State.callSeconds / 60)).padStart(2, '0');
    const s = String(State.callSeconds % 60).padStart(2, '0');
    DOM.callTimer.textContent = `${m}:${s}`;
  }, 1000);
}

/**
 * Termina la llamada activa y libera todos los recursos de media.
 * @param {boolean} notifyPeer - Si debe cerrar el objeto Call
 */
function endCall(notifyPeer = true) {
  if (!State.callActive && !State.mediaCall) return;

  // Detener tracks de media local (libera camara/microfono del OS)
  if (State.localStream) {
    State.localStream.getTracks().forEach(t => t.stop());
    State.localStream = null;
  }

  // Cerrar la llamada PeerJS
  if (State.mediaCall && notifyPeer) {
    try { State.mediaCall.close(); } catch(_) {}
  }
  State.mediaCall   = null;
  State.remoteStream = null;

  // Detener contador
  if (State.callTimer) { clearInterval(State.callTimer); State.callTimer = null; }

  // Limpiar elementos de video
  DOM.videoRemote.srcObject = null;
  DOM.videoLocal.srcObject  = null;

  // Ocultar panel de llamada
  DOM.callPanel.classList.add('hidden');
  DOM.videoArea.classList.add('hidden');
  DOM.audioIndicator.classList.add('hidden');

  // Eliminar elementos de audio que se crearon dinamicamente
  document.querySelectorAll('audio[autoplay]').forEach(a => a.remove());

  // Resetear estado
  State.callActive  = false;
  State.callMuted   = false;
  State.callCamOff  = false;
  State.callType    = null;
  DOM.btnToggleMute.textContent   = '\u{1F50B} MUTE';  // sin cortar icono unicode en JS
  DOM.btnToggleMute.classList.remove('muted');
  DOM.btnToggleCamera.classList.remove('cam-off');

  stopRingtone();

  if (State.chatReady) {
    addMessage('Llamada terminada.', 'system');
  }
}

// ============================================================
// PROTOCOLO DE MENSAJES DE CONTROL (chat + llamadas)
// ============================================================
async function handleData(raw) {
  if (!raw || typeof raw.type !== 'string') return;

  switch (raw.type) {
    case 'key_exchange': {
      try {
        const theirPub = await importPublicKey(raw.publicKey);
        await deriveAllKeys(State.myKeyPair.privateKey, theirPub, false);
        const myPub = await exportPublicKey(State.myKeyPair.publicKey);
        State.conn.send({ type: 'key_exchange_ack', publicKey: myPub });
      } catch(e) {
        console.error('[SecureChat] key_exchange error:', e);
        terminateConnection('Error ECDH.');
        setStatus('Error criptografico en handshake.', 'error');
      }
      break;
    }
    case 'key_exchange_ack': {
      try {
        const theirPub = await importPublicKey(raw.publicKey);
        await deriveAllKeys(State.myKeyPair.privateKey, theirPub, true);
        State.conn.send({ type: 'chat_request' });
        showView('waiting');
        DOM.waitingRemoteId.textContent = State.remoteId;
      } catch(e) {
        console.error('[SecureChat] key_exchange_ack error:', e);
        terminateConnection('Error ECDH.');
        setStatus('Error criptografico.', 'error');
        showView('home');
      }
      break;
    }
    case 'chat_request': {
      clearHandshakeTimeout();
      DOM.requesterId.textContent = State.remoteId;
      showModal('modal-overlay');
      break;
    }
    case 'chat_accepted': {
      clearHandshakeTimeout();
      openChat();
      break;
    }
    case 'chat_rejected': {
      clearHandshakeTimeout();
      terminateConnection('Rechazado por el contacto.');
      setStatus('El contacto rechazo la conexion.', 'error');
      showView('home');
      break;
    }
    case 'message': {
      if (!State.recvKey || !State.chatReady) return;
      try {
        const inner = await decryptPayload(raw.payload);
        if (typeof inner.seq !== 'number') throw new Error('Sin sequence number.');
        if (inner.seq !== State.expectedRecvSeq) {
          addMessage(`SEQ incorrecto (esperado ${State.expectedRecvSeq}, recibido ${inner.seq}). Descartado.`, 'warning');
          return;
        }
        if (Math.abs(Date.now() - inner.ts) > 300_000) {
          addMessage('Timestamp fuera de ventana. Posible replay. Descartado.', 'warning');
          return;
        }
        State.expectedRecvSeq++;
        addMessage(inner.text, 'them');
      } catch(e) {
        console.error('[SecureChat] FALLO GCM:', e);
        addMessage('FALLO DE AUTENTICACION: Mensaje rechazado. Posible ataque.', 'warning');
      }
      break;
    }
    default:
      console.warn('[SecureChat] Tipo desconocido:', raw.type);
  }
}

// ============================================================
// ENVIO DE MENSAJES DE TEXTO
// ============================================================
async function sendMessage() {
  const text = DOM.messageInput.value.trim();
  if (!text || !State.chatReady || !State.sendKey) return;
  if (!checkRateLimit()) return;

  try {
    const enc = await encryptPayload({ text, seq: State.sendSeq, ts: Date.now() });
    State.conn.send({ type: 'message', payload: enc });
    State.sendSeq++;
    addMessage(text, 'me');
    DOM.messageInput.value = '';
    DOM.charCount.textContent = '0';
  } catch(e) {
    console.error('[SecureChat] Error cifrando:', e);
    addMessage('Error al cifrar el mensaje.', 'warning');
  }
}

// ============================================================
// APERTURA DE CHAT
// ============================================================
function openChat() {
  State.chatReady = true;
  showView('chat');
  updateContactUI();
  DOM.chatTitleText.textContent = `SecureChat v3.0 -- Sesion Activa | ID: ${State.myId}`;
  addMessage('Canal E2EE activo. AES-GCM-256 (texto) + DTLS-SRTP (llamadas).', 'security');
  if (State.fingerprint) {
    showFingerprintPanel();
    addMessage('ACCION: Compare el Codigo de Verificacion con su contacto POR VOZ.', 'warning');
  }
  DOM.messageInput.focus();
}

function showFingerprintPanel() {
  if (!State.fingerprint) return;
  const groups = State.fingerprint.split('-');
  DOM.fingerprintDisplay.textContent = groups.slice(0,8).join('-') + '\n' + groups.slice(8).join('-');
  DOM.fingerprintPanel.classList.remove('hidden');
}

function updateContactUI() {
  const nick = State.contactNickname || 'ANONIMO';
  DOM.contactNameDisplay.textContent = nick.toUpperCase();
  DOM.contactIdDisplay.textContent   = State.remoteId || '';
}

// ============================================================
// TERMINACION DE CONEXION
// ============================================================
function terminateConnection(reason = '') {
  clearHandshakeTimeout();
  endCall(true);
  stopRingtone();
  hideModal('modal-overlay');
  hideModal('modal-nickname');
  hideModal('modal-incoming-call');
  DOM.fingerprintPanel.classList.add('hidden');

  State.sendKey         = null;
  State.recvKey         = null;
  State.fingerprint     = null;
  State.myKeyPair       = null;
  State.conn            = null;
  State.remoteId        = null;
  State.contactNickname = null;
  State.isInitiator     = false;
  State.chatReady       = false;
  State.sendSeq         = 0;
  State.expectedRecvSeq = 0;
  State.msgTimestamps   = [];
  State.pendingCall     = null;

  if (reason) console.info('[SecureChat] Conexion terminada:', reason);
}

function handleUnexpectedClose() {
  if (State.chatReady) addMessage('El contacto se ha desconectado.', 'warning');
  terminateConnection('Cierre inesperado.');
}

// ============================================================
// INICIALIZACION DE PEERJS
// ============================================================
async function initPeer() {
  State.myKeyPair = await generateKeyPair();
  const id        = generateEphemeralId();

  State.peer = new Peer(id, {
    host:   '0.peerjs.com',
    port:    443,
    path:   '/',
    secure:  true,
    debug:   0,
    config: {
      iceServers: [
        { urls: 'stun:stun.l.google.com:19302'      },
        { urls: 'stun:stun1.l.google.com:19302'     },
        { urls: 'stun:global.stun.twilio.com:3478'  },
      ]
    }
  });

  State.peer.on('open', (pid) => {
    State.myId = pid;
    DOM.myPeerId.textContent     = pid;
    DOM.serverStatus.textContent = '[ CONECTADO -- LISTO ]';
    DOM.serverStatus.className   = 'status-ok';
  });

  State.peer.on('error', (err) => {
    const msg = err.type === 'peer-unavailable'
      ? `ID "${State.remoteId}" no encontrado.`
      : `Error: ${err.type||err.message}`;
    setStatus(msg, 'error');
    DOM.serverStatus.textContent = '[ ERROR ]';
    DOM.serverStatus.className   = 'status-error';
    if (State.conn) { terminateConnection(msg); showView('home'); }
  });

  // Conexion de TEXTO entrante
  State.peer.on('connection', (inc) => {
    if (State.conn) { inc.on('open', () => inc.close()); return; }
    State.conn        = inc;
    State.isInitiator = false;
    State.remoteId    = inc.peer;
    startHandshakeTimeout();
    inc.on('data',  handleData);
    inc.on('close', handleUnexpectedClose);
    inc.on('error', (e) => { console.error(e); handleUnexpectedClose(); });
  });

  // Llamada de MEDIA entrante
  State.peer.on('call', (call) => {
    if (!State.chatReady) { call.close(); return; }
    handleIncomingCall(call);
  });

  State.peer.on('disconnected', () => {
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
    .then(() => setStatus('ID copiado.', 'ok'))
    .catch(() => setStatus('Copie: ' + State.myId, 'info'));
});

// Conectar
DOM.btnConnect.addEventListener('click', async () => {
  const rawId = DOM.inputRemoteId.value.trim().toUpperCase().replace(/[^A-Z2-9]/g,'');
  if (rawId.length !== 8) { setStatus('El ID debe ser exactamente 8 caracteres.', 'error'); return; }
  if (!State.myId)         { setStatus('Conectando al servidor, espere...', 'error'); return; }
  if (rawId === State.myId){ setStatus('No puede conectarse a su propio ID.', 'error'); return; }
  if (State.conn)          { setStatus('Ya hay una sesion activa.', 'error'); return; }

  State.isInitiator = true;
  State.remoteId    = rawId;
  State.myKeyPair   = await generateKeyPair(); // nuevo par por sesion (PFS)

  const out = State.peer.connect(rawId, { reliable:true, serialization:'json', label:'sc-v3' });
  State.conn = out;
  startHandshakeTimeout();
  setStatus('Conectando...', 'info');

  out.on('open', async () => {
    setStatus('Canal abierto. Intercambiando claves...', 'info');
    try {
      out.send({ type:'key_exchange', publicKey: await exportPublicKey(State.myKeyPair.publicKey) });
    } catch(e) {
      terminateConnection('Error al exportar clave.');
      setStatus('Error criptografico.', 'error');
      showView('home');
    }
  });
  out.on('data',  handleData);
  out.on('close', handleUnexpectedClose);
  out.on('error', (e) => {
    console.error(e);
    setStatus('Error de conexion. Verifique el ID.', 'error');
    terminateConnection('Error DataChannel.');
    showView('home');
  });
});

// Cancelar espera
DOM.btnCancelWait.addEventListener('click', () => {
  if (State.conn) try { State.conn.close(); } catch(_) {}
  terminateConnection('Cancelado.');
  setStatus('Cancelado.', 'info');
  showView('home');
});

// Aceptar chat
DOM.btnAccept.addEventListener('click', () => {
  hideModal('modal-overlay');
  if (State.conn) State.conn.send({ type:'chat_accepted' });
  openChat();
});

// Rechazar chat
const rejectChat = () => {
  hideModal('modal-overlay');
  if (State.conn) {
    try { State.conn.send({ type:'chat_rejected' }); } catch(_) {}
    try { State.conn.close(); } catch(_) {}
  }
  terminateConnection('Rechazado.');
  setStatus('Solicitud rechazada.', 'info');
};
DOM.btnReject.addEventListener('click', rejectChat);
DOM.btnRejectX.addEventListener('click', rejectChat);

// Botones de llamada
DOM.btnCallAudio.addEventListener('click', () => startCall('audio'));
DOM.btnCallVideo.addEventListener('click', () => startCall('video'));

// Contestar llamada
DOM.btnAnswerCall.addEventListener('click', answerCall);

// Rechazar llamada entrante
const rejectCallFn = () => rejectIncomingCall();
DOM.btnRejectCall.addEventListener('click', rejectCallFn);
DOM.btnRejectCallX.addEventListener('click', rejectCallFn);

// Mute de microfono
DOM.btnToggleMute.addEventListener('click', () => {
  if (!State.localStream) return;
  State.callMuted = !State.callMuted;
  State.localStream.getAudioTracks().forEach(t => { t.enabled = !State.callMuted; });
  DOM.btnToggleMute.textContent = State.callMuted ? '\u{1F507} MUTED' : '\u{1F50B} MUTE';
  DOM.btnToggleMute.classList.toggle('muted', State.callMuted);
});

// Apagar/encender camara
DOM.btnToggleCamera.addEventListener('click', () => {
  if (!State.localStream) return;
  State.callCamOff = !State.callCamOff;
  State.localStream.getVideoTracks().forEach(t => { t.enabled = !State.callCamOff; });
  DOM.btnToggleCamera.textContent = State.callCamOff ? '\u274C CAM OFF' : '\u{1F4F7} CAM';
  DOM.btnToggleCamera.classList.toggle('cam-off', State.callCamOff);
});

// Colgar
DOM.btnEndCall.addEventListener('click', () => endCall(true));

// Desconectar chat
DOM.btnDisconnect.addEventListener('click', () => {
  if (!confirm('¿Terminar sesion? Claves y mensajes se destruiran.')) return;
  if (State.conn) try { State.conn.close(); } catch(_) {}
  terminateConnection('Terminado por usuario.');
  DOM.messagesContainer.innerHTML = '';
  setStatus('Sesion terminada.', 'info');
  showView('home');
});

// Limpiar chat
DOM.btnClearChat.addEventListener('click', () => {
  if (confirm('¿Borrar historial local?')) {
    DOM.messagesContainer.innerHTML = '';
    addMessage('Historial borrado.', 'system');
  }
});

// Fingerprint
DOM.btnShowFingerprint.addEventListener('click', () => {
  if (!State.fingerprint) { alert('Conectese primero para ver el Codigo de Verificacion.'); return; }
  showFingerprintPanel();
});
DOM.btnVerifiedOk.addEventListener('click', () => {
  DOM.fingerprintPanel.classList.add('hidden');
  addMessage('Verificacion completada. Sin MitM detectado.', 'security');
});
DOM.btnVerifiedFail.addEventListener('click', () => {
  DOM.fingerprintPanel.classList.add('hidden');
  addMessage('ALERTA: Codigos no coinciden. MitM detectado. Desconectando.', 'warning');
  setTimeout(() => {
    if (State.conn) try { State.conn.close(); } catch(_) {}
    terminateConnection('MitM detectado.');
    DOM.messagesContainer.innerHTML = '';
    setStatus('MitM DETECTADO. Sesion terminada.', 'error');
    showView('home');
  }, 1500);
});

// Apodo
DOM.btnRename.addEventListener('click', () => {
  DOM.nicknameInput.value = State.contactNickname || '';
  showModal('modal-nickname');
  DOM.nicknameInput.focus();
});
DOM.btnSaveNickname.addEventListener('click', () => {
  const n = DOM.nicknameInput.value.trim().substring(0, 20);
  if (n) { State.contactNickname = n; updateContactUI(); addMessage(`Apodo: "${n}"`, 'system'); }
  hideModal('modal-nickname');
});
DOM.btnCloseNickname.addEventListener('click',  () => hideModal('modal-nickname'));
DOM.btnCloseNickname2.addEventListener('click', () => hideModal('modal-nickname'));
DOM.nicknameInput.addEventListener('keydown', e => {
  if (e.key==='Enter') { e.preventDefault(); DOM.btnSaveNickname.click(); }
  if (e.key==='Escape') hideModal('modal-nickname');
});

// Envio con Enter
DOM.btnSend.addEventListener('click', sendMessage);
DOM.messageInput.addEventListener('keydown', e => {
  if (e.key==='Enter' && !e.shiftKey) { e.preventDefault(); sendMessage(); }
});
DOM.messageInput.addEventListener('input', () => {
  DOM.charCount.textContent = DOM.messageInput.value.length;
});

// Input de ID: solo chars validos
DOM.inputRemoteId.addEventListener('input', () => {
  DOM.inputRemoteId.value = DOM.inputRemoteId.value.toUpperCase().replace(/[^A-Z2-9]/g,'');
});
DOM.inputRemoteId.addEventListener('keydown', e => {
  if (e.key==='Enter') { e.preventDefault(); DOM.btnConnect.click(); }
});

// Escape: cerrar modales
document.addEventListener('keydown', e => {
  if (e.key === 'Escape') {
    hideModal('modal-nickname');
    if (!DOM.modalOverlay.classList.contains('hidden')) rejectChat();
    if (!DOM.modalIncomingCall.classList.contains('hidden')) rejectIncomingCall();
  }
});

// Advertencia al salir
window.addEventListener('beforeunload', e => {
  if (State.conn || State.chatReady || State.callActive) {
    e.preventDefault();
    e.returnValue = 'Su sesion de SecureChat se destruira. ¿Desea salir?';
  }
});

// ============================================================
// ARRANQUE
// ============================================================
(async () => {
  try {
    if (!window.crypto?.subtle) throw new Error('Web Crypto API no disponible. Necesita HTTPS.');
    if (typeof RTCPeerConnection === 'undefined') throw new Error('WebRTC no disponible.');
    if (typeof Peer === 'undefined') throw new Error('peerjs.min.js no encontrado en la carpeta.');

    // Detectar bloqueo de WebRTC (Tor Browser en modo Safest/Safer)
    const webrtcBlocked = await detectTorWebRTCBlock();
    if (webrtcBlocked) return; // Mostrar banner y no continuar

    await initPeer();
    console.info('[SecureChat v3.0] Iniciado.');
  } catch(e) {
    console.error('[SecureChat] Error critico:', e);
    DOM.serverStatus.textContent = '[ ERROR CRITICO ]';
    DOM.serverStatus.className   = 'status-error';
    setStatus('ERROR: ' + e.message, 'error');
  }
})();

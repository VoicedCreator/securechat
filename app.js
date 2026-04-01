/**
 * =======================================================================
 *  app.js -- SecureChat v1.0
 *  Logica principal: Identidad Efimera + PeerJS/WebRTC + Cifrado E2EE
 * =======================================================================
 *
 *  ARQUITECTURA DE SEGURIDAD (doble capa):
 *  ----------------------------------------
 *  Capa 1 (Transporte): WebRTC/DTLS-SRTP
 *    - Nativo del protocolo WebRTC. Cifra el canal de datos entre pares.
 *    - El servidor de señalizacion PeerJS SOLO intercambia metadatos para
 *      establecer la conexion (SDP/ICE). Jamas toca el contenido.
 *
 *  Capa 2 (Aplicacion): ECDH P-256 + AES-GCM-256
 *    - Generamos un par de claves ECDH efimero al cargar la pagina.
 *    - Intercambiamos claves publicas por el canal WebRTC (ya cifrado).
 *    - Derivamos un secreto compartido AES-GCM-256 (Diffie-Hellman).
 *    - Cada mensaje se cifra con un IV aleatorio de 96 bits unico.
 *    - Incluso si alguien comprometiera el canal WebRTC, los mensajes
 *      seguirian siendo ilegibles (Perfect Forward Secrecy por sesion).
 *
 *  EPHEMERAL IDENTITY (identidad efimera):
 *  ----------------------------------------
 *    - ID generado con crypto.getRandomValues() al cargar la pagina.
 *    - Almacenado UNICAMENTE en memoria JS (variable local en closure).
 *    - NO se usa localStorage, sessionStorage, cookies ni IndexedDB.
 *    - F5 / cierre de pestana / navegacion = destruccion total de sesion.
 *
 * =======================================================================
 */

'use strict';

// ============================================================
// ESTADO GLOBAL (todo en memoria volatil -- muere con la pagina)
// ============================================================
const State = Object.seal({
  peer:             null,   // Instancia Peer de PeerJS
  conn:             null,   // DataConnection activa
  myId:             null,   // ID efimero de esta sesion
  remoteId:         null,   // ID del par remoto
  contactNickname:  null,   // Apodo local asignado (solo visible para mi)
  myKeyPair:        null,   // { publicKey, privateKey } ECDH P-256
  sharedKey:        null,   // CryptoKey AES-GCM-256 derivada
  keyExchangeDone:  false,  // Flag: intercambio de claves completado
  isInitiator:      false,  // true = yo inicié la conexion (soy "B")
  chatReady:        false,  // true = ambos confirmaron, chat activo
});

// ============================================================
// REFERENCIAS A ELEMENTOS DEL DOM
// ============================================================
const DOM = {
  // Vistas
  viewHome:       document.getElementById('view-home'),
  viewWaiting:    document.getElementById('view-waiting'),
  viewChat:       document.getElementById('view-chat'),
  // Home
  myPeerId:       document.getElementById('my-peer-id'),
  serverStatus:   document.getElementById('server-status'),
  inputRemoteId:  document.getElementById('input-remote-id'),
  btnCopyId:      document.getElementById('btn-copy-id'),
  btnConnect:     document.getElementById('btn-connect'),
  statusMsg:      document.getElementById('status-msg'),
  // Waiting
  waitingRemoteId: document.getElementById('waiting-remote-id'),
  btnCancelWait:   document.getElementById('btn-cancel-wait'),
  // Chat
  chatTitleText:      document.getElementById('chat-title-text'),
  contactNameDisplay: document.getElementById('contact-name-display'),
  contactIdDisplay:   document.getElementById('contact-id-display'),
  messagesContainer:  document.getElementById('messages-container'),
  messageInput:       document.getElementById('message-input'),
  btnSend:            document.getElementById('btn-send'),
  btnDisconnect:      document.getElementById('btn-disconnect'),
  btnRename:          document.getElementById('btn-rename'),
  btnClearChat:       document.getElementById('btn-clear-chat'),
  charCount:          document.getElementById('char-count'),
  // Modal solicitud
  modalOverlay:  document.getElementById('modal-overlay'),
  requesterId:   document.getElementById('requester-id'),
  btnAccept:     document.getElementById('btn-accept'),
  btnReject:     document.getElementById('btn-reject'),
  btnRejectX:    document.getElementById('btn-reject-x'),
  // Modal apodo
  modalNickname:     document.getElementById('modal-nickname'),
  nicknameInput:     document.getElementById('nickname-input'),
  btnSaveNickname:   document.getElementById('btn-save-nickname'),
  btnCloseNickname:  document.getElementById('btn-close-nickname'),
  btnCloseNickname2: document.getElementById('btn-close-nickname2'),
};

// ============================================================
// SPA: NAVEGACION ENTRE VISTAS
// ============================================================

/**
 * Muestra una vista y oculta las demas.
 * @param {'home'|'waiting'|'chat'} name
 */
function showView(name) {
  DOM.viewHome.classList.remove('active');
  DOM.viewWaiting.classList.remove('active');
  DOM.viewChat.classList.remove('active');

  switch (name) {
    case 'home':    DOM.viewHome.classList.add('active');    break;
    case 'waiting': DOM.viewWaiting.classList.add('active'); break;
    case 'chat':    DOM.viewChat.classList.add('active');    break;
  }
}

function showModalRequest(requesterId) {
  DOM.requesterId.textContent = requesterId;
  DOM.modalOverlay.classList.remove('hidden');
}

function hideModalRequest() {
  DOM.modalOverlay.classList.add('hidden');
}

function showModalNickname() {
  DOM.nicknameInput.value = State.contactNickname || '';
  DOM.modalNickname.classList.remove('hidden');
  DOM.nicknameInput.focus();
}

function hideModalNickname() {
  DOM.modalNickname.classList.add('hidden');
}

/**
 * Actualiza el mensaje de estado en la vista home.
 * @param {string} msg
 * @param {'ok'|'error'|'info'} [type='info']
 */
function setStatus(msg, type = 'info') {
  DOM.statusMsg.textContent = msg;
  DOM.statusMsg.style.color =
    type === 'error' ? '#cc0000' :
    type === 'ok'    ? '#006600' :
    '#000080';
}

// ============================================================
// CRIPTOGRAFIA: Web Crypto API (sin librerias externas)
// ============================================================

/**
 * Genera un par de claves ECDH P-256 efimero.
 * La clave privada es NO exportable (solo puede usarse para derivar).
 */
async function generateKeyPair() {
  return crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' },
    true,          // exportable = true (necesario para exportar pubkey)
    ['deriveKey']  // uso: solo derivar claves compartidas
  );
}

/**
 * Exporta la clave publica ECDH al formato JWK para transmitirla.
 * @param {CryptoKey} publicKey
 * @returns {Promise<JsonWebKey>}
 */
async function exportPublicKey(publicKey) {
  return crypto.subtle.exportKey('jwk', publicKey);
}

/**
 * Importa una clave publica ECDH desde formato JWK.
 * @param {JsonWebKey} jwk
 * @returns {Promise<CryptoKey>}
 */
async function importPublicKey(jwk) {
  return crypto.subtle.importKey(
    'jwk',
    jwk,
    { name: 'ECDH', namedCurve: 'P-256' },
    false,  // no necesita ser exportable
    []      // sin uso directo (solo para ECDH)
  );
}

/**
 * Deriva una clave AES-GCM-256 compartida usando ECDH Diffie-Hellman.
 * Ambas partes llegan al mismo secreto sin transmitirlo.
 * @param {CryptoKey} myPrivateKey
 * @param {CryptoKey} theirPublicKey
 * @returns {Promise<CryptoKey>} Clave AES-GCM de 256 bits
 */
async function deriveSharedKey(myPrivateKey, theirPublicKey) {
  return crypto.subtle.deriveKey(
    { name: 'ECDH', public: theirPublicKey },
    myPrivateKey,
    { name: 'AES-GCM', length: 256 },
    false,                     // no exportable - nunca sale de la memoria
    ['encrypt', 'decrypt']     // usos permitidos
  );
}

/**
 * Cifra un texto plano con AES-GCM-256.
 * Genera un IV aleatorio de 96 bits por cada mensaje (fundamental para GCM).
 * @param {CryptoKey} sharedKey
 * @param {string} plaintext
 * @returns {Promise<{ iv: number[], data: number[] }>}
 */
async function encryptMessage(sharedKey, plaintext) {
  // IV aleatorio criptograficamente seguro (96 bits = requerimiento de GCM)
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encoded = new TextEncoder().encode(plaintext);

  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, tagLength: 128 }, // Tag de autenticacion de 128 bits
    sharedKey,
    encoded
  );

  // Convertimos a arrays de numeros para serializar como JSON por PeerJS
  return {
    iv:   Array.from(iv),
    data: Array.from(new Uint8Array(ciphertext))
  };
}

/**
 * Descifra un objeto { iv, data } con AES-GCM-256.
 * Si el mensaje fue alterado, la autenticacion GCM fallara (excepcion).
 * @param {CryptoKey} sharedKey
 * @param {{ iv: number[], data: number[] }} encObj
 * @returns {Promise<string>}
 */
async function decryptMessage(sharedKey, encObj) {
  const iv       = new Uint8Array(encObj.iv);
  const ciphertext = new Uint8Array(encObj.data);

  const decrypted = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv, tagLength: 128 },
    sharedKey,
    ciphertext
  );

  return new TextDecoder().decode(decrypted);
}

// ============================================================
// GENERACION DE ID EFIMERO
// ============================================================

/**
 * Genera un ID de 8 caracteres alfanumericos sin ambiguedades.
 * Usa crypto.getRandomValues (CSPRNG del navegador, no Math.random).
 * Excluimos: 0, O, I, 1 (para evitar confusion visual al compartir).
 * @returns {string} Ej: "AB3K7PQR"
 */
function generateEphemeralId() {
  const CHARSET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // 32 chars, sin ambiguos
  const bytes = crypto.getRandomValues(new Uint8Array(8));
  return Array.from(bytes).map(b => CHARSET[b % CHARSET.length]).join('');
}

// ============================================================
// LOGICA DE CHAT: MENSAJES EN PANTALLA
// ============================================================

/**
 * Agrega un mensaje al contenedor de chat.
 * @param {string} text       - Contenido del mensaje
 * @param {'me'|'them'|null} sender - Remitente ('me', 'them', o null para sistema)
 * @param {boolean} [isSystem=false] - Si es mensaje del sistema
 */
function addMessage(text, sender, isSystem = false) {
  const el = document.createElement('div');

  if (isSystem) {
    el.className = 'msg-system';
    el.textContent = `[${new Date().toLocaleTimeString()}] ${text}`;
  } else {
    el.className = sender === 'me' ? 'msg-me' : 'msg-them';

    const nameEl = document.createElement('span');
    nameEl.className = 'msg-sender';
    nameEl.textContent = sender === 'me'
      ? '[ YO ]'
      : `[ ${(State.contactNickname || 'ANONIMO').toUpperCase()} ]`;

    const textEl = document.createElement('span');
    textEl.className = 'msg-text';
    textEl.textContent = text;

    const timeEl = document.createElement('span');
    timeEl.className = 'msg-time';
    timeEl.textContent = new Date().toLocaleTimeString();

    el.appendChild(nameEl);
    el.appendChild(textEl);
    el.appendChild(timeEl);
  }

  DOM.messagesContainer.appendChild(el);
  // Auto-scroll al ultimo mensaje
  DOM.messagesContainer.scrollTop = DOM.messagesContainer.scrollHeight;
}

/**
 * Envia el mensaje actual del textarea al contacto.
 * Cifra con AES-GCM-256 antes de enviar.
 */
async function sendMessage() {
  const text = DOM.messageInput.value.trim();
  if (!text || !State.conn || !State.sharedKey || !State.chatReady) return;

  try {
    const encrypted = await encryptMessage(State.sharedKey, text);
    State.conn.send({ type: 'message', payload: encrypted });
    addMessage(text, 'me');
    DOM.messageInput.value = '';
    DOM.charCount.textContent = '0';
  } catch (err) {
    console.error('[SecureChat] Error cifrando mensaje:', err);
    addMessage('ERROR: No se pudo cifrar el mensaje. Conexion comprometida.', null, true);
  }
}

// ============================================================
// PROTOCOLO DE SEÑALIZACION (mensajes de control via WebRTC)
// ============================================================
/**
 * Flujo de mensajes de control:
 *
 *  B -> A : { type: 'key_exchange', publicKey: JWK }
 *  A -> B : { type: 'key_exchange_ack', publicKey: JWK }
 *  B -> A : { type: 'chat_request' }
 *  A -> B : { type: 'chat_accepted' }  (o 'chat_rejected')
 *  B <-> A: { type: 'message', payload: { iv, data } }
 */

/**
 * Maneja todos los datos entrantes de la conexion P2P.
 * @param {object} data
 */
async function handleData(data) {
  if (!data || typeof data.type !== 'string') return;

  switch (data.type) {

    // --------------------------------------------------------
    // PASO 1: El iniciador (B) envia su clave publica ECDH
    // --------------------------------------------------------
    case 'key_exchange': {
      // Solo el receptor (A) llega aqui
      try {
        const theirPubKey = await importPublicKey(data.publicKey);
        State.sharedKey = await deriveSharedKey(State.myKeyPair.privateKey, theirPubKey);
        State.keyExchangeDone = true;
        console.info('[SecureChat] Clave AES-GCM-256 derivada (receptor).');

        // Responder con nuestra clave publica
        const myPubKeyJwk = await exportPublicKey(State.myKeyPair.publicKey);
        State.conn.send({ type: 'key_exchange_ack', publicKey: myPubKeyJwk });
      } catch (err) {
        console.error('[SecureChat] Error en key_exchange:', err);
        terminateConnection('Error en intercambio de claves.');
      }
      break;
    }

    // --------------------------------------------------------
    // PASO 2: El receptor (A) responde con su clave publica
    // --------------------------------------------------------
    case 'key_exchange_ack': {
      // Solo el iniciador (B) llega aqui
      try {
        const theirPubKey = await importPublicKey(data.publicKey);
        State.sharedKey = await deriveSharedKey(State.myKeyPair.privateKey, theirPubKey);
        State.keyExchangeDone = true;
        console.info('[SecureChat] Clave AES-GCM-256 derivada (iniciador).');

        // Intercambio completo: enviar solicitud de chat
        State.conn.send({ type: 'chat_request' });
        showView('waiting');
        DOM.waitingRemoteId.textContent = State.remoteId;
      } catch (err) {
        console.error('[SecureChat] Error en key_exchange_ack:', err);
        terminateConnection('Error en intercambio de claves.');
      }
      break;
    }

    // --------------------------------------------------------
    // PASO 3: El iniciador (B) solicita abrir el chat
    // --------------------------------------------------------
    case 'chat_request': {
      // Solo el receptor (A) llega aqui: mostrar modal de aceptacion
      showModalRequest(State.remoteId);
      break;
    }

    // --------------------------------------------------------
    // PASO 4: El receptor (A) acepta
    // --------------------------------------------------------
    case 'chat_accepted': {
      // Solo el iniciador (B) llega aqui: abrir chat
      openChat();
      break;
    }

    // --------------------------------------------------------
    // PASO 4 (alternativa): El receptor (A) rechaza
    // --------------------------------------------------------
    case 'chat_rejected': {
      terminateConnection('El contacto rechazo la solicitud de conexion.');
      setStatus('Conexion rechazada por el contacto.', 'error');
      showView('home');
      break;
    }

    // --------------------------------------------------------
    // MENSAJES DE CHAT (cifrados con AES-GCM-256)
    // --------------------------------------------------------
    case 'message': {
      if (!State.sharedKey || !State.chatReady) {
        console.warn('[SecureChat] Mensaje recibido sin sesion activa. Descartado.');
        return;
      }
      try {
        const plaintext = await decryptMessage(State.sharedKey, data.payload);
        addMessage(plaintext, 'them');
      } catch (err) {
        // El fallo de descifrado AES-GCM indica posible manipulacion
        console.error('[SecureChat] FALLO DE AUTENTICACION GCM:', err);
        addMessage(
          'ADVERTENCIA: Mensaje no pudo ser autenticado/descifrado. ' +
          'Posible manipulacion del canal. Se descarto.',
          null, true
        );
      }
      break;
    }

    default:
      console.warn('[SecureChat] Tipo de mensaje desconocido:', data.type);
  }
}

// ============================================================
// APERTURA Y CIERRE DE CHAT
// ============================================================

/** Abre la interfaz de chat y muestra mensaje de bienvenida. */
function openChat() {
  State.chatReady = true;
  showView('chat');
  updateContactUI();
  DOM.chatTitleText.textContent =
    `SecureChat v1.0 -- Sesion Activa | Mi ID: ${State.myId}`;
  addMessage(
    'Conexion E2EE establecida. Canal cifrado con AES-GCM-256 + ECDH-P256. ' +
    'Ningun mensaje se almacena en servidores.',
    null, true
  );
  DOM.messageInput.focus();
}

/** Actualiza los elementos de UI del contacto en el chat. */
function updateContactUI() {
  const nick = State.contactNickname || 'ANONIMO';
  DOM.contactNameDisplay.textContent = nick.toUpperCase();
  DOM.contactIdDisplay.textContent   = State.remoteId || '';
}

/**
 * Termina la conexion y limpia el estado sensible.
 * @param {string} [reason='']
 */
function terminateConnection(reason = '') {
  // Limpiar referencias sensibles de la memoria
  State.conn            = null;
  State.sharedKey       = null;
  State.keyExchangeDone = false;
  State.chatReady       = false;
  State.remoteId        = null;
  State.contactNickname = null;
  State.isInitiator     = false;

  hideModalRequest();
  hideModalNickname();

  if (reason) {
    console.info('[SecureChat] Conexion terminada:', reason);
  }
}

/** Llamado cuando la conexion se cierra inesperadamente. */
function handleUnexpectedClose() {
  if (State.chatReady) {
    addMessage('Conexion terminada. El contacto se ha desconectado.', null, true);
  }
  terminateConnection('Cierre inesperado.');
}

// ============================================================
// INICIALIZACION DE PEERJS
// ============================================================

/**
 * Inicializa PeerJS con nuestro ID efimero.
 * Configura los manejadores de eventos de señalizacion.
 */
async function initPeer() {
  // 1. Generar par de claves ECDH antes de crear el peer
  State.myKeyPair = await generateKeyPair();
  console.info('[SecureChat] Par de claves ECDH-P256 generado.');

  // 2. Generar ID efimero criptograficamente seguro
  const ephemeralId = generateEphemeralId();

  // 3. Crear instancia PeerJS con el ID generado
  //    Usamos el servidor publico gratuito de PeerJS (0.peerjs.com:443).
  //    Este servidor SOLO maneja la señalizacion inicial (SDP/ICE).
  //    NO toca, ve, ni almacena el contenido de los mensajes.
  State.peer = new Peer(ephemeralId, {
    host:   '0.peerjs.com',
    port:   443,
    path:   '/',
    secure: true,
    debug:  0, // 0=silencioso, 1=errores, 2=warnings, 3=verbose
    config: {
      iceServers: [
        // Servidores STUN para atravesar NAT (sin costo, sin privacidad comprometida)
        { urls: 'stun:stun.l.google.com:19302' },
        { urls: 'stun:stun1.l.google.com:19302' },
        { urls: 'stun:global.stun.twilio.com:3478' },
      ]
    }
  });

  // ---- Evento: peer registrado y listo ----
  State.peer.on('open', (id) => {
    State.myId = id;
    DOM.myPeerId.textContent = id;
    DOM.serverStatus.textContent = '[ CONECTADO -- LISTO ]';
    DOM.serverStatus.className = 'status-ok';
    console.info('[SecureChat] Peer activo. ID:', id);
  });

  // ---- Evento: error de PeerJS ----
  State.peer.on('error', (err) => {
    console.error('[SecureChat] Error PeerJS:', err);
    const msg = err.type === 'peer-unavailable'
      ? 'ID no encontrado o el contacto no esta disponible.'
      : `Error de red: ${err.type || err.message}`;
    setStatus(msg, 'error');
    DOM.serverStatus.textContent = '[ ERROR ]';
    DOM.serverStatus.className = 'status-error';

    // Si habia una conexion en progreso, limpiar
    if (State.conn) {
      terminateConnection('Error PeerJS: ' + msg);
      showView('home');
    }
  });

  // ---- Evento: alguien se conecta a MI peer (yo soy el receptor A) ----
  State.peer.on('connection', (incomingConn) => {
    // Solo aceptamos UNA conexion simultanea
    if (State.conn) {
      console.warn('[SecureChat] Conexion entrante rechazada: ya hay una activa.');
      incomingConn.on('open', () => incomingConn.close());
      return;
    }

    console.info('[SecureChat] Conexion entrante de:', incomingConn.peer);
    State.conn        = incomingConn;
    State.isInitiator = false;
    State.remoteId    = incomingConn.peer;

    // El receptor no necesita hacer nada en 'open' -- espera la clave del iniciador
    incomingConn.on('open', () => {
      console.info('[SecureChat] Canal P2P abierto con:', State.remoteId);
    });

    incomingConn.on('data', handleData);

    incomingConn.on('close', handleUnexpectedClose);

    incomingConn.on('error', (err) => {
      console.error('[SecureChat] Error en conexion:', err);
      handleUnexpectedClose();
    });
  });

  // ---- Evento: peer desconectado del servidor de señalizacion ----
  State.peer.on('disconnected', () => {
    console.warn('[SecureChat] Desconectado del servidor de señalizacion. Reconectando...');
    DOM.serverStatus.textContent = '[ RECONECTANDO... ]';
    DOM.serverStatus.className = 'status-connecting';
    // PeerJS intenta reconectar automaticamente al servidor de señalizacion
    // pero la conexion P2P puede sobrevivir sin el (WebRTC es independiente)
    try { State.peer.reconnect(); } catch(_) {}
  });
}

// ============================================================
// MANEJO DE EVENTOS DE UI
// ============================================================

// ---- Copiar ID propio ----
DOM.btnCopyId.addEventListener('click', () => {
  if (!State.myId) return;
  navigator.clipboard.writeText(State.myId)
    .then(() => setStatus('ID copiado al portapapeles.', 'ok'))
    .catch(() => {
      // Fallback para navegadores sin permiso de clipboard
      try {
        const range = document.createRange();
        range.selectNode(DOM.myPeerId);
        window.getSelection().removeAllRanges();
        window.getSelection().addRange(range);
        setStatus('Seleccione el texto con Ctrl+C para copiar.', 'info');
      } catch (_) {
        setStatus('No se pudo copiar. Copie manualmente: ' + State.myId, 'error');
      }
    });
});

// ---- Iniciar conexion (Usuario B -> Usuario A) ----
DOM.btnConnect.addEventListener('click', async () => {
  const rawInput = DOM.inputRemoteId.value.trim().toUpperCase().replace(/[^A-Z2-9]/g, '');

  if (!rawInput) {
    setStatus('Ingrese el ID del contacto.', 'error');
    return;
  }
  if (!State.myId) {
    setStatus('Aun conectando al servidor. Espere un momento.', 'error');
    return;
  }
  if (rawInput === State.myId) {
    setStatus('No puede conectarse a su propio ID.', 'error');
    return;
  }
  if (State.conn) {
    setStatus('Ya hay una conexion activa.', 'error');
    return;
  }

  setStatus('Estableciendo conexion P2P...', 'info');
  State.isInitiator = true;
  State.remoteId    = rawInput;

  // Crear conexion hacia el peer remoto
  const outConn = State.peer.connect(rawInput, {
    reliable:      true,         // Garantiza entrega ordenada (TCP-like sobre WebRTC)
    serialization: 'json',       // Serializacion JSON para nuestros objetos de control
    label:         'securechat', // Identificador del canal de datos
  });

  State.conn = outConn;

  outConn.on('open', async () => {
    setStatus('Canal P2P abierto. Intercambiando claves criptograficas...', 'info');
    console.info('[SecureChat] Conexion abierta hacia:', rawInput);

    // Iniciar el intercambio de claves ECDH: enviamos nuestra clave publica
    try {
      const myPubKeyJwk = await exportPublicKey(State.myKeyPair.publicKey);
      outConn.send({ type: 'key_exchange', publicKey: myPubKeyJwk });
    } catch (err) {
      console.error('[SecureChat] Error exportando clave publica:', err);
      terminateConnection('Error cripto al iniciar conexion.');
      setStatus('Error criptografico. Recargue la pagina.', 'error');
      showView('home');
    }
  });

  outConn.on('data', handleData);

  outConn.on('close', handleUnexpectedClose);

  outConn.on('error', (err) => {
    console.error('[SecureChat] Error de conexion:', err);
    setStatus('Error en la conexion. Verifique el ID e intente de nuevo.', 'error');
    terminateConnection('Error de conexion.');
    showView('home');
  });
});

// ---- Cancelar espera ----
DOM.btnCancelWait.addEventListener('click', () => {
  if (State.conn) {
    try { State.conn.close(); } catch (_) {}
  }
  terminateConnection('Cancelado por el usuario.');
  setStatus('Conexion cancelada.', 'info');
  showView('home');
});

// ---- Aceptar solicitud de chat ----
DOM.btnAccept.addEventListener('click', () => {
  hideModalRequest();
  if (!State.conn) return;
  State.conn.send({ type: 'chat_accepted' });
  openChat();
});

// ---- Rechazar solicitud de chat ----
const rejectConnection = () => {
  hideModalRequest();
  if (State.conn) {
    try {
      State.conn.send({ type: 'chat_rejected' });
      State.conn.close();
    } catch (_) {}
  }
  terminateConnection('Rechazado por el usuario.');
  setStatus('Solicitud rechazada.', 'info');
};

DOM.btnReject.addEventListener('click', rejectConnection);
DOM.btnRejectX.addEventListener('click', rejectConnection);

// ---- Enviar mensaje ----
DOM.btnSend.addEventListener('click', sendMessage);

DOM.messageInput.addEventListener('keydown', (e) => {
  if (e.key === 'Enter' && !e.shiftKey) {
    e.preventDefault();
    sendMessage();
  }
});

// ---- Contador de caracteres ----
DOM.messageInput.addEventListener('input', () => {
  DOM.charCount.textContent = DOM.messageInput.value.length;
});

// ---- Desconectar / terminar chat ----
DOM.btnDisconnect.addEventListener('click', () => {
  // Usamos confirm() -- nativo, sin dependencias
  if (!confirm('¿Desea terminar esta sesion de chat?\n\nLa sesion se destruira y no podra recuperarse.')) return;
  if (State.conn) {
    try { State.conn.close(); } catch (_) {}
  }
  terminateConnection('Terminado por el usuario.');
  setStatus('Sesion de chat terminada.', 'info');
  showView('home');
});

// ---- Limpiar historial local ----
DOM.btnClearChat.addEventListener('click', () => {
  if (confirm('¿Limpiar el historial de mensajes de esta pantalla?\n(Solo afecta su vista. No afecta al contacto.)')) {
    DOM.messagesContainer.innerHTML = '';
    addMessage('Historial local borrado.', null, true);
  }
});

// ---- Asignar apodo: abrir modal ----
DOM.btnRename.addEventListener('click', showModalNickname);

// ---- Guardar apodo ----
DOM.btnSaveNickname.addEventListener('click', () => {
  const nick = DOM.nicknameInput.value.trim().substring(0, 20);
  if (nick) {
    State.contactNickname = nick;
    updateContactUI();
    addMessage(`Apodo local asignado: "${nick}"`, null, true);
  }
  hideModalNickname();
});

// ---- Cerrar modal de apodo ----
DOM.btnCloseNickname.addEventListener('click', hideModalNickname);
DOM.btnCloseNickname2.addEventListener('click', hideModalNickname);

// ---- Enter en campo de apodo ----
DOM.nicknameInput.addEventListener('keydown', (e) => {
  if (e.key === 'Enter') {
    e.preventDefault();
    DOM.btnSaveNickname.click();
  }
  if (e.key === 'Escape') {
    hideModalNickname();
  }
});

// ---- Enter en campo de ID remoto ----
DOM.inputRemoteId.addEventListener('keydown', (e) => {
  if (e.key === 'Enter') {
    e.preventDefault();
    DOM.btnConnect.click();
  }
});

// ---- Normalizar input de ID (solo caracteres validos, mayusculas) ----
DOM.inputRemoteId.addEventListener('input', () => {
  const clean = DOM.inputRemoteId.value.toUpperCase().replace(/[^A-Z2-9]/g, '');
  DOM.inputRemoteId.value = clean;
});

// ---- Cerrar modales con Escape ----
document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape') {
    hideModalNickname();
    if (!DOM.modalOverlay.classList.contains('hidden')) {
      // Presionar Escape en el modal de solicitud = rechazar
      rejectConnection();
    }
  }
});

// ============================================================
// ADVERTENCIA AL SALIR/RECARGAR (refuerza la consciencia del usuario)
// ============================================================
window.addEventListener('beforeunload', (e) => {
  if (State.conn || State.chatReady) {
    // Este mensaje solo aparece en algunos navegadores (es un estandar deprecado)
    // pero sirve como recordatorio de que la sesion se destruira
    e.preventDefault();
    e.returnValue = 'Si sale, su sesion de SecureChat se destruira permanentemente.';
  }
});

// ============================================================
// ARRANQUE DE LA APLICACION
// ============================================================
(async () => {
  try {
    // Verificar soporte de APIs necesarias
    if (!window.crypto?.subtle) {
      throw new Error('Web Crypto API no disponible. Use un navegador moderno con HTTPS.');
    }
    if (typeof RTCPeerConnection === 'undefined') {
      throw new Error('WebRTC no disponible en este navegador.');
    }

    // Iniciar PeerJS y generar identidad efimera
    await initPeer();

  } catch (err) {
    console.error('[SecureChat] Error critico al iniciar:', err);
    DOM.serverStatus.textContent = '[ ERROR CRITICO ]';
    DOM.serverStatus.className = 'status-error';
    setStatus('ERROR: ' + err.message, 'error');
  }
})();

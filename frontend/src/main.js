import QRCode from 'qrcode';
import { startAuthentication, startRegistration } from '@simplewebauthn/browser';

const elements = {
  guestSection: document.querySelector('#guest-section'),
  guestList: document.querySelector('#guest-list'),
  captcha: document.querySelector('#captcha'),
  captchaStatus: document.querySelector('#captcha-status'),
  flowSection: document.querySelector('#flow-section'),
  selectedName: document.querySelector('#selected-name'),
  status: document.querySelector('#status'),
  whatsappPanel: document.querySelector('#whatsapp-panel'),
  qrCode: document.querySelector('#qr-code'),
  whatsappLink: document.querySelector('#whatsapp-link'),
  actions: document.querySelector('#actions'),
  createPasskey: document.querySelector('#create-passkey'),
  whatsappRecovery: document.querySelector('#whatsapp-recovery'),
  backButton: document.querySelector('#back-button'),
  sessionSection: document.querySelector('#session-section'),
  sessionName: document.querySelector('#session-name'),
  sessionStatus: document.querySelector('#session-status'),
  addPasskey: document.querySelector('#add-passkey'),
  logout: document.querySelector('#logout'),
  registrationForm: document.querySelector('#registration-form'),
  registrationStatus: document.querySelector('#registration-status'),
};

let selectedGuest = null;
let pollGeneration = 0;

const api = async (path, options = {}) => {
  const response = await fetch(path, {
    credentials: 'same-origin',
    ...options,
    headers: options.body ? { 'content-type': 'application/json', ...options.headers } : options.headers,
  });
  const body = await response.json().catch(() => ({}));
  if (!response.ok) {
    const error = new Error(body.message || 'O pedido falhou.');
    error.code = body.error;
    error.status = response.status;
    throw error;
  }
  return body;
};

const post = (path, payload = {}) => api(path, { method: 'POST', body: JSON.stringify(payload) });

const showAuthenticated = (nickname) => {
  pollGeneration += 1;
  elements.guestSection.hidden = true;
  elements.flowSection.hidden = true;
  elements.sessionSection.hidden = false;
  elements.sessionName.textContent = nickname;
  elements.sessionStatus.textContent = '';
};

const showFlow = () => {
  elements.guestSection.hidden = true;
  elements.sessionSection.hidden = true;
  elements.flowSection.hidden = false;
  elements.selectedName.textContent = selectedGuest?.nickname || 'Novo registo';
  elements.whatsappPanel.hidden = true;
  elements.actions.hidden = false;
  elements.createPasskey.hidden = true;
  elements.whatsappRecovery.hidden = true;
};

const showRegistrationWhatsapp = async (result) => {
  const generation = ++pollGeneration;
  elements.guestSection.hidden = true;
  elements.flowSection.hidden = false;
  elements.selectedName.textContent = 'Novo registo';
  elements.status.textContent = 'A aguardar a verificação pelo WhatsApp…';
  elements.whatsappPanel.hidden = false;
  elements.actions.hidden = true;
  elements.whatsappLink.href = result.whatsappUrl;
  await QRCode.toCanvas(elements.qrCode, result.whatsappUrl, { width: 228, margin: 1, errorCorrectionLevel: 'M', color: { dark: '#2d261fff', light: '#ffffffff' } });
  const poll = async () => {
    if (generation !== pollGeneration) return;
    try {
      const state = await api('/api/register/status');
      if (state.status === 'created') {
        elements.whatsappPanel.hidden = true;
        elements.status.textContent = 'Verificado. Crie a sua chave de acesso.';
        await registerPasskey();
        return;
      }
      if (state.status === 'expired') { elements.status.textContent = 'Este registo expirou. Tente novamente.'; elements.whatsappPanel.hidden = true; elements.guestSection.hidden = false; return; }
    } catch { elements.status.textContent = 'O estado da verificação está temporariamente indisponível; a tentar novamente…'; }
    window.setTimeout(poll, document.hidden ? 10000 : 3000);
  };
  window.setTimeout(poll, 3000);
};

const startFriendRegistration = async (event) => {
  event.preventDefault();
  const form = new FormData(elements.registrationForm);
  const phone = String(form.get('phone') || '').trim();
  if (!/^\+[1-9][0-9 ()-]{7,20}$/.test(phone)) {
    elements.registrationStatus.textContent = 'Indique o número completo com + e código do país, por exemplo +351 912 345 678.';
    return;
  }
  elements.registrationStatus.textContent = 'A preparar a verificação pelo WhatsApp…';
  try {
    await showRegistrationWhatsapp(await post('/api/register/start', { name: form.get('name'), phone }));
  } catch (error) { elements.registrationStatus.textContent = readableError(error); }
};

const readableError = (error) => {
  if (error.name === 'NotAllowedError') return 'A utilização da chave de acesso foi cancelada ou expirou.';
  if (error.code === 'whatsapp_unavailable') return 'O início de sessão pelo WhatsApp ainda não está configurado.';
  if (error.code === 'authentication_challenge_expired') return 'Esta tentativa de início de sessão expirou. Tente novamente.';
  if (error.code === 'passkey_verification_failed') return 'Não foi possível verificar essa chave de acesso.';
  if (error.code === 'invalid_registration') return 'Indique um nome válido e um número completo com + e código do país.';
  if (error.code === 'registration_unavailable') return 'Esse nome ou contacto já está registado.';
  return 'Não foi possível concluir a autenticação. Tente novamente.';
};

const showWhatsapp = async (result) => {
  const generation = ++pollGeneration;
  elements.status.textContent = 'A aguardar a verificação pelo WhatsApp…';
  elements.whatsappPanel.hidden = false;
  elements.whatsappRecovery.hidden = true;
  elements.createPasskey.hidden = true;
  elements.whatsappLink.href = result.whatsappUrl;
  await QRCode.toCanvas(elements.qrCode, result.whatsappUrl, {
    width: 228,
    margin: 1,
    errorCorrectionLevel: 'M',
    color: { dark: '#2d261fff', light: '#ffffffff' },
  });

  const poll = async () => {
    if (generation !== pollGeneration) return;
    try {
      const state = await api('/api/auth/whatsapp/status');
      if (state.status === 'approved') {
        elements.whatsappPanel.hidden = true;
        elements.status.textContent = 'Aprovado. Crie uma chave de acesso para futuras visitas.';
        elements.createPasskey.hidden = false;
        await registerPasskey();
        return;
      }
      if (state.status === 'expired') {
        elements.status.textContent = 'Este código QR expirou. Inicie novamente a verificação pelo WhatsApp.';
        elements.whatsappPanel.hidden = true;
        elements.whatsappRecovery.hidden = false;
        return;
      }
    } catch {
      elements.status.textContent = 'O estado da verificação está temporariamente indisponível; a tentar novamente…';
    }
    const delay = document.hidden ? 10000 : 3000;
    window.setTimeout(poll, delay);
  };
  window.setTimeout(poll, 3000);
};

const startWhatsappFlow = async () => {
  if (!selectedGuest) return;
  showFlow();
  elements.status.textContent = 'A preparar a verificação pelo WhatsApp…';
  try {
    await showWhatsapp(await post('/api/auth/whatsapp/start', { guestId: selectedGuest.id }));
  } catch (error) {
    elements.status.textContent = readableError(error);
    elements.whatsappRecovery.hidden = false;
  }
};

const registerPasskey = async () => {
  const targetStatus = elements.sessionSection.hidden ? elements.status : elements.sessionStatus;
  targetStatus.textContent = 'A criar uma chave de acesso…';
  try {
    const { options } = await post('/api/auth/passkeys/register/options');
    const credential = await startRegistration({ optionsJSON: options });
    const result = await post('/api/auth/passkeys/register/verify', { credential });
    showAuthenticated(result.nickname);
  } catch (error) {
    targetStatus.textContent = readableError(error);
    if (!elements.flowSection.hidden) elements.createPasskey.hidden = false;
  }
};

const usePasskey = async (options) => {
  elements.status.textContent = 'Utilize a sua chave de acesso para continuar…';
  try {
    const credential = await startAuthentication({ optionsJSON: options });
    const result = await post('/api/auth/passkeys/login/verify', { credential });
    showAuthenticated(result.nickname);
  } catch (error) {
    elements.status.textContent = `${readableError(error)} Pode recuperar o acesso através do WhatsApp.`;
    elements.whatsappRecovery.hidden = false;
  }
};

const selectGuest = async (guest) => {
  selectedGuest = guest;
  pollGeneration += 1;
  showFlow();
  elements.status.textContent = 'A verificar o seu convite…';
  try {
    const result = await post('/api/auth/start', { guestId: guest.id });
    if (result.mode === 'passkey') await usePasskey(result.options);
    else await showWhatsapp(result);
  } catch (error) {
    elements.status.textContent = readableError(error);
    elements.whatsappRecovery.hidden = false;
  }
};

const loadGuests = async (turnstileToken = '') => {
  elements.guestList.replaceChildren();
  try {
    const { guests } = await api('/api/guests', turnstileToken
      ? { headers: { 'x-turnstile-token': turnstileToken } }
      : {});
    if (guests.length === 0) {
      elements.guestList.textContent = 'Ainda não existem convites disponíveis.';
      return;
    }
    for (const guest of guests) {
      const button = document.createElement('button');
      button.type = 'button';
      button.className = 'guest-button';
      button.textContent = guest.nickname;
      button.addEventListener('click', () => selectGuest(guest));
      elements.guestList.append(button);
    }
  } catch {
    elements.guestList.textContent = 'Não foi possível carregar os convites. Tente novamente mais tarde.';
  }
};

const loadTurnstile = async () => {
  const config = await api('/api/captcha/config');
  await new Promise((resolve, reject) => {
    if (window.turnstile) return resolve();
    const script = document.createElement('script');
    script.src = 'https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit';
    script.async = true;
    script.defer = true;
    script.onload = resolve;
    script.onerror = () => reject(new Error('captcha_script_failed'));
    document.head.append(script);
  });
  await new Promise((resolve) => {
    window.turnstile.render(elements.captcha, {
      sitekey: config.siteKey,
      action: 'guest-directory',
      callback: async (token) => {
        elements.captchaStatus.textContent = 'Verificação de segurança concluída.';
        await loadGuests(token);
        resolve();
      },
      'expired-callback': () => {
        elements.captchaStatus.textContent = 'A verificação de segurança expirou. Conclua-a novamente.';
        elements.guestList.replaceChildren();
      },
      'error-callback': () => {
        elements.captchaStatus.textContent = 'Não foi possível carregar a verificação de segurança. Tente novamente mais tarde.';
        resolve();
      },
    });
  });
};

elements.backButton.addEventListener('click', () => {
  pollGeneration += 1;
  selectedGuest = null;
  elements.flowSection.hidden = true;
  elements.guestSection.hidden = false;
});
elements.whatsappRecovery.addEventListener('click', startWhatsappFlow);
elements.createPasskey.addEventListener('click', registerPasskey);
elements.addPasskey.addEventListener('click', registerPasskey);
elements.logout.addEventListener('click', async () => {
  await post('/api/auth/logout').catch(() => {});
  elements.sessionSection.hidden = true;
  elements.guestSection.hidden = false;
  selectedGuest = null;
  await loadGuests();
});
elements.registrationForm.addEventListener('submit', startFriendRegistration);

const initialize = async () => {
  try {
    const session = await api('/api/session');
    if (session.authenticated) {
      showAuthenticated(session.nickname);
      return;
    }
  } catch {
    // The guest list below provides the recoverable entry path.
  }
  try {
    await loadTurnstile();
  } catch {
    elements.captchaStatus.textContent = 'A verificação de segurança ainda não está configurada.';
  }
};

initialize();

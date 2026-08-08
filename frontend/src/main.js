import QRCode from 'qrcode';
import { startAuthentication, startRegistration } from '@simplewebauthn/browser';

const elements = {
  guestSection: document.querySelector('#guest-section'),
  guestList: document.querySelector('#guest-list'),
  groupPicker: document.querySelector('#group-picker'),
  groupSelect: document.querySelector('#group-select'),
  rsvpSummary: document.querySelector('#rsvp-summary'),
  rsvpSummaryTotal: document.querySelector('#rsvp-summary-total'),
  availabilityChart: document.querySelector('#availability-chart'),
  rsvpSummaryPreferences: document.querySelector('#rsvp-summary-preferences'),
  captcha: document.querySelector('#captcha'),
  captchaStatus: document.querySelector('#captcha-status'),
  triviaForm: document.querySelector('#trivia-form'),
  triviaQuestion: document.querySelector('#trivia-question'),
  triviaAnswer: document.querySelector('#trivia-answer'),
  triviaStatus: document.querySelector('#trivia-status'),
  flowSection: document.querySelector('#flow-section'),
  selectedName: document.querySelector('#selected-name'),
  status: document.querySelector('#status'),
  whatsappPanel: document.querySelector('#whatsapp-panel'),
  qrCode: document.querySelector('#qr-code'),
  whatsappLink: document.querySelector('#whatsapp-link'),
  actions: document.querySelector('#actions'),
  createPasskey: document.querySelector('#create-passkey'),
  retryRegistration: document.querySelector('#retry-registration'),
  backButton: document.querySelector('#back-button'),
  sessionSection: document.querySelector('#session-section'),
  sessionName: document.querySelector('#session-name'),
  sessionStatus: document.querySelector('#session-status'),
  restaurantChoice: document.querySelector('#restaurant-choice'),
  adminSection: document.querySelector('#admin-section'),
  adminDates: document.querySelector('#admin-dates'),
  adminSettingsForm: document.querySelector('#admin-settings-form'),
  adminRestaurants: document.querySelector('#admin-restaurants'),
  adminGroups: document.querySelector('#admin-groups'),
  rsvpForm: document.querySelector('#rsvp-form'),
  availabilityDays: document.querySelector('#availability-days'),
  addPasskey: document.querySelector('#add-passkey'),
  logout: document.querySelector('#logout'),
  registrationStatus: document.querySelector('#registration-status'),
  newContactForm: document.querySelector('#new-contact-form'),
  newContactQr: document.querySelector('#new-contact-qr'),
  newContactMessage: document.querySelector('#new-contact-message'),
  newContactQrCanvas: document.querySelector('#new-contact-qr-canvas'),
};

let selectedGuest = null;
let selectedGroup = '';
let pollGeneration = 0;
let triviaChallenge = '';
let triviaToken = '';

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
const put = (path, payload = {}) => api(path, { method: 'PUT', body: JSON.stringify(payload) });

const showAuthenticated = (nickname) => {
  pollGeneration += 1;
  elements.guestSection.hidden = true;
  elements.flowSection.hidden = true;
  elements.sessionSection.hidden = false;
  elements.sessionName.textContent = nickname;
  elements.sessionStatus.textContent = '';
  loadRsvpForm();
  loadAdmin();
};

const renderRsvpForm = ({ days, response }) => {
  elements.availabilityDays.replaceChildren();
  for (const day of days) {
    const label = document.createElement('label');
    const checkbox = document.createElement('input');
    checkbox.type = 'checkbox'; checkbox.name = 'availableDays'; checkbox.value = day;
    checkbox.checked = response?.availableDays?.includes(day) || false;
    label.append(checkbox, ` ${day}`);
    elements.availabilityDays.append(label);
  }
  elements.rsvpForm.elements.guestCount.value = response?.guestCount || '';
  elements.restaurantChoice.replaceChildren();
  const restaurantChoices = response?.restaurantChoices || [];
  const choices = restaurantChoices.length ? restaurantChoices : ['Por decidir'];
  for (const choice of choices) elements.restaurantChoice.add(new Option(choice, choice));
  if (response?.restaurantChoice && !choices.includes(response.restaurantChoice)) elements.restaurantChoice.add(new Option(response.restaurantChoice, response.restaurantChoice));
  elements.rsvpForm.elements.restaurantChoice.value = response?.restaurantChoice || choices[0];
  elements.rsvpForm.elements.dietaryRestrictions.value = response?.dietaryRestrictions || '';
  for (const checkbox of elements.rsvpForm.querySelectorAll('input[name="mealTypes"]')) {
    checkbox.checked = response?.mealTypes?.includes(checkbox.value) || false;
  }
};

const loadRsvpForm = async () => {
  try {
    const data = await api('/api/rsvp');
    renderRsvpForm({ ...data, response: data.response ? { ...data.response, restaurantChoices: data.restaurantChoices } : { restaurantChoices: data.restaurantChoices } });
  } catch { elements.sessionStatus.textContent = 'Não foi possível carregar o RSVP.'; }
};

const loadAdmin = async () => {
  try {
    const settings = await api('/api/admin/settings');
    elements.adminSection.hidden = false;
    elements.adminDates.textContent = settings.days.join(' · ');
    elements.adminRestaurants.value = settings.restaurantChoices.join('\n');
    const { groups } = await api('/api/admin/groups');
    elements.adminGroups.textContent = groups.length ? groups.map((group) => `${group.name}: ${group.members} membro(s)`).join(' · ') : 'Ainda não existem grupos.';
  } catch (error) {
    if (error.status !== 403) elements.adminSection.hidden = true;
  }
};

const loadRsvpSummary = async () => {
  try {
    const summary = await api('/api/rsvp/summary');
    const maximum = Math.max(1, ...Object.values(summary.byDay));
    elements.availabilityChart.replaceChildren();
    for (const [day, count] of Object.entries(summary.byDay)) {
      const row = document.createElement('div');
      row.className = 'availability-row';
      const label = document.createElement('span'); label.textContent = day;
      const bar = document.createElement('span'); bar.className = 'availability-bar'; bar.style.setProperty('--availability', `${(count / maximum) * 100}%`); bar.textContent = `${count}`;
      row.append(label, bar); elements.availabilityChart.append(row);
    }
    elements.rsvpSummaryTotal.textContent = `${summary.guests} pessoa(s) em ${summary.responses} resposta(s).`;
    const meals = Object.entries(summary.byMeal).filter(([, count]) => count).map(([meal, count]) => `${meal}: ${count}`).join(' · ');
    const restaurants = Object.entries(summary.restaurants).sort((a, b) => b[1] - a[1]).slice(0, 3).map(([name, count]) => `${name}: ${count}`).join(' · ');
    elements.rsvpSummaryPreferences.textContent = [meals, restaurants].filter(Boolean).join(' — ');
    elements.rsvpSummary.hidden = false;
  } catch { elements.rsvpSummary.hidden = true; }
};

const showFlow = () => {
  elements.guestSection.hidden = true;
  elements.sessionSection.hidden = true;
  elements.flowSection.hidden = false;
  elements.selectedName.textContent = selectedGuest?.nickname || 'Novo registo';
  elements.whatsappPanel.hidden = true;
  elements.actions.hidden = false;
  elements.createPasskey.hidden = true;
  elements.retryRegistration.hidden = true;
};

const showRegistrationWhatsapp = async (result) => {
  const generation = ++pollGeneration;
  elements.guestSection.hidden = true;
  elements.flowSection.hidden = false;
  elements.selectedName.textContent = selectedGuest?.nickname || 'Registo';
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
      if (state.status === 'sender_mismatch') {
        elements.whatsappPanel.hidden = true;
        elements.actions.hidden = false;
        elements.retryRegistration.hidden = false;
        elements.status.textContent = 'Não consegui verificar o contacto. Verifica o nome ou se estás a usar o WhatsApp da conta certa.';
        return;
      }
      if (state.status === 'expired') { elements.status.textContent = 'Este registo expirou. Tente novamente.'; elements.whatsappPanel.hidden = true; elements.guestSection.hidden = false; return; }
    } catch { elements.status.textContent = 'O estado da verificação está temporariamente indisponível; a tentar novamente…'; }
    window.setTimeout(poll, document.hidden ? 10000 : 3000);
  };
  window.setTimeout(poll, 3000);
};

const startGuestRegistration = async () => {
  elements.registrationStatus.textContent = 'A preparar a verificação pelo WhatsApp…';
  try {
    await showRegistrationWhatsapp(await post('/api/register/start', { guestId: selectedGuest.id }));
  } catch (error) { elements.registrationStatus.textContent = readableError(error); }
};

elements.retryRegistration.addEventListener('click', () => startGuestRegistration());

const readableError = (error) => {
  if (error.name === 'NotAllowedError') return 'A utilização da chave de acesso foi cancelada ou expirou.';
  if (error.code === 'whatsapp_unavailable') return 'O início de sessão pelo WhatsApp ainda não está configurado.';
  if (error.code === 'authentication_challenge_expired') return 'Esta tentativa de início de sessão expirou. Tente novamente.';
  if (error.code === 'passkey_verification_failed') return 'Não foi possível verificar essa chave de acesso.';
  if (error.code === 'registration_required') return 'Este contacto precisa de concluir o registo.';
  if (error.code === 'registration_not_required') return 'Este contacto já está registado.';
  if (error.code === 'passkey_required') return 'Este contacto já está confirmado, mas ainda não tem uma chave de acesso configurada.';
  if (error.code === 'registration_unavailable') return 'Esse nome ou contacto já está registado.';
  if (error.code === 'sender_mismatch') return 'Não consegui verificar o contacto. Verifica o nome ou se estás a usar o WhatsApp da conta certa.';
  if (error.code === 'invalid_contact_details') return 'Indica um nickname válido.';
  if (error.code === 'contact_already_requested') return 'Este nome já tem um pedido pendente.';
  return 'Não foi possível concluir a autenticação. Tente novamente.';
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
    elements.status.textContent = readableError(error);
  }
};

const selectGuest = async (guest) => {
  selectedGuest = guest;
  pollGeneration += 1;
  showFlow();
  elements.status.textContent = 'A verificar o seu convite…';
  try {
    if (guest.registrationRequired) {
      await startGuestRegistration();
      return;
    }
    const result = await post('/api/auth/start', { guestId: guest.id });
    if (result.mode === 'passkey') await usePasskey(result.options);
  } catch (error) {
    elements.status.textContent = readableError(error);
  }
};

const loadGuests = async (turnstileToken = '') => {
  elements.guestList.replaceChildren();
  try {
    const params = new URLSearchParams();
    if (selectedGroup) params.set('group', selectedGroup);
    const path = `/api/guests${params.size ? `?${params}` : ''}`;
    const { guests } = await api(path, turnstileToken
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

const loadGroups = async () => {
  try {
    const { groups } = await api('/api/groups');
    if (groups.length === 0) {
      selectedGroup = '';
      elements.groupPicker.hidden = true;
      await loadGuests();
      return;
    }
    elements.groupPicker.hidden = false;
    elements.groupSelect.replaceChildren();
    const placeholder = new Option('Escolha o seu grupo', '');
    placeholder.disabled = true;
    placeholder.selected = true;
    elements.groupSelect.add(placeholder);
    for (const group of groups) elements.groupSelect.add(new Option(group.name, group.id));
    elements.guestList.textContent = 'Escolha o seu grupo para encontrar o seu nome.';
  } catch {
    elements.guestList.textContent = 'Não foi possível carregar os grupos. Tente novamente mais tarde.';
  }
};

const loadTriviaQuestion = async (turnstileToken) => {
  try {
    const result = await api('/api/trivia/question', {
      headers: { 'x-turnstile-token': turnstileToken },
    });
    triviaChallenge = result.challenge;
    elements.triviaQuestion.textContent = result.question;
    elements.triviaForm.hidden = false;
    elements.triviaAnswer.focus();
  } catch {
    elements.triviaStatus.textContent = 'Não foi possível carregar a pergunta. Tente novamente mais tarde.';
  }
};

const answerTrivia = async (event) => {
  event.preventDefault();
  elements.triviaStatus.textContent = 'A validar a resposta…';
  try {
    await post('/api/trivia/answer', { challenge: triviaChallenge, answer: elements.triviaAnswer.value });
    elements.triviaForm.hidden = true;
    elements.triviaStatus.textContent = 'Resposta correta.';
    elements.newContactForm.hidden = false;
    await Promise.all([loadGroups(), loadRsvpSummary()]);
  } catch (error) {
    elements.triviaStatus.textContent = error.code === 'trivia_incorrect'
      ? 'Resposta incorreta.'
      : 'Não foi possível validar a resposta. Tente novamente.';
    if (error.code === 'trivia_incorrect') {
      elements.triviaStatus.textContent += ' Podes passar à pergunta seguinte.';
      const next = document.createElement('button');
      next.type = 'button';
      next.textContent = 'Passar à pergunta seguinte';
      next.onclick = () => { next.remove(); elements.triviaStatus.textContent = ''; loadTriviaQuestion(triviaToken); };
      elements.triviaStatus.append(' ', next);
    }
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
        triviaToken = token;
        elements.captchaStatus.textContent = 'Verificação de segurança concluída.';
        await loadTriviaQuestion(token);
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
elements.createPasskey.addEventListener('click', registerPasskey);
elements.addPasskey.addEventListener('click', registerPasskey);
elements.logout.addEventListener('click', async () => {
  await post('/api/auth/logout').catch(() => {});
  elements.sessionSection.hidden = true;
  elements.guestSection.hidden = false;
  selectedGuest = null;
  await loadGroups();
});
elements.triviaForm.addEventListener('submit', answerTrivia);
elements.groupSelect.addEventListener('change', async () => {
  selectedGroup = elements.groupSelect.value;
  await loadGuests();
});
elements.rsvpForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  const form = new FormData(elements.rsvpForm);
  const payload = {
    availableDays: form.getAll('availableDays'),
    guestCount: Number(form.get('guestCount')),
    mealTypes: form.getAll('mealTypes'),
    restaurantChoice: form.get('restaurantChoice'),
    dietaryRestrictions: form.get('dietaryRestrictions'),
  };
  elements.sessionStatus.textContent = 'A guardar…';
  try {
    await put('/api/rsvp', payload);
    elements.sessionStatus.textContent = 'Disponibilidade guardada.';
  } catch { elements.sessionStatus.textContent = 'Não foi possível guardar. Confirma as opções e tenta novamente.'; }
});
elements.adminSettingsForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  const restaurantChoices = elements.adminRestaurants.value.split(/\r?\n/).map((choice) => choice.trim()).filter(Boolean);
  try {
    await put('/api/admin/settings', { restaurantChoices });
    elements.sessionStatus.textContent = 'Opções do evento guardadas.';
    await loadRsvpForm();
  } catch { elements.sessionStatus.textContent = 'Não foi possível guardar as opções do evento.'; }
});
elements.newContactForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  const form = new FormData(elements.newContactForm);
  elements.registrationStatus.textContent = 'A criar o pedido…';
  try {
    const result = await post('/api/contact/request', { name: form.get('name') });
    elements.newContactForm.hidden = true;
    elements.newContactQr.hidden = false;
    elements.newContactMessage.textContent = 'Pedido criado como “para adicionar”. Envia esta mensagem para o Antonio.';
    await QRCode.toCanvas(elements.newContactQrCanvas, result.whatsappUrl, { width: 228, margin: 1 });
  } catch (error) { elements.registrationStatus.textContent = readableError(error); }
});

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

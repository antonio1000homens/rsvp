import QRCode from 'qrcode';
import { startAuthentication, startRegistration } from '@simplewebauthn/browser';

const elements = {
  guestSection: document.querySelector('#guest-section'),
  guestList: document.querySelector('#guest-list'),
  guestSearch: document.querySelector('#guest-search'),
  groupPicker: document.querySelector('#group-picker'),
  groupSelect: document.querySelector('#group-select'),
  validatedContent: document.querySelector('#validated-content'),
  rsvpSummary: document.querySelector('#rsvp-summary'),
  rsvpSummaryNarrative: document.querySelector('#rsvp-summary-narrative'),
  rsvpSummaryTotal: document.querySelector('#rsvp-summary-total'),
  availabilityChart: document.querySelector('#availability-chart'),
  restaurantVotes: document.querySelector('#restaurant-votes'),
  rsvpSummaryPreferences: document.querySelector('#rsvp-summary-preferences'),
  captcha: document.querySelector('#captcha'),
  captchaStatus: document.querySelector('#captcha-status'),
  triviaForm: document.querySelector('#trivia-form'),
  triviaQuestion: document.querySelector('#trivia-question'),
  triviaAnswer: document.querySelector('#trivia-answer'),
  skipTrivia: document.querySelector('#skip-trivia'),
  triviaStatus: document.querySelector('#trivia-status'),
  flowSection: document.querySelector('#flow-section'),
  selectedName: document.querySelector('#selected-name'),
  status: document.querySelector('#status'),
  waitingIndicator: document.querySelector('#waiting-indicator'),
  credentialActions: document.querySelector('#credential-actions'),
  usePasskey: document.querySelector('#use-passkey'),
  usePassword: document.querySelector('#use-password'),
  passwordLoginForm: document.querySelector('#password-login-form'),
  passwordLoginInput: document.querySelector('#password-login-input'),
  passwordRecovery: document.querySelector('#password-recovery'),
  passwordLoginStatus: document.querySelector('#password-login-status'),
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
  toast: document.querySelector('#toast'),
  restaurantChoices: document.querySelector('#restaurant-choices'),
  adminSection: document.querySelector('#admin-section'),
  adminDates: document.querySelector('#admin-dates'),
  adminSettingsForm: document.querySelector('#admin-settings-form'),
  adminRestaurants: document.querySelector('#admin-restaurants'),
  adminTrivia: document.querySelector('#admin-trivia'),
  adminUseTrivia: document.querySelector('#admin-use-trivia'),
  adminSummaryForm: document.querySelector('#admin-summary-form'),
  adminSummary: document.querySelector('#admin-summary'),
  adminSummaryStatus: document.querySelector('#admin-summary-status'),
  adminGroups: document.querySelector('#admin-groups'),
  rsvpForm: document.querySelector('#rsvp-form'),
  whatsappRsvpForm: document.querySelector('#whatsapp-rsvp-form'),
  whatsappAvailabilityDays: document.querySelector('#whatsapp-availability-days'),
  whatsappRestaurantChoices: document.querySelector('#whatsapp-restaurant-choices'),
  availabilityDays: document.querySelector('#availability-days'),
  addPasskey: document.querySelector('#add-passkey'),
  passwordForm: document.querySelector('#password-form'),
  passwordNew: document.querySelector('#password-new'),
  passwordConfirm: document.querySelector('#password-confirm'),
  passwordRemove: document.querySelector('#password-remove'),
  passwordStatus: document.querySelector('#password-status'),
  logout: document.querySelector('#logout'),
  registrationStatus: document.querySelector('#registration-status'),
  newContactForm: document.querySelector('#new-contact-form'),
  toggleNewContact: document.querySelector('#toggle-new-contact'),
  newContactPanel: document.querySelector('#new-contact-panel'),
  newContactQr: document.querySelector('#new-contact-qr'),
  newContactMessage: document.querySelector('#new-contact-message'),
  newContactQrCanvas: document.querySelector('#new-contact-qr-canvas'),
  newContactWhatsappLink: document.querySelector('#new-contact-whatsapp-link'),
  linkSection: document.querySelector('#link-section'),
  linkTarget: document.querySelector('#link-target'),
  linkCreate: document.querySelector('#link-create'),
  linkStatus: document.querySelector('#link-status'),
  linkQr: document.querySelector('#link-qr'),
  linkWhatsapp: document.querySelector('#link-whatsapp'),
  linkCancel: document.querySelector('#link-cancel'),
};

let selectedGuest = null;
let selectedGroup = '';
let pollGeneration = 0;
let triviaChallenge = '';
let triviaToken = '';
let selectedAuthResult = null;
let toastTimer = null;

const showToast = (message) => {
  elements.toast.textContent = message;
  elements.toast.hidden = false;
  if (toastTimer) window.clearTimeout(toastTimer);
  toastTimer = window.setTimeout(() => {
    elements.toast.hidden = true;
    toastTimer = null;
  }, 3500);
};

const setWaiting = (waiting) => {
  elements.waitingIndicator.hidden = !waiting;
  elements.status.setAttribute('aria-busy', String(waiting));
};

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
const del = (path, payload = {}) => api(path, { method: 'DELETE', body: JSON.stringify(payload) });

const showAuthenticated = (nickname, message = '', passkeyLabel = 'Adicionar outra chave de acesso') => {
  pollGeneration += 1;
  setWaiting(false);
  elements.guestSection.hidden = true;
  elements.flowSection.hidden = true;
  elements.sessionSection.hidden = false;
  elements.sessionName.textContent = nickname;
  elements.sessionStatus.textContent = message;
  elements.passwordForm.reset();
  elements.addPasskey.textContent = passkeyLabel;
  loadRsvpForm();
  loadAdmin();
  loadRsvpSummary();
  loadLinkState();
};

const renderLinkState = async (state) => {
  elements.linkSection.hidden = false;
  elements.linkQr.hidden = true;
  elements.linkCancel.hidden = state.status === 'none';
  elements.linkTarget.hidden = state.status !== 'none';
  elements.linkCreate.hidden = state.status !== 'none';
  if (state.status === 'none') {
    elements.linkWhatsapp.hidden = true;
    elements.linkWhatsapp.removeAttribute('href');
    elements.linkStatus.textContent = 'Podes ligar a tua resposta à de outro membro.';
    return;
  }
  const otherName = state.other?.nickname || 'outro membro';
  if (state.status === 'pending') {
    elements.linkStatus.textContent = `Ligação pendente com ${otherName}. O membro seleccionado deve ler o QR e enviar a mensagem WhatsApp.`;
    elements.linkQr.hidden = false;
    elements.linkWhatsapp.hidden = false;
    elements.linkWhatsapp.href = state.whatsappUrl;
    await QRCode.toCanvas(elements.linkQr, state.whatsappUrl, { width: 228, margin: 1, errorCorrectionLevel: 'M' });
  } else {
    elements.linkWhatsapp.hidden = true;
    elements.linkStatus.textContent = `Ligado a ${otherName}. As respostas dos dois membros são mantidas em conjunto.`;
  }
};

const loadLinkState = async () => {
  try {
    const [{ candidates }, state] = await Promise.all([api('/api/link/candidates'), api('/api/link')]);
    elements.linkTarget.replaceChildren(new Option('Escolhe um membro', ''));
    for (const candidate of candidates) elements.linkTarget.add(new Option(candidate.nickname, candidate.id));
    await renderLinkState(state);
  } catch { elements.linkSection.hidden = true; }
};

const addNoAvailabilityOption = (container, noAvailability = false) => {
  const dates = [...container.querySelectorAll('input[name="availableDays"]')];
  const label = document.createElement('label');
  const checkbox = document.createElement('input');
  checkbox.type = 'checkbox'; checkbox.name = 'noAvailability'; checkbox.value = 'true';
  checkbox.checked = noAvailability || !dates.some((date) => date.checked);
  label.append(checkbox, ' Não posso em nenhuma data');
  container.append(label);
  const sync = () => {
    if (dates.some((date) => date.checked)) checkbox.checked = false;
    else checkbox.checked = true;
  };
  dates.forEach((date) => date.addEventListener('change', sync));
  checkbox.addEventListener('change', () => {
    if (checkbox.checked) dates.forEach((date) => { date.checked = false; });
    sync();
  });
};

const renderRestaurantChoices = (container, choices, selectedChoices = []) => {
  container.replaceChildren();
  const options = choices.length ? choices : ['Por decidir'];
  const selected = selectedChoices.length ? new Set(selectedChoices) : new Set([options[0]]);
  for (const choice of options) {
    const label = document.createElement('label');
    const checkbox = document.createElement('input');
    checkbox.type = 'checkbox'; checkbox.name = 'restaurantChoices'; checkbox.value = choice;
    checkbox.checked = selected.has(choice);
    label.append(checkbox, ` ${choice}`);
    container.append(label);
  }
};

const renderRsvpForm = ({ days, restaurantChoices, response }) => {
  elements.availabilityDays.replaceChildren();
  for (const day of days) {
    const label = document.createElement('label');
    const checkbox = document.createElement('input');
    checkbox.type = 'checkbox'; checkbox.name = 'availableDays'; checkbox.value = day;
    checkbox.checked = response?.availableDays?.includes(day) || false;
    label.append(checkbox, ` ${day}`);
    elements.availabilityDays.append(label);
  }
  addNoAvailabilityOption(elements.availabilityDays, response?.noAvailability === true);
  elements.rsvpForm.elements.guestCount.value = response?.guestCount || '';
  elements.rsvpForm.elements.preferenceType.value = response?.preferenceType || 'families';
  renderRestaurantChoices(elements.restaurantChoices, restaurantChoices || [], response?.restaurantChoices || []);
  elements.rsvpForm.elements.proposedRestaurantChoices.value = (response?.proposedRestaurantChoices || []).join('\n');
  elements.rsvpForm.elements.dietaryRestrictions.value = response?.dietaryRestrictions || '';
  for (const checkbox of elements.rsvpForm.querySelectorAll('input[name="mealTypes"]')) {
    checkbox.checked = response?.mealTypes?.includes(checkbox.value) || false;
  }
};

const renderWhatsappRsvpForm = ({ days, restaurantChoices }) => {
  elements.whatsappAvailabilityDays.replaceChildren();
  for (const day of days) {
    const label = document.createElement('label');
    const checkbox = document.createElement('input');
    checkbox.type = 'checkbox'; checkbox.name = 'availableDays'; checkbox.value = day;
    label.append(checkbox, ` ${day}`);
    elements.whatsappAvailabilityDays.append(label);
  }
  addNoAvailabilityOption(elements.whatsappAvailabilityDays);
  renderRestaurantChoices(elements.whatsappRestaurantChoices, restaurantChoices);
};

const hasMealType = (form) => form.querySelector('input[name="mealTypes"]:checked') !== null;

const openWhatsappRsvpForm = (config) => {
  renderWhatsappRsvpForm(config);
  elements.whatsappRsvpForm.hidden = false;
};

const loadRsvpForm = async () => {
  try {
    const data = await api('/api/rsvp');
    renderRsvpForm(data);
  } catch { elements.sessionStatus.textContent = 'Não foi possível carregar o RSVP.'; }
};

const loadAdmin = async () => {
  try {
    const settings = await api('/api/admin/settings');
    elements.adminSection.hidden = false;
    elements.adminDates.textContent = settings.days.join(' · ');
    elements.adminRestaurants.value = settings.restaurantChoices.join('\n');
    elements.adminTrivia.value = settings.triviaQuestions.map((item) => `${item.question} | ${item.answers.join(', ')}`).join('\n');
    elements.adminUseTrivia.checked = settings.useTrivia;
    const { groups } = await api('/api/admin/groups');
    elements.adminGroups.textContent = groups.length ? groups.map((group) => `${group.name}: ${group.members} membro(s)`).join(' · ') : 'Ainda não existem grupos.';
    const summary = await api('/api/admin/summary');
    elements.adminSummary.value = summary.narrative || '';
  } catch (error) {
    if (error.status !== 403) elements.adminSection.hidden = true;
  }
};

const loadRsvpSummary = async () => {
  try {
    const summary = await api('/api/rsvp/summary');
    elements.rsvpSummaryNarrative.textContent = summary.narrative || '';
    elements.rsvpSummaryNarrative.hidden = !summary.narrative;
    const maximum = Math.max(1, ...Object.values(summary.byDay));
    elements.availabilityChart.replaceChildren();
    for (const [day, count] of Object.entries(summary.byDay)) {
      const row = document.createElement('div');
      row.className = 'availability-row';
      const label = document.createElement('span'); label.textContent = day;
      const bar = document.createElement('span'); bar.className = 'availability-bar'; bar.style.setProperty('--availability', `${(count / maximum) * 100}%`); bar.textContent = `${count}`;
      row.append(label, bar); elements.availabilityChart.append(row);
      const voterNames = document.createElement('small');
      voterNames.className = 'vote-names';
      const voters = (summary.dayVoters || {})[day] || [];
      voterNames.textContent = voters.length ? voters.map(({ nickname, guestCount }) => guestCount > 1 ? `${nickname} (${guestCount})` : nickname).join(', ') : 'Ainda sem respostas';
      elements.availabilityChart.append(voterNames);
    }
    const restaurantCounts = summary.restaurants || {};
    const restaurantNames = summary.restaurantChoices?.length ? summary.restaurantChoices : Object.keys(restaurantCounts);
    const maximumRestaurant = Math.max(1, ...restaurantNames.map((name) => restaurantCounts[name] || 0));
    elements.restaurantVotes.replaceChildren();
    for (const name of restaurantNames) {
      const row = document.createElement('div');
      row.className = 'availability-row';
      const label = document.createElement('span'); label.textContent = name;
      const bar = document.createElement('span'); bar.className = 'availability-bar'; bar.style.setProperty('--availability', `${((restaurantCounts[name] || 0) / maximumRestaurant) * 100}%`); bar.textContent = `${restaurantCounts[name] || 0}`;
      row.append(label, bar); elements.restaurantVotes.append(row);
      const voters = (summary.restaurantVoters || {})[name] || [];
      const voterNames = document.createElement('small');
      voterNames.className = 'vote-names';
      voterNames.textContent = voters.length ? voters.map(({ nickname, guestCount }) => guestCount > 1 ? `${nickname} (${guestCount})` : nickname).join(', ') : 'Ainda sem votos';
      elements.restaurantVotes.append(voterNames);
    }
    elements.rsvpSummaryTotal.textContent = `${summary.guests} pessoa(s) em ${summary.responses} resposta(s).`;
    const mealLabels = { lunch: 'Almoço', dinner: 'Jantar', drinks: 'Copos' };
    const meals = Object.entries(summary.byMeal).filter(([, count]) => count).map(([meal, count]) => {
      const voters = (summary.mealVoters || {})[meal] || [];
      const names = voters.map(({ nickname, guestCount }) => guestCount > 1 ? `${nickname} (${guestCount})` : nickname).join(', ') || 'sem nomes';
      return `${mealLabels[meal] || meal}: ${count} — ${names}`;
    }).join(' · ');
    elements.rsvpSummaryPreferences.textContent = meals || 'Ainda sem preferências registadas.';
    elements.rsvpSummary.hidden = false;
  } catch { elements.rsvpSummary.hidden = true; }
};

const showFlow = () => {
  setWaiting(false);
  elements.guestSection.hidden = true;
  elements.sessionSection.hidden = true;
  elements.flowSection.hidden = false;
  elements.selectedName.textContent = selectedGuest?.nickname || 'Novo registo';
  elements.whatsappPanel.hidden = true;
  elements.actions.hidden = false;
  elements.createPasskey.hidden = true;
  elements.whatsappRsvpForm.hidden = true;
  elements.retryRegistration.hidden = true;
  elements.credentialActions.hidden = true;
  elements.usePasskey.hidden = true;
  elements.usePassword.hidden = true;
  elements.passwordLoginForm.hidden = true;
  elements.passwordLoginForm.querySelector('label').hidden = false;
  elements.passwordLoginInput.hidden = false;
  elements.passwordLoginForm.querySelector('button[type="submit"]').hidden = false;
  elements.passwordLoginStatus.textContent = '';
};

const showValidatedGuestSelection = () => {
  pollGeneration += 1;
  setWaiting(false);
  selectedGuest = null;
  elements.flowSection.hidden = true;
  elements.sessionSection.hidden = true;
  elements.guestSection.hidden = false;
  elements.captcha.hidden = true;
  elements.captchaStatus.hidden = true;
  elements.triviaForm.hidden = true;
  elements.triviaStatus.hidden = true;
  elements.validatedContent.hidden = false;
};

const showRegistrationWhatsapp = async (result) => {
  const generation = ++pollGeneration;
  elements.guestSection.hidden = true;
  elements.flowSection.hidden = false;
  elements.whatsappRsvpForm.hidden = true;
  elements.selectedName.textContent = selectedGuest?.nickname || 'Registo';
  elements.status.textContent = 'A aguardar a verificação pelo WhatsApp…';
  setWaiting(true);
  elements.whatsappPanel.hidden = false;
  elements.actions.hidden = true;
  elements.whatsappLink.href = result.whatsappUrl;
  await QRCode.toCanvas(elements.qrCode, result.whatsappUrl, { width: 228, margin: 1, errorCorrectionLevel: 'M', color: { dark: '#2d261fff', light: '#ffffffff' } });
  const poll = async () => {
    if (generation !== pollGeneration) return;
    try {
      const state = await api('/api/register/status');
      if (state.status === 'created') {
        setWaiting(false);
        elements.whatsappPanel.hidden = true;
        if (result.mode === 'retrieve') {
          showAuthenticated(selectedGuest?.nickname || 'Registo', 'Já tinhas enviado uma resposta. As tuas escolhas foram carregadas; podes revê-las ou editá-las. Cria uma chave de acesso para voltares mais facilmente.', 'Criar uma chave de acesso');
          return;
        }
        if (result.mode === 'recover') {
          showAuthenticated(selectedGuest?.nickname || 'Registo', 'WhatsApp confirmado. Podes agora criar uma palavra-passe ou adicionar uma chave de acesso.');
          return;
        }
        elements.status.textContent = 'Disponibilidade recebida. Quer criar uma chave de acesso para editar a resposta?';
        elements.actions.hidden = false;
        elements.createPasskey.hidden = false;
        return;
      }
      if (state.status === 'sender_mismatch') {
        setWaiting(false);
        elements.whatsappPanel.hidden = true;
        elements.status.textContent = 'Contacto WhatsApp não corresponde ao nome escolhido. Escolhe outro nome.';
        showValidatedGuestSelection();
        return;
      }
      if (state.status === 'expired') { setWaiting(false); elements.status.textContent = 'Este registo expirou. Tente novamente.'; elements.whatsappPanel.hidden = true; elements.guestSection.hidden = false; return; }
    } catch { setWaiting(false); elements.status.textContent = 'O estado da verificação está temporariamente indisponível. Tente novamente.'; return; }
    window.setTimeout(poll, document.hidden ? 10000 : 3000);
  };
  window.setTimeout(poll, 3000);
};

const startGuestRegistration = async (mode = 'register') => {
  elements.registrationStatus.textContent = 'A preparar a verificação pelo WhatsApp…';
  try {
    await showRegistrationWhatsapp(await post('/api/rsvp/whatsapp/start', mode === 'retrieve' || mode === 'recover'
      ? { guestId: selectedGuest.id, mode }
      : { guestId: selectedGuest.id }));
  } catch (error) { elements.registrationStatus.textContent = readableError(error); }
};

elements.retryRegistration.addEventListener('click', () => startGuestRegistration());

const readableError = (error) => {
  if (error.name === 'NotAllowedError') return 'A utilização da chave de acesso foi cancelada ou expirou.';
  if (error.code === 'whatsapp_unavailable') return 'O início de sessão pelo WhatsApp ainda não está configurado.';
  if (error.code === 'authentication_challenge_expired') return 'Esta tentativa de início de sessão expirou. Tente novamente.';
  if (error.code === 'passkey_verification_failed') return 'Não foi possível verificar essa chave de acesso.';
  if (error.code === 'password_verification_failed') return 'Palavra-passe incorreta. Podes recuperar pelo WhatsApp.';
  if (error.code === 'password_confirmation_mismatch') return 'As palavras-passe não coincidem.';
  if (error.code === 'invalid_password') return 'A palavra-passe deve ter entre 8 e 128 caracteres.';
  if (error.code === 'password_not_configured') return 'Este nome ainda não tem palavra-passe configurada.';
  if (error.code === 'registration_required') return 'Este contacto precisa de concluir o registo.';
  if (error.code === 'registration_already_pending') return 'Já existe uma validação WhatsApp pendente para este contacto. Continua a utilizar a mensagem anterior.';
  if (error.code === 'invalid_link_target') return 'Esse membro não pode ser ligado.';
  if (error.code === 'member_already_linked') return 'Um dos membros já tem uma ligação pendente ou activa.';
  if (error.code === 'link_not_found') return 'A ligação já não existe.';
  if (error.code === 'registration_not_required') return 'Este contacto já está registado.';
  if (error.code === 'passkey_required') return 'Este contacto já está confirmado, mas ainda não tem uma chave de acesso configurada.';
  if (error.code === 'registration_unavailable') return 'Esse nome ou contacto já está registado.';
  if (error.code === 'sender_mismatch') return 'Não consegui verificar o contacto. Verifica o nome ou se estás a usar o WhatsApp da conta certa.';
  if (error.code === 'invalid_contact_details') return 'Indica um nickname válido.';
  if (error.code === 'invalid_availability') return 'Seleciona pelo menos um dia disponível.';
  if (error.code === 'invalid_meal_types') return 'Seleciona pelo menos uma preferência: almoço, jantar ou copos.';
  if (error.code === 'invalid_guest_count') return 'Indica quantas pessoas participam.';
  if (error.code === 'invalid_preference_type') return 'Seleciona uma preferência válida: 18+, +1s ou Famílias.';
  if (error.code === 'invalid_preferences' || error.code === 'invalid_restaurant_choice') return 'Seleciona uma escolha de restaurante válida.';
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
    if (!selectedAuthResult?.methods?.password) {
      elements.passwordLoginForm.querySelector('label').hidden = true;
      elements.passwordLoginInput.hidden = true;
      elements.passwordLoginForm.querySelector('button[type="submit"]').hidden = true;
      elements.passwordLoginStatus.textContent = 'Podes recuperar o acesso pelo WhatsApp.';
    }
    elements.passwordLoginForm.hidden = false;
  }
};

const showPasswordLogin = () => {
  elements.credentialActions.hidden = true;
  elements.passwordLoginForm.hidden = false;
  elements.passwordLoginInput.focus();
};

const loginWithPassword = async (event) => {
  event.preventDefault();
  elements.passwordLoginStatus.textContent = 'A verificar…';
  try {
    const result = await post('/api/auth/password/login', { guestId: selectedGuest.id, password: elements.passwordLoginInput.value });
    showAuthenticated(result.nickname);
  } catch (error) {
    elements.passwordLoginStatus.textContent = readableError(error);
  }
};

const selectGuest = async (guest) => {
  selectedGuest = guest;
  pollGeneration += 1;
  showFlow();
  elements.status.textContent = 'A verificar o seu convite…';
  try {
    const result = await post('/api/auth/start', { guestId: guest.id });
    selectedAuthResult = result;
    if (result.mode === 'passkey') await usePasskey(result.options);
    if (result.mode === 'password') showPasswordLogin();
    if (result.mode === 'credentials') {
      elements.credentialActions.hidden = false;
      elements.usePasskey.hidden = !result.methods.passkey;
      elements.usePassword.hidden = !result.methods.password;
    }
    if (result.mode === 'whatsapp-rsvp') {
      elements.status.textContent = 'Preencha a disponibilidade para continuar.';
      openWhatsappRsvpForm(result);
    }
    if (result.mode === 'whatsapp-retrieve') {
      elements.status.textContent = 'Já existe uma resposta para este nome. Confirma o teu WhatsApp para carregar as escolhas anteriores.';
      await startGuestRegistration('retrieve');
    }
  } catch (error) {
    elements.status.textContent = readableError(error);
  }
};

const loadGuests = async (turnstileToken = '', query = elements.guestSearch.value.trim()) => {
  elements.guestList.replaceChildren();
  if (!query) {
    elements.guestList.textContent = 'Começa a escrever para procurar o teu nome.';
    return;
  }
  try {
    const params = new URLSearchParams();
    if (selectedGroup) params.set('group', selectedGroup);
    params.set('q', query);
    const path = `/api/guests?${params}`;
    const { guests } = await api(path, turnstileToken
      ? { headers: { 'x-turnstile-token': turnstileToken } }
      : {});
    if (guests.length === 0) {
      elements.guestList.textContent = 'Ainda não existem convites disponíveis.';
      return;
    }
    for (const guest of guests) {
      if (guest.members) {
        const pair = document.createElement('div');
        pair.className = 'linked-guest';
        const label = document.createElement('strong'); label.textContent = guest.nickname;
        pair.append(label);
        for (const member of guest.members) {
          const button = document.createElement('button');
          button.type = 'button'; button.className = 'guest-button'; button.textContent = `Entrar como ${member.nickname}`;
          button.addEventListener('click', () => selectGuest(member));
          pair.append(button);
        }
        elements.guestList.append(pair);
      } else {
        const button = document.createElement('button');
        button.type = 'button'; button.className = 'guest-button'; button.textContent = guest.nickname;
        button.addEventListener('click', () => selectGuest(guest));
        elements.guestList.append(button);
      }
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
    elements.triviaStatus.textContent = '';
    elements.triviaAnswer.value = '';
    const result = await api('/api/trivia/question', {
      headers: { 'x-turnstile-token': turnstileToken },
    });
    if (result.enabled === false) {
      await completeValidation();
      return;
    }
    triviaChallenge = result.challenge;
    elements.triviaQuestion.textContent = result.question;
    elements.triviaForm.hidden = false;
    elements.triviaAnswer.focus();
  } catch {
    elements.triviaStatus.textContent = 'Não foi possível carregar a pergunta; pode continuar para a lista.';
    await completeValidation();
  }
};

const completeValidation = async () => {
  elements.captcha.hidden = true;
  elements.captchaStatus.hidden = true;
  elements.triviaForm.hidden = true;
  elements.triviaStatus.hidden = true;
  elements.validatedContent.hidden = false;
  elements.newContactForm.hidden = false;
  elements.guestSearch.value = '';
  elements.guestSearch.focus();
  elements.guestList.textContent = 'Começa a escrever para procurar o teu nome.';
  await loadGroups();
};

const answerTrivia = async (event) => {
  event.preventDefault();
  elements.triviaStatus.textContent = 'A validar a resposta…';
  try {
    await post('/api/trivia/answer', { challenge: triviaChallenge, answer: elements.triviaAnswer.value });
    elements.triviaStatus.textContent = '';
    await completeValidation();
  } catch (error) {
    elements.triviaStatus.textContent = error.code === 'trivia_incorrect'
      ? 'Resposta incorreta. Tenta novamente ou escolhe “Não sei”.'
      : 'Não foi possível validar a resposta. Tente novamente.';
  }
};

const skipTrivia = async () => {
  elements.skipTrivia.disabled = true;
  await loadTriviaQuestion(triviaToken);
  elements.skipTrivia.disabled = false;
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
        elements.captchaStatus.textContent = '';
        await loadTriviaQuestion(token);
        resolve();
      },
      'expired-callback': () => {
        elements.captcha.hidden = false;
        elements.captchaStatus.hidden = false;
        elements.triviaStatus.hidden = false;
        elements.captchaStatus.textContent = 'A verificação de segurança expirou. Conclua-a novamente.';
        elements.guestList.replaceChildren();
        elements.validatedContent.hidden = true;
        elements.rsvpSummary.hidden = true;
      },
      'error-callback': () => {
        elements.captchaStatus.textContent = 'Não foi possível carregar a verificação de segurança. Tente novamente mais tarde.';
        resolve();
      },
    });
  });
};

elements.backButton.addEventListener('click', () => {
  showValidatedGuestSelection();
});
elements.usePasskey.addEventListener('click', () => usePasskey(selectedAuthResult.options));
elements.usePassword.addEventListener('click', showPasswordLogin);
elements.passwordLoginForm.addEventListener('submit', loginWithPassword);
elements.passwordRecovery.addEventListener('click', () => startGuestRegistration('recover'));
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
elements.skipTrivia.addEventListener('click', skipTrivia);
elements.toggleNewContact.addEventListener('click', () => {
  elements.newContactPanel.hidden = !elements.newContactPanel.hidden;
  elements.toggleNewContact.textContent = elements.newContactPanel.hidden
    ? 'Não encontro o meu nome'
    : 'Esconder formulário';
});
elements.groupSelect.addEventListener('change', async () => {
  selectedGroup = elements.groupSelect.value;
  elements.guestSearch.value = '';
  await loadGuests('', '');
});
elements.guestSearch.addEventListener('input', async () => {
  await loadGuests('', elements.guestSearch.value.trim());
});
elements.rsvpForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  if (!hasMealType(elements.rsvpForm)) {
    elements.sessionStatus.textContent = 'Seleciona pelo menos uma preferência: almoço, jantar ou copos.';
    return;
  }
  const form = new FormData(elements.rsvpForm);
  const payload = {
    availableDays: form.getAll('availableDays'),
    noAvailability: form.get('noAvailability') === 'true',
    guestCount: Number(form.get('guestCount')),
    mealTypes: form.getAll('mealTypes'),
    restaurantChoices: form.getAll('restaurantChoices'),
    proposedRestaurantChoices: form.get('proposedRestaurantChoices').split(/\r?\n/).map((choice) => choice.trim()).filter(Boolean),
    preferenceType: form.get('preferenceType'),
    dietaryRestrictions: form.get('dietaryRestrictions'),
  };
  elements.sessionStatus.textContent = 'A guardar…';
  try {
    await put('/api/rsvp', payload);
    elements.sessionStatus.textContent = '';
    showToast('Disponibilidade guardada.');
  } catch { elements.sessionStatus.textContent = 'Não foi possível guardar. Confirma as opções e tenta novamente.'; }
});
elements.whatsappRsvpForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  if (!hasMealType(elements.whatsappRsvpForm)) {
    elements.status.textContent = 'Seleciona pelo menos uma preferência: almoço, jantar ou copos.';
    return;
  }
  const form = new FormData(elements.whatsappRsvpForm);
  const payload = {
    availableDays: form.getAll('availableDays'), guestCount: Number(form.get('guestCount')),
    noAvailability: form.get('noAvailability') === 'true',
    mealTypes: form.getAll('mealTypes'), restaurantChoices: form.getAll('restaurantChoices'), preferenceType: form.get('preferenceType'),
    proposedRestaurantChoices: form.get('proposedRestaurantChoices').split(/\r?\n/).map((choice) => choice.trim()).filter(Boolean),
    dietaryRestrictions: form.get('dietaryRestrictions'),
  };
  try {
    await showRegistrationWhatsapp(await post('/api/rsvp/whatsapp/start', { guestId: selectedGuest.id, ...payload }));
  } catch (error) { elements.status.textContent = readableError(error); }
});
elements.adminSettingsForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  const restaurantChoices = elements.adminRestaurants.value.split(/\r?\n/).map((choice) => choice.trim()).filter(Boolean);
  try {
    const triviaQuestions = elements.adminTrivia.value.split(/\r?\n/).filter(Boolean).map((line) => {
      const separator = line.indexOf('|');
      if (separator < 1) throw new Error('invalid_trivia_questions');
      return { question: line.slice(0, separator).trim(), answers: line.slice(separator + 1).split(',').map((answer) => answer.trim()).filter(Boolean) };
    });
    await put('/api/admin/settings', { restaurantChoices, triviaQuestions, useTrivia: elements.adminUseTrivia.checked });
    elements.sessionStatus.textContent = 'Opções do evento guardadas.';
    await loadRsvpForm();
  } catch { elements.sessionStatus.textContent = 'Não foi possível guardar as opções do evento. Confirma o formato das perguntas.'; }
});
elements.adminSummaryForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  elements.adminSummaryStatus.textContent = 'A guardar…';
  try {
    await put('/api/admin/summary', { narrative: elements.adminSummary.value });
    elements.adminSummaryStatus.textContent = 'Comentário guardado.';
  } catch (error) {
    elements.adminSummaryStatus.textContent = readableError(error);
  }
});
elements.linkCreate.addEventListener('click', async () => {
  if (!elements.linkTarget.value) { elements.linkStatus.textContent = 'Escolhe primeiro o membro a ligar.'; return; }
  elements.linkCreate.disabled = true;
  try { await renderLinkState(await post('/api/link', { targetGuestId: elements.linkTarget.value })); }
  catch (error) { elements.linkStatus.textContent = readableError(error); }
  finally { elements.linkCreate.disabled = false; }
});
elements.linkCancel.addEventListener('click', async () => {
  elements.linkCancel.disabled = true;
  try { await renderLinkState(await del('/api/link')); }
  catch (error) { elements.linkStatus.textContent = readableError(error); }
  finally { elements.linkCancel.disabled = false; }
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
    elements.newContactWhatsappLink.href = result.whatsappUrl;
    await QRCode.toCanvas(elements.newContactQrCanvas, result.whatsappUrl, { width: 228, margin: 1 });
  } catch (error) { elements.registrationStatus.textContent = readableError(error); }
});

elements.passwordForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  elements.passwordStatus.textContent = 'A guardar…';
  try {
    await post('/api/auth/password', { password: elements.passwordNew.value, confirmPassword: elements.passwordConfirm.value });
    elements.passwordForm.reset();
    elements.passwordStatus.textContent = 'Palavra-passe guardada.';
  } catch (error) { elements.passwordStatus.textContent = readableError(error); }
});
elements.passwordRemove.addEventListener('click', async () => {
  elements.passwordStatus.textContent = 'A remover…';
  try {
    await del('/api/auth/password');
    elements.passwordStatus.textContent = 'Palavra-passe removida.';
  } catch (error) { elements.passwordStatus.textContent = readableError(error); }
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

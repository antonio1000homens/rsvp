import QRCode from 'qrcode';
import { startAuthentication, startRegistration } from '@simplewebauthn/browser';

const elements = {
  guestSection: document.querySelector('#guest-section'),
  guestHeading: document.querySelector('#guest-heading'),
  guestHeadingIntro: document.querySelector('#guest-heading-intro'),
  guestList: document.querySelector('#guest-list'),
  guestSearch: document.querySelector('#guest-search'),
  guestStatusFilters: [...document.querySelectorAll('input[name="guest-status"]')],
  groupPicker: document.querySelector('#group-picker'),
  groupSelect: document.querySelector('#group-select'),
  validatedContent: document.querySelector('#validated-content'),
  rsvpSummary: document.querySelector('#rsvp-summary'),
  rsvpSummaryNarrative: document.querySelector('#rsvp-summary-narrative'),
  rsvpSummaryTotal: document.querySelector('#rsvp-summary-total'),
  availabilityChart: document.querySelector('#availability-chart'),
  restaurantVotes: document.querySelector('#restaurant-votes'),
  restaurantSummaryHeading: document.querySelector('#restaurant-summary-heading'),
  includedRestaurants: document.querySelector('#included-restaurants'),
  whatsappIncludedRestaurants: document.querySelector('#whatsapp-included-restaurants'),
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
  reportValidationMismatch: document.querySelector('#report-validation-mismatch'),
  validationReportPanel: document.querySelector('#validation-report-panel'),
  validationReportQr: document.querySelector('#validation-report-qr'),
  validationReportWhatsapp: document.querySelector('#validation-report-whatsapp'),
  backButton: document.querySelector('#back-button'),
  sessionSection: document.querySelector('#session-section'),
  sessionIntro: document.querySelector('#session-intro'),
  editResponseSection: document.querySelector('#edit-response-section'),
  sessionName: document.querySelector('#session-name'),
  sessionStatus: document.querySelector('#session-status'),
  toast: document.querySelector('#toast'),
  roundCountdown: document.querySelector('#round-countdown-value'),
  restaurantChoices: document.querySelector('#restaurant-choices'),
  adminSection: document.querySelector('#admin-section'),
  adminDates: document.querySelector('#admin-dates'),
  adminSettingsForm: document.querySelector('#admin-settings-form'),
  adminRestaurants: document.querySelector('#admin-restaurants'),
  adminTrivia: document.querySelector('#admin-trivia'),
  adminUseTrivia: document.querySelector('#admin-use-trivia'),
  adminUseWhatsappVerification: document.querySelector('#admin-use-whatsapp-verification'),
  adminSummaryForm: document.querySelector('#admin-summary-form'),
  adminSummary: document.querySelector('#admin-summary'),
  adminSummaryStatus: document.querySelector('#admin-summary-status'),
  adminGuestForm: document.querySelector('#admin-guest-form'),
  adminGuestSelect: document.querySelector('#admin-guest-select'),
  adminGuestSearch: document.querySelector('#admin-guest-search'),
  adminGuestGrid: document.querySelector('#admin-guest-grid'),
  adminGuestNickname: document.querySelector('#admin-guest-nickname'),
  adminGuestSender: document.querySelector('#admin-guest-sender'),
  adminGuestStatus: document.querySelector('#admin-guest-status'),
  adminRegistrationStatus: document.querySelector('#admin-registration-status'),
  adminRefreshGuestStatus: document.querySelector('#admin-refresh-guest-status'),
  adminResetGuestVote: document.querySelector('#admin-reset-guest-vote'),
  adminGuestAccessLink: document.querySelector('#admin-guest-access-link'),
  adminGuestAccessLinkValue: document.querySelector('#admin-guest-access-link-value'),
  adminCopyGuestAccessLink: document.querySelector('#admin-copy-guest-access-link'),
  adminShareGuestAccessLink: document.querySelector('#admin-share-guest-access-link'),
  adminGuestAccessLinkQr: document.querySelector('#admin-guest-access-link-qr'),
  adminReissueRegistration: document.querySelector('#admin-reissue-registration'),
  adminRecoverRegistration: document.querySelector('#admin-recover-registration'),
  adminReissueRegistrationValue: document.querySelector('#admin-reissue-registration-value'),
  adminCopyReissueRegistration: document.querySelector('#admin-copy-reissue-registration'),
  adminShareReissueRegistration: document.querySelector('#admin-share-reissue-registration'),
  adminReissueRegistrationQr: document.querySelector('#admin-reissue-registration-qr'),
  adminAddGuestForm: document.querySelector('#admin-add-guest-form'),
  adminNewGuestNickname: document.querySelector('#admin-new-guest-nickname'),
  adminNewGuestSender: document.querySelector('#admin-new-guest-sender'),
  adminAddGuestStatus: document.querySelector('#admin-add-guest-status'),
  adminRemoveGuest: document.querySelector('#admin-remove-guest'),
  adminGroups: document.querySelector('#admin-groups'),
  rsvpForm: document.querySelector('#rsvp-form'),
  whatsappRsvpForm: document.querySelector('#whatsapp-rsvp-form'),
  whatsappAvailabilityDays: document.querySelector('#whatsapp-availability-days'),
  whatsappRestaurantChoices: document.querySelector('#whatsapp-restaurant-choices'),
  availabilityDays: document.querySelector('#availability-days'),
  addPasskey: document.querySelector('#add-passkey'),
  openPassword: document.querySelector('#open-password'),
  profileDetails: document.querySelector('#profile-details'),
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

const updateRoundCountdown = () => {
  const remaining = new Date('2026-08-20T23:59:59+01:00').getTime() - Date.now();
  if (remaining <= 0) { elements.roundCountdown.textContent = 'Ronda 1 encerrada'; return; }
  const totalSeconds = Math.floor(remaining / 1000);
  const days = Math.floor(totalSeconds / 86400);
  const hours = Math.floor((totalSeconds % 86400) / 3600);
  const minutes = Math.floor((totalSeconds % 3600) / 60);
  const seconds = totalSeconds % 60;
  elements.roundCountdown.textContent = `${days}d ${String(hours).padStart(2, '0')}h ${String(minutes).padStart(2, '0')}m ${String(seconds).padStart(2, '0')}s`;
};
updateRoundCountdown();
window.setInterval(updateRoundCountdown, 1000);

let selectedGuest = null;
let selectedGroup = '';
let pollGeneration = 0;
let triviaChallenge = '';
let triviaToken = '';
let selectedAuthResult = null;
let toastTimer = null;
let guestSearchTimer = null;
let guestLookupGeneration = 0;

const showToast = (message) => {
  elements.toast.textContent = message;
  elements.toast.hidden = false;
  if (toastTimer) window.clearTimeout(toastTimer);
  toastTimer = window.setTimeout(() => {
    elements.toast.hidden = true;
    toastTimer = null;
  }, 3000);
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
    if (response.status === 401 && ['authentication_required', 'session_expired'].includes(body.error)) {
      if (!window.__rsvpSessionReloading) {
        window.__rsvpSessionReloading = true;
        window.location.reload();
      }
      await new Promise(() => {});
    }
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

const showAuthenticated = (nickname, message = '', passkeyLabel = 'Criar chave de acesso') => {
  pollGeneration += 1;
  setWaiting(false);
  elements.guestSection.hidden = true;
  elements.flowSection.hidden = true;
  elements.sessionSection.hidden = false;
  elements.sessionIntro.hidden = false;
  elements.editResponseSection.hidden = false;
  elements.sessionName.textContent = nickname;
  elements.sessionStatus.textContent = message;
  elements.passwordForm.reset();
  elements.addPasskey.textContent = passkeyLabel;
  elements.credentialActions.hidden = true;
  elements.addPasskey.hidden = true;
  elements.openPassword.hidden = true;
  void api('/api/session').then((session) => {
    if (!session.authenticated) return;
    elements.addPasskey.hidden = Boolean(session.methods?.passkey);
    elements.openPassword.hidden = Boolean(session.methods?.password);
    elements.addPasskey.textContent = session.methods?.passkey ? 'Adicionar outra chave de acesso' : 'Criar chave de acesso';
  }).catch(() => {
    elements.addPasskey.hidden = false;
    elements.openPassword.hidden = false;
  });
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
  elements.includedRestaurants.textContent = restaurantChoices?.length
    ? `Já incluídos: ${restaurantChoices.join(', ')}. Não os repitas na sugestão.`
    : 'Ainda não existem restaurantes incluídos.';
  elements.rsvpForm.elements.proposedRestaurantChoices.value = (response?.proposedRestaurantChoices || []).join('\n');
  for (const radio of elements.rsvpForm.querySelectorAll('input[name="mealPreference"]')) {
    radio.checked = (response?.mealPreference || response?.mealTypes?.[0]) === radio.value;
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
  elements.whatsappIncludedRestaurants.textContent = restaurantChoices?.length
    ? `Já incluídos: ${restaurantChoices.join(', ')}. Não os repitas na sugestão.`
    : 'Ainda não existem restaurantes incluídos.';
};

const hasMealPreference = (form) => form.querySelector('input[name="mealPreference"]:checked') !== null;

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
    elements.adminUseWhatsappVerification.checked = settings.useWhatsappVerification !== false;
    const { groups } = await api('/api/admin/groups');
    elements.adminGroups.textContent = groups.length ? groups.map((group) => `${group.name}: ${group.members} membro(s)`).join(' · ') : 'Ainda não existem grupos.';
    const summary = await api('/api/admin/summary');
    elements.adminSummary.value = summary.narrative || '';
    await loadAdminGuests();
  } catch (error) {
    if (error.status !== 403) elements.adminSection.hidden = true;
  }
};

const adminShareUrl = (link) => `https://wa.me/?text=${encodeURIComponent(link)}`;

const formatAdminTimestamp = (value) => new Intl.DateTimeFormat('pt-PT', {
  dateStyle: 'short', timeStyle: 'short',
}).format(new Date(Number(value) * 1000));

const renderAdminGuest = (guest) => {
  if (!guest) {
    elements.adminRegistrationStatus.textContent = '';
    return;
  }
  elements.adminGuestNickname.value = guest.nickname;
  elements.adminGuestSender.value = guest.sender;
  if (guest.pendingRegistration) {
    const expires = guest.validationExpiresAt ? ` até ${formatAdminTimestamp(guest.validationExpiresAt)}` : '';
    elements.adminRegistrationStatus.textContent = `Validação WhatsApp pendente${expires}. Podes gerar um novo QR se for necessário.`;
  } else if (guest.lastRegistrationApprovedAt) {
    elements.adminRegistrationStatus.textContent = `WhatsApp confirmado em ${formatAdminTimestamp(guest.lastRegistrationApprovedAt)}. Gera um link seguro para o convidado criar uma palavra-passe ou chave de acesso.`;
  } else {
    elements.adminRegistrationStatus.textContent = 'Não existe uma validação WhatsApp pendente.';
  }
};

const selectedAdminGuestId = () => elements.adminGuestSelect.value;

const renderAdminGuestGrid = () => {
  const guests = elements.adminGuestSelect._guests || [];
  const query = elements.adminGuestSearch.value.trim().toLocaleLowerCase();
  const visible = guests.filter((guest) => `${guest.nickname} ${guest.sender || ''}`.toLocaleLowerCase().includes(query));
  if (!visible.length) {
    elements.adminGuestGrid.replaceChildren(Object.assign(document.createElement('p'), { className: 'empty', textContent: 'Nenhum convidado encontrado.' }));
    return;
  }
  elements.adminGuestGrid.replaceChildren(...visible.map((guest) => {
    const button = document.createElement('button');
    button.type = 'button';
    button.role = 'option';
    button.dataset.guestId = guest.id;
    button.setAttribute('aria-selected', String(guest.id === selectedAdminGuestId()));
    button.textContent = guest.nickname;
    button.title = guest.sender ? `WhatsApp: ${guest.sender}` : 'Sem remetente WhatsApp';
    return button;
  }));
};

const hideAdminGuestLinks = () => {
  elements.adminGuestAccessLinkValue.hidden = true;
  elements.adminCopyGuestAccessLink.hidden = true;
  elements.adminShareGuestAccessLink.hidden = true;
  elements.adminGuestAccessLinkQr.hidden = true;
  elements.adminReissueRegistrationValue.hidden = true;
  elements.adminCopyReissueRegistration.hidden = true;
  elements.adminShareReissueRegistration.hidden = true;
  elements.adminReissueRegistrationQr.hidden = true;
};

const loadAdminGuests = async () => {
  const selectedGuestId = selectedAdminGuestId();
  const { guests } = await api('/api/admin/guests');
  elements.adminGuestSelect.replaceChildren(...guests.map((guest) => new Option(`${guest.nickname} (${guest.sender || 'sem remetente'})`, guest.id)));
  const selected = guests.find((guest) => guest.id === selectedGuestId) || guests[0];
  if (selected) elements.adminGuestSelect.value = selected.id;
  elements.adminGuestSelect._guests = guests;
  renderAdminGuestGrid();
  elements.adminRemoveGuest.disabled = !selected;
  renderAdminGuest(selected);
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
    elements.restaurantSummaryHeading.hidden = restaurantNames.length === 0;
    for (const name of restaurantNames) {
      const row = document.createElement('div');
      row.className = 'availability-row';
      const label = document.createElement('span'); label.textContent = name;
      const bar = document.createElement('span'); bar.className = 'availability-bar'; bar.style.setProperty('--availability', `${((restaurantCounts[name] || 0) / maximumRestaurant) * 100}%`); bar.textContent = `${restaurantCounts[name] || 0}`;
      row.append(label, bar); elements.restaurantVotes.append(row);
      const voters = (summary.restaurantVoters || {})[name] || [];
      const voterNames = document.createElement('small');
      voterNames.className = 'vote-names';
      voterNames.textContent = voters.length ? voters.map(({ nickname, guestCount }) => guestCount > 1 ? `${nickname} (${guestCount})` : nickname).join(', ') : 'votos na Proxima ronda';
      elements.restaurantVotes.append(voterNames);
    }
    elements.rsvpSummaryTotal.textContent = `${summary.guests} pessoa(s) em ${summary.responses} resposta(s).`;
    const mealLabels = { lunch: 'Almoço', dinner: 'Jantar', drinks: 'Só copos', any: 'Qualquer uma das opções' };
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
  elements.rsvpSummary.hidden = true;
  elements.sessionSection.hidden = true;
  elements.sessionIntro.hidden = true;
  elements.editResponseSection.hidden = true;
  elements.flowSection.hidden = false;
  elements.selectedName.textContent = selectedGuest?.nickname || 'Novo registo';
  elements.whatsappPanel.hidden = true;
  elements.actions.hidden = false;
  elements.createPasskey.hidden = true;
  elements.whatsappRsvpForm.hidden = true;
  elements.retryRegistration.hidden = true;
  elements.credentialActions.hidden = true;
  elements.usePasskey.disabled = true;
  elements.usePassword.disabled = true;
  elements.passwordLoginForm.hidden = true;
  elements.passwordLoginForm.querySelector('label').hidden = false;
  elements.passwordLoginInput.hidden = false;
  elements.passwordLoginForm.querySelector('button[type="submit"]').hidden = false;
  elements.passwordLoginStatus.textContent = '';
  window.requestAnimationFrame(() => elements.flowSection.scrollIntoView({ block: 'start' }));
};

const showValidatedGuestSelection = () => {
  pollGeneration += 1;
  setWaiting(false);
  selectedGuest = null;
  elements.flowSection.hidden = true;
  elements.sessionSection.hidden = true;
  elements.sessionIntro.hidden = true;
  elements.editResponseSection.hidden = true;
  elements.guestSection.hidden = false;
  elements.captcha.hidden = true;
  elements.captchaStatus.hidden = true;
  elements.triviaForm.hidden = true;
  elements.triviaStatus.hidden = true;
  elements.validatedContent.hidden = false;
  elements.validationReportPanel.hidden = true;
  elements.reportValidationMismatch.hidden = true;
  loadRsvpSummary();
};

const showRegistrationWhatsapp = async (result) => {
  if (result.mode === 'bypass') {
    showAuthenticated(selectedGuest?.nickname || 'Registo', 'Disponibilidade guardada. A verificação WhatsApp está temporariamente desativada.');
    return;
  }
  const generation = ++pollGeneration;
  elements.guestSection.hidden = true;
  elements.flowSection.hidden = false;
  elements.whatsappRsvpForm.hidden = true;
  elements.selectedName.textContent = selectedGuest?.nickname || 'Registo';
  elements.status.textContent = 'A aguardar a verificação pelo WhatsApp…';
  setWaiting(true);
  elements.whatsappPanel.hidden = false;
  elements.actions.hidden = true;
  elements.reportValidationMismatch.hidden = true;
  elements.validationReportPanel.hidden = true;
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
        showAuthenticated(selectedGuest?.nickname || 'Registo', 'Disponibilidade guardada. Podes criar uma chave de acesso e/ou uma palavra-passe para voltar a entrar.');
        return;
      }
      if (state.status === 'sender_mismatch') {
        setWaiting(false);
        elements.whatsappPanel.hidden = true;
        const mismatchMessage = 'O nome do contacto WhatsApp não corresponde ao convidado escolhido. Confirma o contacto e tenta novamente.';
        elements.status.textContent = mismatchMessage;
        showToast(mismatchMessage);
        elements.actions.hidden = false;
        elements.retryRegistration.hidden = false;
        elements.reportValidationMismatch.hidden = false;
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

elements.retryRegistration.addEventListener('click', async () => {
  elements.registrationStatus.textContent = 'A preparar novamente a verificação pelo WhatsApp…';
  try { await showRegistrationWhatsapp(await post('/api/rsvp/whatsapp/start', { guestId: selectedGuest.id, retry: true })); }
  catch (error) { elements.registrationStatus.textContent = readableError(error); }
});
elements.reportValidationMismatch.addEventListener('click', async () => {
  elements.reportValidationMismatch.disabled = true;
  try {
    const result = await post('/api/rsvp/validation-report');
    elements.validationReportWhatsapp.href = result.whatsappUrl;
    elements.validationReportPanel.hidden = false;
    await QRCode.toCanvas(elements.validationReportQr, result.whatsappUrl, { width: 228, margin: 1, errorCorrectionLevel: 'M' });
  } catch (error) {
    showToast('Não foi possível preparar o aviso. Tenta novamente.');
  } finally { elements.reportValidationMismatch.disabled = false; }
});

const readableError = (error) => {
  if (error.name === 'NotAllowedError') return 'A utilização da chave de acesso foi cancelada ou expirou.';
  if (error.code === 'whatsapp_unavailable') return 'O início de sessão pelo WhatsApp ainda não está configurado.';
  if (error.code === 'authentication_challenge_expired') return 'Esta tentativa de início de sessão expirou. Tente novamente.';
  if (error.code === 'authentication_required' || error.code === 'session_expired') return 'A sessão expirou. A iniciar novamente…';
  if (error.code === 'passkey_verification_failed') return 'Não foi possível verificar essa chave de acesso.';
  if (error.code === 'password_verification_failed') return 'Palavra-passe incorreta. Podes recuperar pelo WhatsApp.';
  if (error.code === 'password_confirmation_mismatch') return 'As palavras-passe não coincidem.';
  if (error.code === 'invalid_password') return 'A palavra-passe deve ter entre 8 e 128 caracteres.';
  if (error.code === 'password_not_configured') return 'Este nome ainda não tem palavra-passe configurada.';
  if (error.code === 'registration_required') return 'Este contacto precisa de concluir o registo.';
  if (error.code === 'registration_already_pending') return 'Já existe uma validação WhatsApp pendente para este contacto. Continua a utilizar a mensagem anterior.';
  if (error.code === 'pending_submission_not_found') return 'Não existe uma submissão pendente para recuperar para este contacto.';
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
  if (error.code === 'invalid_guest_names') return 'Indica um nome público e um nome de remetente válidos.';
  if (error.code === 'duplicate_guest_nickname') return 'Esse nome público já está atribuído a outro convidado.';
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
    if (result.methods) {
      elements.credentialActions.hidden = false;
      elements.usePasskey.disabled = !result.methods.passkey;
      elements.usePassword.disabled = !result.methods.password;
    }
    if (result.mode === 'passkey') await usePasskey(result.options);
    if (result.mode === 'password') showPasswordLogin();
    if (result.mode === 'credentials') {
      elements.credentialActions.hidden = false;
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

const consumeAccessLink = async (token) => {
  const result = await post('/api/access-link/consume', { token });
  selectedGuest = result.guest;
  if (result.mode === 'session') {
    showAuthenticated(result.guest.nickname, 'Podes rever e alterar a tua resposta. Cria uma palavra-passe ou chave de acesso para protegeres este link.');
    return;
  }
  await selectGuest(result.guest);
};

const loadGuests = async (turnstileToken = '', query = elements.guestSearch.value.trim()) => {
  const lookupGeneration = ++guestLookupGeneration;
  elements.guestList.replaceChildren();
  try {
    const params = new URLSearchParams();
    if (selectedGroup) params.set('group', selectedGroup);
    params.set('q', query);
    const path = `/api/guests?${params}`;
    const { guests } = await api(path, turnstileToken
      ? { headers: { 'x-turnstile-token': turnstileToken } }
      : {});
    if (lookupGeneration !== guestLookupGeneration) return;
    const enabledStatuses = new Set(elements.guestStatusFilters.filter((input) => input.checked).map((input) => input.value));
    const visibleGuests = guests.map((guest) => guest.members
      ? { ...guest, members: guest.members.filter((member) => enabledStatuses.has(member.status)) }
      : guest).filter((guest) => guest.members ? guest.members.length > 0 : enabledStatuses.has(guest.status));
    if (visibleGuests.length === 0) {
      elements.guestList.textContent = 'Ainda não existem convites disponíveis.';
      return;
    }
    for (const guest of visibleGuests) {
      if (guest.members) {
        const pair = document.createElement('div');
        pair.className = 'linked-guest';
        const label = document.createElement('strong'); label.textContent = guest.nickname;
        pair.append(label);
        for (const member of guest.members) {
          const button = document.createElement('button');
          button.type = 'button'; button.className = `guest-button guest-status-${member.status}`; button.textContent = `Entrar como ${member.nickname}`;
          button.addEventListener('click', () => selectGuest(member));
          pair.append(button);
        }
        elements.guestList.append(pair);
      } else {
        const button = document.createElement('button');
        button.type = 'button'; button.className = `guest-button guest-status-${guest.status}`; button.textContent = guest.nickname;
        button.addEventListener('click', () => selectGuest(guest));
        elements.guestList.append(button);
      }
    }
  } catch {
    if (lookupGeneration !== guestLookupGeneration) return;
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
      return true;
    }
    elements.groupPicker.hidden = false;
    elements.groupSelect.replaceChildren();
    const placeholder = new Option('Escolha o seu grupo', '');
    placeholder.disabled = true;
    placeholder.selected = true;
    elements.groupSelect.add(placeholder);
    for (const group of groups) elements.groupSelect.add(new Option(group.name, group.id));
    await loadGuests();
    return true;
  } catch {
    elements.guestList.textContent = 'Não foi possível carregar os grupos. Tente novamente mais tarde.';
    return false;
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

const completeValidation = async ({ groupsAlreadyLoaded = false } = {}) => {
  elements.captcha.hidden = true;
  elements.captchaStatus.hidden = true;
  elements.triviaForm.hidden = true;
  elements.triviaStatus.hidden = true;
  elements.guestHeading.hidden = false;
  elements.guestHeadingIntro.hidden = false;
  elements.validatedContent.hidden = false;
  elements.newContactForm.hidden = false;
  elements.guestSearch.value = '';
  elements.guestSearch.focus();
  elements.guestList.textContent = 'Filtrar nomes.';
  await loadRsvpSummary();
  if (!groupsAlreadyLoaded) await loadGroups();
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

const restartSecurityValidation = async () => {
  elements.validatedContent.hidden = true;
  elements.triviaForm.hidden = true;
  elements.triviaStatus.hidden = true;
  elements.captcha.hidden = false;
  elements.captchaStatus.hidden = false;
  elements.captchaStatus.textContent = 'A carregar a verificação de segurança…';
  elements.captcha.replaceChildren();
  try {
    await loadTurnstile();
  } catch {
    elements.captchaStatus.textContent = 'A verificação de segurança ainda não está configurada.';
  }
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
  elements.sessionIntro.hidden = true;
  elements.editResponseSection.hidden = true;
  elements.guestSection.hidden = false;
  elements.adminSection.hidden = true;
  selectedGuest = null;
  const gateStillValid = await loadGroups();
  if (gateStillValid) {
    await completeValidation({ groupsAlreadyLoaded: true });
  } else {
    await restartSecurityValidation();
  }
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
  if (guestSearchTimer) window.clearTimeout(guestSearchTimer);
  selectedGroup = elements.groupSelect.value;
  elements.guestSearch.value = '';
  await loadGuests('', '');
});
elements.guestSearch.addEventListener('input', () => {
  if (guestSearchTimer) window.clearTimeout(guestSearchTimer);
  const query = elements.guestSearch.value.trim();
  guestSearchTimer = window.setTimeout(() => {
    guestSearchTimer = null;
    loadGuests('', query);
  }, 200);
});
elements.guestStatusFilters.forEach((input) => input.addEventListener('change', () => loadGuests('', elements.guestSearch.value.trim())));
elements.rsvpForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  if (!hasMealPreference(elements.rsvpForm)) {
    showToast('Seleciona uma preferência.');
    return;
  }
  const form = new FormData(elements.rsvpForm);
  const payload = {
    availableDays: form.getAll('availableDays'),
    noAvailability: form.get('noAvailability') === 'true',
    guestCount: 1,
    mealPreference: form.get('mealPreference'),
    proposedRestaurantChoices: form.get('proposedRestaurantChoices').split(/\r?\n/).map((choice) => choice.trim()).filter(Boolean),
    preferenceType: 'families',
    dietaryRestrictions: '',
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
  if (!hasMealPreference(elements.whatsappRsvpForm)) {
    showToast('Seleciona uma preferência.');
    return;
  }
  const form = new FormData(elements.whatsappRsvpForm);
  const payload = {
    availableDays: form.getAll('availableDays'), guestCount: 1,
    noAvailability: form.get('noAvailability') === 'true',
    mealPreference: form.get('mealPreference'), preferenceType: 'families',
    proposedRestaurantChoices: form.get('proposedRestaurantChoices').split(/\r?\n/).map((choice) => choice.trim()).filter(Boolean),
    dietaryRestrictions: '',
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
    await put('/api/admin/settings', { restaurantChoices, triviaQuestions, useTrivia: elements.adminUseTrivia.checked, useWhatsappVerification: elements.adminUseWhatsappVerification.checked });
    elements.sessionStatus.textContent = '';
    showToast('Opções do evento guardadas.');
    await loadRsvpForm();
  } catch { elements.sessionStatus.textContent = 'Não foi possível guardar as opções do evento. Confirma o formato das perguntas.'; }
});
elements.adminSummaryForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  elements.adminSummaryStatus.textContent = 'A guardar…';
  try {
    await put('/api/admin/summary', { narrative: elements.adminSummary.value });
    elements.adminSummaryStatus.textContent = '';
    showToast('Comentário guardado.');
  } catch (error) {
    elements.adminSummaryStatus.textContent = readableError(error);
  }
});
elements.adminGuestGrid.addEventListener('click', (event) => {
  const button = event.target.closest('button[data-guest-id]');
  if (!button) return;
  elements.adminGuestSelect.value = button.dataset.guestId;
  const guest = elements.adminGuestSelect._guests?.find((item) => item.id === selectedAdminGuestId());
  if (!guest) return;
  renderAdminGuest(guest);
  hideAdminGuestLinks();
  renderAdminGuestGrid();
});
elements.adminGuestSearch.addEventListener('input', renderAdminGuestGrid);
elements.adminRefreshGuestStatus.addEventListener('click', async () => {
  elements.adminRefreshGuestStatus.disabled = true;
  try {
    await loadAdminGuests();
    showToast('Estado de validação atualizado.');
  } catch (error) { elements.adminGuestStatus.textContent = readableError(error); }
  finally { elements.adminRefreshGuestStatus.disabled = false; }
});
elements.adminResetGuestVote.addEventListener('click', async () => {
  const guestId = selectedAdminGuestId();
  if (!guestId) return;
  const guest = elements.adminGuestSelect._guests?.find((item) => item.id === guestId);
  if (!window.confirm(`Repor a votação de ${guest?.nickname || 'este convidado'}? Esta ação remove as escolhas guardadas.`)) return;
  elements.adminResetGuestVote.disabled = true;
  try {
    const result = await post('/api/admin/guests/reset-vote', { guestId });
    showToast(result.guestIds.length > 1 ? 'Votação do par reposta.' : 'Votação reposta.');
  } catch (error) { elements.adminGuestStatus.textContent = readableError(error); }
  finally { elements.adminResetGuestVote.disabled = false; }
});
elements.adminGuestAccessLink.addEventListener('click', async () => {
  const guestId = selectedAdminGuestId();
  if (!guestId) return;
  elements.adminGuestAccessLink.disabled = true;
  try {
    const result = await post('/api/admin/guests/access-link', { guestId });
    elements.adminGuestAccessLinkValue.value = result.link;
    elements.adminGuestAccessLinkValue.hidden = false;
    elements.adminCopyGuestAccessLink.hidden = false;
    elements.adminShareGuestAccessLink.href = adminShareUrl(result.link);
    elements.adminShareGuestAccessLink.hidden = false;
    await QRCode.toCanvas(elements.adminGuestAccessLinkQr, result.link, { width: 228, margin: 1, errorCorrectionLevel: 'M' });
    elements.adminGuestAccessLinkQr.hidden = false;
    showToast('Link seguro criado. O link anterior foi revogado.');
  } catch (error) { elements.adminGuestStatus.textContent = readableError(error); }
  finally { elements.adminGuestAccessLink.disabled = false; }
});
elements.adminCopyGuestAccessLink.addEventListener('click', async () => {
  try { await navigator.clipboard.writeText(elements.adminGuestAccessLinkValue.value); showToast('Link copiado.'); }
  catch { elements.adminGuestAccessLinkValue.select(); document.execCommand('copy'); showToast('Link selecionado para copiar.'); }
});
elements.adminReissueRegistration.addEventListener('click', async () => {
  const guestId = selectedAdminGuestId();
  if (!guestId) return;
  elements.adminReissueRegistration.disabled = true;
  try {
    const result = await post('/api/admin/guests/reissue-registration', { guestId });
    elements.adminReissueRegistrationValue.value = result.whatsappUrl;
    elements.adminReissueRegistrationValue.hidden = false;
    elements.adminCopyReissueRegistration.hidden = false;
    elements.adminShareReissueRegistration.href = adminShareUrl(result.whatsappUrl);
    elements.adminShareReissueRegistration.hidden = false;
    await QRCode.toCanvas(elements.adminReissueRegistrationQr, result.whatsappUrl, { width: 228, margin: 1, errorCorrectionLevel: 'M' });
    elements.adminReissueRegistrationQr.hidden = false;
    showToast('Nova validação WhatsApp criada. A mensagem anterior foi revogada.');
  } catch (error) { elements.adminGuestStatus.textContent = readableError(error); }
  finally { elements.adminReissueRegistration.disabled = false; }
});
elements.adminRecoverRegistration.addEventListener('click', async () => {
  const guestId = selectedAdminGuestId();
  if (!guestId) return;
  elements.adminRecoverRegistration.disabled = true;
  try {
    const result = await post('/api/admin/guests/recover-registration', { guestId });
    elements.adminReissueRegistrationValue.value = result.link;
    elements.adminReissueRegistrationValue.hidden = false;
    elements.adminCopyReissueRegistration.hidden = false;
    elements.adminShareReissueRegistration.href = adminShareUrl(result.link);
    elements.adminShareReissueRegistration.hidden = false;
    await QRCode.toCanvas(elements.adminReissueRegistrationQr, result.link, { width: 228, margin: 1, errorCorrectionLevel: 'M' });
    elements.adminReissueRegistrationQr.hidden = false;
    showToast('Validação WhatsApp aprovada. Link seguro gerado.');
    await loadAdminGuests();
  } catch (error) { elements.adminGuestStatus.textContent = readableError(error); }
  finally { elements.adminRecoverRegistration.disabled = false; }
});
elements.adminCopyReissueRegistration.addEventListener('click', async () => {
  try { await navigator.clipboard.writeText(elements.adminReissueRegistrationValue.value); showToast('Link de validação copiado.'); }
  catch { elements.adminReissueRegistrationValue.select(); document.execCommand('copy'); showToast('Link de validação selecionado para copiar.'); }
});
elements.adminGuestForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  elements.adminGuestStatus.textContent = 'A guardar…';
  try {
    const result = await put('/api/admin/guests', { guestId: selectedAdminGuestId(), nickname: elements.adminGuestNickname.value, sender: elements.adminGuestSender.value });
    const guests = elements.adminGuestSelect._guests || [];
    const guest = guests.find((item) => item.id === result.guest.id);
    if (guest) { guest.nickname = result.guest.nickname; guest.sender = result.guest.sender; }
    const option = [...elements.adminGuestSelect.options].find((item) => item.value === result.guest.id);
    if (option) option.textContent = `${result.guest.nickname} (${result.guest.sender})`;
    renderAdminGuestGrid();
    elements.adminGuestStatus.textContent = '';
    showToast('Nomes guardados.');
  } catch (error) { elements.adminGuestStatus.textContent = readableError(error); }
});
elements.adminAddGuestForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  elements.adminAddGuestStatus.textContent = 'A adicionar…';
  try {
    await post('/api/admin/guests', { nickname: elements.adminNewGuestNickname.value, sender: elements.adminNewGuestSender.value });
    elements.adminAddGuestForm.reset();
    elements.adminAddGuestStatus.textContent = '';
    showToast('Convidado adicionado.');
    await loadAdminGuests();
  } catch (error) { elements.adminAddGuestStatus.textContent = readableError(error); }
});
elements.adminRemoveGuest.addEventListener('click', async () => {
  const guestId = selectedAdminGuestId();
  if (!guestId || !window.confirm('Remover este convidado da lista pública?')) return;
  elements.adminRemoveGuest.disabled = true;
  try {
    await del('/api/admin/guests', { guestId });
    showToast('Convidado removido.');
    await loadAdminGuests();
  } catch (error) {
    elements.adminGuestStatus.textContent = readableError(error);
    elements.adminRemoveGuest.disabled = false;
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
    elements.passwordStatus.textContent = '';
    showToast('Palavra-passe guardada.');
  } catch (error) { elements.passwordStatus.textContent = readableError(error); }
});
elements.openPassword.addEventListener('click', () => {
  elements.profileDetails.open = true;
  elements.passwordNew.focus();
});
elements.passwordRemove.addEventListener('click', async () => {
  elements.passwordStatus.textContent = 'A remover…';
  try {
    await del('/api/auth/password');
    elements.passwordStatus.textContent = '';
    showToast('Palavra-passe removida.');
  } catch (error) { elements.passwordStatus.textContent = readableError(error); }
});

const initialize = async () => {
  const accessToken = new URLSearchParams(window.location.search).get('access');
  if (accessToken) {
    window.history.replaceState({}, '', `${window.location.pathname}${window.location.hash}`);
    try {
      await consumeAccessLink(accessToken);
      return;
    } catch {
      elements.captchaStatus.textContent = 'Este link é inválido ou expirou. Pede um novo link ao Antonio.';
    }
  }
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

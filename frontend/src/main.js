const form = document.querySelector('#login-form');
const status = document.querySelector('#status');

form.addEventListener('submit', async (event) => {
  event.preventDefault();
  status.textContent = 'Checking your invitation…';

  const data = new FormData(form);
  const payload = {
    contact: String(data.get('contact') || ''),
    passphrase: String(data.get('passphrase') || ''),
  };

  try {
    const response = await fetch('/api/auth/login', {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(payload),
    });
    const body = await response.json().catch(() => ({}));
    status.textContent = body.message || 'The RSVP service is not ready yet.';
  } catch {
    status.textContent = 'Unable to reach the RSVP service. Please try again later.';
  }
});


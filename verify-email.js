// Reads the one-time token from the URL fragment (#token=...) -- the fragment is
// never sent to the server in the GET, so it stays out of access logs; we POST it
// explicitly to /verify-email/confirm.
const token = new URLSearchParams(location.hash.slice(1)).get('token') || '';

const show = (id) => {
  document.querySelectorAll('.screen').forEach(s => s.classList.remove('on'));
  document.getElementById(id).classList.add('on');
};

async function confirm() {
  if (!token) {
    document.getElementById('err-msg').textContent = 'No confirmation token in the link.';
    return show('s-err');
  }
  try {
    const r = await fetch('/verify-email/confirm', {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ token }),
    });
    const data = await r.json().catch(() => ({}));
    if (r.ok && data.ok) {
      document.getElementById('ok-email').textContent = data.email || 'Your email';
      show('s-ok');
    } else {
      if (data.error === 'email_changed') {
        document.getElementById('err-msg').textContent =
          'This address is no longer on the account. Ask your administrator for a new link.';
      }
      show('s-err');
    }
  } catch {
    document.getElementById('err-msg').textContent = 'Could not reach the server. Try again later.';
    show('s-err');
  }
}

confirm();

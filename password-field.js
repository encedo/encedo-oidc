/**
 * password-field.js -- shared by signin, enrollment, signup and the admin panel.
 *
 * A classic script (not a module) so admin-panel.html can load it the same way
 * as the module pages. Load it BEFORE the page script. Served at
 * /password-field.js -- a new UI file lives in THREE places (src/app.js route,
 * Dockerfile COPY, release.yml zip list).
 *
 * 1. The eye. Every <input type="password"> is wrapped at startup and gets a
 *    show/hide button; the markup stays a plain password input. Same mechanism
 *    as encedo-chat:
 *    - masked again on blur: peeking is a gesture, not a state -- a passphrase
 *      left visible is a passphrase on a projector. pointerdown on the eye is
 *      prevented, so the click does not blur the input and fight this rule;
 *    - tabindex=-1: tabbing from the passphrase to the next control should not
 *      stop at an ornament.
 *    Styles (.pw-wrap / .pw-eye) are in each page's <style> block: CSP allows
 *    only hashed inline styles, so this script cannot inject them.
 *
 * 2. Password managers. They save what a real <form> submits, so the password
 *    fields sit in forms whose submit event is the ONE path to the handler (the
 *    page's listener prevents the navigation). Two helpers for those forms:
 *    - on submit every password field is masked again before the manager
 *      reads the form (Enter while peeking would submit a type=text field);
 *    - form[data-enter-next]: Enter in a text field moves to the next field
 *      instead of submitting. The HSM passphrase is optional -- an Enter in the
 *      URL field would otherwise start the flow without it (mobile approval).
 */
(function () {
  'use strict';

  const EYE_SVG = '<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M1 12s4-7 11-7 11 7 11 7-4 7-11 7-11-7-11-7z"/><circle cx="12" cy="12" r="3"/></svg>';
  const EYE_OFF_SVG = '<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 19c-7 0-11-7-11-7a18.45 18.45 0 0 1 5.06-5.94"/><path d="M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 7 11 7a18.5 18.5 0 0 1-2.16 3.19"/><path d="M14.12 14.12a3 3 0 1 1-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/></svg>';

  const hides = [];   // re-mask callbacks, one per wrapped field

  function attachEye(input) {
    const wrap = document.createElement('span');
    wrap.className = 'pw-wrap';
    input.parentElement.insertBefore(wrap, input);
    wrap.appendChild(input);

    const btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'pw-eye';
    btn.tabIndex = -1;
    const paint = () => {
      const shown = input.type === 'text';
      btn.innerHTML = shown ? EYE_OFF_SVG : EYE_SVG;
      btn.title = shown ? 'Hide passphrase' : 'Show passphrase';
      btn.setAttribute('aria-label', btn.title);
      btn.setAttribute('aria-pressed', String(shown));
    };
    const hide = () => { if (input.type === 'text') { input.type = 'password'; paint(); } };

    // The eye must not steal focus -- the blur would re-mask before the click lands.
    btn.addEventListener('pointerdown', e => e.preventDefault());
    btn.addEventListener('click', () => {
      input.type = input.type === 'text' ? 'password' : 'text';
      paint();
      input.focus();
    });
    input.addEventListener('blur', hide);
    hides.push({ input, hide });
    paint();
    wrap.appendChild(btn);
  }

  // Capture phase: runs before the page's own submit handler.
  document.addEventListener('submit', e => {
    for (const h of hides) if (e.target.contains(h.input)) h.hide();
  }, true);

  document.addEventListener('keydown', e => {
    if (e.key !== 'Enter' || e.isComposing) return;
    const t = e.target;
    const form = t.form;
    if (!form || !form.hasAttribute('data-enter-next')) return;
    if (t.tagName !== 'INPUT' || ['password', 'checkbox', 'radio', 'hidden'].includes(t.type)) return;
    if (t.dataset.pwEye) return;   // a passphrase being peeked at (type=text) still submits
    const fields = [...form.querySelectorAll('input, select, textarea')]
      .filter(f => f.type !== 'hidden' && !f.hidden && !f.disabled && !f.readOnly && f.getClientRects().length);
    const next = fields[fields.indexOf(t) + 1];
    if (!next) return;
    e.preventDefault();
    next.focus();
  });

  function init() {
    for (const input of document.querySelectorAll('input[type="password"]')) {
      input.dataset.pwEye = '1';
      attachEye(input);
    }
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
  else init();
})();

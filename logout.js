/**
 * logout.js -- served with the /logout page (logout.html). The SSO session
 * (HEM tokens cached by signin.js under encedo_sso:*) lives only in this
 * browser, so only a script on the OP origin can end it.
 *
 * RP-Initiated Logout 1.0 s.2: the OP asks the user whether to log out of the
 * OP as well. So: if this browser holds a session for the signed-out user
 * (without an id_token_hint: any session), ask, and only clear it on "Yes".
 * With nothing to keep there is nothing to ask -- follow the permitted
 * post-logout redirect at once, exactly as before.
 *
 * Classic script, no imports: it must work on a page the RP navigated to.
 */
(function () {
  var el = document.getElementById('logout');
  if (!el) return;
  var sub = el.getAttribute('data-sub') || '';
  var to  = el.getAttribute('data-redirect') || '';
  var rp  = el.getAttribute('data-rp') || '';
  var PREFIX = 'encedo_sso:';

  // Sessions this logout is about: { key, username } -- malformed entries
  // count too, they are dropped on "Yes" like everything else.
  function sessions() {
    var out = [];
    try {
      var keys = [];
      for (var i = 0; i < localStorage.length; i++) keys.push(localStorage.key(i));
      keys.forEach(function (k) {
        if (k.indexOf(PREFIX) !== 0) return;
        var v = null;
        try { v = JSON.parse(localStorage.getItem(k)); } catch (e) { v = null; }
        if (!v || !sub || v.sub === sub) out.push({ key: k, username: v && v.username ? String(v.username) : '' });
      });
    } catch (e) { /* storage unavailable -- nothing kept here */ }
    return out;
  }
  function forget(list) {
    list.forEach(function (s) { try { localStorage.removeItem(s.key); } catch (e) { /* gone */ } });
  }
  function leave() {
    if (to) { location.replace(to); return; }
    document.getElementById('lo-ask').hidden = true;
    document.getElementById('lo-done').hidden = false;
  }

  var list = sessions();
  if (!list.length) { leave(); return; }

  var names = [];
  list.forEach(function (s) { if (s.username && names.indexOf(s.username) < 0) names.push(s.username); });
  if (names.length) document.getElementById('lo-who').textContent = names.join(', ');
  var title = document.getElementById('lo-ask-title');
  title.textContent = '';
  title.appendChild(document.createTextNode(rp ? 'You have been signed out of ' : 'You have been signed out.'));
  if (rp) {
    var strong = document.createElement('strong'); strong.textContent = rp;
    title.appendChild(strong); title.appendChild(document.createTextNode('.'));
  }
  document.getElementById('lo-yes').addEventListener('click', function () { forget(list); leave(); });
  document.getElementById('lo-no').addEventListener('click', function () { leave(); });
  document.getElementById('lo-done').hidden = true;
  document.getElementById('lo-ask').hidden = false;
})();

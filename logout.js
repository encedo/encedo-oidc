/**
 * logout.js -- served with the /logout page. Drops this browser's SSO sessions
 * (HEM tokens cached by signin.js under encedo_sso:*) for the signed-out user,
 * then follows the permitted post-logout redirect. Classic script, no imports:
 * it must work on a page the RP navigated to, before anything else.
 */
(function () {
  var el = document.getElementById('logout');
  var sub = el ? el.getAttribute('data-sub') : '';
  var to  = el ? el.getAttribute('data-redirect') : '';
  try {
    var keys = [];
    for (var i = 0; i < localStorage.length; i++) keys.push(localStorage.key(i));
    keys.forEach(function (k) {
      if (k.indexOf('encedo_sso:') !== 0) return;
      if (!sub) { localStorage.removeItem(k); return; }
      try {
        var v = JSON.parse(localStorage.getItem(k));
        if (!v || v.sub === sub) localStorage.removeItem(k);
      } catch (e) { localStorage.removeItem(k); }
    });
  } catch (e) { /* storage unavailable -- nothing to clear */ }
  if (to) location.replace(to);
})();

try {
  const r = await fetch('/health');
  const h = await r.json();
  if (h.issuer)  document.getElementById('td-issuer').textContent  = h.issuer;
  if (h.commit)  document.getElementById('td-version').textContent = 'v ' + h.commit;
} catch { /* server unreachable — leave dots */ }

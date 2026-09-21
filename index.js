try {
  const r = await fetch('/health');
  const h = await r.json();
  if (h.issuer)  document.getElementById('td-issuer').textContent  = h.issuer;
  const ver = h.version && h.version !== 'unknown' ? 'v' + h.version : '';
  const build = h.commit && h.commit !== 'unknown' ? h.commit : '';
  if (ver || build) document.getElementById('td-version').textContent = [ver, build].filter(Boolean).join(' · ');
} catch { /* server unreachable — leave dots */ }

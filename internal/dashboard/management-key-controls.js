// Shared by the existing Administration page and My keys. Secrets stay in
// closures: never in HTML, attributes, local/session storage or status messages.
const KeyControls = (() => {
  function singleFlight(form, fn) {
    let pending = false;
    return async (...args) => {
      if (args[0] && typeof args[0].preventDefault === 'function') args[0].preventDefault();
      if (pending) return;
      pending = true;
      const buttons = [...form.querySelectorAll('button[type="submit"], button:not([type])')];
      const previous = buttons.map(button => button.disabled);
      buttons.forEach(button => button.disabled = true);
      try { return await fn(...args); }
      finally { pending = false; buttons.forEach((button, i) => button.disabled = previous[i]); }
    };
  }
  function expiry(key) { return key.expirationDate || key.expiresAt; }
  function state(key, now = Date.now()) {
    if (key.status === 'revoked' || key.status === 'expired') return key.status;
    if (key.status !== 'active') return 'unknown';
    // A key with no reported expiry is non-expiring by policy; an unparsable
    // expiry is unverifiable and must not be presented as active.
    const raw = expiry(key);
    if (!raw) return 'active';
    const timestamp = Date.parse(raw);
    if (!Number.isFinite(timestamp)) return 'unknown';
    return timestamp <= now ? 'expired' : 'active';
  }
  function remaining(key, now = Date.now()) {
    if (!expiry(key)) return 'No expiry reported';
    const timestamp = Date.parse(expiry(key));
    if (!Number.isFinite(timestamp)) return 'Expiry unavailable';
    let seconds = Math.max(0, Math.ceil((timestamp - now) / 1000));
    if (!seconds) return 'Expired';
    const parts = [];
    for (const [unit, size] of [['d', 86400], ['h', 3600], ['m', 60], ['s', 1]]) {
      const amount = Math.floor(seconds / size); seconds %= size;
      if (amount || parts.length) parts.push(amount + unit);
      if (parts.length === 2) break;
    }
    return parts.join(' ') + ' remaining';
  }
  function filename(metadata = {}) {
    const parts = [metadata.subject, metadata.name].map(value => typeof value === 'string'
      ? value.normalize('NFKC').replace(/[^a-zA-Z0-9_-]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 64) : '').filter(Boolean);
    return parts.length ? parts.join('-') + '-pricetag.key' : 'pricetag.key';
  }
  function delivery(panel) {
    let secret = '', downloadName = 'pricetag.key';
    function clear() {
      secret = ''; downloadName = 'pricetag.key'; panel.hidden = true; delete panel.dataset.keyId;
      panel.querySelectorAll('button').forEach(button => button.disabled = true);
    }
    clear();
    return {
      clear,
      // Only callers responsible for clipboard/download receive this value.
      value: () => secret,
      set(result, metadata = {}) {
        clear();
        if (typeof result.key !== 'string' || !result.key.trim() || /\s/.test(result.key)) {
          throw new Error('The key service returned no usable key. Check your key list before issuing another.');
        }
        downloadName = filename(metadata);
        secret = result.key; panel.dataset.keyId = typeof result.id === 'string' ? result.id : ''; panel.hidden = false;
        panel.querySelectorAll('button').forEach(button => button.disabled = false);
      },
      async copy() {
        if (!secret) throw new Error('No new key to copy.');
        try { await navigator.clipboard.writeText(secret); }
        catch (_) { throw new Error('Clipboard access was denied. Use Download .key instead.'); }
      },
      download() {
        if (!secret) throw new Error('No new key to download.');
        const url = URL.createObjectURL(new Blob([secret + '\n'], {type: 'text/plain'}));
        const link = document.createElement('a'); link.href = url; link.download = downloadName;
        try { document.body.append(link); link.click(); }
        finally { link.remove(); setTimeout(() => URL.revokeObjectURL(url), 1000); }
      }
    };
  }
  return {singleFlight, state, expiry, remaining, filename, delivery};
})();

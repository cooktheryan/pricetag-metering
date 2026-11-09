// Shared table behavior for personal keys, quota overrides and model prices.
const TableControls = (() => {
  function page(rows, offset, size) {
    offset = Math.min(Math.max(0, offset), Math.max(0, Math.ceil(rows.length / size) - 1) * size);
    return {rows: rows.slice(offset, offset + size), offset, hasMore: offset + size < rows.length};
  }
  function filterKeys(keys, search, status, now = Date.now()) {
    search = search.trim().toLowerCase();
    return keys.filter(key => (status === 'all' || KeyControls.state(key, now) === status) &&
      ((key.name || '') + ' ' + key.id).toLowerCase().includes(search))
      .sort((a, b) => Number(KeyControls.state(b, now) === 'active') - Number(KeyControls.state(a, now) === 'active'));
  }
  async function loadKeys(api, maxPages = 100) {
    // MaaS currently ignores nameContains. Load owner-scoped metadata before
    // filtering, never present a partial list as a complete search result.
    const keys = [], seen = new Set();
    for (let index = 0; index < maxPages; index++) {
      const result = await api('/me/keys?offset=' + index * 50);
      if (!Array.isArray(result.data) || typeof result.has_more !== 'boolean') throw new Error('Invalid key list response.');
      if (result.has_more && !result.data.length) throw new Error('Key service returned an empty page with more results.');
      for (const key of result.data) {
        if (!key || typeof key.id !== 'string' || !key.id) throw new Error('Invalid key metadata.');
        if (!seen.has(key.id)) {keys.push(key); seen.add(key.id);}
      }
      if (!result.has_more) return keys;
    }
    throw new Error('Too many keys to search safely in this view. Use the key management API to review them.');
  }
  function pager(target, {offset, size, hasMore, count, onPage}) {
    target.replaceChildren();
    const label = document.createElement('span');
    label.className = 'page-label'; label.setAttribute('aria-live', 'polite');
    label.textContent = 'Page ' + (Math.floor(offset / size) + 1);
    if (Number.isInteger(count)) label.textContent += ' of ' + Math.max(1, Math.ceil(count / size)) + ' · ' + count + ' results';
    for (const [text, delta, enabled] of [['Previous', -size, offset > 0], ['Next', size, hasMore]]) {
      const button = document.createElement('button'); button.type = 'button';
      button.className = 'btn btn-outline'; button.textContent = text; button.disabled = !enabled;
      button.onclick = () => onPage(offset + delta);
      target.append(button);
      if (delta < 0) target.append(label);
    }
  }
  return {page, filterKeys, loadKeys, pager};
})();

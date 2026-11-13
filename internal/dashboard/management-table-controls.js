// Shared table behavior for personal keys, quota overrides and model prices.
const TableControls = (() => {
  function page(rows, offset, size) {
    if (!Number.isInteger(size) || size <= 0) throw new Error('Invalid page size.');
    offset = Math.min(Math.max(0, offset), Math.max(0, Math.ceil(rows.length / size) - 1) * size);
    return {rows: rows.slice(offset, offset + size), offset, hasMore: offset + size < rows.length};
  }
  function filterKeys(keys, search, status, now = Date.now()) {
    search = search.trim().toLowerCase();
    return keys.filter(key => (status === 'all' || KeyControls.state(key, now) === status) &&
      ((key.name || '') + ' ' + key.id).toLowerCase().includes(search))
      .sort((a, b) => Number(KeyControls.state(b, now) === 'active') - Number(KeyControls.state(a, now) === 'active'));
  }
  async function loadKeys(api) {
    // /me/keys returns the caller's complete key list in one response
    // (the server walks any upstream paging). If a future server paginates,
    // fail instead of presenting a partial list as complete.
    const result = await api('/me/keys');
    if (!Array.isArray(result.data)) throw new Error('Invalid key list response.');
    if (result.has_more !== undefined) {
      if (typeof result.has_more !== 'boolean') throw new Error('Invalid key list response.');
      if (result.has_more) throw new Error('Key list was truncated by the service.');
    }
    for (const key of result.data) {
      if (!key || typeof key.id !== 'string' || !key.id) throw new Error('Invalid key metadata.');
    }
    return result.data;
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

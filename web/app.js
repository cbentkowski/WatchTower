const $ = (id) => document.getElementById(id);
let results = [];
let allResults = [];
let workspaces = [];
let owners = [];
let activeFilters = null;
let editorMode = null;
let editorTargetId = null;
let detailAppId = null;
let editorConfig = { applications: [], workspaces: [] };
let cpeMapping = null;
let cpeDraft = null;
let lifecycleMapping = null;
let lifecycleDraft = null;
let cpeSearchPage = { previousIndex: null, nextIndex: null, startIndex: 0, totalResults: 0 };
let settingsLoaded = false;
let logsLoaded = false;
let activeLogType = 'system';
let accessLoaded = false;
let feedsLoaded = false;
let ownersLoaded = false;
let feedData = { feeds: [], applications: [], canManage: false };
let currentFeedId = null;
let currentOwnerId = null;
let editorSelections = { ownerIds: new Set(), workspaceIds: new Set(), feedIds: new Set(), applicationIds: new Set() };
let associationState = null;
let resumeOwnerAssociation = null;
let accessData = null;
let isAdmin = false;
let canManageAccess = false;
let activePreview = null;
let renderedHash = location.hash;
let previewNavigation = false;
const selectedMappingIds = new Set();
const selectedGrantIds = new Set();
const accessDraftKey = 'watchtower-access-preview-draft';
const accessDraftLifetime = 8 * 60 * 60 * 1000;
let permissions = { accessManage: false, scan: false, feeds: { manage: false, view: [], edit: [] }, applications: { view: [], edit: [] }, workspaces: { view: [], edit: [], membership: [], notifications: [] } };
const escape = (s) => String(s ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const safeUrl = (url) => { try { const u = new URL(url); return u.protocol === 'https:' ? u.href : '#'; } catch { return '#'; } };
const labels = { red: 'Needs action', yellow: 'Approaching EOL', green: 'Clear', unknown: 'Unknown' };
function setTheme(theme) {
  document.documentElement.dataset.theme = theme;
  try { localStorage.setItem('dashboard-theme', theme); } catch {}
  $('theme-toggle').innerHTML = theme === 'dark' ? '☀ <span>Light mode</span>' : '☾ <span>Dark mode</span>';
  $('theme-toggle').setAttribute('aria-label', `Switch to ${theme === 'dark' ? 'light' : 'dark'} mode`);
  $('theme-toggle').setAttribute('aria-pressed', String(theme === 'dark'));
}

function activeWorkspace() {
  const id = location.hash.startsWith('#workspace=') ? decodeURIComponent(location.hash.slice(11)) : null;
  return id === 'all' ? { id: 'all', name: 'All Applications', applications: allResults.map(app => app.id) } : workspaces.find(group => group.id === id) || null;
}

function selectWorkspace(id) {
  activeFilters = null;
  location.hash = id ? `workspace=${encodeURIComponent(id)}` : 'overview';
  renderView();
}

function toggleFilter(filter) {
  if (!activeWorkspace()) return;
  if (filter === 'all') activeFilters = null;
  else if (!activeFilters) activeFilters = new Set([filter]);
  else {
    if (activeFilters.has(filter)) activeFilters.delete(filter);
    else activeFilters.add(filter);
    if (!activeFilters.size) activeFilters = null;
  }
  renderView();
}

function renderSidebar() {
  const groups = [{ id: 'all', name: 'All Applications', applications: allResults.map(app => app.id) }, ...workspaces];
  $('workspace-list').innerHTML = groups.map(group => `<div class="workspace-group"><button type="button" class="workspace-link" data-workspace="${escape(group.id)}"><span class="workspace-name">${escape(group.name)}</span><span class="workspace-count">${group.applications.length}</span></button><div class="workspace-apps">${group.applications.map(id => { const app = allResults.find(item => item.id === id); return app ? `<button type="button" data-workspace="${escape(group.id)}" data-app-id="${escape(id)}" title="${escape(app.name)}">${escape(app.name)}</button>` : ''; }).join('')}</div></div>`).join('');
}

function renderView() {
  const enteringOwnersPage = location.hash === '#owners' && renderedHash !== '#owners';
  if (renderedHash === '#access' && location.hash !== '#access' && !activePreview && !previewNavigation) {
    clearAccessDraft();
    accessLoaded = false;
    accessData = null;
    selectedMappingIds.clear();
    selectedGrantIds.clear();
  }
  renderedHash = location.hash;
  const settingsPage = location.hash === '#settings';
  const logsPage = location.hash === '#logs';
  const accessPage = location.hash === '#access';
  const feedsPage = location.hash === '#feeds';
  const ownersPage = location.hash === '#owners';
  if (enteringOwnersPage) ownersLoaded = false;
  $('dashboard-content').hidden = settingsPage || logsPage || accessPage || feedsPage || ownersPage;
  $('settings-content').hidden = !settingsPage;
  $('logs-content').hidden = !logsPage;
  $('access-content').hidden = !accessPage;
  $('feeds-content').hidden = !feedsPage;
  $('owners-content').hidden = !ownersPage;
  $('settings-nav').classList.toggle('active', settingsPage);
  $('settings-nav').setAttribute('aria-current', settingsPage ? 'page' : 'false');
  $('logs-nav').classList.toggle('active', logsPage);
  $('logs-nav').setAttribute('aria-current', logsPage ? 'page' : 'false');
  $('access-nav').classList.toggle('active', accessPage);
  $('access-nav').setAttribute('aria-current', accessPage ? 'page' : 'false');
  $('feeds-nav').classList.toggle('active', feedsPage);
  $('feeds-nav').setAttribute('aria-current', feedsPage ? 'page' : 'false');
  $('owners-nav').classList.toggle('active', ownersPage);
  $('owners-nav').setAttribute('aria-current', ownersPage ? 'page' : 'false');
  if (settingsPage || logsPage || accessPage || feedsPage || ownersPage) {
    $('overview-nav').classList.remove('active');
    for (const button of $('workspace-list').querySelectorAll('.workspace-link')) button.classList.remove('active');
    $('crumb-current').textContent = settingsPage ? 'Settings' : logsPage ? 'Logs' : accessPage ? 'Access Control' : feedsPage ? 'Feeds' : 'Owners';
    if (settingsPage && !settingsLoaded) loadSettings();
    if (logsPage && !logsLoaded) loadLogs();
    if (accessPage && !accessLoaded) loadAccess();
    if (feedsPage && !feedsLoaded) loadFeeds();
    if (ownersPage && !ownersLoaded) loadOwners();
    return;
  }
  const group = activeWorkspace();
  const scoped = group ? allResults.filter(app => group.applications.includes(app.id)) : allResults;
  results = group ? activeFilters ? scoped.filter(app => activeFilters.has(app.status)) : scoped : scoped.filter(app => app.status === 'red');
  for (const card of document.querySelectorAll('.summary-card[data-filter]')) {
    const filter = card.dataset.filter;
    const selected = filter === 'all' ? !activeFilters : Boolean(activeFilters?.has(filter));
    card.classList.toggle('interactive', Boolean(group));
    card.classList.toggle('selected', Boolean(group && selected));
    if (group) { card.setAttribute('role', 'button'); card.tabIndex = 0; card.setAttribute('aria-pressed', String(selected)); }
    else { card.removeAttribute('role'); card.removeAttribute('tabindex'); card.removeAttribute('aria-pressed'); }
  }
  $('overview-nav').classList.toggle('active', !group);
  $('overview-nav').setAttribute('aria-current', group ? 'false' : 'page');
  for (const button of $('workspace-list').querySelectorAll('.workspace-link')) {
    const selected = group?.id === button.dataset.workspace;
    button.classList.toggle('active', selected);
    button.setAttribute('aria-current', selected ? 'page' : 'false');
  }
  $('crumb-current').textContent = group?.name || 'Overview';
  $('page-eyebrow').textContent = group ? 'WORKSPACE' : 'APPLICATION EXPOSURE';
  $('page-title').textContent = group?.name || 'Vulnerability Dashboard';
  $('page-description').textContent = group ? `Application status for ${group.name}.` : 'Security posture across all monitored applications.';
  $('edit-workspace').hidden = !group || group.id === 'all' || !(isAdmin || permissions.workspaces.edit.includes(group.id) || permissions.workspaces.membership.includes(group.id) || permissions.workspaces.notifications.includes(group.id));
  $('table-title').textContent = group ? 'Application inventory' : 'Needs action';
  $('table-description').textContent = group ? activeFilters ? `Showing ${[...activeFilters].map(key => labels[key]).join(' or ')}.` : 'Click an application to review evidence and source links.' : 'Applications with high risk findings or past end of life.';
  for (const key of ['red','yellow','green']) $(key).textContent = scoped.filter(a => a.status === key).length;
  $('total').textContent = scoped.length;
  $('count').textContent = `${results.length} application${results.length === 1 ? '' : 's'}`;
  if (!results.length) {
    $('rows').innerHTML = group ? activeFilters ? '<tr><td colspan="6" class="empty"><div class="empty-mark">◇</div><strong>No applications match</strong><p>Select Monitored Applications to show the full workspace.</p></td></tr>' : '<tr><td colspan="6" class="empty"><div class="empty-mark">◇</div><strong>No applications in this workspace</strong><p>Add application IDs to this group in <code>config/workspaces.yaml</code>, then refresh.</p></td></tr>' : '<tr><td colspan="6" class="empty"><div class="empty-mark">◇</div><strong>Nothing needs action</strong><p>Applications with high risk findings or past end of life will appear here.</p></td></tr>';
    return;
  }
  $('rows').innerHTML = results.map((a, i) => `<tr data-index="${i}" tabindex="0" aria-label="Review ${escape(a.name)}"><td><strong>${escape(a.name)}</strong><span class="vendor">${escape(a.vendor || a.cpeVendor)}</span></td><td class="mono">${escape(a.version)}</td><td>${escape(a.lifecycle?.note || 'Unknown')}</td><td>${a.vulnerabilities.length ? `<strong class="finding">${a.vulnerabilities.length} ${a.vendorConfirmed ? 'vendor' : 'possible'} finding${a.vulnerabilities.length === 1 ? '' : 's'}</strong>` : '<span class="muted">None found</span>'}<span class="vendor">${escape(a.assessmentSource || 'NVD')}</span></td><td><span class="badge ${a.status}"><i></i>${labels[a.status]}</span></td><td class="chevron">›</td></tr>`).join('');
  for (const row of $('rows').querySelectorAll('[data-index]')) {
    const open = () => showDetails(results[Number(row.dataset.index)]);
    row.addEventListener('click', open);
    row.addEventListener('keydown', e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); open(); } });
  }
}

function showEnvironmentStatus(data) {
  const smtp = data.smtp;
  if (smtp.unauthenticated) { $('settings-env-status').textContent = 'Unauthenticated relay selected. SMTP credentials are not used.'; return; }
  const passwordStatus = data.envStatus.passwordPresent ? 'password secret present' : data.envStatus.passwordFileConfigured ? 'password secret file missing or empty' : 'SMTP_PASSWORD_FILE not configured';
  $('settings-env-status').textContent = `Credential status: ${smtp.usernameEnv || 'username not configured'} ${smtp.usernameEnv ? data.envStatus.usernamePresent ? '(present)' : '(missing)' : ''}; ${passwordStatus}. Secret values are never shown or saved here.`;
}

async function loadOwners() {
  ownersLoaded = true;
  const list = $('owners-list');
  try {
    const response = await fetch('/api/owners', { cache: 'no-store' });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || 'Could not load owners');
    owners = data.owners || [];
    list.innerHTML = owners.length ? owners.map(owner => `<article class="owner-row"><div><h3>${escape(owner.name)}</h3><p>Email: ${escape(owner.email)}</p>${owner.escalationEmail ? `<p>Escalation: ${escape(owner.escalationEmail)}</p>` : ''}</div><span>${owner.applicationCount} application${owner.applicationCount === 1 ? '' : 's'} · ${owner.workspaceCount} workspace${owner.workspaceCount === 1 ? '' : 's'}</span><button type="button" data-owner="${escape(owner.id)}">Edit</button></article>`).join('') : '<p class="empty"><strong>No owners configured</strong><span>Add a reusable owner before assigning responsibility to applications or workspaces.</span></p>';
  } catch (error) { list.innerHTML = `<p class="form-error">${escape(error.message)}</p>`; }
}

function openOwnerEditor(id = '') {
  currentOwnerId = id;
  const owner = owners.find(item => item.id === id);
  $('owner-editor-title').textContent = owner ? 'Edit owner' : 'Add owner';
  $('owner-form').reset();
  $('owner-form').elements.name.value = owner?.name || '';
  $('owner-form').elements.email.value = owner?.email || '';
  $('owner-form').elements.escalationEmail.value = owner?.escalationEmail || '';
  $('owner-editor-id').innerHTML = owner ? `Owner ID: <code>${escape(owner.id)}</code> (immutable) · assigned to ${owner.applicationCount} application${owner.applicationCount === 1 ? '' : 's'} and ${owner.workspaceCount} workspace${owner.workspaceCount === 1 ? '' : 's'}` : 'A permanent owner ID will be generated when saved.';
  $('owner-delete').hidden = !owner;
  $('owner-delete').disabled = Boolean(owner?.applicationCount || owner?.workspaceCount);
  $('owner-error').hidden = true;
  $('owner-editor').showModal();
}

async function saveOwner(event) {
  event.preventDefault();
  try {
    const payload = Object.fromEntries(new FormData($('owner-form')));
    const knownOwners = resumeOwnerAssociation ? editorConfig.owners || [] : owners;
    if (!currentOwnerId && knownOwners.some(owner => owner.email.toLowerCase() === payload.email.trim().toLowerCase())) throw new Error('An owner with this email already exists. Select the existing owner instead.');
    const response = await fetch(currentOwnerId ? `/api/owners/${encodeURIComponent(currentOwnerId)}` : '/api/owners', { method: currentOwnerId ? 'PUT' : 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || 'Could not save owner');
    $('owner-editor').close();
    if (resumeOwnerAssociation && !currentOwnerId) {
      editorConfig.owners = [...(editorConfig.owners || []), data];
      owners = [...owners.filter(owner => owner.id !== data.id), data];
      ownersLoaded = false;
      editorSelections.ownerIds.add(data.id);
      const resume = resumeOwnerAssociation;
      resumeOwnerAssociation = null;
      openAssociation('ownerIds', resume.title);
      associationState.draft.add(data.id);
      renderAssociationList();
      return;
    }
    ownersLoaded = false;
    await loadOwners();
  } catch (error) { $('owner-error').textContent = error.message; $('owner-error').hidden = false; }
}

async function deleteOwner() {
  if (!currentOwnerId) return;
  try {
    const response = await fetch(`/api/owners/${encodeURIComponent(currentOwnerId)}`, { method: 'DELETE' });
    if (!response.ok) { const data = await response.json(); throw new Error(data.error || 'Could not remove owner'); }
    $('owner-editor').close();
    ownersLoaded = false;
    await loadOwners();
  } catch (error) { $('owner-error').textContent = error.message; $('owner-error').hidden = false; }
}

function closeOwnerEditor() {
  $('owner-editor').close();
  if (!resumeOwnerAssociation) return;
  const resume = resumeOwnerAssociation;
  resumeOwnerAssociation = null;
  openAssociation('ownerIds', resume.title);
}

async function loadLogs() {
  logsLoaded = true;
  const list = $('logs-list');
  const types = {
    system: { title: 'System events', description: 'Newest first. Scans, notifications, server activity, and runtime errors.' },
    feed: { title: 'Feed events', description: 'Newest first. Source requests, collection results, failures, and recovery.' },
    audit: { title: 'Audit events', description: 'Newest first. Attributable changes to configuration and access control.' },
    auth: { title: 'Authentication events', description: 'Newest first. Sign-ins, sign-outs, rejected sessions, and identity matching.' },
  };
  $('logs-title').textContent = types[activeLogType].title;
  $('logs-description').textContent = types[activeLogType].description;
  for (const button of document.querySelectorAll('[data-log-type]')) button.setAttribute('aria-selected', String(button.dataset.logType === activeLogType));
  try {
    const response = await fetch(`/api/logs?type=${encodeURIComponent(activeLogType)}`, { cache: 'no-store' });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || 'Could not load logs');
    list.innerHTML = data.entries.length ? data.entries.map(entry => {
      const authentication = entry.authentication;
      const identityDetails = authentication?.identities?.map(identity => identity.mappings.length
        ? identity.mappings.map(mapping => `${escape(mapping.name)} → ${escape(mapping.roles.join(', ') || 'No grants')}`).join('<br>')
        : `${escape(identity.source)}: ${escape(identity.value)} <span class="muted">(unmatched)</span>`).join('<br>') || '';
      const authContext = authentication ? [authentication.issuer ? `Provider: ${escape(authentication.issuer)}` : '', authentication.reason ? `Reason: ${escape(authentication.reason)}` : '', authentication.fromOrigin && authentication.toOrigin ? `${escape(authentication.fromOrigin)} → ${escape(authentication.toOrigin)}` : ''].filter(Boolean).join(' · ') : '';
      const showClaims = Boolean(authentication && (authentication.identities?.length || authentication.groupOverage || ['Sign-in succeeded', 'Sign-in denied'].includes(entry.message)));
      const authSummary = authentication ? `${authContext ? `<p>${authContext}</p>` : ''}${showClaims ? `<p>${authentication.groupCount} group value${authentication.groupCount === 1 ? '' : 's'} received · ${authentication.matchedCount} access value${authentication.matchedCount === 1 ? '' : 's'} matched · ${authentication.unmatchedCount} unmatched${authentication.groupOverage ? ' · group overage reported' : ''}</p>${identityDetails ? `<p class="log-identities">${identityDetails}</p>` : ''}` : ''}` : '';
      return `<article class="log-entry"><time>${escape(new Date(entry.at).toLocaleString())}</time><span class="log-level ${escape(entry.level)}">${escape(entry.level)}</span><div><strong>${escape(entry.message)}</strong>${entry.actor ? `<p class="log-actor">${escape(entry.actor.name)} · ${escape(entry.actor.username || entry.actor.subject)}</p>` : ''}${entry.detail ? `<p>${escape(entry.detail)}</p>` : ''}${authSummary}</div></article>`;
    }).join('') : '<p class="muted">No log entries yet.</p>';
  } catch (error) { logsLoaded = false; list.innerHTML = `<p class="form-error">${escape(error.message)}</p>`; }
}

function renderFeeds() {
  $('add-feed').hidden = !feedData.canManage;
  const list = $('feeds-list');
  list.innerHTML = feedData.feeds.length ? feedData.feeds.map(feed => {
    const state = feed.state || {};
    return `<article class="feed-row"><div><h3>${escape(feed.name)}</h3><p>${escape(feed.url)}</p></div><div class="feed-meta">${feed.categories.map(value => `<span class="feed-chip">${escape(value)}</span>`).join('')}</div><div><span class="feed-state ${escape(state.status || '')}">${escape(state.status || 'not checked')}</span><p>${state.checkedAt ? escape(new Date(state.checkedAt).toLocaleString()) : 'Waiting for first collection'} · ${(state.entries || []).length} entries${state.error ? `<br>${escape(state.error)}` : ''}</p></div><button type="button" data-feed="${escape(feed.id)}">${feed.canEdit ? 'Edit' : 'View'}</button></article>`;
  }).join('') : '<div class="empty"><strong>No feeds configured</strong><p>Add a vendor RSS, Atom, JSON, HTML, or GitHub advisory source.</p></div>';
}

async function loadFeeds() {
  feedsLoaded = true;
  try {
    const response = await fetch('/api/feeds', { cache: 'no-store' });
    feedData = await response.json();
    if (!response.ok) throw new Error(feedData.error || 'Could not load feeds');
    renderFeeds();
  } catch (error) { feedsLoaded = false; $('feeds-list').innerHTML = `<p class="form-error">${escape(error.message)}</p>`; }
}

function openFeedEditor(id = null) {
  currentFeedId = id;
  const feed = feedData.feeds.find(item => item.id === id);
  const editable = !feed || feed.canEdit;
  const form = $('feed-form');
  form.reset();
  $('feed-editor-title').textContent = feed ? editable ? 'Edit feed' : 'View feed' : 'Add feed';
  $('feed-editor-id').innerHTML = feed ? `Feed ID: <code>${escape(feed.id)}</code> (immutable)` : 'A permanent feed ID will be generated when saved.';
  form.elements.name.value = feed?.name || '';
  form.elements.url.value = feed?.url || '';
  form.elements.format.value = feed?.format || 'auto';
  form.elements.productAliases.value = (feed?.productAliases || []).join(', ');
  form.elements.enabled.checked = feed?.enabled !== false;
  for (const input of form.querySelectorAll('[name="category"]')) input.checked = (feed?.categories || ['security', 'release', 'lifecycle']).includes(input.value);
  $('feed-applications').querySelector('.check-grid').innerHTML = feedData.applications.map(app => `<label><input type="checkbox" name="feedApplication" value="${escape(app.id)}" ${(feed?.applicationIds || []).includes(app.id) ? 'checked' : ''} ${feedData.canManage ? '' : 'disabled'}> ${escape(app.name)}</label>`).join('') || '<p class="muted">No visible applications.</p>';
  for (const input of form.querySelectorAll('input,select')) if (input.name !== 'feedApplication') input.disabled = !editable;
  $('feed-save').hidden = !editable;
  $('feed-test').hidden = !feed || !editable;
  $('feed-refresh').hidden = !feed || !editable;
  $('feed-delete').hidden = !feed || !feedData.canManage;
  $('feed-preview').hidden = true;
  $('feed-preview').innerHTML = '';
  $('feed-error').hidden = true;
  $('feed-editor').showModal();
}

async function saveFeed(event) {
  event.preventDefault();
  const form = $('feed-form');
  const payload = {
    name: form.elements.name.value, url: form.elements.url.value, format: form.elements.format.value,
    enabled: form.elements.enabled.checked,
    categories: [...form.querySelectorAll('[name="category"]:checked')].map(input => input.value),
    productAliases: form.elements.productAliases.value.split(',').map(value => value.trim()).filter(Boolean),
    applicationIds: [...form.querySelectorAll('[name="feedApplication"]:checked')].map(input => input.value),
  };
  $('feed-save').disabled = true; $('feed-error').hidden = true;
  try {
    const response = await fetch(currentFeedId ? `/api/feeds/${encodeURIComponent(currentFeedId)}` : '/api/feeds', { method: currentFeedId ? 'PUT' : 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || 'Could not save feed');
    $('feed-editor').close(); feedsLoaded = false; await loadFeeds(); void load(false, true);
  } catch (error) { $('feed-error').textContent = error.message; $('feed-error').hidden = false; }
  finally { $('feed-save').disabled = false; }
}

async function testFeed() {
  $('feed-test').disabled = true; $('feed-error').hidden = true;
  try {
    const response = await fetch(`/api/feeds/${encodeURIComponent(currentFeedId)}/test`, { method: 'POST' });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || 'Feed test failed');
    $('feed-preview').innerHTML = data.entries.length ? data.entries.map(entry => `<article><strong>${escape(entry.title)}</strong><small>${escape(entry.type)} · ${escape(entry.confidence)} confidence · ${escape(entry.severity)}</small><p>${escape(entry.summary)}</p></article>`).join('') : '<p class="muted">The source was fetched safely, but no configured event types were recognized.</p>';
    $('feed-preview').hidden = false;
  } catch (error) { $('feed-error').textContent = error.message; $('feed-error').hidden = false; }
  finally { $('feed-test').disabled = false; }
}

async function refreshFeed() {
  $('feed-refresh').disabled = true; $('feed-error').hidden = true;
  try {
    const response = await fetch(`/api/feeds/${encodeURIComponent(currentFeedId)}/refresh`, { method: 'POST' });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || 'Feed collection failed');
    $('feed-preview').innerHTML = `<p><strong>Collection complete.</strong> ${escape(data.state.entries?.length || 0)} entries cached.</p>`;
    $('feed-preview').hidden = false;
    feedsLoaded = false; await loadFeeds();
  } catch (error) { $('feed-error').textContent = error.message; $('feed-error').hidden = false; }
  finally { $('feed-refresh').disabled = false; }
}

async function deleteFeed() {
  if (!confirm('Remove this feed and its application associations?')) return;
  const response = await fetch(`/api/feeds/${encodeURIComponent(currentFeedId)}`, { method: 'DELETE' });
  if (!response.ok) { const data = await response.json(); $('feed-error').textContent = data.error || 'Could not remove feed'; $('feed-error').hidden = false; return; }
  $('feed-editor').close(); feedsLoaded = false; await loadFeeds(); void load(false, true);
}

function updateCredentialFields() {
  const form = $('settings-form');
  const relay = form.querySelector('[name="unauthenticated"]').checked;
  const enabled = form.querySelector('[name="enabled"]').checked;
  for (const input of form.querySelectorAll('.credential-field input')) { input.disabled = relay; input.required = enabled && !relay; }
  for (const name of ['host', 'port', 'from']) form.querySelector(`[name="${name}"]`).required = enabled;
  if (relay) $('settings-env-status').textContent = 'Unauthenticated relay selected. SMTP credentials are not used.';
}

async function loadSettings() {
  settingsLoaded = true;
  try {
    const response = await fetch('/api/settings', { cache: 'no-store' });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || 'Could not load settings');
    $('settings-version').textContent = data.version || 'Unknown';
    const form = $('settings-form');
    for (const [key, value] of Object.entries(data.smtp)) {
      const input = form.querySelector(`[name="${key}"]`);
      if (!input) continue;
      if (input.type === 'checkbox') input.checked = Boolean(value);
      else input.value = value ?? '';
    }
    const general = data.general?.host ? data.general : { protocol: location.protocol.replace(':', '') || 'http', host: location.hostname, port: Number(location.port) || (location.protocol === 'https:' ? 443 : 80) };
    form.querySelector('[name="protocol"]').value = general.protocol;
    form.querySelector('[name="publicHost"]').value = general.host;
    form.querySelector('[name="publicPort"]').value = general.port;
    form.querySelector(`[name="transportSecurity"][value="${data.smtp.secure ? 'tls' : data.smtp.requireTls ? 'starttls' : 'none'}"]`).checked = true;
    updateCredentialFields();
    showEnvironmentStatus(data);
  } catch (error) { settingsLoaded = false; $('settings-message').textContent = error.message; $('settings-message').hidden = false; $('settings-message').classList.remove('success'); }
}

async function saveSettings(event) {
  event.preventDefault();
  const form = $('settings-form');
  const fields = new FormData(form);
  const payload = Object.fromEntries(fields);
  delete payload.testRecipient;
  const general = { protocol: payload.protocol, host: payload.publicHost, port: Number(payload.publicPort) };
  delete payload.protocol;
  delete payload.publicHost;
  delete payload.publicPort;
  delete payload.transportSecurity;
  const security = form.querySelector('[name="transportSecurity"]:checked')?.value;
  payload.secure = security === 'tls';
  payload.requireTls = security === 'starttls';
  payload.unauthenticated = form.querySelector('[name="unauthenticated"]').checked;
  if (payload.unauthenticated) payload.usernameEnv = form.querySelector('[name="usernameEnv"]').value;
  payload.enabled = form.querySelector('[name="enabled"]').checked;
  payload.port = payload.port === '' ? '' : Number(payload.port);
  payload.sendHour = payload.sendHour === '' ? '' : Number(payload.sendHour);
  $('settings-save').disabled = true;
  $('settings-message').hidden = true;
  try {
    const response = await fetch('/api/settings', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ smtp: payload, general }) });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || 'Could not save settings');
    settingsLoaded = false;
    await loadSettings();
    $('settings-message').textContent = 'Settings saved.';
    $('settings-message').classList.add('success');
    $('settings-message').hidden = false;
  } catch (error) { $('settings-message').textContent = error.message; $('settings-message').classList.remove('success'); $('settings-message').hidden = false; }
  finally { $('settings-save').disabled = false; }
}

async function testEmailSettings() {
  const form = $('settings-form');
  const fields = new FormData(form);
  const payload = Object.fromEntries(fields);
  const recipient = String(payload.testRecipient || '').trim();
  delete payload.testRecipient;
  delete payload.protocol; delete payload.publicHost; delete payload.publicPort; delete payload.transportSecurity;
  const security = form.querySelector('[name="transportSecurity"]:checked')?.value;
  payload.secure = security === 'tls';
  payload.requireTls = security === 'starttls';
  payload.unauthenticated = form.querySelector('[name="unauthenticated"]').checked;
  payload.enabled = true;
  payload.port = payload.port === '' ? '' : Number(payload.port);
  payload.sendHour = payload.sendHour === '' ? '' : Number(payload.sendHour);
  if (payload.unauthenticated) payload.usernameEnv = form.querySelector('[name="usernameEnv"]').value;
  $('settings-test-email').disabled = true;
  $('settings-message').hidden = true;
  try {
    const response = await fetch('/api/settings/test-email', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ smtp: payload, recipient }) });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || 'Could not send test email');
    $('settings-message').textContent = `Test email sent to ${recipient}. Settings were not saved.`;
    $('settings-message').classList.add('success'); $('settings-message').hidden = false;
  } catch (error) { $('settings-message').textContent = error.message; $('settings-message').classList.remove('success'); $('settings-message').hidden = false; }
  finally { $('settings-test-email').disabled = false; }
}

function identityRow(group = {}) {
  return `<article class="access-row identity-row" data-id="${escape(group.id || '')}"><div class="form-grid"><label>Display name <input data-field="name" required value="${escape(group.name || '')}" placeholder="Infrastructure Admins"></label><label>Claim source <select data-field="claimSource"><option value="groups">groups</option><option value="roles">roles</option><option value="realm_access.roles">realm_access.roles</option><option value="resource_access.roles">resource_access.roles</option></select></label><label class="form-full">Exact claim value <input data-field="claimValue" required value="${escape(group.claimValue || '')}" placeholder="Group UUID or role name"></label></div><div class="identity-options"><label><input data-field="enabled" type="checkbox" ${group.enabled === false ? '' : 'checked'}> Enabled</label><label><input data-preview-mapping type="checkbox" ${selectedMappingIds.has(group.id) ? 'checked' : ''}> Include in verification</label></div><button class="remove-access" type="button">Remove</button>${group.id ? `<small>ID: <code>${escape(group.id)}</code></small>` : ''}</article>`;
}

function grantRow(grant = {}) {
  const groups = accessData?.groups || [];
  const scope = grant.scopeType || 'workspace';
  const roleOptions = Object.entries(accessData?.roles || {}).filter(([, value]) => value.scopes.includes(scope));
  const resources = scope === 'workspace' ? accessData?.workspaces || [] : scope === 'application' ? accessData?.applications || [] : scope === 'feed' ? accessData?.feeds || [] : [];
  const resourceTitle = scope === 'workspace' ? 'Workspaces' : scope === 'application' ? 'Applications' : 'Feeds';
  return `<article class="access-row grant-row" data-id="${escape(grant.id || '')}"><div class="form-grid"><label>Identity mapping <select data-field="groupId" required>${groups.map(group => `<option value="${escape(group.id)}" ${group.id === grant.groupId ? 'selected' : ''}>${escape(group.name)}</option>`).join('')}</select></label><label>Scope <select data-field="scopeType"><option value="workspace" ${scope === 'workspace' ? 'selected' : ''}>Workspace</option><option value="application" ${scope === 'application' ? 'selected' : ''}>Application</option><option value="feed" ${scope === 'feed' ? 'selected' : ''}>Feed</option><option value="global" ${scope === 'global' ? 'selected' : ''}>Global</option></select></label></div><fieldset><legend>Roles</legend><div class="check-grid">${roleOptions.map(([id, role]) => `<label><input data-role="${escape(id)}" type="checkbox" ${grant.roles?.includes(id) ? 'checked' : ''}> ${escape(role.name)}</label>`).join('')}</div></fieldset>${scope === 'global' ? '' : `<fieldset><legend>${resourceTitle}</legend><select data-field="resourceIds" multiple size="5">${resources.map(item => `<option value="${escape(item.id)}" ${grant.resourceIds?.includes(item.id) ? 'selected' : ''}>${escape(resourceLabel(item, resources))}</option>`).join('')}</select></fieldset>`}<label class="verification-option"><input data-preview-grant type="checkbox" ${selectedGrantIds.has(grant.id) ? 'checked' : ''}> Include this grant in verification</label><button class="remove-access" type="button">Remove</button>${grant.id ? `<small>ID: <code>${escape(grant.id)}</code></small>` : ''}</article>`;
}

function resourceLabel(item, list) { return list.filter(other => other.name === item.name).length > 1 ? `${item.name} (${item.id})` : item.name; }
function renderAccess() {
  $('identity-list').innerHTML = accessData.groups.map(identityRow).join('') || '<p class="muted">No identity mappings configured.</p>';
  $('grant-list').innerHTML = accessData.grants.map(grantRow).join('') || '<p class="muted">No grants configured.</p>';
  $('session-claims').textContent = JSON.stringify(accessData.session, null, 2);
  for (const row of $('identity-list').querySelectorAll('.identity-row')) row.querySelector('[data-field="claimSource"]').value = accessData.groups.find(item => item.id === row.dataset.id)?.claimSource || 'groups';
}
function clearAccessDraft() {
  try { sessionStorage.removeItem(accessDraftKey); } catch {}
}
function saveAccessDraft(config) {
  try {
    sessionStorage.setItem(accessDraftKey, JSON.stringify({ config, mappingIds: [...selectedMappingIds], grantIds: [...selectedGrantIds], expires: Date.now() + accessDraftLifetime }));
  } catch {}
}
function restoreAccessDraft() {
  try {
    const draft = JSON.parse(sessionStorage.getItem(accessDraftKey) || 'null');
    if (!draft || draft.expires <= Date.now() || !Array.isArray(draft.config?.groups) || !Array.isArray(draft.config?.grants)) { clearAccessDraft(); return false; }
    accessData = { ...accessData, groups: draft.config.groups, grants: draft.config.grants };
    selectedMappingIds.clear();
    for (const id of draft.mappingIds || []) selectedMappingIds.add(id);
    selectedGrantIds.clear();
    for (const id of draft.grantIds || []) selectedGrantIds.add(id);
    return true;
  } catch { clearAccessDraft(); return false; }
}
async function loadAccess() {
  accessLoaded = true;
  try { const response = await fetch('/api/rbac', { cache: 'no-store' }); accessData = await response.json(); if (!response.ok) throw new Error(accessData.error || 'Could not load access control'); if (!restoreAccessDraft()) { selectedMappingIds.clear(); selectedGrantIds.clear(); for (const grant of accessData.grants) selectedGrantIds.add(grant.id); } renderAccess(); }
  catch (error) { accessLoaded = false; $('access-message').textContent = error.message; $('access-message').hidden = false; }
}
function collectAccess() {
  const groups = [...$('identity-list').querySelectorAll('.identity-row')].map(row => ({ id: row.dataset.id, name: row.querySelector('[data-field="name"]').value, claimSource: row.querySelector('[data-field="claimSource"]').value, claimValue: row.querySelector('[data-field="claimValue"]').value, enabled: row.querySelector('[data-field="enabled"]').checked }));
  const grants = [...$('grant-list').querySelectorAll('.grant-row')].map(row => ({ id: row.dataset.id, groupId: row.querySelector('[data-field="groupId"]').value, scopeType: row.querySelector('[data-field="scopeType"]').value, roles: [...row.querySelectorAll('[data-role]:checked')].map(input => input.dataset.role), resourceIds: [...(row.querySelector('[data-field="resourceIds"]')?.selectedOptions || [])].map(option => option.value) }));
  return { groups, grants };
}
async function saveAccess(event) {
  event.preventDefault(); $('access-save').disabled = true;
  try { const response = await fetch('/api/rbac', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(collectAccess()) }); const data = await response.json(); if (!response.ok) throw new Error(data.error || 'Could not save access control'); clearAccessDraft(); accessLoaded = false; await loadAccess(); $('access-message').textContent = 'Access control saved.'; $('access-message').classList.add('success'); $('access-message').hidden = false; }
  catch (error) { $('access-message').textContent = error.message; $('access-message').classList.remove('success'); $('access-message').hidden = false; }
  finally { $('access-save').disabled = false; }
}

function accessList(title, items) {
  return `<div><strong>${escape(title)}</strong>${items.length ? `<ul>${items.map(item => `<li>${escape(item.name)}</li>`).join('')}</ul>` : '<p class="muted">None</p>'}</div>`;
}

function renderAccessExplanation(data) {
  const mappings = data.selectedMappings.length ? data.selectedMappings.map(item => `${item.name}${item.enabled ? '' : ' (disabled)'}`).join(', ') : 'Unmatched authenticated user';
  const grants = data.grants.length ? data.grants.map(grant => `<article><strong>${escape(grant.identity)}</strong><span>${escape(grant.scopeType)}</span><p>${grant.roles.map(role => escape(role.name)).join(', ')}</p>${grant.resources.length ? `<small>${grant.resources.map(item => escape(item.name)).join(', ')}</small>` : ''}</article>`).join('') : '<p class="muted">No grants matched.</p>';
  const globals = [data.access.accessManage ? 'Access Administrator' : '', data.access.scan ? 'Scan Operator' : '', data.access.feeds.manage ? 'Feed Manager' : ''].filter(Boolean).map(name => ({ name }));
  $('access-explanation').innerHTML = `<div class="verification-summary"><span>SELECTED IDENTITY</span><strong>${escape(mappings)}</strong></div><h3>Contributing grants</h3><div class="verification-grants">${grants}</div><h3>Effective permissions</h3><div class="verification-grid">${accessList('Global', globals)}${accessList('Applications visible', data.effective.applications.view)}${accessList('Applications editable', data.effective.applications.edit)}${accessList('Workspaces visible', data.effective.workspaces.view)}${accessList('Workspaces manageable', data.effective.workspaces.edit)}${accessList('Workspace membership', data.effective.workspaces.membership)}${accessList('Workspace notifications', data.effective.workspaces.notifications)}${accessList('Feeds visible', data.effective.feeds.view)}${accessList('Feeds editable', data.effective.feeds.edit)}</div>`;
}

async function verifyAccess(startPreview = false) {
  const button = startPreview ? $('access-preview') : $('access-evaluate');
  button.disabled = true;
  $('access-message').hidden = true;
  try {
    const config = collectAccess();
    const selected = config.groups.filter(group => selectedMappingIds.has(group.id));
    const name = selected.map(group => group.name).filter(Boolean).join(' + ') || 'Unmatched authenticated user';
    const response = await fetch(startPreview ? '/api/rbac/preview' : '/api/rbac/evaluate', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ config, mappingIds: [...selectedMappingIds], grantIds: [...selectedGrantIds], name }) });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || 'Could not verify access');
    renderAccessExplanation(startPreview ? data.explanation : data);
    if (startPreview) { saveAccessDraft(config); previewNavigation = true; location.hash = 'overview'; location.reload(); }
  } catch (error) {
    $('access-message').textContent = error.message;
    $('access-message').classList.remove('success');
    $('access-message').hidden = false;
  } finally { button.disabled = false; }
}

function render(data) {
  allResults = data.results || [];
  workspaces = data.workspaces || [];
  if (!ownersLoaded) owners = data.owners || [];
  permissions = data.access || permissions;
  isAdmin = Boolean(permissions.isAdmin);
  canManageAccess = Boolean(permissions.accessManage);
  $('admin-actions').hidden = !isAdmin;
  $('logs-nav').hidden = !isAdmin;
  $('settings-nav').hidden = !isAdmin;
  $('owners-nav').hidden = !isAdmin;
  $('access-nav').hidden = !canManageAccess;
  $('refresh').hidden = !(isAdmin || permissions.scan);
  $('feeds-nav').hidden = !(isAdmin || permissions.feeds?.view?.length || permissions.feeds?.manage);
  $('updated').textContent = `Checked ${new Date(data.checkedAt).toLocaleString()}`;
  renderSidebar();
  renderView();
}

function showDetails(a) {
  detailAppId = a.id;
  $('detail-name').textContent = a.name;
  $('detail-kicker').textContent = `${a.version} · ${labels[a.status].toUpperCase()}`;
  $('edit-app').hidden = !(isAdmin || permissions.applications.edit.includes(a.id));
  const findings = a.vulnerabilities.length ? a.vulnerabilities.map(v => `<article class="vuln"><div class="vuln-top"><a href="${safeUrl(v.url)}" target="_blank" rel="noopener noreferrer">${escape(v.id)} ↗</a><span class="badge ${v.knownExploited ? 'red' : 'yellow'}">${v.knownExploited ? 'Known exploited' : `${v.label} · ${v.score}`}</span></div><p>${escape(v.description)}</p>${v.advisories.map(url => `<a class="source" href="${safeUrl(url)}" target="_blank" rel="noopener noreferrer">Vendor advisory ↗</a>`).join('')}</article>`).join('') : `<p class="muted">No high or critical CVEs found for this version in ${escape(a.assessmentSource || 'the current source')}.</p>`;
  const upgrade = a.upgrades || {};
  const releaseLink = upgrade.sourceUrl ? `<a href="${safeUrl(upgrade.sourceUrl)}" target="_blank" rel="noopener noreferrer">Release source ↗</a>` : '';
  const containing = workspaces.filter(group => group.applications.includes(a.id));
  const sharedWarning = containing.length > 1 && (isAdmin || permissions.applications.edit.includes(a.id)) ? `<p class="form-error">This application is shared by ${containing.length} workspaces. Editing it changes the application everywhere it appears.</p>` : '';
  const assignedOwners = (a.ownerIds || []).map(id => owners.find(owner => owner.id === id)).filter(Boolean);
  const ownership = assignedOwners.length ? assignedOwners.map(owner => `<article class="owner-contact"><strong>${escape(owner.name)}</strong><span>Email: ${escape(owner.email)}</span>${owner.escalationEmail ? `<span>Escalation: ${escape(owner.escalationEmail)}</span>` : ''}</article>`).join('') : '<p class="muted">No owner assigned.</p>';
  const context = `<div class="detail-grid context-grid"><div><span>CRITICALITY</span><strong>${escape(a.criticality || 'unspecified')}</strong></div><div><span>ENVIRONMENT</span><strong>${escape(a.environment || 'unspecified')}</strong></div><div><span>EXPOSURE</span><strong>${escape(a.exposure || 'unknown')}</strong></div><div><span>TAGS</span><strong>${escape((a.tags || []).join(', ') || 'None')}</strong></div></div><h3>Ownership</h3><div class="owner-contacts">${ownership}</div>`;
  const feedEvidence = (a.feedEvents || []).length ? `<h3>Feed evidence</h3>${a.feedEvents.map(event => `<div class="feed-evidence"><a href="${safeUrl(event.url)}" target="_blank" rel="noopener noreferrer">${escape(event.title)} ↗</a><span class="vendor">${escape(event.type)} · ${escape(event.confidence)} confidence${event.severity && event.severity !== 'UNKNOWN' ? ` · ${escape(event.severity)}` : ''}</span></div>`).join('')}` : '';
  $('detail-body').innerHTML = `${sharedWarning}<div class="detail-grid"><div><span>INSTALLED VERSION</span><strong>${escape(a.version)}</strong></div><div><span>LATEST AVAILABLE</span><strong>${escape(upgrade.latest || 'Unavailable')}</strong>${releaseLink}</div><div><span>LATEST ON INSTALLED LINE</span><strong>${escape(upgrade.currentLine || 'Unavailable')}</strong></div><div><span>LATEST LTS VERSION</span><strong>${escape(upgrade.latestLts || 'No designated LTS')}</strong></div><div><span>SUPPORT</span><strong>${escape(a.lifecycle?.note || 'Unknown')}</strong></div></div><h3>Application context</h3>${context}<h3>Assessment</h3><ul class="reasons">${a.reasons.map(r => `<li>${escape(r)}</li>`).join('')}</ul><h3>Vulnerability findings</h3>${findings}${feedEvidence}<h3>Sources</h3><div class="sources">${a.sources.map(s => `<a href="${safeUrl(s.url)}" target="_blank" rel="noopener noreferrer">${escape(s.name)} ↗</a>`).join('') || '<span class="muted">No source links available</span>'}</div><p class="detail-note">CPE: <code>${escape(a.cpe)}</code>. Confirm product identity and affected version ranges in the linked advisories before remediation decisions.</p>`;
  $('details').showModal();
}

function associationRow(key, title, emptyText) {
  const count = editorSelections[key].size;
  return `<section class="association-summary"><div><strong>${escape(title)}</strong><span id="${key}-summary">${count ? `${count} selected` : escape(emptyText)}</span></div><button type="button" data-association="${key}">Choose</button></section>`;
}

function associationItems(key) {
  if (key === 'ownerIds') return (editorConfig.owners || []).map(item => ({ ...item, detail: item.email }));
  if (key === 'workspaceIds') return editorConfig.workspaces || [];
  if (key === 'feedIds') return editorConfig.feeds || [];
  return (editorConfig.applications || []).filter(item => item.enabled !== false);
}

function renderAssociationList() {
  if (!associationState) return;
  const query = $('association-search').value.trim().toLowerCase();
  const items = associationState.items.filter(item => `${item.name} ${item.detail || ''}`.toLowerCase().includes(query));
  $('association-list').innerHTML = items.length ? items.map(item => `<label><input type="checkbox" value="${escape(item.id)}" ${associationState.draft.has(item.id) ? 'checked' : ''}> <span><strong>${escape(item.name)}</strong>${item.detail ? `<small>${escape(item.detail)}</small>` : ''}</span></label>`).join('') : '<p class="muted">No matching items.</p>';
}

function openAssociation(key, title) {
  associationState = { key, items: associationItems(key), draft: new Set(editorSelections[key]) };
  $('association-title').textContent = title;
  const canCreateOwner = isAdmin || permissions.applications.edit.length > 0 || permissions.workspaces.notifications.length > 0;
  $('association-add-owner').hidden = key !== 'ownerIds' || !canCreateOwner;
  $('association-search').value = '';
  renderAssociationList();
  $('association-dialog').showModal();
  $('association-search').focus();
}

function applyAssociation() {
  if (!associationState) return;
  editorSelections[associationState.key] = new Set(associationState.draft);
  const summary = $(`${associationState.key}-summary`);
  if (summary) summary.textContent = editorSelections[associationState.key].size ? `${editorSelections[associationState.key].size} selected` : 'None selected';
  $('association-dialog').close();
}

async function openEditor(mode, targetId = null) {
  editorMode = mode;
  editorTargetId = targetId;
  $('editor-error').hidden = true;
  $('editor-danger').hidden = true;
  $('editor-fields').innerHTML = '<p class="muted">Loading inventory…</p>';
  $('editor-title').textContent = mode === 'app' ? targetId ? 'Edit application' : 'Add application' : targetId ? 'Edit workspace' : 'Add or edit workspace';
  $('editor').showModal();
  try {
    const response = await fetch('/api/config', { cache: 'no-store' });
    editorConfig = await response.json();
    if (!response.ok) throw new Error(editorConfig.error || 'Could not load inventory');
    editorSelections = { ownerIds: new Set(), workspaceIds: new Set(), feedIds: new Set(), applicationIds: new Set() };
    if (mode === 'app') {
      $('editor-fields').innerHTML = `<div class="form-grid">
        <label>Display name <input name="name" required placeholder="Application name"></label>
        <label>Vendor <input name="vendor" placeholder="Vendor name"></label>
        <label>Installed version <input name="version" required pattern="[A-Za-z0-9._-]+" placeholder="1.2.3"></label>
        <label>Criticality <select name="criticality"><option value="unspecified">Unspecified</option><option value="low">Low</option><option value="medium">Medium</option><option value="high">High</option><option value="critical">Critical</option></select></label>
        <label>Environment <select name="environment"><option value="unspecified">Unspecified</option><option value="production">Production</option><option value="staging">Staging</option><option value="development">Development</option><option value="test">Test</option><option value="disaster-recovery">Disaster recovery</option></select></label>
        <label>Exposure <select name="exposure"><option value="unknown">Unknown</option><option value="internal">Internal</option><option value="external">Externally accessible</option><option value="internet">Internet-facing</option></select></label>
        <label class="form-full">Tags <input name="tags" placeholder="payments, customer-facing, pci"></label>
        <section class="form-full mapping-summary"><div><span>VULNERABILITY MAPPING</span><strong id="mapping-title">No CPE selected</strong><code id="mapping-cpe"></code><small id="mapping-mode"></small></div><button id="change-cpe" type="button">Choose CPE</button></section>
        <input name="cpeName" type="hidden"><input name="cpeMode" type="hidden"><input name="cpeTitle" type="hidden"><input name="cpeDeprecated" type="hidden"><input name="cpeLastTestedAt" type="hidden"><input name="cpeTestCandidateCount" type="hidden"><input name="cpeTestApplicableCount" type="hidden">
        <section class="form-full mapping-summary"><div><span>LIFECYCLE MAPPING</span><strong id="lifecycle-title">No lifecycle product selected</strong><code id="lifecycle-product"></code><small id="lifecycle-mode"></small></div><button id="change-lifecycle" type="button">Choose source</button></section>
        <input name="lifecycleProduct" type="hidden">
        <label>Manual end-of-life date <input name="eolDate" type="date"></label>
        <label>Lifecycle source URL <input name="lifecycleUrl" type="url" placeholder="https://…"></label>
        <label>Vendor security URL <input name="vendorBulletinUrl" type="url" placeholder="https://…"></label>
        <label>Release notes URL <input name="releaseUrl" type="url" placeholder="https://…"></label>
        <label>Latest version override <input name="latestVersion" placeholder="Optional"></label>
        <label>Latest installed-line override <input name="latestBranchVersion" placeholder="Optional"></label>
        <label>Latest LTS override <input name="latestLtsVersion" placeholder="Optional"></label>
      </div>${targetId ? `<p class="form-hint">Application ID: <code>${escape(targetId)}</code> (immutable)</p>` : ''}<p class="form-hint">Provide a lifecycle product or a manual end-of-life date. Vulnerability mappings use the canonical NVD CPE Dictionary.</p><div class="association-summaries">${associationRow('ownerIds', 'Owners', 'None selected')}${associationRow('workspaceIds', 'Workspaces', 'None selected')}${associationRow('feedIds', 'Feeds', 'None selected')}</div>`;
      $('change-cpe').addEventListener('click', openCpeDialog);
      $('change-lifecycle').addEventListener('click', openLifecycleDialog);
      cpeMapping = null;
      lifecycleMapping = null;
      if (targetId) {
        const app = editorConfig.applications.find(item => item.id === targetId);
        if (!app) throw new Error('Application not found');
        for (const [key, value] of Object.entries(app)) {
          const input = $('editor-form').querySelector(`[name="${key}"]`);
          if (input && input.type !== 'checkbox') input.value = value ?? '';
        }
        editorSelections.workspaceIds = new Set(editorConfig.workspaces.filter(group => group.applications.includes(targetId)).map(group => group.id));
        editorSelections.feedIds = new Set(editorConfig.feeds.filter(feed => feed.applicationIds.includes(targetId)).map(feed => feed.id));
        editorSelections.ownerIds = new Set(app.ownerIds || []);
        for (const key of ['ownerIds', 'workspaceIds', 'feedIds']) $(`${key}-summary`).textContent = editorSelections[key].size ? `${editorSelections[key].size} selected` : 'None selected';
        $('editor-form').elements.tags.value = (app.tags || []).join(', ');
        cpeMapping = { cpeName: app.cpeName || `cpe:2.3:a:${app.cpeVendor}:${app.cpeProduct}:*:*:*:*:${app.cpeEdition || '*'}:*:*:*`, mode: app.cpeMode || 'product', title: app.cpeTitle || app.name, deprecated: app.cpeDeprecated === true || app.cpeDeprecated === 'true', testedAt: app.cpeLastTestedAt || '', candidateCount: app.cpeTestCandidateCount || '', applicableCount: app.cpeTestApplicableCount || '' };
        if (app.lifecycleProduct) lifecycleMapping = { name: app.lifecycleProduct, label: app.lifecycleProduct, sourceUrl: app.lifecycleUrl || `https://endoflife.date/${app.lifecycleProduct}` };
      }
      updateEditorDanger();
      renderMappingSummary();
      renderLifecycleSummary();
    } else {
      $('editor-fields').innerHTML = `<label class="form-full">Workspace to edit <select id="workspace-choice"><option value="">New workspace</option>${editorConfig.workspaces.map(group => `<option value="${escape(group.id)}">${escape(group.name)}</option>`).join('')}</select></label><div class="form-grid"><label>Workspace name <input name="name" required placeholder="Customer, system, or group name"></label></div><p id="workspace-id-label" class="form-hint"></p><p class="form-hint">Workspace owners receive notifications for the applications assigned here.</p><div class="association-summaries">${associationRow('ownerIds', 'Workspace owners', 'None selected')}${associationRow('applicationIds', 'Applications', 'None selected')}</div>`;
      $('workspace-choice').addEventListener('change', populateWorkspaceEditor);
      if (targetId) { $('workspace-choice').value = targetId; populateWorkspaceEditor(); $('workspace-choice').hidden = true; $('workspace-choice').closest('label').hidden = true; }
    }
  } catch (error) { $('editor-fields').innerHTML = ''; $('editor-error').textContent = error.message; $('editor-error').hidden = false; }
}

function renderMappingSummary() {
  const form = $('editor-form');
  $('mapping-title').textContent = cpeMapping?.title || 'No CPE selected';
  $('mapping-cpe').textContent = cpeMapping?.cpeName || '';
  $('mapping-mode').textContent = cpeMapping ? `${cpeMapping.mode === 'exact' ? 'Exact CPE' : 'Product mapping'}${cpeMapping.testedAt ? ` · tested ${new Date(cpeMapping.testedAt).toLocaleString()}` : ' · not tested'}` : 'Choose a mapping before saving.';
  for (const [name, value] of Object.entries({ cpeName: cpeMapping?.cpeName || '', cpeMode: cpeMapping?.mode || '', cpeTitle: cpeMapping?.title || '', cpeDeprecated: String(Boolean(cpeMapping?.deprecated)), cpeLastTestedAt: cpeMapping?.testedAt || '', cpeTestCandidateCount: cpeMapping?.candidateCount ?? '', cpeTestApplicableCount: cpeMapping?.applicableCount ?? '' })) form.elements[name].value = value;
}

function renderLifecycleSummary() {
  const form = $('editor-form');
  $('lifecycle-title').textContent = lifecycleMapping?.label || lifecycleMapping?.name || 'No lifecycle product selected';
  $('lifecycle-product').textContent = lifecycleMapping?.name || '';
  $('lifecycle-mode').textContent = lifecycleMapping ? `${lifecycleMapping.matchedRelease ? `Matched release ${lifecycleMapping.matchedRelease.cycle}` : 'endoflife.date product'}${lifecycleMapping.testedAt ? ` · tested ${new Date(lifecycleMapping.testedAt).toLocaleString()}` : ''}` : 'Choose an endoflife.date product or use a manual date.';
  form.elements.lifecycleProduct.value = lifecycleMapping?.name || '';
  form.elements.lifecycleUrl.value = lifecycleMapping?.sourceUrl || '';
}

function openLifecycleDialog() {
  lifecycleDraft = lifecycleMapping ? { ...lifecycleMapping } : null;
  $('lifecycle-error').hidden = true;
  $('lifecycle-error').textContent = '';
  $('lifecycle-search-form').elements.q.value = lifecycleMapping?.name || $('editor-form').elements.name.value;
  $('lifecycle-search-hint').textContent = cpeMapping ? `Suggested results use ${cpeMapping.title || cpeMapping.cpeName} as a ranking hint.` : 'Select a CPE first for better lifecycle suggestions.';
  renderLifecycleSelection();
  $('lifecycle-dialog').showModal();
  searchLifecycleProducts();
}

function lifecycleDate(value) {
  if (value === false) return 'Not announced';
  if (value === true) return 'Ended';
  return value || 'Unknown';
}

function renderLifecycleSelection() {
  $('lifecycle-selection').hidden = !lifecycleDraft?.product;
  if (!lifecycleDraft?.product) return;
  const { product, matchedRelease, warnings = [] } = lifecycleDraft;
  $('lifecycle-selection-title').textContent = product.label;
  $('lifecycle-selection-name').textContent = product.name;
  $('lifecycle-identifiers').innerHTML = product.identifiers.length ? product.identifiers.map(item => `<code>${escape(item.type)}: ${escape(item.id)}</code>`).join('') : '<span class="muted">No package or CPE identifiers published.</span>';
  $('lifecycle-warnings').innerHTML = warnings.map(item => `<p class="cpe-warning ${escape(item.level)}"><strong>${escape(item.level)}</strong> ${escape(item.message)}</p>`).join('');
  $('lifecycle-match').innerHTML = matchedRelease ? `<p class="form-error success">Installed version matches release ${escape(matchedRelease.cycle)} · latest ${escape(matchedRelease.latest || 'unavailable')} · EOL ${escape(lifecycleDate(matchedRelease.eol))}</p>` : '<p class="form-hint">Test the installed version before using this mapping.</p>';
  $('lifecycle-releases').innerHTML = product.releases.slice(0, 30).map(item => `<tr class="${matchedRelease?.cycle === item.cycle ? 'matched' : ''}"><td><strong>${escape(item.label)}</strong></td><td>${escape(item.latest || '—')}</td><td>${escape(item.releaseDate || '—')}</td><td>${escape(lifecycleDate(item.eol))}</td><td>${item.maintained ? '<span class="badge green">Maintained</span>' : '<span class="badge red">Not maintained</span>'}</td></tr>`).join('');
}

async function searchLifecycleProducts() {
  const form = new FormData($('lifecycle-search-form'));
  const params = new URLSearchParams({ q: String(form.get('q') || '').trim(), vendor: $('editor-form').elements.vendor.value.trim(), cpe: cpeMapping?.cpeName || '', category: String(form.get('category') || '') });
  $('lifecycle-results').innerHTML = '<p class="muted">Searching endoflife.date…</p>';
  try {
    const response = await fetch(`/api/lifecycle-products?${params}`, { cache: 'no-store' });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || 'Lifecycle search failed');
    const category = $('lifecycle-search-form').elements.category;
    if (category.options.length === 1) for (const name of data.categories) category.add(new Option(name.replace(/-/g, ' '), name));
    $('lifecycle-results').innerHTML = data.products.length ? `<div class="cpe-table-wrap"><table class="cpe-table"><thead><tr><th>PRODUCT</th><th>IDENTIFIER</th><th>CATEGORY</th><th>TAGS</th></tr></thead><tbody>${data.products.map((item, index) => `<tr tabindex="0" data-lifecycle-index="${index}"><td><div class="lifecycle-result-title"><strong>${escape(item.label)}</strong>${index === 0 && item.score ? '<span class="badge green">Best match</span>' : ''}</div></td><td><code>${escape(item.name)}</code></td><td>${escape(item.category)}</td><td>${escape(item.tags.join(', '))}</td></tr>`).join('')}</tbody></table></div>` : '<p class="muted">No lifecycle products matched. Try fewer words or use a manual EOL date.</p>';
    for (const row of $('lifecycle-results').querySelectorAll('[data-lifecycle-index]')) {
      const select = () => loadLifecycleProduct(data.products[Number(row.dataset.lifecycleIndex)].name);
      row.addEventListener('click', select);
      row.addEventListener('keydown', event => { if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); select(); } });
    }
  } catch (error) { $('lifecycle-results').innerHTML = `<p class="form-error">${escape(error.message)}</p>`; }
}

async function loadLifecycleProduct(name) {
  $('lifecycle-error').hidden = true;
  $('lifecycle-selection').hidden = false;
  $('lifecycle-selection-title').textContent = 'Loading lifecycle data…';
  try {
    const params = new URLSearchParams({ version: $('editor-form').elements.version.value.trim(), cpe: cpeMapping?.cpeName || '' });
    const response = await fetch(`/api/lifecycle-products/${encodeURIComponent(name)}?${params}`, { cache: 'no-store' });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || 'Could not load lifecycle product');
    lifecycleDraft = data;
    renderLifecycleSelection();
    $('lifecycle-selection').scrollIntoView({ behavior: 'smooth', block: 'start' });
  } catch (error) { $('lifecycle-selection').hidden = true; $('lifecycle-error').textContent = error.message; $('lifecycle-error').hidden = false; }
}

function useLifecycleMapping() {
  if (!lifecycleDraft?.product) return;
  lifecycleMapping = { name: lifecycleDraft.product.name, label: lifecycleDraft.product.label, sourceUrl: lifecycleDraft.sourceUrl, matchedRelease: lifecycleDraft.matchedRelease, testedAt: lifecycleDraft.testedAt };
  $('editor-form').elements.eolDate.value = '';
  renderLifecycleSummary();
  $('lifecycle-dialog').close();
}

function openCpeDialog() {
  cpeDraft = cpeMapping ? { ...cpeMapping } : null;
  $('cpe-error').hidden = true;
  renderCpeSelection();
  $('cpe-dialog').showModal();
  $('cpe-search-form').elements.any.focus();
}

function renderCpeSelection() {
  $('cpe-selection').hidden = !cpeDraft;
  if (!cpeDraft) return;
  $('cpe-selection-title').textContent = cpeDraft.title || cpeDraft.cpeName;
  $('cpe-selection-name').textContent = cpeDraft.cpeName;
  const components = ['part','vendor','product','version','update','edition','language','swEdition','targetSw','targetHw','other'];
  $('cpe-components').innerHTML = components.map(name => `<div><span>${escape(name)}</span><strong>${escape(cpeDraft[name] || '—')}</strong></div>`).join('');
  const mode = cpeDraft.mode === 'exact' ? 'exact' : 'product';
  document.querySelector(`[name="cpeMappingMode"][value="${mode}"]`).checked = true;
  $('cpe-test-result').innerHTML = cpeDraft.testedAt ? `<p class="form-error success">Last test: ${escape(new Date(cpeDraft.testedAt).toLocaleString())} · ${escape(cpeDraft.candidateCount)} candidates · ${escape(cpeDraft.applicableCount)} applicable in tested results</p>` : '';
  renderCpeWarnings(cpeDraft.warnings || []);
}

function renderCpeWarnings(warnings) {
  $('cpe-warnings').innerHTML = warnings.map(item => `<p class="cpe-warning ${escape(item.level)}"><strong>${escape(item.level)}</strong> ${escape(item.message)}</p>`).join('');
}

function selectedCpeWarnings(item, mode = 'product') {
  const warnings = [];
  if (item.deprecated) {
    const replacement = item.replacements?.[0];
    warnings.push({ code: 'deprecated', level: 'danger', message: replacement ? `This CPE is deprecated. Suggested replacement: ${replacement}` : 'This CPE is deprecated. Select its replacement when one is available.' });
  }
  if (mode === 'product') warnings.push({ code: 'product-wildcard', level: 'info', message: 'Product mode ignores the CPE version and evaluates the installed version against NVD affected ranges.' });
  if (mode === 'exact' && ['*', '-'].includes(item.version)) warnings.push({ code: 'broad-exact', level: 'warning', message: 'Exact mode still contains a wildcard or not-applicable version and may be broader than expected.' });
  const installedVersion = $('editor-form').elements.version.value.trim();
  if (mode === 'exact' && installedVersion && !['*', '-', installedVersion].includes(item.version)) warnings.push({ code: 'version-conflict', level: 'danger', message: `The exact CPE version (${item.version}) differs from the installed version (${installedVersion}).` });
  const qualified = ['update','edition','language','swEdition','targetSw','targetHw','other'].filter(name => !['*', '-', ''].includes(item[name]));
  if (mode === 'product' && qualified.length) warnings.push({ code: 'qualifiers-ignored', level: 'warning', message: `Product mode ignores these exact qualifiers: ${qualified.join(', ')}.` });
  return warnings;
}

async function searchCpes(startIndex = 0) {
  const form = new FormData($('cpe-search-form'));
  const params = new URLSearchParams();
  for (const name of ['any','part','vendor','product','version','edition']) if (form.get(name)?.trim()) params.set(name, form.get(name).trim());
  if (![...params.values()].length) { $('cpe-results').innerHTML = '<p class="form-error">Enter at least one search field.</p>'; return; }
  if (form.get('includeDeprecated')) params.set('includeDeprecated', 'true');
  params.set('startIndex', String(startIndex));
  $('cpe-results').innerHTML = '<p class="muted">Searching NVD…</p>';
  $('cpe-pagination').hidden = true;
  try {
    const response = await fetch(`/api/cpes?${params}`, { cache: 'no-store' });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || 'CPE search failed');
    $('cpe-results').innerHTML = data.results.length ? `<div class="cpe-table-wrap"><table class="cpe-table"><thead><tr><th>PRODUCT</th><th>VENDOR</th><th>VERSION</th><th>EDITION</th><th>STATUS</th></tr></thead><tbody>${data.results.map((item, index) => `<tr tabindex="0" data-cpe-index="${index}"><td><strong>${escape(item.title)}</strong><code>${escape(item.cpeName)}</code></td><td>${escape(item.vendor)}</td><td>${escape(item.version)}</td><td>${escape(item.edition)}</td><td>${item.deprecated ? '<span class="badge red">Deprecated</span>' : '<span class="badge green">Current</span>'}</td></tr>`).join('')}</tbody></table></div>` : '<p class="muted">No CPEs matched this page. Refine the fields or continue to the next NVD page.</p>';
    cpeSearchPage = data;
    $('cpe-pagination').hidden = data.previousIndex == null && data.nextIndex == null;
    $('cpe-previous').disabled = data.previousIndex == null;
    $('cpe-next').disabled = data.nextIndex == null;
    $('cpe-page-status').textContent = `${data.totalResults.toLocaleString()} NVD records · starting at ${data.startIndex + 1}`;
    for (const row of $('cpe-results').querySelectorAll('[data-cpe-index]')) {
      const select = () => { const item = data.results[Number(row.dataset.cpeIndex)]; cpeDraft = { ...item, mode: 'product', warnings: selectedCpeWarnings(item), testedAt: '', candidateCount: '', applicableCount: '' }; renderCpeSelection(); $('cpe-selection').scrollIntoView({ behavior: 'smooth', block: 'start' }); };
      row.addEventListener('click', select);
      row.addEventListener('keydown', event => { if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); select(); } });
    }
  } catch (error) { $('cpe-results').innerHTML = `<p class="form-error">${escape(error.message)}</p>`; }
}

async function parseManualCpe() {
  $('cpe-error').hidden = true;
  $('cpe-error').textContent = '';
  try {
    const response = await fetch('/api/cpes/parse', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ cpeName: $('cpe-manual-value').value, mode: 'product', version: $('editor-form').elements.version.value }) });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || 'Could not parse CPE');
    cpeDraft = { ...data.mapping, title: data.mapping.cpeName, warnings: data.warnings, testedAt: '', candidateCount: '', applicableCount: '' };
    renderCpeSelection();
  } catch (error) { $('cpe-error').textContent = error.message; $('cpe-error').hidden = false; }
}

async function testCpeMapping() {
  if (!cpeDraft) return;
  $('cpe-test').disabled = true;
  $('cpe-test').textContent = 'Testing…';
  $('cpe-test-result').innerHTML = '<p class="muted">Querying NVD and evaluating affected version ranges…</p>';
  try {
    const mode = document.querySelector('[name="cpeMappingMode"]:checked').value;
    const response = await fetch('/api/cpes/test', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ cpeName: cpeDraft.cpeName, mode, deprecated: cpeDraft.deprecated, version: $('editor-form').elements.version.value }) });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || 'Mapping test failed');
    cpeDraft = { ...cpeDraft, mode, testedAt: data.testedAt, candidateCount: data.candidateCount, applicableCount: data.applicableCount, warnings: data.warnings };
    renderCpeWarnings(data.warnings);
    $('cpe-test-result').innerHTML = `<div class="cpe-test-summary"><strong>${data.candidateCount.toLocaleString()} candidates</strong><strong>${data.applicableCount.toLocaleString()} applicable in tested results</strong><code>${escape(data.queryCpe)}</code></div>${data.sample.length ? data.sample.map(item => `<article><a href="${safeUrl(item.url)}" target="_blank" rel="noopener noreferrer">${escape(item.id)} ↗</a><small>${escape(item.published || '')}</small><p>${escape(item.description)}</p></article>`).join('') : '<p class="muted">No applicable CVEs were found in the tested results. This does not prove that the mapping is correct or the product is vulnerability-free.</p>'}`;
  } catch (error) { $('cpe-test-result').innerHTML = `<p class="form-error">${escape(error.message)}</p>`; }
  finally { $('cpe-test').disabled = false; $('cpe-test').textContent = 'Test this mapping'; }
}

function useCpeMapping() {
  if (!cpeDraft) return;
  cpeMapping = { ...cpeDraft, mode: document.querySelector('[name="cpeMappingMode"]:checked').value };
  renderMappingSummary();
  $('cpe-dialog').close();
}

function populateWorkspaceEditor() {
  const group = editorConfig.workspaces.find(item => item.id === $('workspace-choice').value);
  editorTargetId = group?.id || null;
  const form = $('editor-form');
  $('workspace-id-label').innerHTML = group ? `Workspace ID: <code>${escape(group.id)}</code> (immutable)` : 'A permanent workspace ID will be generated when saved.';
  form.querySelector('[name="name"]').value = group?.name || '';
  editorSelections.ownerIds = new Set(group?.ownerIds || []);
  editorSelections.applicationIds = new Set(group?.applications || []);
  $('ownerIds-summary').textContent = editorSelections.ownerIds.size ? `${editorSelections.ownerIds.size} selected` : 'None selected';
  $('applicationIds-summary').textContent = editorSelections.applicationIds.size ? `${editorSelections.applicationIds.size} selected` : 'None selected';
  if (group && !isAdmin) {
    form.querySelector('[name="name"]').readOnly = !permissions.workspaces.edit.includes(group.id);
    form.querySelector('[data-association="ownerIds"]').disabled = !permissions.workspaces.notifications.includes(group.id);
    form.querySelector('[data-association="applicationIds"]').disabled = !permissions.workspaces.membership.includes(group.id);
  }
  updateEditorDanger();
}

function updateEditorDanger() {
  const resource = editorMode === 'app' ? editorConfig.applications.find(item => item.id === editorTargetId) : editorConfig.workspaces.find(item => item.id === editorTargetId);
  const allowed = resource && (isAdmin || (editorMode === 'app' ? permissions.applications.edit.includes(resource.id) : permissions.workspaces.edit.includes(resource.id)));
  $('editor-danger').hidden = !allowed;
  if (!allowed) return;
  $('editor-danger-title').textContent = `Delete ${editorMode === 'app' ? 'application' : 'workspace'}`;
  $('editor-danger-description').textContent = editorMode === 'app'
    ? 'Removes this application from inventory, workspaces, feeds, and the current snapshot. Finding workflow history is preserved.'
    : 'Removes only this workspace. Its applications and finding workflow history are preserved.';
  $('editor-delete').textContent = `Delete ${editorMode === 'app' ? 'application' : 'workspace'}`;
}

async function deleteEditorResource() {
  const resource = editorMode === 'app' ? editorConfig.applications.find(item => item.id === editorTargetId) : editorConfig.workspaces.find(item => item.id === editorTargetId);
  if (!resource) return;
  const confirmation = prompt(`Type ${resource.name} to permanently delete this ${editorMode === 'app' ? 'application' : 'workspace'}.`);
  if (confirmation === null) return;
  if (confirmation !== resource.name) { $('editor-error').textContent = 'The name did not match. Nothing was deleted.'; $('editor-error').hidden = false; return; }
  const button = $('editor-delete');
  button.disabled = true;
  button.textContent = 'Deleting…';
  $('editor-error').hidden = true;
  try {
    const endpoint = `/api/${editorMode === 'app' ? 'applications' : 'workspaces'}/${encodeURIComponent(resource.id)}`;
    const response = await fetch(endpoint, { method: 'DELETE', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ confirmation }) });
    if (!response.ok) throw new Error((await response.json()).error || 'Could not delete resource');
    $('editor').close();
    if (editorMode === 'workspace') selectWorkspace(null);
    await load(false, false);
  } catch (error) {
    $('editor-error').textContent = error.message;
    $('editor-error').hidden = false;
    button.disabled = false;
    updateEditorDanger();
  }
}

function applySavedEditorState(saved, payload, fields) {
  if (editorMode === 'workspace') {
    const index = workspaces.findIndex(group => group.id === saved.previousId);
    if (index < 0) workspaces = [...workspaces, saved];
    else workspaces = workspaces.map(group => group.id === saved.previousId ? saved : group);
  } else {
    allResults = allResults.map(app => app.id === saved.previousId ? { ...app, id: saved.id, name: payload.name } : app);
    const selectedWorkspaces = editorSelections.workspaceIds;
    workspaces = workspaces.map(group => {
      const applicationsAfterRename = group.applications.map(id => id === saved.previousId ? saved.id : id);
      const containsApp = applicationsAfterRename.includes(saved.id);
      const selected = selectedWorkspaces.has(group.id);
      if (containsApp === selected) return { ...group, applications: applicationsAfterRename };
      return { ...group, applications: selected ? [...applicationsAfterRename, saved.id] : applicationsAfterRename.filter(id => id !== saved.id) };
    });
  }
  renderSidebar();
  renderView();
}

async function saveEditor(event) {
  event.preventDefault();
  const form = $('editor-form');
  const fields = new FormData(form);
  const currentWorkspace = editorMode === 'workspace' && editorTargetId ? editorConfig.workspaces.find(group => group.id === editorTargetId) : null;
  const payload = editorMode === 'app' ? { ...Object.fromEntries(fields), ownerIds: [...editorSelections.ownerIds] } : { name: fields.get('name'), ownerIds: currentWorkspace && !isAdmin && !permissions.workspaces.notifications.includes(currentWorkspace.id) ? currentWorkspace.ownerIds : [...editorSelections.ownerIds], applications: currentWorkspace && !isAdmin && !permissions.workspaces.membership.includes(currentWorkspace.id) ? currentWorkspace.applications : [...editorSelections.applicationIds] };
  if (editorMode === 'app' && !payload.cpeName) { $('editor-error').textContent = 'Choose a vulnerability mapping before saving.'; $('editor-error').hidden = false; return; }
  if (editorMode === 'app' && !payload.lifecycleProduct && !payload.eolDate) { $('editor-error').textContent = 'Enter a lifecycle product or manual end-of-life date.'; $('editor-error').hidden = false; return; }
  $('editor-save').disabled = true;
  $('editor-save').textContent = 'Saving…';
  $('editor-error').hidden = true;
  try {
    const endpoint = editorMode === 'app' ? editorTargetId ? `/api/applications/${encodeURIComponent(editorTargetId)}` : '/api/applications' : editorTargetId ? `/api/workspaces/${encodeURIComponent(editorTargetId)}` : '/api/workspaces';
    const response = await fetch(endpoint, { method: editorTargetId ? 'PUT' : 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) });
    const saved = await response.json();
    if (!response.ok) throw new Error(saved.error || 'Could not save');
    if (editorMode === 'app') {
      const feedUpdate = await fetch(`/api/applications/${encodeURIComponent(saved.id)}/feeds`, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ feedIds: [...editorSelections.feedIds] }) });
      if (!feedUpdate.ok) throw new Error((await feedUpdate.json()).error || 'Could not update feed associations');
      for (const group of editorConfig.workspaces) {
        const selected = editorSelections.workspaceIds.has(group.id);
        const applicationsAfterRename = group.applications.map(id => id === saved.previousId ? saved.id : id);
        const membership = applicationsAfterRename.includes(saved.id);
        if (selected === membership) continue;
        const applications = selected ? [...applicationsAfterRename, saved.id] : applicationsAfterRename.filter(id => id !== saved.id);
        const update = await fetch(`/api/workspaces/${encodeURIComponent(group.id)}`, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ ...group, applications }) });
        if (!update.ok) throw new Error((await update.json()).error || `Could not add application to ${group.name}`);
      }
    }
    if (editorMode === 'app') {
      const refresh = await fetch(`/api/applications/${encodeURIComponent(saved.id)}/refresh`, { method: 'POST' });
      const data = await refresh.json();
      if (!refresh.ok) throw new Error(data.error || 'Application saved, but its source check failed');
      render(data);
    }
    $('editor').close();
    applySavedEditorState(saved, payload, fields);
    if (editorMode === 'workspace') selectWorkspace(saved.id);
    if (editorMode !== 'app') void load(false, true);
  } catch (error) { $('editor-error').textContent = error.message; $('editor-error').hidden = false; }
  finally { $('editor-save').disabled = false; $('editor-save').textContent = 'Save'; }
}

let loadingStatus = false;
let currentLoadDone = Promise.resolve();
async function load(force = false, silent = false) {
  if (loadingStatus) {
    if (silent) return;
    await currentLoadDone;
    return load(force, silent);
  }
  loadingStatus = true;
  let finishLoad;
  currentLoadDone = new Promise(resolve => { finishLoad = resolve; });
  if (!silent) { $('refresh').disabled = true; $('refresh').innerHTML = '<span>↻</span> Checking…'; }
  try {
    const response = await fetch(`/api/status${force ? '?refresh=1' : ''}`, { cache: 'no-store' });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || 'Source check failed');
    render(data);
  } catch (error) {
    $('updated').textContent = 'Check failed';
    $('rows').innerHTML = `<tr><td colspan="6" class="empty"><strong>Could not load the dashboard</strong><p>${escape(error.message)}</p></td></tr>`;
  } finally { loadingStatus = false; finishLoad(); if (!silent) { $('refresh').disabled = false; $('refresh').innerHTML = '<span>↻</span> Refresh checks'; } }
}

$('refresh').addEventListener('click', () => load(true));
$('add-app').addEventListener('click', () => openEditor('app'));
$('manage-workspaces').addEventListener('click', () => openEditor('workspace'));
$('edit-workspace').addEventListener('click', () => { const group = activeWorkspace(); if (group && group.id !== 'all') openEditor('workspace', group.id); });
$('edit-app').addEventListener('click', () => { const id = detailAppId; $('details').close(); if (id) openEditor('app', id); });
$('editor-form').addEventListener('submit', saveEditor);
$('editor-delete').addEventListener('click', deleteEditorResource);
$('editor-fields').addEventListener('click', event => {
  const button = event.target.closest('[data-association]');
  if (!button || button.disabled) return;
  const titles = { ownerIds: editorMode === 'workspace' ? 'Choose workspace owners' : 'Choose application owners', workspaceIds: 'Choose workspaces', feedIds: 'Choose feeds', applicationIds: 'Choose applications' };
  openAssociation(button.dataset.association, titles[button.dataset.association]);
});
$('editor-close').addEventListener('click', () => $('editor').close());
$('editor-cancel').addEventListener('click', () => $('editor').close());
$('association-search').addEventListener('input', renderAssociationList);
$('association-list').addEventListener('change', event => { if (!associationState || event.target.type !== 'checkbox') return; if (event.target.checked) associationState.draft.add(event.target.value); else associationState.draft.delete(event.target.value); });
$('association-apply').addEventListener('click', applyAssociation);
$('association-add-owner').addEventListener('click', () => {
  if (!associationState || associationState.key !== 'ownerIds') return;
  editorSelections.ownerIds = new Set(associationState.draft);
  resumeOwnerAssociation = { title: $('association-title').textContent };
  $('association-dialog').close();
  openOwnerEditor();
});
$('association-close').addEventListener('click', () => $('association-dialog').close());
$('association-cancel').addEventListener('click', () => $('association-dialog').close());
$('cpe-close').addEventListener('click', () => $('cpe-dialog').close());
$('cpe-search-form').addEventListener('submit', event => { event.preventDefault(); searchCpes(0); });
$('cpe-search-reset').addEventListener('click', () => { $('cpe-search-form').reset(); $('cpe-results').innerHTML = '<p class="muted">Search the NVD CPE Dictionary or paste a complete CPE below.</p>'; $('cpe-pagination').hidden = true; });
$('cpe-previous').addEventListener('click', () => searchCpes(cpeSearchPage.previousIndex));
$('cpe-next').addEventListener('click', () => searchCpes(cpeSearchPage.nextIndex));
$('cpe-parse').addEventListener('click', parseManualCpe);
$('cpe-test').addEventListener('click', testCpeMapping);
$('cpe-use').addEventListener('click', useCpeMapping);
for (const radio of document.querySelectorAll('[name="cpeMappingMode"]')) radio.addEventListener('change', () => { if (!cpeDraft) return; cpeDraft = { ...cpeDraft, mode: radio.value, warnings: selectedCpeWarnings(cpeDraft, radio.value), testedAt: '', candidateCount: '', applicableCount: '' }; renderCpeWarnings(cpeDraft.warnings); $('cpe-test-result').innerHTML = '<p class="muted">Mapping mode changed. Test the mapping again to validate this query.</p>'; });
$('lifecycle-close').addEventListener('click', () => $('lifecycle-dialog').close());
$('lifecycle-search-form').addEventListener('submit', event => { event.preventDefault(); searchLifecycleProducts(); });
$('lifecycle-search-reset').addEventListener('click', () => { $('lifecycle-search-form').reset(); searchLifecycleProducts(); });
$('lifecycle-test').addEventListener('click', () => { if (lifecycleDraft?.product) loadLifecycleProduct(lifecycleDraft.product.name); });
$('lifecycle-use').addEventListener('click', useLifecycleMapping);
for (const card of document.querySelectorAll('.summary-card[data-filter]')) {
  card.addEventListener('click', () => toggleFilter(card.dataset.filter));
  card.addEventListener('keydown', e => { if ((e.key === 'Enter' || e.key === ' ') && activeWorkspace()) { e.preventDefault(); toggleFilter(card.dataset.filter); } });
}
$('overview-nav').addEventListener('click', () => selectWorkspace(null));
$('settings-nav').addEventListener('click', () => { location.hash = 'settings'; renderView(); });
$('logs-nav').addEventListener('click', () => { location.hash = 'logs'; renderView(); });
$('access-nav').addEventListener('click', () => { location.hash = 'access'; renderView(); });
$('feeds-nav').addEventListener('click', () => { location.hash = 'feeds'; renderView(); });
$('owners-nav').addEventListener('click', () => { location.hash = 'owners'; renderView(); });
$('feeds-refresh').addEventListener('click', () => { feedsLoaded = false; loadFeeds(); });
$('add-feed').addEventListener('click', () => openFeedEditor());
$('feeds-list').addEventListener('click', event => { const button = event.target.closest('[data-feed]'); if (button) openFeedEditor(button.dataset.feed); });
$('feed-form').addEventListener('submit', saveFeed);
$('feed-test').addEventListener('click', testFeed);
$('feed-refresh').addEventListener('click', refreshFeed);
$('feed-delete').addEventListener('click', deleteFeed);
$('feed-editor-close').addEventListener('click', () => $('feed-editor').close());
$('feed-cancel').addEventListener('click', () => $('feed-editor').close());
$('owners-refresh').addEventListener('click', () => { ownersLoaded = false; loadOwners(); });
$('add-owner').addEventListener('click', () => openOwnerEditor());
$('owners-list').addEventListener('click', event => { const button = event.target.closest('[data-owner]'); if (button) openOwnerEditor(button.dataset.owner); });
$('owner-form').addEventListener('submit', saveOwner);
$('owner-delete').addEventListener('click', deleteOwner);
$('owner-editor-close').addEventListener('click', closeOwnerEditor);
$('owner-cancel').addEventListener('click', closeOwnerEditor);
$('logs-refresh').addEventListener('click', loadLogs);
for (const button of document.querySelectorAll('[data-log-type]')) button.addEventListener('click', () => { activeLogType = button.dataset.logType; loadLogs(); });
$('settings-form').addEventListener('submit', saveSettings);
$('settings-test-email').addEventListener('click', testEmailSettings);
$('access-form').addEventListener('submit', saveAccess);
$('access-evaluate').addEventListener('click', () => verifyAccess(false));
$('access-preview').addEventListener('click', () => verifyAccess(true));
$('identity-list').addEventListener('change', event => {
  if (!event.target.matches('[data-preview-mapping]')) return;
  const id = event.target.closest('.identity-row').dataset.id;
  if (event.target.checked) selectedMappingIds.add(id); else selectedMappingIds.delete(id);
});
$('grant-list').addEventListener('change', event => {
  if (!event.target.matches('[data-preview-grant]')) return;
  const id = event.target.closest('.grant-row').dataset.id;
  if (event.target.checked) selectedGrantIds.add(id); else selectedGrantIds.delete(id);
});
$('add-identity').addEventListener('click', () => { accessData.groups = [...collectAccess().groups, { id: crypto.randomUUID(), name: '', claimSource: 'groups', claimValue: '', enabled: true }]; accessData.grants = collectAccess().grants; renderAccess(); });
$('add-grant').addEventListener('click', () => { const current = collectAccess(); const id = crypto.randomUUID(); selectedGrantIds.add(id); accessData.groups = current.groups; accessData.grants = [...current.grants, { id, groupId: current.groups[0]?.id || '', scopeType: 'workspace', roles: [], resourceIds: [] }]; renderAccess(); });
$('access-form').addEventListener('click', event => { const button = event.target.closest('.remove-access'); if (!button) return; const row = button.closest('.access-row'); const current = collectAccess(); if (row.classList.contains('identity-row')) { selectedMappingIds.delete(row.dataset.id); for (const grant of current.grants.filter(item => item.groupId === row.dataset.id)) selectedGrantIds.delete(grant.id); } if (row.classList.contains('grant-row')) selectedGrantIds.delete(row.dataset.id); accessData.groups = current.groups.filter(item => row.classList.contains('identity-row') ? item.id !== row.dataset.id : true); accessData.grants = current.grants.filter(item => row.classList.contains('grant-row') ? item.id !== row.dataset.id : item.groupId !== row.dataset.id); renderAccess(); });
$('grant-list').addEventListener('change', event => { if (event.target.dataset.field !== 'scopeType') return; const current = collectAccess(); accessData.groups = current.groups; accessData.grants = current.grants; renderAccess(); });
$('settings-form').querySelector('[name="unauthenticated"]').addEventListener('change', updateCredentialFields);
$('settings-form').querySelector('[name="enabled"]').addEventListener('change', updateCredentialFields);
for (const input of $('settings-form').querySelectorAll('[name="transportSecurity"]')) input.addEventListener('change', () => {
  if (input.checked) $('settings-form').querySelector('[name="port"]').value = { tls: 465, starttls: 587, none: 25 }[input.value];
});
$('workspace-list').addEventListener('click', e => {
  const button = e.target.closest('button[data-workspace]');
  if (!button) return;
  selectWorkspace(button.dataset.workspace);
  if (button.dataset.appId) {
    const app = allResults.find(item => item.id === button.dataset.appId);
    if (app) showDetails(app);
  }
});
window.addEventListener('hashchange', () => { activeFilters = null; renderView(); });
$('theme-toggle').addEventListener('click', () => setTheme(document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark'));
$('close').addEventListener('click', () => $('details').close());
$('details').addEventListener('click', e => { if (e.target === $('details')) $('details').close(); });
setTheme(document.documentElement.dataset.theme || 'light');
fetch('/api/session', { cache: 'no-store' }).then(response => response.json()).then(data => {
  isAdmin = Boolean(data.isAdmin);
  canManageAccess = Boolean(data.canManageAccess);
  activePreview = data.preview;
  if (!activePreview && location.hash !== '#access') clearAccessDraft();
  $('admin-actions').hidden = !isAdmin;
  $('refresh').hidden = !isAdmin;
  $('logs-nav').hidden = !isAdmin;
  $('settings-nav').hidden = !isAdmin;
  $('owners-nav').hidden = !isAdmin;
  $('access-nav').hidden = !canManageAccess;
  $('preview-banner').hidden = !activePreview;
  if (activePreview) $('preview-name').textContent = activePreview.name;
  if (!isAdmin && ['#settings', '#logs'].includes(location.hash)) location.hash = 'overview';
  if (!canManageAccess && location.hash === '#access') location.hash = 'overview';
  renderView();
  if (data.enabled) {
    $('signed-in-user').textContent = data.user;
    $('logout-form').hidden = false;
  }
}).catch(() => {});
$('preview-exit').addEventListener('click', async () => {
  $('preview-exit').disabled = true;
  try {
    const response = await fetch('/api/rbac/preview', { method: 'DELETE' });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || 'Could not exit Permission Preview');
    location.hash = 'access';
    location.reload();
  } catch (error) { alert(error.message); $('preview-exit').disabled = false; }
});
load();
setInterval(() => { if (!document.hidden) load(false, true); }, 60_000);
document.addEventListener('visibilitychange', () => { if (!document.hidden) load(false, true); });

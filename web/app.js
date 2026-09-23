const $ = (id) => document.getElementById(id);
let results = [];
let allResults = [];
let workspaces = [];
let activeFilters = null;
let editorMode = null;
let editorTargetId = null;
let detailAppId = null;
let editorConfig = { applications: [], workspaces: [] };
let settingsLoaded = false;
let logsLoaded = false;
let accessLoaded = false;
let accessData = null;
let isAdmin = false;
let permissions = { scan: false, applications: { view: [], edit: [] }, workspaces: { view: [], edit: [], membership: [], notifications: [] } };
const escape = (s) => String(s ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const safeUrl = (url) => { try { const u = new URL(url); return ['https:', 'http:'].includes(u.protocol) ? u.href : '#'; } catch { return '#'; } };
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
  const settingsPage = location.hash === '#settings';
  const logsPage = location.hash === '#logs';
  const accessPage = location.hash === '#access';
  $('dashboard-content').hidden = settingsPage || logsPage || accessPage;
  $('settings-content').hidden = !settingsPage;
  $('logs-content').hidden = !logsPage;
  $('access-content').hidden = !accessPage;
  $('settings-nav').classList.toggle('active', settingsPage);
  $('settings-nav').setAttribute('aria-current', settingsPage ? 'page' : 'false');
  $('logs-nav').classList.toggle('active', logsPage);
  $('logs-nav').setAttribute('aria-current', logsPage ? 'page' : 'false');
  $('access-nav').classList.toggle('active', accessPage);
  $('access-nav').setAttribute('aria-current', accessPage ? 'page' : 'false');
  if (settingsPage || logsPage || accessPage) {
    $('overview-nav').classList.remove('active');
    for (const button of $('workspace-list').querySelectorAll('.workspace-link')) button.classList.remove('active');
    $('crumb-current').textContent = settingsPage ? 'Settings' : logsPage ? 'Logs' : 'Access Control';
    if (settingsPage && !settingsLoaded) loadSettings();
    if (logsPage && !logsLoaded) loadLogs();
    if (accessPage && !accessLoaded) loadAccess();
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
  $('settings-env-status').textContent = `Credential variables: ${smtp.usernameEnv || 'username not configured'} ${smtp.usernameEnv ? data.envStatus.usernamePresent ? '(present)' : '(missing)' : ''}; ${smtp.passwordEnv || 'password not configured'} ${smtp.passwordEnv ? data.envStatus.passwordPresent ? '(present)' : '(missing)' : ''}. Values are never shown or saved here.`;
}

async function loadLogs() {
  logsLoaded = true;
  const list = $('logs-list');
  try {
    const response = await fetch('/api/logs', { cache: 'no-store' });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || 'Could not load logs');
    list.innerHTML = data.entries.length ? data.entries.map(entry => `<article class="log-entry"><time>${escape(new Date(entry.at).toLocaleString())}</time><span class="log-level ${escape(entry.level)}">${escape(entry.level)}</span><div><strong>${escape(entry.message)}</strong>${entry.actor ? `<p class="log-actor">By ${escape(entry.actor.name)} · ${escape(entry.actor.username || entry.actor.subject)}</p>` : ''}${entry.detail ? `<p>${escape(entry.detail)}</p>` : ''}</div></article>`).join('') : '<p class="muted">No log entries yet.</p>';
  } catch (error) { logsLoaded = false; list.innerHTML = `<p class="form-error">${escape(error.message)}</p>`; }
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
  const general = { protocol: payload.protocol, host: payload.publicHost, port: Number(payload.publicPort) };
  delete payload.protocol;
  delete payload.publicHost;
  delete payload.publicPort;
  delete payload.transportSecurity;
  const security = form.querySelector('[name="transportSecurity"]:checked')?.value;
  payload.secure = security === 'tls';
  payload.requireTls = security === 'starttls';
  payload.unauthenticated = form.querySelector('[name="unauthenticated"]').checked;
  if (payload.unauthenticated) {
    payload.usernameEnv = form.querySelector('[name="usernameEnv"]').value;
    payload.passwordEnv = form.querySelector('[name="passwordEnv"]').value;
  }
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

function identityRow(group = {}) {
  return `<article class="access-row identity-row" data-id="${escape(group.id || '')}"><div class="form-grid"><label>Display name <input data-field="name" required value="${escape(group.name || '')}" placeholder="Infrastructure Admins"></label><label>Claim source <select data-field="claimSource"><option value="groups">groups</option><option value="roles">roles</option><option value="realm_access.roles">realm_access.roles</option><option value="resource_access.roles">resource_access.roles</option></select></label><label class="form-full">Exact claim value <input data-field="claimValue" required value="${escape(group.claimValue || '')}" placeholder="Group UUID or role name"></label></div><label><input data-field="enabled" type="checkbox" ${group.enabled === false ? '' : 'checked'}> Enabled</label><button class="remove-access" type="button">Remove</button>${group.id ? `<small>ID: <code>${escape(group.id)}</code></small>` : ''}</article>`;
}

function grantRow(grant = {}) {
  const groups = accessData?.groups || [];
  const scope = grant.scopeType || 'workspace';
  const roleOptions = Object.entries(accessData?.roles || {}).filter(([, value]) => value.scopes.includes(scope));
  const resources = scope === 'workspace' ? accessData?.workspaces || [] : scope === 'application' ? accessData?.applications || [] : [];
  return `<article class="access-row grant-row" data-id="${escape(grant.id || '')}"><div class="form-grid"><label>Identity mapping <select data-field="groupId" required>${groups.map(group => `<option value="${escape(group.id)}" ${group.id === grant.groupId ? 'selected' : ''}>${escape(group.name)}</option>`).join('')}</select></label><label>Scope <select data-field="scopeType"><option value="workspace" ${scope === 'workspace' ? 'selected' : ''}>Workspace</option><option value="application" ${scope === 'application' ? 'selected' : ''}>Application</option><option value="global" ${scope === 'global' ? 'selected' : ''}>Global</option></select></label></div><fieldset><legend>Roles</legend><div class="check-grid">${roleOptions.map(([id, role]) => `<label><input data-role="${escape(id)}" type="checkbox" ${grant.roles?.includes(id) ? 'checked' : ''}> ${escape(role.name)}</label>`).join('')}</div></fieldset>${scope === 'global' ? '' : `<fieldset><legend>${scope === 'workspace' ? 'Workspaces' : 'Applications'}</legend><select data-field="resourceIds" multiple size="5">${resources.map(item => `<option value="${escape(item.id)}" ${grant.resourceIds?.includes(item.id) ? 'selected' : ''}>${escape(resourceLabel(item, resources))}</option>`).join('')}</select></fieldset>`}<button class="remove-access" type="button">Remove</button>${grant.id ? `<small>ID: <code>${escape(grant.id)}</code></small>` : ''}</article>`;
}

function resourceLabel(item, list) { return list.filter(other => other.name === item.name).length > 1 ? `${item.name} (${item.id})` : item.name; }
function renderAccess() {
  $('identity-list').innerHTML = accessData.groups.map(identityRow).join('') || '<p class="muted">No identity mappings configured.</p>';
  $('grant-list').innerHTML = accessData.grants.map(grantRow).join('') || '<p class="muted">No grants configured.</p>';
  $('session-claims').textContent = JSON.stringify(accessData.session, null, 2);
  for (const row of $('identity-list').querySelectorAll('.identity-row')) row.querySelector('[data-field="claimSource"]').value = accessData.groups.find(item => item.id === row.dataset.id)?.claimSource || 'groups';
}
async function loadAccess() {
  accessLoaded = true;
  try { const response = await fetch('/api/rbac', { cache: 'no-store' }); accessData = await response.json(); if (!response.ok) throw new Error(accessData.error || 'Could not load access control'); renderAccess(); }
  catch (error) { accessLoaded = false; $('access-message').textContent = error.message; $('access-message').hidden = false; }
}
function collectAccess() {
  const groups = [...$('identity-list').querySelectorAll('.identity-row')].map(row => ({ id: row.dataset.id, name: row.querySelector('[data-field="name"]').value, claimSource: row.querySelector('[data-field="claimSource"]').value, claimValue: row.querySelector('[data-field="claimValue"]').value, enabled: row.querySelector('[data-field="enabled"]').checked }));
  const grants = [...$('grant-list').querySelectorAll('.grant-row')].map(row => ({ id: row.dataset.id, groupId: row.querySelector('[data-field="groupId"]').value, scopeType: row.querySelector('[data-field="scopeType"]').value, roles: [...row.querySelectorAll('[data-role]:checked')].map(input => input.dataset.role), resourceIds: [...(row.querySelector('[data-field="resourceIds"]')?.selectedOptions || [])].map(option => option.value) }));
  return { groups, grants };
}
async function saveAccess(event) {
  event.preventDefault(); $('access-save').disabled = true;
  try { const response = await fetch('/api/rbac', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(collectAccess()) }); const data = await response.json(); if (!response.ok) throw new Error(data.error || 'Could not save access control'); accessLoaded = false; await loadAccess(); $('access-message').textContent = 'Access control saved.'; $('access-message').classList.add('success'); $('access-message').hidden = false; }
  catch (error) { $('access-message').textContent = error.message; $('access-message').classList.remove('success'); $('access-message').hidden = false; }
  finally { $('access-save').disabled = false; }
}

function render(data) {
  allResults = data.results || [];
  workspaces = data.workspaces || [];
  permissions = data.access || permissions;
  isAdmin = Boolean(permissions.isAdmin || isAdmin);
  $('refresh').hidden = !(isAdmin || permissions.scan);
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
  $('detail-body').innerHTML = `${sharedWarning}<div class="detail-grid"><div><span>INSTALLED VERSION</span><strong>${escape(a.version)}</strong></div><div><span>LATEST AVAILABLE</span><strong>${escape(upgrade.latest || 'Unavailable')}</strong>${releaseLink}</div><div><span>LATEST ON INSTALLED LINE</span><strong>${escape(upgrade.currentLine || 'Unavailable')}</strong></div><div><span>LATEST LTS VERSION</span><strong>${escape(upgrade.latestLts || 'No designated LTS')}</strong></div><div><span>SUPPORT</span><strong>${escape(a.lifecycle?.note || 'Unknown')}</strong></div></div><h3>Assessment</h3><ul class="reasons">${a.reasons.map(r => `<li>${escape(r)}</li>`).join('')}</ul><h3>Vulnerability findings</h3>${findings}<h3>Sources</h3><div class="sources">${a.sources.map(s => `<a href="${safeUrl(s.url)}" target="_blank" rel="noopener noreferrer">${escape(s.name)} ↗</a>`).join('') || '<span class="muted">No source links available</span>'}</div><p class="detail-note">CPE: <code>${escape(a.cpe)}</code>. Confirm product identity and affected version ranges in the linked advisories before remediation decisions.</p>`;
  $('details').showModal();
}

async function openEditor(mode, targetId = null) {
  editorMode = mode;
  editorTargetId = targetId;
  $('editor-error').hidden = true;
  $('editor-fields').innerHTML = '<p class="muted">Loading inventory…</p>';
  $('editor-title').textContent = mode === 'app' ? targetId ? 'Edit application' : 'Add application' : targetId ? 'Edit workspace' : 'Add or edit workspace';
  $('editor').showModal();
  try {
    const response = await fetch('/api/config', { cache: 'no-store' });
    editorConfig = await response.json();
    if (!response.ok) throw new Error(editorConfig.error || 'Could not load inventory');
    if (mode === 'app') {
      $('editor-fields').innerHTML = `<div class="form-grid">
        <label>Display name <input name="name" required placeholder="Application name"></label>
        <label>Vendor <input name="vendor" placeholder="Vendor name"></label>
        <label>Installed version <input name="version" required pattern="[A-Za-z0-9._-]+" placeholder="1.2.3"></label>
        <label>CPE vendor <input name="cpeVendor" required pattern="[A-Za-z0-9._-]+" placeholder="vendor"></label>
        <label>CPE product <input name="cpeProduct" required pattern="[A-Za-z0-9._-]+" placeholder="product"></label>
        <label>CPE edition <input name="cpeEdition" pattern="[A-Za-z0-9._-]+" placeholder="Optional"></label>
        <label>Lifecycle product <input name="lifecycleProduct" pattern="[A-Za-z0-9._-]+" placeholder="endoflife.date product ID"></label>
        <label>Manual end-of-life date <input name="eolDate" type="date"></label>
        <label>Lifecycle source URL <input name="lifecycleUrl" type="url" placeholder="https://…"></label>
        <label>Vendor security URL <input name="vendorBulletinUrl" type="url" placeholder="https://…"></label>
        <label>Release notes URL <input name="releaseUrl" type="url" placeholder="https://…"></label>
        <label>Latest version override <input name="latestVersion" placeholder="Optional"></label>
        <label>Latest installed-line override <input name="latestBranchVersion" placeholder="Optional"></label>
        <label>Latest LTS override <input name="latestLtsVersion" placeholder="Optional"></label>
      </div>${targetId ? `<p class="form-hint">Application ID: <code>${escape(targetId)}</code> (immutable)</p>` : ''}<p class="form-hint">Provide a lifecycle product or a manual end-of-life date. Verify CPE vendor and product at <a href="https://nvd.nist.gov/products/cpe/search" target="_blank" rel="noopener noreferrer">NVD CPE Search ↗</a>.</p>${editorConfig.workspaces.length ? `<fieldset><legend>Add to workspaces</legend><div class="check-grid">${editorConfig.workspaces.map(group => `<label><input type="checkbox" name="workspace" value="${escape(group.id)}"> ${escape(group.name)}</label>`).join('')}</div></fieldset>` : ''}`;
      if (targetId) {
        const app = editorConfig.applications.find(item => item.id === targetId);
        if (!app) throw new Error('Application not found');
        for (const [key, value] of Object.entries(app)) {
          const input = $('editor-form').querySelector(`[name="${key}"]`);
          if (input && input.type !== 'checkbox') input.value = value ?? '';
        }
        for (const input of $('editor-form').querySelectorAll('[name="workspace"]')) input.checked = Boolean(editorConfig.workspaces.find(group => group.id === input.value)?.applications.includes(targetId));
      }
    } else {
      $('editor-fields').innerHTML = `<label class="form-full">Workspace to edit <select id="workspace-choice"><option value="">New workspace</option>${editorConfig.workspaces.map(group => `<option value="${escape(group.id)}">${escape(group.name)}</option>`).join('')}</select></label><div class="form-grid"><label>Workspace name <input name="name" required placeholder="Customer, system, or group name"></label></div><p id="workspace-id-label" class="form-hint"></p><label class="form-full notification-emails">Notification emails <input name="notificationEmails" type="text" placeholder="alex@example.com, team@example.com"></label><p class="form-hint">Separate recipients with commas. Leave blank to turn off email for this workspace.</p><fieldset><legend>Applications in this workspace</legend><div class="check-grid">${editorConfig.applications.filter(app => app.enabled !== false).map(app => `<label><input type="checkbox" name="application" value="${escape(app.id)}"> ${escape(app.name)}</label>`).join('') || '<p class="muted">Add an application first.</p>'}</div></fieldset>`;
      $('workspace-choice').addEventListener('change', populateWorkspaceEditor);
      if (targetId) { $('workspace-choice').value = targetId; populateWorkspaceEditor(); $('workspace-choice').hidden = true; $('workspace-choice').closest('label').hidden = true; }
    }
  } catch (error) { $('editor-fields').innerHTML = ''; $('editor-error').textContent = error.message; $('editor-error').hidden = false; }
}

function populateWorkspaceEditor() {
  const group = editorConfig.workspaces.find(item => item.id === $('workspace-choice').value);
  editorTargetId = group?.id || null;
  const form = $('editor-form');
  $('workspace-id-label').innerHTML = group ? `Workspace ID: <code>${escape(group.id)}</code> (immutable)` : 'A permanent workspace ID will be generated when saved.';
  form.querySelector('[name="name"]').value = group?.name || '';
  form.querySelector('[name="notificationEmails"]').value = group?.notificationEmails || '';
  for (const input of form.querySelectorAll('[name="application"]')) input.checked = Boolean(group?.applications.includes(input.value));
  if (group && !isAdmin) {
    form.querySelector('[name="name"]').readOnly = !permissions.workspaces.edit.includes(group.id);
    form.querySelector('[name="notificationEmails"]').readOnly = !permissions.workspaces.notifications.includes(group.id);
    for (const input of form.querySelectorAll('[name="application"]')) input.disabled = !permissions.workspaces.membership.includes(group.id);
  }
}

function applySavedEditorState(saved, payload, fields) {
  if (editorMode === 'workspace') {
    const index = workspaces.findIndex(group => group.id === saved.previousId);
    if (index < 0) workspaces = [...workspaces, saved];
    else workspaces = workspaces.map(group => group.id === saved.previousId ? saved : group);
  } else {
    allResults = allResults.map(app => app.id === saved.previousId ? { ...app, id: saved.id, name: payload.name } : app);
    const selectedWorkspaces = new Set(fields.getAll('workspace'));
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
  const payload = editorMode === 'app' ? Object.fromEntries([...fields].filter(([key]) => key !== 'workspace')) : { name: fields.get('name'), notificationEmails: fields.get('notificationEmails'), applications: currentWorkspace && !isAdmin && !permissions.workspaces.membership.includes(currentWorkspace.id) ? currentWorkspace.applications : fields.getAll('application') };
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
      for (const group of editorConfig.workspaces) {
        const selected = fields.getAll('workspace').includes(group.id);
        const applicationsAfterRename = group.applications.map(id => id === saved.previousId ? saved.id : id);
        const membership = applicationsAfterRename.includes(saved.id);
        if (selected === membership) continue;
        const applications = selected ? [...applicationsAfterRename, saved.id] : applicationsAfterRename.filter(id => id !== saved.id);
        const update = await fetch(`/api/workspaces/${encodeURIComponent(group.id)}`, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ ...group, applications }) });
        if (!update.ok) throw new Error((await update.json()).error || `Could not add application to ${group.name}`);
      }
    }
    $('editor').close();
    applySavedEditorState(saved, payload, fields);
    if (editorMode === 'workspace') selectWorkspace(saved.id);
    void load(false, true);
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
$('editor-close').addEventListener('click', () => $('editor').close());
$('editor-cancel').addEventListener('click', () => $('editor').close());
for (const card of document.querySelectorAll('.summary-card[data-filter]')) {
  card.addEventListener('click', () => toggleFilter(card.dataset.filter));
  card.addEventListener('keydown', e => { if ((e.key === 'Enter' || e.key === ' ') && activeWorkspace()) { e.preventDefault(); toggleFilter(card.dataset.filter); } });
}
$('overview-nav').addEventListener('click', () => selectWorkspace(null));
$('settings-nav').addEventListener('click', () => { location.hash = 'settings'; renderView(); });
$('logs-nav').addEventListener('click', () => { location.hash = 'logs'; renderView(); });
$('access-nav').addEventListener('click', () => { location.hash = 'access'; renderView(); });
$('logs-refresh').addEventListener('click', loadLogs);
$('settings-form').addEventListener('submit', saveSettings);
$('access-form').addEventListener('submit', saveAccess);
$('add-identity').addEventListener('click', () => { accessData.groups = [...collectAccess().groups, { id: crypto.randomUUID(), name: '', claimSource: 'groups', claimValue: '', enabled: true }]; accessData.grants = collectAccess().grants; renderAccess(); });
$('add-grant').addEventListener('click', () => { const current = collectAccess(); accessData.groups = current.groups; accessData.grants = [...current.grants, { id: crypto.randomUUID(), groupId: current.groups[0]?.id || '', scopeType: 'workspace', roles: [], resourceIds: [] }]; renderAccess(); });
$('access-form').addEventListener('click', event => { const button = event.target.closest('.remove-access'); if (!button) return; const row = button.closest('.access-row'); const current = collectAccess(); accessData.groups = current.groups.filter(item => row.classList.contains('identity-row') ? item.id !== row.dataset.id : true); accessData.grants = current.grants.filter(item => row.classList.contains('grant-row') ? item.id !== row.dataset.id : item.groupId !== row.dataset.id); renderAccess(); });
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
  $('admin-actions').hidden = !isAdmin;
  $('refresh').hidden = !isAdmin;
  $('logs-nav').hidden = !isAdmin;
  $('settings-nav').hidden = !isAdmin;
  $('access-nav').hidden = !isAdmin;
  if (!isAdmin && ['#settings', '#logs', '#access'].includes(location.hash)) location.hash = 'overview';
  renderView();
  if (data.enabled) {
    $('signed-in-user').textContent = data.user;
    $('logout-form').hidden = false;
  }
}).catch(() => {});
load();
setInterval(() => { if (!document.hidden) load(false, true); }, 60_000);
document.addEventListener('visibilitychange', () => { if (!document.hidden) load(false, true); });

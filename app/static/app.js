const csrf = document.querySelector('meta[name="csrf-token"]').content;
const dialog = document.querySelector('#route-dialog');
const form = document.querySelector('#route-form');
const notice = document.querySelector('#notice');
let routes = [];
let activeRoutes = [];
let status = {};

function message(text, error = false) {
  notice.textContent = text;
  notice.className = error ? 'error' : 'success';
}

async function api(path, options = {}) {
  const headers = {'Content-Type': 'application/json', ...(options.headers || {})};
  if (options.method && options.method !== 'GET') headers['X-CSRF-Token'] = csrf;
  const response = await fetch(path, {...options, headers});
  const body = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(body.error || `Error HTTP ${response.status}`);
  return body;
}

function escapeText(value) {
  const node = document.createElement('span');
  node.textContent = value;
  return node.innerHTML;
}

function render() {
  const list = document.querySelector('#route-list');
  list.innerHTML = routes.length ? routes.map(route => `
    <article class="route">
      <div class="status-dot"></div>
      <div class="route-name"><strong>${escapeText(route.name)}</strong><span>${escapeText(route.domain)}</span></div>
      <code>${escapeText(route.scheme)}://${escapeText(route.upstream_host)}:${route.upstream_port}</code>
      <div class="route-actions">
        <button class="ghost edit" data-id="${escapeText(route.id)}">Editar</button>
        <button class="danger delete" data-id="${escapeText(route.id)}">Eliminar</button>
      </div>
    </article>`).join('') : '<p class="empty">Todavía no hay rutas gestionadas.</p>';
  document.querySelector('#route-count').textContent = routes.length;
  document.querySelectorAll('.edit').forEach(button => button.addEventListener('click', () => openEditor(button.dataset.id)));
  document.querySelectorAll('.delete').forEach(button => button.addEventListener('click', () => removeRoute(button.dataset.id)));
}

function renderActive() {
  const list = document.querySelector('#active-route-list');
  list.innerHTML = activeRoutes.length ? activeRoutes.map(route => `
    <article class="route active-route">
      <div class="status-dot ${route.managed ? '' : 'detected'}"></div>
      <div class="route-name"><strong>${escapeText(route.domain)}</strong><span>Configuración activa</span></div>
      <code>${escapeText(route.scheme)}://${escapeText(route.upstream)}</code>
      <span class="badge ${route.managed ? 'managed' : 'readonly'}">${route.managed ? 'Gestionada' : 'Solo lectura'}</span>
    </article>`).join('') : '<p class="empty">No se han detectado rutas reverse_proxy activas.</p>';
  document.querySelector('#active-count').textContent = activeRoutes.length;
}

async function refresh() {
  try {
    [routes, activeRoutes, status] = await Promise.all([
      api('/api/routes'),
      api('/api/active-routes'),
      api('/api/status'),
    ]);
    document.querySelector('#import-state').textContent = status.import_present ? 'correcta' : 'falta';
    document.querySelector('#import-state').className = status.import_present ? 'ok' : 'bad';
    render();
    renderActive();
  } catch (error) { message(error.message, true); }
}

function openEditor(id = '') {
  form.reset();
  form.elements.upstream_port.value = 80;
  const route = routes.find(item => item.id === id);
  if (route) {
    Object.entries(route).forEach(([key, value]) => {
      const field = form.elements[key];
      if (!field) return;
      if (field.type === 'checkbox') field.checked = Boolean(value);
      else field.value = value;
    });
    form.elements.id.readOnly = true;
  } else form.elements.id.readOnly = false;
  dialog.showModal();
}

async function removeRoute(id) {
  if (!confirm(`¿Eliminar la ruta “${id}”? Se creará una copia antes de aplicar el cambio.`)) return;
  try {
    await api(`/api/routes/${encodeURIComponent(id)}`, {method: 'DELETE'});
    message('Ruta eliminada y configuración aplicada.');
    await refresh();
  } catch (error) { message(error.message, true); }
}

form.addEventListener('submit', async event => {
  event.preventDefault();
  const data = Object.fromEntries(new FormData(form));
  data.upstream_port = Number(data.upstream_port);
  data.tls_insecure_skip_verify = form.elements.tls_insecure_skip_verify.checked;
  try {
    await api('/api/routes', {method: 'POST', body: JSON.stringify(data)});
    dialog.close();
    message('Ruta validada y aplicada correctamente.');
    await refresh();
  } catch (error) { message(error.message, true); }
});

document.querySelector('#new-route').addEventListener('click', () => openEditor());
document.querySelector('#refresh-active').addEventListener('click', refresh);
document.querySelector('#close-dialog').addEventListener('click', () => dialog.close());
document.querySelector('#cancel-dialog').addEventListener('click', () => dialog.close());
document.querySelector('#logout').addEventListener('click', async () => {
  try {
    await api('/logout', {method: 'POST', body: '{}'});
    window.location.assign('/login');
  } catch (error) { message(error.message, true); }
});
refresh();

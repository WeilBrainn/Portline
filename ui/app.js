'use strict';
const token = document.querySelector('meta[name="app-token"]').content;
const $ = id => document.getElementById(id);
const panels = [...document.querySelectorAll('[data-panel]')];
const navItems = [...document.querySelectorAll('[data-goto]')];
const protocolOptions = [...document.querySelectorAll('[data-protocol]')];
const hints = [
    { micro: 'ПОДСКАЗКА', title: 'Сначала доступ по SSH', text: 'Понадобятся адрес VPS, логин и пароль или путь к приватному ключу.', footer: 'Подключение по SSH' },
    { micro: 'ПОДСКАЗКА', title: 'Собственный туннель Portline', text: 'Для встроенного подключения выбери Portline Tunnel. Остальные варианты предназначены для внешних клиентов.', footer: 'Проверка UDP-порта доступна здесь' },
    { micro: 'ПОДСКАЗКА', title: 'Следи за журналом', text: 'Установка проходит по SSH. Сначала создаётся конфигурация, затем запускается служба systemd.', footer: 'Служба запускается на VPS' },
    { micro: 'ПОДСКАЗКА', title: 'Проверка туннеля', text: 'Portline использует отдельный сетевой интерфейс Windows. Проверь IP, DNS и IPv6 после подключения.', footer: 'Подключение → диагностика' }
];
let step = 1, selectedProtocol = 'portline', lastStatus = null, lastLink = '', revealed = false;
let pollTimer = null, happPollTimer = null, portPollTimer = null, toastTimer = null, requestInFlight = false;
let lastPortResult = null;
let statusFailures = 0;
let happDoneNotified = false;
let savedProfiles = [];
let selectedProfileId = '';
let passwordStorageDescription = '';
function setStep(n) {
    step = n;
    panels.forEach(p => p.classList.toggle('visible', Number(p.dataset.panel) === n));
    navItems.forEach((el, i) => {
        el.classList.toggle('is-active', i + 1 === n);
        el.classList.toggle('is-done', i + 1 < n);
        el.disabled = i + 1 !== n && !(n === 2 && i === 0);
        el.setAttribute('aria-current', i + 1 === n ? 'step' : 'false');
    });
    const stepTitles = ['Доступ к серверу', 'Выбор протокола', 'Развёртывание', 'Подключение'];
    if ($('crumbStep')) $('crumbStep').textContent = stepTitles[n - 1] || 'Настройка сервера';
    const hint = hints[n - 1];
    $('tipMicro').textContent = hint.micro;
    $('tipTitle').textContent = hint.title;
    $('tipText').textContent = hint.text;
    $('tipFooter').textContent = hint.footer;
    document.querySelector('.guide-number').textContent = String(n).padStart(2, '0') + ' / 04';
    if (n === 4) {
        $('nodeStatus').className = 'status-pill live';
        $('nodeStatus').innerHTML = '<i></i> Профиль готов';
    }
    else if (n === 3) {
        $('nodeStatus').className = 'status-pill working';
        $('nodeStatus').innerHTML = '<i></i> Настройка';
    }
    else {
        $('nodeStatus').className = 'status-pill';
        $('nodeStatus').innerHTML = '<i></i> Не настроен';
    }
    window.scrollTo({ top: 0, behavior: 'auto' });
}
// Modal focus stays in the dialog; closing returns focus to the invoking control.
let activeDialog = null;
let dialogTrigger = null;
function openDialog(id, focusId) {
    dialogTrigger = document.activeElement;
    activeDialog = $(id);
    activeDialog.hidden = false;
    $(focusId).focus();
}
function closeDialog(id) {
    const dialog = $(id);
    dialog.hidden = true;
    if (activeDialog === dialog) {
        activeDialog = null;
        if (dialogTrigger?.isConnected)
            dialogTrigger.focus();
        dialogTrigger = null;
    }
}
document.addEventListener('keydown', (event) => {
    if (!activeDialog)
        return;
    if (event.key === 'Escape') {
        event.preventDefault();
        closeDialog(activeDialog.id);
        return;
    }
    if (event.key !== 'Tab')
        return;
    const focusable = [...activeDialog.querySelectorAll('button:not(:disabled), a[href], input:not(:disabled)')];
    if (!focusable.length)
        return;
    const first = focusable[0];
    const last = focusable[focusable.length - 1];
    if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last.focus();
    }
    else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first.focus();
    }
});
function showError(id, text) { const el = $(id); el.textContent = text; el.hidden = false; }
function hideError(id) { $(id).hidden = true; }
function toast(message) { clearTimeout(toastTimer); $('toast').textContent = message; $('toast').classList.add('show'); toastTimer = setTimeout(() => $('toast').classList.remove('show'), 2800); }
function validHost(s) { return /^[a-z\d](?:[a-z\d.\-]{0,251}[a-z\d])?$/i.test(s) && !s.includes('..'); }
function validPort(n) { return Number.isInteger(+n) && +n >= 1 && +n <= 65535; }
function updateSummary() { const host = $('host').value.trim(); const label = selectedProtocol === 'portline' ? 'Portline Tunnel' : selectedProtocol === 'vless' ? 'VLESS / REALITY' : 'Hysteria 2'; const port = $('vpnPort').value || '—'; $('nodeHost').textContent = host || '—'; $('nodeProtocol').textContent = label; $('nodePort').textContent = port; if ($('successHost')) $('successHost').textContent = host || '—'; if ($('successProtocol')) $('successProtocol').textContent = label; if ($('successPort')) $('successPort').textContent = port; }
function setProtocol(protocol) {
    if (selectedProtocol !== protocol)
        resetPortResult();
    selectedProtocol = protocol;
    protocolOptions.forEach(e => { const active = e.dataset.protocol === protocol; e.classList.toggle('selected', active); e.setAttribute('aria-pressed', String(active)); });
    $('sniBox').classList.toggle('hidden', protocol !== 'vless');
    $('portHint').textContent = protocol === 'hy2' ? 'UDP · выбери свободный порт' : 'TCP · выбери свободный порт';
    $('protocolNotice').textContent = protocol === 'portline'
        ? 'Собственная реализация Portline Tunnel: TLS 1.3 поверх TCP. Устанавливает отдельную службу на VPS и использует Wintun как сетевой адаптер. Это тестовая версия.'
        : protocol === 'vless'
        ? 'VLESS + REALITY остаётся доступен для внешних клиентов. Встроенный Portline Tunnel не подключается к VLESS.'
        : 'Hysteria 2 остаётся доступна для внешних клиентов. Встроенный Portline Tunnel не подключается к Hysteria 2.';
    updateSummary();
}
$('auth').addEventListener('change', () => { const keyMode = $('auth').value === 'key'; $('passwordBox').classList.toggle('hidden', keyMode); $('keyBox').classList.toggle('hidden', !keyMode); $('savePasswordProfile').disabled = keyMode; if (keyMode) $('savePasswordProfile').checked = false; });
$('togglePassword').addEventListener('click', () => { const inp = $('password'); const reveal = inp.type === 'password'; inp.type = reveal ? 'text' : 'password'; $('togglePassword').textContent = reveal ? 'Скрыть' : 'Показать'; });
$('serverForm').addEventListener('submit', e => {
    e.preventDefault();
    hideError('serverError');
    const host = $('host').value.trim();
    if (!validHost(host)) {
        showError('serverError', 'Укажи корректный IP-адрес или DNS-имя сервера.');
        return;
    }
    if (!validPort($('sshPort').value)) {
        showError('serverError', 'Порт SSH должен быть от 1 до 65535.');
        return;
    }
    if (!/^[a-z_][a-z0-9_-]{0,31}$/.test($('username').value)) {
        showError('serverError', 'Укажи корректное SSH-имя пользователя.');
        return;
    }
    if ($('auth').value === 'password' && !$('password').value) {
        showError('serverError', 'Введи пароль SSH.');
        return;
    }
    if ($('auth').value === 'key' && !$('keyFile').value.trim()) {
        showError('serverError', 'Укажи полный путь к приватному ключу.');
        return;
    }
    updateSummary();
    setStep(2);
});
$('savedProfilesSelect').addEventListener('change', () => { selectedProfileId = $('savedProfilesSelect').value; $('loadProfileBtn').disabled = !selectedProfileId; $('deleteProfileBtn').disabled = !selectedProfileId; const current = savedProfiles.find(p => p.id === selectedProfileId); if (current) $('profileName').value = current.name || ''; });
$('saveProfileBtn').addEventListener('click', () => saveCurrentProfile().catch(e => toast(e.message)));
$('loadProfileBtn').addEventListener('click', async () => { if (!selectedProfileId) { toast('Сначала выбери сохранённый сервер.'); return; } try { const data = await api('/api/profiles/load?id=' + encodeURIComponent(selectedProfileId)); fillProfileForm(data.profile); toast(data.profile?.hasPassword ? 'Параметры сервера и сохранённый SSH-пароль загружены в форму.' : 'Параметры сервера загружены в форму.'); } catch (e) { toast(e.message); } });
$('deleteProfileBtn').addEventListener('click', async () => { if (!selectedProfileId) { toast('Сначала выбери профиль.'); return; } if (!confirm('Удалить этот сохранённый сервер?')) return; try { const data = await api('/api/profiles?id=' + encodeURIComponent(selectedProfileId), { method: 'DELETE' }); $('profileName').value = ''; selectedProfileId = ''; renderSavedProfiles(data.profiles || [], '', data.passwordStorage || ''); toast('Профиль удалён.'); } catch (e) { toast(e.message); } });
$('back1').addEventListener('click', () => setStep(1));
navItems.forEach(e => e.addEventListener('click', () => { const n = Number(e.dataset.goto); if (!e.disabled)
    setStep(n); }));
protocolOptions.forEach(e => e.addEventListener('click', () => setProtocol(e.dataset.protocol)));
$('vpnPort').addEventListener('input', () => { updateSummary(); resetPortResult(); });
$('reviewBtn').addEventListener('click', () => {
    hideError('protocolError');
    if (!validPort($('vpnPort').value)) {
        showError('protocolError', 'Укажи порт протокола от 1 до 65535.');
        return;
    }
    if (selectedProtocol === 'vless' && !validHost($('sni').value.trim())) {
        showError('protocolError', 'Введи корректное имя TLS SNI, например www.cloudflare.com.');
        return;
    }
    const p = selectedProtocol === 'portline' ? 'Portline Tunnel / TCP' : selectedProtocol === 'vless' ? 'VLESS + REALITY / TCP' : 'Hysteria 2 / UDP';
    const summary = $('modalSummary');
    const target = document.createElement('strong');
    target.textContent = $('host').value.trim();
    const service = document.createElement('span');
    service.textContent = `${p} · ${$('vpnPort').value}`;
    summary.replaceChildren(target, service);
    openDialog('confirmModal', 'confirmInstall');
});
const closeModal = () => closeDialog('confirmModal');
$('cancelInstall').addEventListener('click', closeModal);
$('confirmModal').addEventListener('click', e => { if (e.target === $('confirmModal'))
    closeModal(); });
async function api(path, options = {}) {
    const response = await fetch(path, { cache: 'no-store', ...options, headers: { 'Authorization': 'Bearer ' + token, ...options.headers } });
    const data = await response.json().catch(() => ({ error: 'Ошибка ответа приложения.' }));
    if (!response.ok)
        throw new Error(data.error || `Ошибка ${response.status}`);
    return data;
}
function payload() { return { host: $('host').value.trim(), sshPort: Number($('sshPort').value), username: $('username').value.trim(), auth: $('auth').value, password: $('auth').value === 'password' ? $('password').value : '', keyFile: $('auth').value === 'key' ? $('keyFile').value.trim() : '', protocol: selectedProtocol, port: Number($('vpnPort').value), sni: $('sni').value.trim() }; }

function currentProfilePayload() { return { id: selectedProfileId, name: $('profileName').value.trim(), host: $('host').value.trim(), sshPort: Number($('sshPort').value), username: $('username').value.trim(), auth: $('auth').value, keyFile: $('auth').value === 'key' ? $('keyFile').value.trim() : '', protocol: selectedProtocol, port: Number($('vpnPort').value), sni: $('sni').value.trim(), password: $('auth').value === 'password' ? $('password').value : '', savePassword: $('auth').value === 'password' && $('savePasswordProfile').checked }; }
function renderSavedProfiles(list, preferredId = '', passwordStorage = passwordStorageDescription) {
    if (passwordStorage) {
        passwordStorageDescription = passwordStorage;
        if ($('passwordStorageHint')) $('passwordStorageHint').textContent = passwordStorage;
    }
    savedProfiles = Array.isArray(list) ? list : [];
    const select = $('savedProfilesSelect');
    select.replaceChildren();
    if (!savedProfiles.length) {
        const empty = document.createElement('option');
        empty.value = '';
        empty.textContent = 'Нет сохранённых профилей';
        select.append(empty);
        $('loadProfileBtn').disabled = true;
        $('deleteProfileBtn').disabled = true;
        selectedProfileId = '';
        return;
    }
    const placeholder = document.createElement('option');
    placeholder.value = '';
    placeholder.textContent = 'Выбери сохранённый сервер';
    select.append(placeholder);
    for (const profile of savedProfiles) {
        const option = document.createElement('option');
        option.value = profile.id;
        option.textContent = `${profile.name} · ${profile.host}:${profile.port}`;
        select.append(option);
    }
    const chosen = preferredId || selectedProfileId || savedProfiles[0].id;
    select.value = savedProfiles.some(p => p.id === chosen) ? chosen : '';
    selectedProfileId = select.value;
    $('loadProfileBtn').disabled = !selectedProfileId;
    $('deleteProfileBtn').disabled = !selectedProfileId;
}
function fillProfileForm(profile) {
    if (!profile) return;
    $('host').value = profile.host || '';
    $('sshPort').value = String(profile.sshPort || 22);
    $('username').value = profile.username || 'root';
    $('auth').value = profile.auth || 'password';
    const keyMode = $('auth').value === 'key';
    $('passwordBox').classList.toggle('hidden', keyMode);
    $('keyBox').classList.toggle('hidden', !keyMode);
    $('keyFile').value = profile.keyFile || '';
    $('password').value = profile.password || '';
    $('profileName').value = profile.name || '';
    $('savePasswordProfile').disabled = keyMode;
    $('savePasswordProfile').checked = !!profile.hasPassword && !keyMode;
    setProtocol(profile.protocol || 'portline');
    $('vpnPort').value = String(profile.port || 8443);
    $('sni').value = profile.sni || 'www.cloudflare.com';
    updateSummary();
}
async function refreshProfiles(preferredId = '') {
    const data = await api('/api/profiles');
    renderSavedProfiles(data.profiles || [], preferredId, data.passwordStorage || '');
}
function renderNativeProfileInfo(status = lastStatus || {}) {
    if (!$('nativeProfileInfo')) return;
    if (status.needsFreshProfile) {
        $('nativeProfileInfo').textContent = 'Для этого сервера требуется новый локальный профиль Portline. Старый профиль не будет использоваться, пока установка не вернёт новую конфигурацию.';
        return;
    }
    const host = status.nativeProfileHost || '';
    const port = status.nativeProfilePort || 0;
    if (!host || !port) {
        $('nativeProfileInfo').textContent = 'Локальный профиль ещё не сохранён.';
        return;
    }
    let text = `Локальный профиль туннеля: ${host}:${port}.`;
    const formHost = $('host').value.trim();
    const formPort = Number($('vpnPort').value || 0);
    if (formHost && formPort && (formHost !== host || formPort !== port)) {
        text += ` В форме сейчас указан ${formHost}:${formPort}. Если это другой сервер или порт, сначала переустанови Portline, иначе подключение пойдёт к сохранённому профилю ${host}:${port}.`;
    }
    $('nativeProfileInfo').textContent = text;
}
async function saveCurrentProfile() {
    const body = currentProfilePayload();
    if (!validHost(body.host)) {
        toast('Сначала укажи корректный адрес VPS.');
        return;
    }
    if (!validPort(body.sshPort) || !validPort(body.port)) {
        toast('Сначала укажи корректные порты.');
        return;
    }
    if (!/^[a-z_][a-z0-9_-]{0,31}$/.test(body.username)) {
        toast('Укажи корректное SSH-имя пользователя.');
        return;
    }
    const data = await api('/api/profiles', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
    selectedProfileId = data.profile?.id || '';
    $('profileName').value = data.profile?.name || $('profileName').value;
    renderSavedProfiles(data.profiles || [], selectedProfileId, data.passwordStorage || '');
    toast($('savePasswordProfile').checked ? 'Профиль сервера сохранён. SSH-пароль защищён локальным хранилищем Windows.' : 'Профиль сервера сохранён.');
}
async function beginInstall() {
    if (requestInFlight)
        return;
    requestInFlight = true;
    closeModal();
    setStep(3);
    $('retryBtn').hidden = true;
    $('resolvePortBtn').hidden = true;
    $('installError').hidden = true;
    $('installLogs').textContent = '> Установка инициализируется…';
    $('progressFill').style.width = '5%';
    $('progressNumber').textContent = '5%';
    try {
        await api('/api/install', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload()) });
        startPolling();
    }
    catch (e) {
        showError('installError', e.message);
        $('retryBtn').hidden = false;
        $('progressStatus').textContent = 'Не начато';
        $('terminalStatus').textContent = 'ОШИБКА';
    }
    finally {
        requestInFlight = false;
    }
}
$('confirmInstall').addEventListener('click', beginInstall);
$('retryBtn').addEventListener('click', () => openDialog('confirmModal', 'confirmInstall'));
$('resolvePortBtn').addEventListener('click', () => { setStep(2); checkPort(); });
function updateInstall(status) {
    lastStatus = status;
    renderNativeProfileInfo(status);
    $('installPhase').textContent = status.phase || 'Развёртывание';
    $('progressNumber').textContent = status.progress + '%';
    $('progressFill').style.width = status.progress + '%';
    $('progressStatus').textContent = status.state === 'running' ? 'В процессе' : status.state === 'success' ? 'Готово' : 'Требуется внимание';
    $('terminalStatus').textContent = status.state === 'running' ? 'ВЫПОЛНЯЕТСЯ' : status.state === 'success' ? 'ЗАВЕРШЕНО' : 'ОСТАНОВЛЕНО';
    const lines = status.logs || [];
    const pre = $('installLogs');
    const text = lines.length ? lines.map(x => '> ' + x).join('\n') : '> Ожидание соединения…';
    if (pre.textContent !== text) {
        const pinned = pre.scrollTop + pre.clientHeight >= pre.scrollHeight - 30;
        pre.textContent = text;
        if (pinned)
            pre.scrollTop = pre.scrollHeight;
    }
    if (status.state === 'error') {
        clearInterval(pollTimer);
        pollTimer = null;
        showError('installError', status.error || 'Установка остановлена.');
        $('retryBtn').hidden = false;
        if (status.portConflict)
            $('resolvePortBtn').hidden = false;
    }
    if (status.state === 'success') {
        clearInterval(pollTimer);
        pollTimer = null;
        lastLink = selectedProtocol === 'portline' ? '' : (status.link || '');
        revealed = false;
        renderLink();
        setStep(4);
        showConnectionPanel();
        toast('Сервер настроен. Сохрани ключ доступа.');
        if (selectedProtocol === 'portline') startNativeTunnel('connect');
    }
}
async function poll() {
    try {
        const status = await api('/api/status');
        statusFailures = 0;
        if (['running', 'success', 'error'].includes(status.state))
            updateInstall(status);
    }
    catch (error) {
        statusFailures++;
        if (statusFailures < 8)
            return;
        clearInterval(pollTimer);
        pollTimer = null;
        showError('installError', 'Потеряно соединение с локальным приложением. Проверь, что Portline запущен. Не запускай повторную установку, пока не проверишь VPS.');
        $('terminalStatus').textContent = 'НЕТ СВЯЗИ';
    }
}
function startPolling() { if (pollTimer)
    clearInterval(pollTimer); statusFailures = 0; poll(); pollTimer = setInterval(poll, 800); }
function renderLink() { const e = $('resultLink'); e.classList.toggle('masked-link', !revealed); e.textContent = revealed ? lastLink : '••••••••••••••••••••••••••••••'; e.title = revealed ? lastLink : 'Ключ скрыт'; }
$('revealBtn').addEventListener('click', () => { revealed = !revealed; renderLink(); });
$('copyBtn').addEventListener('click', async () => { if (!lastLink) return; try {
    await navigator.clipboard.writeText(lastLink);
    toast('Ссылка скопирована в буфер обмена.');
}
catch (_) {
    const input = document.createElement('textarea');
    input.value = lastLink;
    input.style.position = 'fixed';
    input.style.top = '-9999px';
    document.body.append(input);
    input.select();
    const ok = document.execCommand('copy');
    input.remove();
    toast(ok ? 'Ссылка скопирована.' : 'Не удалось скопировать. Покажи ссылку и выдели её вручную.');
} });
$('saveBtn').addEventListener('click', () => { if (!lastLink) return; if (!lastLink)
    return; const blob = new Blob([lastLink + '\n'], { type: 'text/plain;charset=utf-8' }); const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = selectedProtocol === 'portline' ? 'Portline.txt' : `portline-${selectedProtocol}-${$('host').value.trim()}.txt`; a.click(); setTimeout(() => URL.revokeObjectURL(a.href), 3000); toast('Файл с ключом сохранён. Храни его в безопасном месте.'); });
// Import via HAPP's registered deeplink. HAPP controls its own TUN permissions.
function openInHAPP() {
    if (!lastLink) {
        toast('Сначала настрой сервер.');
        return;
    }
    $('happMessage').textContent = 'Открываем HAPP. Если окно не появилось, установи HAPP или воспользуйся «Скопировать ссылку».';
    window.location.href = 'happ://add/' + encodeURIComponent(lastLink);
}
$('openHappBtn').addEventListener('click', openInHAPP);
function renderHAPPProgress(task) {
    if (!task)
        return;
    const btn = $('installHappBtn');
    const running = task.state === 'running';
    btn.disabled = running;
    btn.classList.toggle('is-busy', running);
    btn.textContent = running ? 'Идёт установка…' : 'Установить HAPP';
    if (task.state === 'running') {
        $('happMessage').textContent = task.phase || 'Устанавливаем HAPP в фоновом режиме…';
        $('happDownloadLink').hidden = true;
    }
    else if (task.state === 'success') {
        $('happMessage').textContent = task.message || 'HAPP установлен. Можно импортировать профиль.';
        $('happDownloadLink').hidden = true;
    }
    else if (task.state === 'error') {
        $('happMessage').textContent = task.message || 'Не удалось установить HAPP автоматически.';
        $('happDownloadLink').hidden = false;
    }
    if (!running && happPollTimer) {
        clearInterval(happPollTimer);
        happPollTimer = null;
    }
}
async function checkHAPPProgress() {
    try {
        const status = await api('/api/status');
        renderHAPPProgress(status.happ);
        if (status.happ?.state === 'success' && !happDoneNotified) {
            happDoneNotified = true;
            toast('HAPP готов. Импортируй профиль.');
        }
    }
    catch (e) {
        $('happMessage').textContent = 'Проверка состояния недоступна: ' + e.message;
    }
}
$('installHappBtn').addEventListener('click', async () => {
    const b = $('installHappBtn');
    if (b.disabled)
        return;
    happDoneNotified = false;
    b.disabled = true;
    b.classList.add('is-busy');
    b.textContent = 'Подготавливаем…';
    $('happMessage').textContent = 'Запускаем тихую установку. Внешняя консоль не откроется.';
    $('happDownloadLink').hidden = true;
    try {
        await api('/api/happ-install', { method: 'POST' });
        if (happPollTimer)
            clearInterval(happPollTimer);
        happPollTimer = setInterval(checkHAPPProgress, 850);
        await checkHAPPProgress();
    }
    catch (e) {
        b.disabled = false;
        b.classList.remove('is-busy');
        b.textContent = 'Установить HAPP';
        $('happMessage').textContent = e.message;
    }
});
function showConnectionPanel() {
    const native = selectedProtocol === 'portline';
    $('nativeSetup').hidden = !native;
    $('happSetup').hidden = native;
    if ($('resultCard')) $('resultCard').hidden = native;
    $('successIntro').textContent = native
        ? 'Сервер Portline установлен. Подключение запускается из этого приложения.'
        : 'Служба запущена на VPS. Для этого протокола потребуется внешний совместимый клиент.';
    $('profileLabel').textContent = native ? 'НАСТРОЙКИ ХРАНЯТСЯ ЛОКАЛЬНО' : 'ССЫЛКА ПОДКЛЮЧЕНИЯ';
    $('copyBtn').hidden = native; $('revealBtn').hidden = native; $('resultLink').textContent = native ? 'Ключ доступа сохранён локально' : $('resultLink').textContent;
    $('saveBtn').hidden = native;
    renderNativeProfileInfo(lastStatus || {});
}
let tunnelPollTimer = null;
let tunnelPollFailures = 0;
let uptimeTimer = null;
let connectedSinceMs = 0;
function formatPackets(n) {
    const val = Number(n || 0);
    if (val >= 1000000) return (val / 1000000).toFixed(2) + 'M';
    if (val >= 10000) return (val / 1000).toFixed(1) + 'K';
    return val.toLocaleString('ru-RU');
}
function updateUptimeDisplay() {
    if (!$('metricUptime')) return;
    if (!connectedSinceMs) {
        $('metricUptime').textContent = '00:00:00';
        return;
    }
    const sec = Math.max(0, Math.floor((Date.now() - connectedSinceMs) / 1000));
    const h = String(Math.floor(sec / 3600)).padStart(2, '0');
    const m = String(Math.floor((sec % 3600) / 60)).padStart(2, '0');
    const s = String(sec % 60).padStart(2, '0');
    $('metricUptime').textContent = `${h}:${m}:${s}`;
}
function renderTelemetry(state) {
    const connected = state?.state === 'connected';
    const nodeArt = document.querySelector('.node-art');
    if (nodeArt) nodeArt.classList.toggle('is-live', connected);
    if ($('metricSent')) $('metricSent').textContent = formatPackets(state?.sentPackets);
    if ($('metricRecv')) $('metricRecv').textContent = formatPackets(state?.receivedPackets);
    if ($('metricLatency')) {
        const ms = state?.latencyMs;
        $('metricLatency').textContent = connected && ms > 0 ? `${ms} мс` : connected ? '…' : '—';
    }
    if (connected && state?.connectedAt) {
        const parsed = Date.parse(state.connectedAt);
        connectedSinceMs = Number.isFinite(parsed) ? parsed : (connectedSinceMs || Date.now());
        if (!uptimeTimer) uptimeTimer = setInterval(updateUptimeDisplay, 1000);
    } else {
        connectedSinceMs = 0;
        if (uptimeTimer) {
            clearInterval(uptimeTimer);
            uptimeTimer = null;
        }
    }
    updateUptimeDisplay();
}
async function refreshTunnel() {
    try {
        const status = await api('/api/status');
        tunnelPollFailures = 0;
        const prevState = lastStatus?.tunnel?.state;
        lastStatus = status;
        renderNativeProfileInfo(status);
        const state = status.tunnel || {};
        const running = state.state === 'running';
        const disconnecting = state.state === 'disconnecting';
        const busy = running || disconnecting;
        const connected = state.state === 'connected';
        $('nativeConnectBtn').disabled = busy || connected;
        $('nativeDisconnectBtn').disabled = disconnecting || (!running && !connected);
        $('nativeDiagnoseBtn').disabled = busy;
        $('nativeDiagnoseBtn').textContent = connected ? 'Проверить трафик' : 'Проверить протокол';
        $('nativeConnectBtn').textContent = running ? 'Подключаем…' : 'Подключить VPN';
        $('nativeDisconnectBtn').textContent = disconnecting ? 'Отключаем…' : 'Отключить';
        if ($('leakCheckLink')) $('leakCheckLink').hidden = !connected;
        document.body.classList.toggle('is-vpn-connected', connected);
        document.body.classList.toggle('is-vpn-connecting', running);
        if ($('topIndicator')) $('topIndicator').classList.toggle('is-live', connected);
        if ($('topIndicatorText')) $('topIndicatorText').textContent = connected ? 'Туннель активен' : disconnecting ? 'Отключение…' : running ? 'Подключение…' : 'Локальная панель';
        if (step === 4) {
            if (connected) {
                $('nodeStatus').className = 'status-pill live';
                $('nodeStatus').innerHTML = '<i></i> VPN подключён';
            } else if (disconnecting) {
                $('nodeStatus').className = 'status-pill working';
                $('nodeStatus').innerHTML = '<i></i> Отключение';
            } else if (running) {
                $('nodeStatus').className = 'status-pill working';
                $('nodeStatus').innerHTML = '<i></i> Подключение';
            } else {
                $('nodeStatus').className = 'status-pill';
                $('nodeStatus').innerHTML = '<i></i> Отключён';
            }
        }
        const stateNames = {connected:'VPN подключён',running:'Подключение…',disconnecting:'Отключение…',disconnected:'Отключено',error:'Ошибка подключения',idle:'Не подключено'};
        $('connectionState').textContent = stateNames[state.state] || 'Не подключено';
        $('connectionHero').dataset.state = state.state || 'idle';
        $('nativeStatus').textContent = state.message || state.phase || 'Готов к подключению';
        $('firewallFix').hidden = !(state.needsFirewall || (connected && state.guardMode === 'routes'));
        $('enableFirewallBtn').disabled = connected || busy;
        $('enableFirewallBtn').title = connected ? 'Сначала отключи VPN, затем включи брандмауэр и подключись снова' : '';
        $('guardModePill').hidden = !connected || !state.guardMode;
        $('guardModePill').textContent = state.guardMode === 'wfp' ? 'Защита: WFP' : state.guardMode === 'routes' ? 'Защита: маршруты' : 'Защита: брандмауэр';
        renderTelemetry(state);
        if (connected && prevState !== 'connected') {
            toast(state.guardMode === 'wfp' ? 'Полный туннель активен. Защита WFP включена.' : state.guardMode === 'routes' ? 'Туннель активен. Защита через маршруты (брандмауэр выключен).' : 'Полный туннель активен. DNS и IPv6 защищены.');
        }
        if (busy || connected) {
            const desiredMs = busy ? 900 : 2000;
            if (!tunnelPollTimer || tunnelPollTimer._interval !== desiredMs) {
                if (tunnelPollTimer) clearInterval(tunnelPollTimer);
                tunnelPollTimer = setInterval(refreshTunnel, desiredMs);
                tunnelPollTimer._interval = desiredMs;
            }
        } else if (tunnelPollTimer) {
            clearInterval(tunnelPollTimer);
            tunnelPollTimer = null;
        }
    } catch(e) {
        tunnelPollFailures++;
        if (tunnelPollFailures >= 5 && tunnelPollTimer) {
            clearInterval(tunnelPollTimer);
            tunnelPollTimer = null;
            $('nativeConnectBtn').disabled = false;
            $('nativeDisconnectBtn').disabled = true;
            $('nativeStatus').textContent = 'Локальное приложение Portline закрыто или перезапущено. Закрой это окно и открой Portline.exe заново.';
            return;
        }
        $('nativeStatus').textContent = 'Не удалось проверить соединение: ' + e.message;
    }
}
async function startNativeTunnel(action) {
    $('nativeConnectBtn').disabled = true;
    $('nativeDisconnectBtn').disabled = true;
    $('nativeStatus').textContent = action === 'connect' ? 'Подготавливаем подключение…' : 'Отключаем…';
    try {
        await api(`/api/tunnel/${action}`, {method:'POST', headers: action === 'connect' ? {'Content-Type':'application/json'} : {}, body: action === 'connect' ? JSON.stringify({expectedHost:$('host').value.trim(),expectedPort:Number($('vpnPort').value)}) : undefined});
        if (tunnelPollTimer) clearInterval(tunnelPollTimer);
        tunnelPollTimer = setInterval(refreshTunnel, 900);
        tunnelPollTimer._interval = 900;
        await refreshTunnel();
    } catch(e) {
        $('nativeStatus').textContent = e.message;
        $('nativeConnectBtn').disabled = false;
        $('nativeDisconnectBtn').disabled = false;
    }
}
async function diagnoseNativeTunnel() {
    const b = $('nativeDiagnoseBtn');
    b.disabled = true;
    $('diagnosticResult').hidden = false;
    $('diagnosticResult').dataset.state = 'running';
    const connected = lastStatus?.tunnel?.state === 'connected';
    $('diagnosticTitle').textContent = connected ? 'Проверяем трафик сеанса' : 'Проверяем TCP → TLS → доступ';
    $('diagnosticMessage').textContent = connected ? 'Читаем счётчики адаптера и соединения…' : 'Проверяем сохранённый профиль…';
    $('diagnosticAdvice').textContent = '';
    try {
        const result = await api('/api/tunnel/diagnose', {method:'POST'});
        const stages = {traffic:'Трафик туннеля',tcp:'TCP-соединение',tls:'TLS-рукопожатие',identity:'Ключ сервера',auth:'Авторизация',ready:'Протокол готов',profile:'Сохранённый профиль'};
        $('diagnosticResult').dataset.state = result.state;
        $('diagnosticTitle').textContent = `${stages[result.stage] || 'Проверка'} · ${result.endpoint}`;
        $('diagnosticMessage').textContent = result.message;
        $('diagnosticAdvice').textContent = result.advice;
    } catch(e) {
        $('diagnosticResult').dataset.state = 'error';
        $('diagnosticTitle').textContent = 'Проверка не выполнена';
        $('diagnosticMessage').textContent = e.message;
        $('diagnosticAdvice').textContent = '';
    } finally {
        b.disabled = false;
    }
}
$('nativeDiagnoseBtn').addEventListener('click', diagnoseNativeTunnel);
$('enableFirewallBtn').addEventListener('click', async () => {
    if (!confirm('Включить брандмауэр Windows для всех сетевых профилей? Он останется включённым и после отключения VPN.')) return;
    const b = $('enableFirewallBtn');
    b.disabled = true;
    b.textContent = 'Включаем…';
    try {
        await api('/api/firewall/enable', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({confirm:true})});
        $('firewallFix').hidden = true;
        toast('Брандмауэр включён. Следующее подключение будет с усиленной защитой.');
        await refreshTunnel();
    } catch (e) {
        toast(e.message);
    } finally {
        b.disabled = false;
        b.textContent = 'Включить брандмауэр';
    }
});
$('nativeConnectBtn').addEventListener('click', () => startNativeTunnel('connect'));
$('nativeDisconnectBtn').addEventListener('click', () => startNativeTunnel('disconnect'));
$('newBtn').addEventListener('click', () => { resetPortResult(); if (happPollTimer) {
    clearInterval(happPollTimer);
    happPollTimer = null;
} lastLink = ''; revealed = false; setStep(1); toast('Введи данные следующего VPS.'); });
$('quitBtn').addEventListener('click', async () => { try {
    await api('/api/quit', { method: 'POST' });
    window.close();
}
catch (e) {
    toast(e.message);
} });
function resetPortResult() {
    lastPortResult = null;
    if ($('portResponse'))
        $('portResponse').hidden = true;
    if (portPollTimer) {
        clearInterval(portPollTimer);
        portPollTimer = null;
    }
    if ($('portCheckBtn'))
        $('portCheckBtn').disabled = false;
    if ($('reviewBtn'))
        $('reviewBtn').disabled = false;
}
function renderPortResult(task) {
    if (!task)
        return;
    const expectedProtocol = selectedProtocol === 'hy2' ? 'udp' : 'tcp';
    if (task.port !== Number($('vpnPort').value) || task.protocol !== expectedProtocol)
        return;
    lastPortResult = task;
    const panel = $('portResponse');
    panel.hidden = false;
    panel.className = 'port-response';
    $('portCheckBtn').disabled = task.state === 'running';
    $('reviewBtn').disabled = task.state === 'running';
    $('portCheckBtn').textContent = task.state === 'running' ? 'Проверяем…' : 'Проверить снова';
    if (task.state === 'running')
        panel.classList.add('is-busy');
    if (task.state === 'busy')
        panel.classList.add('is-conflict');
    if (task.state === 'error')
        panel.classList.add('is-error');
    $('portMessage').textContent = task.message || 'Проверка порта';
    $('portOwner').hidden = task.state !== 'busy';
    $('portOwner').textContent = `Процесс: ${task.process || 'не установлен'} · systemd: ${task.service || 'не обнаружена'} · PID: ${task.pid || '—'}`;
    $('portStopBtn').hidden = !(task.state === 'busy' && task.canStop);
    const suggestions = $('portSuggestions');
    suggestions.hidden = task.state !== 'busy' || !(task.suggestions?.length);
    const list = $('portSuggestedList');
    list.replaceChildren();
    for (const port of task.suggestions || []) {
        const b = document.createElement('button');
        b.type = 'button';
        b.textContent = String(port);
        b.setAttribute('aria-label', `Выбрать порт ${port} и проверить`);
        b.addEventListener('click', () => { $('vpnPort').value = String(port); updateSummary(); resetPortResult(); checkPort(); });
        list.append(b);
    }
    if (task.state === 'busy' && !task.canStop) {
        $('portMessage').textContent += ' Автоматическая остановка недоступна; выбери другой порт.';
    }
    if (task.state !== 'running' && portPollTimer) {
        clearInterval(portPollTimer);
        portPollTimer = null;
    }
}
async function pollPort() {
    try {
        const status = await api('/api/status');
        renderPortResult(status.portTask);
    }
    catch (e) {
        if (portPollTimer) {
            clearInterval(portPollTimer);
            portPollTimer = null;
        }
        renderPortResult({ state: 'error', port: Number($('vpnPort').value), protocol: selectedProtocol === 'hy2' ? 'udp' : 'tcp', message: e.message });
    }
}
function startPortPolling() { if (portPollTimer)
    clearInterval(portPollTimer); portPollTimer = setInterval(pollPort, 750); pollPort(); }
async function checkPort() {
    if (!validPort($('vpnPort').value)) {
        showError('protocolError', 'Укажи порт от 1 до 65535.');
        return;
    }
    $('portCheckBtn').disabled = true;
    $('reviewBtn').disabled = true;
    lastPortResult = null;
    $('portStopBtn').hidden = true;
    $('portOwner').hidden = true;
    $('portSuggestions').hidden = true;
    $('portResponse').hidden = false;
    $('portMessage').textContent = 'Соединяемся с VPS и проверяем занятость порта…';
    $('portResponse').className = 'port-response is-busy';
    try {
        await api('/api/ports/check', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload()) });
        startPortPolling();
    }
    catch (e) {
        renderPortResult({ state: 'error', port: Number($('vpnPort').value), protocol: selectedProtocol === 'hy2' ? 'udp' : 'tcp', message: e.message });
    }
}

// Gateway discovery is read-only. Using an existing installation and updating
// it require separate, explicit user actions.
let gatewayPoll = null;
let gatewayAction = '';
function renderGatewayState(status) {
    const tool = $('gatewayTool');
    if (!tool) return;
    const progress = status.gatewayAction || '';
    const info = status.gateway || {};
    const box = $('gatewayResult');
    if (!progress && !info.state) return;
    box.hidden = false;
    $('gatewayInspectBtn').disabled = progress === 'running';
    $('gatewayHeadline').textContent = progress === 'running' ? 'Проверяем Gateway…' : progress === 'error' ? 'Не удалось выполнить операцию' : info.state === 'missing' ? 'Gateway не установлен' : info.state === 'installed' ? 'Gateway обнаружен' : 'Проверка';
    $('gatewayMessage').textContent = status.gatewayError || info.message || '';
    const facts = $('gatewayFacts'); facts.replaceChildren();
    if (info.state === 'installed') {
      for (const value of [`Служба: ${info.activity === 'active' ? 'активна' : 'остановлена'}`, `Адрес: ${info.host}:${info.port}`, `Версия: ${info.version}`, `Конфигурация: v${info.configVersion}`]) {
        const span=document.createElement('span');span.textContent=value;facts.append(span);
      }
    }
    const matches = info.state === 'installed' && info.compatible && info.host === $('host').value.trim() && Number(info.port) === Number($('vpnPort').value);
    $('gatewayUseBtn').hidden = !(matches && info.activity === 'active' && progress !== 'running');
    $('gatewayUpdateBtn').hidden = !(matches && info.needsUpdate && progress !== 'running');
    if (!matches && info.state === 'installed') {
      $('gatewayMessage').textContent += ` Профиль сервера привязан к ${info.host}:${info.port}; введённые параметры — ${$('host').value.trim()}:${$('vpnPort').value}. Выбери порт существующей службы, чтобы использовать её без переустановки.`;
    }
    if (gatewayPoll && progress !== 'running') {
      clearInterval(gatewayPoll);gatewayPoll = null;
      if (progress === 'success' && gatewayAction === 'use') {
        lastStatus = status;selectedProtocol = 'portline';
        $('host').value = status.nativeProfileHost || $('host').value;
        $('vpnPort').value = String(status.nativeProfilePort || $('vpnPort').value);
        updateSummary();setStep(4);showConnectionPanel();refreshTunnel();
        toast('Подключение к установленному Gateway готово.');
      } else if (progress === 'success' && gatewayAction === 'update') toast('Gateway обновлён, резервная копия сохранена на VPS.');
    }
}
async function runGatewayUI(action) {
    if (gatewayPoll) return;
    if (selectedProtocol !== 'portline') { toast('Выбери протокол Portline Tunnel.');return; }
    if (action === 'update' && !confirm('Обновить Portline Gateway? Перед заменой бинарника на VPS будет создана резервная копия. Соединение может прерваться.')) return;
    gatewayAction = action;
    $('gatewayResult').hidden = false;
    $('gatewayHeadline').textContent = action === 'inspect' ? 'Проверяем Gateway…' : action === 'use' ? 'Читаем существующий профиль…' : 'Обновляем Gateway…';
    $('gatewayMessage').textContent = 'Соединение SSH. Не закрывай приложение до завершения операции.';
    try {
      await api('/api/gateway/' + action,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({...payload(),confirmUpdate: action === "update"})});
      const poll = async()=> { try { renderGatewayState(await api('/api/status')); } catch(err) { $('gatewayMessage').textContent='Не удалось получить состояние: '+err.message; } };
      gatewayPoll = setInterval(poll,850);
      await poll();
    } catch(err) {
      $('gatewayHeadline').textContent = 'Ошибка проверки Gateway';
      $('gatewayMessage').textContent = err.message;
    }
}
$('gatewayInspectBtn').addEventListener('click',()=>runGatewayUI('inspect'));
$('gatewayUseBtn').addEventListener('click',()=>runGatewayUI('use'));
$('gatewayUpdateBtn').addEventListener('click',()=>runGatewayUI('update'));

$('portCheckBtn').addEventListener('click', checkPort);
$('portStopBtn').addEventListener('click', () => {
    if (!lastPortResult || !lastPortResult.canStop || lastPortResult.state !== 'busy')
        return;
    $('stopPortSummary').textContent = `${lastPortResult.service} · ${lastPortResult.protocol.toUpperCase()} ${lastPortResult.port} · ${$('host').value.trim()}`;
    openDialog('stopPortModal', 'confirmStopPort');
});
function closeStopPortModal() { closeDialog('stopPortModal'); }
$('cancelStopPort').addEventListener('click', closeStopPortModal);
$('stopPortModal').addEventListener('click', e => { if (e.target === $('stopPortModal'))
    closeStopPortModal(); });
$('confirmStopPort').addEventListener('click', async () => {
    if (!lastPortResult?.canStop || lastPortResult.state !== 'busy')
        return;
    const service = lastPortResult.service;
    closeStopPortModal();
    $('portCheckBtn').disabled = true;
    $('reviewBtn').disabled = true;
    $('portStopBtn').hidden = true;
    $('portMessage').textContent = 'Останавливаем службу и проверяем освобождение порта…';
    try {
        await api('/api/ports/stop', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ ...payload(), service }) });
        startPortPolling();
    }
    catch (e) {
        renderPortResult({ state: 'error', port: Number($('vpnPort').value), protocol: selectedProtocol === 'hy2' ? 'udp' : 'tcp', message: e.message });
    }
});
setProtocol('portline');
updateSummary();
setStep(1);
refreshProfiles().catch(() => {});
// Keep the desktop process alive while its GUI is open, but don't poll a running deployment twice.
setInterval(() => { if (!pollTimer)
    api('/api/status').catch(() => { }); }, 7000);


// Restore the active native profile after restart. This does not start a new
// connection without user action; the Windows service may already be active.
api('/api/status').then(status => {
    lastStatus = status;
    renderNativeProfileInfo(status);
    if (status.state !== 'success' || status.protocol !== 'portline' || !status.hasNativeProfile) return;
    selectedProtocol = 'portline';
    $('host').value = status.host || '';
    if (status.nativeProfilePort) $('vpnPort').value = String(status.nativeProfilePort);
    updateSummary();
    lastLink = '';
    revealed = false;
    renderLink();
    setStep(4);
    showConnectionPanel();
    refreshTunnel();
}).catch(() => {});

$('importTunnelBtn').addEventListener('click', () => $('importTunnelFile').click());
$('importTunnelFile').addEventListener('change', async event => {
    const file = event.target.files[0];
    event.target.value = '';
    if (!file) return;
    try {
        if (file.size > 8192) throw new Error('Слишком большой файл профиля.');
        if (lastStatus?.hasNativeProfile && !confirm('Заменить текущий VPN-профиль импортированным?')) return;
        await api('/api/tunnel/profile/import', {method:'POST', body:await file.text()});
        location.reload();
    } catch (e) { toast(e.message); }
});
async function importProfileText(raw) {
    const text = (raw || '').trim();
    if (!text) throw new Error('Вставь ключ-строку профиля Portline.');
    if (text.length > 8192) throw new Error('Слишком длинный ключ профиля.');
    if (lastStatus?.hasNativeProfile && !confirm('Заменить текущий VPN-профиль импортированным?')) return;
    await api('/api/tunnel/profile/import', {method:'POST', body:text});
    location.reload();
}
if ($('pasteTunnelBtn') && $('pasteTunnelBox')) {
    $('pasteTunnelBtn').addEventListener('click', () => {
        const box = $('pasteTunnelBox');
        box.hidden = !box.hidden;
        if (!box.hidden && $('pasteTunnelInput')) $('pasteTunnelInput').focus();
    });
}
if ($('applyPasteTunnelBtn') && $('pasteTunnelInput')) {
    $('applyPasteTunnelBtn').addEventListener('click', async () => {
        try { await importProfileText($('pasteTunnelInput').value); }
        catch (e) { toast(e.message); }
    });
    $('pasteTunnelInput').addEventListener('keydown', async e => {
        if (e.key === 'Enter') {
            e.preventDefault();
            try { await importProfileText($('pasteTunnelInput').value); }
            catch (err) { toast(err.message); }
        }
    });
}
if ($('copyTunnelConfigBtn')) {
    $('copyTunnelConfigBtn').addEventListener('click', async () => {
        const btn = $('copyTunnelConfigBtn');
        try {
            const data = await api('/api/tunnel/profile/export', {method:'POST'});
            const shareText = 'portline://' + data.profile;
            if (navigator.clipboard && navigator.clipboard.writeText) {
                await navigator.clipboard.writeText(shareText);
            } else {
                const ta = document.createElement('textarea');
                ta.value = shareText;
                ta.style.position = 'fixed';
                ta.style.opacity = '0';
                document.body.appendChild(ta);
                ta.select();
                document.execCommand('copy');
                document.body.removeChild(ta);
            }
            const orig = btn.textContent;
            btn.textContent = 'Скопировано ✓';
            setTimeout(() => { btn.textContent = orig; }, 2000);
            toast('Ключ-конфиг скопирован. Отправь его другу — он сможет подключиться без SSH.');
        } catch (e) { toast(e.message); }
    });
}
$('exportTunnelBtn').addEventListener('click', async () => {
    try {
        const data = await api('/api/tunnel/profile/export', {method:'POST'});
        const url = URL.createObjectURL(new Blob([data.profile], {type:'application/octet-stream'}));
        const link = document.createElement('a');
        link.href = url;
        link.download = 'Portline.portline';
        link.click();
        setTimeout(() => URL.revokeObjectURL(url), 1000);
        toast('Файл .portline сохранён. Передай его друзьям для подключения.');
    } catch (e) { toast(e.message); }
});

'use strict';
const token = document.querySelector('meta[name="app-token"]').content;
const $ = id => document.getElementById(id);
const panels = [...document.querySelectorAll('[data-panel]')];
const navItems = [...document.querySelectorAll('[data-goto]')];
const protocolOptions = [...document.querySelectorAll('[data-protocol]')];
const hints = [
    { micro: 'ПОДСКАЗКА', title: 'Сначала доступ по SSH', text: 'Понадобятся адрес VPS, логин и пароль или путь к приватному ключу.', footer: 'Подключение по SSH' },
    { micro: 'ПОДСКАЗКА', title: 'TCP или UDP', text: 'VLESS + REALITY использует TCP, Hysteria 2 — UDP. Проверь занятость порта до установки.', footer: 'Проверка порта доступна здесь' },
    { micro: 'ПОДСКАЗКА', title: 'Следи за журналом', text: 'Установка проходит по SSH. Сначала создаётся конфигурация, затем запускается служба systemd.', footer: 'Служба запускается на VPS' },
    { micro: 'ПОДСКАЗКА', title: 'Последний шаг — HAPP', text: 'Импортируй конфигурацию, включи TUN и отдельно проверь внешний IP, DNS и IPv6.', footer: 'Импорт → TUN → проверка' }
];
let step = 1, selectedProtocol = 'vless', lastStatus = null, lastLink = '', revealed = false;
let pollTimer = null, happPollTimer = null, portPollTimer = null, toastTimer = null, requestInFlight = false;
let lastPortResult = null;
let statusFailures = 0;
let happDoneNotified = false;
function setStep(n) {
    step = n;
    panels.forEach(p => p.classList.toggle('visible', Number(p.dataset.panel) === n));
    navItems.forEach((el, i) => {
        el.classList.toggle('is-active', i + 1 === n);
        el.classList.toggle('is-done', i + 1 < n);
        el.disabled = i + 1 !== n && !(n === 2 && i === 0);
        el.setAttribute('aria-current', i + 1 === n ? 'step' : 'false');
    });
    const hint = hints[n - 1];
    $('tipMicro').textContent = hint.micro;
    $('tipTitle').textContent = hint.title;
    $('tipText').textContent = hint.text;
    $('tipFooter').textContent = hint.footer;
    document.querySelector('.guide-number').textContent = String(n).padStart(2, '0') + ' / 04';
    if (n === 4) {
        $('nodeStatus').className = 'status-pill live';
        $('nodeStatus').innerHTML = '<i></i> Настроен';
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
function updateSummary() { const host = $('host').value.trim(); $('nodeHost').textContent = host || '—'; $('nodeProtocol').textContent = selectedProtocol === 'vless' ? 'VLESS / REALITY' : 'Hysteria 2'; $('nodePort').textContent = $('vpnPort').value || '—'; }
function setProtocol(protocol) {
    if (selectedProtocol !== protocol)
        resetPortResult();
    selectedProtocol = protocol;
    protocolOptions.forEach(e => { const active = e.dataset.protocol === protocol; e.classList.toggle('selected', active); e.setAttribute('aria-pressed', String(active)); });
    $('sniBox').classList.toggle('hidden', protocol === 'hy2');
    $('portHint').textContent = protocol === 'hy2' ? 'UDP, по умолчанию 443' : 'TCP, по умолчанию 443';
    $('protocolNotice').textContent = protocol === 'vless'
        ? 'REALITY не требует собственного домена. Приложение установит Xray-core и настроит автозапуск через systemd.'
        : 'Hysteria 2 будет работать без домена с самоподписанным TLS-сертификатом и pinSHA256. Не все старые клиенты поддерживают закрепление сертификата. Сертификат действует 365 дней.';
    updateSummary();
}
$('auth').addEventListener('change', () => { $('passwordBox').classList.toggle('hidden', $('auth').value === 'key'); $('keyBox').classList.toggle('hidden', $('auth').value === 'password'); });
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
    const p = selectedProtocol === 'vless' ? 'VLESS + REALITY / TCP' : 'Hysteria 2 / UDP';
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
        lastLink = status.link || '';
        revealed = false;
        renderLink();
        setStep(4);
        toast('Сервер настроен. Сохрани ключ доступа.');
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
$('copyBtn').addEventListener('click', async () => { try {
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
$('saveBtn').addEventListener('click', () => { if (!lastLink)
    return; const blob = new Blob([lastLink + '\n'], { type: 'text/plain;charset=utf-8' }); const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = `portline-${selectedProtocol}-${$('host').value.trim()}.txt`; a.click(); setTimeout(() => URL.revokeObjectURL(a.href), 3000); toast('Файл с ключом сохранён. Храни его в безопасном месте.'); });
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
setProtocol('vless');
setStep(1);
// Keep the desktop process alive while its GUI is open, but don't poll a running deployment twice.
setInterval(() => { if (!pollTimer)
    api('/api/status').catch(() => { }); }, 7000);

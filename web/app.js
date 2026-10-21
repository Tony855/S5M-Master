const { createApp, ref, reactive, onMounted, computed, watch } = Vue;
const { ElMessage, ElMessageBox } = ElementPlus;
const TOKEN_KEY = 's5m_next_token';

function useApi(tokenRef, onUnauth) {
  const base = '/api/v1';
  async function call(path, opts = {}) {
    const headers = Object.assign({}, opts.headers || {});
    if (opts.body !== undefined) headers['Content-Type'] = 'application/json';
    if (tokenRef.value) headers['Authorization'] = 'Bearer ' + tokenRef.value;
    const res = await fetch(base + path, Object.assign({}, opts, { headers }));
    if (res.status === 401) { onUnauth(); throw new Error('登录已失效'); }
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.error || ('HTTP ' + res.status));
    return data;
  }
  return { get: p => call(p), post: (p, b) => call(p, { method: 'POST', body: JSON.stringify(b || {}) }), put: (p, b) => call(p, { method: 'PUT', body: JSON.stringify(b || {}) }), del: p => call(p, { method: 'DELETE' }) };
}

const App = {
  setup() {
    const token = ref(localStorage.getItem(TOKEN_KEY) || '');
    const user  = ref(null);
    const page  = ref('dashboard');
    const api = useApi(token, () => logout(true));

    const loginForm = reactive({ username: 'admin', password: '' });
    const loginLoading = ref(false);

    async function doLogin() {
      if (!loginForm.username || !loginForm.password) return ElMessage.warning('请输入用户名和密码');
      loginLoading.value = true;
      try {
        const r = await fetch('/api/v1/auth/login', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(loginForm) });
        const d = await r.json().catch(() => ({}));
        if (!r.ok) throw new Error(d.error || '登录失败');
        token.value = d.token; user.value = d.user;
        localStorage.setItem(TOKEN_KEY, d.token);
        ElMessage.success('欢迎回来，' + d.user.username);
        await refreshAll();
      } catch (e) { ElMessage.error(e.message); }
      finally { loginLoading.value = false; }
    }

    function logout(silent) { token.value = ''; user.value = null; localStorage.removeItem(TOKEN_KEY); if (!silent) ElMessage.success('已退出'); }
    async function loadMe() { try { user.value = await api.get('/auth/me'); return true; } catch { return false; } }

    const overview = ref({ mihomo: {}, proxy_total: 0, proxy_enabled: 0 });
    async function loadOverview() { try { const res = await api.get('/monitor/overview'); overview.value = res || { mihomo: {}, proxy_total: 0, proxy_enabled: 0 }; } catch (e) { console.warn(e); } }

    const settings = ref({ tun_enable: false });
    async function loadSettings() { try { const res = await api.get('/settings'); settings.value.tun_enable = res.tun_enable === 'true'; } catch (e) { console.warn(e); } }
    async function saveSettings() { try { await api.put('/settings', { tun_enable: settings.value.tun_enable ? 'true' : 'false' }); ElMessage.success('设置已保存，请点击发布生效'); await loadPreview(); } catch (e) { ElMessage.error(e.message); } }

    const proxies = ref([]);
    const proxyDialog = ref(false);
    const proxySaving = ref(false);
    const proxyForm = reactive({ id: 0, name: '', mode: 'proxy', type: 'vless', server: '', port: 443, source_cidr: '0.0.0.0/0', enabled: true, extraText: '{}' });

    function getModeLabel(mode) { const map = { proxy: '代理模式', direct: '直连模式', reject: '拦截模式', china: '回国模式', game: '游戏模式' }; return map[mode] || mode; }
    async function loadProxies() { try { proxies.value = (await api.get('/proxies')) || []; } catch (e) { ElMessage.error(e.message); } }

    function openCreate() { Object.assign(proxyForm, { id: 0, name: '', mode: 'proxy', type: 'vless', server: '', port: 443, source_cidr: '0.0.0.0/0', enabled: true, extraText: '{}' }); proxyDialog.value = true; }
    function openEdit(row) { Object.assign(proxyForm, { id: row.id, name: row.name, mode: row.mode, type: row.type, server: row.server, port: row.port, source_cidr: row.source_cidr, enabled: row.enabled, extraText: JSON.stringify(row.extra || {}, null, 2) }); proxyDialog.value = true; }
    
    async function saveProxy() {
      let extra = {};
      if (['proxy', 'china', 'game'].includes(proxyForm.mode)) { try { extra = JSON.parse(proxyForm.extraText || '{}'); } catch { return ElMessage.error('扩展参数不是合法 JSON'); } }
      const body = { name: proxyForm.name, mode: proxyForm.mode, type: proxyForm.type, server: proxyForm.server, port: Number(proxyForm.port), source_cidr: proxyForm.source_cidr, enabled: proxyForm.enabled, extra };
      proxySaving.value = true;
      try {
        if (proxyForm.id) await api.put('/proxies/' + proxyForm.id, body); else await api.post('/proxies', body);
        ElMessage.success('已保存'); proxyDialog.value = false; await loadProxies(); await loadOverview();
      } catch (e) { ElMessage.error(e.message); } finally { proxySaving.value = false; }
    }
    
    async function removeProxy(row) { try { await ElMessageBox.confirm('确认删除节点 "' + row.name + '" ?', '提示', { type: 'warning' }); await api.del('/proxies/' + row.id); ElMessage.success('已删除'); await loadProxies(); await loadOverview(); } catch (e) { if (e && e !== 'cancel') ElMessage.error(e.message || '删除失败'); } }

    const importDialog = ref(false);
    const importContent = ref('');
    const importing = ref(false);
    function handleFileUpload(file) { const reader = new FileReader(); reader.onload = (e) => { importContent.value = e.target.result; ElMessage.success('文件内容已读取，请点击确认导入'); }; reader.readAsText(file.raw); }
    async function doImport() {
      if (!importContent.value.trim()) return ElMessage.warning('请粘贴节点链接');
      importing.value = true;
      try {
        const r = await api.post('/proxies/import', { content: importContent.value });
        if (r.fail > 0) { ElMessageBox.alert(r.message, '导入警告', { type: 'warning' }); }
        else { ElMessage.success('导入完成：成功 ' + r.success + ' 个'); }
        importDialog.value = false; importContent.value = ''; await loadProxies(); await loadOverview();
      } catch (e) { ElMessage.error(e.message); } finally { importing.value = false; }
    }

    const yamlText = ref('');
    const versions = ref([]);
    const publishing = ref(false);
    const previewing = ref(false);
    const updating = ref(false);

    async function loadPreview() { previewing.value = true; try { const r = await api.get('/config/preview'); yamlText.value = r.yaml || ''; } catch (e) { ElMessage.error(e.message); } finally { previewing.value = false; } }
    async function loadVersions() { try { versions.value = (await api.get('/config/versions')) || []; } catch (e) { console.warn(e); } }
    async function publish() { publishing.value = true; try { const r = await api.post('/config/publish', {}); if (r.ok) ElMessage.success('发布成功 · 版本 v' + r.version.version); else ElMessage.error(r.message || '发布失败'); await loadVersions(); } catch (e) { ElMessage.error(e.message); } finally { publishing.value = false; } }
    async function rollback(row) { try { await ElMessageBox.confirm('确认回滚到 v' + row.version + ' ?', '提示', { type: 'warning' }); const r = await api.post('/config/rollback', { version: row.version }); if (r.ok) ElMessage.success('回滚成功'); else ElMessage.error(r.message || '回滚失败'); await loadPreview(); await loadVersions(); } catch (e) { if (e && e !== 'cancel') ElMessage.error(e.message || '回滚失败'); } }

    const pwdForm = reactive({ old: '', new: '', confirm: '' });
    async function changePwd() {
      if (pwdForm.new.length < 6) return ElMessage.warning('新密码至少 6 位');
      if (pwdForm.new !== pwdForm.confirm) return ElMessage.warning('两次输入不一致');
      try { await api.put('/auth/password', { old: pwdForm.old, new: pwdForm.new }); ElMessage.success('密码已更新'); pwdForm.old = pwdForm.new = pwdForm.confirm = ''; } catch (e) { ElMessage.error(e.message); }
    }

    async function updateMihomo() {
      updating.value = true;
      try { const r = await api.post('/mihomo/update'); if (r.status === 'latest') ElMessage.info(r.message); else ElMessage.success(r.message); await loadOverview(); } catch (e) { ElMessage.error(e.message); } finally { updating.value = false; }
    }

    function formatTime(timeStr) {
      if (!timeStr) return ''; const date = new Date(timeStr); if (isNaN(date.getTime())) return timeStr;
      return date.getFullYear() + '-' + String(date.getMonth() + 1).padStart(2, '0') + '-' + String(date.getDate()).padStart(2, '0') + ' ' + String(date.getHours()).padStart(2, '0') + ':' + String(date.getMinutes()).padStart(2, '0') + ':' + String(date.getSeconds()).padStart(2, '0');
    }

    
    const logText = ref('');
    const logBox = ref(null);
    let logTimer = null;

    async function loadLogs() {
      try {
        const r = await api.get('/logs');
        logText.value = r.logs || '';
        // 自动滚动到底部
        if (logBox.value) {
          setTimeout(() => { logBox.value.scrollTop = logBox.value.scrollHeight; }, 100);
        }
      } catch (e) { console.warn('获取日志失败', e); }
    }

    
    const traffic = ref({ up: 0, down: 0, conns: 0 });
    let trafficTimer = null;

    function formatSpeed(bytes) {
      if (!bytes) return '0 B/s';
      const k = 1024;
      const sizes = ['B/s', 'KB/s', 'MB/s', 'GB/s'];
      const i = Math.floor(Math.log(bytes) / Math.log(k));
      return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }

    async function loadTraffic() {
      try {
        const res = await api.get('/monitor/traffic');
        traffic.value = res;
      } catch (e) {}
    }

    async function refreshAll() { await Promise.all([loadOverview(), loadProxies(), loadPreview(), loadVersions(), loadSettings()]); }
    onMounted(async () => { if (token.value) { const ok = await loadMe(); if (ok) await refreshAll(); } });

    watch(page, (newVal) => {
      if (newVal === 'logs') {
        loadLogs();
        logTimer = setInterval(loadLogs, 3000);
      } else {
        if (logTimer) { clearInterval(logTimer); logTimer = null; }
      }
    });
    
    const menuTitle = computed(() => ({ dashboard: '仪表盘', proxies: '代理规则', config: '配置管理', settings: '系统设置' }[page.value] || ''));

    return {
      token, user, page, loginForm, loginLoading, doLogin, logout,
      overview, proxies, proxyDialog, proxySaving, proxyForm, getModeLabel,
      openCreate, openEdit, saveProxy, removeProxy,
      importDialog, importContent, importing, handleFileUpload, doImport,
      yamlText, versions, publishing, previewing, loadPreview, loadVersions, publish, rollback,
      pwdForm, changePwd, menuTitle, settings, saveSettings, updating, updateMihomo, formatTime, logText, loadLogs, logBox
    };
  }
};

const app = createApp(App);
app.config.errorHandler = (err, instance, info) => { console.error(err); alert('Vue 渲染出错: ' + err.message); };
app.use(ElementPlus);
if (typeof ElementPlusIconsVue !== 'undefined') { for (const [k, v] of Object.entries(ElementPlusIconsVue)) app.component(k, v); }
app.mount('#app');

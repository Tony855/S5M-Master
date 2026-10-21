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
  return {
    get: p => call(p),
    post: (p, b) => call(p, { method: 'POST', body: JSON.stringify(b || {}) }),
    put:  (p, b) => call(p, { method: 'PUT',  body: JSON.stringify(b || {}) }),
    del:  p => call(p, { method: 'DELETE' }),
  };
}

const App = {
  setup() {
    const token = ref(localStorage.getItem(TOKEN_KEY) || '');
    const user  = ref(null);
    const page  = ref('dashboard');
    const api = useApi(token, () => logout(true));

    const loginForm = reactive({ username: 'admin', password: '' });
    const loginLoading = ref(false);

    const overview = ref({ mihomo: {}, proxy_total: 0, proxy_enabled: 0 });
    const traffic = ref({ up: 0, down: 0, conns: 0 });
    const trafficTimer = ref(null);
    const settings = ref({ tun_enable: false });
    const proxies = ref([]);
    const yamlText = ref('');
    const versions = ref([]);
    const publishing = ref(false);
    const previewing = ref(false);
    const updating = ref(false);
    
    const logText = ref('');
    const logBox = ref(null);
    const logTimer = ref(null);

    async function doLogin() {
      if (!loginForm.username || !loginForm.password) return ElMessage.warning('请输入用户名和密码');
      loginLoading.value = true;
      try {
        const r = await fetch('/api/v1/auth/login', {
          method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(loginForm)
        });
        const d = await r.json().catch(() => ({}));
        if (!r.ok) throw new Error(d.error || '登录失败');
        token.value = d.token; user.value = d.user;
        localStorage.setItem(TOKEN_KEY, d.token);
        ElMessage.success('欢迎回来，' + d.user.username);
        await refreshAll();
      } catch (e) { ElMessage.error(e.message); }
      finally { loginLoading.value = false; }
    }

    function logout(silent) {
      token.value = ''; user.value = null;
      localStorage.removeItem(TOKEN_KEY);
      if (!silent) ElMessage.success('已退出');
    }

    async function loadMe() {
      try { user.value = await api.get('/auth/me'); return true; } catch { return false; }
    }

    async function loadOverview() {
      try { overview.value = await api.get('/monitor/overview') || {}; } catch (e) { console.warn(e); }
    }

    async function loadTraffic() {
      try { traffic.value = await api.get('/monitor/traffic') || { up: 0, down: 0, conns: 0 }; } catch (e) {}
    }

    function formatSpeed(bytes) {
      if (!bytes) return '0 B/s';
      const k = 1024;
      const sizes = ['B/s', 'KB/s', 'MB/s', 'GB/s'];
      const i = Math.floor(Math.log(bytes) / Math.log(k));
      return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }

    async function loadSettings() {
      try {
        const res = await api.get('/settings');
        settings.value.tun_enable = res.tun_enable === 'true';
      } catch (e) { console.warn(e); }
    }

    async function saveSettings() {
      try {
        await api.put('/settings', { tun_enable: settings.value.tun_enable ? 'true' : 'false' });
        ElMessage.success('设置已保存，请点击发布生效');
        await loadPreview();
      } catch (e) { ElMessage.error(e.message); }
    }

    async function loadProxies() {
      try { proxies.value = await api.get('/proxies') || []; } catch (e) { console.warn(e); }
    }

    const proxyDialog = ref(false);
    const proxySaving = ref(false);
    const proxyForm = reactive({ id: 0, name: '', mode: 'proxy', type: 'vless', server: '', port: 443, source_cidr: '0.0.0.0/0', enabled: true, extraText: '{}' });

    function getModeLabel(mode) {
      const map = { proxy: '代理模式', direct: '直连模式', reject: '拦截模式', china: '回国模式', game: '游戏模式' };
      return map[mode] || mode;
    }

    function openCreate() {
      Object.assign(proxyForm, { id: 0, name: '', mode: 'proxy', type: 'vless', server: '', port: 443, source_cidr: '0.0.0.0/0', enabled: true, extraText: '{}' });
      proxyDialog.value = true;
    }

    function openEdit(row) {
      Object.assign(proxyForm, {
        id: row.id, name: row.name, mode: row.mode, type: row.type, server: row.server,
        port: row.port, source_cidr: row.source_cidr, enabled: row.enabled,
        extraText: JSON.stringify(row.extra || {}, null, 2)
      });
      proxyDialog.value = true;
    }

    async function saveProxy() {
      let extra = {};
      if (['proxy', 'china', 'game'].includes(proxyForm.mode)) {
        try { extra = JSON.parse(proxyForm.extraText || '{}'); }
        catch { return ElMessage.error('扩展参数不是合法 JSON'); }
      }
      const body = { 
        name: proxyForm.name, mode: proxyForm.mode, type: proxyForm.type, 
        server: proxyForm.server, port: Number(proxyForm.port), 
        source_cidr: proxyForm.source_cidr, enabled: proxyForm.enabled, extra 
      };
      proxySaving.value = true;
      try {
        if (proxyForm.id) await api.put('/proxies/' + proxyForm.id, body);
        else await api.post('/proxies', body);
        ElMessage.success('已保存');
        proxyDialog.value = false;
        await loadProxies(); await loadOverview();
      } catch (e) { ElMessage.error(e.message); }
      finally { proxySaving.value = false; }
    }

    async function removeProxy(row) {
      try {
        await ElMessageBox.confirm('确认删除节点 "' + row.name + '" ?', '提示', { type: 'warning' });
        await api.del('/proxies/' + row.id);
        ElMessage.success('已删除');
        await loadProxies(); await loadOverview();
      } catch (e) { if (e && e !== 'cancel') ElMessage.error(e.message || '删除失败'); }
    }

    const importDialog = ref(false);
    const importContent = ref('');
    const importing = ref(false);

    function handleFileUpload(file) {
      const reader = new FileReader();
      reader.onload = (e) => {
        importContent.value = e.target.result;
        ElMessage.success('文件内容已读取，请点击确认导入');
      };
      reader.readAsText(file.raw);
    }

    async function doImport() {
      if (!importContent.value.trim()) return ElMessage.warning('请粘贴节点链接');
      importing.value = true;
      try {
        const r = await api.post('/proxies/import', { content: importContent.value });
        if (r.fail > 0) ElMessageBox.alert(r.message, '导入警告', { type: 'warning' });
        else ElMessage.success('导入完成：成功 ' + r.success + ' 个');
        importDialog.value = false; importContent.value = ''; 
        await loadProxies(); await loadOverview();
      } catch (e) { ElMessage.error(e.message); } 
      finally { importing.value = false; }
    }

    async function loadPreview() {
      previewing.value = true;
      try { yamlText.value = (await api.get('/config/preview')).yaml || ''; }
      catch (e) { ElMessage.error(e.message); }
      finally { previewing.value = false; }
    }

    async function loadVersions() {
      try { versions.value = await api.get('/config/versions') || []; } catch (e) { console.warn(e); }
    }

    async function publish() {
      publishing.value = true;
      try {
        const r = await api.post('/config/publish', {});
        if (r.ok) ElMessage.success('发布成功 · 版本 v' + r.version.version);
        else ElMessage.error(r.message || '发布失败');
        await loadVersions();
      } catch (e) { ElMessage.error(e.message); }
      finally { publishing.value = false; }
    }

    async function rollback(row) {
      try {
        await ElMessageBox.confirm('确认回滚到 v' + row.version + ' ?', '提示', { type: 'warning' });
        const r = await api.post('/config/rollback', { version: row.version });
        if (r.ok) ElMessage.success('回滚成功');
        else ElMessage.error(r.message || '回滚失败');
        await loadPreview(); await loadVersions();
      } catch (e) { if (e && e !== 'cancel') ElMessage.error(e.message || '回滚失败'); }
    }

    const pwdForm = reactive({ old: '', new: '', confirm: '' });
    async function changePwd() {
      if (pwdForm.new.length < 6) return ElMessage.warning('新密码至少 6 位');
      if (pwdForm.new !== pwdForm.confirm) return ElMessage.warning('两次输入不一致');
      try {
        await api.put('/auth/password', { old: pwdForm.old, new: pwdForm.new });
        ElMessage.success('密码已更新');
        pwdForm.old = pwdForm.new = pwdForm.confirm = '';
      } catch (e) { ElMessage.error(e.message); }
    }

    async function updateMihomo() {
      updating.value = true;
      try {
        const r = await api.post('/mihomo/update');
        if (r.status === 'latest') ElMessage.info(r.message);
        else ElMessage.success(r.message);
        await loadOverview();
      } catch (e) { ElMessage.error(e.message); }
      finally { updating.value = false; }
    }

    async function loadLogs() {
      try {
        const r = await api.get('/logs');
        logText.value = r.logs || '';
        if (logBox.value) {
          setTimeout(() => { logBox.value.scrollTop = logBox.value.scrollHeight; }, 100);
        }
      } catch (e) { console.warn('获取日志失败', e); }
    }

    function formatTime(timeStr) {
      if (!timeStr) return '';
      const date = new Date(timeStr);
      if (isNaN(date.getTime())) return timeStr;
      const y = date.getFullYear();
      const m = String(date.getMonth() + 1).padStart(2, '0');
      const d = String(date.getDate()).padStart(2, '0');
      const h = String(date.getHours()).padStart(2, '0');
      const min = String(date.getMinutes()).padStart(2, '0');
      const s = String(date.getSeconds()).padStart(2, '0');
      return y + '-' + m + '-' + d + ' ' + h + ':' + min + ':' + s;
    }

    
    const themeIcon = ref(localStorage.getItem('theme') === 'dark' ? 'dark' : 'light');
    
    function toggleTheme() {
      if (themeIcon.value === 'dark') {
        document.body.classList.remove('dark');
        themeIcon.value = 'light';
        localStorage.setItem('theme', 'light');
      } else {
        document.body.classList.add('dark');
        themeIcon.value = 'dark';
        localStorage.setItem('theme', 'dark');
      }
    }

    function initTheme() {
      if (localStorage.getItem('theme') === 'dark') {
        document.body.classList.add('dark');
        themeIcon.value = 'dark';
      }
    }

    
    async function downloadBackup() {
      try {
        const res = await fetch('/api/v1/backup?token=' + token.value);
        if (!res.ok) throw new Error('下载失败');
        const blob = await res.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 's5m_backup_' + new Date().getTime() + '.db';
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        window.URL.revokeObjectURL(url);
        ElMessage.success('备份文件已开始下载');
      } catch (e) {
        ElMessage.error('下载失败，请重试');
      }
    }
    
    async function handleRestoreUpload(file) {
      try {
        await ElMessageBox.confirm('警告：恢复数据库将覆盖当前所有节点和设置！确认继续吗？', '危险操作', { type: 'error' });
        const formData = new FormData();
        formData.append('file', file.raw);
        const res = await fetch('/api/v1/restore?token=' + token.value, {
          method: 'POST',
          headers: { 'Authorization': 'Bearer ' + token.value },
          body: formData
        });
        const data = await res.json();
        if (res.ok) ElMessage.success(data.message);
        else throw new Error(data.error);
      } catch (e) {
        if (e !== 'cancel') ElMessage.error(e.message || '恢复失败');
      }
    }

    async function refreshAll() {
      await Promise.all([loadOverview(), loadProxies(), loadPreview(), loadVersions(), loadSettings(), loadTraffic()]);
    }

    onMounted(async () => {
      initTheme();
      if (token.value) {
        const ok = await loadMe();
        if (ok) {
          await refreshAll();
          trafficTimer.value = setInterval(loadTraffic, 2000);
        }
      }
    });

    watch(page, (newVal) => {
      if (newVal === 'logs') {
        loadLogs();
        logTimer.value = setInterval(loadLogs, 3000);
      } else {
        if (logTimer.value) { clearInterval(logTimer.value); logTimer.value = null; }
      }
    });

    const menuTitle = computed(() => ({
      dashboard: '仪表盘', proxies: '代理规则', config: '配置管理', logs: '系统日志', settings: '系统设置'
    }[page.value] || ''));

    return {
      token, user, page, loginForm, loginLoading, doLogin, logout,
      overview, traffic, proxies, proxyDialog, proxySaving, proxyForm, getModeLabel,
      openCreate, openEdit, saveProxy, removeProxy,
      importDialog, importContent, importing, handleFileUpload, doImport,
      yamlText, versions, publishing, previewing, loadPreview, loadVersions, publish, rollback,
      pwdForm, changePwd, menuTitle, settings, saveSettings, updating, updateMihomo, formatTime,
      logText, logBox, loadLogs, formatSpeed, themeIcon, toggleTheme, downloadBackup, handleRestoreUpload
    };
  }
};

const app = createApp(App);
app.use(ElementPlus);
if (typeof ElementPlusIconsVue !== 'undefined') { 
  for (const [k, v] of Object.entries(ElementPlusIconsVue)) app.component(k, v); 
}
app.mount('#app');

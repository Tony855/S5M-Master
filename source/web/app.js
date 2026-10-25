const { createApp, ref, reactive, onMounted, onUnmounted, computed } = Vue;

createApp({
  setup() {
    const page = ref('dashboard');
    const token = ref(localStorage.getItem('s5m_next_token') || '');
    const loginUser = ref('admin');
    const loginPass = ref('');
    const loggingIn = ref(false);
    const currentUser = ref(localStorage.getItem('s5m_next_user') || '');
    const pwdDialog = ref(false);
    const pwdSaving = ref(false);
    const pwdForm = reactive({ old: '', new: '', confirm: '' });

    const overview = ref({});
    const traffic = ref({ up: 0, down: 0, conns: 0 });
    let overviewTimer = null;
    let instanceRefreshTimer = null;
    const proxies = ref([]);
    const loadingProxies = ref(false);

    const newMachineCode = ref('');
    const generatedToken = ref('');
    const generating = ref(false);
    const agentEntries = ref([]);
    const agentLoadError = ref('');
    const agentLoading = ref(false);
    const agentSearch = ref('');
    const agentStatusFilter = ref('all');
    const filteredAgentEntries = computed(() => {
      const query = String(agentSearch.value || '').trim().toLowerCase();
      return agentEntries.value.filter(item => {
        const matchesQuery = !query || [item.code, item.hostname, item.os, item.arch].some(value => String(value || '').toLowerCase().includes(query));
        const matchesStatus = agentStatusFilter.value === 'all'
          || (agentStatusFilter.value === 'online' && item.online)
          || (agentStatusFilter.value === 'offline' && !item.online)
          || (agentStatusFilter.value === 'docker' && item.runtimeReported && item.dockerAvailable);
        return matchesQuery && matchesStatus;
      });
    });
    const routerOSAgentEntries = computed(() => agentEntries.value.filter(item => item.os === 'routeros'));
    const dockerAgentEntries = computed(() => agentEntries.value.filter(item => item.os !== 'routeros'));
    const dockerMachineCode = ref('');
    const dockerLoading = ref(false);
    const routerosLoading = ref(false);
    const routerosContainers = ref([]);
    const routerosStatus = ref('');
    const dockerContainers = ref([]);
    const selectedDockerIDs = ref([]);
    const bulkDockerProgress = ref('');
    const dockerStatus = ref('');
    const dockerOutput = ref('');
    const dockerOutputVisible = ref(false);
    const containerTasks = ref([]);
    const containerTasksLoading = ref(false);
    const containerTaskSearch = ref('');
    const containerTaskStatusFilter = ref('all');
    const containerTaskMachineFilter = ref('');
    const containerTaskStartDate = ref('');
    const containerTaskEndDate = ref('');
    const selectedFailedContainerTasks = ref([]);
    const bulkRetryLoading = ref(false);
    const containerTaskPage = ref(1);
    const containerTaskTotal = ref(0);
    const containerTaskMachineOptions = computed(() => [...new Set(containerTasks.value.map(t => t.machine_code).filter(Boolean))].sort());
    const containerTaskDuration = (task) => {
      if (!task.claimed_at || !task.finished_at) return '—';
      const elapsed = Date.parse(task.finished_at) - Date.parse(task.claimed_at);
      if (!Number.isFinite(elapsed) || elapsed < 0) return '—';
      return elapsed < 1000 ? '<1 秒' : (elapsed < 60000 ? Math.round(elapsed / 1000) + ' 秒' : (elapsed / 60000).toFixed(1) + ' 分钟');
    };
    const filteredContainerTasks = computed(() => {
      const query = String(containerTaskSearch.value || '').trim().toLowerCase();
      return containerTasks.value.filter(task => {
        const matchesQuery = !query || [task.id, task.machine_code, task.action].some(value => String(value == null ? '' : value).toLowerCase().includes(query));
        const matchesStatus = containerTaskStatusFilter.value === 'all' || task.status === containerTaskStatusFilter.value;
        const matchesMachine = !containerTaskMachineFilter.value || task.machine_code === containerTaskMachineFilter.value;
        return matchesQuery && matchesStatus && matchesMachine;
      });
    });

    const subUrl = ref('');
    const globalConfigYaml = ref('');
    const savingGlobalConfig = ref(false);
    const publishingGlobalConfig = ref(false);
    const loadingConfigVersions = ref(false);
    const configVersions = ref([]);
    const retryingNodeConfigSync = ref(false);
    const configYaml = ref('');
    const selectedConfigNode = ref('');
    const savingConfig = ref(false);
    const publishing = ref(false);
    const updatingKernel = ref(false);
    const kernelUpdateDialog = ref(false);
    const kernelUpdateMachineCode = ref('');
    const kernelUpdateVersion = ref('v1.19.31');
    const kernelUpdateSHA256 = ref('');
    const queueingKernelUpdate = ref(false);
    const systemLogs = ref('');
    const loadingSystemLogs = ref(false);
    const restoringBackup = ref(false);

    const proxyDialog = ref(false);
    const proxyForm = reactive({ id: 0, name: '', mode: 'proxy', type: 'socks5', server: '', port: 1080, machine_code: '', source_cidr: '0.0.0.0/0', enabled: true, username: '', password: '', extra_json: '{}' });
    const savingProxy = ref(false);

    const showImport = ref(false);
    const importTab = ref('text');
    const importText = ref('');
    const importing = ref(false);
    const importMachineCode = ref('');

    // ======== 分组管理逻辑 ========
    const activeGroup = ref('ALL');
    
    // 获取所有存在的机器码（从已注册的 Agent 和 现有代理节点中提取）
    // 绑定下拉框保留所有已注册 Agent；代理分组只显示当前确实有代理的机器码。
    const availableMachineCodes = computed(() => {
      const set = new Set();
      agentEntries.value.forEach(a => { if (a.code) set.add(a.code); });
      proxies.value.forEach(p => { if (p.machine_code) set.add(p.machine_code); });
      return Array.from(set).sort();
    });
    const proxyGroupCodes = computed(() => Array.from(new Set(
      proxies.value.map(p => p.machine_code).filter(Boolean)
    )).sort());
    const agentEntryByCode = computed(() => {
      const map = {};
      agentEntries.value.forEach(item => { if (item && item.code) map[item.code] = item; });
      return map;
    });
    const machineCodeOptionLabel = (code) => {
      const item = agentEntryByCode.value[code];
      if (!item) return code + '（未注册/待核对）';
      return code + (item.hostname ? ' · ' + item.hostname : '') + (item.online ? '（在线）' : '（离线）');
    };
    const machineCodeStatus = (code) => {
      const item = agentEntryByCode.value[code];
      if (!item) return '未找到已授权的节点实例';
      return (item.online ? '在线' : '离线') + (item.hostname ? ' · ' + item.hostname : '');
    };
    const proxyCountForMachine = (code) => proxies.value.filter(p => p.machine_code === code).length;
    // Do not infer whether a dedicated YAML exists from the proxy count.
    // The node-config GET endpoint may initialize a default YAML on first access.
    const nodeConfigState = () => '可在配置管理中查看/编辑';
    const openProxiesForMachine = (code) => {
      activeGroup.value = code;
      switchPage('proxies');
    };
    const openNodeConfigForMachine = async (code) => {
      selectedConfigNode.value = code;
      switchPage('config');
      await loadNodeConfig();
    };

    const filteredProxies = computed(() => {
      if (activeGroup.value === 'ALL') return proxies.value;
      if (activeGroup.value === 'UNBOUND') return proxies.value.filter(p => !p.machine_code);
      return proxies.value.filter(p => p.machine_code === activeGroup.value);
    });

    const getUnboundCount = () => proxies.value.filter(p => !p.machine_code).length;
    const getMachineCount = (code) => proxies.value.filter(p => p.machine_code === code).length;
    // =============================

    const fmtBytes = (n) => {
      n = Number(n) || 0;
      if (n < 1024) return n + ' B';
      const units = ['KB','MB','GB','TB'];
      let i = -1;
      do { n /= 1024; i++; } while (n >= 1024 && i < units.length - 1);
      return n.toFixed(2) + ' ' + units[i];
    };

    const fmtSpeed = (n) => {
      n = Math.max(0, Number(n) || 0);
      if (n < 1024) return n.toFixed(0) + ' B/s';
      if (n < 1024 * 1024) return (n / 1024).toFixed(2) + ' KB/s';
      if (n < 1024 * 1024 * 1024) return (n / (1024 * 1024)).toFixed(2) + ' MB/s';
      return (n / (1024 * 1024 * 1024)).toFixed(2) + ' GB/s';
    };

    const authHeaders = (extra) => Object.assign({ 'Authorization': 'Bearer ' + token.value }, extra || {});
    const showMsg = (msg, type) => { ElementPlus.ElMessage({ message: msg, type: type || 'info', duration: 3000 }); };

    async function api(path, opts) {
      opts = opts || {};
      opts.headers = authHeaders(opts.headers || {});
      const res = await fetch(path, opts);
      if (res.status === 401) { logout(); throw new Error('登录已失效'); }
      return res;
    }

    async function parseErr(res) {
      try { const d = await res.json(); return d.error || d.message || ('HTTP ' + res.status); }
      catch (e) { return 'HTTP ' + res.status; }
    }

    const logout = () => {
      localStorage.removeItem('s5m_next_token');
      localStorage.removeItem('s5m_next_user');
      token.value = ''; currentUser.value = ''; loginPass.value = '';
    };

    const handleLoginEnter = (event) => {
      // Chinese/Japanese IMEs emit Enter to commit the composition. Never submit while composing.
      if (event && (event.isComposing || event.keyCode === 229 || event.which === 229)) return;
      doLogin();
    };

    const resetPwdForm = () => { pwdForm.old = ''; pwdForm.new = ''; pwdForm.confirm = ''; };
    const handleUserMenu = (command) => {
      if (command === 'password') { resetPwdForm(); pwdDialog.value = true; }
      if (command === 'logout') logout();
    };
    const changeAdminPassword = async () => {
      if (!pwdForm.old) return showMsg('请输入当前密码', 'warning');
      if (pwdForm.new.length < 6) return showMsg('新密码至少 6 位', 'warning');
      if (pwdForm.new !== pwdForm.confirm) return showMsg('两次输入的新密码不一致', 'warning');
      if (pwdForm.old === pwdForm.new) return showMsg('新密码不能与当前密码相同', 'warning');
      pwdSaving.value = true;
      try {
        const res = await api('/api/v1/auth/password', { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ old: pwdForm.old, new: pwdForm.new }) });
        const data = await res.json().catch(() => ({}));
        if (!res.ok) throw new Error(data.error || data.message || ('HTTP ' + res.status));
        showMsg(data.message || '管理员密码已更新', 'success');
        pwdDialog.value = false;
        resetPwdForm();
      } catch (e) { showMsg(e.message || '修改密码失败', 'error'); }
      finally { pwdSaving.value = false; }
    };

    const doLogin = async () => {
      if (!loginUser.value || !loginPass.value) return showMsg('请输入账号密码', 'warning');
      loggingIn.value = true;
      try {
        const res = await fetch('/api/v1/auth/login', {
          method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ username: loginUser.value, password: loginPass.value })
        });
        const data = await res.json().catch(() => ({}));
        if (res.ok && data.token) {
          localStorage.setItem('s5m_next_token', data.token);
          localStorage.setItem('s5m_next_user', data.user.username || loginUser.value);
          token.value = data.token; currentUser.value = data.user.username || loginUser.value;
          loginPass.value = ''; switchPage('dashboard');
        } else { showMsg(data.error || data.message || '账号或密码错误', 'error'); }
      } catch (e) { showMsg('网络错误', 'error'); }
      loggingIn.value = false;
    };

    const PAGES = ['dashboard','proxies','instances','docker','routeros-containers','config','system'];
    const switchPage = (v) => {
      if (!PAGES.includes(v)) v = 'dashboard';
      page.value = v;
      if (v === 'dashboard') loadOverview();
      if (v === 'proxies') { loadProxies(); loadAgentsData(); }
      if (v === 'instances') loadAgentsData();
      if (v === 'docker') {
        if (!dockerAgentEntries.value.some(item => item.code === dockerMachineCode.value)) dockerMachineCode.value = '';
        loadAgentsData(); loadContainerTasks();
      }
      if (v === 'routeros-containers') {
        if (!routerOSAgentEntries.value.some(item => item.code === dockerMachineCode.value)) dockerMachineCode.value = '';
        loadAgentsData(); routerosContainers.value = []; routerosStatus.value = '';
      }
      if (v === 'config') { loadAgentsData(); loadSettings(); loadGlobalConfig(); loadConfigVersions(); }
      if (v === 'system') loadSystemLogs();
    };

    const loadOverview = async () => {
      try {
        const res = await api('/api/v1/monitor/overview?t=' + Date.now());
        if (res.ok) overview.value = await res.json() || {};
      } catch (e) { console.warn('读取仪表盘概览失败', e); }

      try {
        const res = await api('/api/v1/monitor/traffic?t=' + Date.now());
        if (res.ok) {
          const data = await res.json() || {};
          traffic.value = {
            up: Number(data.up) || 0,
            down: Number(data.down) || 0,
            conns: Number(data.conns) || 0
          };
        }
      } catch (e) { console.warn('读取实时流量失败', e); }
    };

    const updateKernel = async () => {
      try {
        await ElementPlus.ElMessageBox.confirm(
          '此操作只更新主控服务器上的 Mihomo 二进制文件，并会重启主控机的 mihomo 服务；不会更新各个 Agent 节点。更新期间主控代理流量可能中断，请确认已安排维护窗口。',
          '确认更新主控 Mihomo',
          { type: 'warning', confirmButtonText: '确认更新', cancelButtonText: '取消' }
        );
      } catch (_) {
        return;
      }
      updatingKernel.value = true;
      try {
        const res = await api('/api/v1/mihomo/update', { method: 'POST' });
        const d = await res.json().catch(() => ({}));
        if (res.ok) showMsg(d.message || '操作成功', d.status === 'latest' ? 'info' : 'success');
        else showMsg(d.error || '更新失败', 'error');
        await loadOverview();
      } catch (e) { showMsg(e.message || '网络错误', 'error'); }
      finally { updatingKernel.value = false; }
    };

    const loadSystemLogs = async () => {
      loadingSystemLogs.value = true;
      try {
        const res = await api('/api/v1/logs?t=' + Date.now());
        const data = await res.json().catch(() => ({}));
        if (!res.ok) throw new Error(data.error || data.message || '读取系统日志失败');
        systemLogs.value = data.logs || '';
      } catch (e) {
        showMsg(e.message || '读取系统日志失败', 'error');
      } finally {
        loadingSystemLogs.value = false;
      }
    };

    const downloadBackup = async () => {
      try {
        const res = await fetch('/api/v1/backup', { headers: authHeaders() });
        if (res.status === 401) { logout(); throw new Error('登录已失效'); }
        if (!res.ok) {
          const data = await res.json().catch(() => ({}));
          throw new Error(data.error || data.message || ('HTTP ' + res.status));
        }
        const blob = await res.blob();
        const objectUrl = URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = objectUrl;
        link.download = 's5m_backup.db';
        document.body.appendChild(link);
        link.click();
        link.remove();
        URL.revokeObjectURL(objectUrl);
        showMsg('数据库备份已开始下载', 'success');
      } catch (e) {
        showMsg(e.message || '下载备份失败', 'error');
      }
    };

    const restoreBackup = async (event) => {
      const file = event && event.target && event.target.files && event.target.files[0];
      if (!file) return;
      // Reset the input so the same file can be selected again after an error.
      event.target.value = '';
      if (file.size <= 0 || file.size > 128 * 1024 * 1024) {
        showMsg('备份文件为空或超过 128 MiB 限制', 'warning');
        return;
      }
      try {
        await ElementPlus.ElMessageBox.confirm(
          '恢复数据库会覆盖当前代理、节点、设置和任务数据。请先下载当前备份；恢复后需要重新登录。',
          '确认恢复数据库',
          { type: 'warning', confirmButtonText: '确认覆盖', cancelButtonText: '取消' }
        );
      } catch (_) {
        return;
      }
      restoringBackup.value = true;
      try {
        const form = new FormData();
        form.append('file', file, file.name);
        const res = await api('/api/v1/restore', { method: 'POST', body: form });
        const data = await res.json().catch(() => ({}));
        if (!res.ok) throw new Error(data.error || data.message || ('HTTP ' + res.status));
        showMsg(data.message || '数据库恢复请求已完成，请重新登录并检查数据', 'success');
        logout();
      } catch (e) {
        showMsg(e.message || '恢复数据库失败', 'error');
      } finally {
        restoringBackup.value = false;
      }
    };

    const loadProxies = async () => {
      loadingProxies.value = true;
      try {
        const res = await api('/api/v1/proxies?t=' + Date.now());
        if (res.ok) {
          const d = await res.json();
          proxies.value = Array.isArray(d) ? d : (d.data || d.proxies || []);
        }
      } catch (e) { console.warn(e); }
      finally {
        loadingProxies.value = false;
        // 删除分组最后一个代理后回到“全部”；Agent 注册记录不会被删除。
        if (activeGroup.value !== 'ALL' && activeGroup.value !== 'UNBOUND' &&
            !proxies.value.some(p => p.machine_code === activeGroup.value)) activeGroup.value = 'ALL';
      }
    };

    const openCreateProxy = () => {
      Object.assign(proxyForm, { id: 0, name: '', mode: 'proxy', type: 'socks5', server: '', port: 1080, machine_code: '', source_cidr: '0.0.0.0/0', enabled: true, username: '', password: '', extra_json: '{}' });
      // 如果当前正在看某个机器的分组，默认绑定该机器
      if (activeGroup.value !== 'ALL' && activeGroup.value !== 'UNBOUND') {
        proxyForm.machine_code = activeGroup.value;
      }
      proxyDialog.value = true;
    };

    const openEditProxy = (row) => {
      const extra = row.extra && typeof row.extra === 'object' && !Array.isArray(row.extra) ? row.extra : {};
      Object.assign(proxyForm, {
        id: row.id || 0, name: row.name || row.proxy_name || '', mode: row.mode || 'proxy',
        type: row.type || row.proxy_type || 'socks5',
        server: row.server || '', port: row.port || 1080, machine_code: row.machine_code || '',
        source_cidr: row.source_cidr || '0.0.0.0/0',
        enabled: row.enabled === true || row.enabled === 1,
        username: extra.username || '', password: extra.password || '',
        extra_json: JSON.stringify(extra, null, 2)
      });
      proxyDialog.value = true;
    };

    const saveProxy = async () => {
      if (!proxyForm.name || !proxyForm.server || !proxyForm.port) return showMsg('请填写名称/服务器/端口', 'warning');
      savingProxy.value = true;
      try {
        const isEdit = proxyForm.id > 0;
        const url = isEdit ? ('/api/v1/proxies/' + proxyForm.id) : '/api/v1/proxies';
        let extra;
        try {
          extra = JSON.parse(proxyForm.extra_json || '{}');
        } catch (_) {
          showMsg('高级参数 JSON 格式无效，请检查后再保存', 'warning');
          savingProxy.value = false;
          return;
        }
        if (!extra || typeof extra !== 'object' || Array.isArray(extra)) {
          showMsg('高级参数必须是 JSON 对象，例如 {"uuid":"..."}', 'warning');
          savingProxy.value = false;
          return;
        }
        // Non-empty credential fields override JSON; empty inputs never silently erase
        // existing credentials while editing unrelated properties.
        if (proxyForm.username) extra.username = proxyForm.username;
        if (proxyForm.password) extra.password = proxyForm.password;

        const res = await api(url, {
          method: isEdit ? 'PUT' : 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            name: proxyForm.name, mode: proxyForm.mode || 'proxy', type: proxyForm.type, server: proxyForm.server, port: proxyForm.port,
            machine_code: proxyForm.machine_code, source_cidr: proxyForm.source_cidr || '0.0.0.0/0',
            enabled: Boolean(proxyForm.enabled), extra: extra
          })
        });
        if (res.ok) {
          proxyDialog.value = false; loadProxies(); showMsg('保存成功', 'success');
        } else {
          const message = await parseErr(res);
          if (String(message).includes('同步失败') || String(message).includes('已保存') || String(message).includes('已更新')) {
            proxyDialog.value = false;
            await loadProxies();
            showMsg('代理数据已保存，但节点配置同步失败：' + message + '。请检查节点状态后重试同步。', 'warning');
          } else {
            showMsg(message, 'error');
          }
        }
      } catch (e) { showMsg(e.message || '网络错误', 'error'); }
      savingProxy.value = false;
    };

    const deleteProxy = async (row) => {
      if (!row.id) return showMsg('该节点无 id，无法删除', 'warning');
      if (!confirm('确定删除节点 "' + (row.name || row.proxy_name || row.id) + '" ？')) return;
      try {
        const res = await api('/api/v1/proxies/' + encodeURIComponent(row.id), { method: 'DELETE' });
        if (res.ok) {
          await loadProxies();
          showMsg('已删除', 'success');
          return;
        }
        const message = await parseErr(res);
        // Deletion is committed before the server regenerates authorized-node YAML.
        // Refresh the list on this partial-success path so the removed proxy doesn't linger.
        if (message.includes('代理已删除')) {
          await loadProxies();
          showMsg(message + '。请进入配置管理点击“立即重试同步所有节点”。', 'warning');
          return;
        }
        showMsg(message, 'error');
      } catch (e) {
        showMsg(e.message || '删除失败', 'error');
      }
    };

    const findProxyArray = (obj) => {
      if (Array.isArray(obj)) {
        if (obj.length > 0 && typeof obj[0] === 'object' && (obj[0].server || obj[0].address)) return obj;
        for (let item of obj) { const res = findProxyArray(item); if (res) return res; }
      } else if (obj !== null && typeof obj === 'object') {
        for (let key of ['proxies', 'nodes', 'servers', 'list', 'items', 'data']) {
          if (obj[key]) { const res = findProxyArray(obj[key]); if (res) return res; }
        }
        for (let key in obj) { if (Object.prototype.hasOwnProperty.call(obj, key)) { const res = findProxyArray(obj[key]); if (res) return res; } }
      }
      return null;
    };

    const handleFileUpload = (e) => {
      const file = e.target.files[0]; if (!file) return;
      const reader = new FileReader();
      reader.onload = (evt) => {
        const content = evt.target.result;
        if (file.name.endsWith('.json')) {
          try {
            const arr = findProxyArray(JSON.parse(content));
            if (!arr || !arr.length) throw new Error('找不到包含 server/address 的节点数组');
            const lines = arr.map(item => {
              const name = item.name || item.remark || item.proxy_name || '未命名';
              const type = item.type || item.protocol || 'socks5';
              const server = item.server || item.address || item.host || '';
              const port = item.port || 1080;
              return `${name} ${type} ${server} ${port}`;
            }).filter(line => line.split(' ')[2] !== ''); 
            if (!lines.length) throw new Error('解析出了节点但缺少有效字段');
            importText.value = lines.join('\n'); showMsg(`成功解析 ${lines.length} 条节点`, 'success');
          } catch (err) { showMsg('JSON 解析失败：' + err.message, 'error'); importText.value = ''; }
        } else {
          importText.value = content; showMsg('文件读取成功，请点击导入', 'success');
        }
      };
      reader.readAsText(file);
    };

    const parseProxyLine = (line) => {
      if (!line) return null;
      const urlRegex = /^([a-zA-Z0-9]+):\/\/(?:(.*?)@)?([^@]+)$/;
      const urlMatch = line.match(urlRegex);
      if (urlMatch) {
        let protocol = urlMatch[1].toLowerCase(); let authStr = urlMatch[2] || ''; let hostPort = urlMatch[3];
        let username = '', password = '';
        if (authStr) {
          const authParts = authStr.split(':');
          if (authParts.length >= 2) { username = authParts[0]; password = authParts.slice(1).join(':'); } else { username = authStr; }
        }
        if (protocol === 'socks') protocol = 'socks5';
        let host = ''; let port = 1080;
        if (hostPort.startsWith('[')) {
          const match6 = hostPort.match(/^\[([^\]]+)\](?::(\d+))?$/);
          if (match6) { host = match6[1]; port = parseInt(match6[2], 10) || 1080; }
        } else if (hostPort.split(':').length > 2) {
          const matchPort = hostPort.match(/(.+?):?(\d+)$/);
          if (matchPort) { host = matchPort[1]; port = parseInt(matchPort[2], 10); } else { host = hostPort; }
        } else {
          const parts = hostPort.split(':'); host = parts[0]; port = parseInt(parts[1], 10) || 1080;
        }
        const extra = {}; if (username) extra.username = username; if (password) extra.password = password;
        return { name: `${protocol}-${host}:${port}`, type: protocol, server: host, port: port, extra: Object.keys(extra).length > 0 ? extra : undefined };
      }
      const parts = line.split(/[\s,]+/);
      if (parts.length >= 4) return { name: parts[0], type: parts[1], server: parts[2], port: parseInt(parts[3], 10) || 1080 };
      if (line.includes(':') && !line.includes(' ')) {
        const parts = line.split(':'); if (parts.length === 2) return { name: 'socks5-' + line, type: 'socks5', server: parts[0], port: parseInt(parts[1], 10) };
      }
      return null;
    };

    const importProxies = async () => {
      const content = String(importText.value || '').trim();
      if (!content) return showMsg('请输入或上传代理链接', 'warning');
      if (importing.value) return;
      importing.value = true;
      try {
        // 后端 handleImportProxies 的请求结构是 { content: "多行文本" }。
        // 不发送前端自行解析的 { proxies: [...] }，避免接口结构不匹配。
        const res = await api('/api/v1/proxies/import', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ content })
        });
        const data = await res.json().catch(() => ({}));
        if (!res.ok) throw new Error(data.error || data.message || ('HTTP ' + res.status));
        const success = Number(data.success) || 0;
        const fail = Number(data.fail) || 0;
        if (data.sync_failed) {
          showMsg(`代理导入已完成：成功 ${success} 条，失败 ${fail} 条。${data.message || ''}。请进入配置管理点击“立即重试同步所有节点”。`, 'warning');
        } else if (success === 0) {
          showMsg(data.message || '没有成功导入节点，请检查格式和服务端日志', 'warning');
        } else if (fail > 0) {
          showMsg(`导入完成：成功 ${success} 条，失败 ${fail} 条。${data.message || ''}`, 'warning');
        } else {
          showMsg(`导入成功 ${success} 条`, 'success');
        }
        await loadProxies();
        if (success > 0) showImport.value = false;
      } catch (e) {
        showMsg(e.message || '导入失败', 'error');
      } finally {
        importing.value = false;
      }
    };

    const loadAgentsData = async () => {
      agentLoading.value = true;
      agentLoadError.value = '';
      try {
        const res = await api('/api/v1/agents?t=' + Date.now());
        if (!res.ok) {
          const detail = await res.text().catch(() => '');
          agentLoadError.value = '读取实例失败（HTTP ' + res.status + '）。请确认登录状态及主控 API。';
          console.error('读取实例失败', res.status, detail);
          agentEntries.value = []; return;
        }
        const data = await res.json();
        const now = Math.floor(Date.now() / 1000);
        let nodeByCode = {};
        try {
          const nodeRes = await api('/api/v1/container/nodes?t=' + Date.now());
          if (nodeRes.ok) {
            const nodeData = await nodeRes.json();
            (Array.isArray(nodeData.nodes) ? nodeData.nodes : []).forEach(node => {
              if (node && node.machine_code) nodeByCode[node.machine_code] = node;
            });
          }
        } catch (nodeError) {
          console.warn('读取节点运行状态失败，暂时使用注册心跳数据', nodeError);
        }
        const list = [];
        Object.keys(data || {}).forEach(code => {
          const item = data[code] || {};
          const node = nodeByCode[code] || {};
          const last = Number(item.last_seen) || 0;
          const online = typeof node.online === 'boolean' ? node.online : last > 0 && (now - last) < 90;
          list.push({
            code: code,
            tokenConfigured: item.token_configured === true,
            online: online,
            last_seen: last,
            hostname: node.hostname || '',
            os: node.os || '',
            arch: node.arch || '',
            runtimeReported: Object.prototype.hasOwnProperty.call(nodeByCode, code),
            dockerAvailable: node.docker_available === true,
            mihomoRunning: node.mihomo_running === true,
            mihomoVersion: node.mihomo_version || '',
            updated_at: node.updated_at || ''
          });
        });
        list.sort((a, b) => (b.last_seen || 0) - (a.last_seen || 0));
        agentEntries.value = list;
      } catch (e) { agentLoadError.value = '读取实例失败：网络连接异常，请检查主控服务和浏览器连接。'; console.error('读取实例失败', e); agentEntries.value = []; }
      finally { agentLoading.value = false; }
    };

    const generateAgentToken = async () => {
      if (!newMachineCode.value) return showMsg('请输入机器码', 'warning');
      generating.value = true;
      try {
        const res = await api('/api/v1/agents/generate', {
          method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ machine_code: newMachineCode.value })
        });
        const data = await res.json().catch(() => ({}));
        if (res.ok && data.token) {
          generatedToken.value = data.token; newMachineCode.value = ''; loadAgentsData();
        } else { showMsg(data.error || data.message || '生成失败', 'error'); }
      } catch (e) { showMsg(e.message || '网络错误', 'error'); }
      generating.value = false;
    };

    const openAgentKernelUpdate = (code) => {
      kernelUpdateMachineCode.value = String(code || '').trim();
      kernelUpdateVersion.value = 'v1.19.31';
      kernelUpdateSHA256.value = '';
      kernelUpdateDialog.value = Boolean(kernelUpdateMachineCode.value);
    };

    const queueAgentKernelUpdate = async () => {
      const machineCode = String(kernelUpdateMachineCode.value || '').trim();
      const version = String(kernelUpdateVersion.value || '').trim();
      const sha256 = String(kernelUpdateSHA256.value || '').trim().toLowerCase();
      if (!machineCode) return showMsg('请先选择目标 Agent', 'warning');
      if (!/^v\d+\.\d+\.\d+$/.test(version)) return showMsg('版本号格式无效，应为 v主版本.次版本.修订版本', 'warning');
      if (!/^[a-f0-9]{64}$/.test(sha256)) return showMsg('SHA-256 必须是 64 位十六进制字符串', 'warning');
      if (queueingKernelUpdate.value) return;
      try {
        await ElementPlus.ElMessageBox.confirm(
          '确认向 Agent ' + machineCode + ' 排队更新 Mihomo 到 ' + version + '？请确保版本与节点架构匹配，并已从官方 Release 核实 SHA-256。',
          '确认更新 Mihomo 内核',
          { type: 'warning', confirmButtonText: '确认排队', cancelButtonText: '取消' }
        );
      } catch (_) {
        return;
      }
      queueingKernelUpdate.value = true;
      try {
        const res = await api('/api/v1/agents/kernel-update', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ machine_code: machineCode, version, sha256 })
        });
        const data = await res.json().catch(() => ({}));
        if (!res.ok) throw new Error(data.error || data.message || ('HTTP ' + res.status));
        kernelUpdateDialog.value = false;
        showMsg(data.message || '更新命令已排队；Agent 在线时将执行', 'success');
      } catch (e) {
        showMsg(e.message || '排队更新失败', 'error');
      } finally {
        queueingKernelUpdate.value = false;
      }
    };

    const deleteAgent = async (code) => {
      if (!confirm('确定删除机器码 "' + code + '" 的 Token？')) return;
      try {
        const res = await api('/api/v1/agents?code=' + encodeURIComponent(code), { method: 'DELETE' });
        if (res.ok) { if (dockerMachineCode.value === code) { dockerMachineCode.value = ''; dockerContainers.value = []; dockerStatus.value = ''; } if (selectedConfigNode.value === code) { selectedConfigNode.value = ''; configYaml.value = ''; } await loadAgentsData(); showMsg('已撤销绑定；旧 Token 已失效，未完成任务已标记失败', 'success'); } else showMsg(await parseErr(res), 'error');
      } catch (e) { showMsg(e.message || '删除失败', 'error'); }
    };

    const dockerTask = async (action, params = {}) => {
      if (!dockerMachineCode.value) throw new Error('请先选择实例');
      if (!dockerAgentEntries.value.some(item => item.code === dockerMachineCode.value)) {
        dockerMachineCode.value = '';
        throw new Error('所选机器码不是可用的 Docker Agent，请重新选择实例');
      }
      const create = await api('/api/v1/container/tasks', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ machine_code: dockerMachineCode.value, action, params }) });
      const created = await create.json().catch(() => ({}));
      if (!create.ok || !created.id) throw new Error(created.error || '创建 Docker 任务失败');
      dockerStatus.value = '任务 #' + created.id + ' 已提交，等待实例 Agent 执行…';
      for (let i = 0; i < 20; i++) {
        await new Promise(resolve => setTimeout(resolve, 1000));
        const response = await api('/api/v1/container/tasks?limit=100&t=' + Date.now());
        const data = await response.json().catch(() => ({}));
        const task = (data.tasks || []).find(x => Number(x.id) === Number(created.id));
        if (task && (task.status === 'succeeded' || task.status === 'failed')) {
          await loadContainerTasks();
          if (task.status === 'failed') {
            const error = new Error(task.error || '实例执行失败');
            error.taskId = Number(created.id);
            error.taskStatus = 'failed';
            throw error;
          }
          dockerStatus.value = '任务 #' + created.id + ' 执行成功';
          const result = task.result && typeof task.result === 'object' ? task.result : { output: String(task.result || '') };
          return { ...result, task_id: Number(created.id) };
        }
      }
      const timeoutError = new Error('任务 #' + created.id + ' 在 20 秒内未返回最终状态；任务可能仍在执行，请到任务记录查询，不要直接重复提交');
      timeoutError.taskId = Number(created.id);
      timeoutError.taskStatus = 'unknown';
      throw timeoutError;
    };
    const taskStatusLabel = (status) => ({ pending: '等待执行', running: '执行中', succeeded: '成功', failed: '失败', cancelled: '已取消' }[status] || status || '未知');
    const taskStatusType = (status) => ({ pending: 'info', running: 'warning', succeeded: 'success', failed: 'danger', cancelled: 'info' }[status] || 'info');
    const loadContainerTasks = async (options = {}) => {
      const silent = options.silent === true;
      containerTasksLoading.value = true;
      try {
        const res = await api('/api/v1/container/tasks?limit=100&offset=' + ((containerTaskPage.value - 1) * 100) + '&t=' + Date.now());
        const data = await res.json().catch(() => ({}));
        if (!res.ok) throw new Error(data.error || '读取容器任务失败');
        containerTasks.value = Array.isArray(data.tasks) ? data.tasks : [];
        containerTaskTotal.value = Number.isFinite(Number(data.total)) ? Number(data.total) : containerTasks.value.length;
      } catch (e) {
        if (!silent) showMsg(e.message || '读取容器任务失败', 'error');
      } finally {
        containerTasksLoading.value = false;
      }
    };
    const isRetryableContainerTask = (task) => task.status === 'failed';
    const onContainerTaskSelectionChange = (rows) => { selectedFailedContainerTasks.value = rows.filter(task => task.status === 'failed'); };
    const retryFailedContainerTasks = async () => {
      const tasks = selectedFailedContainerTasks.value.slice();
      if (!tasks.length || bulkRetryLoading.value) return;
      try {
        await ElementPlus.ElMessageBox.confirm(
          `将为选中的 ${tasks.length} 个失败任务分别创建新任务，原任务记录会保留。重试可能重复执行启停/重启等操作，请确认已检查失败原因。`,
          '批量重新提交失败任务',
          { type: 'warning', confirmButtonText: '创建新任务', cancelButtonText: '取消' }
        );
      } catch (e) { return; }
      bulkRetryLoading.value = true;
      const results = [];
      let cursor = 0;
      const worker = async () => {
        while (cursor < tasks.length) {
          const task = tasks[cursor++];
          try {
            const res = await api('/api/v1/container/tasks', {
              method: 'POST', headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ machine_code: task.machine_code, action: task.action, params: task.params || {} })
            });
            const data = await res.json().catch(() => ({}));
            if (!res.ok || !data.id) throw new Error(data.error || '提交失败');
            results.push({ id: task.id, ok: true, newId: data.id });
          } catch (e) { results.push({ id: task.id, ok: false, error: e.message || '提交失败' }); }
        }
      };
      try {
        await Promise.all(Array.from({ length: Math.min(3, tasks.length) }, () => worker()));
        const ok = results.filter(x => x.ok);
        const failed = results.filter(x => !x.ok);
        selectedFailedContainerTasks.value = [];
        await loadContainerTasks();
        const summary = ok.map(x => `原 #${x.id} → 新 #${x.newId}`).concat(failed.map(x => `原 #${x.id}：${x.error}`)).join('\n');
        dockerOutput.value = `批量重试完成：成功 ${ok.length}，失败 ${failed.length}\n\n${summary}`;
        dockerOutputVisible.value = true;
        showMsg(`批量重新提交完成：成功 ${ok.length}，失败 ${failed.length}`, failed.length ? 'warning' : 'success');
      } finally { bulkRetryLoading.value = false; }
    };
    const changeContainerTaskPage = (page) => {
      containerTaskPage.value = page;
      containerTaskSearch.value = '';
      containerTaskMachineFilter.value = '';
      containerTaskStartDate.value = '';
      containerTaskEndDate.value = '';
      loadContainerTasks();
    };
    const showContainerTask = (task) => {
      const formatJSON = value => value == null ? '' : (typeof value === 'string' ? value : JSON.stringify(value, null, 2));
      const result = formatJSON(task.result);
      const params = formatJSON(task.params);
      dockerOutput.value = '任务 #' + task.id + ' · ' + taskStatusLabel(task.status)
        + '\n实例：' + task.machine_code
        + '\n动作：' + task.action
        + '\n创建时间：' + (task.created_at || '—')
        + '\n领取时间：' + (task.claimed_at || '—')
        + '\n更新时间：' + (task.updated_at || '—')
        + '\n完成时间：' + (task.finished_at || '—')
        + '\n错误：' + (task.error || '无')
        + '\n\n任务参数：\n' + (params || '无参数')
        + '\n\n执行结果：\n' + (result || '无结果');
      dockerOutputVisible.value = true;
    };
    const retryContainerTask = async (task) => {
      try {
        await ElementPlus.ElMessageBox.confirm(
          '将为实例 ' + task.machine_code + ' 创建一个新的任务 #' + task.id + ' 的副本。请先检查失败原因，确认重复执行不会造成意外影响。',
          '重新提交失败任务',
          { type: 'warning', confirmButtonText: '创建新任务', cancelButtonText: '取消' }
        );
        const res = await api('/api/v1/container/tasks', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ machine_code: task.machine_code, action: task.action, params: task.params || {} })
        });
        const data = await res.json().catch(() => ({}));
        if (!res.ok || !data.id) throw new Error(data.error || '重新提交任务失败');
        dockerMachineCode.value = task.machine_code;
        showMsg('已创建新任务 #' + data.id + '（原任务 #' + task.id + ' 保留）', 'success');
        await loadContainerTasks();
      } catch (e) {
        if (e !== 'cancel' && e !== 'close') showMsg(e.message || '重新提交任务失败', 'error');
      }
    };
    const cancelContainerTask = async (task) => {
      try {
        await ElementPlus.ElMessageBox.confirm('确定取消尚未被 Agent 领取的任务 #' + task.id + '？', '取消容器任务', { type: 'warning', confirmButtonText: '确认取消', cancelButtonText: '返回' });
        const res = await api('/api/v1/container/tasks/' + encodeURIComponent(task.id), { method: 'DELETE' });
        const data = await res.json().catch(() => ({}));
        if (!res.ok) throw new Error(data.error || '取消任务失败');
        showMsg('任务 #' + task.id + ' 已取消', 'success');
        await loadContainerTasks();
      } catch (e) {
        if (e !== 'cancel' && e !== 'close') showMsg(e.message || '取消任务失败', 'error');
      }
    };

    const containerIdentity = (row) => String(row && (row.ID || row.Id || row.Names) || '');
    const isDockerSelected = (row) => selectedDockerIDs.value.includes(containerIdentity(row));
    const onDockerSelectionChange = (rows) => {
      selectedDockerIDs.value = rows.map(containerIdentity).filter(Boolean);
    };
    const toggleDockerSelection = (row, checked) => {
      const id = containerIdentity(row);
      if (!id) return;
      const next = new Set(selectedDockerIDs.value);
      if (checked) next.add(id); else next.delete(id);
      selectedDockerIDs.value = Array.from(next);
    };
    const clearDockerSelection = () => {
      selectedDockerIDs.value = [];
    };

    const runBulkDockerAction = async (action) => {
      const labels = { 'docker.start': '启动', 'docker.stop': '停止', 'docker.restart': '重启' };
      const label = labels[action];
      if (!label || dockerLoading.value) return;
      const selected = dockerContainers.value.filter(row => selectedDockerIDs.value.includes(containerIdentity(row)));
      const eligible = selected.filter(row => action === 'docker.start' ? row.State !== 'running' : action === 'docker.stop' ? row.State === 'running' : true);
      const skipped = selected.length - eligible.length;
      if (!eligible.length) {
        showMsg(action === 'docker.start' ? '所选容器均已运行，无需启动' : '所选容器均未运行，无需停止', 'info');
        return;
      }
      try {
        await ElementPlus.ElMessageBox.confirm(
          '即将' + label + ' ' + eligible.length + ' 个容器。任务最多 3 个并发执行，每个容器单独记录任务 ID。' +
          (skipped ? '\n另有 ' + skipped + ' 个容器因当前状态不适用而跳过。' : '') +
          '\n部分任务若 20 秒内未完成，系统会标记为“状态待确认”，请在任务记录核实，避免重复提交。\n是否继续？',
          '确认批量' + label,
          { type: 'warning', confirmButtonText: '确认执行', cancelButtonText: '取消' }
        );
      } catch (e) {
        if (e !== 'cancel' && e !== 'close') showMsg(e.message || '批量操作已取消', 'warning');
        return;
      }
      dockerLoading.value = true;
      bulkDockerProgress.value = '正在批量' + label + '：0/' + eligible.length + ' 完成';
      const outcomes = new Array(eligible.length);
      let cursor = 0;
      let completed = 0;
      const worker = async () => {
        while (cursor < eligible.length) {
          const index = cursor++;
          const row = eligible[index];
          const id = containerIdentity(row);
          try {
            const result = await dockerTask(action, { container_id: id });
            outcomes[index] = {
              name: row.Names || id, id, beforeState: row.State || '未知',
              afterState: '待刷新', ok: true, status: 'succeeded',
              taskId: result.task_id || null,
              detail: String(result.output || '操作成功').trim()
            };
          } catch (e) {
            outcomes[index] = {
              name: row.Names || id, id, beforeState: row.State || '未知',
              afterState: '待确认', ok: false,
              status: e.taskStatus || (e.taskId ? 'unknown' : 'failed'),
              taskId: e.taskId || null,
              detail: e.message || '执行失败'
            };
          }
          completed++;
          bulkDockerProgress.value = '正在批量' + label + '：' + completed + '/' + eligible.length + ' 完成';
        }
      };
      try {
        await Promise.all(Array.from({ length: Math.min(3, eligible.length) }, () => worker()));
        try {
          await refreshDocker();
          const refreshedById = new Map(dockerContainers.value.map(row => [containerIdentity(row), row]));
          outcomes.forEach(item => {
            if (!item) return;
            const current = refreshedById.get(item.id);
            item.afterState = current ? (current.State || '未知') : '未查询到';
          });
        } catch (_) {
          // Preserve task results even when the post-operation state refresh fails.
        }
        const succeeded = outcomes.filter(item => item && item.ok).length;
        const failed = outcomes.filter(item => item && item.status === 'failed').length;
        const unknown = outcomes.filter(item => item && item.status === 'unknown').length;
        const lines = outcomes.map(item => {
          if (!item) return '[状态待确认] 未能读取该容器的任务结果';
          const statusLabel = item.status === 'succeeded' ? '成功' : item.status === 'failed' ? '失败' : '状态待确认';
          return '[' + statusLabel + '] ' + item.name + ' (' + item.id + ')' +
            (item.taskId ? ' · 任务 #' + item.taskId : '') +
            '\n容器状态：' + item.beforeState + ' → ' + item.afterState +
            '\n' + item.detail;
        });
        if (skipped) lines.push('[跳过] ' + skipped + ' 个容器：状态不符合该操作条件');
        dockerOutput.value = '批量' + label + '结果：成功 ' + succeeded + '，失败 ' + failed +
          '，状态待确认 ' + unknown + '，跳过 ' + skipped + '\n\n' + lines.join('\n\n') +
          (unknown ? '\n\n注意：状态待确认的任务可能仍在执行。请按任务 ID 到“容器任务记录”核实后再决定是否重试。' : '');
        dockerOutputVisible.value = true;
        bulkDockerProgress.value = '批量' + label + '完成：成功 ' + succeeded + '，失败 ' + failed +
          '，状态待确认 ' + unknown + '，跳过 ' + skipped;
        showMsg(bulkDockerProgress.value, (failed || unknown) ? 'warning' : 'success');
        selectedDockerIDs.value = [];
      } finally {
        dockerLoading.value = false;
      }
    };

    const refreshDocker = async () => {
      dockerLoading.value = true;
      try {
        const result = await dockerTask('docker.list');
        const output = result.output || '';
        dockerContainers.value = output.split(/\r?\n/).filter(Boolean).map(line => { try { return JSON.parse(line); } catch (_) { return {}; } });
        selectedDockerIDs.value = [];
        dockerStatus.value = '已读取 ' + dockerContainers.value.length + ' 个容器';
      } catch (e) { dockerStatus.value = e.message || '查询失败'; showMsg(dockerStatus.value, 'warning'); }
      finally { dockerLoading.value = false; }
    };
    const showDockerResult = (title, result) => {
      dockerOutput.value = title + '\n\n' + (result.output || JSON.stringify(result, null, 2));
      dockerOutputVisible.value = true;
    };
    const inspectDocker = async (id) => {
      dockerLoading.value = true;
      try { const r = await dockerTask('docker.inspect', { container_id: id }); showDockerResult('容器详情：' + id, r); }
      catch (e) { showMsg(e.message || '读取详情失败', 'error'); }
      finally { dockerLoading.value = false; }
    };
    const logsDocker = async (id) => {
      dockerLoading.value = true;
      try { const r = await dockerTask('docker.logs', { container_id: id, tail: 200 }); showDockerResult('容器日志：' + id, r); }
      catch (e) { showMsg(e.message || '读取日志失败', 'error'); }
      finally { dockerLoading.value = false; }
    };
    const dockerAction = async (action, row) => {
      const id = row.ID || row.Id || row.Names;
      if (!id) return showMsg('容器 ID 不存在', 'error');
      const labels = { 'docker.start': '启动', 'docker.stop': '停止', 'docker.restart': '重启' };
      if (!confirm('确定' + labels[action] + '容器 ' + (row.Names || id) + '？')) return;
      dockerLoading.value = true;
      try { const r = await dockerTask(action, { container_id: id }); showDockerResult(labels[action] + '容器结果', r); await refreshDocker(); }
      catch (e) { showMsg(e.message || 'Docker 操作失败', 'error'); }
      finally { dockerLoading.value = false; }
    };

    const refreshRouterOS = async () => {
      if (!dockerMachineCode.value) return showMsg('请先选择 RouterOS Agent 机器码', 'warning');
      if (!routerOSAgentEntries.value.some(item => item.code === dockerMachineCode.value)) {
        dockerMachineCode.value = '';
        return showMsg('所选机器码不是 RouterOS Agent，请重新选择', 'warning');
      }
      routerosLoading.value = true;
      routerosStatus.value = '正在读取 RouterOS 原生 /container/print…';
      try {
        const result = await dockerTask('routeros.container.list');
        routerosContainers.value = Array.isArray(result.containers) ? result.containers : [];
        routerosStatus.value = '读取完成：' + routerosContainers.value.length + ' 个 RouterOS 容器；任务 #' + (result.task_id || '—');
        await loadContainerTasks({ silent: true });
      } catch (e) {
        routerosStatus.value = e.message || '读取 RouterOS 容器失败';
        showMsg(routerosStatus.value, 'error');
      } finally { routerosLoading.value = false; }
    };
    const routerOSAction = async (action, row) => {
      if (!dockerMachineCode.value || !routerOSAgentEntries.value.some(item => item.code === dockerMachineCode.value)) {
        dockerMachineCode.value = '';
        return showMsg('当前选择不是 RouterOS Agent，请重新选择后操作', 'warning');
      }
      const id = String(row && row['.id'] || '');
      if (!/^\*[0-9a-fA-F]{1,31}$/.test(id)) return showMsg('RouterOS 容器内部 ID 无效', 'error');
      const labels = { 'routeros.container.start': '启动', 'routeros.container.stop': '停止', 'routeros.container.restart': '重启' };
      const label = labels[action];
      if (!label) return;
      try {
        await ElementPlus.ElMessageBox.confirm('确定' + label + ' RouterOS 容器 ' + (row.name || id) + '（' + id + '）？', '确认 RouterOS 操作', { type: 'warning', confirmButtonText: '确认' + label, cancelButtonText: '取消' });
      } catch (_) { return; }
      routerosLoading.value = true;
      routerosStatus.value = '正在提交' + label + '任务…';
      try {
        const result = await dockerTask(action, { container_id: id });
        routerosStatus.value = label + '任务成功，任务 #' + (result.task_id || '—');
        showDockerResult('RouterOS ' + label + '结果', result);
        await refreshRouterOS();
      } catch (e) {
        routerosStatus.value = e.message || 'RouterOS 操作失败';
        showMsg(routerosStatus.value, 'error');
      } finally { routerosLoading.value = false; }
    };

    const loadNodeConfig = async () => {
      const code = selectedConfigNode.value;
      configYaml.value = '';
      if (!code) return;
      try {
        const res = await api('/api/v1/nodes/' + encodeURIComponent(code) + '/config?t=' + Date.now());
        const data = await res.json().catch(() => ({}));
        if (res.ok) {
          configYaml.value = data.config_yaml || '';
          showMsg('已加载节点 ' + code + ' 的独立 YAML', 'success');
        } else {
          configYaml.value = '';
          showMsg(data.error || data.message || '该节点尚无独立 YAML，请编辑后保存', 'warning');
        }
      } catch (e) {
        showMsg(e.message || '读取节点配置失败', 'error');
      }
    };

    const saveNodeConfig = async () => {
      const code = String(selectedConfigNode.value || '').trim();
      const yaml = String(configYaml.value || '');

      if (!code) {
        showMsg('保存失败：请先选择节点机器码', 'warning');
        return;
      }
      if (!yaml.trim()) {
        showMsg('保存失败：YAML 配置不能为空', 'warning');
        return;
      }
      if (savingConfig.value) return;

      savingConfig.value = true;
      showMsg('正在保存节点 ' + code + ' 的 YAML…', 'info');

      try {
        const path = '/api/v1/nodes/' +
          encodeURIComponent(code) + '/config';

        const res = await api(path, {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ config_yaml: yaml })
        });

        const data = await res.json().catch(() => ({}));

        if (!res.ok) {
          const message = data.error || data.message ||
            ('HTTP ' + res.status);
          showMsg('保存失败（HTTP ' + res.status + '）：' + message, 'error');
          console.error('[S5M node config] PUT failed', {
            code, status: res.status, message
          });
          return;
        }

        // 保存成功后重新读取，验证后端确实返回了已保存的配置。
        const verify = await api(path + '?t=' + Date.now());
        const saved = await verify.json().catch(() => ({}));

        if (!verify.ok) {
          showMsg('服务器已接受保存请求，但回读验证失败（HTTP ' +
            verify.status + '）', 'warning');
          console.error('[S5M node config] verification failed', {
            code, status: verify.status, response: saved
          });
          return;
        }

        if (String(saved.config_yaml || '') !== yaml) {
          showMsg('保存请求成功，但回读内容不一致，请检查后端存储', 'error');
          console.error('[S5M node config] verification mismatch', { code });
          return;
        }

        showMsg('节点 ' + code + ' 的 YAML 已保存并验证成功', 'success');
      } catch (e) {
        showMsg('保存请求异常：' + (e.message || String(e)), 'error');
        console.error('[S5M node config] request exception', e);
      } finally {
        savingConfig.value = false;
      }
    };

const safeCopy = async (text) => {
      try {
        if (navigator.clipboard && window.isSecureContext) {
          await navigator.clipboard.writeText(String(text ?? ''));
        } else {
          const t = document.createElement('textarea');
          t.value = String(text ?? '');
          t.style.position = 'fixed';
          t.style.left = '-9999px';
          document.body.appendChild(t);
          t.select();
          const ok = document.execCommand('copy');
          document.body.removeChild(t);
          if (!ok) throw new Error('浏览器复制操作失败');
        }
        showMsg('复制成功', 'success');
      } catch (e) {
        showMsg('复制失败：' + (e.message || '请检查浏览器权限'), 'error');
      }
    };

    const loadConfig = async () => {
      try {
        const res = await api('/api/v1/config/preview?t=' + Date.now());
        if (res.ok) { const d = await res.json().catch(() => ({})); configYaml.value = d.config_yaml || d.yaml || d.yaml_text || ''; }
      } catch (e) { console.warn(e); }
    };

    const loadGlobalConfig = async () => {
      try {
        const res = await api('/api/v1/config/preview?t=' + Date.now());
        const data = await res.json().catch(() => ({}));
        if (!res.ok) throw new Error(data.error || data.message || '读取全局配置失败');
        globalConfigYaml.value = data.config_yaml || data.yaml || data.yaml_text || '';
      } catch (e) {
        showMsg(e.message || '读取全局配置失败', 'error');
      }
    };

    const saveGlobalConfig = async () => {
      if (!globalConfigYaml.value.trim()) return showMsg('全局配置不能为空', 'warning');
      savingGlobalConfig.value = true;
      try {
        const res = await api('/api/v1/config/save', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ config_yaml: globalConfigYaml.value })
        });
        const data = await res.json().catch(() => ({}));
        if (!res.ok) throw new Error(data.error || data.message || '保存全局配置失败');
        showMsg(data.message || '全局配置草稿已保存', 'success');
      } catch (e) {
        showMsg(e.message || '保存全局配置失败', 'error');
      } finally {
        savingGlobalConfig.value = false;
      }
    };

    const retryNodeConfigSync = async () => {
      if (retryingNodeConfigSync.value) return;
      retryingNodeConfigSync.value = true;
      try {
        const res = await api('/api/v1/nodes/config-sync', { method: 'POST' });
        const data = await res.json().catch(() => ({}));
        if (!res.ok || data.ok === false) throw new Error(data.error || data.message || '节点配置同步失败');
        showMsg(data.message || '节点配置已重新生成', 'success');
      } catch (e) {
        showMsg(e.message || '节点配置同步失败', 'error');
      } finally {
        retryingNodeConfigSync.value = false;
      }
    };

    const loadConfigVersions = async () => {
      loadingConfigVersions.value = true;
      try {
        const res = await api('/api/v1/config/versions?t=' + Date.now());
        const data = await res.json().catch(() => []);
        if (!res.ok) throw new Error(data.error || data.message || '读取配置版本失败');
        configVersions.value = Array.isArray(data) ? data : [];
      } catch (e) {
        showMsg(e.message || '读取配置版本失败', 'error');
      } finally {
        loadingConfigVersions.value = false;
      }
    };

    const publishGlobalConfig = async () => {
      if (!globalConfigYaml.value.trim()) return showMsg('全局配置不能为空', 'warning');
      publishingGlobalConfig.value = true;
      try {
        const saveRes = await api('/api/v1/config/save', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ config_yaml: globalConfigYaml.value })
        });
        const saveData = await saveRes.json().catch(() => ({}));
        if (!saveRes.ok) throw new Error(saveData.error || saveData.message || '保存全局配置失败');
        const res = await api('/api/v1/config/publish', { method: 'POST' });
        const data = await res.json().catch(() => ({}));
        if (!res.ok || data.ok === false) throw new Error(data.message || data.error || '发布全局配置失败');
        showMsg(data.message || '全局配置已发布', 'success');
        await loadConfigVersions();
      } catch (e) {
        showMsg(e.message || '发布全局配置失败', 'error');
      } finally {
        publishingGlobalConfig.value = false;
      }
    };

    const rollbackGlobalConfig = async (row) => {
      if (!row || !Number(row.version)) return;
      try {
        await ElementPlus.ElMessageBox.confirm(
          '确定回滚到配置版本 v' + row.version + '？将恢复该版本的全局设置；代理列表和路由规则仍以当前代理数据库为准。',
          '确认回滚配置',
          { type: 'warning', confirmButtonText: '确认回滚', cancelButtonText: '取消' }
        );
      } catch (_) {
        return;
      }
      try {
        const res = await api('/api/v1/config/rollback', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ version: Number(row.version) })
        });
        const data = await res.json().catch(() => ({}));
        if (!res.ok || data.ok === false) {
          const message = data.message || data.error || '回滚失败';
          if (String(message).includes('回滚已完成，但全局配置草稿同步失败')) {
            await loadConfigVersions();
            showMsg(message, 'warning');
            return;
          }
          throw new Error(message);
        }
        showMsg(data.message || ('已回滚到 v' + row.version), 'success');
        await Promise.all([loadGlobalConfig(), loadConfigVersions()]);
      } catch (e) {
        showMsg(e.message || '回滚配置失败', 'error');
      }
    };

    const loadSettings = async () => {
      try {
        const res = await api('/api/v1/settings?t=' + Date.now());
        if (res.ok) { const s = await res.json().catch(() => ({})); subUrl.value = s.subscribe_url || s.sub_url || (location.origin + '/api/v1/subscribe'); }
        else { subUrl.value = location.origin + '/api/v1/subscribe'; }
      } catch (e) { subUrl.value = location.origin + '/api/v1/subscribe'; }
    };

    const saveConfig = async () => {
      if (!configYaml.value) return showMsg('配置不能为空', 'warning');
      savingConfig.value = true;
      try {
        const res = await api('/api/v1/config/save', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ config_yaml: configYaml.value }) });
        if (res.ok) showMsg('已保存草稿', 'success'); else showMsg(await parseErr(res), 'error');
      } catch (e) { showMsg(e.message || '保存失败', 'error'); }
      savingConfig.value = false;
    };

    const publishConfig = async () => {
      if (!configYaml.value) return showMsg('配置不能为空', 'warning');
      publishing.value = true;
      try {
        let res = await api('/api/v1/config/save', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ config_yaml: configYaml.value }) });
        if (!res.ok) { showMsg('保存失败：' + (await parseErr(res)), 'error'); publishing.value = false; return; }
        res = await api('/api/v1/config/publish', { method: 'POST' });
        const d = await res.json().catch(() => ({}));
        if (res.ok) showMsg(d.message || '已下发，Agent 将在 30 秒内拉取', 'success'); else showMsg(d.error || d.message || '发布失败', 'error');
      } catch (e) { showMsg(e.message || '发布失败', 'error'); }
      publishing.value = false;
    };

    onMounted(() => {
      if (token.value) {
        fetch('/api/v1/auth/me', { headers: authHeaders() }).then(r => { if (r.status === 401) logout(); }).catch(() => {});
        switchPage('dashboard');
        if (overviewTimer === null) {
          overviewTimer = setInterval(() => {
            if (token.value && page.value === 'dashboard') loadOverview();
          }, 3000);
        }
        loadAgentsData(); // 预加载一次 Agent 列表，以便下拉框有数据
        if (instanceRefreshTimer === null) {
          instanceRefreshTimer = setInterval(() => {
            if (!token.value || page.value !== 'instances') return;
            if (!agentLoading.value) loadAgentsData();
            if (!containerTasksLoading.value) loadContainerTasks({ silent: true });
          }, 10000);
        }
      }
    });

    onUnmounted(() => {
      if (overviewTimer !== null) clearInterval(overviewTimer);
      if (instanceRefreshTimer !== null) clearInterval(instanceRefreshTimer);
      overviewTimer = null;
      instanceRefreshTimer = null;
    });

    return {
      page, token, loginUser, loginPass, loggingIn, currentUser,
      pwdDialog, pwdSaving, pwdForm, handleLoginEnter, handleUserMenu, resetPwdForm, changeAdminPassword,
      overview, traffic, proxies, loadingProxies, filteredProxies, availableMachineCodes, proxyGroupCodes, activeGroup,
      getUnboundCount, getMachineCount, machineCodeOptionLabel, machineCodeStatus, proxyCountForMachine, nodeConfigState, openProxiesForMachine, openNodeConfigForMachine,
      newMachineCode, generatedToken, generating, agentEntries, agentLoading, agentSearch, agentStatusFilter, filteredAgentEntries,
      dockerMachineCode, dockerLoading, dockerContainers, selectedDockerIDs, bulkDockerProgress, isDockerSelected, toggleDockerSelection, onDockerSelectionChange, clearDockerSelection, runBulkDockerAction, dockerStatus, dockerOutput, dockerOutputVisible, refreshDocker, inspectDocker, logsDocker, dockerAction,
      routerOSAgentEntries, routerosLoading, routerosContainers, routerosStatus, refreshRouterOS, routerOSAction,
      containerTasks, containerTasksLoading, containerTaskSearch, containerTaskStatusFilter, containerTaskMachineFilter, containerTaskMachineOptions, containerTaskStartDate, containerTaskEndDate, containerTaskDuration, containerTaskPage, containerTaskTotal, changeContainerTaskPage, selectedFailedContainerTasks, bulkRetryLoading, isRetryableContainerTask, onContainerTaskSelectionChange, retryFailedContainerTasks, filteredContainerTasks, loadContainerTasks, cancelContainerTask, showContainerTask, retryContainerTask, taskStatusLabel, taskStatusType,
      subUrl, globalConfigYaml, savingGlobalConfig, publishingGlobalConfig, loadingConfigVersions, configVersions,
      retryingNodeConfigSync, retryNodeConfigSync,
      saveGlobalConfig, publishGlobalConfig, loadGlobalConfig, loadConfigVersions, rollbackGlobalConfig,
      configYaml, selectedConfigNode, savingConfig, publishing, updatingKernel,
      kernelUpdateDialog, kernelUpdateMachineCode, kernelUpdateVersion, kernelUpdateSHA256, queueingKernelUpdate,
      openAgentKernelUpdate, queueAgentKernelUpdate,
      systemLogs, loadingSystemLogs, restoringBackup, loadSystemLogs, downloadBackup, restoreBackup,
      proxyDialog, proxyForm, savingProxy,
      showImport, importTab, importText, importing, importMachineCode,
      switchPage, doLogin, logout, loadOverview,
      updateKernel, loadProxies, openCreateProxy, openEditProxy, saveProxy, deleteProxy, importProxies, handleFileUpload,
      loadAgentsData, generateAgentToken, deleteAgent, safeCopy,
      loadNodeConfig, loadSettings, saveNodeConfig,
      fmtBytes, fmtSpeed
    };
  }
}).use(ElementPlus).mount('#app');
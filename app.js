// 周期记录 —— 单页应用，数据加密后存在本机 IndexedDB
// 无外部依赖，无网络请求。

(() => {
  'use strict';

  const DB_NAME = 'cycle-db';
  const STORE = 'kv';
  const ITERATIONS = 200000;
  const $ = (id) => document.getElementById(id);

  // ---------------- 存储 ----------------
  let dbPromise = null;

  function openDB() {
    if (!dbPromise) {
      dbPromise = new Promise((resolve, reject) => {
        const req = indexedDB.open(DB_NAME, 1);
        req.onupgradeneeded = () => req.result.createObjectStore(STORE);
        req.onsuccess = () => resolve(req.result);
        req.onerror = () => reject(req.error);
      });
    }
    return dbPromise;
  }

  async function kvGet(key) {
    const db = await openDB();
    return new Promise((resolve, reject) => {
      const req = db.transaction(STORE, 'readonly').objectStore(STORE).get(key);
      req.onsuccess = () => resolve(req.result ?? null);
      req.onerror = () => reject(req.error);
    });
  }

  async function kvSet(key, value) {
    const db = await openDB();
    return new Promise((resolve, reject) => {
      const req = db.transaction(STORE, 'readwrite').objectStore(STORE).put(value, key);
      req.onsuccess = () => resolve();
      req.onerror = () => reject(req.error);
    });
  }

  // ---------------- 加密 ----------------
  const te = new TextEncoder();
  const td = new TextDecoder();

  function b64e(bytes) {
    const a = new Uint8Array(bytes);
    let s = '';
    for (let i = 0; i < a.length; i += 0x8000) {
      s += String.fromCharCode.apply(null, a.subarray(i, i + 0x8000));
    }
    return btoa(s);
  }

  function b64d(str) {
    const s = atob(str);
    const a = new Uint8Array(s.length);
    for (let i = 0; i < s.length; i++) a[i] = s.charCodeAt(i);
    return a;
  }

  async function deriveKey(password, salt, iterations) {
    const base = await crypto.subtle.importKey(
      'raw', te.encode(password), 'PBKDF2', false, ['deriveKey'],
    );
    return crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt, iterations, hash: 'SHA-256' },
      base,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt'],
    );
  }

  async function seal(k, obj) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv }, k, te.encode(JSON.stringify(obj)),
    );
    return { iv: b64e(iv), ct: b64e(ct) };
  }

  async function unseal(k, ivB64, ctB64) {
    const pt = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: b64d(ivB64) }, k, b64d(ctB64),
    );
    return JSON.parse(td.decode(pt));
  }

  // ---------------- 状态 ----------------
  let key = null;
  let vault = null;
  let salt = null;
  let viewMonth = new Date();
  let editingId = null;
  let editingDay = null;

  const emptyVault = () => ({ version: 1, settings: {}, records: [] });

  // ---------------- 日期工具 ----------------
  function ymd(d) {
    const p = (n) => String(n).padStart(2, '0');
    return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}`;
  }

  function parseYmd(s) {
    if (!s) return null;
    const [y, m, d] = s.split('-').map(Number);
    if (!y || !m || !d) return null;
    return new Date(y, m - 1, d);
  }

  function addDays(s, n) {
    const d = parseYmd(s);
    d.setDate(d.getDate() + n);
    return ymd(d);
  }

  function diffDays(a, b) {
    return Math.round((parseYmd(b) - parseYmd(a)) / 86400000);
  }

  // ---------------- 记录逻辑 ----------------
  // open=true 表示经期进行中，跨度算到「今天」；否则以 end 为准
  function span(r) {
    if (r.open) {
      const today = ymd(new Date());
      return [r.start, today > r.start ? today : r.start];
    }
    return [r.start, r.end && r.end >= r.start ? r.end : r.start];
  }

  function ongoingRecord() {
    return vault.records.find((r) => r.open) || null;
  }

  // 兼容旧版本：end 为空且没有 open 字段的记录，按“单日已完成”处理
  function migrate() {
    let changed = false;
    for (const r of vault.records) {
      if (r.open === undefined) {
        r.open = false;
        if (!r.end) r.end = r.start;
        changed = true;
      }
    }
    return changed;
  }

  function dayInRecord(day, r) {
    const [s, e] = span(r);
    return day >= s && day <= e;
  }

  function sortedRecords() {
    return [...vault.records].sort((a, b) => (a.start < b.start ? -1 : 1));
  }

  function cycleStats() {
    const list = sortedRecords();
    const lens = [];
    for (let i = 1; i < list.length; i++) {
      const d = diffDays(list[i - 1].start, list[i].start);
      if (d >= 15 && d <= 60) lens.push(d);
    }
    const avg = lens.length
      ? Math.round(lens.reduce((a, b) => a + b, 0) / lens.length)
      : null;

    // 经期持续天数：取已完成记录的中位数，过滤明显异常值
    const durations = list
      .filter((r) => !r.open && r.end)
      .map((r) => diffDays(r.start, r.end) + 1)
      .filter((n) => n >= 2 && n <= 12)
      .sort((a, b) => a - b);
    const avgLen = durations.length
      ? durations[Math.floor(durations.length / 2)]
      : 5;

    const last = list.length ? list[list.length - 1].start : null;
    const next = last && avg ? addDays(last, avg) : null;
    const nextEnd = next ? addDays(next, avgLen - 1) : null;

    // 排卵日按「下次经期前 14 天」估算；易孕期取排卵前 5 天到后 1 天
    const ovu = next ? addDays(next, -14) : null;
    const ovuStart = ovu ? addDays(ovu, -5) : null;
    const ovuEnd = ovu ? addDays(ovu, 1) : null;

    return { lens, avg, avgLen, last, next, nextEnd, ovu, ovuStart, ovuEnd };
  }

  async function saveAll() {
    const blob = await seal(key, vault);
    await kvSet('vault', blob);
  }

  async function persistMeta(saltB64) {
    await kvSet('meta', { version: 1, salt: saltB64, iterations: ITERATIONS });
  }

  // ---------------- 界面辅助 ----------------
  let toastTimer = null;

  function toast(message, kind) {
    const el = $('toast');
    el.textContent = message;
    el.className = `toast${kind ? ` ${kind}` : ''}`;
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => el.classList.add('hidden'), 2600);
  }

  /**
   * 页内对话框。
   * fields: [{ id, label, type, placeholder }]
   * buttons: [{ label, value, kind }]  value === null 表示取消
   * 返回：null（取消）或 { value, ...字段值 }
   */
  function dialog({ title, text = '', fields = [], buttons }) {
    return new Promise((resolve) => {
      $('modal-title').textContent = title;
      $('modal-text').textContent = text;
      $('modal-text').classList.toggle('hidden', !text);

      const body = $('modal-body');
      body.innerHTML = '';
      const inputs = {};
      for (const f of fields) {
        const label = document.createElement('label');
        label.textContent = f.label ?? '';
        const input = document.createElement('input');
        input.type = f.type ?? 'text';
        input.placeholder = f.placeholder ?? '';
        input.autocomplete = 'off';
        label.appendChild(input);
        body.appendChild(label);
        inputs[f.id] = input;
      }

      const actions = $('modal-actions');
      actions.innerHTML = '';
      const finish = (value) => {
        $('modal').classList.add('hidden');
        resolve(value);
      };
      for (const b of buttons) {
        const btn = document.createElement('button');
        btn.textContent = b.label;
        if (b.kind) btn.className = b.kind;
        btn.addEventListener('click', () => {
          if (b.value === null) { finish(null); return; }
          const values = { value: b.value };
          for (const [k, el] of Object.entries(inputs)) values[k] = el.value;
          finish(values);
        });
        actions.appendChild(btn);
      }

      $('modal').classList.remove('hidden');
      const first = body.querySelector('input');
      if (first) setTimeout(() => first.focus(), 30);
    });
  }

  // ---------------- 渲染 ----------------
  function render() {
    if (!vault) return;
    const y = viewMonth.getFullYear();
    const m = viewMonth.getMonth();
    $('month-label').textContent = `${y} 年 ${m + 1} 月`;

    const first = new Date(y, m, 1);
    const offset = (first.getDay() + 6) % 7;
    const daysInMonth = new Date(y, m + 1, 0).getDate();
    const todayStr = ymd(new Date());
    const stats = cycleStats();

    const cells = [];
    for (let i = 0; i < offset; i++) cells.push(null);
    for (let d = 1; d <= daysInMonth; d++) cells.push(ymd(new Date(y, m, d)));
    while (cells.length % 7 !== 0) cells.push(null);

    const grid = $('grid');
    grid.innerHTML = '';
    for (const day of cells) {
      const el = document.createElement('button');
      el.className = 'day';
      if (!day) {
        el.disabled = true;
        grid.appendChild(el);
        continue;
      }
      el.textContent = String(parseYmd(day).getDate());
      el.dataset.day = day;
      if (day === todayStr) el.classList.add('today');
      const hit = vault.records.some((r) => dayInRecord(day, r));
      if (hit) {
        el.classList.add('period');
      } else if (stats.next && day >= stats.next && day <= stats.nextEnd) {
        el.classList.add('predicted');
      } else if (stats.ovuEnd && day >= stats.ovuStart && day <= stats.ovuEnd) {
        el.classList.add(day === stats.ovu ? 'ovuday' : 'ovu');
      } else {
        el.classList.add('safe');
      }
      if (vault.records.some((r) => dayInRecord(day, r) && r.days && r.days[day])) {
        el.classList.add('hasnote');
      }
      grid.appendChild(el);
    }

    $('s-avg').textContent = stats.avg ? `${stats.avg} 天` : '–';
    $('s-last').textContent = stats.last ? stats.last.slice(5) : '–';
    $('s-next').textContent = stats.next ? stats.next.slice(5) : '–';
    $('s-len').textContent = stats.avgLen ? `${stats.avgLen} 天` : '–';

    const on = ongoingRecord();
    const banner = $('banner');
    const fab = $('add-record');
    if (on) {
      const idx = diffDays(on.start, ymd(new Date())) + 1;
      banner.textContent = `经期中 · 第 ${idx} 天（${on.start.slice(5)} 开始）`;
      banner.classList.remove('hidden');
      fab.textContent = '结束';
      fab.classList.add('ongoing');
    } else {
      banner.classList.add('hidden');
      fab.textContent = '＋';
      fab.classList.remove('ongoing');
    }
  }

  // ---------------- 记录弹层 ----------------
  function openSheet(day, record, opts = {}) {
    editingId = record ? record.id : null;
    editingDay = day || null;
    $('sheet-title').textContent = record ? '修改记录' : '记录经期';
    $('f-start').value = record ? record.start : day;
    $('f-end').value = record ? (record.end || '') : (opts.endPrefill || '');
    const dayNote = record?.days?.[day] ?? '';
    $('f-daynote').value = dayNote;
    $('daynote-wrap').classList.toggle('hidden', !record);
    if (record) {
      $('daynote-wrap').firstChild.textContent = `这一天的备注（${day.slice(5)}）`;
    }
    $('f-flow').value = record ? (record.flow || 'medium') : 'medium';
    $('f-meds').value = record ? (record.meds || '') : '';
    $('f-notes').value = record ? (record.notes || '') : '';
    document.querySelectorAll('fieldset input[type=checkbox]').forEach((cb) => {
      cb.checked = Boolean(record && (record.symptoms || []).includes(cb.value));
    });
    $('f-delete').classList.toggle('hidden', !record);
    $('sheet').classList.remove('hidden');
  }

  function closeSheet() {
    $('sheet').classList.add('hidden');
    editingId = null;
    editingDay = null;
  }

  async function saveRecord() {
    const start = $('f-start').value;
    let end = $('f-end').value;
    if (!start) {
      toast('开始日期不能为空', 'err');
      return;
    }
    if (end && end < start) end = start;
    const symptoms = [...document.querySelectorAll('fieldset input[type=checkbox]')]
      .filter((cb) => cb.checked)
      .map((cb) => cb.value);
    const data = {
      start,
      end: end || '',
      flow: $('f-flow').value,
      symptoms,
      meds: $('f-meds').value.trim(),
      notes: $('f-notes').value.trim(),
    };
    if (editingId) {
      const rec = vault.records.find((r) => r.id === editingId);
      if (rec) {
        const wasOpen = Boolean(rec.open);
        Object.assign(rec, data);
        // 填了结束日就视为已完成；留空则保持原来的状态
        rec.open = end ? false : wasOpen;
        // 当日备注只属于这一天，不参与整次经期的字段
        const dayNote = $('f-daynote').value.trim();
        rec.days = rec.days || {};
        if (editingDay && dayNote) rec.days[editingDay] = dayNote;
        else if (editingDay) delete rec.days[editingDay];
      }
    } else {
      vault.records.push({ id: crypto.randomUUID(), ...data, open: false });
    }
    await saveAll();
    closeSheet();
    render();
  }

  async function deleteRecord() {
    if (!editingId) return;
    const ans = await dialog({
      title: '删除这条记录？',
      text: '删除后无法恢复。',
      buttons: [
        { label: '取消', value: null },
        { label: '删除', value: 'ok', kind: 'danger' },
      ],
    });
    if (!ans) return;
    vault.records = vault.records.filter((r) => r.id !== editingId);
    await saveAll();
    closeSheet();
    render();
    toast('已删除');
  }

  // ---------------- 导入导出 ----------------
  function download(filename, text) {
    const blob = new Blob([text], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  /**
   * 优先调起系统分享（选微信/邮件发出去），不支持或失败时退回下载。
   * 返回 'shared' | 'cancelled' | 'downloaded'
   */
  async function deliverFile(filename, text) {
    const file = new File([text], filename, { type: 'application/json' });
    if (navigator.canShare && navigator.canShare({ files: [file] })) {
      try {
        await navigator.share({ files: [file], title: '经期备份', text: '加密备份' });
        return 'shared';
      } catch (err) {
        if (err && err.name === 'AbortError') return 'cancelled';
        // 其它错误（权限、目标不支持）退回下载
      }
    }
    download(filename, text);
    return 'downloaded';
  }

  async function exportEncrypted() {
    const blob = await seal(key, vault);
    const name = `cycle-backup-${ymd(new Date())}.json`;
    const text = JSON.stringify({
      app: 'cycle',
      format: 'enc-v1',
      salt: b64e(salt),
      iterations: ITERATIONS,
      iv: blob.iv,
      ct: blob.ct,
      at: new Date().toISOString(),
    }, null, 2);
    const how = await deliverFile(name, text);
    if (how === 'shared') toast('已通过分享面板发出');
    else if (how === 'downloaded') toast('已保存到「下载」目录');
  }

  async function exportPlain() {
    const ans = await dialog({
      title: '导出明文？',
      text: '文件里是未加密的记录，任何人拿到都能直接看到内容。',
      buttons: [
        { label: '取消', value: null },
        { label: '仍然导出', value: 'ok', kind: 'danger' },
      ],
    });
    if (!ans) return;
    download(
      `cycle-plain-${ymd(new Date())}.json`,
      JSON.stringify({ app: 'cycle', format: 'plain-v1', vault, at: new Date().toISOString() }, null, 2),
    );
    toast('明文备份已导出');
  }

  async function importFile(file) {
    let obj;
    try {
      obj = JSON.parse(await file.text());
    } catch {
      toast('文件不是有效的 JSON', 'err');
      return;
    }

    let incoming = null;
    if (obj.format === 'enc-v1') {
      const ans = await dialog({
        title: '输入备份密码',
        text: '这份备份是用密码加密的。',
        fields: [{ id: 'pw', label: '密码', type: 'password' }],
        buttons: [
          { label: '取消', value: null },
          { label: '确定', value: 'ok', kind: 'primary' },
        ],
      });
      if (!ans) return;
      try {
        const k = await deriveKey(ans.pw, b64d(obj.salt), obj.iterations || ITERATIONS);
        incoming = await unseal(k, obj.iv, obj.ct);
      } catch {
        toast('密码不对，或文件已损坏', 'err');
        return;
      }
    } else if (obj.format === 'plain-v1') {
      incoming = obj.vault;
    } else {
      toast('不认识的备份格式', 'err');
      return;
    }

    if (!incoming || !Array.isArray(incoming.records)) {
      toast('备份内容不完整', 'err');
      return;
    }

    const mode = await dialog({
      title: `导入 ${incoming.records.length} 条记录`,
      text: '合并：保留现有记录，同一条以备份为准。覆盖：清空现有记录，只留备份。',
      buttons: [
        { label: '取消', value: null },
        { label: '合并', value: 'merge', kind: 'primary' },
        { label: '覆盖', value: 'replace', kind: 'danger' },
      ],
    });
    if (!mode) return;

    if (mode.value === 'merge') {
      const byId = new Map(vault.records.map((r) => [r.id, r]));
      for (const r of incoming.records) byId.set(r.id, r);
      vault.records = [...byId.values()];
    } else {
      vault = { version: 1, settings: incoming.settings || {}, records: incoming.records };
    }
    migrate();
    await saveAll();
    render();
    toast(`导入完成，共 ${vault.records.length} 条`);
  }

  // ---------------- 密码流程 ----------------
  function show(el) { el.classList.remove('hidden'); }
  function hide(el) { el.classList.add('hidden'); }

  async function startSetup() {
    hide($('lock'));
    show($('setup'));
    $('setup-go').onclick = async () => {
      const p1 = $('setup-pw1').value;
      const p2 = $('setup-pw2').value;
      const err = $('setup-err');
      if (p1.length < 6) { err.textContent = '密码至少 6 位'; return; }
      if (p1 !== p2) { err.textContent = '两次输入不一致'; return; }
      err.textContent = '';
      salt = crypto.getRandomValues(new Uint8Array(16));
      key = await deriveKey(p1, salt, ITERATIONS);
      vault = emptyVault();
      await saveAll();
      await persistMeta(b64e(salt));
      enterApp();
    };
  }

  async function tryUnlock() {
    const pw = $('lock-pw').value;
    const err = $('lock-err');
    if (!pw) return;
    try {
      key = await deriveKey(pw, salt, ITERATIONS);
      const blob = await kvGet('vault');
      vault = await unseal(key, blob.iv, blob.ct);
      if (migrate()) await saveAll();
      err.textContent = '';
      $('lock-pw').value = '';
      enterApp();
    } catch {
      key = null;
      err.textContent = '密码不对';
    }
  }

  function enterApp() {
    hide($('lock'));
    hide($('setup'));
    show($('app'));
    render();
  }

  async function lockNow() {
    key = null;
    vault = null;
    editingId = null;
    hide($('app'));
    hide($('settings'));
    hide($('sheet'));
    $('lock-err').textContent = '';
    $('lock-pw').value = '';
    show($('lock'));
  }

  async function changePassword() {
    const ans = await dialog({
      title: '修改密码',
      text: '修改后，之前导出的加密备份仍要用旧密码打开。',
      fields: [
        { id: 'pw1', label: '新密码（至少 6 位）', type: 'password' },
        { id: 'pw2', label: '再输一次', type: 'password' },
      ],
      buttons: [
        { label: '取消', value: null },
        { label: '确定', value: 'ok', kind: 'primary' },
      ],
    });
    if (!ans) return;
    if (ans.pw1.length < 6) { toast('密码至少 6 位', 'err'); return; }
    if (ans.pw1 !== ans.pw2) { toast('两次输入不一致', 'err'); return; }

    salt = crypto.getRandomValues(new Uint8Array(16));
    key = await deriveKey(ans.pw1, salt, ITERATIONS);
    await saveAll();
    await persistMeta(b64e(salt));
    toast('密码已修改');
  }

  // ---------------- 开始 / 结束 ----------------
  async function onPrimaryAction() {
    const today = ymd(new Date());
    const on = ongoingRecord();

    if (on) {
      if (today < on.start) {
        toast('今天早于开始日期，请手动修改记录', 'err');
        return;
      }
      const ans = await dialog({
        title: '结束经期？',
        text: `结束日期记为今天（${today}）。`,
        buttons: [
          { label: '取消', value: null },
          { label: '结束', value: 'ok', kind: 'primary' },
        ],
      });
      if (!ans) return;
      on.end = today;
      on.open = false;
      await saveAll();
      render();
      toast('已结束本次经期');
      return;
    }

    const ans = await dialog({
      title: '开始经期？',
      text: `开始日期记为今天（${today}）。之后在结束当天点「结束」即可。`,
      buttons: [
        { label: '取消', value: null },
        { label: '补录历史', value: 'backfill' },
        { label: '开始', value: 'ok', kind: 'primary' },
      ],
    });
    if (!ans) return;
    if (ans.value === 'backfill') {
      openSheet(today, null, { endPrefill: today });
      return;
    }
    vault.records.push({
      id: crypto.randomUUID(), start: today, end: '', open: true, flow: 'medium', symptoms: [], meds: '', notes: '',
    });
    await saveAll();
    render();
    toast('已开始记录，结束那天点「结束」');
  }

  async function onDayClick(e) {
    const btn = e.target.closest('.day');
    if (!btn || !btn.dataset.day) return;
    const day = btn.dataset.day;

    const rec = vault.records.find((r) => dayInRecord(day, r));
    if (rec) {
      openSheet(day, rec);
      return;
    }

    const ans = await dialog({
      title: `${day} 还没有记录`,
      text: '从这天开始一次经期（不填结束日），还是补录一段有起止的记录？',
      buttons: [
        { label: '取消', value: null },
        { label: '补录一段', value: 'backfill' },
        { label: '从这天开始', value: 'start', kind: 'primary' },
      ],
    });
    if (!ans) return;

    if (ans.value === 'backfill') {
      openSheet(day, null, { endPrefill: day });
      return;
    }
    if (ongoingRecord()) {
      toast('已有一段未结束的记录，先结束它', 'err');
      return;
    }
    vault.records.push({
      id: crypto.randomUUID(), start: day, end: '', open: true, flow: 'medium', symptoms: [], meds: '', notes: '',
    });
    await saveAll();
    render();
    toast('已开始记录');
  }

  // ---------------- 事件绑定 ----------------
  function bind() {
    $('lock-go').addEventListener('click', tryUnlock);
    $('lock-pw').addEventListener('keydown', (e) => { if (e.key === 'Enter') tryUnlock(); });

    $('prev-month').addEventListener('click', () => {
      viewMonth = new Date(viewMonth.getFullYear(), viewMonth.getMonth() - 1, 1);
      render();
    });
    $('next-month').addEventListener('click', () => {
      viewMonth = new Date(viewMonth.getFullYear(), viewMonth.getMonth() + 1, 1);
      render();
    });

    $('lock-now').addEventListener('click', lockNow);

    $('add-record').addEventListener('click', onPrimaryAction);
    $('f-cancel').addEventListener('click', closeSheet);
    $('f-save').addEventListener('click', saveRecord);
    $('f-delete').addEventListener('click', deleteRecord);

    $('grid').addEventListener('click', onDayClick);

    $('open-settings').addEventListener('click', () => show($('settings')));
    $('close-settings').addEventListener('click', () => hide($('settings')));
    $('exp-encrypted').addEventListener('click', exportEncrypted);
    $('exp-plain').addEventListener('click', exportPlain);
    $('change-pw').addEventListener('click', changePassword);
    $('imp').addEventListener('click', () => $('imp-file').click());
    $('imp-file').addEventListener('change', async (e) => {
      const f = e.target.files?.[0];
      if (f) await importFile(f);
      e.target.value = '';
    });
  }

  // ---------------- 启动 ----------------
  async function boot() {
    if (!('crypto' in window) || !crypto.subtle) {
      document.body.innerHTML = '<p style="padding:24px">需要 HTTPS 或 localhost 才能使用加密功能。</p>';
      return;
    }
    bind();
    const meta = await kvGet('meta');
    const blob = await kvGet('vault');
    if (!meta || !blob) {
      await startSetup();
      return;
    }
    salt = b64d(meta.salt);
    hide($('app'));
    show($('lock'));
  }

  boot();

  if ('serviceWorker' in navigator) {
    navigator.serviceWorker.register('./sw.js').catch(() => {});
  }
})();

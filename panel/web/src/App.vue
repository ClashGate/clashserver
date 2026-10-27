<script setup>
import { ref, reactive, computed, watch, onMounted } from 'vue'

const boot = window.__CS_BOOT__ || {
  page: 'dashboard',
  version: '0.7',
  csrf: '',
  login_error: '',
  flash_msg: '',
  flash_ok: true,
  sub_url: '',
  zb_url: '',
  srv_cfg_url: '/config/server.yaml',
  controller_port: 0,
  controller_listening: false,
  certs_present: true,
  custom_config_mode: false,
  custom_config_raw: '',
  status: {
    active: 'active',
    state_txt: '运行中',
    state_cls: 'ok',
    inbound_total: 0,
    inbound_listening: 0,
    outbound_nodes_count: 0,
    outbound_providers_count: 0,
    cert_days: null,
    cert_hours: null,
    cert_expires: '',
  },
  inbounds: [],
  all_proxies_yaml: '',
  proxies: [],
  providers: [],
}

const pageMode = ref(boot.page || 'dashboard')
const state = reactive({
  version: boot.version || '0.7',
  csrf: boot.csrf || '',
  sub_url: boot.sub_url || '',
  zb_url: boot.zb_url || '',
  srv_cfg_url: boot.srv_cfg_url || '/config/server.yaml',
  controller_port: boot.controller_port || 0,
  controller_listening: !!boot.controller_listening,
  certs_present: boot.certs_present !== false,
  custom_config_mode: !!boot.custom_config_mode,
  custom_config_raw: boot.custom_config_raw || '',
  status: { ...(boot.status || {}) },
  inbounds: Array.isArray(boot.inbounds) ? boot.inbounds : [],
  all_proxies_yaml: boot.all_proxies_yaml || '',
  proxies: Array.isArray(boot.proxies) ? boot.proxies : [],
  providers: Array.isArray(boot.providers) ? boot.providers : [],
})

const activeTab = ref('inbounds')
const busyKey = ref('')
const copiedKey = ref('')
const toast = reactive({ show: false, msg: '', ok: true })
let toastTimer = null

function showToast(msg, ok = true) {
  if (!msg) return
  toast.msg = msg
  toast.ok = ok
  toast.show = true
  if (toastTimer) clearTimeout(toastTimer)
  toastTimer = setTimeout(() => {
    toast.show = false
  }, 4500)
}

const PROTOCOLS = [
  { value: 'vless-reality', label: 'VLESS Reality', defaultName: 'VlessReality' },
  { value: 'shadowsocks', label: 'Shadowsocks', defaultName: 'Shadowsocks' },
  { value: 'hysteria2', label: 'Hysteria2', defaultName: 'Hysteria2' },
  { value: 'snell', label: 'Snell V5', defaultName: 'SnellV5' },
  { value: 'anytls', label: 'AnyTLS', defaultName: 'AnyTLS' },
  { value: 'tuic', label: 'TUIC v5', defaultName: 'TUICv5' },
  { value: 'trusttunnel', label: 'TrustTunnel', defaultName: 'TrustTunnel' },
  { value: 'shadowquic', label: 'ShadowQUIC', defaultName: 'ShadowQUIC' },
  { value: 'mieru', label: 'Mieru', defaultName: 'Mieru' },
  { value: 'sudoku', label: 'Sudoku', defaultName: 'Sudoku' },
  { value: 'http', label: 'HTTP', defaultName: 'HTTP' },
  { value: 'socks', label: 'SOCKS5', defaultName: 'SOCKS5' },
]

const DEFAULT_NAMES = Object.fromEntries(PROTOCOLS.map((p) => [p.value, p.defaultName]))

const inboundForm = reactive({
  kind: 'vless-reality',
  name: 'VlessReality',
  port: '',
  reality_sni: '',
  reality_enc: 'x25519',
  ss_cipher: 'aes-128-gcm',
  hy2_obfs_pw: '',
  snell_obfs: 'tls',
  snell_host: '',
  anytls_fp: 'chrome',
  tuic_cc: 'bbr',
  tt_cc: 'bbr',
  sq_jls: '',
  mieru_transport: 'TCP',
  sudoku_aead: 'chacha20-poly1305',
  http_tls: '0',
  socks_tls: '0',
})

const currentDefaultName = computed(() => DEFAULT_NAMES[inboundForm.kind] || 'VlessReality')

watch(
  () => inboundForm.kind,
  (newKind, oldKind) => {
    const oldDefault = DEFAULT_NAMES[oldKind] || ''
    const newDefault = DEFAULT_NAMES[newKind] || newKind
    if (!inboundForm.name.trim() || inboundForm.name.trim() === oldDefault) {
      inboundForm.name = newDefault
    }
  }
)

const providerForm = reactive({
  sub_url: '',
  provider_name: '',
})

const proxiesRaw = ref('')
const customConfigText = ref(state.custom_config_raw || '')

const certDisplay = computed(() => {
  const s = state.status || {}
  if (s.cert_days !== null && s.cert_days !== undefined) {
    if (s.cert_days < 1) {
      return `${s.cert_hours ?? 0} 小时`
    }
    return `${s.cert_days} 天`
  }
  return state.certs_present ? '有效' : '未就绪'
})

function applyServerState(newState) {
  if (!newState) return
  if (newState.csrf) state.csrf = newState.csrf
  if (newState.sub_url !== undefined) state.sub_url = newState.sub_url
  if (newState.zb_url !== undefined) state.zb_url = newState.zb_url
  if (newState.srv_cfg_url !== undefined) state.srv_cfg_url = newState.srv_cfg_url
  if (newState.controller_port !== undefined) state.controller_port = newState.controller_port
  if (newState.controller_listening !== undefined) state.controller_listening = newState.controller_listening
  if (newState.certs_present !== undefined) state.certs_present = newState.certs_present
  if (newState.custom_config_mode !== undefined) state.custom_config_mode = newState.custom_config_mode
  if (newState.custom_config_raw !== undefined) {
    state.custom_config_raw = newState.custom_config_raw
    customConfigText.value = newState.custom_config_raw
  }
  if (newState.status) Object.assign(state.status, newState.status)
  if (Array.isArray(newState.inbounds)) state.inbounds = newState.inbounds
  if (newState.all_proxies_yaml !== undefined) state.all_proxies_yaml = newState.all_proxies_yaml
  if (Array.isArray(newState.proxies)) state.proxies = newState.proxies
  if (Array.isArray(newState.providers)) state.providers = newState.providers
}

async function postAction(url, params = {}, key = url, retry = 0) {
  busyKey.value = key
  const body = new URLSearchParams({ csrf: state.csrf, ...params }).toString()
  const ctrl = window.AbortController ? new AbortController() : null
  const timer = ctrl ? setTimeout(() => ctrl.abort(), 120000) : null
  try {
    const res = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'X-Requested-With': 'fetch',
        Accept: 'application/json',
      },
      body,
      credentials: 'same-origin',
      cache: 'no-store',
      signal: ctrl ? ctrl.signal : undefined,
    })
    if (timer) clearTimeout(timer)
    if (res.status === 401) {
      window.location.href = '/login'
      return null
    }
    const text = await res.text()
    let data = null
    try {
      data = JSON.parse(text)
    } catch {
      data = { ok: res.ok, msg: text || `HTTP ${res.status}` }
    }
    if (data.state) {
      applyServerState(data.state)
    } else {
      if (data.zb_url) state.zb_url = data.zb_url
      if (data.sub_url) state.sub_url = data.sub_url
    }
    showToast(data.msg || (data.ok ? '操作成功' : '操作失败'), !!data.ok)
    return data
  } catch (err) {
    if (timer) clearTimeout(timer)
    if (err && err.name === 'AbortError') {
      showToast('请求超时（120s），请稍后刷新查看状态', false)
      return null
    }
    if (retry < 1) {
      await new Promise((r) => setTimeout(r, 350))
      return postAction(url, params, key, retry + 1)
    }
    showToast(`网络请求异常：${(err && err.message) || err}`, false)
    return null
  } finally {
    busyKey.value = ''
  }
}

async function copyRaw(text, key) {
  if (!text) return
  const done = () => {
    copiedKey.value = key
    setTimeout(() => {
      if (copiedKey.value === key) copiedKey.value = ''
    }, 1600)
  }
  try {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      await navigator.clipboard.writeText(text)
      done()
      return
    }
  } catch {
    // fallback below
  }
  const ta = document.createElement('textarea')
  ta.value = text
  ta.style.position = 'fixed'
  ta.style.opacity = '0'
  document.body.appendChild(ta)
  ta.select()
  try {
    document.execCommand('copy')
    done()
  } catch {}
  document.body.removeChild(ta)
}

async function submitAddInbound() {
  const payload = {
    kind: inboundForm.kind,
    name: inboundForm.name.trim() || currentDefaultName.value,
    port: inboundForm.port.trim(),
    reality_sni: inboundForm.reality_sni.trim(),
    reality_enc: inboundForm.reality_enc,
    ss_cipher: inboundForm.ss_cipher,
    hy2_obfs_pw: inboundForm.hy2_obfs_pw.trim(),
    snell_obfs: inboundForm.snell_obfs,
    snell_host: inboundForm.snell_host.trim(),
    anytls_fp: inboundForm.anytls_fp,
    tuic_cc: inboundForm.tuic_cc,
    tt_cc: inboundForm.tt_cc,
    sq_jls: inboundForm.sq_jls.trim(),
    mieru_transport: inboundForm.mieru_transport,
    sudoku_aead: inboundForm.sudoku_aead,
    http_tls: inboundForm.http_tls,
    socks_tls: inboundForm.socks_tls,
  }
  const res = await postAction('/inbounds/add', payload, 'add-inbound')
  if (res && res.ok) {
    inboundForm.port = ''
    inboundForm.name = currentDefaultName.value
  }
}

async function deleteInbound(item) {
  if (!window.confirm(`确定删除节点「${item.name}」？`)) return
  await postAction(item.delete_url, {}, `del-${item.key}`)
}

async function resetSubUrl() {
  if (!window.confirm('确定更换订阅链接？更换后原订阅链接将立即失效。')) return
  await postAction('/action/reset-sub', {}, 'reset-sub')
}

async function resetZbSecret() {
  if (!window.confirm('确定重置 Zashboard API 密钥？')) return
  await postAction('/action/reset-secret', {}, 'reset-secret')
}

async function submitAddProvider() {
  if (!providerForm.sub_url.trim()) return
  const res = await postAction(
    '/providers/add',
    {
      sub_url: providerForm.sub_url.trim(),
      provider_name: providerForm.provider_name.trim(),
    },
    'add-provider'
  )
  if (res && res.ok) {
    providerForm.sub_url = ''
    providerForm.provider_name = ''
  }
}

async function deleteProvider(name) {
  if (!window.confirm(`确定删除订阅源「${name}」？`)) return
  await postAction('/providers/delete', { name }, `del-prov-${name}`)
}

async function submitAddProxies() {
  if (!proxiesRaw.value.trim()) return
  const res = await postAction('/proxies/add', { proxies_raw: proxiesRaw.value }, 'add-proxies')
  if (res && res.ok) {
    proxiesRaw.value = ''
  }
}

async function deleteProxy(name) {
  if (!window.confirm(`确定删除出站节点「${name}」？`)) return
  await postAction('/proxies/delete', { name }, `del-proxy-${name}`)
}

function loadFileInto(ev, targetRef) {
  const f = ev.target.files && ev.target.files[0]
  if (!f) return
  const r = new FileReader()
  r.onload = () => {
    targetRef.value = r.result || ''
  }
  r.readAsText(f)
  ev.target.value = ''
}

function autoFixCertPaths() {
  const certPath = '/etc/clashserve/certs/fullchain.pem'
  const keyPath = '/etc/clashserve/certs/privkey.pem'
  const lines = (customConfigText.value || '').split(/\r?\n/)
  let inReality = false
  let realityIndent = 0
  let inProviders = false
  let provIndent = 0
  let changed = 0

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]
    const stripped = line.replace(/^ +/, '')
    const indent = line.length - stripped.length
    if (stripped && stripped.charAt(0) !== '#') {
      if (inReality && indent <= realityIndent) inReality = false
      if (inProviders && indent <= provIndent) inProviders = false
      if (/^reality-config\s*:/.test(stripped)) {
        inReality = true
        realityIndent = indent
        continue
      }
      if (/^proxy-providers\s*:/.test(stripped)) {
        inProviders = true
        provIndent = indent
        continue
      }
      if (inProviders && indent === provIndent + 2 && /^default\s*:\s*(#.*)?$/.test(stripped)) {
        lines[i] = line.slice(0, indent) + stripped.replace(/^default(\s*:)/, 'default-sub$1')
        changed++
        continue
      }
      const mc = stripped.match(/^((?:-\s+)?certificate\s*:\s*)([^#\n]+?)(\s*(?:#.*)?)$/)
      if (mc) {
        const cv = mc[2].trim().replace(/^['"]|['"]$/g, '')
        if (cv !== certPath) changed++
        lines[i] = line.slice(0, indent) + mc[1] + certPath + (mc[3] || '')
        continue
      }
      if (!inReality) {
        const mk = stripped.match(/^((?:-\s+)?private-key\s*:\s*)([^#\n]+?)(\s*(?:#.*)?)$/)
        if (mk) {
          const kv = mk[2].trim().replace(/^['"]|['"]$/g, '')
          if (kv.indexOf('/') >= 0 || kv.indexOf('.') >= 0 || /key|pem/i.test(kv)) {
            if (kv !== keyPath) changed++
            lines[i] = line.slice(0, indent) + mk[1] + keyPath + (mk[3] || '')
            continue
          }
        }
      }
    }
  }
  customConfigText.value = lines.join('\n')
  showToast(`已自动修正 ${changed} 处证书路径，请点击「更新 mihomo 服务端配置」保存生效。`, true)
}

async function submitCustomConfig() {
  if (!customConfigText.value.trim()) return
  await postAction('/config/custom', { custom_config_raw: customConfigText.value }, 'save-custom')
}

async function resetTemplateConfig() {
  if (!window.confirm('确定退出自定义配置模式并恢复为默认服务端模板？')) return
  await postAction('/config/reset-template', {}, 'reset-template')
}

onMounted(() => {
  if (boot.flash_msg) {
    showToast(boot.flash_msg, boot.flash_ok !== false)
  }
  try {
    const savedTab = sessionStorage.getItem('cs_tab')
    if (savedTab && ['inbounds', 'outbounds', 'server'].includes(savedTab)) {
      activeTab.value = savedTab
    }
  } catch {}
})

function selectTab(tab) {
  activeTab.value = tab
  try {
    sessionStorage.setItem('cs_tab', tab)
  } catch {}
}
</script>

<template>
  <!-- Login View -->
  <div
    v-if="pageMode === 'login'"
    class="min-h-screen flex items-center justify-center p-6 bg-gradient-to-br from-slate-900 via-slate-800 to-indigo-950"
  >
    <div class="w-full max-w-md bg-white/95 backdrop-blur rounded-2xl shadow-2xl border border-white/20 p-8">
      <div class="flex items-center gap-3.5 mb-6">
        <div
          class="w-11 h-11 rounded-xl bg-gradient-to-tr from-indigo-600 to-violet-500 text-white flex items-center justify-center font-bold text-lg shadow-lg shadow-indigo-500/30"
        >
          CS
        </div>
        <div>
          <div class="flex items-center gap-2">
            <h1 class="text-xl font-bold text-slate-900 tracking-tight">Clash Serve</h1>
            <span class="px-2 py-0.5 text-xs font-semibold rounded-full bg-indigo-50 text-indigo-600 border border-indigo-200/60">
              v{{ state.version }}
            </span>
          </div>
          <p class="text-xs text-slate-500 mt-0.5">请登录管理面板</p>
        </div>
      </div>

      <div
        v-if="boot.login_error"
        class="mb-5 rounded-xl bg-rose-50 border border-rose-200 px-4 py-3 text-sm text-rose-700 font-medium"
      >
        {{ boot.login_error }}
      </div>

      <form method="post" action="/login" class="space-y-4">
        <div>
          <label for="u" class="block text-xs font-semibold text-slate-700 mb-1.5">用户名</label>
          <input
            id="u"
            name="username"
            value="admin"
            autocomplete="username"
            required
            class="w-full h-10 px-3.5 rounded-xl border border-slate-300 bg-white text-sm text-slate-900 focus:outline-none focus:border-indigo-500 focus:ring-3 focus:ring-indigo-500/15 transition"
          />
        </div>
        <div>
          <label for="p" class="block text-xs font-semibold text-slate-700 mb-1.5">密码</label>
          <input
            id="p"
            name="password"
            type="password"
            autocomplete="current-password"
            placeholder="请输入面板密码"
            required
            autofocus
            class="w-full h-10 px-3.5 rounded-xl border border-slate-300 bg-white text-sm text-slate-900 focus:outline-none focus:border-indigo-500 focus:ring-3 focus:ring-indigo-500/15 transition"
          />
        </div>
        <button
          type="submit"
          class="w-full h-10 mt-2 rounded-xl bg-indigo-600 hover:bg-indigo-500 text-white font-semibold text-sm shadow-md shadow-indigo-600/20 transition cursor-pointer"
        >
          登 录
        </button>
      </form>
    </div>
  </div>

  <!-- Dashboard View -->
  <div v-else class="min-h-screen bg-slate-50 text-slate-900 flex flex-col">
    <!-- Toast Notification -->
    <transition
      enter-active-class="transition duration-200 ease-out"
      enter-from-class=" opacity-0 -translate-y-2"
      enter-to-class="opacity-100 translate-y-0"
      leave-active-class="transition duration-150 ease-in"
      leave-from-class="opacity-100 translate-y-0"
      leave-to-class="opacity-0 -translate-y-2"
    >
      <div
        v-if="toast.show"
        class="fixed top-16 right-6 z-50 max-w-md rounded-xl px-4 py-3 shadow-lg border flex items-center gap-2.5 text-sm font-medium"
        :class="
          toast.ok
            ? 'bg-emerald-50 border-emerald-200 text-emerald-900'
            : 'bg-rose-50 border-rose-200 text-rose-900'
        "
      >
        <span
          class="w-5 h-5 rounded-full flex items-center justify-center text-xs font-bold shrink-0"
          :class="toast.ok ? 'bg-emerald-500 text-white' : 'bg-rose-500 text-white'"
        >
          {{ toast.ok ? '✓' : '!' }}
        </span>
        <span class="break-all">{{ toast.msg }}</span>
      </div>
    </transition>

    <!-- Topbar (clean: single version badge, no hostname, no URL, no subtitle clutter) -->
    <header class="sticky top-0 z-30 bg-slate-900/95 backdrop-blur border-b border-slate-800 text-white">
      <div class="max-w-7xl mx-auto px-4 sm:px-6 h-14 flex items-center justify-between gap-4">
        <div class="flex items-center gap-3">
          <div
            class="w-8 h-8 rounded-lg bg-gradient-to-tr from-indigo-500 to-violet-500 flex items-center justify-center font-bold text-sm shadow-sm"
          >
            CS
          </div>
          <span class="font-bold text-base tracking-tight">Clash Serve</span>
          <span class="px-2 py-0.5 text-xs font-semibold rounded-full bg-indigo-500/20 text-indigo-300 border border-indigo-400/30">
            v{{ state.version }}
          </span>
        </div>

        <div class="flex items-center gap-2 flex-wrap">
          <button
            type="button"
            :disabled="busyKey === '/action/restart'"
            @click="postAction('/action/restart', {}, '/action/restart')"
            class="px-3 py-1.5 rounded-lg text-xs font-medium bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 text-white transition cursor-pointer"
          >
            {{ busyKey === '/action/restart' ? '重启中…' : '重启内核' }}
          </button>
          <button
            type="button"
            :disabled="busyKey === '/action/reload'"
            @click="postAction('/action/reload', {}, '/action/reload')"
            class="px-3 py-1.5 rounded-lg text-xs font-medium bg-slate-800 hover:bg-slate-700 border border-slate-700 disabled:opacity-50 text-slate-200 transition cursor-pointer"
          >
            {{ busyKey === '/action/reload' ? '重载中…' : '重载配置' }}
          </button>
          <button
            type="button"
            :disabled="busyKey === '/action/cert'"
            @click="postAction('/action/cert', {}, '/action/cert')"
            class="px-3 py-1.5 rounded-lg text-xs font-medium bg-slate-800 hover:bg-slate-700 border border-slate-700 disabled:opacity-50 text-slate-200 transition cursor-pointer"
          >
            {{ busyKey === '/action/cert' ? '续期中…' : '续期证书' }}
          </button>
          <form method="post" action="/logout" class="inline">
            <input type="hidden" name="csrf" :value="state.csrf" />
            <button
              type="submit"
              class="px-3 py-1.5 rounded-lg text-xs font-medium bg-slate-800/60 hover:bg-rose-500/20 hover:text-rose-300 border border-slate-700/80 text-slate-300 transition cursor-pointer"
            >
              退出
            </button>
          </form>
        </div>
      </div>
    </header>

    <!-- Main Container -->
    <main class="max-w-7xl w-full mx-auto px-4 sm:px-6 py-6 space-y-6 flex-1">
      <!-- Concise Status Strip (no version block, no PID, no uptime/since, no restarts, no /etc/clashserve) -->
      <div class="grid grid-cols-2 lg:grid-cols-4 gap-3.5">
        <div class="bg-white rounded-xl border border-slate-200/80 p-4 shadow-xs flex items-center justify-between">
          <div>
            <div class="text-xs font-medium text-slate-500">运行状态</div>
            <div class="mt-1 flex items-center gap-2">
              <span
                class="w-2.5 h-2.5 rounded-full"
                :class="{
                  'bg-emerald-500 ring-4 ring-emerald-500/20': state.status.state_cls === 'ok',
                  'bg-amber-500 ring-4 ring-amber-500/20': state.status.state_cls === 'warn',
                  'bg-rose-500 ring-4 ring-rose-500/20': state.status.state_cls !== 'ok' && state.status.state_cls !== 'warn',
                }"
              ></span>
              <span class="text-lg font-bold text-slate-900">{{ state.status.state_txt || '未知' }}</span>
            </div>
          </div>
        </div>

        <div class="bg-white rounded-xl border border-slate-200/80 p-4 shadow-xs">
          <div class="text-xs font-medium text-slate-500">入站监听</div>
          <div class="mt-1 flex items-baseline gap-1.5">
            <span class="text-lg font-bold text-slate-900">{{ state.status.inbound_listening ?? 0 }}</span>
            <span class="text-xs text-slate-500">/ {{ state.status.inbound_total ?? 0 }} 个端口监听中</span>
          </div>
        </div>

        <div class="bg-white rounded-xl border border-slate-200/80 p-4 shadow-xs">
          <div class="text-xs font-medium text-slate-500">服务端出站</div>
          <div class="mt-1 flex items-baseline gap-1.5">
            <span class="text-lg font-bold text-slate-900">
              {{ (state.status.outbound_nodes_count ?? 0) + (state.status.outbound_providers_count ?? 0) }}
            </span>
            <span class="text-xs text-slate-500">
              {{ state.status.outbound_nodes_count ?? 0 }} 节点 · {{ state.status.outbound_providers_count ?? 0 }} 订阅源
            </span>
          </div>
        </div>

        <div class="bg-white rounded-xl border border-slate-200/80 p-4 shadow-xs">
          <div class="text-xs font-medium text-slate-500">证书有效期</div>
          <div class="mt-1 flex items-baseline gap-1.5">
            <span class="text-lg font-bold text-slate-900">{{ certDisplay }}</span>
            <span v-if="state.status.cert_expires" class="text-xs text-slate-400 truncate">
              {{ state.status.cert_expires }}
            </span>
          </div>
        </div>
      </div>

      <!-- Segmented Navigation Tabs -->
      <div class="flex items-center gap-1.5 bg-white p-1.5 rounded-xl border border-slate-200/80 shadow-xs w-fit">
        <button
          type="button"
          @click="selectTab('inbounds')"
          class="px-4 py-2 rounded-lg text-sm font-semibold transition cursor-pointer"
          :class="
            activeTab === 'inbounds'
              ? 'bg-indigo-600 text-white shadow-xs'
              : 'text-slate-600 hover:text-slate-900 hover:bg-slate-100'
          "
        >
          入站与订阅
        </button>
        <button
          type="button"
          @click="selectTab('outbounds')"
          class="px-4 py-2 rounded-lg text-sm font-semibold transition cursor-pointer"
          :class="
            activeTab === 'outbounds'
              ? 'bg-indigo-600 text-white shadow-xs'
              : 'text-slate-600 hover:text-slate-900 hover:bg-slate-100'
          "
        >
          服务端出站
        </button>
        <button
          type="button"
          @click="selectTab('server')"
          class="px-4 py-2 rounded-lg text-sm font-semibold transition cursor-pointer"
          :class="
            activeTab === 'server'
              ? 'bg-indigo-600 text-white shadow-xs'
              : 'text-slate-600 hover:text-slate-900 hover:bg-slate-100'
          "
        >
          服务端配置
        </button>
      </div>

      <!-- TAB 1: 入站与客户端订阅 -->
      <div v-show="activeTab === 'inbounds'" class="space-y-6">
        <!-- 客户端订阅链接 (Concise, with 更换订阅链接 button) -->
        <section v-if="state.sub_url" class="bg-white rounded-2xl border border-slate-200/80 p-5 shadow-xs">
          <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
            <div class="flex items-center gap-2.5">
              <h2 class="text-base font-bold text-slate-900">客户端订阅链接</h2>
            </div>
            <div class="flex items-center gap-2 flex-wrap">
              <button
                type="button"
                @click="copyRaw(state.sub_url, 'sub-url')"
                class="px-3.5 py-1.5 rounded-lg text-xs font-semibold bg-indigo-600 hover:bg-indigo-500 text-white transition cursor-pointer"
              >
                {{ copiedKey === 'sub-url' ? '已复制' : '复制订阅链接' }}
              </button>
              <button
                type="button"
                :disabled="busyKey === 'reset-sub'"
                @click="resetSubUrl"
                class="px-3.5 py-1.5 rounded-lg text-xs font-semibold bg-amber-50 hover:bg-amber-100 text-amber-800 border border-amber-200 disabled:opacity-50 transition cursor-pointer"
              >
                {{ busyKey === 'reset-sub' ? '更换中…' : '更换订阅链接' }}
              </button>
              <a
                :href="state.sub_url"
                target="_blank"
                rel="noopener"
                class="px-3 py-1.5 rounded-lg text-xs font-medium bg-slate-100 hover:bg-slate-200 text-slate-700 transition"
              >
                预览
              </a>
            </div>
          </div>
          <div
            id="sub-url"
            class="mt-3 px-3.5 py-2.5 rounded-xl bg-slate-50 border border-slate-200/80 font-mono text-xs text-slate-700 break-all select-all"
          >
            {{ state.sub_url }}
          </div>
        </section>

        <!-- 入站节点列表 & 添加监听器表单 -->
        <div class="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
          <!-- Left: Inbound Nodes List -->
          <section class="lg:col-span-7 bg-white rounded-2xl border border-slate-200/80 p-5 shadow-xs">
            <div class="flex items-center justify-between gap-2 mb-4">
              <div class="flex items-center gap-2">
                <h2 class="text-base font-bold text-slate-900">入站节点</h2>
                <span class="px-2 py-0.5 text-xs font-semibold rounded-full bg-slate-100 text-slate-600">
                  {{ state.inbounds.length }}
                </span>
              </div>
              <button
                v-if="state.inbounds.length > 0"
                type="button"
                @click="copyRaw(state.all_proxies_yaml, 'all-proxies')"
                class="px-3 py-1.5 rounded-lg text-xs font-medium bg-slate-100 hover:bg-slate-200 text-slate-700 transition cursor-pointer"
              >
                {{ copiedKey === 'all-proxies' ? '已复制' : '复制全部配置' }}
              </button>
            </div>

            <div v-if="state.inbounds.length === 0" class="py-12 text-center text-sm text-slate-400">
              暂无入站节点，请在右侧添加监听器
            </div>

            <div v-else class="divide-y divide-slate-100 border border-slate-200/70 rounded-xl overflow-hidden">
              <div
                v-for="item in state.inbounds"
                :key="item.key"
                class="p-4 hover:bg-slate-50/80 transition flex flex-col sm:flex-row sm:items-center justify-between gap-3"
              >
                <div class="space-y-1 min-w-0">
                  <div class="flex items-center gap-2 flex-wrap">
                    <span class="font-bold text-sm text-slate-900 break-all">{{ item.name }}</span>
                    <span class="px-2 py-0.5 text-xs font-semibold rounded-md bg-indigo-50 text-indigo-700">
                      {{ item.kind_label }}
                    </span>
                    <span
                      class="inline-flex items-center gap-1 px-2 py-0.5 text-xs font-medium rounded-full"
                      :class="
                        item.listening
                          ? 'bg-emerald-50 text-emerald-700'
                          : 'bg-rose-50 text-rose-700'
                      "
                    >
                      <span
                        class="w-1.5 h-1.5 rounded-full"
                        :class="item.listening ? 'bg-emerald-500' : 'bg-rose-500'"
                      ></span>
                      {{ item.listening ? '监听中' : '未监听' }}
                    </span>
                  </div>
                  <div class="text-xs text-slate-500 font-mono">端口 :{{ item.port }}</div>
                </div>

                <!-- Two direct copy buttons (复制配置 & 复制易读配置) + 删除 -->
                <div class="flex items-center gap-2 shrink-0 flex-wrap">
                  <button
                    type="button"
                    @click="copyRaw(item.single_config, `single-${item.key}`)"
                    class="px-2.5 py-1.5 rounded-lg text-xs font-medium bg-white hover:bg-slate-100 text-slate-700 border border-slate-200/90 transition cursor-pointer"
                  >
                    {{ copiedKey === `single-${item.key}` ? '已复制' : '复制配置' }}
                  </button>
                  <button
                    type="button"
                    @click="copyRaw(item.readable_config, `multi-${item.key}`)"
                    class="px-2.5 py-1.5 rounded-lg text-xs font-medium bg-white hover:bg-slate-100 text-slate-700 border border-slate-200/90 transition cursor-pointer"
                  >
                    {{ copiedKey === `multi-${item.key}` ? '已复制' : '复制易读配置' }}
                  </button>
                  <button
                    type="button"
                    :disabled="busyKey === `del-${item.key}`"
                    @click="deleteInbound(item)"
                    class="px-2.5 py-1.5 rounded-lg text-xs font-medium text-rose-600 hover:bg-rose-50 border border-rose-200/80 disabled:opacity-50 transition cursor-pointer"
                  >
                    删除
                  </button>
                </div>
              </div>
            </div>
          </section>

          <!-- Right: Simplified Add Listener Form -->
          <section class="lg:col-span-5 bg-white rounded-2xl border border-slate-200/80 p-5 shadow-xs">
            <h2 class="text-base font-bold text-slate-900 mb-4">添加监听器</h2>

            <form @submit.prevent="submitAddInbound" class="space-y-3.5">
              <div>
                <label for="kind" class="block text-xs font-semibold text-slate-700 mb-1">协议类型</label>
                <select
                  id="kind"
                  v-model="inboundForm.kind"
                  name="kind"
                  class="w-full h-9 px-3 rounded-lg border border-slate-300 bg-white text-sm text-slate-900 focus:outline-none focus:border-indigo-500 focus:ring-2 focus:ring-indigo-500/15"
                >
                  <option v-for="p in PROTOCOLS" :key="p.value" :value="p.value">
                    {{ p.label }}
                  </option>
                </select>
              </div>

              <div class="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <div>
                  <label for="nm" class="block text-xs font-semibold text-slate-700 mb-1">节点名称</label>
                  <input
                    id="nm"
                    v-model="inboundForm.name"
                    name="name"
                    :placeholder="`默认 ${currentDefaultName}`"
                    class="w-full h-9 px-3 rounded-lg border border-slate-300 bg-white text-sm text-slate-900 focus:outline-none focus:border-indigo-500 focus:ring-2 focus:ring-indigo-500/15"
                  />
                </div>
                <div>
                  <label for="port" class="block text-xs font-semibold text-slate-700 mb-1">监听端口</label>
                  <input
                    id="port"
                    v-model="inboundForm.port"
                    name="port"
                    inputmode="numeric"
                    placeholder="留空随机端口"
                    class="w-full h-9 px-3 rounded-lg border border-slate-300 bg-white text-sm text-slate-900 focus:outline-none focus:border-indigo-500 focus:ring-2 focus:ring-indigo-500/15"
                  />
                </div>
              </div>

              <!-- VLESS Reality -->
              <template v-if="inboundForm.kind === 'vless-reality'">
                <div class="grid grid-cols-1 sm:grid-cols-2 gap-3">
                  <div>
                    <label class="block text-xs font-semibold text-slate-700 mb-1">伪装域名 (SNI)</label>
                    <input
                      v-model="inboundForm.reality_sni"
                      name="reality_sni"
                      placeholder="留空随机抽取"
                      class="w-full h-9 px-3 rounded-lg border border-slate-300 bg-white text-sm text-slate-900 focus:outline-none focus:border-indigo-500"
                    />
                  </div>
                  <div>
                    <label class="block text-xs font-semibold text-slate-700 mb-1">VLESS 加密</label>
                    <select
                      v-model="inboundForm.reality_enc"
                      name="reality_enc"
                      class="w-full h-9 px-3 rounded-lg border border-slate-300 bg-white text-sm text-slate-900 focus:outline-none focus:border-indigo-500"
                    >
                      <option value="x25519">启用 (默认)</option>
                      <option value="none">不启用</option>
                    </select>
                  </div>
                </div>
              </template>

              <!-- Shadowsocks -->
              <template v-else-if="inboundForm.kind === 'shadowsocks'">
                <div>
                  <label class="block text-xs font-semibold text-slate-700 mb-1">加密方式</label>
                  <select
                    v-model="inboundForm.ss_cipher"
                    name="ss_cipher"
                    class="w-full h-9 px-3 rounded-lg border border-slate-300 bg-white text-sm text-slate-900 focus:outline-none focus:border-indigo-500"
                  >
                    <option value="aes-128-gcm">aes-128-gcm (默认)</option>
                    <option value="aes-256-gcm">aes-256-gcm</option>
                  </select>
                </div>
              </template>

              <!-- Hysteria2 -->
              <template v-else-if="inboundForm.kind === 'hysteria2'">
                <div>
                  <label class="block text-xs font-semibold text-slate-700 mb-1">混淆密码 (选填)</label>
                  <input
                    v-model="inboundForm.hy2_obfs_pw"
                    name="hy2_obfs_pw"
                    placeholder="留空不启用"
                    class="w-full h-9 px-3 rounded-lg border border-slate-300 bg-white text-sm text-slate-900 focus:outline-none focus:border-indigo-500"
                  />
                </div>
              </template>

              <!-- Snell V5 (no version selector, default v5) -->
              <template v-else-if="inboundForm.kind === 'snell'">
                <div class="grid grid-cols-1 sm:grid-cols-2 gap-3">
                  <div>
                    <label class="block text-xs font-semibold text-slate-700 mb-1">混淆模式</label>
                    <select
                      v-model="inboundForm.snell_obfs"
                      name="snell_obfs"
                      class="w-full h-9 px-3 rounded-lg border border-slate-300 bg-white text-sm text-slate-900 focus:outline-none focus:border-indigo-500"
                    >
                      <option value="tls">tls (默认)</option>
                      <option value="http">http</option>
                    </select>
                  </div>
                  <div>
                    <label class="block text-xs font-semibold text-slate-700 mb-1">伪装 Host</label>
                    <input
                      v-model="inboundForm.snell_host"
                      name="snell_host"
                      placeholder="留空随机抽取"
                      class="w-full h-9 px-3 rounded-lg border border-slate-300 bg-white text-sm text-slate-900 focus:outline-none focus:border-indigo-500"
                    />
                  </div>
                </div>
              </template>

              <!-- AnyTLS (no Padding field in UI, random padding scheme generated internally) -->
              <template v-else-if="inboundForm.kind === 'anytls'">
                <div>
                  <label class="block text-xs font-semibold text-slate-700 mb-1">客户端 TLS 指纹</label>
                  <select
                    v-model="inboundForm.anytls_fp"
                    name="anytls_fp"
                    class="w-full h-9 px-3 rounded-lg border border-slate-300 bg-white text-sm text-slate-900 focus:outline-none focus:border-indigo-500"
                  >
                    <option value="chrome">chrome (默认)</option>
                    <option value="safari">safari</option>
                    <option value="firefox">firefox</option>
                    <option value="ios">ios</option>
                  </select>
                </div>
              </template>

              <!-- TUIC v5 -->
              <template v-else-if="inboundForm.kind === 'tuic'">
                <div>
                  <label class="block text-xs font-semibold text-slate-700 mb-1">拥塞控制</label>
                  <select
                    v-model="inboundForm.tuic_cc"
                    name="tuic_cc"
                    class="w-full h-9 px-3 rounded-lg border border-slate-300 bg-white text-sm text-slate-900 focus:outline-none focus:border-indigo-500"
                  >
                    <option value="bbr">bbr (默认)</option>
                    <option value="cubic">cubic</option>
                    <option value="new_reno">new_reno</option>
                  </select>
                </div>
              </template>

              <!-- TrustTunnel -->
              <template v-else-if="inboundForm.kind === 'trusttunnel'">
                <div>
                  <label class="block text-xs font-semibold text-slate-700 mb-1">拥塞控制</label>
                  <select
                    v-model="inboundForm.tt_cc"
                    name="tt_cc"
                    class="w-full h-9 px-3 rounded-lg border border-slate-300 bg-white text-sm text-slate-900 focus:outline-none focus:border-indigo-500"
                  >
                    <option value="bbr">bbr (默认)</option>
                    <option value="cubic">cubic</option>
                  </select>
                </div>
              </template>

              <!-- ShadowQUIC -->
              <template v-else-if="inboundForm.kind === 'shadowquic'">
                <div>
                  <label class="block text-xs font-semibold text-slate-700 mb-1">伪装地址 (JLS)</label>
                  <input
                    v-model="inboundForm.sq_jls"
                    name="sq_jls"
                    placeholder="默认 www.microsoft.com:443"
                    class="w-full h-9 px-3 rounded-lg border border-slate-300 bg-white text-sm text-slate-900 focus:outline-none focus:border-indigo-500"
                  />
                </div>
              </template>

              <!-- Mieru -->
              <template v-else-if="inboundForm.kind === 'mieru'">
                <div>
                  <label class="block text-xs font-semibold text-slate-700 mb-1">传输协议</label>
                  <select
                    v-model="inboundForm.mieru_transport"
                    name="mieru_transport"
                    class="w-full h-9 px-3 rounded-lg border border-slate-300 bg-white text-sm text-slate-900 focus:outline-none focus:border-indigo-500"
                  >
                    <option value="TCP">TCP (默认)</option>
                    <option value="UDP">UDP</option>
                  </select>
                </div>
              </template>

              <!-- Sudoku -->
              <template v-else-if="inboundForm.kind === 'sudoku'">
                <div>
                  <label class="block text-xs font-semibold text-slate-700 mb-1">AEAD 加密</label>
                  <select
                    v-model="inboundForm.sudoku_aead"
                    name="sudoku_aead"
                    class="w-full h-9 px-3 rounded-lg border border-slate-300 bg-white text-sm text-slate-900 focus:outline-none focus:border-indigo-500"
                  >
                    <option value="chacha20-poly1305">chacha20-poly1305 (默认)</option>
                    <option value="aes-128-gcm">aes-128-gcm</option>
                    <option value="none">none</option>
                  </select>
                </div>
              </template>

              <!-- HTTP -->
              <template v-else-if="inboundForm.kind === 'http'">
                <div>
                  <label class="block text-xs font-semibold text-slate-700 mb-1">启用 TLS</label>
                  <select
                    v-model="inboundForm.http_tls"
                    name="http_tls"
                    class="w-full h-9 px-3 rounded-lg border border-slate-300 bg-white text-sm text-slate-900 focus:outline-none focus:border-indigo-500"
                  >
                    <option value="0">不启用 (默认)</option>
                    <option value="1">启用</option>
                  </select>
                </div>
              </template>

              <!-- SOCKS5 -->
              <template v-else-if="inboundForm.kind === 'socks'">
                <div>
                  <label class="block text-xs font-semibold text-slate-700 mb-1">启用 TLS</label>
                  <select
                    v-model="inboundForm.socks_tls"
                    name="socks_tls"
                    class="w-full h-9 px-3 rounded-lg border border-slate-300 bg-white text-sm text-slate-900 focus:outline-none focus:border-indigo-500"
                  >
                    <option value="0">不启用 (默认)</option>
                    <option value="1">启用</option>
                  </select>
                </div>
              </template>

              <button
                type="submit"
                :disabled="busyKey === 'add-inbound'"
                class="w-full h-9 mt-2 rounded-lg bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 text-white text-sm font-semibold transition cursor-pointer"
              >
                {{ busyKey === 'add-inbound' ? '正在添加…' : '添加入站节点' }}
              </button>
            </form>
          </section>
        </div>
      </div>

      <!-- TAB 2: 服务端出站与外部订阅 -->
      <div v-show="activeTab === 'outbounds'" class="space-y-6">
        <!-- 导入外部订阅 (proxy-providers) -->
        <section class="bg-white rounded-2xl border border-slate-200/80 p-5 shadow-xs space-y-4">
          <div class="flex items-center gap-2">
            <h2 class="text-base font-bold text-slate-900">外部订阅源 (proxy-providers)</h2>
            <span class="px-2 py-0.5 text-xs font-semibold rounded-full bg-slate-100 text-slate-600">
              {{ state.providers.length }}
            </span>
          </div>

          <div
            v-if="state.providers.length > 0"
            class="divide-y divide-slate-100 border border-slate-200/70 rounded-xl overflow-hidden"
          >
            <div
              v-for="prov in state.providers"
              :key="prov.name"
              class="p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-3"
            >
              <div class="min-w-0 space-y-1">
                <div class="flex items-center gap-2">
                  <span class="font-bold text-sm text-slate-900">{{ prov.name }}</span>
                  <span class="text-xs font-mono text-slate-500">{{ prov.path }}</span>
                </div>
                <div class="text-xs text-slate-400 font-mono truncate">{{ prov.url }}</div>
              </div>
              <div class="flex items-center gap-2 shrink-0">
                <button
                  type="button"
                  @click="copyRaw(prov.yaml, `prov-${prov.name}`)"
                  class="px-2.5 py-1.5 rounded-lg text-xs font-medium bg-white hover:bg-slate-100 text-slate-700 border border-slate-200/90 transition cursor-pointer"
                >
                  {{ copiedKey === `prov-${prov.name}` ? '已复制' : '复制配置' }}
                </button>
                <button
                  type="button"
                  :disabled="busyKey === `del-prov-${prov.name}`"
                  @click="deleteProvider(prov.name)"
                  class="px-2.5 py-1.5 rounded-lg text-xs font-medium text-rose-600 hover:bg-rose-50 border border-rose-200/80 disabled:opacity-50 transition cursor-pointer"
                >
                  删除
                </button>
              </div>
            </div>
          </div>

          <form @submit.prevent="submitAddProvider" class="grid grid-cols-1 sm:grid-cols-12 gap-3 items-end">
            <div class="sm:col-span-7">
              <label class="block text-xs font-semibold text-slate-700 mb-1">订阅链接 (HTTP / HTTPS)</label>
              <input
                v-model="providerForm.sub_url"
                name="sub_url"
                placeholder="https://example.com/sub.yaml?token=..."
                required
                class="w-full h-9 px-3 rounded-lg border border-slate-300 bg-white text-sm text-slate-900 focus:outline-none focus:border-indigo-500"
              />
            </div>
            <div class="sm:col-span-3">
              <label class="block text-xs font-semibold text-slate-700 mb-1">名称 (选填)</label>
              <input
                v-model="providerForm.provider_name"
                name="provider_name"
                placeholder="默认 sub"
                class="w-full h-9 px-3 rounded-lg border border-slate-300 bg-white text-sm text-slate-900 focus:outline-none focus:border-indigo-500"
              />
            </div>
            <div class="sm:col-span-2">
              <button
                type="submit"
                :disabled="busyKey === 'add-provider'"
                class="w-full h-9 rounded-lg bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 text-white text-xs font-semibold transition cursor-pointer"
              >
                {{ busyKey === 'add-provider' ? '导入中…' : '导入订阅' }}
              </button>
            </div>
          </form>
        </section>

        <!-- 服务端手工出站节点 (proxies) -->
        <section class="bg-white rounded-2xl border border-slate-200/80 p-5 shadow-xs space-y-4">
          <div class="flex items-center gap-2">
            <h2 class="text-base font-bold text-slate-900">服务端出站节点 (proxies)</h2>
            <span class="px-2 py-0.5 text-xs font-semibold rounded-full bg-slate-100 text-slate-600">
              {{ state.proxies.length }}
            </span>
          </div>

          <div
            v-if="state.proxies.length > 0"
            class="divide-y divide-slate-100 border border-slate-200/70 rounded-xl overflow-hidden"
          >
            <div
              v-for="p in state.proxies"
              :key="p.name"
              class="p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-3"
            >
              <div class="space-y-1 min-w-0">
                <div class="flex items-center gap-2 flex-wrap">
                  <span class="font-bold text-sm text-slate-900 break-all">{{ p.name }}</span>
                  <span class="px-2 py-0.5 text-xs font-semibold rounded-md bg-indigo-50 text-indigo-700">
                    {{ p.type }}
                  </span>
                </div>
                <div class="text-xs text-slate-500 font-mono">{{ p.endpoint }}</div>
              </div>
              <div class="flex items-center gap-2 shrink-0 flex-wrap">
                <button
                  type="button"
                  @click="copyRaw(p.single_config, `p-single-${p.name}`)"
                  class="px-2.5 py-1.5 rounded-lg text-xs font-medium bg-white hover:bg-slate-100 text-slate-700 border border-slate-200/90 transition cursor-pointer"
                >
                  {{ copiedKey === `p-single-${p.name}` ? '已复制' : '复制配置' }}
                </button>
                <button
                  type="button"
                  @click="copyRaw(p.readable_config, `p-multi-${p.name}`)"
                  class="px-2.5 py-1.5 rounded-lg text-xs font-medium bg-white hover:bg-slate-100 text-slate-700 border border-slate-200/90 transition cursor-pointer"
                >
                  {{ copiedKey === `p-multi-${p.name}` ? '已复制' : '复制易读配置' }}
                </button>
                <button
                  type="button"
                  :disabled="busyKey === `del-proxy-${p.name}`"
                  @click="deleteProxy(p.name)"
                  class="px-2.5 py-1.5 rounded-lg text-xs font-medium text-rose-600 hover:bg-rose-50 border border-rose-200/80 disabled:opacity-50 transition cursor-pointer"
                >
                  删除
                </button>
              </div>
            </div>
          </div>

          <form @submit.prevent="submitAddProxies" class="space-y-3">
            <textarea
              v-model="proxiesRaw"
              name="proxies_raw"
              rows="5"
              placeholder="粘贴单行 JSON / Flow 或多行 YAML 格式的 mihomo 节点配置…"
              class="w-full p-3 rounded-xl border border-slate-300 bg-slate-50 font-mono text-xs text-slate-900 focus:bg-white focus:outline-none focus:border-indigo-500"
            ></textarea>
            <div class="flex items-center gap-2.5 flex-wrap">
              <button
                type="submit"
                :disabled="busyKey === 'add-proxies'"
                class="px-4 py-2 rounded-lg bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 text-white text-xs font-semibold transition cursor-pointer"
              >
                {{ busyKey === 'add-proxies' ? '添加中…' : '添加出站节点' }}
              </button>
              <label
                class="px-3 py-2 rounded-lg bg-slate-100 hover:bg-slate-200 text-slate-700 text-xs font-medium transition cursor-pointer"
              >
                从文件载入
                <input
                  type="file"
                  accept=".yaml,.yml,.json,.txt"
                  class="hidden"
                  @change="(e) => loadFileInto(e, proxiesRaw)"
                />
              </label>
            </div>
          </form>
        </section>
      </div>

      <!-- TAB 3: 服务端配置 -->
      <div v-show="activeTab === 'server'" class="space-y-6">
        <!-- Zashboard 与服务端运行配置 -->
        <section class="bg-white rounded-2xl border border-slate-200/80 p-5 shadow-xs space-y-4">
          <div class="flex items-center justify-between gap-3 flex-wrap">
            <div class="flex items-center gap-2.5">
              <h2 class="text-base font-bold text-slate-900">Zashboard 控制面板</h2>
              <span
                class="inline-flex items-center gap-1 px-2.5 py-0.5 text-xs font-semibold rounded-full"
                :class="
                  state.controller_listening
                    ? 'bg-emerald-50 text-emerald-700'
                    : 'bg-amber-50 text-amber-700'
                "
              >
                端口 :{{ state.controller_port }} {{ state.controller_listening ? '监听中' : '未监听' }}
              </span>
            </div>
            <div class="flex items-center gap-2 flex-wrap">
              <a
                :href="state.zb_url || '#'"
                target="_blank"
                rel="noopener"
                class="px-3.5 py-1.5 rounded-lg text-xs font-semibold bg-indigo-600 hover:bg-indigo-500 text-white transition"
              >
                打开 Zashboard
              </a>
              <button
                type="button"
                @click="copyRaw(state.zb_url, 'zb-url')"
                class="px-3 py-1.5 rounded-lg text-xs font-medium bg-slate-100 hover:bg-slate-200 text-slate-700 transition cursor-pointer"
              >
                {{ copiedKey === 'zb-url' ? '已复制' : '复制地址' }}
              </button>
              <button
                type="button"
                :disabled="busyKey === 'reset-secret'"
                @click="resetZbSecret"
                class="px-3 py-1.5 rounded-lg text-xs font-medium bg-slate-100 hover:bg-slate-200 text-slate-700 disabled:opacity-50 transition cursor-pointer"
              >
                重置 API 密钥
              </button>
              <a
                href="/config/server.yaml"
                target="_blank"
                rel="noopener"
                class="px-3 py-1.5 rounded-lg text-xs font-medium bg-slate-100 hover:bg-slate-200 text-slate-700 transition"
              >
                查看运行配置
              </a>
            </div>
          </div>
          <div
            id="zb-url"
            class="px-3.5 py-2.5 rounded-xl bg-slate-50 border border-slate-200/80 font-mono text-xs text-slate-600 break-all select-all"
          >
            {{ state.zb_url || '—' }}
          </div>
        </section>

        <!-- 自定义服务端配置 -->
        <section class="bg-white rounded-2xl border border-slate-200/80 p-5 shadow-xs space-y-4">
          <div class="flex items-center justify-between gap-3 flex-wrap">
            <div class="flex items-center gap-2.5">
              <h2 class="text-base font-bold text-slate-900">自定义 mihomo 服务端配置</h2>
              <span
                class="px-2.5 py-0.5 text-xs font-semibold rounded-full"
                :class="
                  state.custom_config_mode
                    ? 'bg-amber-50 text-amber-700'
                    : 'bg-emerald-50 text-emerald-700'
                "
              >
                {{ state.custom_config_mode ? '自定义配置模式' : '标准模板模式' }}
              </span>
            </div>
            <button
              v-if="state.custom_config_mode"
              type="button"
              :disabled="busyKey === 'reset-template'"
              @click="resetTemplateConfig"
              class="px-3 py-1.5 rounded-lg text-xs font-medium text-rose-600 hover:bg-rose-50 border border-rose-200/80 disabled:opacity-50 transition cursor-pointer"
            >
              恢复默认模板
            </button>
          </div>

          <form @submit.prevent="submitCustomConfig" class="space-y-3">
            <textarea
              id="custom-config-raw"
              v-model="customConfigText"
              name="custom_config_raw"
              rows="14"
              placeholder="在此粘贴完整的 mihomo 服务端 YAML 配置…"
              class="w-full p-3.5 rounded-xl border border-slate-700 bg-slate-900 text-slate-100 font-mono text-xs leading-relaxed focus:outline-none focus:border-indigo-500"
            ></textarea>
            <div class="flex items-center gap-2.5 flex-wrap">
              <button
                type="button"
                @click="autoFixCertPaths"
                class="px-3.5 py-2 rounded-lg bg-amber-50 hover:bg-amber-100 text-amber-800 border border-amber-200 text-xs font-semibold transition cursor-pointer"
              >
                自动修改证书路径
              </button>
              <button
                type="submit"
                :disabled="busyKey === 'save-custom'"
                class="px-4 py-2 rounded-lg bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 text-white text-xs font-semibold transition cursor-pointer"
              >
                {{ busyKey === 'save-custom' ? '正在校验并更新…' : '更新 mihomo 服务端配置' }}
              </button>
              <label
                class="px-3 py-2 rounded-lg bg-slate-100 hover:bg-slate-200 text-slate-700 text-xs font-medium transition cursor-pointer"
              >
                从本地文件载入
                <input
                  type="file"
                  accept=".yaml,.yml,.txt"
                  class="hidden"
                  @change="(e) => loadFileInto(e, customConfigText)"
                />
              </label>
              <button
                type="button"
                @click="copyRaw(customConfigText, 'custom-cfg')"
                class="px-3 py-2 rounded-lg bg-slate-100 hover:bg-slate-200 text-slate-700 text-xs font-medium transition cursor-pointer"
              >
                {{ copiedKey === 'custom-cfg' ? '已复制' : '复制当前配置' }}
              </button>
            </div>
          </form>
        </section>
      </div>
    </main>
  </div>
</template>

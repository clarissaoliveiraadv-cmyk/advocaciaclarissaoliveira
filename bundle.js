// ── Error handler global — captura erros silenciosos e exibe toast ──
window.onerror = function(msg, src, line, col, err){
  var txt = '⚠ Erro: ' + (msg||'desconhecido');
  if(line) txt += ' (L'+line+')';
  if(typeof showToast==='function') showToast(txt);
  console.error('[CO]', msg, src, line, col, err);
  return false;
};
window.addEventListener('unhandledrejection', function(e){
  var msg = e.reason ? (e.reason.message||String(e.reason)) : 'Promise rejeitada';
  // Filtrar erros benignos que não valem um toast pro usuário:
  // - Falhas transientes de update do Service Worker (GitHub Pages 404)
  // - AbortError de timeouts intencionais (fetch com AbortSignal.timeout)
  if(/ServiceWorker/i.test(msg) || /AbortError/i.test(msg) || /aborted/i.test(msg)){
    console.debug('[CO] rejection benigna ignorada:', msg);
    return;
  }
  if(typeof showToast==='function') showToast('⚠ ' + msg);
  console.error('[CO] unhandledrejection:', e.reason);
});

// Utilitários globais (definidos antes de tudo para garantir disponibilidade)
function fDt(d){ if(!d) return '—'; var p=String(d).split('-'); return p.length===3?p[2]+'/'+p[1]+'/'+p[0]:d; }
// ═══════════════════════════════════════════════════════
// ══ SUPABASE — sincronização em nuvem ══
// ═══════════════════════════════════════════════════════
//
// NOTA DE SEGURANÇA:
// A chave abaixo é uma "anon key" do Supabase (token público).
// É PROJETADA para ficar no client-side — a proteção real vem
// das RLS (Row Level Security) policies configuradas no Supabase.
// NÃO é uma service_role key — não dá acesso admin.
//
var _SB_CFG = (function(){
  var _p = ['aWFsZ2xvZ2F5dHd6ZG9oZmprb','mc','c3VwYWJhc2UuY28'];
  var _u = 'https://'+atob(_p[0]+'mc')+'.'+atob(_p[2]);
  var _k = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImlhbGdsb2dheXR3emRvaGZqa25nIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NzMxMzkwMTAsImV4cCI6MjA4ODcxNTAxMH0.wvNm_hSA78yxP0w2mv0AeeuHeQeaXo3xxBcWwphpecg';
  return {url:_u, key:_k};
})();
var _SB_URL = _SB_CFG.url;
var _SB_KEY = _SB_CFG.key;
var _SB_TBL = 'escritorio_dados';

// ═══════════════════════════════════════════════════════
// ══ AUTENTICAÇÃO — Supabase Auth (gate de acesso) ═══
// ═══════════════════════════════════════════════════════
//
// Fluxo:
// 1. Usuário abre o app → authBoot() checa sessão em localStorage
// 2. Se sessão válida → roda init() normalmente
// 3. Se ausente/expirada → mostra tela de login (#auth-overlay)
// 4. Após login, _sbSession é preenchido e init() é chamado
// 5. _sbH() usa o access_token do usuário no header Authorization
//
var _sbSession = null;  // {access_token, refresh_token, expires_at, user:{id,email}}
var _sbPerfil = null;   // {nome, perfil} da tabela perfis (carregado após login)

function _authLoadSession(){
  try {
    var s = localStorage.getItem('co_session');
    if(!s) return null;
    var sess = JSON.parse(s);
    // Checar validade
    if(!sess || !sess.access_token || !sess.expires_at) return null;
    var now = Math.floor(Date.now()/1000);
    // Se já expirou completamente, descartar
    if(sess.expires_at <= now) return null;
    return sess;
  } catch(e){ return null; }
}

function _authSaveSession(sess){
  _sbSession = sess;
  if(sess){
    try { localStorage.setItem('co_session', JSON.stringify(sess)); } catch(e){}
    if(sess.user && sess.user.email){
      _sbUsuario = sess.user.email.split('@')[0];
      try { localStorage.setItem('co_usuario', _sbUsuario); } catch(e){}
    }
  } else {
    try { localStorage.removeItem('co_session'); } catch(e){}
  }
}

async function authLogin(email, password){
  var r = await fetch(_SB_URL+'/auth/v1/token?grant_type=password', {
    method:'POST',
    headers:{'Content-Type':'application/json', 'apikey':_SB_KEY},
    body: JSON.stringify({email:email, password:password})
  });
  var data = await r.json();
  if(!r.ok){
    throw new Error(data.error_description || data.msg || data.message || 'Falha no login');
  }
  // Resposta: {access_token, refresh_token, expires_in, expires_at, user:{id,email,...}}
  _authSaveSession(data);
  return data;
}

async function authMagicLink(email){
  var r = await fetch(_SB_URL+'/auth/v1/otp', {
    method:'POST',
    headers:{'Content-Type':'application/json', 'apikey':_SB_KEY},
    body: JSON.stringify({email:email, create_user:false})
  });
  if(!r.ok){
    var data = await r.json().catch(()=>({}));
    throw new Error(data.error_description || data.msg || data.message || 'Falha ao enviar link');
  }
  return true;
}

// Pede ao Supabase um e-mail de recuperação de senha. O link no e-mail
// volta para o app com #type=recovery&access_token=... — _authHandleHash
// detecta isso e mostra a tela de "Defina uma nova senha".
async function authResetSenha(email){
  var redirectTo = window.location.origin + window.location.pathname;
  var r = await fetch(_SB_URL+'/auth/v1/recover', {
    method:'POST',
    headers:{'Content-Type':'application/json', 'apikey':_SB_KEY},
    body: JSON.stringify({email:email, redirect_to:redirectTo})
  });
  if(!r.ok){
    var data = await r.json().catch(()=>({}));
    throw new Error(data.error_description || data.msg || data.message || 'Falha ao enviar e-mail de recuperação');
  }
  return true;
}

// Atualiza a senha do usuário logado (precisa de access_token válido —
// vindo do hash de recovery ou de uma sessão ativa).
async function authAtualizarSenha(novaSenha){
  if(!_sbSession || !_sbSession.access_token) throw new Error('Sessão inválida');
  var r = await fetch(_SB_URL+'/auth/v1/user', {
    method:'PUT',
    headers:{
      'Content-Type':'application/json',
      'apikey':_SB_KEY,
      'Authorization':'Bearer '+_sbSession.access_token
    },
    body: JSON.stringify({password: novaSenha})
  });
  if(!r.ok){
    var data = await r.json().catch(()=>({}));
    throw new Error(data.error_description || data.msg || data.message || 'Falha ao atualizar senha');
  }
  return true;
}

async function authRefresh(){
  if(!_sbSession || !_sbSession.refresh_token) return false;
  try {
    var r = await fetch(_SB_URL+'/auth/v1/token?grant_type=refresh_token', {
      method:'POST',
      headers:{'Content-Type':'application/json', 'apikey':_SB_KEY},
      body: JSON.stringify({refresh_token: _sbSession.refresh_token})
    });
    if(!r.ok) return false;
    var data = await r.json();
    _authSaveSession(data);
    return true;
  } catch(e){ return false; }
}

async function authLogout(){
  if(_sbSession && _sbSession.access_token){
    try {
      await fetch(_SB_URL+'/auth/v1/logout', {
        method:'POST',
        headers:{'apikey':_SB_KEY, 'Authorization':'Bearer '+_sbSession.access_token}
      });
    } catch(e){}
  }
  _authSaveSession(null);
  _sbPerfil = null;
  window.location.reload();
}

async function authCarregarPerfil(){
  if(!_sbSession || !_sbSession.user) return null;
  try {
    var r = await fetch(_SB_URL+'/rest/v1/perfis?id=eq.'+_sbSession.user.id+'&select=nome,perfil', {
      headers:{'apikey':_SB_KEY, 'Authorization':'Bearer '+_sbSession.access_token}
    });
    if(!r.ok) return null;
    var rows = await r.json();
    if(rows && rows.length){
      _sbPerfil = rows[0];
      return _sbPerfil;
    }
  } catch(e){}
  return null;
}

// Auto-refresh 5 min antes de expirar
function _authScheduleRefresh(){
  if(!_sbSession || !_sbSession.expires_at) return;
  var now = Math.floor(Date.now()/1000);
  var ms = (_sbSession.expires_at - now - 300) * 1000;
  if(ms < 1000) ms = 1000;
  setTimeout(async ()=>{
    var ok = await authRefresh();
    if(ok) _authScheduleRefresh();
  }, ms);
}

// ═══════════════════════════════════════════════════════
// ══ APIs PÚBLICAS — ViaCEP + BrasilAPI CNPJ ══════════
// ═══════════════════════════════════════════════════════
//
// Usadas no cadastro para auto-preencher endereço/razão social.
// Ambas são públicas (sem chave) e suportam CORS direto do browser.

async function _buscarCep(cepStr){
  var cep = String(cepStr||'').replace(/\D/g,'');
  if(cep.length !== 8) return null;
  try {
    var r = await fetch('https://viacep.com.br/ws/'+cep+'/json/', {signal: AbortSignal.timeout(5000)});
    if(!r.ok) return null;
    var data = await r.json();
    if(data.erro) return null;
    return {
      rua: data.logradouro||'',
      bairro: data.bairro||'',
      cidade: data.localidade||'',
      uf: data.uf||''
    };
  } catch(e){ return null; }
}

async function _buscarCnpj(cnpjStr){
  var cnpj = String(cnpjStr||'').replace(/\D/g,'');
  if(cnpj.length !== 14) return null;
  try {
    var r = await fetch('https://brasilapi.com.br/api/cnpj/v1/'+cnpj, {signal: AbortSignal.timeout(8000)});
    if(!r.ok) return null;
    var data = await r.json();
    var cepFmt = String(data.cep||'').replace(/\D/g,'').replace(/(\d{5})(\d{3})/,'$1-$2');
    var nomeFinal = data.nome_fantasia || data.razao_social || '';
    return {
      nome: nomeFinal,
      razao_social: data.razao_social||'',
      nome_fantasia: data.nome_fantasia||'',
      cep: cepFmt,
      rua: data.logradouro||'',
      num: String(data.numero||''),
      complemento: data.complemento||'',
      bairro: data.bairro||'',
      cidade: data.municipio||'',
      uf: data.uf||'',
      email: data.email||'',
      tel: data.ddd_telefone_1||''
    };
  } catch(e){ return null; }
}

// Preenche campos de endereço dado um prefixo de id (ex: 'nc', 'ec').
// Só escreve em campos vazios — não sobrescreve o que o usuário já digitou.
async function _preencherCepFields(prefixo){
  var cepEl = document.getElementById(prefixo+'-cep');
  if(!cepEl) return;
  var btn = document.getElementById(prefixo+'-cep-btn');
  if(btn){ btn.textContent='⏳'; btn.disabled=true; }
  try {
    var data = await _buscarCep(cepEl.value);
    if(!data){ if(typeof showToast==='function') showToast('CEP não encontrado'); return; }
    ['rua','bairro','cidade','uf'].forEach(function(f){
      var el = document.getElementById(prefixo+'-'+f);
      if(el && !el.value && data[f]) el.value = data[f];
    });
    if(typeof showToast==='function') showToast('✓ Endereço preenchido');
  } finally {
    if(btn){ btn.textContent='🔍'; btn.disabled=false; }
  }
}
window._preencherCepFields = _preencherCepFields;

async function _preencherCnpjFields(prefixo){
  var docEl = document.getElementById(prefixo+'-doc') || document.getElementById(prefixo+'-cpf');
  if(!docEl) return;
  var btn = document.getElementById(prefixo+'-cnpj-btn');
  if(btn){ btn.textContent='⏳'; btn.disabled=true; }
  try {
    var data = await _buscarCnpj(docEl.value);
    if(!data){ if(typeof showToast==='function') showToast('CNPJ não encontrado'); return; }
    var map = {nome:'nome', cep:'cep', rua:'rua', num:'num', complemento:'comp',
               bairro:'bairro', cidade:'cidade', uf:'uf', email:'email', tel:'tel'};
    Object.keys(map).forEach(function(apiKey){
      var fieldSuffix = map[apiKey];
      var el = document.getElementById(prefixo+'-'+fieldSuffix);
      if(el && !el.value && data[apiKey]) el.value = data[apiKey];
    });
    if(typeof showToast==='function') showToast('✓ Dados da empresa preenchidos');
  } finally {
    if(btn){ btn.textContent='🔍'; btn.disabled=false; }
  }
}
window._preencherCnpjFields = _preencherCnpjFields;

var _SB_SYNC = new Set([
  'co_tasks','co_vktasks','co_fin','co_localLanc','co_ag','co_encerrados','co_notes','co_ctc','co_consultas','co_colab','co_despfixas','co_td','co_tarefasDia','co_t','co_n','co_localAg','co_localMov','co_localLanc','co_desp_proc','co_coments','co_atend','co_clientes','co_clientes_consulta','co_iniciais','co_prazos',
  // Tombstones: DEVEM sincronizar entre PCs, senão deleção feita num PC
  // fica invisível para o outro (filtro por tombstone só existe localmente).
  'co_fin_del','co_localLanc_del','co_clientes_del','co_ctc_del',
  'co_vktasks_del','co_ag_del','co_localAg_del','co_atend_del',
  'co_projuris_del'
]);

var _sbOnline = false;
var _sbUsuario = localStorage.getItem('co_usuario')||'clarissa';
// ID único desta sessão/aba — evita que realtime ignore updates do mesmo usuário em outro computador
var _sbSessionId = 'sess_'+Date.now()+'_'+Math.random().toString(36).slice(2,6);

// ═══════════════════════════════════════════════════════
// ══ ISOLAMENTO POR USUÁRIO — prefixo nas chaves ══════
// ═══════════════════════════════════════════════════════
//
// Cada usuário tem suas chaves no localStorage prefixadas.
// Evita vazamento de dados ao trocar de conta.
//
function _lsKey(chave){
  // Escritório compartilhado — todos os usuários acessam os mesmos dados
  // Prefixo removido para garantir sync entre computadores
  return chave;
}

// Wrappers de localStorage com prefixo por usuário
function lsGet(chave){
  var v = localStorage.getItem(chave);
  if(v!==null) return v;
  // Fallback: tentar com prefixo antigo (migração)
  var prefixado = localStorage.getItem(_sbUsuario+'::'+chave);
  if(prefixado!==null){
    localStorage.setItem(chave, prefixado); // migrar
    return prefixado;
  }
  return null;
}

function lsSet(chave, valor){
  try {
    localStorage.setItem(_lsKey(chave), valor);
  } catch(e){
    console.error('[Storage] Quota excedida:', chave);
    _sbCheckQuota();
  }
}

function lsRemove(chave){
  localStorage.removeItem(_lsKey(chave));
}

// ═══════════════════════════════════════════════════════
// ══ RESOLUÇÃO DE CONFLITO — merge por array ══════════
// ═══════════════════════════════════════════════════════
//
// Estratégia: para arrays (co_fin, co_localLanc, etc),
// merge por ID — mantém items de ambos, remoto + local.
// Para objetos simples: last-write-wins com versão.
//
function _sbMergeArrays(local, remote, chave){
  if(!Array.isArray(local) || !Array.isArray(remote)) return remote;
  // Tombstones: filtrar IDs deletados de AMBOS os lados antes de mergear
  var tombstones = (chave && typeof _arrayTombstones !== 'undefined') ? _tombstoneLoad(chave) : null;
  function _isTombstoned(item){
    if(!tombstones) return false;
    var id = item.id||item.id_agenda||item._id;
    return id != null && tombstones.has(String(id));
  }
  // Ordem de preferência para timestamp de "quando foi editado":
  // 1. updated_at (carimbado por nós em toda edição) — fonte de verdade
  // 2. dt_baixa / data (campos de negócio, usado como fallback pra dados antigos)
  function _ts(item){
    return item.updated_at||item._updated_at||item.dt_baixa||item.data||'';
  }
  // Criar Map do remoto por ID (excluindo tombstoned)
  var map = new Map();
  remote.forEach(function(item){
    if(_isTombstoned(item)) return;
    var id = item.id||item.id_agenda||item._id||JSON.stringify(item);
    map.set(String(id), item);
  });
  // Adicionar itens locais que não existem no remoto (também respeitando tombstone)
  local.forEach(function(item){
    if(_isTombstoned(item)) return;
    var id = item.id||item.id_agenda||item._id||JSON.stringify(item);
    var k = String(id);
    if(!map.has(k)){
      map.set(k, item); // item local não existe no remoto → preservar
    } else {
      var r = map.get(k);
      var localTs = _ts(item);
      var remoteTs = _ts(r);
      // Local vence em empate (>=), pois o usuário acabou de editar
      if(localTs >= remoteTs) map.set(k, item);
    }
  });
  return Array.from(map.values());
}

// Merge profundo para objetos cujo valor é um array (ex: co_localMov = {cid: [movs]})
// Une as chaves e, para cada chave presente em ambos, mergea os arrays por conteúdo
// (hash estável dos campos relevantes) para não perder entradas criadas em PCs diferentes.
function _sbMergeObjectOfArrays(local, remote){
  var out = {};
  var keys = new Set();
  Object.keys(local||{}).forEach(function(k){ keys.add(k); });
  Object.keys(remote||{}).forEach(function(k){ keys.add(k); });
  function _movKey(m){
    if(!m) return '';
    if(m.id) return 'id:'+m.id;
    // Fallback: hash dos campos essenciais (data+movimentacao+tipo)
    return (m.data||'')+'|'+(m.movimentacao||m.texto||m.desc||'')+'|'+(m.tipo_movimentacao||m.tipo||'')+'|'+(m.origem||'');
  }
  keys.forEach(function(k){
    var a = Array.isArray(local[k]) ? local[k] : [];
    var b = Array.isArray(remote[k]) ? remote[k] : [];
    if(!a.length){ out[k] = b.slice(); return; }
    if(!b.length){ out[k] = a.slice(); return; }
    // União por chave de conteúdo — ordena por data descendente
    var map = new Map();
    a.forEach(function(m){ map.set(_movKey(m), m); });
    b.forEach(function(m){
      var mk = _movKey(m);
      if(!map.has(mk)) map.set(mk, m);
    });
    var merged = Array.from(map.values());
    merged.sort(function(x,y){ return (y.data||'').localeCompare(x.data||''); });
    out[k] = merged;
  });
  return out;
}

function _sbMerge(chave, localVal, remoteVal){
  // Chaves de tombstone: union de sets
  if(typeof chave==='string' && chave.endsWith('_del') && Array.isArray(remoteVal)){
    var u = new Set();
    if(Array.isArray(localVal)) localVal.forEach(function(x){ u.add(String(x)); });
    remoteVal.forEach(function(x){ u.add(String(x)); });
    return Array.from(u);
  }
  // Arrays: merge por ID (com tombstone)
  if(Array.isArray(localVal) && Array.isArray(remoteVal)){
    return _sbMergeArrays(localVal, remoteVal, chave);
  }
  // Objetos-de-arrays: co_localMov {clienteId: [movs]}, co_coments {cid: [coments]}
  // Merge profundo: para cada chave, mergea os arrays internos por conteúdo
  if(chave==='co_localMov' || chave==='co_coments' || chave==='co_notes'){
    if(localVal && remoteVal && typeof localVal==='object' && typeof remoteVal==='object'
       && !Array.isArray(localVal)){
      return _sbMergeObjectOfArrays(localVal, remoteVal);
    }
  }
  // Objetos (prazos, encerrados): merge de chaves
  if(localVal && remoteVal && typeof localVal==='object' && typeof remoteVal==='object'
     && !Array.isArray(localVal)){
    return Object.assign({}, remoteVal, localVal); // local tem prioridade
  }
  // Primitivos: remoto vence (cloud = source of truth)
  return remoteVal;
}

// ═══════════════════════════════════════════════════════
// ══ DEBOUNCE + QUOTA + HEADERS ═══════════════════════
// ═══════════════════════════════════════════════════════

var _sbSetTimers = {};
var _sbSetPending = {};
function sbSetDebounced(chave, valor){
  // CRÍTICO: salvar no localStorage IMEDIATAMENTE — sem esperar o debounce.
  // Sem isso, há uma janela de 300-900ms onde o dado só existe em memória.
  // Se o usuário fechar a aba, dar F5, ou o browser crashar nessa janela,
  // o dado é PERDIDO (ex: cliente "Reinaldo Chaves Batista" sumiu).
  try{ lsSet(chave, JSON.stringify(valor)); }catch(e){}
  // Debounce apenas o POST ao Supabase (operação de rede, cara, pode esperar)
  _sbSetPending[chave] = valor;
  clearTimeout(_sbSetTimers[chave]);
  _sbSetTimers[chave] = setTimeout(function(){ sbSet(chave, _sbSetPending[chave]); delete _sbSetPending[chave]; }, 300);
}

function _sbCheckQuota(){
  try {
    var total = 0, prefix = _sbUsuario+'::';
    for(var i=0; i<localStorage.length; i++){
      var k = localStorage.key(i);
      total += (localStorage.getItem(k)||'').length;
    }
    if(total > 4000000){
      console.warn('[Storage] Uso alto: '+(total/1024/1024).toFixed(1)+'MB de ~5MB');
      for(var j=localStorage.length-1; j>=0; j--){
        var key = localStorage.key(j);
        if(key && key.indexOf('_ts_')!==-1) localStorage.removeItem(key);
      }
    }
  } catch(e){}
}
setInterval(_sbCheckQuota, 300000);

// ── beforeunload: flush saves pendentes antes da aba fechar ──
// Sem isso, sbSetDebounced agenda um timer de 300ms. Se o usuário
// fecha a aba em <300ms, o POST nunca dispara e o dado se perde.
// O lsSet imediato (fix acima) já protege o localStorage, mas o
// Supabase ainda precisa do POST. Usamos navigator.sendBeacon
// como fallback (funciona mesmo com a aba fechando).
window.addEventListener('beforeunload', function(){
  var keys = Object.keys(_sbSetPending);
  if(!keys.length) return;
  keys.forEach(function(chave){
    var valor = _sbSetPending[chave];
    if(!valor) return;
    // Garantir lsSet (redundante com o fix no sbSetDebounced, mas seguro)
    try{ lsSet(chave, JSON.stringify(valor)); }catch(e){}
    // Tentar enviar ao Supabase via sendBeacon (non-blocking, funciona no unload)
    try{
      if(navigator.sendBeacon && _SB_SYNC.has(chave)){
        navigator.sendBeacon(
          _SB_URL+'/rest/v1/'+_SB_TBL,
          new Blob([JSON.stringify({
            chave: chave, valor: valor,
            updated_at: new Date().toISOString(),
            updated_by: _sbUsuario,
            _session_id: _sbSessionId
          })], {type:'application/json'})
        );
      }
    }catch(e){}
    delete _sbSetPending[chave];
  });
});

function _sbH(){
  // Com usuário logado, Authorization usa o access_token (JWT do usuário).
  // Isso permite que RLS policies como auth.uid() funcionem nas tabelas novas.
  // Sem login, cai no anon key — útil só durante migração/testes da tabela legada.
  var token = (_sbSession && _sbSession.access_token) ? _sbSession.access_token : _SB_KEY;
  return {
    'Content-Type':'application/json',
    'apikey': _SB_KEY,
    'Authorization': 'Bearer '+token
  };
}

function _sbStatus(online){
  _sbOnline = online;
  var el = document.getElementById('sb-dot');
  if(el) el.style.background = online ? '#22c55e' : '#ef4444';
  var lb = document.getElementById('sb-label');
  if(lb) lb.textContent = online ? 'Nuvem' : 'Local';
}

// ═══════════════════════════════════════════════════════
// ══ sbSet / sbGet / sbCarregarTudo (com merge) ═══════
// ═══════════════════════════════════════════════════════

// Chaves de array que precisam de read-modify-write antes de salvar
// (para evitar que um cliente stale sobrescreva o trabalho de outro).
var _SB_MERGED_KEYS = new Set(['co_fin','co_localLanc','co_clientes','co_ctc','co_vktasks','co_ag','co_localAg','co_atend']);
// Chaves de objeto-de-arrays que precisam de merge profundo NO RECEBIMENTO (Realtime).
// NÃO fazem read-modify-write no ENVIO (sbSet), porque o RMW re-insere itens deletados
// — o GET remoto ainda tem o item, o merge-union o traz de volta.
// A proteção contra concurrent writes fica por conta do Realtime (sbAplicar + _sbMergeObjectOfArrays).
var _SB_MERGED_OBJ_KEYS = new Set(['co_localMov','co_coments','co_notes']);
// Cooldown: após salvar uma chave de objeto-de-arrays, ignorar Realtime events
// dessa chave por X ms. Sem isso, o Realtime traz o valor ANTIGO (do antes do
// nosso POST completar) e o merge-union re-insere itens que acabamos de deletar.
var _sbObjWriteTs = {};  // {chave: timestamp do último save local}
var _SB_OBJ_COOLDOWN_MS = 5000; // 5 segundos de proteção após save

async function sbSet(chave, valor){
  // Carimbar updated_at nos itens modificados de arrays financeiros
  // (co_localLanc, co_fin) antes de salvar. Crítico para _sbMergeArrays
  // não reverter edições locais quando o Realtime chegar com versão antiga.
  if((chave==='co_localLanc'||chave==='co_fin') && Array.isArray(valor)){
    try{
      var _prev = {};
      var _prevArr = JSON.parse(lsGet(chave)||'[]');
      if(Array.isArray(_prevArr)){
        _prevArr.forEach(function(p){ if(p && p.id!=null) _prev[String(p.id)] = p; });
      }
      var _nowIso = new Date().toISOString();
      valor.forEach(function(item){
        if(!item||item.id==null) return;
        var old = _prev[String(item.id)];
        // Item novo ou item com alteração detectada → carimbar
        if(!old){
          if(!item.updated_at) item.updated_at = _nowIso;
          return;
        }
        // Comparar campos-chave para detectar alteração real
        var changed = false;
        var keys = ['desc','valor','valor_integral','valor_parcela','percentual_honorarios',
                    'parceiro_nome','parceiro_percentual','ressarcimento','data','venc','forma',
                    'pago','status','recebido','dt_baixa','obs','tipo','cat','_vbruto','_honperc',
                    '_parceiro','_parceiro_perc','_parceiro_val','_tipo_parc','_parcela','_total_parc'];
        for(var ki=0; ki<keys.length; ki++){
          var k = keys[ki];
          if(JSON.stringify(item[k]) !== JSON.stringify(old[k])){ changed = true; break; }
        }
        if(changed) item.updated_at = _nowIso;
      });
    }catch(e){}
  }
  // ═══ READ-MODIFY-WRITE para arrays sincronizados ═══
  // Sem isso, dois clientes que salvam simultaneamente se sobrescrevem
  // (Postgrest UPSERT substitui a coluna valor inteira, não faz merge de JSON).
  // Fluxo: ler remoto → mergear com local → escrever resultado merged.
  // NOTA: não gatear por _sbOnline — tentar o GET mesmo se "offline"; se
  // voltar, é sinal de que a conexão voltou e não ficamos presos off-line.
  if(_SB_MERGED_KEYS.has(chave) && Array.isArray(valor)){
    try{
      var _r0 = await fetch(
        _SB_URL+'/rest/v1/'+_SB_TBL+'?chave=eq.'+encodeURIComponent(chave)+'&select=valor',
        {headers:_sbH(), signal:AbortSignal.timeout(3000)}
      );
      if(_r0.ok){
        var _rows0 = await _r0.json();
        if(_rows0.length && Array.isArray(_rows0[0].valor)){
          // Merge: remote + local → resultado consistente sem perder dados de ninguém
          valor = _sbMergeArrays(valor, _rows0[0].valor, chave);
        }
        if(!_sbOnline) _sbStatus(true); // GET funcionou → reconectado
      }
    }catch(e){}
  }
  // Objetos-de-arrays: marcar timestamp do save para o cooldown do Realtime.
  if(_SB_MERGED_OBJ_KEYS.has(chave)) _sbObjWriteTs[chave] = Date.now();
  lsSet(chave, JSON.stringify(valor));
  lsSet('_ts_'+chave, new Date().toISOString());
  if(!_SB_SYNC.has(chave)) return;
  // CRÍTICO: NÃO gatear por _sbOnline aqui. Se a última request falhou,
  // _sbOnline virou false — mas a próxima pode funcionar. Gatear silencioso
  // causava sync travada até o usuário dar F5.
  // Ao invés de bloquear, sempre tentar. Se falhar, _sbStatus(false) é setado
  // pelo próprio sbSet no final. Se funcionar, _sbStatus(true) é setado no sucesso.
  for(var _retry=0; _retry<2; _retry++){
    try{
      var r = await fetch(_SB_URL+'/rest/v1/'+_SB_TBL, {
        method:'POST',
        headers:Object.assign({}, _sbH(), {'Prefer':'resolution=merge-duplicates,return=minimal'}),
        body: JSON.stringify({chave:chave, valor:valor,
          updated_at: new Date().toISOString(),
          updated_by: _sbUsuario,
          _session_id: _sbSessionId
        })
      });
      if(r.ok){
        // POST ok → garantir indicador verde (pode ter vindo de false)
        if(!_sbOnline) _sbStatus(true);
        return;
      }
      // 4xx: não adianta retry (auth/permissão), mas marca offline
      if(r.status < 500){ _sbStatus(false); return; }
    }catch(e){
      if(_retry===0) await new Promise(function(ok){setTimeout(ok, 1000);});
    }
  }
  _sbStatus(false);
}

async function sbGet(chave){
  // Não gatear por _sbOnline — tentar o GET mesmo se "offline", para
  // reconectar automaticamente. Fallback ao localStorage se o fetch falhar.
  if(!_SB_SYNC.has(chave)){
    try { return JSON.parse(lsGet(chave)||'null'); } catch(e){ return null; }
  }
  try{
    var r = await fetch(
      _SB_URL+'/rest/v1/'+_SB_TBL+'?chave=eq.'+encodeURIComponent(chave)+'&select=valor',
      {headers:_sbH()}
    );
    var rows = await r.json();
    if(rows.length) return rows[0].valor;
    return JSON.parse(lsGet(chave)||'null');
  }catch(e){
    try { return JSON.parse(lsGet(chave)||'null'); } catch(pe){ return null; }
  }
}

async function sbCarregarTudo(){
  try{
    var r = await fetch(
      _SB_URL+'/rest/v1/'+_SB_TBL+'?select=chave,valor,updated_at',
      {headers:_sbH(), signal:AbortSignal.timeout(5000)}
    );
    if(!r.ok) throw new Error(r.status);
    var rows = await r.json();
    // IMPORTANTE: carregar TOMBSTONES PRIMEIRO — só depois aplicar os dados.
    // Senão, dados com IDs tombstoneados são carregados e só filtrados tarde demais.
    rows.filter(function(row){ return /_del$/.test(row.chave); }).forEach(function(row){
      try{
        var localVal = JSON.parse(lsGet(row.chave)||'null');
        var merged = _sbMerge(row.chave, localVal, row.valor);
        lsSet(row.chave, JSON.stringify(merged));
        // Atualiza o Set em memória
        if(typeof sbAplicar === 'function') sbAplicar(row.chave, merged, row.updated_by);
      }catch(e){}
    });
    rows.forEach(function(row){
      // Tombstones já processados acima
      if(/_del$/.test(row.chave)) return;
      var tsLocal = lsGet('_ts_'+row.chave)||'';
      var tsRemoto = row.updated_at||'';
      if(tsLocal && tsLocal > tsRemoto){
        // Local mais recente — merge e re-sync
        try {
          var localVal = JSON.parse(lsGet(row.chave)||'null');
          var merged = _sbMerge(row.chave, localVal, row.valor);
          lsSet(row.chave, JSON.stringify(merged));
          sbSet(row.chave, merged);
        } catch(pe){ console.warn('[Sync] Parse erro:', row.chave); }
        return;
      }
      // Remoto mais recente — merge com local
      try {
        var localVal2 = JSON.parse(lsGet(row.chave)||'null');
        var merged2 = localVal2 ? _sbMerge(row.chave, localVal2, row.valor) : row.valor;
        lsSet(row.chave, JSON.stringify(merged2));
        lsSet('_ts_'+row.chave, tsRemoto);
      } catch(qe){ console.error('[Storage] Erro ao salvar '+row.chave); }
    });
    _sbStatus(true);
    return true;
  }catch(e){ _sbStatus(false); return false; }
}


// Realtime — escuta mudanças de outras usuárias
function sbRealtime(){
  try{
    // Se já existe um WS aberto, não criar outro
    if(window._sbWs && window._sbWs.readyState === 1) return;
    // Se tem um em conexão, descartar (não cria duplicata)
    if(window._sbWs && window._sbWs.readyState === 0){ try{ window._sbWs.close(); }catch(e){} }
    const ws = new WebSocket(
      _SB_URL.replace('https://','wss://')+
      `/realtime/v1/websocket?apikey=${_SB_KEY}&vsn=1.0.0`
    );
    window._sbWs = ws;
    window._sbWsLastState = 0;
    ws.onopen = ()=>{
      window._sbWsLastState = 1;
      console.debug('[SB Realtime] WebSocket aberto');
      ws.send(JSON.stringify({
        topic:`realtime:public:${_SB_TBL}`,
        event:'phx_join',
        payload:{config:{postgres_changes:[
          {event:'*',schema:'public',table:_SB_TBL}
        ]}},
        ref:'1'
      }));
      // Heartbeat a cada 25s — limpa intervalo anterior se houver
      if(window._sbHeartbeat) clearInterval(window._sbHeartbeat);
      window._sbHeartbeat = setInterval(()=>ws.readyState===1&&ws.send(JSON.stringify(
        {topic:'phoenix',event:'heartbeat',payload:{},ref:'hb'}
      )),25000);
    };
    ws.onerror = (err)=>{
      window._sbWsLastState = 3;
      console.debug('[SB Realtime] erro no WebSocket:', err);
      if(window._sbHeartbeat) clearInterval(window._sbHeartbeat);
    };
    ws.onmessage = e=>{
      try{
        const msg = JSON.parse(e.data);
        const rec = msg.payload?.data?.record;
        if(!rec) return;
        // Ignorar apenas updates DESTA sessão (não de outro computador do mesmo usuário)
        if(rec._session_id && rec._session_id===_sbSessionId) return;
        const {chave,updated_by} = rec;
        // Parse defensivo: valor pode vir como string JSON (dependendo de
        // como o Postgrest serializa jsonb no webhook) — tentar parsear se
        // for string antes de passar pro merge.
        var valor = rec.valor;
        if(typeof valor === 'string'){
          try{ valor = JSON.parse(valor); }catch(pe){ /* mantém string se não for JSON */ }
        }
        // Cooldown: se acabamos de salvar esta chave de objeto-de-arrays localmente,
        // ignorar Realtime events por _SB_OBJ_COOLDOWN_MS para não re-inserir itens deletados.
        // O Realtime pode trazer o valor ANTIGO (de antes do nosso POST completar).
        if(_SB_MERGED_OBJ_KEYS.has(chave) && _sbObjWriteTs[chave] &&
           (Date.now() - _sbObjWriteTs[chave]) < _SB_OBJ_COOLDOWN_MS){
          console.debug('[SB Realtime] cooldown ativo para', chave, '— ignorando evento');
          return; // nosso save local é mais recente, ignorar este evento
        }
        // Merge com dados locais antes de aplicar
        try {
          var localVal = JSON.parse(lsGet(chave)||'null');
          var merged = localVal ? _sbMerge(chave, localVal, valor) : valor;
          lsSet(chave, JSON.stringify(merged));
          sbAplicar(chave, merged, updated_by);
        } catch(me){ lsSet(chave, JSON.stringify(valor)); sbAplicar(chave, valor, updated_by); }
      }catch{}
    };
    ws.onclose = ()=>{
      window._sbWsLastState = 3;
      console.debug('[SB Realtime] WebSocket fechado, reconectando em 5s');
      if(window._sbHeartbeat) clearInterval(window._sbHeartbeat);
      setTimeout(sbRealtime, 5000);
    };
  }catch(e){ console.debug('[SB Realtime] erro ao criar WebSocket:', e); }
}

function sbAplicar(chave, valor, quem){
  var n = {clarissa:'Clarissa',assistente:'Assistente',financeiro:'Financeiro'}[quem]||quem;
  // Chaves de tombstone: atualizar o Set em memória para bloquear ressuscitação
  if(typeof chave==='string' && chave.endsWith('_del') && Array.isArray(valor)){
    var baseKey = chave.slice(0, -4);
    // Tratamento especial para co_projuris_del (usa chaves compostas, não IDs)
    if(baseKey==='co_projuris'){
      if(typeof _projurisDeletados !== 'undefined'){
        var prjSet = new Set();
        valor.forEach(function(k){ prjSet.add(String(k)); });
        _projurisDeletados.clear();
        prjSet.forEach(function(k){ _projurisDeletados.add(k); });
      }
      return;
    }
    if(typeof _arrayTombstones !== 'undefined'){
      var set = new Set();
      valor.forEach(function(id){ set.add(String(id)); });
      _arrayTombstones[baseKey] = set;
    }
    // Filtrar o array em memória conforme a chave base
    if(baseKey==='co_fin' && Array.isArray(finLancs)){
      finLancs = finLancs.filter(function(x){ return !_tombstoneHas('co_fin', x.id); });
    } else if(baseKey==='co_localLanc' && Array.isArray(localLanc)){
      localLanc = localLanc.filter(function(x){ return !_tombstoneHas('co_localLanc', x.id); });
    } else if(baseKey==='co_clientes' && typeof CLIENTS!=='undefined' && Array.isArray(CLIENTS)){
      var cFilt = CLIENTS.filter(function(x){ return !_tombstoneHas('co_clientes', x.id); });
      CLIENTS.length = 0; cFilt.forEach(function(c){ CLIENTS.push(c); });
      _clientByIdCache={}; _clientByNameCache={};
      if(typeof montarClientesAgrupados==='function') montarClientesAgrupados();
      if(typeof doSearch==='function') doSearch();
    } else if(baseKey==='co_ctc' && Array.isArray(localContatos)){
      localContatos = localContatos.filter(function(x){ return !_tombstoneHas('co_ctc', x.id); });
      if(typeof invalidarCtcCache==='function') invalidarCtcCache();
    } else if(baseKey==='co_vktasks' && Array.isArray(vkTasks)){
      vkTasks = vkTasks.filter(function(x){ return !_tombstoneHas('co_vktasks', x.id); });
      if(typeof renderChecklist==='function') try{ renderChecklist(); }catch(e){}
    } else if((baseKey==='co_ag'||baseKey==='co_localAg') && Array.isArray(localAg)){
      localAg = localAg.filter(function(x){ return !_tombstoneHas(baseKey, x.id); });
      if(typeof invalidarAllPend==='function') invalidarAllPend();
    } else if(baseKey==='co_atend' && Array.isArray(localAtend)){
      localAtend = localAtend.filter(function(x){ return !_tombstoneHas('co_atend', x.id); });
    }
    if(document.getElementById('vf')?.classList.contains('on')) vfRender();
    return;
  }
  switch(chave){
    case 'co_vktasks':
      // Filtrar tombstones ao receber (anti-zombificação — se o array chegou
      // antes do tombstone num race, não deixamos itens deletados ressuscitarem)
      vkTasks=(valor||[]).filter(function(x){ return !_tombstoneHas('co_vktasks', x.id); });
      if(document.getElementById('vkt')?.classList.contains('on')) vkRender();
      break;
    case 'co_fin':
      // Filtrar tombstones ao receber do remoto (anti-zombificação)
      finLancs=(valor||[]).filter(function(x){ return !_tombstoneHas('co_fin', x.id); });
      if(document.getElementById('vf')?.classList.contains('on')) vfRender();
      break;
    case 'co_localLanc':
      localLanc=(valor||[]).filter(function(x){ return !_tombstoneHas('co_localLanc', x.id); });
      _finLocaisCache={};
      if(document.getElementById('vf')?.classList.contains('on')) vfRender();
      break;
    case 'co_localMov':
      localMov=valor||{};
      // Re-render da ficha do cliente se o usuário está com ela aberta
      // (sem isso, andamentos adicionados por outro PC não aparecem até recarregar)
      if(typeof AC!=='undefined' && AC && typeof renderFicha==='function'){
        try{ renderFicha(AC); }catch(e){}
      }
      if(document.getElementById('vf')?.classList.contains('on')) vfRender();
      break;
    case 'co_localAg':
      localAg=(valor||[]).filter(function(x){ return !_tombstoneHas('co_localAg', x.id) && !_tombstoneHas('co_ag', x.id); });
      invalidarAllPend();
      if(typeof AC!=='undefined' && AC && typeof renderFicha==='function'){ try{ renderFicha(AC); }catch(e){} }
      if(typeof renderHomeAlerts==='function') try{ renderHomeAlerts(); }catch(e){}
      if(typeof renderHomeWeek==='function') try{ renderHomeWeek(); }catch(e){}
      break;
    case 'co_ag':
      localAg=(valor||[]).filter(function(x){ return !_tombstoneHas('co_ag', x.id) && !_tombstoneHas('co_localAg', x.id); });
      invalidarAllPend();
      if(typeof AC!=='undefined' && AC && typeof renderFicha==='function'){ try{ renderFicha(AC); }catch(e){} }
      if(typeof renderHomeAlerts==='function') try{ renderHomeAlerts(); }catch(e){}
      break;
    case 'co_encerrados': encerrados=valor||{}; _encIdsCache=null; if(typeof doSearch==='function') try{ doSearch(); }catch(e){} break;
    case 'co_notes':
      notes=valor||{};
      if(typeof AC!=='undefined' && AC && typeof renderFicha==='function'){ try{ renderFicha(AC); }catch(e){} }
      break;
    case 'co_ctc':
      localContatos=(valor||[]).filter(function(x){ return !_tombstoneHas('co_ctc', x.id); });
      invalidarCtcCache();
      if(document.getElementById('ctc-view')?.classList.contains('on') && typeof ctcRender==='function'){ try{ ctcRender(); }catch(e){} }
      break;
    case 'co_tasks':
      if(typeof tasks!=='undefined') tasks=valor||{};
      if(typeof AC!=='undefined' && AC && typeof renderFicha==='function'){ try{ renderFicha(AC); }catch(e){} }
      if(typeof renderHomeAlerts==='function') try{ renderHomeAlerts(); }catch(e){}
      break;
    case 'co_td': case 'co_prazos':
      prazos=valor||{};
      if(typeof AC!=='undefined' && AC && typeof renderFicha==='function'){ try{ renderFicha(AC); }catch(e){} }
      break;
    case 'co_colab': if(typeof _colaboradores!=='undefined') _colaboradores=valor||[]; break;
    case 'co_despfixas': if(typeof _despFixas!=='undefined') _despFixas=valor||[]; break;
    case 'co_coments':
      if(typeof comentarios!=='undefined') comentarios=valor||{};
      if(typeof AC!=='undefined' && AC && typeof renderFicha==='function'){ try{ renderFicha(AC); }catch(e){} }
      break;
    case 'co_atend':
      if(typeof localAtend!=='undefined'){
        localAtend=(valor||[]).filter(function(x){ return !_tombstoneHas('co_atend', x.id); });
      }
      if(document.getElementById('at')?.classList.contains('on') && typeof atRender==='function'){ try{ atRender(); }catch(e){} }
      break;
    case 'co_clientes':
      if(typeof CLIENTS!=='undefined' && Array.isArray(valor)){
        // Merge com tombstones: passa 'co_clientes' como chave para que
        // clientes excluídos não ressuscitem via sync.
        var merged = _sbMergeArrays(CLIENTS, valor, 'co_clientes');
        CLIENTS.length=0; merged.forEach(function(c){CLIENTS.push(c);});
        _clientByIdCache={}; _clientByNameCache={};
        if(typeof montarClientesAgrupados==='function') montarClientesAgrupados();
        if(typeof doSearch==='function') doSearch();
        // Se o usuário está vendo a ficha de um cliente, re-renderiza
        // para que mudanças de parte/polo/pasta apareçam imediatamente.
        if(typeof AC!=='undefined' && AC && typeof renderFicha==='function'){
          try{ renderFicha(AC); }catch(e){}
        }
      } break;
    case 'co_clientes_consulta': break; // ignorar — tudo está em co_clientes agora
    case 'co_audit': if(typeof _auditLog!=='undefined') _auditLog=valor||[]; break;
    case 'co_iniciais': if(typeof _iniciais!=='undefined') _iniciais=valor||[]; break;
  }
  if(n && n!==_sbUsuario) showToast('\u2601 '+n+' atualizou '+chave.replace('co_',''));
}


function sbSetUsuario(u){
  _sbUsuario=u; localStorage.setItem('co_usuario',u);
  const n={clarissa:'Clarissa',assistente:'Assistente',financeiro:'Financeiro'}[u]||u;
  showToast('Logado como '+n+' ✓');
  sbAtualizarNome();
}

function sbAtualizarNome(){
  const el=document.getElementById('sb-usuario');
  const n={clarissa:'Clarissa',assistente:'Assistente',financeiro:'Financeiro'}[_sbUsuario]||_sbUsuario;
  if(el) el.textContent=n;
}

// Watchdog de reconexão: a cada 30s, se estivermos offline, tenta
// resincronizar. Também tenta se o WebSocket do Realtime estiver fechado.
// Isso evita que o app fique "preso" offline depois de um hiccup de rede.
var _sbWatchdogStarted = false;
function sbStartWatchdog(){
  if(_sbWatchdogStarted) return;
  _sbWatchdogStarted = true;
  setInterval(async function(){
    try{
      // Se perdeu o status online, tentar recarregar tudo
      if(!_sbOnline){
        console.debug('[SB] watchdog: offline detectado, tentando reconectar...');
        await sbCarregarTudo();
        if(_sbOnline) console.debug('[SB] watchdog: reconectado ✓');
      }
      // Se o WebSocket não está aberto, reiniciar
      // (ws.onclose já agenda reconexão, mas pode falhar silencioso)
      if(window._sbWsLastState !== 1){
        // Força reabrir — sbRealtime é idempotente
        try{ sbRealtime(); }catch(e){}
      }
    }catch(e){ console.debug('[SB] watchdog erro:', e); }
  }, 30000);
}

// Função global exposta para debug: força ressincronização completa da nuvem
// Uso: abrir console do browser (F12) e digitar coForceSync()
window.coForceSync = async function(){
  console.log('[coForceSync] Iniciando ressincronização completa...');
  try{
    var ok = await sbCarregarTudo();
    console.log('[coForceSync] sbCarregarTudo:', ok ? 'OK' : 'FALHA');
    if(typeof sbCarregarClientes === 'function'){
      var clientes = await sbCarregarClientes();
      console.log('[coForceSync] sbCarregarClientes:', clientes ? 'OK' : 'sem dados');
    }
    if(typeof sbRealtime === 'function') sbRealtime();
    if(typeof doSearch === 'function') doSearch();
    if(typeof renderFicha === 'function' && typeof AC !== 'undefined' && AC) renderFicha(AC);
    if(typeof vfRender === 'function' && document.getElementById('vf')?.classList.contains('on')) vfRender();
    if(typeof showToast === 'function') showToast('🔄 Ressincronização completa');
    return 'OK';
  }catch(e){
    console.error('[coForceSync] erro:', e);
    return 'ERRO: ' + (e.message || e);
  }
};

// Diagnóstico: mostra estado local x remoto. Uso: F12 → Console → coDiagnose()
window.coDiagnose = async function(){
  console.log('%c=== DIAGNÓSTICO DE SYNC ===','font-weight:bold;color:#60a5fa');
  console.log('Usuário:', _sbUsuario, '| Session:', _sbSessionId);
  console.log('Online:', _sbOnline, '| WS state:', window._sbWsLastState);
  console.log('---');
  function count(x){ return Array.isArray(x) ? x.length : (typeof x==='object'&&x ? Object.keys(x).length : 0); }
  // Contagem de clientes ativos (como aparece no dashboard): total - encerrados - consultas
  var encSet = getEncIds();
  var ativos = CLIENTS.filter(function(c){ return !encSet.has(c.id) && c.tipo!=='consulta'; }).length;
  var consultas = CLIENTS.filter(function(c){ return c.tipo==='consulta'; }).length;
  var arquivados = CLIENTS.filter(function(c){ return encSet.has(c.id); }).length;
  console.log('%cCLIENTES:','font-weight:bold');
  console.log('  Total no CLIENTS array:', CLIENTS.length);
  console.log('  → Ativos (mostrado no dashboard):', ativos);
  console.log('  → Consultas:', consultas);
  console.log('  → Arquivados (encerrados):', arquivados);
  console.log('  Total encerrados (object keys):', Object.keys(encerrados||{}).length);
  console.log('---');
  var locals = {
    localLanc: count(localLanc),
    finLancs: count(finLancs),
    localContatos: count(localContatos),
    vkTasks: count(vkTasks),
    localAg: count(localAg),
    localMov: count(localMov),
    localAtend: count(localAtend),
    tasks_clientes: count(tasks),
    notes_clientes: count(notes),
    prazos_clientes: count(prazos)
  };
  console.log('LOCAL (outras memórias):', locals);
  var tombs = {};
  ['co_fin','co_localLanc','co_clientes','co_ctc','co_vktasks','co_ag','co_localAg','co_atend'].forEach(function(k){
    var set = _tombstoneLoad(k);
    tombs[k] = set.size;
  });
  tombs['co_projuris'] = _projurisDeletados ? _projurisDeletados.size : 0;
  console.log('TOMBSTONES (itens marcados como deletados):', tombs);
  console.log('---');
  // Buscar remoto
  try{
    var r = await fetch(_SB_URL+'/rest/v1/'+_SB_TBL+'?select=chave,valor',{headers:_sbH()});
    if(!r.ok){ console.error('Erro ao buscar remoto:', r.status); return; }
    var rows = await r.json();
    var remotos = {};
    var remotoClientes = null;
    var remotoEncerrados = null;
    rows.forEach(function(row){
      var v = typeof row.valor==='string' ? JSON.parse(row.valor) : row.valor;
      remotos[row.chave] = count(v);
      if(row.chave==='co_clientes') remotoClientes = v;
      if(row.chave==='co_encerrados') remotoEncerrados = v;
    });
    console.log('REMOTO (Supabase):', remotos);
    if(Array.isArray(remotoClientes)){
      var rEncSet = new Set([...Object.keys(remotoEncerrados||{}).map(Number),...Object.keys(remotoEncerrados||{})]);
      var rAtivos = remotoClientes.filter(function(c){ return !rEncSet.has(c.id)&&c.tipo!=='consulta'; }).length;
      console.log('  → Ativos no remoto:', rAtivos);
    }
    console.log('---');
    // Diffs críticos
    var diffs = [];
    if(remotos.co_clientes && CLIENTS.length !== remotos.co_clientes){
      diffs.push('CLIENTS total: local='+CLIENTS.length+' remoto='+remotos.co_clientes);
    }
    if(remotos.co_encerrados !== undefined && Object.keys(encerrados||{}).length !== remotos.co_encerrados){
      diffs.push('ENCERRADOS: local='+Object.keys(encerrados||{}).length+' remoto='+remotos.co_encerrados);
    }
    if(remotos.co_localLanc && locals.localLanc !== remotos.co_localLanc){
      diffs.push('LOCALLANC: local='+locals.localLanc+' remoto='+remotos.co_localLanc);
    }
    if(diffs.length){
      console.warn('%c⚠ DIVERGÊNCIAS:','font-weight:bold;color:#f87676', diffs);
      console.log('→ Rodar coForceSync() para ressincronizar');
    } else {
      console.log('%c✓ Sem divergências detectadas','color:#4ade80');
    }
  }catch(e){ console.error('Erro no diagnóstico:', e); }
  console.log('---');
  console.log('Comandos úteis:');
  console.log('  coForceSync()       → ressincroniza com a nuvem');
  console.log('  coVerEncerrados()   → lista IDs e nomes dos encerrados');
  console.log('  coReativarTodos()   → desarquiva todos (cuidado!)');
  return 'Diagnóstico completo — veja acima';
};

// Ver quais clientes estão encerrados/arquivados (pode ter sido feito sem querer)
window.coVerEncerrados = function(){
  var ids = Object.keys(encerrados||{});
  if(!ids.length){ console.log('Nenhum processo encerrado.'); return; }
  console.log('%c=== PROCESSOS ENCERRADOS ('+ids.length+') ===','font-weight:bold;color:#fb923c');
  ids.forEach(function(id){
    var c = findClientById(id) || findClientById(Number(id));
    if(c){
      console.log('  ['+id+'] '+c.cliente+(c.pasta?' — Pasta '+c.pasta:''));
    } else {
      console.log('  ['+id+'] (cliente não encontrado no CLIENTS)');
    }
  });
  console.log('---');
  console.log('Para desarquivar UM: coReativar(ID_DO_CLIENTE)');
  console.log('Para desarquivar TODOS: coReativarTodos()');
  return ids.length + ' encerrados';
};

// Desarquivar um cliente específico
window.coReativar = function(id){
  if(!encerrados[id] && !encerrados[String(id)]){ return 'ID '+id+' não está arquivado'; }
  delete encerrados[id]; delete encerrados[String(id)];
  _encIdsCache = null;
  sbSet('co_encerrados', encerrados);
  marcarAlterado();
  if(typeof doSearch==='function') doSearch();
  if(typeof atualizarStats==='function') atualizarStats();
  return 'Cliente '+id+' reativado ✓';
};

// Desarquivar TODOS os clientes encerrados (usar com cuidado!)
window.coReativarTodos = function(){
  var ids = Object.keys(encerrados||{});
  if(!ids.length){ return 'Nenhum encerrado'; }
  var count = ids.length;
  for(var k in encerrados) delete encerrados[k];
  _encIdsCache = null;
  sbSet('co_encerrados', encerrados);
  marcarAlterado();
  if(typeof doSearch==='function') doSearch();
  if(typeof atualizarStats==='function') atualizarStats();
  return count+' processos reativados ✓';
};

async function sbInit(){
  const ok = await sbCarregarTudo();
  sbStartWatchdog();
  if(ok){
    // Recarregar dados da nuvem na memória
    function ls(k,def){ try{return JSON.parse(lsGet(k)||'null')||def;}catch{return def;} }
    const asArr = v => Array.isArray(v) ? v : [];
    const asObj = v => (v&&typeof v==='object'&&!Array.isArray(v)) ? v : {};
    tarefasDia   = asObj(ls('co_td',{}));
    tasks        = asObj(ls('co_tasks',{}));
    vkTasks      = asArr(ls('co_vktasks',[]));
    localAtend   = asArr(ls('co_atend',[]));
    // Carregar tombstones PRIMEIRO, antes dos arrays, para filtrar na carga
    try{
      var _finDel = ls('co_fin_del',[]);
      if(Array.isArray(_finDel)){ var s1=_tombstoneLoad('co_fin'); _finDel.forEach(function(id){ s1.add(String(id)); }); }
      var _locDel = ls('co_localLanc_del',[]);
      if(Array.isArray(_locDel)){ var s2=_tombstoneLoad('co_localLanc'); _locDel.forEach(function(id){ s2.add(String(id)); }); }
    }catch{}
    finLancs     = asArr(ls('co_fin',[])).filter(function(x){ return !_tombstoneHas('co_fin', x.id); });
    localLanc    = asArr(ls('co_localLanc',[])).filter(function(x){ return !_tombstoneHas('co_localLanc', x.id); });
    localAg      = asArr(ls('co_ag',[]));
    localMov     = asObj(ls('co_localMov',{}));
    encerrados   = asObj(ls('co_encerrados',{}));
    // co_clientes recarregado via sbCarregarClientes() no init()
    notes        = asObj(ls('co_notes',{}));
    localContatos= asArr(ls('co_ctc',[]));
    _iniciais    = asArr(ls('co_iniciais',[]));
    // Migrar lançamentos do Projuris para localLanc
    (function(){
      var novos = [{"id": 1780000000001, "id_processo": 62197181, "tipo": "honorario", "direcao": "receber", "desc": "Taxa de Manutenção PCD", "valor": 97.0, "data": "2026-03-02", "venc": "2026-03-02", "pago": false, "status": "pendente", "dt_baixa": "", "cliente": "FATIMA FRANCISCA GUIRLANDA", "natureza": "honorario_escritorio", "_migrado_projuris": "p45"}, {"id": 1780000000011, "id_processo": 4181597, "tipo": "honorario", "direcao": "receber", "desc": "Parcela 7/11 — honorários 30%", "valor": 300.0, "data": "2026-03-02", "venc": "2026-03-02", "pago": true, "status": "pago", "dt_baixa": "2026-03-05", "cliente": "PALOMA ALVES DOS SANTOS", "natureza": "honorario_escritorio", "_migrado_projuris": "p46", "_perc_hon": 30, "_vbruto": 1000.0}, {"id": 1780000000012, "id_processo": 4181597, "tipo": "repasse", "direcao": "pagar", "desc": "Repasse — PALOMA ALVES DOS SANTOS (70% de Parcela 7/11)", "valor": 700.0, "data": "2026-03-02", "venc": "2026-03-02", "pago": true, "status": "pago", "dt_baixa": "2026-03-05", "cliente": "PALOMA ALVES DOS SANTOS", "_repasse_acordo": true, "_migrado_projuris": "p46"}, {"id": 1780000000021, "id_processo": 62044220, "tipo": "honorario", "direcao": "receber", "desc": "2ª Fase - Consultoria", "valor": 350.0, "data": "2026-03-05", "venc": "2026-03-05", "pago": false, "status": "pendente", "dt_baixa": "", "cliente": "MARY LUCIA DE OLIVEIRA", "natureza": "honorario_escritorio", "_migrado_projuris": "p43"}, {"id": 1780000000031, "id_processo": 58420195, "tipo": "honorario", "direcao": "receber", "desc": "5/10 Parcela - Acordo — honorários 30%", "valor": 2850.0, "data": "2026-03-05", "venc": "2026-03-05", "pago": true, "status": "pago", "dt_baixa": "2026-03-05", "cliente": "ELIEDSON FERREIRA DE ALMEIDA", "natureza": "honorario_escritorio", "_migrado_projuris": "p44", "_perc_hon": 30, "_vbruto": 9500.0}, {"id": 1780000000032, "id_processo": 58420195, "tipo": "repasse", "direcao": "pagar", "desc": "Repasse — ELIEDSON FERREIRA DE ALMEIDA (70% de 5/10 Parcela - Acordo)", "valor": 6650.0, "data": "2026-03-05", "venc": "2026-03-05", "pago": true, "status": "pago", "dt_baixa": "2026-03-05", "cliente": "ELIEDSON FERREIRA DE ALMEIDA", "_repasse_acordo": true, "_migrado_projuris": "p44"}, {"id": 1780000000041, "id_processo": 61138230, "tipo": "honorario", "direcao": "receber", "desc": "Requerimento PCD 1/6", "valor": 253.0, "data": "2026-03-06", "venc": "2026-03-06", "pago": false, "status": "pendente", "dt_baixa": "", "cliente": "LUCIMAR APARECIDA DE ASSIS", "natureza": "honorario_escritorio", "_migrado_projuris": "p41"}, {"id": 1780000000061, "id_processo": 52276707, "tipo": "honorario", "direcao": "receber", "desc": "6/6 Parcela Acordo INTER — honorários 30%", "valor": 300.0, "data": "2026-03-09", "venc": "2026-03-09", "pago": false, "status": "pendente", "dt_baixa": "", "cliente": "AMANDA VITORIA PEREIRA DA SILVA", "natureza": "honorario_escritorio", "_migrado_projuris": "p39", "_perc_hon": 30, "_vbruto": 1000.0}, {"id": 1780000000062, "id_processo": 52276707, "tipo": "repasse", "direcao": "pagar", "desc": "Repasse — AMANDA VITORIA PEREIRA DA SILVA (70% de 6/6 Parcela Acordo INTER)", "valor": 700.0, "data": "2026-03-09", "venc": "2026-03-09", "pago": false, "status": "pendente", "dt_baixa": "", "cliente": "AMANDA VITORIA PEREIRA DA SILVA", "_repasse_acordo": true, "_migrado_projuris": "p39"}, {"id": 1780000000071, "id_processo": 62081782, "tipo": "honorario", "direcao": "receber", "desc": "Defesa - INSS - 2/4", "valor": 407.0, "data": "2026-03-09", "venc": "2026-03-09", "pago": false, "status": "pendente", "dt_baixa": "", "cliente": "ROGERIO JOSE DE AMORIM", "natureza": "honorario_escritorio", "_migrado_projuris": "p40"}, {"id": 1780000000081, "id_processo": 56825228, "tipo": "honorario", "direcao": "receber", "desc": "Monitoramento processual", "valor": 99.9, "data": "2026-03-17", "venc": "2026-03-17", "pago": false, "status": "pendente", "dt_baixa": "", "cliente": "Shirley Alves Braga Santos", "natureza": "honorario_escritorio", "_migrado_projuris": "p38"}, {"id": 1780000000091, "id_processo": 61899034, "tipo": "honorario", "direcao": "receber", "desc": "Consultoria Empresarial - Funcionária Eduarda", "valor": 600.0, "data": "2026-03-20", "venc": "2026-03-20", "pago": false, "status": "pendente", "dt_baixa": "", "cliente": "ADEGA 13 COMÉRCIO DE BEBIDAS LTDA", "natureza": "honorario_escritorio", "_migrado_projuris": "p37"}, {"id": 1780000000111, "id_processo": 49674121, "tipo": "honorario", "direcao": "receber", "desc": "Taxa de Manutenção Processual", "valor": 99.9, "data": "2026-03-30", "venc": "2026-03-30", "pago": false, "status": "pendente", "dt_baixa": "", "cliente": "CARLOS ALBERTO ALVES LACERDA", "natureza": "honorario_escritorio", "_migrado_projuris": "p35"}, {"id": 1780000000121, "id_processo": 62197181, "tipo": "honorario", "direcao": "receber", "desc": "Taxa de Manutenção PCD", "valor": 97.0, "data": "2026-04-02", "venc": "2026-04-02", "pago": false, "status": "pendente", "dt_baixa": "", "cliente": "FATIMA FRANCISCA GUIRLANDA", "natureza": "honorario_escritorio", "_migrado_projuris": "p33"}, {"id": 1780000000131, "id_processo": 4181597, "tipo": "honorario", "direcao": "receber", "desc": "Parcela 8/11 — honorários 30%", "valor": 300.0, "data": "2026-04-02", "venc": "2026-04-02", "pago": false, "status": "pendente", "dt_baixa": "", "cliente": "PALOMA ALVES DOS SANTOS", "natureza": "honorario_escritorio", "_migrado_projuris": "p34", "_perc_hon": 30, "_vbruto": 1000.0}, {"id": 1780000000132, "id_processo": 4181597, "tipo": "repasse", "direcao": "pagar", "desc": "Repasse — PALOMA ALVES DOS SANTOS (70% de Parcela 8/11)", "valor": 700.0, "data": "2026-04-02", "venc": "2026-04-02", "pago": false, "status": "pendente", "dt_baixa": "", "cliente": "PALOMA ALVES DOS SANTOS", "_repasse_acordo": true, "_migrado_projuris": "p34"}, {"id": 1780000000141, "id_processo": 58420195, "tipo": "honorario", "direcao": "receber", "desc": "6/10 Parcela - Acordo — honorários 30%", "valor": 2850.0, "data": "2026-04-05", "venc": "2026-04-05", "pago": false, "status": "pendente", "dt_baixa": "", "cliente": "ELIEDSON FERREIRA DE ALMEIDA", "natureza": "honorario_escritorio", "_migrado_projuris": "p32", "_perc_hon": 30, "_vbruto": 9500.0}, {"id": 1780000000142, "id_processo": 58420195, "tipo": "repasse", "direcao": "pagar", "desc": "Repasse — ELIEDSON FERREIRA DE ALMEIDA (70% de 6/10 Parcela - Acordo)", "valor": 6650.0, "data": "2026-04-05", "venc": "2026-04-05", "pago": false, "status": "pendente", "dt_baixa": "", "cliente": "ELIEDSON FERREIRA DE ALMEIDA", "_repasse_acordo": true, "_migrado_projuris": "p32"}, {"id": 1780000000151, "id_processo": 61138230, "tipo": "honorario", "direcao": "receber", "desc": "Requerimento PCD 2/6", "valor": 253.0, "data": "2026-04-06", "venc": "2026-04-06", "pago": false, "status": "pendente", "dt_baixa": "", "cliente": "LUCIMAR APARECIDA DE ASSIS", "natureza": "honorario_escritorio", "_migrado_projuris": "p31"}, {"id": 1780000000161, "id_processo": 52276707, "tipo": "honorario", "direcao": "receber", "desc": "5/6 Parcela Acordo INTER — honorários 30%", "valor": 300.0, "data": "2026-04-09", "venc": "2026-04-09", "pago": false, "status": "pendente", "dt_baixa": "", "cliente": "AMANDA VITORIA PEREIRA DA SILVA", "natureza": "honorario_escritorio", "_migrado_projuris": "p29", "_perc_hon": 30, "_vbruto": 1000.0}, {"id": 1780000000162, "id_processo": 52276707, "tipo": "repasse", "direcao": "pagar", "desc": "Repasse — AMANDA VITORIA PEREIRA DA SILVA (70% de 5/6 Parcela Acordo INTER)", "valor": 700.0, "data": "2026-04-09", "venc": "2026-04-09", "pago": false, "status": "pendente", "dt_baixa": "", "cliente": "AMANDA VITORIA PEREIRA DA SILVA", "_repasse_acordo": true, "_migrado_projuris": "p29"}, {"id": 1780000000171, "id_processo": 62081782, "tipo": "honorario", "direcao": "receber", "desc": "Defesa - INSS - 3/4", "valor": 407.0, "data": "2026-04-09", "venc": "2026-04-09", "pago": false, "status": "pendente", "dt_baixa": "", "cliente": "ROGERIO JOSE DE AMORIM", "natureza": "honorario_escritorio", "_migrado_projuris": "p30"}, {"id": 1780000000181, "id_processo": 56825228, "tipo": "honorario", "direcao": "receber", "desc": "Monitoramento processual", "valor": 99.9, "data": "2026-04-17", "venc": "2026-04-17", "pago": false, "status": "pendente", "dt_baixa": "", "cliente": "Shirley Alves Braga Santos", "natureza": "honorario_escritorio", "_migrado_projuris": "p28"}, {"id": 1780000000201, "id_processo": 49674121, "tipo": "honorario", "direcao": "receber", "desc": "Taxa de Manutenção Processual", "valor": 99.9, "data": "2026-04-30", "venc": "2026-04-30", "pago": false, "status": "pendente", "dt_baixa": "", "cliente": "CARLOS ALBERTO ALVES LACERDA", "natureza": "honorario_escritorio", "_migrado_projuris": "p26"}, {"id": 1780000000211, "id_processo": 4181597, "tipo": "honorario", "direcao": "receber", "desc": "Parcela 9/11 — honorários 30%", "valor": 300.0, "data": "2026-05-01", "venc": "2026-05-01", "pago": false, "status": "pendente", "dt_baixa": "", "cliente": "PALOMA ALVES DOS SANTOS", "natureza": "honorario_escritorio", "_migrado_projuris": "p25", "_perc_hon": 30, "_vbruto": 1000.0}, {"id": 1780000000212, "id_processo": 4181597, "tipo": "repasse", "direcao": "pagar", "desc": "Repasse — PALOMA ALVES DOS SANTOS (70% de Parcela 9/11)", "valor": 700.0, "data": "2026-05-01", "venc": "2026-05-01", "pago": false, "status": "pendente", "dt_baixa": "", "cliente": "PALOMA ALVES DOS SANTOS", "_repasse_acordo": true, "_migrado_projuris": "p25"}, {"id": 1780000000221, "id_processo": 62197181, "tipo": "honorario", "direcao": "receber", "desc": "Taxa de Manutenção PCD", "valor": 97.0, "data": "2026-05-02", "venc": "2026-05-02", "pago": false, "status": "pendente", "dt_baixa": "", "cliente": "FATIMA FRANCISCA GUIRLANDA", "natureza": "honorario_escritorio", "_migrado_projuris": "p24"}, {"id": 1780000000231, "id_processo": 58420195, "tipo": "honorario", "direcao": "receber", "desc": "7/10 Parcela - Acordo — honorários 30%", "valor": 2850.0, "data": "2026-05-05", "venc": "2026-05-05", "pago": false, "status": "pendente", "dt_baixa": "", "cliente": "ELIEDSON FERREIRA DE ALMEIDA", "natureza": "honorario_escritorio", "_migrado_projuris": "p23", "_perc_hon": 30, "_vbruto": 9500.0}, {"id": 1780000000232, "id_processo": 58420195, "tipo": "repasse", "direcao": "pagar", "desc": "Repasse — ELIEDSON FERREIRA DE ALMEIDA (70% de 7/10 Parcela - Acordo)", "valor": 6650.0, "data": "2026-05-05", "venc": "2026-05-05", "pago": false, "status": "pendente", "dt_baixa": "", "cliente": "ELIEDSON FERREIRA DE ALMEIDA", "_repasse_acordo": true, "_migrado_projuris": "p23"}, {"id": 1780000000241, "id_processo": 61138230, "tipo": "honorario", "direcao": "receber", "desc": "Requerimento PCD 3/6", "valor": 253.0, "data": "2026-05-06", "venc": "2026-05-06", "pago": false, "status": "pendente", "dt_baixa": "", "cliente": "LUCIMAR APARECIDA DE ASSIS", "natureza": "honorario_escritorio", "_migrado_projuris": "p22"}, {"id": 1780000000251, "id_processo": 62081782, "tipo": "honorario", "direcao": "receber", "desc": "Defesa - INSS - 4/4", "valor": 407.0, "data": "2026-05-09", "venc": "2026-05-09", "pago": false, "status": "pendente", "dt_baixa": "", "cliente": "ROGERIO JOSE DE AMORIM", "natureza": "honorario_escritorio", "_migrado_projuris": "p21"}, {"id": 1780000000261, "id_processo": 56825228, "tipo": "honorario", "direcao": "receber", "desc": "Monitoramento processual", "valor": 99.9, "data": "2026-05-17", "venc": "2026-05-17", "pago": false, "status": "pendente", "dt_baixa": "", "cliente": "Shirley Alves Braga Santos", "natureza": "honorario_escritorio", "_migrado_projuris": "p20"}, {"id": 1780000000281, "id_processo": 49674121, "tipo": "honorario", "direcao": "receber", "desc": "Taxa de Manutenção Processual", "valor": 99.9, "data": "2026-05-30", "venc": "2026-05-30", "pago": false, "status": "pendente", "dt_baixa": "", "cliente": "CARLOS ALBERTO ALVES LACERDA", "natureza": "honorario_escritorio", "_migrado_projuris": "p18"}, {"id": 1780000000291, "id_processo": 62197181, "tipo": "honorario", "direcao": "receber", "desc": "Taxa de Manutenção PCD", "valor": 97.0, "data": "2026-06-02", "venc": "2026-06-02", "pago": false, "status": "pendente", "dt_baixa": "", "cliente": "FATIMA FRANCISCA GUIRLANDA", "natureza": "honorario_escritorio", "_migrado_projuris": "p16"}, {"id": 1780000000301, "id_processo": 4181597, "tipo": "honorario", "direcao": "receber", "desc": "Parcela 10/11 — honorários 30%", "valor": 300.0, "data": "2026-06-02", "venc": "2026-06-02", "pago": false, "status": "pendente", "dt_baixa": "", "cliente": "PALOMA ALVES DOS SANTOS", "natureza": "honorario_escritorio", "_migrado_projuris": "p17", "_perc_hon": 30, "_vbruto": 1000.0}, {"id": 1780000000302, "id_processo": 4181597, "tipo": "repasse", "direcao": "pagar", "desc": "Repasse — PALOMA ALVES DOS SANTOS (70% de Parcela 10/11)", "valor": 700.0, "data": "2026-06-02", "venc": "2026-06-02", "pago": false, "status": "pendente", "dt_baixa": "", "cliente": "PALOMA ALVES DOS SANTOS", "_repasse_acordo": true, "_migrado_projuris": "p17"}, {"id": 1780000000311, "id_processo": 58420195, "tipo": "honorario", "direcao": "receber", "desc": "8/10 Parcela - Acordo — honorários 30%", "valor": 2850.0, "data": "2026-06-05", "venc": "2026-06-05", "pago": false, "status": "pendente", "dt_baixa": "", "cliente": "ELIEDSON FERREIRA DE ALMEIDA", "natureza": "honorario_escritorio", "_migrado_projuris": "p15", "_perc_hon": 30, "_vbruto": 9500.0}, {"id": 1780000000312, "id_processo": 58420195, "tipo": "repasse", "direcao": "pagar", "desc": "Repasse — ELIEDSON FERREIRA DE ALMEIDA (70% de 8/10 Parcela - Acordo)", "valor": 6650.0, "data": "2026-06-05", "venc": "2026-06-05", "pago": false, "status": "pendente", "dt_baixa": "", "cliente": "ELIEDSON FERREIRA DE ALMEIDA", "_repasse_acordo": true, "_migrado_projuris": "p15"}, {"id": 1780000000321, "id_processo": 61138230, "tipo": "honorario", "direcao": "receber", "desc": "Requerimento PCD 4/6", "valor": 253.0, "data": "2026-06-06", "venc": "2026-06-06", "pago": false, "status": "pendente", "dt_baixa": "", "cliente": "LUCIMAR APARECIDA DE ASSIS", "natureza": "honorario_escritorio", "_migrado_projuris": "p14"}, {"id": 1780000000331, "id_processo": 56825228, "tipo": "honorario", "direcao": "receber", "desc": "Monitoramento processual", "valor": 99.9, "data": "2026-06-17", "venc": "2026-06-17", "pago": false, "status": "pendente", "dt_baixa": "", "cliente": "Shirley Alves Braga Santos", "natureza": "honorario_escritorio", "_migrado_projuris": "p13"}, {"id": 1780000000341, "id_processo": 49674121, "tipo": "honorario", "direcao": "receber", "desc": "Taxa de Manutenção Processual", "valor": 99.9, "data": "2026-06-30", "venc": "2026-06-30", "pago": false, "status": "pendente", "dt_baixa": "", "cliente": "CARLOS ALBERTO ALVES LACERDA", "natureza": "honorario_escritorio", "_migrado_projuris": "p12"}, {"id": 1780000000351, "id_processo": 62197181, "tipo": "honorario", "direcao": "receber", "desc": "Taxa de Manutenção PCD", "valor": 97.0, "data": "2026-07-02", "venc": "2026-07-02", "pago": false, "status": "pendente", "dt_baixa": "", "cliente": "FATIMA FRANCISCA GUIRLANDA", "natureza": "honorario_escritorio", "_migrado_projuris": "p10"}, {"id": 1780000000361, "id_processo": 4181597, "tipo": "honorario", "direcao": "receber", "desc": "Parcela 11/11 — honorários 30%", "valor": 300.0, "data": "2026-07-02", "venc": "2026-07-02", "pago": false, "status": "pendente", "dt_baixa": "", "cliente": "PALOMA ALVES DOS SANTOS", "natureza": "honorario_escritorio", "_migrado_projuris": "p11", "_perc_hon": 30, "_vbruto": 1000.0}, {"id": 1780000000362, "id_processo": 4181597, "tipo": "repasse", "direcao": "pagar", "desc": "Repasse — PALOMA ALVES DOS SANTOS (70% de Parcela 11/11)", "valor": 700.0, "data": "2026-07-02", "venc": "2026-07-02", "pago": false, "status": "pendente", "dt_baixa": "", "cliente": "PALOMA ALVES DOS SANTOS", "_repasse_acordo": true, "_migrado_projuris": "p11"}, {"id": 1780000000371, "id_processo": 58420195, "tipo": "honorario", "direcao": "receber", "desc": "9/10 Parcela - Acordo — honorários 30%", "valor": 2850.0, "data": "2026-07-05", "venc": "2026-07-05", "pago": false, "status": "pendente", "dt_baixa": "", "cliente": "ELIEDSON FERREIRA DE ALMEIDA", "natureza": "honorario_escritorio", "_migrado_projuris": "p9", "_perc_hon": 30, "_vbruto": 9500.0}, {"id": 1780000000372, "id_processo": 58420195, "tipo": "repasse", "direcao": "pagar", "desc": "Repasse — ELIEDSON FERREIRA DE ALMEIDA (70% de 9/10 Parcela - Acordo)", "valor": 6650.0, "data": "2026-07-05", "venc": "2026-07-05", "pago": false, "status": "pendente", "dt_baixa": "", "cliente": "ELIEDSON FERREIRA DE ALMEIDA", "_repasse_acordo": true, "_migrado_projuris": "p9"}, {"id": 1780000000381, "id_processo": 61138230, "tipo": "honorario", "direcao": "receber", "desc": "Requerimento PCD 5/6", "valor": 253.0, "data": "2026-07-06", "venc": "2026-07-06", "pago": false, "status": "pendente", "dt_baixa": "", "cliente": "LUCIMAR APARECIDA DE ASSIS", "natureza": "honorario_escritorio", "_migrado_projuris": "p8"}, {"id": 1780000000391, "id_processo": 56825228, "tipo": "honorario", "direcao": "receber", "desc": "Monitoramento processual", "valor": 99.9, "data": "2026-07-17", "venc": "2026-07-17", "pago": false, "status": "pendente", "dt_baixa": "", "cliente": "Shirley Alves Braga Santos", "natureza": "honorario_escritorio", "_migrado_projuris": "p7"}, {"id": 1780000000401, "id_processo": 49674121, "tipo": "honorario", "direcao": "receber", "desc": "Taxa de Manutenção Processual", "valor": 99.9, "data": "2026-07-30", "venc": "2026-07-30", "pago": false, "status": "pendente", "dt_baixa": "", "cliente": "CARLOS ALBERTO ALVES LACERDA", "natureza": "honorario_escritorio", "_migrado_projuris": "p47"}, {"id": 1780000000411, "id_processo": 62197181, "tipo": "honorario", "direcao": "receber", "desc": "Taxa de Manutenção PCD", "valor": 97.0, "data": "2026-08-02", "venc": "2026-08-02", "pago": false, "status": "pendente", "dt_baixa": "", "cliente": "FATIMA FRANCISCA GUIRLANDA", "natureza": "honorario_escritorio", "_migrado_projuris": "p6"}, {"id": 1780000000421, "id_processo": 4181597, "tipo": "honorario", "direcao": "receber", "desc": "Parcela 12/12 — honorários 30%", "valor": 348.0, "data": "2026-08-03", "venc": "2026-08-03", "pago": false, "status": "pendente", "dt_baixa": "", "cliente": "PALOMA ALVES DOS SANTOS", "natureza": "honorario_escritorio", "_migrado_projuris": "p5", "_perc_hon": 30, "_vbruto": 1160.0}, {"id": 1780000000422, "id_processo": 4181597, "tipo": "repasse", "direcao": "pagar", "desc": "Repasse — PALOMA ALVES DOS SANTOS (70% de Parcela 12/12)", "valor": 812.0, "data": "2026-08-03", "venc": "2026-08-03", "pago": false, "status": "pendente", "dt_baixa": "", "cliente": "PALOMA ALVES DOS SANTOS", "_repasse_acordo": true, "_migrado_projuris": "p5"}, {"id": 1780000000431, "id_processo": 58420195, "tipo": "honorario", "direcao": "receber", "desc": "10/10 Parcela - Acordo — honorários 30%", "valor": 2850.0, "data": "2026-08-05", "venc": "2026-08-05", "pago": false, "status": "pendente", "dt_baixa": "", "cliente": "ELIEDSON FERREIRA DE ALMEIDA", "natureza": "honorario_escritorio", "_migrado_projuris": "p4", "_perc_hon": 30, "_vbruto": 9500.0}, {"id": 1780000000432, "id_processo": 58420195, "tipo": "repasse", "direcao": "pagar", "desc": "Repasse — ELIEDSON FERREIRA DE ALMEIDA (70% de 10/10 Parcela - Acordo)", "valor": 6650.0, "data": "2026-08-05", "venc": "2026-08-05", "pago": false, "status": "pendente", "dt_baixa": "", "cliente": "ELIEDSON FERREIRA DE ALMEIDA", "_repasse_acordo": true, "_migrado_projuris": "p4"}, {"id": 1780000000441, "id_processo": 61138230, "tipo": "honorario", "direcao": "receber", "desc": "Requerimento PCD 6/6", "valor": 253.0, "data": "2026-08-06", "venc": "2026-08-06", "pago": false, "status": "pendente", "dt_baixa": "", "cliente": "LUCIMAR APARECIDA DE ASSIS", "natureza": "honorario_escritorio", "_migrado_projuris": "p3"}, {"id": 1780000000451, "id_processo": 56825228, "tipo": "honorario", "direcao": "receber", "desc": "Monitoramento processual", "valor": 99.9, "data": "2026-08-17", "venc": "2026-08-17", "pago": false, "status": "pendente", "dt_baixa": "", "cliente": "Shirley Alves Braga Santos", "natureza": "honorario_escritorio", "_migrado_projuris": "p2"}, {"id": 1780000000461, "id_processo": 49674121, "tipo": "honorario", "direcao": "receber", "desc": "Taxa de Manutenção Processual", "valor": 99.9, "data": "2026-08-30", "venc": "2026-08-30", "pago": false, "status": "pendente", "dt_baixa": "", "cliente": "CARLOS ALBERTO ALVES LACERDA", "natureza": "honorario_escritorio", "_migrado_projuris": "p48"}, {"id": 1780000000471, "id_processo": 62197181, "tipo": "honorario", "direcao": "receber", "desc": "Taxa de Manutenção PCD", "valor": 97.0, "data": "2026-09-02", "venc": "2026-09-02", "pago": false, "status": "pendente", "dt_baixa": "", "cliente": "FATIMA FRANCISCA GUIRLANDA", "natureza": "honorario_escritorio", "_migrado_projuris": "p56"}, {"id": 1780000000481, "id_processo": 56825228, "tipo": "honorario", "direcao": "receber", "desc": "Monitoramento processual", "valor": 99.9, "data": "2026-09-17", "venc": "2026-09-17", "pago": false, "status": "pendente", "dt_baixa": "", "cliente": "Shirley Alves Braga Santos", "natureza": "honorario_escritorio", "_migrado_projuris": "p1"}, {"id": 1780000000491, "id_processo": 49674121, "tipo": "honorario", "direcao": "receber", "desc": "Taxa de Manutenção Processual", "valor": 99.9, "data": "2026-09-30", "venc": "2026-09-30", "pago": false, "status": "pendente", "dt_baixa": "", "cliente": "CARLOS ALBERTO ALVES LACERDA", "natureza": "honorario_escritorio", "_migrado_projuris": "p49"}, {"id": 1780000000501, "id_processo": 62197181, "tipo": "honorario", "direcao": "receber", "desc": "Taxa de Manutenção PCD", "valor": 97.0, "data": "2026-10-02", "venc": "2026-10-02", "pago": false, "status": "pendente", "dt_baixa": "", "cliente": "FATIMA FRANCISCA GUIRLANDA", "natureza": "honorario_escritorio", "_migrado_projuris": "p57"}, {"id": 1780000000511, "id_processo": 56825228, "tipo": "honorario", "direcao": "receber", "desc": "Monitoramento processual", "valor": 99.9, "data": "2026-10-17", "venc": "2026-10-17", "pago": false, "status": "pendente", "dt_baixa": "", "cliente": "Shirley Alves Braga Santos", "natureza": "honorario_escritorio", "_migrado_projuris": "p53"}, {"id": 1780000000521, "id_processo": 49674121, "tipo": "honorario", "direcao": "receber", "desc": "Taxa de Manutenção Processual", "valor": 99.9, "data": "2026-10-30", "venc": "2026-10-30", "pago": false, "status": "pendente", "dt_baixa": "", "cliente": "CARLOS ALBERTO ALVES LACERDA", "natureza": "honorario_escritorio", "_migrado_projuris": "p50"}, {"id": 1780000000531, "id_processo": 62197181, "tipo": "honorario", "direcao": "receber", "desc": "Taxa de Manutenção PCD", "valor": 97.0, "data": "2026-11-02", "venc": "2026-11-02", "pago": false, "status": "pendente", "dt_baixa": "", "cliente": "FATIMA FRANCISCA GUIRLANDA", "natureza": "honorario_escritorio", "_migrado_projuris": "p58"}, {"id": 1780000000541, "id_processo": 56825228, "tipo": "honorario", "direcao": "receber", "desc": "Monitoramento processual", "valor": 99.9, "data": "2026-11-17", "venc": "2026-11-17", "pago": false, "status": "pendente", "dt_baixa": "", "cliente": "Shirley Alves Braga Santos", "natureza": "honorario_escritorio", "_migrado_projuris": "p54"}, {"id": 1780000000551, "id_processo": 49674121, "tipo": "honorario", "direcao": "receber", "desc": "Taxa de Manutenção Processual", "valor": 99.9, "data": "2026-11-30", "venc": "2026-11-30", "pago": false, "status": "pendente", "dt_baixa": "", "cliente": "CARLOS ALBERTO ALVES LACERDA", "natureza": "honorario_escritorio", "_migrado_projuris": "p51"}, {"id": 1780000000561, "id_processo": 62197181, "tipo": "honorario", "direcao": "receber", "desc": "Taxa de Manutenção PCD", "valor": 97.0, "data": "2026-12-02", "venc": "2026-12-02", "pago": false, "status": "pendente", "dt_baixa": "", "cliente": "FATIMA FRANCISCA GUIRLANDA", "natureza": "honorario_escritorio", "_migrado_projuris": "p59"}, {"id": 1780000000571, "id_processo": 56825228, "tipo": "honorario", "direcao": "receber", "desc": "Monitoramento processual", "valor": 99.9, "data": "2026-12-17", "venc": "2026-12-17", "pago": false, "status": "pendente", "dt_baixa": "", "cliente": "Shirley Alves Braga Santos", "natureza": "honorario_escritorio", "_migrado_projuris": "p55"}, {"id": 1780000000581, "id_processo": 49674121, "tipo": "honorario", "direcao": "receber", "desc": "Taxa de Manutenção Processual", "valor": 99.9, "data": "2026-12-30", "venc": "2026-12-30", "pago": false, "status": "pendente", "dt_baixa": "", "cliente": "CARLOS ALBERTO ALVES LACERDA", "natureza": "honorario_escritorio", "_migrado_projuris": "p52"}];
      var existeIds = new Set((localLanc||[]).filter(function(l){return l._migrado_projuris;}).map(function(l){return l._migrado_projuris+'|'+l.tipo;}));
      var added = 0;
      novos.forEach(function(n){
        var key = n._migrado_projuris+'|'+n.tipo;
        // Pular se já existe OU se foi explicitamente excluído pelo usuário (tombstone)
        if(existeIds.has(key)) return;
        if(_projurisDeletados && _projurisDeletados.has(key)) return;
        localLanc.push(n); added++;
      });
      if(added > 0){
        lsSet('co_localLanc', JSON.stringify(localLanc));
        sbSet('co_localLanc', localLanc);
      }
    })();
    // Re-renderizar tudo
    atualizarStats(); renderHomeAlerts(); renderFinDash();
    renderChecklist(); renderHomeWeek(); doSearch();
    if(typeof dshRenderMin==='function') try{ dshRenderMin(); }catch(e){}
    // Re-renderizar view financeiro se estiver ativa
    if(document.getElementById('vf')?.classList.contains('on')) vfRender();
    sbRealtime();
    showToast('Conectado à nuvem ✓');
  }
  sbAtualizarNome();
}
// ═══════════════════════════════════════════════════════════════
// CAMADA SUPABASE — substitui localStorage para dados compartilhados
// ═══════════════════════════════════════════════════════════════


// ═══════════════════════════════════════════════════════════════
// ══ VIEW CONTATOS ══
// ═══════════════════════════════════════════════════════════════

let _ctcSel = null; // id do contato selecionado

// ── Cache de contatos deduplicados ──
var _ctcCache = null;
var _ctcCacheVer = 0;
function ctcTodos(){
  var ver = (localContatos||[]).length;
  if(_ctcCache && _ctcCacheVer===ver) return _ctcCache;
  var seen = new Set();
  _ctcCache = (localContatos||[])
    .filter(function(c){
      var k = (c.nome||'').toLowerCase().trim()+'|'+(c.tipo||'');
      if(seen.has(k)) return false;
      seen.add(k);
      return true;
    })
    .map(function(c){return Object.assign({}, c, {_src:'manual'});});
  _ctcCacheVer = ver;
  return _ctcCache;
}
function invalidarCtcCache(){ _ctcCache=null; }

function ctcRender(){
  ctcRenderLista();
  if(_ctcSel) ctcAbrirFicha(_ctcSel);
  else renderCtcEmpty();
}

function renderCtcEmpty(){
  var el = document.getElementById('ctc-empty-dashboard');
  if(!el) return;
  var todos = ctcTodos();
  var pf = todos.filter(function(c){return c.tipo!=='pj';}).length;
  var pj = todos.filter(function(c){return c.tipo==='pj';}).length;
  var semTel = todos.filter(function(c){return !c.tel;});
  var semEmail = todos.filter(function(c){return !c.email;});
  var ultimos = todos.slice().sort(function(a,b){return (b.id||'').localeCompare(a.id||'');}).slice(0,5);

  function card(lbl,val,cor){
    return '<div style="padding:10px 12px;background:var(--sf2);border:1px solid var(--bd);border-radius:8px;text-align:center">'
      +'<div style="font-size:22px;font-weight:800;color:'+cor+'">'+val+'</div>'
      +'<div style="font-size:9px;font-weight:700;text-transform:uppercase;color:var(--mu);margin-top:2px">'+lbl+'</div>'
    +'</div>';
  }

  var html = '<div style="text-align:center;margin-bottom:16px">'
    +'<div style="font-size:28px;margin-bottom:4px">\ud83d\udc64</div>'
    +'<div style="font-size:14px;font-weight:700;color:var(--tx)">Contatos</div>'
    +'<div style="font-size:11px;color:var(--mu)">Selecione um contato ou veja o resumo</div>'
  +'</div>';

  html += '<div style="display:grid;grid-template-columns:repeat(3,1fr);gap:8px;margin-bottom:14px">'
    +card('Total', todos.length, 'var(--tx)')
    +card('Pessoa F\u00edsica', pf, '#60a5fa')
    +card('Pessoa Jur\u00eddica', pj, '#D4AF37')
  +'</div>';

  // Incompletos
  if(semTel.length||semEmail.length){
    html += '<div style="background:rgba(245,158,11,.08);border:1px solid rgba(245,158,11,.3);border-radius:6px;padding:8px 12px;margin-bottom:12px;font-size:11px;color:#f59e0b">'
      +(semTel.length?'\ud83d\udcf1 <strong>'+semTel.length+'</strong> sem telefone':'')
      +(semTel.length&&semEmail.length?' \u00b7 ':'')
      +(semEmail.length?'\ud83d\udce7 <strong>'+semEmail.length+'</strong> sem email':'')
    +'</div>';
  }

  // Últimos adicionados
  if(ultimos.length){
    html += '<div style="font-size:10px;font-weight:700;text-transform:uppercase;color:var(--mu);margin-bottom:6px;letter-spacing:.05em">\u00daltimos adicionados</div>';
    ultimos.forEach(function(c){
      var iniciais = (c.nome||'?').split(' ').map(function(p){return p[0];}).slice(0,2).join('').toUpperCase();
      html += '<div style="display:flex;align-items:center;gap:8px;padding:5px 0;border-bottom:1px solid var(--bd);cursor:pointer" onclick="ctcAbrirFicha(\''+c.id+'\')">'
        +'<div style="width:28px;height:28px;border-radius:50%;background:var(--vinho);display:flex;align-items:center;justify-content:center;font-size:10px;font-weight:700;color:#fff">'+iniciais+'</div>'
        +'<div style="flex:1">'
          +'<div style="font-size:11px;font-weight:600;color:var(--tx)">'+escapeHtml(c.nome||'\u2014')+'</div>'
          +'<div style="font-size:9px;color:var(--mu)">'+(c.tel||c.email||c.tipo||'')+'</div>'
        +'</div>'
        +'<span style="font-size:9px;padding:2px 6px;border-radius:3px;background:var(--sf3);color:var(--mu)">'+(c.tipo==='pj'?'PJ':'PF')+'</span>'
      +'</div>';
    });
  }

  el.innerHTML = html;
}

function ctcRenderLista(){
  const q    = (document.getElementById('ctc-busca')?.value||'').toLowerCase();
  const list = document.getElementById('ctc-lista');
  if(!list) return;

  const fTipo = (document.getElementById('ctc-filtro-tipo')||{}).value||'';
  const todos = ctcTodos().filter(c=>{
    if(fTipo && (c.tipo||'').toLowerCase()!==fTipo) return false;
    return !q || (c.nome||'').toLowerCase().includes(q)
       || (c.tel||'').includes(q)
       || (c.email||'').toLowerCase().includes(q)
       || (c.cpf||'').includes(q);
  }).sort((a,b)=>(a.nome||'').localeCompare(b.nome||''));

  if(!todos.length){
    list.innerHTML=`<div style="padding:20px;text-align:center;font-size:12px;color:var(--mu)">
      Nenhum contato encontrado.<br><br>
      Use <strong>＋ Novo → 👤 Novo contato</strong> para adicionar.
    </div>`;
    return;
  }

  list.innerHTML = todos.map(c=>{
    const iniciais = (c.nome||'?').split(' ').map(p=>p[0]).slice(0,2).join('').toUpperCase();
    const sub = [c.tel, c.email].filter(Boolean).join(' · ') || c.tipo || '—';
    const sel = String(c.id)===String(_ctcSel);
    const semProc = !_ctcTemProcesso(c);
    const semProcBadge = semProc
      ? '<span style="font-size:9px;padding:1px 5px;border-radius:3px;background:rgba(245,158,11,.12);color:#f59e0b;font-weight:600;margin-left:4px" title="Sem processo vinculado">Sem Proc.</span>'
      : '';
    return `<div class="ctc-sb-item${sel?' on':''}" onclick="ctcAbrirFicha('${c.id}')">
      <div class="ctc-avatar-big" style="width:34px;height:34px;font-size:13px">${iniciais}</div>
      <div style="min-width:0">
        <div class="ctc-sb-nome">${c.nome}</div>
        <div class="ctc-sb-sub">${sub}</div>
      </div>
      <span class="ctc-sb-tipo">${c.tipo||'Contato'}${semProcBadge}</span>
    </div>`;
  }).join('');
}

function ctcAbrirFicha(id){
  _ctcSel = id;
  ctcRenderLista(); // atualizar seleção na lista
  const c = ctcTodos().find(x=>String(x.id)===String(id));
  const main = document.getElementById('ctc-main');
  if(!c || !main) return;

  const iniciais = (c.nome||'?').split(' ').map(p=>p[0]).slice(0,2).join('').toUpperCase();
  const ex = c.extra||{};

  const field = (lbl,val,full=false) => val
    ? `<div class="ctc-field${full?' ctc-field-full':''}">
        <div class="ctc-field-lbl">${lbl}</div>
        <div class="ctc-field-val">${val}</div>
       </div>` : '';

  const telLink  = c.tel  ? `<a href="tel:${c.tel}">${c.tel}</a>` : '';
  const mailLink = c.email? `<a href="mailto:${c.email}">${c.email}</a>` : '';

  var secIdent = `
    <div class="ctc-sec">\ud83d\udc64 Identifica\u00e7\u00e3o</div>
    <div class="ctc-grid">
      ${field('CPF/CNPJ', c.doc||c.cpf||'')}
      ${c.pis?field('PIS/PASEP/NIT', c.pis):''}
      ${field('Data de nascimento', ex.nasc)}
      ${field('Naturalidade', ex.natural)}
      ${field('Estado civil', ex.ecivil)}
      ${field('Nome da m\u00e3e', ex.mae)}
      ${field('Origem', c.origem)}
    </div>`;

  const secContato = `
    <div class="ctc-sec">📞 Contato</div>
    <div class="ctc-grid">
      ${c.tel   ? `<div class="ctc-field"><div class="ctc-field-lbl">Telefone</div><div class="ctc-field-val">${telLink}</div></div>` : ''}
      ${c.email ? `<div class="ctc-field"><div class="ctc-field-lbl">E-mail</div><div class="ctc-field-val">${mailLink}</div></div>` : ''}
      ${field('Rua', ex.rua)} ${field('Nº', ex.num)} ${field('Complemento', ex.comp)}
      ${field('Bairro', ex.bairro)} ${field('Cidade/UF', [ex.cidade,ex.uf].filter(Boolean).join(' — '))}
      ${field('CEP', ex.cep)}
    </div>`;

  var pisVal = c.pis||ex.nit||ex.pis||'';
  var secProf = (ex.prof||pisVal||ex.ctps) ? `
    <div class="ctc-sec">\ud83d\udcbc Profissional</div>
    <div class="ctc-grid">
      ${field('Profiss\u00e3o', ex.prof)}
      ${field('PIS / PASEP / NIT', pisVal)}
      ${field('CTPS', ex.ctps)}
    </div>` : (c.pis ? `
    <div class="ctc-sec">\ud83d\udcbc Profissional</div>
    <div class="ctc-grid">
      ${field('PIS / PASEP / NIT', c.pis)}
    </div>` : '');

  // Dados bancários — ocultos por padrão
  const hasBanco = ex.banco||ex.ag||ex.conta||ex.pix;
  const secPriv = hasBanco ? `
    <div class="ctc-sec">🔒 Dados Bancários
      <button onclick="ctcTogglePriv()" id="ctc-priv-btn" style="background:none;border:none;color:var(--mu);cursor:pointer;font-size:13px;margin-left:8px">👁</button>
    </div>
    <div id="ctc-priv-bloco" style="filter:blur(6px);transition:filter .2s">
      <div class="ctc-grid">
        ${field('Banco', ex.banco)} ${field('Tipo', ex.tconta)}
        ${field('Agência', ex.ag)}  ${field('Conta', ex.conta)}
        ${field('PIX', ex.pix)}
      </div>
    </div>` : '';

  var _cNomeEsc = c.nome.replace(/'/g,"\\'");
  var _semProc = !_ctcTemProcesso(c);
  main.innerHTML = `
    <div class="ctc-ficha-header">
      <div class="ctc-avatar-big">${iniciais}</div>
      <div style="flex:1">
        <div class="ctc-ficha-nome">${c.nome}${_semProc?' <span style="font-size:10px;padding:2px 7px;border-radius:4px;background:rgba(245,158,11,.15);color:#f59e0b;font-weight:700;vertical-align:middle;margin-left:6px" title="Sem processo vinculado">Sem Processo</span>':''}</div>
        <div class="ctc-ficha-sub">${c.tipo||'Contato'} · Cadastrado em ${c.criado||'—'}</div>
        <div style="display:flex;gap:6px;margin-top:6px;flex-wrap:wrap">
          ${c.tel?`<span style="font-size:12px;color:var(--tx)">📞 ${c.tel}</span>`:''}
          ${c.email?`<span style="font-size:12px;color:var(--tx)">✉ ${c.email}</span>`:''}
        </div>
      </div>
      <div class="pj-opcoes-wrap">
        <button class="pj-opcoes-btn" onclick="this.nextElementSibling.style.display=this.nextElementSibling.style.display==='block'?'none':'block'">Opções ▾</button>
        <div class="pj-opcoes-menu" style="display:none" onclick="this.style.display='none'">
          ${c.tel?`<div class="pj-opcoes-item" onclick="navigator.clipboard.writeText('55${c.tel.replace(/\\D/g,'')}');showToast('Tel copiado')">📞 Copiar telefone</div>`:''}
          ${c.email?`<div class="pj-opcoes-item" onclick="window.open('mailto:${c.email}')">✉ Enviar e-mail</div>`:''}
          <div class="pj-opcoes-sep"></div>
          <div class="pj-opcoes-item" onclick="ctcVincularTarefa('${c.id}','${_cNomeEsc}')">✅ Nova tarefa</div>
          <div class="pj-opcoes-item" onclick="ctcVincularProcesso('${c.id}','${_cNomeEsc}')">⚖️ Vincular processo</div>
          <div class="pj-opcoes-sep"></div>
          <div class="pj-opcoes-item" onclick="ctcEditar('${c.id}')">✏ Editar</div>
          <div class="pj-opcoes-item" style="color:#c9484a" onclick="ctcDeletar('${c.id}')">🗑 Excluir</div>
        </div>
      </div>
    </div>
    ${secIdent}
    ${secContato}
    ${secProf}
    ${secPriv}
    ${(()=>{
      const fin = _ctcResumoFinanceiro(c);
      if(!fin) return '';
      const fV = function(v){ return 'R$ '+Math.abs(v||0).toLocaleString('pt-BR',{minimumFractionDigits:2,maximumFractionDigits:2}); };
      const kpi = function(lbl, val, cor){
        return '<div style="background:var(--sf2);border:1px solid var(--bd);border-radius:8px;padding:10px 12px">'
          +'<div style="font-size:18px;font-weight:800;color:'+cor+'">'+val+'</div>'
          +'<div style="font-size:9px;font-weight:700;text-transform:uppercase;color:var(--mu);margin-top:2px;letter-spacing:.05em">'+lbl+'</div>'
        +'</div>';
      };
      const hojeStr = new Date().toISOString().slice(0,10);
      const prox = fin.proxVencimentos.slice(0,3).map(function(p){
        const dias = Math.ceil((new Date(p.venc)-new Date(hojeStr))/(1000*60*60*24));
        const cor = dias<0?'#f87171':dias<=3?'#fb923c':dias<=7?'#d4af37':'var(--mu)';
        const lblDias = dias<0?'atrasado':dias===0?'hoje':dias+'d';
        return '<div onclick="openC('+p.cid+')" style="display:flex;align-items:center;justify-content:space-between;padding:6px 10px;background:var(--sf3);border:1px solid var(--bd);border-radius:6px;cursor:pointer;margin-bottom:4px">'
          +'<div style="min-width:0;flex:1">'
            +'<div style="font-size:12px;color:var(--tx);white-space:nowrap;overflow:hidden;text-overflow:ellipsis">'+escapeHtml(p.desc)+'</div>'
            +'<div style="font-size:10px;color:var(--mu);margin-top:1px">'+escapeHtml(p.cliente)+' · vence '+fDt(p.venc)+'</div>'
          +'</div>'
          +'<div style="text-align:right">'
            +'<div style="font-size:12px;font-weight:700;color:var(--tx)">'+fV(p.valor)+'</div>'
            +'<div style="font-size:10px;font-weight:700;color:'+cor+'">'+lblDias+'</div>'
          +'</div>'
        +'</div>';
      }).join('');
      const saldoCor = fin.aReceber>0 ? '#f59e0b' : '#4ade80';
      return '<div class="ctc-sec">💰 Financeiro do cliente</div>'
        +'<div style="display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:8px;margin-bottom:10px">'
          +kpi('Recebido', fV(fin.recebido), '#4ade80')
          +kpi('A receber', fV(fin.aReceber), saldoCor)
          +kpi('Custas pagas', fV(fin.despesasPagas), 'var(--tx)')
        +'</div>'
        +(prox ? '<div style="font-size:10px;font-weight:700;text-transform:uppercase;color:var(--mu);margin:12px 0 6px;letter-spacing:.05em">Próximos vencimentos</div>'+prox : '');
    })()}
    ${(()=>{
      const procs = CLIENTS.filter(cl=>
        (cl.partes||[]).some(p=>p.nome===c.nome) ||
        String(cl.id)===String(c.id_processo)
      );
      if(!procs.length) return '';
      return `<div class="ctc-sec">⚖️ Processos vinculados (${procs.length})</div>`
        + procs.map(cl=>`
          <div onclick="openC(${cl.id})" style="display:flex;align-items:center;gap:8px;
            padding:8px 10px;background:var(--sf3);border:1px solid var(--bd);border-radius:7px;
            cursor:pointer;margin-bottom:6px;transition:border-color .15s"
            onmouseover="this.style.borderColor='var(--ouro)'" onmouseout="this.style.borderColor='var(--bd)'">
            <span style="font-size:18px">⚖️</span>
            <div>
              <div style="font-size:12px;font-weight:700;color:var(--tx)">${cl.cliente}</div>
              <div style="font-size:10px;color:var(--mu)">Pasta ${cl.pasta} · ${cl.natureza||''}</div>
            </div>
          </div>`).join('');
    })()}
    ${c.processo?`<div style="font-size:12px;color:var(--mu);padding:4px 0">${c.processo}</div>`:''}
  `;
}

function ctcTogglePriv(){
  const bl  = document.getElementById('ctc-priv-bloco');
  const btn = document.getElementById('ctc-priv-btn');
  if(!bl) return;
  const oculto = bl.style.filter!=='none'&&bl.style.filter!=='';
  bl.style.filter  = oculto ? 'none' : 'blur(6px)';
  if(btn) btn.textContent = oculto ? '🙈' : '👁';
}

// ── EDITAR ──
function ctcVincularTarefa(ctcId, ctcNome){
  // Abre modal de nova tarefa pré-preenchida com o contato
  const TIPOS = ['tarefa','audiencia','compromisso'];
  abrirModal('✅ Nova Tarefa — '+ctcNome, `
    <div style="background:var(--sf3);border-radius:8px;padding:8px 12px;margin-bottom:12px;
      font-size:12px;color:var(--mu);display:flex;align-items:center;gap:8px">
      <span>👤</span> <strong style="color:var(--tx)">${ctcNome}</strong> será vinculado a esta tarefa
    </div>
    <div class="fm-row">
      <div style="flex:2"><label class="fm-lbl">Título *</label>
        <input class="fm-inp" id="cvt-titulo" placeholder="Ex: Ligar para ${ctcNome}...">
      </div>
      <div><label class="fm-lbl">Prazo</label>
        <input class="fm-inp" type="date" id="cvt-prazo">
      </div>
    </div>
    <div class="fm-row" style="margin-top:8px">
      <div><label class="fm-lbl">Tipo</label>
        <select class="fm-inp" id="cvt-tipo">
          <option value="tarefa">📋 Tarefa</option>
          <option value="compromisso">📅 Compromisso</option>
        </select>
      </div>
      <div><label class="fm-lbl">Prioridade</label>
        <select class="fm-inp" id="cvt-prior">
          <option value="normal">Normal</option>
          <option value="alta">Alta</option>
          <option value="baixa">Baixa</option>
        </select>
      </div>
    </div>
    <div style="margin-top:8px"><label class="fm-lbl">Descrição</label>
      <textarea class="fm-inp" id="cvt-desc" rows="2" placeholder="Detalhes..."></textarea>
    </div>`,
  ()=>{
    const titulo = document.getElementById('cvt-titulo')?.value.trim();
    if(!titulo){ showToast('Informe o título'); return; }
    const _prazo = document.getElementById('cvt-prazo')?.value||'';
    vkTasks.push({
      id: 'vk'+genId(),
      titulo,
      tipo:        document.getElementById('cvt-tipo')?.value||'tarefa',
      prioridade:  document.getElementById('cvt-prior')?.value||'normal',
      prazo:       _prazo,
      paraHoje:    _prazo===getTodayKey() ? getTodayKey() : '',
      obs:         document.getElementById('cvt-desc')?.value||'',
      responsavel: 'Clarissa',
      status:      'todo',
      cliente:     ctcNome,
      contato_id:  ctcId,
      contato_nome:ctcNome,
      criado:      new Date().toISOString(),
    });
    sbSet('co_vktasks', vkTasks);
    fecharModal();
    // Atualizar kanban e stats
    if(document.getElementById('vkt')?.classList.contains('on')) vkRender();
    atualizarStats();
    renderChecklist();
    showToast('✅ Tarefa criada — '+ctcNome);
    audit('criacao','Tarefa para contato: '+ctcNome,'tarefa');
  }, '✅ Criar tarefa');
}

function ctcVincularProcesso(ctcId, ctcNome){
  abrirModal('⚖️ Vincular ao Processo — '+ctcNome,
    '<div style="background:var(--sf3);border-radius:8px;padding:8px 12px;margin-bottom:12px;font-size:12px;color:var(--mu)">'
      +'👤 <strong style="color:var(--tx)">'+escapeHtml(ctcNome)+'</strong> será adicionado como parte ao processo selecionado'
    +'</div>'
    +'<div>'
      +'<label class="fm-lbl">Processo <span class="req">*</span></label>'
      +_procPickerHtml('cvp', {placeholder:'Digite o nome do cliente, pasta ou número... (sem acento)'})
    +'</div>'
    +'<div style="margin-top:8px">'
      +'<label class="fm-lbl">Papel / Condição <span class="req">*</span></label>'
      +'<select class="fm-inp" id="cvp-cond">'
        +'<option>Testemunha</option>'
        +'<option>Perito</option>'
        +'<option>Advogado adverso</option>'
        +'<option>Réu</option>'
        +'<option>Autor</option>'
        +'<option>Preposto</option>'
        +'<option>Representante Legal</option>'
        +'<option>Outro</option>'
      +'</select>'
    +'</div>',
  function(){
    var procId = document.getElementById('cvp-id')?.value;
    var cond = document.getElementById('cvp-cond')?.value||'Outro';
    if(!procId){ showToast('Selecione um processo da lista (clique no resultado)'); return; }
    var proc = CLIENTS.find(function(x){ return String(x.id)===String(procId); });
    if(!proc){ showToast('Processo não encontrado'); return; }
    if(!proc.partes) proc.partes = [];
    // Evitar duplicata
    if(!proc.partes.some(function(p){ return p.nome===ctcNome && p.condicao===cond; })){
      proc.partes.push({ nome:ctcNome, condicao:cond, cliente:'Não', contato_id:ctcId });
      proc.updated_at = new Date().toISOString();  // força merge correto entre PCs
    }
    var ctc = localContatos.find(function(x){ return String(x.id)===String(ctcId); });
    if(ctc){
      ctc.processo = proc.cliente + ' (Pasta '+proc.pasta+')';
      ctc.id_processo = proc.id;
      ctc.updated_at = new Date().toISOString();
    }
    sbSalvarClientesDebounced();
    sbSet('co_ctc', localContatos);
    invalidarCtcCache();
    marcarAlterado();
    fecharModal();
    ctcAbrirFicha(ctcId);
    showToast('✓ '+ctcNome+' vinculado como '+cond);
    audit('criacao','Contato vinculado ao processo: '+proc.cliente,'processo');
  }, '⚖️ Vincular');
}

function ctcEditar(id){
  const c = ctcTodos().find(x=>String(x.id)===String(id));
  if(!c) return;

  // Preencher cadHtml com dados existentes após abrir
  abrirModal('✏️ Editar Contato', cadHtml('ec',{tipoField:true, processoField:true}), ()=>{
    const v = getCadValues('ec');
    if(!v.nome){ showToast('Nome obrigatório'); return; }
    const idx = localContatos.findIndex(x=>String(x.id)===String(id));
    if(idx<0) return;
    localContatos[idx] = {
      ...localContatos[idx],
      nome: v.nome, cpf: v.cpf, doc: v.cpf, tipo: v.tipo||localContatos[idx].tipo,
      tel: v.tel, email: v.email, processo: v.proc||localContatos[idx].processo,
      origem: v.origem || localContatos[idx].origem || '',
      extra:{
        nasc:v.nasc, natural:v.natural, nacion:v.nacion, ecivil:v.ecivil, mae:v.mae,
        rua:v.rua, num:v.num, comp:v.comp, bairro:v.bairro, cep:v.cep,
        cidade:v.cidade, uf:v.uf, prof:v.prof, nit:v.nit, ctps:v.ctps,
        banco:v.banco, tconta:v.tconta, ag:v.ag, conta:v.conta, pix:v.pix, inss:v.inss
      }
    };
    sbSet('co_ctc', localContatos);
    invalidarCtcCache();
    marcarAlterado();
    fecharModal();
    ctcAbrirFicha(id);
    ctcRenderLista();
    showToast('Contato atualizado ✓');
  }, 'Salvar alterações');

  // Preencher campos com dados atuais após modal abrir
  setTimeout(()=>{
    const ex = c.extra||{};
    const s  = (fid,val) => { const el=document.getElementById('ec-'+fid); if(el&&val) el.value=val; };
    s('nome',c.nome); s('cpf',c.cpf); s('tel',c.tel); s('email',c.email);
    s('nasc',ex.nasc); s('natural',ex.natural); s('nacion',ex.nacion);
    s('ecivil',ex.ecivil); s('mae',ex.mae);
    s('rua',ex.rua); s('num',ex.num); s('comp',ex.comp);
    s('bairro',ex.bairro); s('cep',ex.cep); s('cidade',ex.cidade); s('uf',ex.uf);
    s('prof',ex.prof); s('nit',ex.nit); s('ctps',ex.ctps);
    s('banco',ex.banco); s('tconta',ex.tconta); s('ag',ex.ag);
    s('conta',ex.conta); s('pix',ex.pix); s('inss',ex.inss);
    s('origem', c.origem);
    if(c.tipo){ const el=document.getElementById('ec-tipo'); if(el) el.value=c.tipo; }
    if(c.processo){ const el=document.getElementById('ec-proc'); if(el) el.value=c.processo; }
  }, 80);
}

// ── DELETAR ──
function ctcDeletar(id){
  const c = ctcTodos().find(x=>String(x.id)===String(id));
  if(!c) return;
  abrirModal('Excluir contato',
    `<div style="font-size:13px;color:var(--mu);line-height:1.6">Excluir <strong style="color:var(--tx)">"${escapeHtml(c.nome||'este contato')}"</strong>?<br><span style="font-size:11px">Esta ação não pode ser desfeita.</span></div>`,
    ()=>{
      _tombstoneAdd('co_ctc', id);
      localContatos = localContatos.filter(x=>String(x.id)!==String(id));
      invalidarCtcCache(); sbSet('co_ctc', localContatos);
      marcarAlterado(); _ctcSel = null; fecharModal();
      const main = document.getElementById('ctc-main');
      if(main) main.innerHTML = `<div class="ctc-empty-state"><div style="font-size:32px;margin-bottom:10px">👤</div><div style="font-size:14px">Contato excluído</div></div>`;
      ctcRenderLista();
      showToast('Contato excluído');
    }, 'Excluir'
  );
  setTimeout(()=>{ const b=document.getElementById('modal-save'); if(b){b.style.background='var(--red)';b.textContent='Confirmar exclusão';} },50);
}

// ═══════════════════════════════════════════════════════════════
// ══ MÓDULO PARCERIAS ══
// ═══════════════════════════════════════════════════════════════

// Parcerias ficam em tasks[id]?.parcerias = []
function getParceriasDoProcesso(c){
  const key = String(c.id||c.pasta);
  return tasks[key]?.parcerias || [];
}
function setParceriasDoProcesso(c, lista){
  const key = String(c.id||c.pasta);
  if(!tasks[key]) tasks[key]={};
  tasks[key].parcerias = lista;
  sbSet('co_tasks', tasks);
  marcarAlterado();
}

function renderParceriasBloco(c){
  const parcs = getParceriasDoProcesso(c);
  const cid   = String(c.id||c.pasta);

  const cards = parcs.map((p,i)=>{
    const tipoLabel = p.tipo==='indicou' ? '⭐ Eu indiquei' : '🤝 Me indicaram';
    const tipoCls   = p.tipo==='indicou' ? 'indicou' : 'parceiro';

    // Calcular valores se houver base
    const base    = parseFloat(p.base||0);
    const percMeu = parseFloat(p.percMeu||0);
    const percDel = parseFloat(p.percDel||0);
    const vlMeu   = base && percMeu ? base*percMeu/100 : parseFloat(p.vlMeu||0);
    const vlDel   = base && percDel ? base*percDel/100 : parseFloat(p.vlDel||0);

    const percRow = (percMeu||percDel||vlMeu||vlDel) ? `
      <div class="parc-perc-row">
        <span class="parc-perc-item">Minha parte: <span class="parc-perc-val">${percMeu?percMeu+'%':'—'}${vlMeu?' ('+fBRL(vlMeu)+')':''}</span></span>
        <span class="parc-perc-item">Parte dele/a: <span class="parc-perc-val">${percDel?percDel+'%':'—'}${vlDel?' ('+fBRL(vlDel)+')':''}</span></span>
        ${base?`<span class="parc-perc-item" style="color:var(--mu)">Base: ${fBRL(base)}</span>`:''}
      </div>` : '';

    // Repasse
    let repasseHtml = '';
    if(p.repasse){
      const isPago = p.repasse_status==='pago';
      repasseHtml = `
      <div class="parc-repasse">
        <div>
          <div style="font-size:10px;color:var(--mu)">${p.tipo==='indicou'?'Repasse a pagar ao parceiro':'Repasse a receber do parceiro'}</div>
          <div class="parc-repasse-val ${isPago?'pago':'apagar'}">${fBRL(parseFloat(p.repasse))} ${isPago?'✓ PAGO':'⏳ PENDENTE'}</div>
          ${p.repasse_data?`<div style="font-size:10px;color:var(--mu)">Previsão: ${fDt(p.repasse_data)}</div>`:''}
        </div>
        ${!isPago?`<button class="parc-rep-btn pagar-btn" onclick="parcMarcarPago('${cid}',${i})">✓ Marcar como pago</button>`
                 :`<button class="parc-rep-btn" onclick="parcDesfazerPago('${cid}',${i})">↩ Desfazer</button>`}
      </div>`;
    }

    return `<div class="parc-card">
      <div class="parc-card-top">
        <div>
          <div class="parc-nome">${p.nome||'—'}</div>
          ${p.oab?`<div class="parc-oab">OAB: ${p.oab}</div>`:''}
        </div>
        <div style="display:flex;align-items:center;gap:6px">
          <span class="parc-tipo-badge ${tipoCls}">${tipoLabel}</span>
          <button class="parc-del" onclick="parcEditar('${cid}',${i})" title="Editar">✏</button>
          <button class="parc-del" onclick="parcDeletar('${cid}',${i})" title="Remover">✕</button>
        </div>
      </div>
      ${percRow}
      ${repasseHtml}
      ${p.obs?`<div style="font-size:11px;color:var(--mu);margin-top:6px;font-style:italic">📎 ${p.obs}</div>`:''}
    </div>`;
  }).join('');

  return `<div class="parc-wrap">
    <div class="parc-header">
      <span class="parc-lbl">🤝 Parceria${parcs.length?` (${parcs.length})`:''}</span>
      <button class="parc-add-btn" onclick="parcNovo('${cid}')">＋ Adicionar parceiro</button>
    </div>
    ${cards||`<div style="font-size:11px;color:var(--mu);font-style:italic">Nenhuma parceria registrada</div>`}
  </div>`;
}

function parcModal(titulo, dados, onSave){
  abrirModal(titulo,`
  <div class="fm-row">
    <div style="flex:2">
      <label class="fm-lbl">Nome do advogado parceiro *</label>
      <input class="fm-inp" id="pm-nome" value="${dados.nome||''}" placeholder="Dr(a). Nome Completo">
    </div>
    <div>
      <label class="fm-lbl">OAB</label>
      <input class="fm-inp" id="pm-oab" value="${dados.oab||''}" placeholder="MG 12345">
    </div>
  </div>
  <div class="fm-row" style="margin-top:8px">
    <div>
      <label class="fm-lbl">Tipo de parceria</label>
      <select class="fm-inp" id="pm-tipo">
        <option value="indicou" ${dados.tipo==='indicou'?'selected':''}>⭐ Eu indiquei o cliente</option>
        <option value="parceiro" ${dados.tipo==='parceiro'?'selected':''}>🤝 Parceiro me indicou / co-patrocínio</option>
      </select>
    </div>
  </div>
  <div style="margin:10px 0 6px;font-size:10px;font-weight:700;color:var(--mu);text-transform:uppercase;letter-spacing:.06em">Divisão de honorários</div>
  <div class="fm-row">
    <div>
      <label class="fm-lbl">Minha % (honorários)</label>
      <input class="fm-inp" type="number" id="pm-percMeu" value="${dados.percMeu||''}" placeholder="Ex: 70" min="0" max="100">
    </div>
    <div>
      <label class="fm-lbl">% do parceiro</label>
      <input class="fm-inp" type="number" id="pm-percDel" value="${dados.percDel||''}" placeholder="Ex: 30" min="0" max="100">
    </div>
    <div>
      <label class="fm-lbl">Base de cálculo (R$)</label>
      <input class="fm-inp" type="number" id="pm-base" value="${dados.base||''}" placeholder="Valor dos honor.">
    </div>
  </div>
  <div style="margin:10px 0 6px;font-size:10px;font-weight:700;color:var(--mu);text-transform:uppercase;letter-spacing:.06em">Repasse</div>
  <div class="fm-row">
    <div>
      <label class="fm-lbl">Valor do repasse (R$)</label>
      <input class="fm-inp" type="number" id="pm-repasse" value="${dados.repasse||''}" placeholder="Valor a pagar/receber">
    </div>
    <div>
      <label class="fm-lbl">Data prevista</label>
      <input class="fm-inp" type="date" id="pm-repdata" value="${dados.repasse_data||''}">
    </div>
    <div>
      <label class="fm-lbl">Status</label>
      <select class="fm-inp" id="pm-repstatus">
        <option value="pendente" ${dados.repasse_status!=='pago'?'selected':''}>⏳ Pendente</option>
        <option value="pago" ${dados.repasse_status==='pago'?'selected':''}>✓ Pago</option>
      </select>
    </div>
  </div>
  <div style="margin-top:8px">
    <label class="fm-lbl">Observação</label>
    <input class="fm-inp" id="pm-obs" value="${dados.obs||''}" placeholder="Ex: acordado verbalmente em 01/03/2026">
  </div>
  `, onSave, '💾 Salvar');
}

function parcNovo(cid){
  const c = CLIENTS.find(x=>String(x.id||x.pasta)===cid)||{id:cid};
  parcModal('🤝 Nova Parceria', {}, ()=>{
    const nome = document.getElementById('pm-nome')?.value.trim();
    if(!nome){ showToast('Informe o nome do parceiro'); return; }
    const lista = getParceriasDoProcesso(c);
    lista.push({
      nome, oab: document.getElementById('pm-oab')?.value.trim(),
      tipo:        document.getElementById('pm-tipo')?.value,
      percMeu:     document.getElementById('pm-percMeu')?.value||'',
      percDel:     document.getElementById('pm-percDel')?.value||'',
      base:        document.getElementById('pm-base')?.value||'',
      repasse:     document.getElementById('pm-repasse')?.value||'',
      repasse_data:document.getElementById('pm-repdata')?.value||'',
      repasse_status:document.getElementById('pm-repstatus')?.value||'pendente',
      obs:         document.getElementById('pm-obs')?.value.trim(),
    });
    setParceriasDoProcesso(c, lista);
    fecharModal();
    renderFicha(c);
    showToast('Parceria registrada ✓');
  });
}

function parcEditar(cid, idx){
  const c = CLIENTS.find(x=>String(x.id||x.pasta)===cid)||{id:cid};
  const lista = getParceriasDoProcesso(c);
  const p = lista[idx];
  if(!p) return;
  parcModal('✏️ Editar Parceria', p, ()=>{
    const nome = document.getElementById('pm-nome')?.value.trim();
    if(!nome){ showToast('Informe o nome do parceiro'); return; }
    lista[idx] = {
      nome, oab: document.getElementById('pm-oab')?.value.trim(),
      tipo:        document.getElementById('pm-tipo')?.value,
      percMeu:     document.getElementById('pm-percMeu')?.value||'',
      percDel:     document.getElementById('pm-percDel')?.value||'',
      base:        document.getElementById('pm-base')?.value||'',
      repasse:     document.getElementById('pm-repasse')?.value||'',
      repasse_data:document.getElementById('pm-repdata')?.value||'',
      repasse_status:document.getElementById('pm-repstatus')?.value||'pendente',
      obs:         document.getElementById('pm-obs')?.value.trim(),
    };
    setParceriasDoProcesso(c, lista);
    fecharModal();
    renderFicha(c);
    showToast('Parceria atualizada ✓');
  });
}

function parcDeletar(cid, idx){
  abrirModal('Remover parceria',
    '<div style="font-size:13px;color:var(--mu)">Remover esta parceria? Esta ação não pode ser desfeita.</div>',
    function(){
      var c = CLIENTS.find(function(x){return String(x.id||x.pasta)===String(cid);})||{id:cid};
      var lista = getParceriasDoProcesso(c);
      lista.splice(idx, 1);
      setParceriasDoProcesso(c, lista);
      marcarAlterado(); fecharModal();
      renderFicha(c);
      showToast('Parceria removida');
    }, 'Remover'
  );
  setTimeout(function(){ var b=document.getElementById('modal-save'); if(b){b.style.background='var(--red)';b.textContent='Confirmar';} },50);
}

function parcMarcarPago(cid, idx){
  const c = CLIENTS.find(x=>String(x.id||x.pasta)===cid)||{id:cid};
  const lista = getParceriasDoProcesso(c);
  if(lista[idx]) lista[idx].repasse_status = 'pago';
  setParceriasDoProcesso(c, lista);
  renderFicha(c);
  showToast('Repasse marcado como pago ✓');
}

function parcDesfazerPago(cid, idx){
  const c = CLIENTS.find(x=>String(x.id||x.pasta)===cid)||{id:cid};
  const lista = getParceriasDoProcesso(c);
  if(lista[idx]) lista[idx].repasse_status = 'pendente';
  setParceriasDoProcesso(c, lista);
  renderFicha(c);
  showToast('Repasse reaberto como pendente ✓');
}

// ═══════════════════════════════════════════════════════════════
// ══ TAREFAS UNIFICADAS — fonte única: vkTasks ══
// ═══════════════════════════════════════════════════════════════

function escapeHtml(s){
  if(!s) return '';
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');
}

// ── Auditoria: helper de arredondamento monetário consistente ──
function roundMoney(v){ var n=+(v||0); return isFinite(n)?Math.round(n*100)/100:0; }

// ── Cache de CLIENTS por ID (evita O(n) repetido) ──
var _clientByIdCache = {};
var _clientByIdVer = 0;
function findClientById(id){
  if(!id) return null;
  var ver = (CLIENTS||[]).length;
  if(ver !== _clientByIdVer){ _clientByIdCache={}; _clientByIdVer=ver; }
  if(_clientByIdCache[id] !== undefined) return _clientByIdCache[id];
  var c = (CLIENTS||[]).find(function(x){return String(x.id)===String(id);}) || null;
  _clientByIdCache[id] = c;
  return c;
}

// ── Lookup de cliente case-insensitive (com cache) ──
var _clientByNameCache = {};
var _clientByNameVer = 0;
function findClientByName(nome){
  if(!nome) return null;
  var n = nome.toLowerCase().trim();
  var ver = (CLIENTS||[]).length;
  if(ver !== _clientByNameVer){ _clientByNameCache={}; _clientByNameVer=ver; }
  if(_clientByNameCache[n] !== undefined) return _clientByNameCache[n];
  var c = (CLIENTS||[]).find(function(x){ return (x.cliente||'').toLowerCase().trim()===n; }) || null;
  _clientByNameCache[n] = c;
  return c;
}

// Normaliza string para comparação fuzzy: minúscula, sem acento, sem espaços extras.
// Usado pelo autocomplete de processos/contatos — evita que "Soráia" vs "soraia"
// vs " Soraia" deixem de casar.
function _fuzzyNorm(s){
  if(s==null) return '';
  return String(s).normalize('NFD').replace(/[̀-ͯ]/g,'').toLowerCase().replace(/\s+/g,' ').trim();
}

// Retorna true se TODAS as palavras da query aparecem (em qualquer ordem) no haystack.
// "Soraia Silva" casa com "Silva Soraia" e com "Soraia M. da Silva".
function _fuzzyMatch(haystack, query){
  var h = _fuzzyNorm(haystack);
  var q = _fuzzyNorm(query);
  if(!q) return true;
  if(!h) return false;
  var palavras = q.split(' ');
  for(var i=0;i<palavras.length;i++){
    if(palavras[i] && h.indexOf(palavras[i]) === -1) return false;
  }
  return true;
}

// Busca CLIENTS por fuzzy (nome + pasta + número). Retorna array ordenado por
// priority: match exato de nome → match no início do nome → match geral.
function _fuzzySearchClients(query, maxResults){
  maxResults = maxResults || 20;
  var q = _fuzzyNorm(query);
  if(!q) return (CLIENTS||[]).slice(0, maxResults);
  var exact = [], starts = [], contains = [];
  (CLIENTS||[]).forEach(function(c){
    if(isEncerrado && isEncerrado(c.id)) return;
    var nome = _fuzzyNorm(c.cliente||'');
    var pasta = _fuzzyNorm(c.pasta||'');
    var num = _fuzzyNorm(c.numero||'');
    if(nome === q) { exact.push(c); return; }
    if(nome.indexOf(q) === 0) { starts.push(c); return; }
    if(_fuzzyMatch(nome+' '+pasta+' '+num, query)) contains.push(c);
  });
  return exact.concat(starts).concat(contains).slice(0, maxResults);
}

window._fuzzyNorm = _fuzzyNorm;
window._fuzzyMatch = _fuzzyMatch;
window._fuzzySearchClients = _fuzzySearchClients;

// ═══════════════════════════════════════════════════════
// ══ _procPicker — autocomplete reusável de processo ══
// ═══════════════════════════════════════════════════════
// Resolve o "select com N pastas" que a usuária reclamou.
// Uso: _procPickerHtml('meuPfx', {placeholder, allowCreate:true})
// Resultado salvo em #{pfx}-id (id do cliente) e #{pfx}-inp (nome visível).
// allowCreate: mostra "+ Criar nova pasta" quando não há match exato.
function _procPickerHtml(prefix, opts){
  opts = opts || {};
  var placeholder = opts.placeholder || 'Buscar pasta ou cliente...';
  var allowCreate = opts.allowCreate !== false;
  window['_procPicker_' + prefix] = {allowCreate: allowCreate, onPick: opts.onPick};
  return ''
    +'<div style="position:relative">'
      +'<input class="fm-inp" id="'+prefix+'-inp" placeholder="'+escapeHtml(placeholder)+'" autocomplete="off"'
        +' oninput="_procPickerFilter(\''+prefix+'\')"'
        +' onfocus="_procPickerFilter(\''+prefix+'\')"'
        +' onblur="setTimeout(function(){_procPickerHide(\''+prefix+'\');},200)">'
      +'<input type="hidden" id="'+prefix+'-id" value="">'
      +'<div id="'+prefix+'-list" style="position:absolute;top:100%;left:0;right:0;z-index:9999;max-height:260px;overflow-y:auto;background:var(--sf2);border:1px solid var(--bd);border-radius:6px;margin-top:2px;display:none;box-shadow:0 4px 12px rgba(0,0,0,.4)"></div>'
    +'</div>';
}

function _procPickerFilter(prefix){
  var inp  = document.getElementById(prefix+'-inp');
  var list = document.getElementById(prefix+'-list');
  var idEl = document.getElementById(prefix+'-id');
  if(!inp || !list) return;
  // Se o usuário digitou, descarta a seleção anterior
  if(idEl && idEl.value){
    var selCli = findClientById(parseInt(idEl.value));
    if(selCli && _fuzzyNorm(inp.value) !== _fuzzyNorm(selCli.cliente)) idEl.value = '';
  }
  var q = inp.value.trim();
  var results = _fuzzySearchClients(q, 15);
  var items = results.map(function(c){
    var cli = escapeHtml(c.cliente||'—');
    var metaParts = [];
    if(c.pasta) metaParts.push('Pasta '+c.pasta);
    if(c.natureza) metaParts.push(c.natureza);
    if(c.numero) metaParts.push(c.numero.slice(0,25));
    var sub = escapeHtml(metaParts.join(' · '));
    return '<div onmousedown="_procPickerPick(\''+prefix+'\','+c.id+')" style="padding:9px 12px;cursor:pointer;border-bottom:1px solid var(--bd);transition:background .1s" onmouseover="this.style.background=\'var(--sf3)\'" onmouseout="this.style.background=\'\'">'
      +'<div style="font-size:13px;color:var(--tx);font-weight:600">'+cli+'</div>'
      +(sub?'<div style="font-size:10px;color:var(--mu);margin-top:1px">'+sub+'</div>':'')
    +'</div>';
  }).join('');
  var cfg = window['_procPicker_' + prefix] || {};
  var hasExact = results.some(function(c){ return _fuzzyNorm(c.cliente) === _fuzzyNorm(q); });
  var createBtn = '';
  if(cfg.allowCreate && q && !hasExact){
    createBtn = '<div onmousedown="_procPickerCreate(\''+prefix+'\')" style="padding:10px 12px;cursor:pointer;background:rgba(212,175,55,.12);border-top:1px solid var(--bd);color:var(--ouro);font-weight:600;font-size:12px;text-align:center">+ Criar nova pasta para "'+escapeHtml(q)+'"</div>';
  }
  if(!items && !createBtn){
    list.innerHTML = '<div style="padding:12px;font-size:11px;color:var(--mu);text-align:center">Nenhum resultado. Digite algumas letras do nome ou da pasta.</div>';
  } else {
    list.innerHTML = items + createBtn;
  }
  list.style.display = 'block';
}

function _procPickerPick(prefix, cid){
  var c = findClientById(cid);
  if(!c) return;
  var inp = document.getElementById(prefix+'-inp');
  var idEl = document.getElementById(prefix+'-id');
  var list = document.getElementById(prefix+'-list');
  if(inp) inp.value = c.cliente || '';
  if(idEl) idEl.value = String(c.id);
  if(list) list.style.display = 'none';
  var cfg = window['_procPicker_' + prefix] || {};
  if(typeof cfg.onPick === 'function'){ try{ cfg.onPick(c); }catch(e){} }
}

function _procPickerHide(prefix){
  var list = document.getElementById(prefix+'-list');
  if(list) list.style.display = 'none';
}

function _procPickerCreate(prefix){
  var inp = document.getElementById(prefix+'-inp');
  var nomeInicial = inp ? inp.value.trim() : '';
  fecharModal();  // fecha o modal atual
  novoProcesso({ nome: nomeInicial });
  showToast('💡 Ao salvar o processo, volte aqui para vincular.');
}

window._procPickerHtml = _procPickerHtml;
window._procPickerFilter = _procPickerFilter;
window._procPickerPick = _procPickerPick;
window._procPickerHide = _procPickerHide;
window._procPickerCreate = _procPickerCreate;

// ═══════════════════════════════════════════════════════
// ══ _contatoPicker — autocomplete de contatos ══════════
// ═══════════════════════════════════════════════════════
// Busca sempre sobre localContatos AO VIVO (não usa cache).
// Se não encontra, permite criar contato inline (sem fechar o modal pai).
// Uso: _contatoPickerHtml('pfx', {onPick: function(ctc){...}})
// IDs gerados: #{pfx}-nome (input visível), #{pfx}-contato-id (hidden).

function _fuzzySearchContatos(query, maxResults){
  maxResults = maxResults || 15;
  var q = _fuzzyNorm(query);
  var base = (localContatos||[]).slice();
  if(!q) return base.slice(0, maxResults);
  var exact = [], starts = [], contains = [];
  base.forEach(function(c){
    var n = _fuzzyNorm(c.nome||'');
    var doc = _fuzzyNorm(c.doc||c.cpf||'');
    if(n === q){ exact.push(c); return; }
    if(n.indexOf(q) === 0){ starts.push(c); return; }
    if(_fuzzyMatch(n+' '+doc+' '+_fuzzyNorm(c.email||'')+' '+_fuzzyNorm(c.tel||''), query)){
      contains.push(c);
    }
  });
  return exact.concat(starts).concat(contains).slice(0, maxResults);
}

function _contatoPickerHtml(prefix, opts){
  opts = opts || {};
  var placeholder = opts.placeholder || 'Digite nome, CPF, telefone ou e-mail...';
  window['_contatoPicker_' + prefix] = {onPick: opts.onPick};
  return ''
    +'<div style="position:relative">'
      +'<input class="fm-inp" id="'+prefix+'-nome" placeholder="'+escapeHtml(placeholder)+'" autocomplete="off"'
        +' oninput="_contatoPickerFilter(\''+prefix+'\')"'
        +' onfocus="_contatoPickerFilter(\''+prefix+'\')"'
        +' onblur="setTimeout(function(){_contatoPickerHide(\''+prefix+'\');},200)">'
      +'<input type="hidden" id="'+prefix+'-contato-id" value="">'
      +'<div id="'+prefix+'-contato-list" style="position:absolute;top:100%;left:0;right:0;z-index:9999;max-height:260px;overflow-y:auto;background:var(--sf2);border:1px solid var(--bd);border-radius:6px;margin-top:2px;display:none;box-shadow:0 4px 12px rgba(0,0,0,.4)"></div>'
    +'</div>';
}

function _contatoPickerFilter(prefix){
  var inp  = document.getElementById(prefix+'-nome');
  var list = document.getElementById(prefix+'-contato-list');
  var idEl = document.getElementById(prefix+'-contato-id');
  if(!inp || !list) return;
  // Digitou algo diferente da seleção? invalida o id ligado
  if(idEl && idEl.value){
    var selCtc = (localContatos||[]).find(function(c){ return String(c.id)===idEl.value; });
    if(selCtc && _fuzzyNorm(inp.value) !== _fuzzyNorm(selCtc.nome)) idEl.value = '';
  }
  var q = inp.value.trim();
  // Sempre lê localContatos ao vivo (não cacheia) — garante que contato criado
  // há segundos, mesmo em outro modal, apareça imediatamente.
  var results = _fuzzySearchContatos(q, 12);
  var items = results.map(function(c){
    var nome = escapeHtml(c.nome||'—');
    var meta = [];
    if(c.doc||c.cpf) meta.push('Doc: '+escapeHtml(c.doc||c.cpf));
    if(c.tel) meta.push('📞 '+escapeHtml(c.tel));
    if(c.email) meta.push('✉ '+escapeHtml(c.email));
    var sub = meta.join(' · ');
    return '<div onmousedown="_contatoPickerPick(\''+prefix+'\',\''+c.id+'\')" style="padding:9px 12px;cursor:pointer;border-bottom:1px solid var(--bd);transition:background .1s" onmouseover="this.style.background=\'var(--sf3)\'" onmouseout="this.style.background=\'\'">'
      +'<div style="font-size:13px;color:var(--tx);font-weight:600">'+nome+'</div>'
      +(sub?'<div style="font-size:10px;color:var(--mu);margin-top:1px">'+sub+'</div>':'')
    +'</div>';
  }).join('');
  var hasExact = results.some(function(c){ return _fuzzyNorm(c.nome) === _fuzzyNorm(q); });
  var createBtn = '';
  if(q && !hasExact){
    createBtn = '<div onmousedown="_contatoPickerCreate(\''+prefix+'\')" style="padding:10px 12px;cursor:pointer;background:rgba(212,175,55,.12);border-top:1px solid var(--bd);color:var(--ouro);font-weight:600;font-size:12px;text-align:center">+ Criar contato "'+escapeHtml(q)+'" agora</div>';
  }
  if(!items && !createBtn){
    list.innerHTML = '<div style="padding:12px;font-size:11px;color:var(--mu);text-align:center">Nenhum contato. Digite para buscar ou criar.</div>';
  } else {
    list.innerHTML = items + createBtn;
  }
  list.style.display = 'block';
  // Indicador visual: borda dourada quando está em modo "criar novo"
  if(q && !hasExact){
    inp.style.borderColor = '#D4AF37';
    inp.style.boxShadow = '0 0 0 1px rgba(212,175,55,.3)';
  } else {
    inp.style.borderColor = '';
    inp.style.boxShadow = '';
  }
}

function _contatoPickerPick(prefix, ctcId){
  var c = (localContatos||[]).find(function(x){ return String(x.id)===String(ctcId); });
  if(!c) return;
  var inp = document.getElementById(prefix+'-nome');
  var idEl = document.getElementById(prefix+'-contato-id');
  var list = document.getElementById(prefix+'-contato-list');
  if(inp) inp.value = c.nome || '';
  if(idEl) idEl.value = String(c.id);
  if(list) list.style.display = 'none';
  var cfg = window['_contatoPicker_' + prefix] || {};
  if(typeof cfg.onPick === 'function'){ try{ cfg.onPick(c); }catch(e){} }
}

function _contatoPickerHide(prefix){
  var list = document.getElementById(prefix+'-contato-list');
  if(list) list.style.display = 'none';
}

// Cria contato inline (sem fechar o modal pai). O id gerado é gravado
// no hidden field e também disponibilizado via onPick.
// Captura CPF do modal pai se existir (ex: np-cpf no Novo Processo) — ajuda
// a gerar um contato mais completo no "double-save" atômico.
function _contatoPickerCreate(prefix){
  var inp = document.getElementById(prefix+'-nome');
  var nomeNovo = inp ? inp.value.trim() : '';
  if(!nomeNovo){ showToast('Digite o nome antes'); return; }
  // Procura CPF no mesmo modal (convenção: #np-cpf, #ec-cpf, #vknt-cpf)
  var cpfEl = document.getElementById('np-cpf') || document.getElementById(prefix+'-cpf');
  var cpfVal = cpfEl ? (cpfEl.value||'').trim() : '';
  var nowIso = new Date().toISOString();
  var novoCtc = {
    id: 'ctc'+genId(),
    nome: nomeNovo,
    tipo: 'pf',
    doc: cpfVal, cpf: cpfVal,
    criado: nowIso.slice(0,10),
    updated_at: nowIso
  };
  if(!Array.isArray(localContatos)) window.localContatos = [];
  localContatos.push(novoCtc);
  if(typeof invalidarCtcCache==='function') invalidarCtcCache();
  sbSet('co_ctc', localContatos);
  marcarAlterado();
  showToast('✓ Contato "'+nomeNovo+'" criado e vinculado');
  // Dispara evento global para outras views (contatos, dashboard, etc.)
  // atualizarem contadores e listas sem precisar de F5.
  try { window.dispatchEvent(new CustomEvent('co:reloadState', {detail:{source:'contatoCreate', id:novoCtc.id}})); } catch(e){}
  // Seleciona o recém-criado (fecha dropdown, grava id, chama onPick)
  _contatoPickerPick(prefix, novoCtc.id);
}

window._contatoPickerHtml = _contatoPickerHtml;
window._contatoPickerFilter = _contatoPickerFilter;
window._contatoPickerPick = _contatoPickerPick;
window._contatoPickerHide = _contatoPickerHide;
window._contatoPickerCreate = _contatoPickerCreate;
window._fuzzySearchContatos = _fuzzySearchContatos;

// Listener global de 'co:reloadState' — disparado por fluxos que criam/alteram
// dados atomicamente (ex: novoProcesso com cascade). Atualiza listas, contadores
// e views abertas sem F5. Outros PCs/abas via Realtime já chegam no sbAplicar.
window.addEventListener('co:reloadState', function(ev){
  try { if(typeof invalidarCtcCache==='function') invalidarCtcCache(); }catch(e){}
  try { if(typeof invalidarAllPend==='function') invalidarAllPend(); }catch(e){}
  try { if(typeof invalidarCacheVfTodos==='function') invalidarCacheVfTodos(); }catch(e){}
  try { if(typeof renderCtcEmpty==='function' && document.getElementById('vct')?.classList.contains('on')) renderCtcEmpty(); }catch(e){}
  try { if(typeof ctcRenderLista==='function' && document.getElementById('vct')?.classList.contains('on')) ctcRenderLista(); }catch(e){}
  try { if(typeof atualizarStats==='function') atualizarStats(); }catch(e){}
  try { if(typeof montarClientesAgrupados==='function') montarClientesAgrupados(); }catch(e){}
  try { if(typeof doSearch==='function') doSearch(); }catch(e){}
  // Reatividade do dashboard minimalista — re-renderiza só se a view 'vc' está ativa
  try {
    if(typeof dshRenderMin==='function' && document.getElementById('vc')?.classList.contains('on')){
      dshRenderMin();
    }
  } catch(e){}
});

// ── Helper unificado: lançamento está recebido/pago? ──
function isRec(l){ return !!(l.recebido || l.pago || l.status==='pago'); }

// ── Auditoria: gerador de IDs únicos (evita colisões de Date.now()) ──
var _lastGenId = 0;
function genId(){ var id = Date.now(); if(id <= _lastGenId) id = _lastGenId + 1; _lastGenId = id; return id; }

// ── Auditoria: guard contra double-click em modais financeiros ──
var _finProcessing = false;
function finGuard(fn){
  return function(){
    if(_finProcessing){ showToast('Processando, aguarde...'); return; }
    _finProcessing = true;
    try { fn.apply(this, arguments); }
    finally { setTimeout(function(){ _finProcessing=false; }, 600); }
  };
}

// Phase 2: helper — converte HTML string em DocumentFragment (evita innerHTML em loops)
function _fragFromHtml(html){
  var t = document.createElement('template');
  t.innerHTML = html;
  return t.content;
}

// PERF: retorna constante cacheada em vez de recomputar new Date() a cada chamada
function getTodayKey(){
  return _HOJE_STR;
}

// Checklist do dia = tarefas do vkTasks com prazo=hoje OU marcadas "hoje"
// + tarefas legadas do tarefasDia[hoje] para não perder histórico
let _hcTab = 'tarefas';

function hcSetTab(tab, btn){
  _hcTab = tab;
  // Update button styles
  ['fatais','tarefas','sistema'].forEach(function(t){
    var b = document.getElementById('hctab-'+t);
    if(!b) return;
    if(t===tab){
      b.style.background='#2e2e2e'; b.style.color='#E0E0E0';
    } else {
      b.style.background='transparent'; b.style.color='#9E9E9E';
    }
  });
  renderChecklist();
}


function renderChecklist(){
  const hoje = getTodayKey();
  const el    = document.getElementById('hc-list');
  const empty = document.getElementById('hc-empty');
  if(!el) return;

  // Prazos fatais de hoje (de todas as pastas)
  const fmtDt = d => fDt(d);
  const fataisHoje = prazos ? Object.entries(prazos).flatMap(function([cid,lista]){
    return (lista||[]).filter(function(p){ return !p.cumprido && p.data===hoje; }).map(function(p){
      const c = CLIENTS.find(function(x){ return String(x.id)===String(cid); });
      return { id:'fatal_'+p.id, titulo:p.titulo, cliente:c?c.cliente:'', tipo:'fatal',
               status:'todo', origem:'prazo', _cid:cid, _pid:p.id, _isFatal:true };
    });
  }) : [];

  // Tarefas do kanban para hoje + atrasadas + concluídas de hoje (ficam riscadas)
  const doKanban = vkTasks.filter(function(t){
    var isDone = t.status==='done' || t.status==='concluido';
    // Concluídas de hoje ou atrasadas concluídas hoje: mostrar riscadas
    if(isDone && (t.prazo===hoje || t.paraHoje===hoje)) return true;
    // Pendentes de hoje
    if(!isDone && (t.prazo===hoje || t.paraHoje===hoje)) return true;
    // Atrasadas pendentes (não concluídas)
    if(!isDone && t.prazo && t.prazo < hoje) return true;
    return false;
  });

  // Tarefas legadas
  // Tarefas legadas de hoje
  const legadas = (tarefasDia[hoje]||[]).map(function(t,i){
    return { id:'td_'+hoje+'_'+i, titulo:t.texto, cliente:t.cliente||'',
      tipo:'tarefa', prioridade:'media', responsavel:'Clarissa',
      status:t.done?'concluido':'todo', prazo:hoje, origem:'checklist', _tdIdx:i };
  });
  // Tarefas legadas de dias anteriores não concluídas
  const legadasAtrasadas = [];
  Object.keys(tarefasDia).filter(function(dia){ return dia < hoje; }).forEach(function(dia){
    (tarefasDia[dia]||[]).forEach(function(t,i){
      if(!t.done){
        legadasAtrasadas.push({ id:'td_'+dia+'_'+i, titulo:t.texto, cliente:t.cliente||'',
          tipo:'tarefa', prioridade:'alta', responsavel:'Clarissa',
          status:'todo', prazo:dia, origem:'checklist', _tdIdx:i, _diaOrig:dia });
      }
    });
  });
  // Dedup por ID (prefere), fallback a título para compatibilidade com legadas que não têm ID
  const kanbanKeys = new Set(doKanban.map(function(t){return t.id||t.titulo;}));
  const legadasFiltradas = legadas.filter(function(t){return !kanbanKeys.has(t.id||t.titulo);});
  const tarefasAll = [...doKanban, ...legadasFiltradas, ...legadasAtrasadas.filter(function(la){
    return !kanbanKeys.has(la.id||la.titulo);
  })];

  // Tarefas de sistema (admin, atendimento, audiencia-prep)
  const sistemaTipos = new Set(['admin','atendimento','audiencia-prep']);
  const sistemaAll = tarefasAll.filter(function(t){return sistemaTipos.has(t.tipo);});
  const tarefasSemSistema = tarefasAll.filter(function(t){return !sistemaTipos.has(t.tipo);});

  // Update tab counters
  var tn = document.getElementById('hctab-tarefas-n');
  if(tn) tn.textContent = tarefasSemSistema.length ? '('+tarefasSemSistema.length+')' : '';

  // Filter by current tab
  var todas;
  if(_hcTab==='fatais')  todas = fataisHoje;
  else if(_hcTab==='sistema') todas = sistemaAll;
  else todas = tarefasSemSistema;

  if(!todas.length){
    el.innerHTML='';
    if(empty) empty.style.display='block';
    return;
  }
  if(empty) empty.style.display='none';

  const pendentes  = todas.filter(function(t){return t.status!=='concluido'&&t.status!=='done';});
  const concluidas = todas.filter(function(t){return t.status==='concluido'||t.status==='done';});

  const renderItem = t => {
    const done = t.status==='concluido'||t.status==='done';
    const atrasada = t.prazo && t.prazo < hoje && !done;
    return `<div class="hc-item${done?' hc-item-done':''}" id="hci-${t.id}" onclick="goView('vk',document.getElementById('nav-tasks'));vkRender()" style="cursor:pointer">
      <div class="hc-item-corpo">
        <div class="hc-item-txt${done?' done':''}">${t.titulo||t.text||t.desc||'\u2014'}</div>
        <div class="hc-item-meta">
          ${atrasada ? `<span class="hc-badge-atrasada">ATRASADA</span>` : ''}
          ${t.cliente?`<span class="hc-item-cli">📁 ${t.cliente}</span>`:''}
        </div>
      </div>
    </div>`;
  };

  // Phase 2: DocumentFragment em vez de innerHTML em loop
  var frag = document.createDocumentFragment();
  pendentes.forEach(function(t){ frag.appendChild(_fragFromHtml(renderItem(t))); });
  if(concluidas.length){
    frag.appendChild(_fragFromHtml(`<div class="hc-sec-lbl">Concluídas hoje (${concluidas.length})</div>`));
    concluidas.forEach(function(t){ frag.appendChild(_fragFromHtml(renderItem(t))); });
  }
  el.textContent = '';
  el.appendChild(frag);
}

function hcToggle(id, origem, tdIdx, hoje){
  if(origem==='kanban'){
    const t = vkTasks.find(x=>String(x.id)===String(id));
    if(t){
      var wasDone = t.status==='concluido'||t.status==='done';
      t.status = wasDone ? 'todo' : 'done';
      if(!wasDone) t.concluido_em = new Date(HOJE).toISOString().slice(0,10);
      else delete t.concluido_em;
      vkSalvar();
    }
  } else if(origem==='agenda'){
    // Marcar evento da agenda como realizado/pendente
    const raw = String(id);
    const idx = (localAg||[]).findIndex(a=>String(a.id||a.id_agenda)===raw);
    if(idx>=0){
      localAg[idx].realizado = !localAg[idx].realizado;
      localAg[idx].cumprido = localAg[idx].realizado ? 'Sim' : 'Não';
    } else {
      const orig = (PEND||[]).find(p=>String(p.id||p.id_agenda)===raw);
      if(orig){ if(!localAg) localAg=[]; localAg.push({...orig,id:raw,id_agenda:raw,realizado:true,cumprido:'Sim',_origem_pend:raw}); }
    }
    sbSet('co_ag', localAg); invalidarAllPend();
  } else {
    if(tarefasDia[hoje]?.[tdIdx]!==undefined){
      tarefasDia[hoje][tdIdx].done = !tarefasDia[hoje][tdIdx].done;
      sbSet('co_td', tarefasDia);
    }
  }
  marcarAlterado();
  renderChecklist();
}

function hcRemover(id, origem, tdIdx, hoje){
  abrirModal('Remover tarefa',
    '<div style="font-size:13px;color:var(--mu);line-height:1.6">Remover esta tarefa do checklist?</div>',
    ()=>{
      if(origem==='kanban'){
        vkTasks = vkTasks.filter(function(t){return String(t.id)!==String(id);});
        vkSalvar();
      } else {
        if(tarefasDia[hoje]) tarefasDia[hoje].splice(tdIdx,1);
        sbSet('co_td', tarefasDia);
      }
      fecharModal(); renderChecklist(); marcarAlterado();
      showToast('Tarefa removida');
    }, 'Remover'
  );
  setTimeout(()=>{ const b=document.getElementById('modal-save'); if(b){b.style.background='var(--red)';b.textContent='Confirmar';} },50);
}

function hcEnviarKanban(id, titulo, cliente, hoje){
  // Promover tarefa legada para vkTask real
  vkTasks.push({
    id: 'vk'+genId(),
    titulo, cliente, tipo:'tarefa',
    prioridade:'media', responsavel:'Clarissa',
    prazo: hoje, status:'todo', paraHoje: hoje,
    obs:'', origem:'manual',
    status_since: hoje
  });
  // Remover do legado
  const parts = id.split('_');
  const idx = parseInt(parts[parts.length-1]);
  if(tarefasDia[hoje]) tarefasDia[hoje].splice(idx,1);
  sbSet('co_td', tarefasDia);
  vkSalvar();
  marcarAlterado();
  renderChecklist();
  showToast('Tarefa enviada ao Kanban ✓');
}


// novoTarefaDia — cria direto no vkTasks com prazo=hoje
function novoTarefaDia(){
  document.getElementById('novo-menu').style.display='none';
  const hoje = getTodayKey();
  var _seenCli = {};
  var clientes = CLIENTS.filter(function(c){ var n=(c.cliente||'').toLowerCase(); if(_seenCli[n]) return false; _seenCli[n]=true; return true; })
    .sort(function(a,b){return (a.cliente||'').localeCompare(b.cliente||'');})
    .map(function(c){return '<option value="'+escapeHtml(c.cliente)+'">'+escapeHtml(c.cliente)+'</option>';}).join('');
  abrirModal('📝 Nova Tarefa do Dia',`
    <div class="fm-row">
      <div style="flex:2">
        <label class="fm-lbl">Descrição <span class="req">*</span></label>
        <input class="fm-inp" id="ntd-txt" placeholder="Ex: Protocolar recurso, Ligar para cliente...">
      </div>
      <div>
        <label class="fm-lbl">Tipo</label>
        <select class="fm-inp" id="ntd-tipo">
          <option value="tarefa">📋 Tarefa</option>
          <option value="prazo">⚖️ Prazo Judicial</option>
          <option value="atendimento">📞 Atendimento</option>
          <option value="admin">🗂 Administrativo</option>
          <option value="audiencia-prep">🎯 Prep. Audiência</option>
        </select>
      </div>
    </div>
    <div class="fm-row" style="margin-top:8px">
      <div>
        <label class="fm-lbl">Responsável</label>
        <select class="fm-inp" id="ntd-resp">
          <option>Clarissa</option>
          <option>Assistente</option>
          <option>Estagiário 1</option>
          <option>Estagiário 2</option>
        </select>
      </div>
      <div>
        <label class="fm-lbl">Vincular a cliente</label>
        <input class="fm-inp" id="ntd-cli" list="ntd-clientes" placeholder="opcional">
        <datalist id="ntd-clientes">${clientes}</datalist>
      </div>
    </div>
  `,()=>{
    const texto = document.getElementById('ntd-txt')?.value.trim();
    if(!texto){ showToast('Descreva a tarefa'); return; }
    var cliNome = document.getElementById('ntd-cli')?.value.trim()||'';
    var cliMatch = cliNome ? findClientByName(cliNome) : null;
    vkTasks.push({
      id: 'vk'+genId(),
      titulo: texto,
      tipo:        document.getElementById('ntd-tipo')?.value||'tarefa',
      responsavel: document.getElementById('ntd-resp')?.value||'Clarissa',
      cliente:     cliNome,
      processo:    cliMatch ? cliMatch.id : 0,
      prioridade: 'media',
      prazo: hoje, paraHoje: hoje,
      status: 'todo', origem: 'manual',
      status_since: hoje
    });
    vkSalvar();
    fecharModal();
    renderChecklist();
    marcarAlterado();
    // Re-renderizar pasta se aberta
    if(cliMatch){
      var elTp = document.getElementById('tp7-list-'+cliMatch.id);
      if(elTp) elTp.innerHTML = _renderTarefasPasta(cliMatch.id);
    }
    showToast('Tarefa criada \u2713');
  },'Adicionar');
}

// Compatibilidade com toggleTarefa antigo (por precaução)
function toggleTarefa(key, idx){
  if(tarefasDia[key]?.[idx]!==undefined){
    tarefasDia[key][idx].done = !tarefasDia[key][idx].done;
    sbSet('co_td', tarefasDia);
    renderChecklist();
  }
}

// ═══════════════════════════════════════════════════════════════
// ══ MÓDULO KANBAN / GESTÃO DE TAREFAS ══
// ═══════════════════════════════════════════════════════════════

var vkTasks = [];
try { const _vk = JSON.parse(lsGet('co_vktasks')||'[]'); vkTasks = Array.isArray(_vk) ? _vk : []; } catch{}
// Filtro de tombstone aplicado mais abaixo, depois que _tombstoneHas estiver definido.

let _vkTab = 'kanban';
let _vkDrag = null;

const VK_COLUNAS = [
  { id:'todo',       label:'A Fazer',      icon:'📋', cor:'#6366f1' },
  { id:'andamento',  label:'Em Andamento', icon:'⚡', cor:'#f59e0b' },
  { id:'done',       label:'Concluído',    icon:'✅', cor:'#4ade80' },
];

const VK_RESP_COR = {
  'Clarissa':    '#510f10',
  'Assistente':  '#1d4ed8',
  'Estagiário 1':'#065f46',
  'Estagiário 2':'#713f12',
};

// Mapa perfil (auth) -> nome do responsável (dropdown de tarefas).
// Usado pelo filtro "Minha Pauta" para saber o que é do usuário logado.
function _meuNome(){
  var mapa = {advogada:'Clarissa', assistente:'Assistente', estagiario:'Estagiário 1'};
  if(typeof _sbPerfil!=='undefined' && _sbPerfil && _sbPerfil.perfil){
    return mapa[_sbPerfil.perfil] || 'Clarissa';
  }
  return 'Clarissa';
}

// Muda status de uma tarefa (via dropdown no card OU drag-drop).
// Quando move para 'done', adiciona linha automática em localMov
// da pasta do processo — evita escrever duas vezes a mesma coisa.
// Para tipo='prazo': intercepta e pede protocolo/ID do documento antes
// de marcar como concluído (spec da Clarissa: Mariane só dá baixa se
// anexar prova de cumprimento).
function vkMudarStatus(id, novoStatus, opts){
  opts = opts || {};
  var t = vkTasks.find(function(x){ return String(x.id)===String(id); });
  if(!t) return;
  var antes = t.status;
  var indoPraDone = (novoStatus==='done' || novoStatus==='concluido');
  var jaDone      = (antes==='done' || antes==='concluido');

  // Intercept: prazo indo pra done precisa de protocolo.
  if(!opts.skipPrazoCheck && t.tipo==='prazo' && indoPraDone && !jaDone){
    vkConcluirPrazoComProtocolo(id, novoStatus);
    vkRender();  // redesenha card (garante que drag visual não deixe card órfão)
    return;
  }

  t.status = novoStatus;
  t.status_since = new Date(HOJE).toISOString().slice(0,10);
  if(indoPraDone){
    t.concluido_em = new Date(HOJE).toISOString().slice(0,10);
    // Auto-histórico na pasta — só se a tarefa estiver vinculada a um processo
    // e ainda não tiver gerado histórico (evita duplicar se voltar→concluir).
    if(t.processo && !jaDone){
      if(!localMov[t.processo]) localMov[t.processo] = [];
      var titulo = t.titulo||'—';
      var resp = t.responsavel||'—';
      var msg, tipoMov, origem;
      if(t.tipo==='prazo' && t.protocolo){
        msg = 'Prazo "'+titulo+'" cumprido por '+resp+' — protocolo: '+t.protocolo;
        if(t.desfecho) msg += ' · '+t.desfecho;
        tipoMov = 'Judicial';
        origem = 'kanban_cumprimento_prazo';
      } else {
        msg = 'Tarefa "'+titulo+'" concluída por '+resp;
        tipoMov = 'Sistema';
        origem = 'kanban_conclusao';
      }
      localMov[t.processo].unshift({
        data: new Date(HOJE).toISOString().slice(0,10),
        movimentacao: msg,
        tipo_movimentacao: tipoMov,
        origem: origem
      });
      sbSet('co_localMov', localMov);
    }
  } else {
    delete t.concluido_em;
  }
  vkSalvar();
  vkRender();
  if(typeof renderChecklist==='function') renderChecklist();
  var lbl = VK_COLUNAS.find(function(c){ return c.id===novoStatus; });
  showToast('Movido para "'+(lbl?lbl.label:novoStatus)+'"');
}

// Modal específico para concluir tarefas tipo=prazo — exige prova do cumprimento.
function vkConcluirPrazoComProtocolo(id, novoStatus){
  var t = vkTasks.find(function(x){ return String(x.id)===String(id); });
  if(!t) return;
  abrirModal('⚖️ Cumprimento de Prazo — '+(t.titulo||''),
    '<div style="font-size:12px;color:var(--mu);margin-bottom:10px;line-height:1.5">'
      +'Para marcar este <strong style="color:var(--ouro)">prazo judicial</strong> como cumprido, '
      +'informe a <strong>prova do cumprimento</strong>. Isso fica registrado no histórico da pasta.'
    +'</div>'
    +'<div>'
      +'<label class="fm-lbl">Link do protocolo ou ID do documento <span class="req">*</span></label>'
      +'<input class="fm-inp" id="prazo-protocolo" value="'+escapeHtml(t.protocolo||'')+'" placeholder="Ex: PRJ-12345 · 0012345-67.2026.5.03.0001 · https://...">'
    +'</div>'
    +'<div style="margin-top:8px">'
      +'<label class="fm-lbl">Observações (opcional)</label>'
      +'<textarea class="fm-inp" id="prazo-desfecho" rows="2" placeholder="Detalhes do cumprimento (peça protocolada, etc.)">'+escapeHtml(t.desfecho||'')+'</textarea>'
    +'</div>',
    function(){
      var prot = ((document.getElementById('prazo-protocolo')||{}).value||'').trim();
      if(!prot){
        showToast('Informe o link ou ID do protocolo');
        return;
      }
      t.protocolo = prot;
      var dfc = ((document.getElementById('prazo-desfecho')||{}).value||'').trim();
      if(dfc) t.desfecho = dfc;
      fecharModal();
      vkMudarStatus(id, novoStatus, {skipPrazoCheck:true});
    },
    '✅ Confirmar Cumprimento');
}

// ── Helpers de status unificados ──
const VK_ETAPA_LABEL = {todo:'A Fazer', andamento:'Fazendo', done:'Concluído', concluido:'Concluído'};
const VK_ETAPA_COR = {todo:'var(--mu)', andamento:'#f59e0b', done:'#4ade80', concluido:'#4ade80'};
function isDone(t){ return t.status==='done'||t.status==='concluido'; }

// ── Cache de pasta por cid para render de lista ──
var _pastaLblCache = {};
var _pastaLblVer = 0;
function getPastaLbl(t){
  if(!t.processo) return t.cliente==='Escritório'?'Esc.':'—';
  var ver = (CLIENTS||[]).length;
  if(ver!==_pastaLblVer){ _pastaLblCache={}; _pastaLblVer=ver; }
  if(_pastaLblCache[t.processo]!==undefined) return _pastaLblCache[t.processo];
  var c = findClientById(t.processo);
  var lbl = c ? (c.pasta||c.cliente||'—') : '—';
  _pastaLblCache[t.processo] = lbl;
  return lbl;
}

function vkSalvar(){
  sbSet('co_vktasks', vkTasks);
}

function vkSetTab(tab, el){
  _vkTab = tab;
  document.querySelectorAll('.vk-tab').forEach(b=>b.classList.remove('on'));
  if(el) el.classList.add('on');
  vkRender();
}

function vkFiltrados(){
  const q     = (document.getElementById('vk-busca')?.value||'').toLowerCase();
  const ftipo = document.getElementById('vk-ftipo')?.value||'';
  const fresp = document.getElementById('vk-fresp')?.value||'';
  const fprior= document.getElementById('vk-fprior')?.value||'';

  // Filtrar concluídas com mais de 7 dias (sem mutar vkTasks)
  var seteDiasAtras = new Date(new Date(HOJE).getTime()-7*86400000).toISOString().slice(0,10);
  var hojeVk = new Date(HOJE).toISOString().slice(0,10);
  const base = vkTasks.filter(function(t){
    if(!isDone(t)) return true;
    return (t.concluido_em||hojeVk)>=seteDiasAtras;
  });

  return base.filter(t=>{
    const okQ    = !q || (t.titulo||'').toLowerCase().includes(q) || (t.cliente||'').toLowerCase().includes(q);
    const okTipo = !ftipo || t.tipo===ftipo;
    const okResp = !fresp || t.responsavel===fresp;
    const okPrior= !fprior || t.prioridade===fprior;
    return okQ && okTipo && okResp && okPrior;
  });
}

// ── RENDER PRINCIPAL ──
function vkRender(){
  const el = document.getElementById('vk-content');
  if(!el) return;
  const tasks = vkFiltrados();
  // Lista precisa de overflow auto para scroll
  el.style.overflow = _vkTab==='lista' ? 'auto' : 'hidden';
  if(_vkTab==='kanban')           el.innerHTML = vkRenderKanban(tasks);
  else if(_vkTab==='lista')       el.innerHTML = vkRenderLista(tasks);
  else if(_vkTab==='urgentes')    el.innerHTML = vkRenderUrgentes(tasks);
  else if(_vkTab==='responsavel') el.innerHTML = vkRenderResponsavel(tasks);
  else if(_vkTab==='minhapauta')  el.innerHTML = vkRenderMinhaPauta(tasks);
  vkBindDrag();
}

// ── MINHA PAUTA ──
// Só tarefas atribuídas ao usuário logado com prazo ≤ hoje+2d.
// "Botão de foco total" para começar o dia (spec da Clarissa).
function vkRenderMinhaPauta(tasks){
  var meu = _meuNome();
  var hoje = new Date(HOJE).toISOString().slice(0,10);
  var em2d = new Date(new Date(HOJE).getTime()+2*86400000).toISOString().slice(0,10);
  var minhas = tasks.filter(function(t){
    if(isDone(t)) return false;
    if(t.responsavel !== meu) return false;
    return t.prazo && t.prazo <= em2d;
  });
  var atras = minhas.filter(function(t){ return t.prazo < hoje; }).sort(function(a,b){ return (a.prazo||'').localeCompare(b.prazo||''); });
  var prox = minhas.filter(function(t){ return t.prazo >= hoje; }).sort(function(a,b){ return (a.prazo||'').localeCompare(b.prazo||''); });

  var item = function(t){
    var dias = Math.ceil((new Date(t.prazo)-new Date(hoje))/(1000*60*60*24));
    var cor = dias<0?'#f87171':dias===0?'#fb923c':dias<=2?'#fb923c':'#4ade80';
    return '<div class="vk-urg-item tipo-'+(t.tipo||'tarefa')+'" onclick="vkEditar(\''+t.id+'\')" style="cursor:pointer">'
      +'<span style="font-size:12px">'+(TIPO_LABEL[t.tipo]||'📋')+'</span>'
      +'<div style="flex:1">'
        +'<div class="vk-urg-txt">'+escapeHtml(t.titulo||'—')+'</div>'
        +'<div class="vk-urg-cli">'+escapeHtml(t.cliente||'—')+'</div>'
      +'</div>'
      +'<div style="text-align:right">'
        +'<div style="font-size:11px;font-weight:700;color:'+cor+'">'+(dias<0?'ATRASADO':dias===0?'HOJE':dias+'d')+'</div>'
        +'<div style="font-size:10px;color:var(--mu)">'+fDt(t.prazo)+'</div>'
      +'</div>'
    +'</div>';
  };

  if(!minhas.length){
    return '<div style="text-align:center;padding:48px;color:var(--mu);font-size:13px">🎯 Nada pra hoje ou próximos 2 dias na sua pauta ('+meu+'). Aproveite para avançar em coisas maiores.</div>';
  }
  return '<div class="vk-urgentes" style="overflow-y:auto;flex:1">'
    +'<div style="padding:12px 16px 4px;font-size:11px;color:var(--mu)">🎯 Foco em <strong>'+escapeHtml(meu)+'</strong> · próximos 2 dias</div>'
    +(atras.length?'<div class="vk-urg-title" style="color:#f87171">⚠️ ATRASADAS — '+atras.length+'</div>'+atras.map(item).join(''):'')
    +(prox.length?'<div class="vk-urg-title" style="color:#fb923c;margin-top:'+(atras.length?16:0)+'px">⏰ PRÓXIMAS — '+prox.length+'</div>'+prox.map(item).join(''):'')
  +'</div>';
}

// ── KANBAN ──
function vkRenderKanban(tasks){
  const cols = VK_COLUNAS.map(col=>{
    const itens = tasks.filter(function(t){
      if(col.id==='done') return isDone(t);
      return (t.status||'todo')===col.id;
    });
    // Limitar concluídos a 10 no kanban
    const visivel = col.id==='done' ? itens.slice(0,10) : itens;
    const cards = visivel.map(t=>vkCard(t)).join('') + (itens.length>10&&col.id==='done'?'<div style="font-size:10px;color:var(--mu);padding:8px;text-align:center">+'+(itens.length-10)+' mais</div>':'');
    return `
    <div class="vk-col">
      <div class="vk-col-head">
        <span class="vk-col-title">
          <span style="color:${col.cor}">${col.icon}</span>
          ${col.label}
        </span>
        <span class="vk-col-count">${itens.length}</span>
      </div>
      <div class="vk-col-body" id="vkcol-${col.id}"
        ondragover="event.preventDefault();this.classList.add('drag-over')"
        ondragleave="this.classList.remove('drag-over')"
        ondrop="vkDrop('${col.id}',this)">
        ${cards||`<div style="font-size:11px;color:var(--mu);font-style:italic;padding:8px">Arraste tarefas aqui</div>`}
      </div>
    </div>`;
  }).join('');
  return `<div class="vk-board">${cols}</div>`;
}

// ── VIEW LISTA ──
function vkRenderLista(tasks){
  var hoje = new Date(HOJE).toISOString().slice(0,10);
  // Ordenar: pendentes primeiro (por prazo), depois concluídas
  var sorted = tasks.slice().sort(function(a,b){
    var aD = isDone(a) ? 1 : 0;
    var bD = isDone(b) ? 1 : 0;
    if(aD!==bD) return aD-bD;
    return (a.prazo||'9999').localeCompare(b.prazo||'9999');
  });

  var html = '<div style="overflow-x:auto;overflow-y:auto;flex:1"><table class="vk-lista-table"><thead><tr>'
    +'<th>Título</th>'
    +'<th>Pasta</th>'
    +'<th>Etapa</th>'
    +'<th>Prazo</th>'
    +'<th>Ações</th>'
  +'</tr></thead><tbody>';

  sorted.forEach(function(t){
    var done = isDone(t);
    var vencido = !done && t.prazo && t.prazo < hoje;
    var pastaLbl = getPastaLbl(t);
    var etapaCls = done?'#4ade80':t.status==='andamento'?'#f59e0b':'var(--mu)';

    html += '<tr class="vk-lista-row'+(done?' vk-lista-done':'')+'">'
      +'<td>'
        +'<div class="vk-lista-titulo'+(done?' vk-lista-riscado':'')+'">'+escapeHtml(t.titulo||'—')+'</div>'
        +'<div style="font-size:10px;color:var(--mu)">'+escapeHtml(t.cliente||'')+'</div>'
      +'</td>'
      +'<td style="font-size:11px;color:var(--ouro);font-weight:600">'+pastaLbl+'</td>'
      +'<td><span style="font-size:10px;font-weight:700;color:'+etapaCls+'">'+(VK_ETAPA_LABEL[t.status]||'A Fazer')+'</span></td>'
      +'<td style="font-size:11px;color:'+(vencido?'#f87676':'var(--mu)')+'">'+( t.prazo?fDt(t.prazo):'—')+(vencido?' <span style="font-size:8px;color:#f87676">!</span>':'')+'</td>'
      +'<td style="white-space:nowrap">'
        +(done
          ?'<button onclick="vkToggleLista(\''+t.id+'\')" style="font-size:10px;padding:2px 6px;border-radius:3px;background:var(--sf3);border:1px solid var(--bd);color:var(--mu);cursor:pointer">↩ Reabrir</button> '
          :'<button onclick="vkToggleLista(\''+t.id+'\')" style="font-size:10px;padding:2px 6px;border-radius:3px;background:rgba(76,175,125,.1);border:1px solid rgba(76,175,125,.3);color:#4ade80;cursor:pointer">✅ Concluir</button> ')
        +'<button onclick="vkEditar(\''+t.id+'\')" style="font-size:10px;padding:2px 6px;border-radius:3px;background:var(--sf3);border:1px solid var(--bd);color:var(--mu);cursor:pointer">✏</button> '
        +'<button onclick="vkDeletar(\''+t.id+'\')" style="font-size:10px;padding:2px 6px;border-radius:3px;background:var(--sf3);border:1px solid rgba(201,72,74,.3);color:#c9484a;cursor:pointer">✕</button>'
      +'</td>'
    +'</tr>';
  });

  html += '</tbody></table></div>';
  if(!sorted.length) html = '<div style="padding:30px;text-align:center;font-size:12px;color:var(--mu)">Nenhuma tarefa</div>';
  return html;
}

// ── TAREFAS VINCULADAS À PASTA ──
function _renderTarefasPasta(cid){
  var hoje = new Date(HOJE).toISOString().slice(0,10);
  var tarefas = vkTasks.filter(function(t){ return String(t.processo)===String(cid); });
  if(!tarefas.length) return '<div style="padding:16px;font-size:12px;color:var(--mu);font-style:italic">Nenhuma tarefa vinculada a este processo.</div>';

  var pend = tarefas.filter(function(t){ return !isDone(t); });
  var done = tarefas.filter(isDone);

  function row(t){
    var _done = isDone(t);
    var vencido = !_done && t.prazo && t.prazo < hoje;
    return '<div style="display:flex;align-items:center;gap:10px;padding:10px 14px;border-bottom:1px solid var(--bd)'+(_done?';opacity:.6':'')+'">'
      +'<input type="checkbox" '+(_done?'checked':'')+' onchange="vkTogglePasta(\''+t.id+'\','+cid+')" style="width:16px;height:16px;cursor:pointer">'
      +'<div style="flex:1;min-width:0">'
        +'<div style="font-size:12px;font-weight:600;color:var(--tx)'+(_done?';text-decoration:line-through;color:var(--mu)':'')+'">'+escapeHtml(t.titulo)+'</div>'
        +'<div style="display:flex;gap:6px;margin-top:3px;flex-wrap:wrap">'
          +'<span style="font-size:9px;font-weight:700;color:'+(VK_ETAPA_COR[t.status]||'var(--mu)')+'">'+( VK_ETAPA_LABEL[t.status]||'A Fazer')+'</span>'
          +(t.prazo?'<span style="font-size:9px;color:'+(vencido?'#f87676':'var(--mu)')+'">📅 '+fDt(t.prazo)+(vencido?' (atrasado)':'')+'</span>':'')
          +(t.responsavel?'<span style="font-size:9px;color:var(--mu)">👤 '+t.responsavel+'</span>':'')
        +'</div>'
      +'</div>'
      +'<button onclick="vkEditar(\''+t.id+'\')" style="font-size:10px;padding:3px 8px;border-radius:4px;background:var(--sf3);border:1px solid var(--bd);color:var(--mu);cursor:pointer">✏</button>'
      +'<button onclick="vkDeletarPasta(\''+t.id+'\','+cid+')" style="font-size:10px;padding:3px 8px;border-radius:4px;background:var(--sf3);border:1px solid rgba(201,72,74,.3);color:#c9484a;cursor:pointer">✕</button>'
    +'</div>';
  }

  var html = '';
  if(pend.length) html += pend.map(row).join('');
  if(done.length){
    html += '<div style="padding:6px 14px;font-size:10px;font-weight:700;color:var(--mu);text-transform:uppercase;letter-spacing:.06em;background:var(--sf3);border-bottom:1px solid var(--bd)">Concluídas ('+done.length+')</div>';
    html += done.map(row).join('');
  }
  return html;
}

// ── Criar tarefa a partir de andamento ──
function _criarTarefaDeAndamento(cid, idx){
  var c = findClientById(cid);
  if(!c) return;
  var movs = (localMov[cid]||[]).concat((c.movimentacoes||[]).map(function(m){return {data:m.data,movimentacao:m.desc||m.movimentacao};}));
  var m = movs[idx];
  if(!m) return;
  var txt = (m.movimentacao||m.desc||m.descricao||'').slice(0,120);
  var titulo = 'Providenciar: '+txt;

  abrirModal('\ud83d\udccb Criar Tarefa do Andamento',
    '<div style="background:var(--sf3);border-radius:6px;padding:10px 12px;margin-bottom:12px;font-size:11px;color:var(--mu)">'
      +'<strong>Andamento:</strong> '+escapeHtml(txt)
    +'</div>'
    +'<div><label class="fm-lbl">T\u00edtulo da tarefa</label>'
      +'<input class="fm-inp" id="tma-titulo" value="'+escapeHtml(titulo)+'"></div>'
    +'<div class="fm-row" style="margin-top:8px">'
      +'<div><label class="fm-lbl">Prazo</label><input class="fm-inp" type="date" id="tma-prazo"></div>'
      +'<div><label class="fm-lbl">Prioridade</label><select class="fm-inp" id="tma-prior"><option value="alta">Alta</option><option value="media" selected>M\u00e9dia</option><option value="baixa">Baixa</option></select></div>'
      +'<div><label class="fm-lbl">Respons\u00e1vel</label><select class="fm-inp" id="tma-resp"><option>Clarissa</option><option>Assistente</option><option>Estagi\u00e1rio 1</option><option>Estagi\u00e1rio 2</option></select></div>'
    +'</div>',
  function(){
    var tit = document.getElementById('tma-titulo')?.value.trim();
    if(!tit){ showToast('Informe o t\u00edtulo'); return; }
    vkTasks.push({
      id:'vk'+genId(), titulo:tit, tipo:'tarefa',
      prioridade: document.getElementById('tma-prior')?.value||'media',
      responsavel: document.getElementById('tma-resp')?.value||'Clarissa',
      prazo: document.getElementById('tma-prazo')?.value||'',
      cliente: c.cliente, processo: cid,
      status:'todo', obs:'Criada a partir de andamento: '+txt.slice(0,60),
      origem:'andamento'
    });
    vkSalvar(); fecharModal(); marcarAlterado();
    var el = document.getElementById('tp7-list-'+cid);
    if(el) el.innerHTML = _renderTarefasPasta(cid);
    showToast('Tarefa criada a partir do andamento \u2713');
  }, '\ud83d\udccb Criar tarefa');
}

function vkDeletarPasta(id, cid){
  const t = vkTasks.find(function(x){return String(x.id)===String(id);});
  abrirModal('Excluir tarefa',
    '<div style="font-size:13px;color:var(--mu);line-height:1.6">Excluir <strong style="color:var(--tx)">"'+(t?escapeHtml(t.titulo||'esta tarefa'):'esta tarefa')+'"</strong>?</div>',
    ()=>{
      _tombstoneAdd('co_vktasks', id);
      vkTasks = vkTasks.filter(function(x){return String(x.id)!==String(id);});
      vkSalvar(); marcarAlterado(); fecharModal();
      var el = document.getElementById('tp7-list-'+cid);
      if(el) el.innerHTML = _renderTarefasPasta(cid);
      showToast('Tarefa excluída');
    }, 'Excluir'
  );
  setTimeout(()=>{ const b=document.getElementById('modal-save'); if(b){b.style.background='var(--red)';b.textContent='Confirmar exclusão';} },50);
}

function vkTogglePasta(id, cid){
  var t = vkTasks.find(function(x){return String(x.id)===String(id);});
  if(!t) return;
  var wasDone = isDone(t);
  t.status = wasDone ? 'todo' : 'done';
  if(!wasDone) t.concluido_em = new Date(HOJE).toISOString().slice(0,10);
  else delete t.concluido_em;
  vkSalvar(); marcarAlterado();
  var el = document.getElementById('tp7-list-'+cid);
  if(el) el.innerHTML = _renderTarefasPasta(cid);
}

function vkNovaTaskPasta(cid){
  var c = findClientById(cid);
  var nome = c ? c.cliente : '';
  abrirModal('✅ Nova Tarefa — '+escapeHtml(nome),
    '<div><label class="fm-lbl">Título <span class="req">*</span></label>'
      +'<input class="fm-inp" id="vkntp-titulo" placeholder="Ex: Protocolar recurso..."></div>'
    +'<div class="fm-row" style="margin-top:8px">'
      +'<div><label class="fm-lbl">Prazo</label><input class="fm-inp" type="date" id="vkntp-prazo"></div>'
      +'<div><label class="fm-lbl">Prioridade</label><select class="fm-inp" id="vkntp-prior"><option value="alta">Alta</option><option value="media" selected>Média</option><option value="baixa">Baixa</option></select></div>'
      +'<div><label class="fm-lbl">Responsável</label><select class="fm-inp" id="vkntp-resp"><option>Clarissa</option><option>Assistente</option><option>Estagiário 1</option><option>Estagiário 2</option></select></div>'
    +'</div>'
    +'<div style="margin-top:8px"><label class="fm-lbl">Observação</label><textarea class="fm-inp" id="vkntp-obs" rows="2"></textarea></div>',
    function(){
      var titulo = document.getElementById('vkntp-titulo')?.value.trim();
      if(!titulo){ alert('Informe o título'); return; }
      vkTasks.push({
        id:'vk'+genId(), titulo:titulo, tipo:'tarefa',
        prioridade: document.getElementById('vkntp-prior')?.value||'media',
        responsavel: document.getElementById('vkntp-resp')?.value||'Clarissa',
        prazo: document.getElementById('vkntp-prazo')?.value||'',
        cliente: nome, processo: cid,
        status:'todo', obs: document.getElementById('vkntp-obs')?.value.trim()||'',
        origem:'manual'
      });
      vkSalvar(); fecharModal(); marcarAlterado();
      var el = document.getElementById('tp7-list-'+cid);
      if(el) el.innerHTML = _renderTarefasPasta(cid);
      showToast('Tarefa criada e vinculada ✓');
    }, '✅ Criar tarefa');
}

function vkToggleLista(id){
  var t = vkTasks.find(function(x){return String(x.id)===String(id);});
  if(!t) return;
  var wasDone = isDone(t);
  t.status = wasDone ? 'todo' : 'done';
  if(!wasDone) t.concluido_em = new Date(HOJE).toISOString().slice(0,10);
  else delete t.concluido_em;
  vkSalvar(); vkRender(); marcarAlterado();
}

function vkCard(t){
  const hoje = new Date(HOJE).toISOString().slice(0,10);
  const diasRestantes = t.prazo ? Math.ceil((new Date(t.prazo)-new Date(hoje))/(1000*60*60*24)) : null;
  const fmtDt = d => fDt(d);
  const respCor = VK_RESP_COR[t.responsavel]||'#374151';

  // Barra de prazo
  let prazoBar = '';
  let prazoColor = '#4ade80';
  if(diasRestantes!==null){
    if(diasRestantes<0)  prazoColor='#f87676';
    else if(diasRestantes<=3) prazoColor='#f87171';
    else if(diasRestantes<=7) prazoColor='#fb923c';
    else prazoColor='#4ade80';
    const pct = diasRestantes<=0?100:Math.min(100,Math.max(5,(1-diasRestantes/30)*100));
    prazoBar=`<div class="vk-prazo-bar"><div class="vk-prazo-fill" style="width:${pct}%;background:${prazoColor}"></div></div>`;
  }

  const respTag = t.responsavel
    ? `<span class="vk-resp-avatar" style="background:${respCor}" title="${t.responsavel}">${t.responsavel.slice(0,2).toUpperCase()}</span>`
    : '';

  const bloqueado = t.origem==='agenda';

  // Indicador de gargalo: card parado há mais de 5 dias na mesma coluna.
  // Só considera tarefas com status_since definido (evita falso positivo em
  // cards antigos criados antes desse campo existir — eles ficam neutros).
  var gargaloHtml = '';
  if(t.status_since && t.status!=='done' && t.status!=='concluido'){
    var diasParado = Math.floor((new Date(hoje)-new Date(t.status_since))/(1000*60*60*24));
    if(diasParado>=5){
      var corG = diasParado>=10 ? '#f87171' : '#fb923c';
      gargaloHtml = '<span class="vk-gargalo" title="Parado há '+diasParado+' dias na coluna" style="font-size:10px;color:'+corG+';font-weight:700;margin-left:6px">⏱ '+diasParado+'d</span>';
    }
  }

  // Status dropdown — permite mudar coluna no mobile (onde drag é ruim)
  const statusSel = '<select class="vk-card-status-sel" onchange="vkMudarStatus(\''+t.id+'\', this.value); event.stopPropagation()" onclick="event.stopPropagation()" title="Mover">'
    + VK_COLUNAS.map(function(c){ return '<option value="'+c.id+'"'+(c.id===t.status?' selected':'')+'>'+c.icon+' '+c.label+'</option>'; }).join('')
    + '</select>';

  const isDone = t.status === 'done' || t.status === 'concluido';
  if(isDone){
    return '<div class="vk-card vk-card-done" data-id="'+t.id+'" id="vkcard-'+t.id+'">'
      +'<div class="vk-card-done-inner">'
        +'<span class="vk-card-done-check">✅</span>'
        +'<div style="flex:1;min-width:0">'
          +'<div class="vk-card-titulo vk-card-titulo-done">'+(t.titulo||'Tarefa')+'</div>'
          +(t.cliente?'<div class="vk-card-done-cli">'+t.cliente+'</div>':'')
          +(t.desfecho?'<div class="vk-card-done-desfecho">'+t.desfecho+'</div>':'')
          +'<div class="vk-card-done-data">Concluido em '+(t.concluido_em||'hoje')+'</div>'
        +'</div>'
        +'<button class="vk-card-btn" onclick="vkMudarStatus(\''+t.id+'\',\'todo\')" title="Reabrir">↩</button>'
        +'<button class="vk-card-btn del" onclick="vkDeletar(\''+t.id+'\')" title="Apagar">✕</button>'
      +'</div>'
    +'</div>';
  }

  const prazoCardClass = t.tipo==='prazo' ? ' vk-card-prazo' : '';
  return `<div class="vk-card${prazoCardClass}" draggable="true" data-id="${t.id}" id="vkcard-${t.id}">
    <div class="vk-card-top">
      <div class="vk-card-titulo">${t.titulo}${gargaloHtml}</div>
      ${respTag}
    </div>
    <div class="vk-card-badges">
      <span class="vk-badge tipo-${t.tipo||'tarefa'}">${TIPO_LABEL[t.tipo]||'📋 Tarefa'}</span>
      ${t.prioridade==='alta'?'<span class="vk-badge prior-alta">🔴 Alta</span>':
        t.prioridade==='media'?'<span class="vk-badge prior-media">🟡 Média</span>':
        '<span class="vk-badge prior-baixa">🟢 Baixa</span>'}
      ${t.prazo?`<span class="vk-badge prazo-badge" style="color:${prazoColor}">📅 ${fmtDt(t.prazo)}${diasRestantes!==null?` (${diasRestantes<0?'atrasado':diasRestantes+'d'})`:''}</span>`:''}
    </div>
    ${t.obs?`<div style="font-size:11px;color:var(--mu);margin-bottom:4px;font-style:italic">${t.obs}</div>`:''}
    ${prazoBar}
    <div class="vk-card-footer">
      <span class="vk-card-cli">${t.contato_nome?`👤 ${t.contato_nome}`:(t.cliente||'—')}</span>
      <div class="vk-card-acoes">
        ${statusSel}
        <button class="vk-card-btn" onclick="vkEditar('${t.id}')">✏</button>
        <button class="vk-card-btn" onclick="vkMarcarHoje('${t.id}')" title="Adicionar ao checklist de hoje">📋</button>
        ${t.status==='revisao'?`<button class="vk-card-btn concluir" onclick="vkConcluirComDesfecho('${t.id}')" title="Concluir e lançar próximo ato">✅ Concluir</button>`:''}
        ${!bloqueado?`<button class="vk-card-btn del" onclick="vkDeletar('${t.id}')">✕</button>`:''}
      </div>
    </div>
  </div>`;
}

// ── DRAG AND DROP ──
function vkBindDrag(){
  document.querySelectorAll('.vk-card').forEach(card=>{
    card.addEventListener('dragstart', e=>{
      _vkDrag = card.dataset.id;
      card.classList.add('dragging');
      e.dataTransfer.effectAllowed='move';
    });
    card.addEventListener('dragend', ()=>card.classList.remove('dragging'));
  });
}

function vkDrop(colId, el){
  el.classList.remove('drag-over');
  if(!_vkDrag) return;
  const id = _vkDrag;
  _vkDrag = null;
  // Tarefa manual
  let t = vkTasks.find(x=>String(x.id)===String(id));
  if(!t){
    // Era da agenda — promover para manual com novo status
    const agId = id.startsWith('ag') ? parseInt(id.slice(2)) : null;
    const orig = PEND.find(p=>p.id===agId);
    if(!orig) return;
    t = {
      id: 'vk'+genId(), titulo:orig.titulo, tipo:agTipo(orig),
      status: colId, responsavel:'Clarissa', prioridade:'media',
      prazo:orig.dt_raw, cliente:orig.cliente||'', processo:orig.id_processo||0,
      obs:'', origem:'manual',
      status_since: new Date(HOJE).toISOString().slice(0,10)
    };
    if(colId==='done') t.concluido_em = new Date(HOJE).toISOString().slice(0,10);
    vkTasks.push(t);
    vkSalvar();
    vkRender();
    var lbl = VK_COLUNAS.find(function(c){ return c.id===colId; });
    showToast('Movido para "'+(lbl?lbl.label:colId)+'"');
    return;
  }
  vkMudarStatus(id, colId);
}

// ── URGENTES ──
function vkRenderUrgentes(tasks){
  const hoje = new Date(HOJE).toISOString().slice(0,10);
  const fmtDt= d=>d?fDt(d):'—';
  const urg  = tasks
    .filter(t=>t.prazo && t.prazo>=hoje && !isDone(t))
    .sort((a,b)=>a.prazo.localeCompare(b.prazo));
  const atras= tasks.filter(t=>t.prazo && t.prazo<hoje && !isDone(t))
    .sort((a,b)=>b.prazo.localeCompare(a.prazo));

  const itemHtml = t=>{
    const dias = Math.ceil((new Date(t.prazo)-new Date(hoje))/(1000*60*60*24));
    const cor  = dias<=0?'#f87171':dias<=3?'#f87171':dias<=7?'#fb923c':'#4ade80';
    return `<div class="vk-urg-item tipo-${t.tipo}">
      <span style="font-size:12px">${TIPO_LABEL[t.tipo]||'📋'}</span>
      <div style="flex:1">
        <div class="vk-urg-txt">${t.titulo}</div>
        <div class="vk-urg-cli">${t.cliente||'—'} · Resp: ${t.responsavel||'—'}</div>
      </div>
      <div style="text-align:right">
        <div style="font-size:11px;font-weight:700;color:${cor}">${dias<=0?'ATRASADO':dias===0?'HOJE':dias+'d'}</div>
        <div style="font-size:10px;color:var(--mu)">${fmtDt(t.prazo)}</div>
      </div>
    </div>`;
  };

  return `<div class="vk-urgentes" style="overflow-y:auto;flex:1">
    ${atras.length?`
      <div class="vk-urg-title" style="color:#f87171">⚠️ ATRASADOS — ${atras.length}</div>
      ${atras.map(itemHtml).join('')}
    `:''}
    ${urg.length?`
      <div class="vk-urg-title" style="color:#fb923c;margin-top:${atras.length?16:0}px">⏰ PRÓXIMOS 30 DIAS — ${urg.length}</div>
      ${urg.map(itemHtml).join('')}
    `:''}
    ${!atras.length&&!urg.length?`<div style="text-align:center;padding:48px;color:var(--mu);font-size:13px">✅ Nenhum prazo urgente</div>`:''}
  </div>`;
}

// ── POR RESPONSÁVEL ──
function vkRenderResponsavel(tasks){
  const resps = ['Clarissa','Assistente','Estagiário 1','Estagiário 2'];
  const cols  = resps.map(resp=>{
    const itens = tasks.filter(t=>t.responsavel===resp);
    if(!itens.length) return '';
    const pendentes = itens.filter(t=>!isDone(t)).length;
    const cor = VK_RESP_COR[resp]||'#374151';
    const itensHtml = itens.map(t=>{
      const diasR = t.prazo ? Math.ceil((new Date(t.prazo)-new Date(HOJE))/(1000*60*60*24)) : null;
      const corPrazo = diasR===null?'var(--mu)':diasR<0?'#f87171':diasR<=3?'#f87171':diasR<=7?'#fb923c':'var(--mu)';
      return `<div style="padding:8px 0;border-bottom:1px solid var(--sf3)">
        <div style="font-size:12px;font-weight:600;color:var(--of);margin-bottom:3px">${t.titulo}</div>
        <div style="display:flex;align-items:center;gap:6px;flex-wrap:wrap">
          <span class="vk-badge tipo-${t.tipo||'tarefa'}" style="font-size:9px">${TIPO_LABEL[t.tipo]||'Tarefa'}</span>
          ${t.prazo?`<span style="font-size:10px;color:${corPrazo}">📅 ${fDt(t.prazo).slice(0,8)}</span>`:''}
          <span style="font-size:10px;color:var(--mu)">${t.cliente||''}</span>
          <span class="vk-badge" style="background:var(--sf3);color:var(--mu)">${t.status==='concluido'?'✅ Feito':t.status==='andamento'?'⚡ Em andamento':t.status==='revisao'?'🔍 Revisão':'📋 A fazer'}</span>
        </div>
      </div>`;
    }).join('');
    return `<div class="vk-col" style="flex:0 0 260px">
      <div class="vk-col-head" style="border-left:3px solid ${cor}">
        <span class="vk-col-title">
          <span class="vk-resp-avatar" style="background:${cor}">${resp.slice(0,2).toUpperCase()}</span>
          ${resp}
        </span>
        <span class="vk-col-count">${pendentes} pendente${pendentes!==1?'s':''}</span>
      </div>
      <div class="vk-col-body">${itensHtml||'<div style="font-size:11px;color:var(--mu);padding:8px;font-style:italic">Sem tarefas</div>'}</div>
    </div>`;
  }).filter(Boolean).join('');
  return `<div class="vk-board">${cols||'<div style="padding:32px;color:var(--mu)">Nenhuma tarefa atribuída</div>'}</div>`;
}

// ── NOVA TAREFA ──
function vkNovaTask(tipoDefault='tarefa'){
  // Deduplicar clientes por nome (evita repetições)
  var seen = {};
  // Processo selector agora usa _procPicker (autocomplete fuzzy), n\u00e3o mais dropdown com N options.
  abrirModal('\u2705 Nova Tarefa',
    '<div class="fm-row">'
      +'<div style="flex:2"><label class="fm-lbl">T\u00edtulo <span class="req">*</span></label>'
        +'<input class="fm-inp" id="vknt-titulo" placeholder="Ex: Protocolar recurso..."></div>'
      +'<div><label class="fm-lbl">Prazo</label>'
        +'<input class="fm-inp" type="date" id="vknt-prazo"></div>'
    +'</div>'
    +'<div style="margin-top:8px"><label class="fm-lbl">Vinculado \u00e0 <span class="req">*</span></label>'
      +'<div style="display:flex;gap:6px;margin-bottom:6px">'
        +'<button type="button" class="fm-chip-btn on" id="vknt-vinc-pasta" onclick="document.getElementById(\'vknt-vinc-pasta\').classList.add(\'on\');document.getElementById(\'vknt-vinc-esc\').classList.remove(\'on\');document.getElementById(\'vknt-proc-wrap\').style.display=\'block\'">\ud83d\udcc1 Pasta do cliente</button>'
        +'<button type="button" class="fm-chip-btn" id="vknt-vinc-esc" onclick="document.getElementById(\'vknt-vinc-esc\').classList.add(\'on\');document.getElementById(\'vknt-vinc-pasta\').classList.remove(\'on\');document.getElementById(\'vknt-proc-wrap\').style.display=\'none\'">\ud83c\udfe2 Escrit\u00f3rio (interno)</button>'
      +'</div>'
      +'<div id="vknt-proc-wrap">'+_procPickerHtml('vknt-proc', {placeholder:'Digite nome do cliente, pasta ou n\u00famero...', allowCreate:false})+'</div>'
      +'<input type="hidden" id="vknt-cli" value="">'
    +'</div>'
    +'<div class="fm-row" style="margin-top:8px">'
      +'<div><label class="fm-lbl">Tipo</label><select class="fm-inp" id="vknt-tipo">'
        +'<option value="tarefa"'+(tipoDefault==='tarefa'?' selected':'')+'>\ud83d\udccb Tarefa</option>'
        +'<option value="prazo"'+(tipoDefault==='prazo'?' selected':'')+'>\u2696\ufe0f Prazo Judicial</option>'
        +'<option value="audiencia"'+(tipoDefault==='audiencia'?' selected':'')+'>\ud83d\udd28 Audi\u00eancia</option>'
        +'<option value="compromisso"'+(tipoDefault==='compromisso'?' selected':'')+'>\ud83d\udcc5 Compromisso</option>'
      +'</select></div>'
      +'<div><label class="fm-lbl">Prioridade</label><select class="fm-inp" id="vknt-prior">'
        +'<option value="alta">Alta</option><option value="media" selected>M\u00e9dia</option><option value="baixa">Baixa</option></select></div>'
      +'<div><label class="fm-lbl">Respons\u00e1vel</label><select class="fm-inp" id="vknt-resp">'
        +'<option>Clarissa</option><option>Assistente</option><option>Estagi\u00e1rio 1</option><option>Estagi\u00e1rio 2</option></select></div>'
    +'</div>'
    +'<div style="margin-top:8px"><label class="fm-lbl">Observa\u00e7\u00e3o</label>'
      +'<textarea class="fm-inp" id="vknt-obs" rows="2" placeholder="Detalhes..."></textarea></div>',
  function(){
    var titulo = (document.getElementById('vknt-titulo')||{}).value;
    if(!titulo||!titulo.trim()){ showToast('Informe o título'); return; }
    titulo = titulo.trim();
    var isPasta = document.getElementById('vknt-vinc-pasta') && document.getElementById('vknt-vinc-pasta').classList.contains('on');
    var _procId = parseInt((document.getElementById('vknt-proc-id')||{}).value)||0;
    var _selCli = _procId ? findClientById(_procId) : null;
    var _cliNome = _selCli ? (_selCli.cliente||'') : '';
    if(isPasta && !_procId){ showToast('Selecione a pasta do cliente'); return; }
    if(!isPasta){ _procId = 0; _cliNome = 'Escrit\u00f3rio'; }
    vkTasks.push({
      id:'vk'+genId(), titulo:titulo,
      tipo: (document.getElementById('vknt-tipo')||{}).value||'tarefa',
      prioridade: (document.getElementById('vknt-prior')||{}).value||'media',
      responsavel: (document.getElementById('vknt-resp')||{}).value||'Clarissa',
      prazo: (document.getElementById('vknt-prazo')||{}).value||'',
      cliente: _cliNome, processo: _procId,
      status:'todo', obs: ((document.getElementById('vknt-obs')||{}).value||'').trim(),
      origem:'manual',
      status_since: new Date(HOJE).toISOString().slice(0,10)
    });
    vkSalvar(); fecharModal(); vkRender(); marcarAlterado();
    // Re-renderizar pasta se vinculada
    if(_procId){
      var elTp = document.getElementById('tp7-list-'+_procId);
      if(elTp) elTp.innerHTML = _renderTarefasPasta(_procId);
    }
    showToast('Tarefa criada \u2713');
  },'\u2705 Criar Tarefa');
}

// ── EDITAR ──
function vkEditar(id){
  const t = vkTasks.find(x=>String(x.id)===String(id));
  if(!t){ showToast('Tarefa da agenda — edite na ficha do processo'); return; }
  abrirModal('✏️ Editar Tarefa',`
  <div class="fm-row">
    <div style="flex:2"><label class="fm-lbl">Título</label>
      <input class="fm-inp" id="vked-titulo" value="${t.titulo||''}">
    </div>
    <div><label class="fm-lbl">Prazo</label>
      <input class="fm-inp" type="date" id="vked-prazo" value="${t.prazo||''}">
    </div>
  </div>
  <div class="fm-row" style="margin-top:8px">
    <div><label class="fm-lbl">Responsável</label>
      <select class="fm-inp" id="vked-resp">
        ${['Clarissa','Assistente','Estagiário 1','Estagiário 2'].map(r=>`<option ${r===t.responsavel?'selected':''}>${r}</option>`).join('')}
      </select>
    </div>
    <div><label class="fm-lbl">Prioridade</label>
      <select class="fm-inp" id="vked-prior">
        ${['alta','media','baixa'].map(p=>`<option value="${p}" ${p===t.prioridade?'selected':''}>${p==='alta'?'🔴 Alta':p==='media'?'🟡 Média':'🟢 Baixa'}</option>`).join('')}
      </select>
    </div>
    <div><label class="fm-lbl">Status</label>
      <select class="fm-inp" id="vked-status">
        ${VK_COLUNAS.map(c=>`<option value="${c.id}" ${c.id===t.status?'selected':''}>${c.icon} ${c.label}</option>`).join('')}
      </select>
    </div>
  </div>
  <div style="margin-top:8px"><label class="fm-lbl">Observação</label>
    <textarea class="fm-inp" id="vked-obs" rows="2">${t.obs||''}</textarea>
  </div>
  `,()=>{
    t.titulo      = document.getElementById('vked-titulo')?.value.trim()||t.titulo;
    t.prazo       = document.getElementById('vked-prazo')?.value||t.prazo;
    t.responsavel = document.getElementById('vked-resp')?.value;
    t.prioridade  = document.getElementById('vked-prior')?.value;
    t.status      = document.getElementById('vked-status')?.value;
    t.obs         = document.getElementById('vked-obs')?.value.trim();
    vkSalvar();
    fecharModal();
    vkRender();
    renderChecklist();
    showToast('Tarefa atualizada ✓');
  },'💾 Salvar');
}

// ── DELETAR ──

function vkMarcarHoje(id){
  const t = vkTasks.find(x=>String(x.id)===String(id));
  if(!t) return;
  const hoje = getTodayKey();
  if(t.paraHoje===hoje){
    t.paraHoje='';
    showToast('Removido do checklist de hoje');
  } else {
    t.paraHoje=hoje;
    showToast('Adicionado ao checklist de hoje ✓');
  }
  vkSalvar();
  renderChecklist();
  vkRender();
}
function vkDeletar(id){
  const t = vkTasks.find(x=>String(x.id)===String(id));
  if(!t) return;
  abrirModal('Excluir tarefa',
    `<div style="font-size:13px;color:var(--mu);line-height:1.6">Excluir <strong style="color:var(--tx)">"${escapeHtml(t.titulo||'esta tarefa')}"</strong>?<br><span style="font-size:11px">Esta ação não pode ser desfeita.</span></div>`,
    ()=>{
      _tombstoneAdd('co_vktasks', id);
      vkTasks = vkTasks.filter(x=>String(x.id)!==String(id));
      vkSalvar(); marcarAlterado(); fecharModal(); vkRender();
      showToast('Tarefa excluída');
    }, 'Excluir'
  );
  setTimeout(()=>{ const b=document.getElementById('modal-save'); if(b){b.style.background='var(--red)';b.textContent='Confirmar exclusão';} },50);
}

// ── Detecta tipo de evento pela campo tipo ou pelo título ──
function agTipo(p){
  // tipo_compromisso é preenchido pelo modal novo; p.tipo vem do Projuris
  const t = (p.tipo_compromisso||p.tipo||'').toLowerCase();
  if(/audien|audiên|julgam|instrução|concilia/.test(t)) return 'audiencia';
  if(/prazo|limit|vencim|recurso|embargo|protocolo/.test(t)) return 'prazo';
  if(/reuni[aã]o|meeting/.test(t)) return 'reuniao';
  if(/tarefa|acompanhar|verificar|ligar|enviar/.test(t)) return 'tarefa';
  // Fallback: detectar pelo título/descrição
  const tit = (p.titulo||p.descricao||'').toLowerCase();
  if(/audien|audiên|julgam|instrução|concilia/.test(tit)) return 'audiencia';
  if(/prazo|limit|vencim|recurso|embargo/.test(tit)) return 'prazo';
  if(/reuni[aã]o|meeting/.test(tit)) return 'reuniao';
  if(/tarefa|acompanhar|verificar|ligar|enviar/.test(tit)) return 'tarefa';
  return 'outro';
}
const TIPO_LABEL = {
  tarefa:'📋 Tarefa', audiencia:'🔨 Audiência', compromisso:'📅 Compromisso',
  prazo:'⚖️ Prazo Judicial'
};


// ── Categorias financeiras ──
const CAT_DESPESA = {
  // Fixas do escritório
  'Aluguel':            { grupo:'Estrutura',    icone:'🏢', recorrente:true  },
  'Condomínio':         { grupo:'Estrutura',    icone:'🏢', recorrente:true  },
  'Internet / Telefone':{ grupo:'Estrutura',    icone:'📡', recorrente:true  },
  'Energia elétrica':   { grupo:'Estrutura',    icone:'⚡', recorrente:true  },
  'Água':               { grupo:'Estrutura',    icone:'💧', recorrente:true  },
  // Pessoal
  'Salário colaborador':{ grupo:'Pessoal',      icone:'👤', recorrente:true  },
  'Pro-labore':         { grupo:'Pessoal',      icone:'👤', recorrente:true  },
  'INSS patronal':      { grupo:'Pessoal',      icone:'📋', recorrente:true  },
  'FGTS':               { grupo:'Pessoal',      icone:'📋', recorrente:true  },
  // Serviços
  'Contador':           { grupo:'Serviços',     icone:'📊', recorrente:true  },
  'Projuris / Sistemas':{ grupo:'Serviços',     icone:'💻', recorrente:true  },
  'Limpeza / Faxina':   { grupo:'Serviços',     icone:'🧹', recorrente:true  },
  'Manutenção':         { grupo:'Serviços',     icone:'🔧', recorrente:false },
  'Advocacia terceirizada':{ grupo:'Serviços',  icone:'⚖️', recorrente:false },
  // Variáveis
  'Repasse ao cliente':     { grupo:'Repassses',  icone:'🏦', recorrente:false },
  'Material de escritório':{ grupo:'Variáveis', icone:'📎', recorrente:false },
  'Cartório / Custas':  { grupo:'Variáveis',    icone:'🏛️', recorrente:false },
  'Transporte / Uber':  { grupo:'Variáveis',    icone:'🚗', recorrente:false },
  'Alimentação':        { grupo:'Variáveis',    icone:'🍽️', recorrente:false },
  'Marketing':          { grupo:'Variáveis',    icone:'📢', recorrente:false },
  'Outras despesas':    { grupo:'Variáveis',    icone:'📌', recorrente:false },
};
const CAT_RECEITA = {
  'Honorários advocatícios': { icone:'⚖️' },
  'Sucumbência':             { icone:'🏛️' },
  'Acordo / Condenação':     { icone:'🤝' },
  'Consultoria':             { icone:'💡' },
  'Alvará judicial (repasse)':{ icone:'🏦' },
  'Reembolso de despesas':   { icone:'↩️' },
  'Outras receitas':         { icone:'📌' },
};

// Colaboradores cadastrados
let _colaboradores = [];
try { _colaboradores = JSON.parse(lsGet('co_colab')||'[]'); } catch{}

// Despesas recorrentes (template)
let _despFixas = [];
try { _despFixas = JSON.parse(lsGet('co_despfixas')||'[]'); } catch{}

// ═══════════════════════════════════════════════════════════════
// ══ VIEW FINANCEIRO GLOBAL v2 ══
// ═══════════════════════════════════════════════════════════════
let _vfTab = 'mes';

function vfSetTab(tab, el){
  if(_vfTab && _vfTab !== tab) navPush(navCapture());
  _vfTab = tab;
  document.querySelectorAll('.vf-tab').forEach(function(b){ b.classList.remove('on'); });
  if(el) el.classList.add('on');
  else {
    var btns = document.querySelectorAll('.vf-tab');
    btns.forEach(function(b){
      if(b.getAttribute('onclick')&&b.getAttribute('onclick').indexOf("'"+tab+"'")!==-1) b.classList.add('on');
    });
  }
  vfRender();
}

function goFin(){
  goView('vf');
  vfRender();
}

// Agregar TODOS os lançamentos: Projuris (FIN_XLSX) + localLanc + finLancs
// PERF: resultado cacheado — rebuilt só quando _vfTodosInvalido=true (marcarAlterado invalida)
function vfTodos(){
  if(!_vfTodosInvalido && _vfTodosCache) return _vfTodosCache;
  const hoje = _HOJE_STR;
  const pasta_map = {};
  CLIENTS.forEach(c=>{ pasta_map[String(c.pasta)] = c.cliente; });

  // 1. Projuris — status pode ter sido atualizado por vfBaixar (finLancs._projuris_id)
  //    OU por baixa manual em localLanc (proj_ref)
  const baixasProj = {};
  // Checar finLancs (via vfBaixar)
  (finLancs||[]).forEach(function(l){
    if(l._projuris_id) baixasProj['p'+l._projuris_id] = l;
  });
  // Checar localLanc (via finBaixarLanc)
  (localLanc||[]).forEach(function(l){
    if(l.proj_ref) baixasProj[l.proj_ref] = l;
  });
  // Permanently excluded clients (Amanda Fabiane - confirmed by user)
  var EXCL_PASTAS = new Set(['970','1001']);
  var EXCL_PROC_IDS = new Set([59867077, 60369997]);

  // FIN_XLSX desligado — migrado para localLanc
  const proj = [];

    // 2. localLanc (por processo) — exclude permanently deleted clients
  const local = (localLanc||[]).filter(function(l){
    return !EXCL_PROC_IDS.has(Number(l.id_processo||0));
  }).map(l=>({
    id: 'l'+l.id, origem:'local',
    tipo: (l.tipo==='despesa_reimb'||l.tipo==='despesa_interna'||l.tipo==='despint'||l.tipo==='repasse'||l.direcao==='pagar')?'pagar':'receber',
    subtipo: l.tipo||'outro',
    desc: l.desc||'—', cliente: l.cliente||'—',
    centro: l.centro||'', valor: l.valor||0,
    data: l.data||l.venc, venc: l.venc||l.data,
    status: l.status==='pago'?'pago': l.status==='vencido'?'vencido': (l.venc&&l.venc<hoje?'vencido':'pendente'),
    forma: l.forma||'', obs: l.obs||''
  }));

  // 3. finLancs (escritório global)
  // EXCLUIR: registros "sombra" criados apenas para marcar baixa de Projuris ou extrato
  const glob = (finLancs||[])
    .filter(function(l){ return !l._projuris_id && !l.proj_ref && !l.origem_proj; })
    .map(l=>({
      id: 'g'+l.id, origem:'global',
      tipo: l.tipo||'receber',
      subtipo: l.cat||'outro',
      desc: l.desc||'—', cliente: l.cliente||'Escritório',
      centro: l.centro||'', valor: parseFloat(l.valor)||0,
      data: l.data, venc: l.data,
      status: l.pago?'pago':(l.data&&l.data<hoje?'vencido':'pendente'),
      forma: l.forma||'', obs: ''
    }));

  // 4. localLanc — excluir registros sombra (proj_ref = baixa de Projuris)
  const localFiltrado = local.filter(function(l){
    const orig = (localLanc||[]).find(function(x){ return 'l'+x.id===l.id; });
    return orig && !orig.proj_ref && !orig.origem_proj;
  });

  const result = [...proj,...localFiltrado,...glob].sort((a,b)=>(a.data||'').localeCompare(b.data||''));
  _vfTodosCache = result;
  _vfTodosInvalido = false;
  return result;
}

// ═══════════════════════════════════════════════════════════════
// ══ FINANCEIRO GLOBAL v2 — CONSOLIDAÇÃO DAS PASTAS ════════════
// ═══════════════════════════════════════════════════════════════

// Consolida dados de TODAS as pastas de clientes (somente leitura)
function _vfConsolidar(mesP){
  var recebimentos = [];
  var repasses = [];
  var despesas = [];
  // Guard: mesma lógica de _vfDespesasEscritorio — repasse não é despesa
  var _ehRepasse = function(l){
    if(l._repasse_alvara||l._repasse_acordo) return true;
    if(l.cat==='Repasse ao cliente') return true;
    if(l.tipo==='repasse') return true;
    return false;
  };
  (localLanc||[]).forEach(function(l){
    var isRep = _ehRepasse(l);
    var isDesp = l.tipo==='despesa'||l.tipo==='despint';
    var rec = isRec(l);
    if(isRep && rec){
      repasses.push(l);
    } else if(isDesp){
      despesas.push(l);
    } else if(!isRep && !isDesp && rec){
      var calc = _finCalcLanc(l);
      recebimentos.push({
        data: l.data||l.dt_baixa||'',
        cliente: l.cliente||'',
        processo: l.desc||'',
        descricao: l.desc||'',
        valor_bruto: calc.base_calculo,
        valor_honorarios: calc.honorarios_liquidos_escritorio,
        valor_cliente: calc.valor_cliente,
        forma: l.forma||'',
        _raw: l
      });
    }
  });
  // ── Despesas do escritório ficam em finLancs (tipo='pagar'), não em localLanc ──
  // Sem isso o card "Despesas Escritório" no Resumo fica R$ 0 mesmo com a aba
  // Despesas Escritório mostrando o total real. Excluir repasses (mesmo guard).
  (finLancs||[]).forEach(function(l){
    if(l.tipo==='pagar' && !_ehRepasse(l)){
      despesas.push(l);
    } else if(_ehRepasse(l) && (l.pago||l.status==='pago')){
      repasses.push(l);
    }
  });
  // Filtrar por mês se informado
  if(mesP){
    recebimentos = recebimentos.filter(function(r){return (r.data||'').startsWith(mesP);});
    repasses = repasses.filter(function(r){return (r.dt_baixa||r.data||'').startsWith(mesP);});
    despesas = despesas.filter(function(r){return (r.data||r.dt_baixa||'').startsWith(mesP);});
  }
  var totEntrou = recebimentos.reduce(function(s,r){return s+r.valor_bruto;},0);
  var totHon = recebimentos.reduce(function(s,r){return s+r.valor_honorarios;},0);
  var totCli = recebimentos.reduce(function(s,r){return s+r.valor_cliente;},0);
  var totRep = repasses.reduce(function(s,l){return s+(parseFloat(l.valor)||0);},0);
  var totDesp = despesas.reduce(function(s,l){return s+(parseFloat(l.valor)||0);},0);
  var saldo = roundMoney(totHon - totDesp);
  return {recebimentos:recebimentos, repasses:repasses, despesas:despesas, totEntrou:totEntrou, totHon:totHon, totCli:totCli, totRep:totRep, totDesp:totDesp, saldo:saldo};
}

// ── ABA RESUMO GLOBAL ──
function _vfResumoGlobal(mesP){
  var d = _vfConsolidar(mesP);
  var fV = function(v){return 'R$ '+Math.abs(v||0).toLocaleString('pt-BR',{minimumFractionDigits:2,maximumFractionDigits:2});};
  var maxVal = Math.max(d.totEntrou, d.totHon, d.totCli, d.totRep, d.totDesp, 1);

  function card(lbl, val, cor, sub, destaque){
    var pct = Math.min(100, Math.round(Math.abs(val)/maxVal*100));
    return '<div style="flex:1;min-width:140px;padding:14px 16px;background:'+(destaque?'linear-gradient(135deg,var(--sf2),'+cor+'15)':'var(--sf2)')+';border:1px solid '+(destaque?cor+'40':'var(--bd)')+';border-radius:10px">'
      +'<div style="font-size:9px;font-weight:700;text-transform:uppercase;color:var(--mu);margin-bottom:6px;letter-spacing:.05em">'+lbl+'</div>'
      +'<div style="font-size:20px;font-weight:800;color:'+cor+'">'+fV(val)+'</div>'
      +'<div style="height:4px;background:var(--sf3);border-radius:3px;margin-top:8px;overflow:hidden"><div style="width:'+pct+'%;height:100%;background:'+cor+';border-radius:3px"></div></div>'
      +(sub?'<div style="font-size:10px;color:var(--mu);margin-top:4px">'+sub+'</div>':'')
    +'</div>';
  }

  // Barra receita vs despesa
  var percRec = d.totEntrou > 0 ? Math.round(d.totHon/d.totEntrou*100) : 0;
  var percDesp = d.totHon > 0 ? Math.round(d.totDesp/d.totHon*100) : 0;

  return '<div style="padding:16px;max-width:900px">'
    +'<div style="display:flex;flex-wrap:wrap;gap:10px;margin-bottom:16px">'
      +card('Total que entrou', d.totEntrou, 'var(--tx)', d.recebimentos.length+' recebimento'+(d.recebimentos.length!==1?'s':''), false)
      +card('Receita escrit\u00f3rio', d.totHon, '#4ade80', percRec+'% do total', true)
      +card('Valores de clientes', d.totCli, '#fb923c', 'Cust\u00f3dia', false)
    +'</div>'
    +'<div style="display:flex;flex-wrap:wrap;gap:10px;margin-bottom:16px">'
      +card('Total repassado', d.totRep, 'var(--tx)', d.repasses.length+' repasse'+(d.repasses.length!==1?'s':''), false)
      +card('Despesas escrit\u00f3rio', d.totDesp, '#f87676', percDesp+'% da receita', false)
      +card('Saldo escrit\u00f3rio', d.saldo, d.saldo>=0?'#4ade80':'#c9484a', 'Receita \u2212 Despesas', true)
    +'</div>'
    // Barra visual receita vs despesa
    +'<div style="background:var(--sf2);border:1px solid var(--bd);border-radius:8px;padding:14px;margin-bottom:12px">'
      +'<div style="font-size:9px;font-weight:700;text-transform:uppercase;color:var(--mu);margin-bottom:8px">Receita vs Despesa</div>'
      +'<div style="display:flex;height:24px;border-radius:6px;overflow:hidden;background:var(--sf3)">'
        +(d.totHon>0?'<div style="width:'+Math.round(d.totHon/(d.totHon+d.totDesp)*100)+'%;background:#4ade80;display:flex;align-items:center;justify-content:center;font-size:9px;font-weight:700;color:#000">Receita '+fV(d.totHon)+'</div>':'')
        +(d.totDesp>0?'<div style="width:'+Math.round(d.totDesp/(d.totHon+d.totDesp)*100)+'%;background:#f87676;display:flex;align-items:center;justify-content:center;font-size:9px;font-weight:700;color:#fff">Despesa '+fV(d.totDesp)+'</div>':'')
      +'</div>'
    +'</div>'
    +'<div style="background:var(--sf2);border:1px solid var(--bd);border-radius:8px;padding:12px;font-size:11px;color:var(--mu)">'
      +'<strong>Nota:</strong> Valor de clientes \u00e9 cust\u00f3dia \u2014 n\u00e3o entra no saldo.'
    +'</div>'
  +'</div>';
}


// ── ABA RECEBIMENTOS ──
function _vfRecebimentos(mesP){
  var d = _vfConsolidar(mesP);
  var fV = function(v){return 'R$ '+Math.abs(v||0).toLocaleString('pt-BR',{minimumFractionDigits:2,maximumFractionDigits:2});};
  if(!d.recebimentos.length) return '<div style="padding:40px;text-align:center;color:var(--mu)">Nenhum recebimento no per\u00edodo.</div>';
  var totB=0,totH=0,totC=0;
  var html = '<div style="padding:16px;max-width:960px">'
    +'<div style="overflow-x:auto"><table style="width:100%;border-collapse:collapse">'
    +'<thead><tr style="background:var(--sf3)">'
      +'<th style="padding:8px 10px;text-align:left;font-size:10px;font-weight:700;text-transform:uppercase;color:var(--mu)">Data</th>'
      +'<th style="padding:8px 10px;text-align:left;font-size:10px;font-weight:700;text-transform:uppercase;color:var(--mu)">Cliente</th>'
      +'<th style="padding:8px 10px;text-align:left;font-size:10px;font-weight:700;text-transform:uppercase;color:var(--mu)">Descri\u00e7\u00e3o</th>'
      +'<th style="padding:8px 10px;text-align:right;font-size:10px;font-weight:700;text-transform:uppercase;color:var(--mu)">Valor bruto</th>'
      +'<th style="padding:8px 10px;text-align:right;font-size:10px;font-weight:700;text-transform:uppercase;color:var(--mu)">Honor. escrit.</th>'
      +'<th style="padding:8px 10px;text-align:right;font-size:10px;font-weight:700;text-transform:uppercase;color:var(--mu)">Valor cliente</th>'
      +'<th style="padding:8px 10px;text-align:left;font-size:10px;font-weight:700;text-transform:uppercase;color:var(--mu)">Forma</th>'
    +'</tr></thead><tbody>';
  d.recebimentos.sort(function(a,b){return (b.data||'').localeCompare(a.data||'');}).forEach(function(r){
    totB+=r.valor_bruto; totH+=r.valor_honorarios; totC+=r.valor_cliente;
    html += '<tr style="border-bottom:1px solid var(--bd)">'
      +'<td style="padding:7px 10px;font-size:11px;color:var(--mu);white-space:nowrap">'+fDt(r.data)+'</td>'
      +'<td style="padding:7px 10px;font-size:11px;color:var(--ac);cursor:pointer" onclick="finIrParaPasta(\''+escapeHtml(r.cliente).replace(/'/g,"\\'")+'\')">'+escapeHtml(r.cliente)+'</td>'
      +'<td style="padding:7px 10px;font-size:11px;color:var(--tx)">'+escapeHtml(r.descricao)+'</td>'
      +'<td style="padding:7px 10px;font-size:12px;font-weight:700;color:var(--tx);text-align:right">'+fV(r.valor_bruto)+'</td>'
      +'<td style="padding:7px 10px;font-size:12px;font-weight:700;color:#4ade80;text-align:right">'+fV(r.valor_honorarios)+'</td>'
      +'<td style="padding:7px 10px;font-size:12px;font-weight:700;color:#fb923c;text-align:right">'+fV(r.valor_cliente)+'</td>'
      +'<td style="padding:7px 10px;font-size:11px;color:var(--mu)">'+escapeHtml(r.forma)+'</td>'
    +'</tr>';
  });
  html += '<tr style="background:var(--sf3);font-weight:700">'
    +'<td colspan="3" style="padding:8px 10px;font-size:11px;color:var(--tx)">TOTAL</td>'
    +'<td style="padding:8px 10px;font-size:12px;color:var(--tx);text-align:right">'+fV(totB)+'</td>'
    +'<td style="padding:8px 10px;font-size:12px;color:#4ade80;text-align:right">'+fV(totH)+'</td>'
    +'<td style="padding:8px 10px;font-size:12px;color:#fb923c;text-align:right">'+fV(totC)+'</td>'
    +'<td></td></tr>';
  html += '</tbody></table></div></div>';
  return html;
}

// ── ABA RECEITA DO ESCRITÓRIO ──
function _vfReceitaEscritorio(mesP){
  var d = _vfConsolidar(mesP);
  var fV = function(v){return 'R$ '+Math.abs(v||0).toLocaleString('pt-BR',{minimumFractionDigits:2,maximumFractionDigits:2});};
  if(!d.recebimentos.length) return '<div style="padding:40px;text-align:center;color:var(--mu)">Nenhuma receita no per\u00edodo.</div>';
  var html = '<div style="padding:16px;max-width:800px">'
    +'<div style="background:rgba(76,175,125,.06);border:1px solid rgba(76,175,125,.25);border-radius:8px;padding:12px 16px;margin-bottom:14px;display:flex;justify-content:space-between;align-items:center">'
      +'<span style="font-size:12px;color:var(--mu)">Total honor\u00e1rios l\u00edquidos</span>'
      +'<span style="font-size:20px;font-weight:800;color:#4ade80">'+fV(d.totHon)+'</span>'
    +'</div>';
  d.recebimentos.sort(function(a,b){return (b.data||'').localeCompare(a.data||'');}).forEach(function(r){
    if(r.valor_honorarios <= 0) return;
    html += '<div style="display:flex;align-items:center;gap:10px;padding:8px 0;border-bottom:1px solid var(--bd)">'
      +'<div style="font-size:11px;color:var(--mu);min-width:80px">'+fDt(r.data)+'</div>'
      +'<div style="flex:1;font-size:12px;color:var(--ac);cursor:pointer" onclick="finIrParaPasta(\''+escapeHtml(r.cliente).replace(/'/g,"\\'")+'\')">'+escapeHtml(r.cliente)+'</div>'
      +'<div style="font-size:11px;color:var(--mu);flex:1">'+escapeHtml(r.descricao)+'</div>'
      +'<div style="font-size:13px;font-weight:700;color:#4ade80">'+fV(r.valor_honorarios)+'</div>'
    +'</div>';
  });
  return html+'</div>';
}

// ── ABA VALORES DE CLIENTES ──
function _vfValoresClientes(mesP){
  var d = _vfConsolidar(mesP);
  var fV = function(v){return 'R$ '+Math.abs(v||0).toLocaleString('pt-BR',{minimumFractionDigits:2,maximumFractionDigits:2});};
  var itens = d.recebimentos.filter(function(r){return r.valor_cliente > 0;});
  if(!itens.length) return '<div style="padding:40px;text-align:center;color:var(--mu)">Nenhum valor de cliente no per\u00edodo.</div>';
  // Calcular repasses por cliente
  var repPorCli = {};
  d.repasses.forEach(function(l){ var c=l.cliente||''; repPorCli[c]=(repPorCli[c]||0)+(parseFloat(l.valor)||0); });
  var html = '<div style="padding:16px;max-width:800px">'
    +'<div style="background:rgba(251,146,60,.06);border:1px solid rgba(251,146,60,.25);border-radius:8px;padding:12px 16px;margin-bottom:14px;display:flex;justify-content:space-between;align-items:center">'
      +'<span style="font-size:12px;color:var(--mu)">Total valores de clientes (cust\u00f3dia)</span>'
      +'<span style="font-size:20px;font-weight:800;color:#fb923c">'+fV(d.totCli)+'</span>'
    +'</div>';
  itens.sort(function(a,b){return (b.data||'').localeCompare(a.data||'');}).forEach(function(r){
    var rep = repPorCli[r.cliente]||0;
    var statusRep = rep >= r.valor_cliente ? '\u2713 Repassado' : (rep > 0 ? 'Parcial' : 'Pendente');
    var corRep = rep >= r.valor_cliente ? '#4ade80' : (rep > 0 ? '#f59e0b' : '#c9484a');
    html += '<div style="display:flex;align-items:center;gap:10px;padding:8px 0;border-bottom:1px solid var(--bd)">'
      +'<div style="font-size:11px;color:var(--mu);min-width:80px">'+fDt(r.data)+'</div>'
      +'<div style="flex:1;font-size:12px;color:var(--ac);cursor:pointer" onclick="finIrParaPasta(\''+escapeHtml(r.cliente).replace(/'/g,"\\'")+'\')">'+escapeHtml(r.cliente)+'</div>'
      +'<div style="font-size:13px;font-weight:700;color:#fb923c">'+fV(r.valor_cliente)+'</div>'
      +'<div style="font-size:10px;font-weight:700;color:'+corRep+'">'+statusRep+'</div>'
    +'</div>';
  });
  return html+'</div>';
}

// ── ABA REPASSES GLOBAL ──
function _vfRepassesGlobal(mesP){
  var d = _vfConsolidar(mesP);
  var fV = function(v){return 'R$ '+Math.abs(v||0).toLocaleString('pt-BR',{minimumFractionDigits:2,maximumFractionDigits:2});};
  if(!d.repasses.length) return '<div style="padding:40px;text-align:center;color:var(--mu)">Nenhum repasse no per\u00edodo.</div>';
  var html = '<div style="padding:16px;max-width:800px">'
    +'<div style="background:rgba(201,72,74,.06);border:1px solid rgba(201,72,74,.25);border-radius:8px;padding:12px 16px;margin-bottom:14px;display:flex;justify-content:space-between;align-items:center">'
      +'<span style="font-size:12px;color:var(--mu)">Total repassado</span>'
      +'<span style="font-size:20px;font-weight:800;color:var(--tx)">'+fV(d.totRep)+'</span>'
    +'</div>';
  d.repasses.sort(function(a,b){return (b.data||b.dt_baixa||'').localeCompare(a.data||a.dt_baixa||'');}).forEach(function(l){
    html += '<div style="display:flex;align-items:center;gap:10px;padding:8px 0;border-bottom:1px solid var(--bd)">'
      +'<div style="font-size:11px;color:var(--mu);min-width:80px">'+fDt(l.dt_baixa||l.data)+'</div>'
      +'<div style="flex:1;font-size:12px;color:var(--ac);cursor:pointer" onclick="finIrParaPasta(\''+escapeHtml(l.cliente||'').replace(/'/g,"\\'")+'\')">'+escapeHtml(l.cliente||'\u2014')+'</div>'
      +'<div style="font-size:11px;color:var(--mu)">'+escapeHtml(l.forma||l.conta||'')+'</div>'
      +'<div style="font-size:13px;font-weight:700;color:#c9484a">'+fV(l.valor)+'</div>'
    +'</div>';
  });
  return html+'</div>';
}

// ── ABA DESPESAS DO ESCRITÓRIO ──
// ── MODAL DESPESA DO ESCRITÓRIO ──
function _vfNovaDespEscritorio(){
  var hoje = new Date().toISOString().slice(0,10);
  abrirModal('\ud83c\udfe2 Nova Despesa do Escrit\u00f3rio',
    '<div class="fm-row"><div style="flex:2"><label class="fm-lbl">Descri\u00e7\u00e3o *</label><input class="fm-inp" id="de-desc" placeholder="Ex: Aluguel, Internet, Sal\u00e1rio..."></div></div>'
    +'<div class="fm-row">'
      +'<div><label class="fm-lbl">Valor (R$) *</label><input class="fm-inp" type="number" id="de-valor" min="0.01" step="0.01"></div>'
      +'<div><label class="fm-lbl">Data</label><input class="fm-inp" type="date" id="de-data" value="'+hoje+'"></div>'
    +'</div>'
    +'<div class="fm-row">'
      +'<div><label class="fm-lbl">Categoria</label><select class="fm-inp" id="de-cat"><option>Estrutura</option><option>Pessoal</option><option>Telecom</option><option>Energia</option><option>Sistemas</option><option>Impostos</option><option>Marketing</option><option>Servi\u00e7os</option><option>Outros</option></select></div>'
      +'<div><label class="fm-lbl">Forma pagamento</label><select class="fm-inp" id="de-forma"><option>PIX</option><option>Boleto</option><option>D\u00e9bito</option><option>Cart\u00e3o</option><option>TED</option><option>Dinheiro</option></select></div>'
    +'</div>'
    +'<div class="fm-row">'
      +'<div style="display:flex;align-items:center;gap:6px;padding-top:4px"><input type="checkbox" id="de-recorr"><label for="de-recorr" style="font-size:11px;color:var(--tx)">Despesa fixa (recorrente mensal)</label></div>'
    +'</div>'
    +'<div class="fm-row"><div style="flex:2"><label class="fm-lbl">Observa\u00e7\u00e3o</label><input class="fm-inp" id="de-obs" placeholder="Detalhes..."></div></div>',
  function(){
    var desc = (document.getElementById('de-desc')?.value||'').trim();
    var valor = parseFloat(document.getElementById('de-valor')?.value)||0;
    if(!desc){ showToast('Informe a descri\u00e7\u00e3o'); return; }
    if(valor <= 0){ showToast('Informe o valor'); return; }
    var data = document.getElementById('de-data')?.value||hoje;
    var cat = document.getElementById('de-cat')?.value||'Outros';
    var forma = document.getElementById('de-forma')?.value||'';
    var recorr = document.getElementById('de-recorr')?.checked||false;
    var obs = (document.getElementById('de-obs')?.value||'').trim();
    finLancs.push({
      id: genId(), tipo:'pagar', desc:desc, valor:valor,
      data:data, cat:cat, forma:forma, obs:obs,
      status:'pago', pago:true, dt_baixa:data,
      _recorrente: recorr, _desp_escritorio: true
    });
    sbSet('co_fin', finLancs);
    marcarAlterado(); fecharModal();
    vfRender();
    showToast('Despesa lan\u00e7ada \u2713');
  }, '\ud83d\udcbe Salvar despesa');
}

// ── EXCLUIR DESPESA GLOBAL ──
function _vfDelDespEscritorio(lid){
  abrirModal('Excluir despesa','<div style="font-size:13px;color:var(--mu)">Excluir esta despesa permanentemente?</div>',function(){
    var ls = String(lid);
    _tombstoneAdd('co_fin', ls); // anti-zombificação via sync merge
    finLancs = finLancs.filter(function(l){ return String(l.id)!==ls; });
    fecharModal(); sbSet('co_fin', finLancs);
    _finLocaisCache = {};
    marcarAlterado();
    vfRender();
    renderFinDash();
    showToast('Despesa exclu\u00edda');
  }, 'Excluir');
}

function _vfDespesasEscritorio(mesP){
  var fV = function(v){return 'R$ '+Math.abs(v||0).toLocaleString('pt-BR',{minimumFractionDigits:2,maximumFractionDigits:2});};
  var desp = [];
  // Guard: repasse ao cliente NÃO é despesa do escritório (é liquidação de custódia).
  // Filtra por flags e cat, mesmo que dados legados tenham sido gravados com tipo='pagar'.
  var _ehRepasse = function(l){
    if(l._repasse_alvara||l._repasse_acordo) return true;
    if(l.cat==='Repasse ao cliente') return true;
    if(l.tipo==='repasse') return true;
    return false;
  };
  (finLancs||[]).forEach(function(l){
    if(l.tipo==='pagar' && !_ehRepasse(l)){
      if(mesP && !(l.data||l.dt_baixa||'').startsWith(mesP)) return;
      desp.push({src:'fin', l:l});
    }
  });
  (localLanc||[]).forEach(function(l){
    if(l.tipo==='despint' && !_ehRepasse(l)){
      if(mesP && !(l.data||'').startsWith(mesP)) return;
      desp.push({src:'loc', l:l});
    }
  });
  var tot = desp.reduce(function(s,d){return s+(parseFloat(d.l.valor)||0);},0);
  var catLabel = function(l){
    if(l.cat) return l.cat;
    var d=(l.desc||'').toUpperCase();
    if(d.includes('ALUGUEL')||d.includes('CONDOMIN')) return 'Estrutura';
    if(d.includes('SALARIO')||d.includes('KAREN')||d.includes('PRO LABORE')||d.includes('PROLABORE')) return 'Pessoal';
    if(d.includes('INTERNET')||d.includes('CLARO')||d.includes('TELEFONE')) return 'Telecom';
    if(d.includes('ENERGIA')||d.includes('LUZ')||d.includes('CEMIG')) return 'Energia';
    if(d.includes('SISTEMA')||d.includes('SOFTWARE')||d.includes('PROJURIS')) return 'Sistemas';
    if(d.includes('IMPOSTO')||d.includes('SIMPLES')||d.includes('DARF')) return 'Impostos';
    return 'Outros';
  };
  var catCores = {Estrutura:'#60a5fa',Pessoal:'#a78bfa',Telecom:'#38bdf8',Energia:'#fbbf24',Sistemas:'#4ade80',Impostos:'#f87676',Marketing:'#e879f9',Outros:'var(--mu)'};

  // Agrupar por categoria
  var porCat = {};
  desp.forEach(function(d){
    var cat = catLabel(d.l);
    if(!porCat[cat]) porCat[cat] = {total:0, itens:[]};
    porCat[cat].total += parseFloat(d.l.valor)||0;
    porCat[cat].itens.push(d);
  });
  var catsSorted = Object.keys(porCat).sort(function(a,b){return porCat[b].total - porCat[a].total;});

  var html = '<div style="padding:16px;max-width:800px">'
    +'<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:14px">'
      +'<button onclick="_vfNovaDespEscritorio()" style="font-size:11px;font-weight:700;padding:6px 14px;border-radius:6px;background:rgba(248,118,118,.08);border:1px solid rgba(248,118,118,.3);color:#f87676;cursor:pointer">+ Nova Despesa</button>'
      +'<div style="font-size:11px;color:var(--mu)">'+desp.length+' despesa'+(desp.length!==1?'s':'')+'</div>'
    +'</div>'
    +'<div style="background:rgba(248,118,118,.06);border:1px solid rgba(248,118,118,.25);border-radius:8px;padding:12px 16px;margin-bottom:14px;display:flex;justify-content:space-between;align-items:center">'
      +'<span style="font-size:12px;color:var(--mu)">Total despesas</span>'
      +'<span style="font-size:20px;font-weight:800;color:#f87676">'+fV(tot)+'</span>'
    +'</div>';

  if(!desp.length) return html+'<div style="padding:20px;text-align:center;color:var(--mu)">Nenhuma despesa no per\u00edodo. Clique em + Nova Despesa.</div></div>';

  // Cards por categoria com barra
  html += '<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(150px,1fr));gap:8px;margin-bottom:16px">';
  catsSorted.forEach(function(cat){
    var pct = tot>0 ? Math.round(porCat[cat].total/tot*100) : 0;
    var cor = catCores[cat]||'var(--mu)';
    html += '<div style="padding:10px 12px;background:var(--sf2);border:1px solid var(--bd);border-radius:8px">'
      +'<div style="font-size:9px;font-weight:700;text-transform:uppercase;color:'+cor+';margin-bottom:4px">'+cat+'</div>'
      +'<div style="font-size:14px;font-weight:800;color:'+cor+'">'+fV(porCat[cat].total)+'</div>'
      +'<div style="height:3px;background:var(--sf3);border-radius:2px;margin-top:6px;overflow:hidden"><div style="width:'+pct+'%;height:100%;background:'+cor+';border-radius:2px"></div></div>'
      +'<div style="font-size:9px;color:var(--mu);margin-top:3px">'+pct+'% \u00b7 '+porCat[cat].itens.length+' item'+(porCat[cat].itens.length!==1?'s':'')+'</div>'
    +'</div>';
  });
  html += '</div>';

  // Lista detalhada
  desp.sort(function(a,b){return (b.l.data||'').localeCompare(a.l.data||'');}).forEach(function(d){
    var l = d.l;
    var delFn = d.src==='fin' ? '_vfDelDespEscritorio(\''+l.id+'\')' : 'finDelLanc(0,\''+l.id+'\')';
    var cat = catLabel(l);
    var cor = catCores[cat]||'var(--mu)';
    html += '<div style="display:flex;align-items:center;gap:10px;padding:8px 0;border-bottom:1px solid var(--bd)">'
      +'<div style="font-size:11px;color:var(--mu);min-width:80px">'+fDt(l.data||l.dt_baixa)+'</div>'
      +'<div style="flex:1;font-size:12px;font-weight:600;color:var(--tx)">'+escapeHtml(l.desc||'\u2014')+'</div>'
      +'<div style="font-size:9px;padding:2px 6px;border-radius:3px;background:'+cor+'20;color:'+cor+';font-weight:700">'+cat+'</div>'
      +'<div style="font-size:11px;color:var(--mu)">'+escapeHtml(l.forma||'')+'</div>'
      +(l._recorrente?'<span style="font-size:9px;padding:2px 6px;border-radius:3px;background:rgba(96,165,250,.1);color:#60a5fa;font-weight:700">FIXA</span>':'')
      +'<div style="font-size:13px;font-weight:700;color:#f87676">'+fV(l.valor)+'</div>'
      +(d.src==='fin'?'<button onclick="_vfEditarDespEscritorio(\''+l.id+'\')" style="font-size:10px;padding:3px 8px;border-radius:4px;background:rgba(212,175,55,.1);border:1px solid rgba(212,175,55,.3);color:#D4AF37;cursor:pointer">\u270f</button>':'')
      +'<button onclick="'+delFn+'" style="font-size:10px;padding:3px 6px;border-radius:4px;background:var(--sf3);border:1px solid rgba(201,72,74,.3);color:#c9484a;cursor:pointer">\u2715</button>'
    +'</div>';
  });
  return html+'</div>';
}


// ── EDITAR DESPESA DO ESCRITÓRIO ──
function _vfEditarDespEscritorio(lid){
  var i = (finLancs||[]).findIndex(function(l){return String(l.id)===String(lid);});
  if(i===-1){ showToast('N\u00e3o encontrado'); return; }
  var l = finLancs[i];
  var hoje = new Date().toISOString().slice(0,10);
  abrirModal('\u270f Editar Despesa',
    '<div class="fm-row"><div style="flex:2"><label class="fm-lbl">Descri\u00e7\u00e3o</label><input class="fm-inp" id="ede-desc" value="'+escapeHtml(l.desc||'')+'"></div></div>'
    +'<div class="fm-row">'
      +'<div><label class="fm-lbl">Valor (R$)</label><input class="fm-inp" type="number" id="ede-valor" value="'+(l.valor||0)+'" min="0.01" step="0.01"></div>'
      +'<div><label class="fm-lbl">Data</label><input class="fm-inp" type="date" id="ede-data" value="'+(l.data||l.dt_baixa||hoje)+'"></div>'
    +'</div>'
    +'<div class="fm-row">'
      +'<div><label class="fm-lbl">Categoria</label><select class="fm-inp" id="ede-cat"><option>Estrutura</option><option>Pessoal</option><option>Telecom</option><option>Energia</option><option>Sistemas</option><option>Impostos</option><option>Marketing</option><option>Servi\u00e7os</option><option>Outros</option></select></div>'
      +'<div><label class="fm-lbl">Forma</label><select class="fm-inp" id="ede-forma"><option>PIX</option><option>Boleto</option><option>D\u00e9bito</option><option>Cart\u00e3o</option><option>TED</option><option>Dinheiro</option></select></div>'
    +'</div>'
    +'<div class="fm-row">'
      +'<div style="display:flex;align-items:center;gap:6px"><input type="checkbox" id="ede-recorr" '+(l._recorrente?'checked':'')+'><label for="ede-recorr" style="font-size:11px;color:var(--tx)">Despesa fixa</label></div>'
    +'</div>'
    +'<div class="fm-row"><div style="flex:2"><label class="fm-lbl">Observa\u00e7\u00e3o</label><input class="fm-inp" id="ede-obs" value="'+escapeHtml(l.obs||'')+'"></div></div>',
  function(){
    var desc = (document.getElementById('ede-desc')?.value||'').trim();
    var valor = parseFloat(document.getElementById('ede-valor')?.value)||0;
    if(!desc||valor<=0){ showToast('Preencha descri\u00e7\u00e3o e valor'); return; }
    finLancs[i].desc = desc;
    finLancs[i].valor = valor;
    finLancs[i].data = document.getElementById('ede-data')?.value||hoje;
    finLancs[i].dt_baixa = finLancs[i].data;
    finLancs[i].cat = document.getElementById('ede-cat')?.value||'Outros';
    finLancs[i].forma = document.getElementById('ede-forma')?.value||'';
    finLancs[i]._recorrente = document.getElementById('ede-recorr')?.checked||false;
    finLancs[i].obs = (document.getElementById('ede-obs')?.value||'').trim();
    sbSet('co_fin', finLancs);
    marcarAlterado(); fecharModal();
    vfRender();
    showToast('Despesa atualizada \u2713');
  }, '\ud83d\udcbe Salvar');
  setTimeout(function(){
    var sc = document.getElementById('ede-cat'); if(sc&&l.cat) sc.value=l.cat;
    var sf = document.getElementById('ede-forma'); if(sf&&l.forma) sf.value=l.forma;
  }, 100);
}

function vfRender(){
  const el = document.getElementById('vf-content');
  if(!el) return;

  // Ensure _vfMes is set
  if(!_vfMes) _vfMes = new Date(HOJE).toISOString().slice(0,7);

  // Update month label
  var lbl = document.getElementById('vf-mes-lbl');
  if(lbl){
    var MA = ['Janeiro','Fevereiro','Março','Abril','Maio','Junho',
              'Julho','Agosto','Setembro','Outubro','Novembro','Dezembro'];
    var m = parseInt(_vfMes.slice(5))-1;
    var y = _vfMes.slice(0,4);
    lbl.textContent = MA[m]+' '+y;
  }

  const todos = vfTodos();
  const hoje  = new Date(HOJE).toISOString().slice(0,10);
  const mesP  = _vfMes || new Date(HOJE).toISOString().slice(0,7);
  const fK    = function(v){ return v>=1000?'R$ '+(v/1000).toFixed(1).replace('.0','')+'k':'R$ '+Math.round(v); };

  // ── KPIs consolidados ──
  var cons = _vfConsolidar(mesP);
  var e1=document.getElementById('vfkpi-entrou');   if(e1) e1.textContent=fK(cons.totEntrou);
  var e2=document.getElementById('vfkpi-receita');  if(e2) e2.textContent=fK(cons.totHon);
  var e3=document.getElementById('vfkpi-clientes'); if(e3) e3.textContent=fK(cons.totCli);
  var e4=document.getElementById('vfkpi-saldo');    if(e4) e4.textContent=fK(cons.saldo);

  // ── Routing ──
  var tab = _vfTab||'resumo';
  var htmlTab;
  if(tab==='resumo')          htmlTab = _vfResumoGlobal(mesP);
  else if(tab==='recebimentos') htmlTab = _vfRecebimentos(mesP);
  else if(tab==='receita')    htmlTab = _vfReceitaEscritorio(mesP);
  else if(tab==='valclientes') htmlTab = _vfValoresClientes(mesP);
  else if(tab==='repasses')   htmlTab = _vfRepassesGlobal(mesP);
  else if(tab==='despesas')   htmlTab = _vfDespesasEscritorio(mesP);
  else if(tab==='extrato')   htmlTab = vfExtrato();
  else                        htmlTab = _vfResumoGlobal(mesP);
  el.textContent = '';
  el.appendChild(_fragFromHtml(htmlTab));
  _updateNavBtn();
}
// Invalida cache ao alterar dados financeiros
function vfInvalidarCache(){ if(vfRender._cache) vfRender._cache={}; }

// Phase 3: pré-cachear abas pesadas em tempo ocioso (requestIdleCallback)
function _vfPrefetch(){
  // Prefetch apenas do extrato (pesado)
  var ric = window.requestIdleCallback || function(cb){ setTimeout(cb, 200); };
  ric(function(){
    var mesP = _vfMes || new Date(HOJE).toISOString().slice(0,7);
    var key = 'extrato:' + mesP;
    if(!vfRender._cache) vfRender._cache = {};
    if(!vfRender._cache[key]) vfRender._cache[key] = vfExtrato();
  });
}

function vfNavMes(delta){
  if(!_vfMes) _vfMes = new Date(HOJE).toISOString().slice(0,7);
  var parts = _vfMes.split('-');
  var y = parseInt(parts[0]), m = parseInt(parts[1]) - 1 + delta;
  if(m > 11){ m = 0; y++; }
  if(m < 0){ m = 11; y--; }
  _vfMes = y + '-' + String(m+1).padStart(2,'0');
  _vfTab = _vfTab || 'mes';
  vfRender();
}

// ─── ABA: DESPESAS DE CLIENTES ────────────────────────────────
// ════════════════════════════════════════
// NAVIGATION SYSTEM
// ════════════════════════════════════════
// NAVIGATION SYSTEM
// ════════════════════════════════════════════════════
// GLOBAL NAVIGATION HISTORY
// ════════════════════════════════════════════════════
var _gNavHistory = [];

function navCapture(){
  var activeView = null;
  document.querySelectorAll('.view').forEach(function(v){
    if(v.classList.contains('on')) activeView = v.id;
  });
  return {
    view: activeView || 'vc',
    tab: _vfTab,
    mes: _vfMes,
    clientId: (typeof AC !== 'undefined' && AC) ? (AC.id||null) : null,
    scroll: (activeView==='vf' ? ((document.getElementById('vf-content')||{}).scrollTop||0) : 0)
  };
}

function navPush(state){
  var s = state || navCapture();
  _gNavHistory.push(s);
  if(_gNavHistory.length > 30) _gNavHistory.shift();
  _updateNavBtn();
}

function globalNavBack(){
  if(!_gNavHistory.length){ showToast('Sem histórico'); return; }
  var prev = _gNavHistory.pop();
  _updateNavBtn();
  if(prev.view === 'vcl' && prev.clientId){
    goView('vcl'); openC(prev.clientId); return;
  }
  if(prev.view === 'vf'){
    goView('vf');
    if(prev.mes) _vfMes = prev.mes;
    if(prev.tab) _vfTab = prev.tab;
    vfRender();
    setTimeout(function(){
      var el = document.getElementById('vf-content');
      if(el && prev.scroll) el.scrollTop = prev.scroll;
    }, 150);
    return;
  }
  if(prev.view) goView(prev.view);
}

function navBack(){ globalNavBack(); }

function _updateNavBtn(){
  var btn = document.getElementById('global-back-btn');
  if(!btn) return;
  btn.style.display = _gNavHistory.length ? 'flex' : 'none';
}

function finIrParaPasta(clienteNome){
  if(!clienteNome) return;
  try { clienteNome = decodeURIComponent(clienteNome); } catch(e){}
  navPush(navCapture());
  var nome = String(clienteNome).toLowerCase().trim();
  var c = (CLIENTS||[]).find(function(x){ return (x.cliente||'').toLowerCase().trim()===nome; });
  if(!c) c = (CLIENTS||[]).find(function(x){ var cn=(x.cliente||'').toLowerCase(); return cn.includes(nome)||nome.includes(cn); });
  if(c){ goView('vcl'); openC(c.id); }
  else { showToast('Pasta nao encontrada: '+clienteNome); }
}

function finIrParaLanc(lancId){
  if(!lancId) return;
  var id = String(lancId);
  navPush(navCapture());
  if(id.startsWith('l')){
    var l = (localLanc||[]).find(function(x){ return String(x.id)===id.slice(1); });
    if(l && l.id_processo){ goView('vcl'); openC(l.id_processo); return; }
  }
  if(id.startsWith('p')){
    var pItem = (FIN_XLSX||[]).find(function(x){ return 'p'+x.id===id; });
    if(pItem){
      var c2=(CLIENTS||[]).find(function(x){return String(x.pasta)===String(pItem.pasta);});
      if(c2){ goView('vcl'); openC(c2.id); return; }
    }
  }
  goView('vf'); _vfTab='mes'; vfRender();
  setTimeout(function(){ finScrollToLanc(id); }, 300);
}

function finScrollToLanc(lancId){
  var el = document.querySelector('[data-lanc-id="'+lancId+'"]');
  if(el){ el.style.background='rgba(212,175,55,.2)'; el.scrollIntoView({behavior:'smooth',block:'center'}); setTimeout(function(){ el.style.background=''; },2000); }
}



// Helper: delete any lançamento by id+origin
function fmComplementarLanc(lid){
  var id = String(lid).replace('l','');
  var l  = (localLanc||[]).find(function(x){ return String(x.id)===id; });
  if(!l){ showToast('Lançamento não encontrado'); return; }
  var fmtV2 = function(v){ return 'R$ '+Math.abs(v||0).toLocaleString('pt-BR',{minimumFractionDigits:2,maximumFractionDigits:2}); };

  abrirModal('⚠️ Complementar lançamento — '+escapeHtml(l.desc||''),
    '<div style="background:rgba(245,158,11,.07);border:1px solid rgba(245,158,11,.3);border-radius:6px;padding:10px 12px;margin-bottom:14px;font-size:11px;color:var(--mu)">'
      +'Preencha as informações que faltam para que este lançamento entre corretamente nos seus honorários.'
    +'</div>'
    +'<div class="fm-row">'
      +'<div><label class="fm-lbl">Tipo</label>'
        +'<select class="fm-inp" id="comp-tipo">'
          +'<option value="unica">Única</option>'
          +'<option value="parcelado">Parcelado</option>'
          +'<option value="sucumbencia">Sucumbência</option>'
          +'<option value="mensalidade">Mensalidade</option>'
        +'</select></div>'
      +'<div><label class="fm-lbl">Parcela N</label>'
        +'<input class="fm-inp" type="number" id="comp-parc-n" min="1" value="1" placeholder="1"></div>'
      +'<div><label class="fm-lbl">De Total</label>'
        +'<input class="fm-inp" type="number" id="comp-parc-tot" min="1" value="1" placeholder="1"></div>'
    +'</div>'
    +'<div class="fm-row">'
      +'<div><label class="fm-lbl">Valor bruto total (R$)</label>'
        +'<input class="fm-inp" type="number" id="comp-vbruto" value="'+(l._vbruto||l.valor||0)+'" step="0.01"></div>'
      +'<div><label class="fm-lbl">Seus honorários (%)</label>'
        +'<input class="fm-inp" type="number" id="comp-honperc" value="'+(l._honperc||100)+'" min="0" max="100" step="0.5"></div>'
    +'</div>'
    +'<div style="margin-bottom:10px">'
      +'<label style="display:flex;align-items:center;gap:8px;font-size:12px;cursor:pointer">'
        +'<input type="checkbox" id="comp-tem-parc"> Tem parceiro?</label>'
    +'</div>'
    +'<div id="comp-parc-fields" style="display:none" class="fm-row">'
      +'<div style="flex:2"><label class="fm-lbl">Nome do parceiro</label>'
        +'<input class="fm-inp" id="comp-parc-nome" value="'+(l._parceiro||'')+'" placeholder="Ex: Vivian"></div>'
      +'<div><label class="fm-lbl">% do parceiro</label>'
        +'<input class="fm-inp" type="number" id="comp-parc-perc" value="'+(l._parceiro_perc||60)+'" min="0" max="100"></div>'
    +'</div>',
  function(){
    var tipo    = document.getElementById('comp-tipo')?.value||'unica';
    var pN      = parseInt(document.getElementById('comp-parc-n')?.value||1);
    var pTot    = parseInt(document.getElementById('comp-parc-tot')?.value||1);
    var vbruto  = parseFloat(document.getElementById('comp-vbruto')?.value||0);
    var honperc = parseFloat(document.getElementById('comp-honperc')?.value||100);
    var temParc = document.getElementById('comp-tem-parc')?.checked;
    var pNome   = document.getElementById('comp-parc-nome')?.value||'';
    var pPerc   = parseFloat(document.getElementById('comp-parc-perc')?.value||0);
    var pVal    = temParc ? roundMoney(l.valor*(pPerc/100)) : 0;

    var i = localLanc.findIndex(function(x){ return String(x.id)===id; });
    if(i!==-1){
      localLanc[i] = Object.assign({},localLanc[i],{
        _tipo_parc: tipo,
        _parcela: pN,
        _total_parc: pTot,
        _vbruto: vbruto,
        _honperc: honperc,
        _parceiro: temParc?pNome:'',
        _parceiro_perc: temParc?pPerc:0,
        _parceiro_val: pVal,
      });
      sbSet('co_localLanc', localLanc);
      marcarAlterado(); fecharModal(); vfRender();
      showToast('✓ Lançamento complementado');
    }
  }, '✓ Salvar');

  // Wire checkbox
  setTimeout(function(){
    var cb = document.getElementById('comp-tem-parc');
    if(cb && l._parceiro){ cb.checked=true; document.getElementById('comp-parc-fields').style.display='flex'; }
    if(cb) cb.addEventListener('change',function(){ document.getElementById('comp-parc-fields').style.display=cb.checked?'flex':'none'; });
  },100);
}

function finDelItem(lid, origem){
  if(origem==='global'){
    finDelGlobal(String(lid).replace('g',''));
  } else {
    vfDelLocal(String(lid).startsWith('l') ? lid : 'l'+lid);
  }
}

// Helper: estornar any lançamento
function finEstornarItem(lid, origem){
  abrirModal('Estornar lançamento?',
    '<div style="font-size:12px;color:var(--mu);line-height:1.7">O lançamento voltará para <strong>pendente</strong>. O valor de baixa será removido.</div>',
    function(){
      if(origem==='global'){
        var id = String(lid).replace('g','');
        finLancs = (finLancs||[]).map(function(l){
          if(String(l.id)===id) return Object.assign({},l,{pago:false,status:'pendente',dt_baixa:''});
          return l;
        });
        sbSet('co_fin', finLancs);
      } else {
        localLanc = (localLanc||[]).map(function(l){
          if('l'+l.id===lid||String(l.id)===lid) return Object.assign({},l,{pago:false,status:'pendente',dt_baixa:''});
          return l;
        });
        sbSet('co_localLanc', localLanc);
      }
      invalidarCacheVfTodos();
      marcarAlterado(); fecharModal(); vfRender();
      showToast('↩ Estorno registrado');
    }, 'Estornar'
  );
}

// Helper: renders a block table (recebiveis or despesas)
function _vfMesBloco(titulo, itens, cor, isRec, mesP2, hoje, fmtV){
  var soma = itens.reduce(function(s,l){return s+(parseFloat(l.valor)||0);},0);
  var html = '<div style="border:1px solid var(--bd);border-radius:8px;overflow:hidden;margin-bottom:16px">'
    +'<div style="padding:10px 14px;background:var(--sf3);border-bottom:1px solid var(--bd);display:flex;justify-content:space-between;align-items:center">'
      +'<span style="font-size:12px;font-weight:700;color:var(--tx)">'+titulo+'</span>'
      +'<span style="font-size:13px;font-weight:700;color:'+cor+'">'+fmtV(soma)+'</span>'
    +'</div>';

  if(!itens.length){
    return html+'<div style="padding:14px;font-size:12px;color:var(--mu);font-style:italic;text-align:center">Nenhum lançamento neste mês</div></div>';
  }

  html += '<table style="width:100%;border-collapse:collapse"><tbody>';
  itens.sort(function(a,b){return (a.data||a.venc||'').localeCompare(b.data||b.venc||'');}).forEach(function(l){
    var isPago   = l.status==='pago';
    var vencido  = !isPago && l.venc && l.venc < hoje;
    var sCor     = isPago?cor:vencido?'#c9484a':'#f59e0b';
    var sTxt     = isPago?(isRec?'Recebido':'Pago'):vencido?'Vencido':'Pendente';

    // Check if client exists in CLIENTS
    var cliNome = l.cliente||'—';
    var cliExists = cliNome==='Escritório'||cliNome==='—'||(CLIENTS||[]).some(function(c){return (c.cliente||'').toLowerCase()===cliNome.toLowerCase();});
    var cliStyle  = !isRec||cliExists ? 'color:var(--ac);cursor:pointer' : 'color:#c9484a;cursor:pointer;font-weight:700';
    var cliTitle  = !isRec||cliExists ? 'Abrir pasta' : '⚠️ Cliente não cadastrado — clique para cadastrar';
    var cliOnclick= !isRec||cliExists
      ? 'finIrParaPasta(this.dataset.cli)'
      : 'abrirCadastrarCliente(this.dataset.cli,\''+l.id+'\')';

    // Actions
    var acoes = '';
    if(isPago){
      var estFn = l.origem==='projuris'?'vfEstornarProjuris(\''+l.id+'\')':l.origem==='global'?'vfEstornarGlobal(\''+l.id+'\')':'finEstornarLocal(0,\''+l.id.replace('l','')+'\')';
      acoes += '<button onclick="'+estFn+'" title="Estornar" style="font-size:10px;padding:2px 6px;border-radius:4px;background:var(--sf3);border:1px solid var(--bd);color:var(--mu);cursor:pointer">↩</button> ';
    } else {
      acoes += '<button onclick="vfBaixar(\''+l.id+'\')" style="font-size:10px;font-weight:700;padding:3px 9px;border-radius:4px;background:'+(isRec?'rgba(76,175,125,.1)':'rgba(248,118,118,.08)')+';border:1px solid '+(isRec?'rgba(76,175,125,.25)':'rgba(248,118,118,.25)')+';color:'+(isRec?'#4ade80':'#f87676')+';cursor:pointer">'+(isRec?'✓ Receber':'✓ Pagar')+'</button> ';
    }
    if(l.origem!=='projuris'){
      var delFn = l.origem==='global'?'finDelGlobal(\''+l.id.replace('g','')+'\')':'finDelLanc(0,\''+l.id.replace('l','')+'\')';
      acoes += '<button onclick="'+delFn+'" title="Excluir" style="font-size:10px;padding:2px 5px;border-radius:4px;background:var(--sf3);border:1px solid var(--bd);color:var(--mu);cursor:pointer">✕</button>';
    }

    html += '<tr data-lanc-id="'+l.id+'" style="border-bottom:1px solid var(--bd)">'
      +'<td style="padding:7px 12px;font-size:11px;color:var(--mu);white-space:nowrap;min-width:90px">'+fDt(l.data||l.venc)+'</td>'
      +'<td style="padding:7px 8px;font-size:11px;font-weight:600;'+cliStyle+'" onclick="'+cliOnclick+'" data-cli="'+encodeURIComponent(cliNome)+'" title="'+cliTitle+'">'+escapeHtml(cliNome)+'</td>'
      +'<td style="padding:7px 8px;font-size:11px;color:var(--mu);max-width:220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="'+escapeHtml(l.desc||'')+'">'+escapeHtml(l.desc||'—')+'</td>'
      +'<td style="padding:7px 8px;font-size:12px;font-weight:700;color:'+(isPago?cor:'var(--tx)')+';text-align:right;cursor:pointer;white-space:nowrap" onclick="finIrParaLanc(this.dataset.lid)" data-lid="'+l.id+'" title="Ver lançamento">'+fmtV(l.valor)+'</td>'
      +'<td style="padding:7px 8px;text-align:center;white-space:nowrap"><span style="font-size:9px;font-weight:700;color:'+sCor+'">'+sTxt+'</span></td>'
      +'<td style="padding:7px 8px;text-align:right;white-space:nowrap">'+acoes+'</td>'
    +'</tr>';
  });
  html += '</tbody></table></div>';
  return html;
}

// Modal to link unlisted client to existing or create new
function abrirCadastrarCliente(cliNome, lancId){
  try { cliNome = decodeURIComponent(cliNome); } catch(e){}
  var opts = (CLIENTS||[]).map(function(c,i){
    return '<option value="'+i+'">'+escapeHtml(c.cliente||'—')+'</option>';
  }).join('');

  abrirModal('⚠️ Lançamento sem vínculo: '+escapeHtml(cliNome),
    '<div style="margin-bottom:14px;padding:10px 12px;background:rgba(245,158,11,.07);border:1px solid rgba(245,158,11,.25);border-radius:6px;font-size:11px;color:var(--mu)">'
      +'<strong style="color:#f59e0b">'+escapeHtml(cliNome)+'</strong> não está cadastrado como cliente. Escolha como tratar este lançamento:'
    +'</div>'
    // Option 1: link to existing
    +'<div style="border:1px solid var(--bd);border-radius:8px;padding:12px;margin-bottom:8px">'
      +'<div style="font-size:11px;font-weight:700;color:var(--tx);margin-bottom:8px">1. Vincular a cliente existente</div>'
      +'<select class="fm-inp" id="cad-sel-cli" style="margin-bottom:0"><option value="">— selecione —</option>'+opts+'</select>'
      +'<button onclick="cadVincular(\''+encodeURIComponent(cliNome)+'\',\''+lancId+'\')" style="width:100%;margin-top:8px;font-size:11px;font-weight:700;padding:7px;border-radius:6px;background:rgba(76,175,125,.1);border:1px solid rgba(76,175,125,.3);color:#4ade80;cursor:pointer">Vincular</button>'
    +'</div>'
    // Option 2: parte contrária
    +'<div style="border:1px solid var(--bd);border-radius:8px;padding:12px;margin-bottom:8px">'
      +'<div style="font-size:11px;font-weight:700;color:var(--tx);margin-bottom:4px">2. É parte contrária (réu/empresa devedora)</div>'
      +'<div style="font-size:10px;color:var(--mu);margin-bottom:8px">O dinheiro entrou, mas veio de uma parte oposta num processo. Vincule ao processo do seu cliente.</div>'
      +'<select class="fm-inp" id="cad-proc-cli" style="margin-bottom:0"><option value="">— selecione o processo do cliente —</option>'
        +(CLIENTS||[]).map(function(c,i){ return '<option value="'+i+'">'+escapeHtml(c.cliente||'—')+(c.adverso?' × '+escapeHtml(c.adverso):'')+'</option>'; }).join('')
      +'</select>'
      +'<button onclick="cadParteContraria(\''+encodeURIComponent(cliNome)+'\',\''+lancId+'\')" style="width:100%;margin-top:8px;font-size:11px;font-weight:700;padding:7px;border-radius:6px;background:rgba(212,175,55,.08);border:1px solid rgba(212,175,55,.3);color:#D4AF37;cursor:pointer">Marcar como parte contrária</button>'
    +'</div>'
    // Option 3: avulso
    +'<div style="border:1px solid var(--bd);border-radius:8px;padding:12px">'
      +'<div style="font-size:11px;font-weight:700;color:var(--tx);margin-bottom:4px">3. Lançamento avulso (sem processo)</div>'
      +'<div style="font-size:10px;color:var(--mu);margin-bottom:8px">Já identificado, não precisa de pasta. O lançamento fica como "Avulso" e não gera alerta.</div>'
      +'<button onclick="cadAvulso(\''+encodeURIComponent(cliNome)+'\',\''+lancId+'\')" style="width:100%;font-size:11px;font-weight:700;padding:7px;border-radius:6px;background:var(--sf3);border:1px solid var(--bd);color:var(--mu);cursor:pointer">Confirmar como avulso</button>'
    +'</div>',
  null, null);
}

function cadVincular(cliNomeEnc, lancId){
  var cliNome = decodeURIComponent(cliNomeEnc);
  var sel = document.getElementById('cad-sel-cli');
  var idx2 = sel ? parseInt(sel.value) : NaN;
  if(isNaN(idx2)||!CLIENTS[idx2]){ showToast('Selecione um cliente'); return; }
  var c = CLIENTS[idx2];
  _cadUpdateLanc(lancId, {cliente: c.cliente, _sem_cadastro: false});
  fecharModal(); vfRender();
  showToast('✓ Vinculado a '+c.cliente);
}

function cadParteContraria(cliNomeEnc, lancId){
  var cliNome = decodeURIComponent(cliNomeEnc);
  var sel = document.getElementById('cad-proc-cli');
  var idx2 = sel ? parseInt(sel.value) : NaN;
  if(isNaN(idx2)||!CLIENTS[idx2]){ showToast('Selecione o processo'); return; }
  var c = CLIENTS[idx2];
  _cadUpdateLanc(lancId, {
    cliente: c.cliente,
    _parte_contraria: cliNome,
    _parte_contraria_flag: true,
    _sem_cadastro: false,
  });
  fecharModal(); vfRender();
  showToast('✓ Marcado como parte contrária — vinculado a '+c.cliente);
}

function cadAvulso(cliNomeEnc, lancId){
  var cliNome = decodeURIComponent(cliNomeEnc);
  _cadUpdateLanc(lancId, {_avulso: true, _sem_cadastro: false});
  fecharModal(); vfRender();
  showToast('✓ Lançamento marcado como avulso');
}

function _cadUpdateLanc(lancId, fields){
  var lid = String(lancId);
  finLancs = (finLancs||[]).map(function(l){
    if('g'+l.id===lid||String(l.id)===lid.replace('g','')) return Object.assign({},l,fields);
    return l;
  });
  localLanc = (localLanc||[]).map(function(l){
    if('l'+l.id===lid||String(l.id)===lid.replace('l','')) return Object.assign({},l,fields);
    return l;
  });
  sbSet('co_fin', finLancs);
  sbSet('co_localLanc', localLanc);
  marcarAlterado();
}

// ── A Receber (todos os meses, lista de honorários pendentes) ──


// ── Repasses (custódia de clientes) ──






function nlgCalcSplit(){
  if(window._nlgNatureza!=='split') return;
  var prev   = document.getElementById('nlg-split-preview');
  if(!prev) return;
  var total  = parseFloat(document.getElementById('nlg-valor')?.value||0);
  var perc   = parseFloat(document.getElementById('nlg-split-perc')?.value||30);
  var meu    = roundMoney(total*(perc/100));
  var cliente= roundMoney(total-meu);
  var fmtV2  = function(v){ return 'R$ '+Math.abs(v||0).toLocaleString('pt-BR',{minimumFractionDigits:2,maximumFractionDigits:2}); };
  if(!total){ prev.textContent='Digite o valor para ver o split'; return; }
  prev.innerHTML = '<strong style="color:#4ade80">Seu ('+perc+'%): '+fmtV2(meu)+'</strong>'
    +' &nbsp;·&nbsp; <strong style="color:#fb923c">Repasse ao cliente ('+(100-perc).toFixed(0)+'%): '+fmtV2(cliente)+'</strong>';
}

function vfListaDespClientes(todos){
  const hoje = new Date(HOJE).toISOString().slice(0,10);
  const fmtV = function(v){return 'R$ '+Math.abs(v||0).toLocaleString('pt-BR',{minimumFractionDigits:2,maximumFractionDigits:2});};

  // Split into repasses (to clients) and despesas (office costs)
  const isRepasse = function(l){
    return l.subtipo==='repasse'||(l.desc||'').toLowerCase().startsWith('repasse')||l._repasse_alvara||l._repasse_acordo;
  };

  const pendentes = todos.filter(function(l){return l.tipo==='pagar'&&l.status!=='pago';});
  const repassesPend = pendentes.filter(isRepasse);
  const despPend     = pendentes.filter(function(l){return !isRepasse(l)&&l.subtipo!=='repasse';});
  const pagos        = todos.filter(function(l){return l.tipo==='pagar'&&l.status==='pago';}).slice(0,10);

  if(!pendentes.length && !pagos.length)
    return '<div style="padding:30px;text-align:center;color:var(--mu);font-size:13px">Nenhuma obrigação de pagamento lançada.</div>';

  var html = '<div style="padding:12px">';

  // ── Repasses ao cliente (destaque) ──
  if(repassesPend.length){
    var totRep = repassesPend.reduce(function(s,l){return s+(l.valor||0);},0);
    html += '<div style="background:rgba(201,72,74,.07);border:1px solid rgba(201,72,74,.3);border-radius:8px;padding:12px;margin-bottom:14px">'
      +'<div style="font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.07em;color:#c9484a;margin-bottom:8px">📤 Repasses ao cliente — '+fmtV(totRep)+'</div>';
    repassesPend.forEach(function(l){
      var venc = l.venc&&l.venc<hoje;
      html += '<div style="display:flex;align-items:center;gap:10px;padding:8px 0;border-bottom:1px solid rgba(201,72,74,.15)">'
        +'<div style="flex:1;min-width:0">'
          +'<div style="font-size:12px;font-weight:600;color:var(--tx)">'+escapeHtml(l.desc||'—')+'</div>'
          +'<div style="font-size:10px;color:var(--mu)">'+escapeHtml(l.cliente||'')+(l.data?' · vence '+fDt(l.data):'')+'</div>'
        +'</div>'
        +'<div style="font-size:14px;font-weight:700;color:'+(venc?'#c9484a':'#f87676')+'">'+fmtV(l.valor)+'</div>'
        +'<button onclick="vfBaixar(\''+l.id+'\')" style="font-size:11px;font-weight:700;padding:5px 12px;border-radius:5px;border:none;background:#c9484a;color:#fff;cursor:pointer">✓ Pagar</button>'
      +'</div>';
    });
    html += '</div>';
  }

  // ── Despesas pendentes ──
  if(despPend.length){
    html += '<div style="font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.07em;color:var(--mu);margin-bottom:8px">Despesas pendentes</div>';
    despPend.forEach(function(l){
      var venc = l.venc&&l.venc<hoje;
      html += '<div style="display:flex;align-items:center;gap:10px;padding:8px 12px;border:1px solid var(--bd);border-radius:8px;margin-bottom:6px;background:var(--sf2)">'
        +'<div style="flex:1;min-width:0">'
          +'<div style="font-size:12px;font-weight:600;color:var(--tx)">'+escapeHtml(l.desc||'—')+'</div>'
          +'<div style="font-size:10px;color:var(--mu)">'+escapeHtml(l.cliente||'')+(l.data?' · '+fDt(l.data):'')+'</div>'
        +'</div>'
        +'<div style="font-size:13px;font-weight:700;color:'+(venc?'#c9484a':'#f87676')+'">'+fmtV(l.valor)+'</div>'
        +'<span style="font-size:9px;font-weight:700;padding:2px 6px;border-radius:4px;background:'+(venc?'rgba(201,72,74,.12)':'rgba(245,158,11,.1)')+';color:'+(venc?'#c9484a':'#f59e0b')+'">'+( venc?'VENCIDO':'PENDENTE')+'</span>'
        +'<button onclick="vfBaixar(\''+l.id+'\')" style="font-size:10px;padding:4px 10px;border-radius:5px;background:var(--sf3);border:1px solid var(--bd);color:var(--mu);cursor:pointer">✓ Pagar</button>'
        +'<button onclick="finDelGlobal(\'' +l.id+ '\')" title="Excluir" style="font-size:10px;padding:4px 7px;border-radius:5px;background:rgba(201,72,74,.06);border:1px solid rgba(201,72,74,.2);color:#c9484a;cursor:pointer">✕</button>'
      +'</div>';
    });
  }

  // ── Últimos pagamentos ──
  if(pagos.length){
    html += '<div style="font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.07em;color:var(--mu);margin:14px 0 8px">Últimos pagamentos</div>';
    pagos.forEach(function(l){
      var isRep = isRepasse(l);
      html += '<div style="display:flex;align-items:center;gap:10px;padding:7px 0;border-bottom:1px solid var(--bd);opacity:.7">'
        +'<div style="flex:1;font-size:12px;color:var(--tx)">'+escapeHtml(l.desc||'—')+(isRep?' <span style="font-size:9px;color:#c9484a">repasse</span>':'')+'</div>'
        +'<div style="font-size:11px;color:var(--mu)">'+fDt(l.dt_baixa||l.data)+'</div>'
        +'<div style="font-size:12px;font-weight:600;color:#4ade80">'+fmtV(l.valor)+'</div>'
        +'<span style="font-size:9px;padding:1px 6px;border-radius:4px;background:rgba(76,175,125,.12);color:#4ade80">PAGO</span>'
        +'<button onclick="finDelGlobal(\'' +l.id+ '\')" title="Excluir" style="font-size:10px;padding:2px 6px;border-radius:4px;background:var(--sf3);border:1px solid var(--bd);color:var(--mu);cursor:pointer">✕</button>'
      +'</div>';
    });
  }

  html += '</div>';
  return html;
}


// ─── ABA: DESPESAS FIXAS ──────────────────────────────────────

function abrirNovaFixa(){
  var hoje = new Date().toISOString().slice(0,10);
  abrirModal('+ Nova Despesa Fixa',
    '<div class="fm-row">'
      +'<div style="flex:2"><label class="fm-lbl">Descrição *</label><input class="fm-inp" id="nf-desc" placeholder="Ex: Aluguel, INSS, Assinatura..."></div>'
      +'<div><label class="fm-lbl">Dia vencimento</label><input class="fm-inp" type="number" id="nf-dia" min="1" max="31" value="5"></div>'
    +'</div>'
    +'<div class="fm-row">'
      +'<div><label class="fm-lbl">Valor (R$) *</label><input class="fm-inp" type="number" id="nf-valor" min="0" step="0.01" placeholder="0,00"></div>'
      +'<div><label class="fm-lbl">Categoria</label><select class="fm-inp" id="nf-cat"><option value="Estrutura">Estrutura</option><option value="Pessoal">Pessoal</option><option value="Serviços">Serviços</option><option value="Impostos">Impostos</option><option value="Variáveis">Variáveis</option></select></div>'
    +'</div>'
    +'<div><label class="fm-lbl">Observação</label><input class="fm-inp" id="nf-obs" placeholder="Opcional"></div>',
  function(){
    var desc  = document.getElementById('nf-desc')?.value.trim();
    var valor = parseFloat(document.getElementById('nf-valor')?.value||0);
    var dia   = parseInt(document.getElementById('nf-dia')?.value||5);
    var cat   = document.getElementById('nf-cat')?.value||'Variáveis';
    var obs   = document.getElementById('nf-obs')?.value||'';
    if(!desc||!valor){ showToast('Preencha descrição e valor'); return; }
    if(!_despFixas) _despFixas=[];
    _despFixas.push({id:genId(),desc:desc,valor:valor,dia:dia,cat:cat,obs:obs,ate:'2099-12'});
    sbSet('co_despfixas',_despFixas);
    marcarAlterado(); fecharModal(); vfRender();
    showToast('✓ Template criado');
  }, '✓ Salvar');
}


// ─── ABA: FLUXO DE CAIXA ───────────────────────────────────────

function vfLista(todos, tipo){
  const fmtDt=d=>d?fDt(d):'-';
  const isRec=tipo==='receber';
  const mesAtual=new Date(HOJE).toISOString().slice(0,7);
  const MESES=['Jan','Fev','Mar','Abr','Mai','Jun','Jul','Ago','Set','Out','Nov','Dez'];
  const mesesOpts=Array.from({length:12},(_,i)=>{
    const mv='2026-'+String(i+1).padStart(2,'0');
    return '<option value="'+mv+'"'+(mv===mesAtual?' selected':'')+'>'+MESES[i]+'/26</option>';
  }).join('');
  const itens=todos.filter(l=>l.tipo===tipo);
  const soma=arr=>arr.reduce((s,l)=>s+l.valor,0);
  const totAll=soma(itens), totPago=soma(itens.filter(l=>l.status==='pago'));
  const totVenc=soma(itens.filter(l=>l.status==='vencido'));
  const totPend=soma(itens.filter(l=>l.status==='pendente'));

  const cards='<div class="vf-cards">'
    +'<div class="vf-card '+(isRec?'verde':'vermelho')+'">'
      +'<div class="vf-card-lbl">Total '+(isRec?'a receber':'a pagar')+'</div>'
      +'<div class="vf-card-val">'+fBRL(totAll)+'</div>'
      +'<div class="vf-card-sub">'+itens.length+' lancamentos</div>'
    +'</div>'
    +'<div class="vf-card verde">'
      +'<div class="vf-card-lbl">'+(isRec?'Recebido':'Pago')+'</div>'
      +'<div class="vf-card-val">'+fBRL(totPago)+'</div>'
    +'</div>'
    +'<div class="vf-card laranja">'
      +'<div class="vf-card-lbl">Pendente</div>'
      +'<div class="vf-card-val">'+fBRL(totPend)+'</div>'
    +'</div>'
    +(totVenc?'<div class="vf-card vermelho">'
      +'<div class="vf-card-lbl">Vencido</div>'
      +'<div class="vf-card-val">'+fBRL(totVenc)+'</div>'
    +'</div>':'')
  +'</div>';

  const filtros='<div class="vf-filtros-bar">'
    +'<input class="vf-finp" id="vf-busca" placeholder="Buscar..." oninput="vfFiltrar()">'
    +'<select class="vf-finp" id="vf-fmes" onchange="vfFiltrar()"><option value="">Todos meses</option>'+mesesOpts+'</select>'
    +'<select class="vf-finp" id="vf-fstatus" onchange="vfFiltrar()"><option value="">Todos status</option><option value="pendente">Pendente</option><option value="pago">'+(isRec?'Recebido':'Pago')+'</option><option value="vencido">Vencido</option></select>'
    +'<button class="fin-new-btn" onclick="novoLancamentoDir(this.dataset.tipo)" data-tipo="'+tipo+'" style="white-space:nowrap">+ '+(isRec?'Nova receita':'Nova despesa')+'</button>'
  +'</div>';

  const BADGE={
    pago:'<span class="vf-st-badge pago">'+(isRec?'RECEBIDO':'PAGO')+'</span>',
    pendente:'<span class="vf-st-badge pendente">PENDENTE</span>',
    vencido:'<span class="vf-st-badge vencido">VENCIDO</span>',
    parcelado:'<span class="vf-st-badge parcelado">PARCELADO</span>',
    recorrente:'<span class="vf-st-badge parcelado">RECORRENTE</span>',
  };

  const linhas=itens.map(l=>{
    const isPago=l.status==='pago', isVenc=l.status==='vencido';
    const badge=BADGE[l.status]||BADGE.pendente;
    const canBaixa=!isPago;
    const canEdit=l.origem==='global';
    const baixaFn='vfBaixar(&quot;' + l.id + '&quot;)';
    const editFn='vfEditarLanc(\'' + l.id + '\')';
    const delFn='vfDelGlobal(\'' + l.id + '\')';
    const baixaBtn=canBaixa?('<button class="vf-ac-btn baixar" onclick="'+baixaFn+'" title="Dar baixa">'+(isRec?'✓ Receber':'✓ Pagar')+'</button>'):'';
    // Edit/delete para global e local; retificação para projuris (baixas)
    const _lid = String(l.id).replace(/'/g,"");
    const editBtn = l.origem==='global'
      ? ('<button class="vf-ac-btn editar" onclick="'+editFn+'">✏</button>'
          +'<button class="vf-ac-btn excluir" onclick="'+delFn+'">✕</button>')
      : l.origem==='local'
        ? ('<button class="vf-ac-btn editar" onclick="vfEditarLocal(&quot;'+_lid+'&quot;)">✏</button>'
            +'<button class="vf-ac-btn excluir" onclick="vfDelLocal(&quot;'+_lid+'&quot;)">✕</button>')
        : l.origem==='projuris' && isPago
          ? ('<button class="vf-ac-btn excluir" onclick="vfEstornarProjuris(&quot;'+_lid+'&quot;)" title="Estornar baixa">↩</button>')
          : l.origem==='projuris'
            ? '<span class="vf-origem-tag" title="Lançamento do Projuris — não pode ser excluído aqui. Para ignorar, use Estornar após dar baixa.">Projuris</span>'
            : '';
    return '<tr class="'+(isPago?'vf-row-pago':isVenc?'vf-row-venc':'')+'"'
      +' data-desc="'+((l.desc||'').toLowerCase().replace(/"/g,''))+'"'
      +' data-mes="'+((l.venc||l.data||'').slice(0,7))+'"'
      +' data-status="'+l.status+'">'
      +'<td style="white-space:nowrap">'+fmtDt(l.venc||l.data)+'</td>'
      +'<td><div style="font-weight:500">'+(l.desc||'-')+'</div>'
        +(l.obs?'<div style="font-size:10px;color:var(--mu)">'+l.obs+'</div>':'')+'</td>'
      +'<td style="color:var(--mu)">'+(l.cliente||'-')+'</td>'
      +'<td style="color:var(--mu);font-size:11px">'+(l.subtipo&&typeof l.subtipo==='string'?l.subtipo:(l.centro||''))+'</td>'
      +'<td class="td-val '+(isRec?'pos':'neg')+'" style="text-align:right;font-weight:700">'+fBRL(l.valor)+'</td>'
      +'<td>'+badge+(l.dt_baixa?'<div style="font-size:9px;color:var(--mu)">'+fmtDt(l.dt_baixa)+'</div>':'')+'</td>'
      +'<td><div class="vf-acoes">'+baixaBtn+editBtn+'</div></td>'
    +'</tr>';
  }).join('');

  return cards+filtros
    +'<div style="overflow-x:auto"><table class="vf-table" id="vf-tabela">'
    +'<thead><tr><th>Vencimento</th><th>Descricao</th>'
    +'<th>'+(isRec?'Cliente':'Fornecedor')+'</th>'
    +'<th>Categoria</th><th style="text-align:right">Valor</th><th>Status</th><th>Acoes</th></tr></thead>'
    +'<tbody>'+(linhas||'<tr><td colspan="7" style="text-align:center;color:var(--mu);padding:24px">Nenhum lancamento</td></tr>')+'</tbody>'
    +'</table></div>';
}


// ─── ABA: HONORÁRIOS ──────────────────────────────────────────
function vfHonorarios(todos){
  const fmtDt = d => d?fDt(d):'—';
  const hons = todos.filter(l=>
    l.tipo==='receber' && (l.subtipo==='honorario'||l.subtipo==='honorario_fixo'||
    l.subtipo==='honorario_perc'||l.subtipo==='sucumbencia'||l.origem==='projuris')
  );
  const recebidos = hons.filter(l=>l.status==='pago').reduce((s,l)=>s+l.valor,0);
  const aReceber  = hons.filter(l=>l.status!=='pago').reduce((s,l)=>s+l.valor,0);
  const total     = hons.reduce((s,l)=>s+l.valor,0);

  const cards = `
  <div class="vf-cards">
    <div class="vf-card ouro"><div class="vf-card-lbl">Total honorários</div><div class="vf-card-val">${fBRL(total)}</div></div>
    <div class="vf-card verde"><div class="vf-card-lbl">Recebidos</div><div class="vf-card-val">${fBRL(recebidos)}</div></div>
    <div class="vf-card laranja"><div class="vf-card-lbl">A receber</div><div class="vf-card-val">${fBRL(aReceber)}</div></div>
  </div>`;

  const linhas = hons.sort((a,b)=>(a.venc||'').localeCompare(b.venc||'')).map(l=>`
    <tr>
      <td>${fmtDt(l.venc||l.data)}</td>
      <td>${l.desc}</td>
      <td style="color:var(--mu)">${l.cliente}</td>
      <td style="color:var(--mu)">${l.centro||'—'}</td>
      <td class="td-val pos">${fBRL(l.valor)}</td>
      <td><span class="vf-pill ${l.status}">${l.status==='pago'?'✓ PAGO':l.status==='vencido'?'⚠ VENC':'PEND'}</span></td>
    </tr>`).join('');

  return `${cards}
  <div class="vf-sec">Detalhamento</div>
  <table class="vf-table">
    <thead><tr><th>Vencimento</th><th>Descrição</th><th>Cliente</th><th>Centro</th><th style="text-align:right">Valor</th><th>Status</th></tr></thead>
    <tbody>${linhas||'<tr><td colspan="6" style="text-align:center;color:var(--mu);padding:24px">Nenhum lançamento</td></tr>'}</tbody>
  </table>`;
}

// ─── ABA: INADIMPLÊNCIA ───────────────────────────────────────

// ─── ABA: DRE ─────────────────────────────────────────────────




function vfEditarLanc(id){
  const rawId = id.startsWith('g') ? parseInt(id.slice(1)) : parseInt(id);
  const l = finLancs.find(x=>x.id===rawId);
  if(!l){ showToast('Lançamento não encontrado'); return; }
  _renderModalLanc({...l, id: l.id});
}

// ── Despesas a Reembolsar ──
function vfReembolsar(){
  const pendentes = despesasProcesso.filter(d=>!d.reembolsado);
  const reembolsados = despesasProcesso.filter(d=>d.reembolsado);
  const totalPend = pendentes.reduce((s,d)=>s+d.valor,0);
  const totalRec  = reembolsados.reduce((s,d)=>s+d.valor,0);

  const fBRL = v => 'R$ '+v.toFixed(2).replace('.',',').replace(/\B(?=(\d{3})+(?!\d))/g,'.');
// fDt defined at top of script;

  const linhas = (arr, mostrarReemb) => arr.length===0
    ? `<tr><td colspan="6" style="text-align:center;color:var(--mu);padding:14px">Nenhum item</td></tr>`
    : arr.map(d=>`
      <tr style="border-bottom:1px solid var(--sf3)">
        <td style="padding:7px 6px;font-size:12px">${d.data||'—'}</td>
        <td style="padding:7px 6px;font-size:12px;max-width:220px">
          <div style="font-weight:500;color:var(--of)">${d.desc||'—'}</div>
          <div style="font-size:10px;color:var(--mu)">${d.cat||''} · ${d.mov_projuris||''}</div>
          ${d.cliente_vinc?`<div style="font-size:10px;color:var(--ouro)">👤 ${d.cliente_vinc}</div>`:'<div style="font-size:10px;color:#f87676">⚠ Cliente não vinculado</div>'}
        </td>
        <td style="padding:7px 6px;font-size:12px;color:#fb923c;font-weight:600;white-space:nowrap">${fBRL(d.valor)}</td>
        <td style="padding:7px 6px;font-size:11px;color:var(--mu)">${d.obs?d.obs.slice(0,40)+'…':''}</td>
        <td style="padding:7px 6px">
          <button class="btn-bordo btn-bordo-sm" onclick="reembVincularCliente(${d.id})"></button>
        </td>
        <td style="padding:7px 6px">
          ${mostrarReemb
            ? `<button onclick="reembMarcarPago(${d.id})" 
                style="background:#14532d;border:1px solid #16a34a;border-radius:4px;color:#4ade80;font-size:10px;padding:3px 7px;cursor:pointer">
                ✓ Pago</button>`
            : `<button class="btn-bordo btn-bordo-sm" onclick="reembDesfazer(${d.id})">↩ Desfazer</button>`
          }
        </td>
      </tr>`).join('');

  return `
  <div class="vf-cards">
    <div class="vf-card vermelho">
      <div class="vf-card-lbl">⚠ A Reembolsar pelo cliente</div>
      <div class="vf-card-val">${fBRL(totalPend)}</div>
      <div class="vf-card-sub">${pendentes.length} itens pendentes</div>
    </div>
    <div class="vf-card verde">
      <div class="vf-card-lbl">✓ Já reembolsado</div>
      <div class="vf-card-val">${fBRL(totalRec)}</div>
      <div class="vf-card-sub">${reembolsados.length} itens</div>
    </div>
    <div class="vf-card ouro">
      <div class="vf-card-lbl">Total adiantado pelo escritório</div>
      <div class="vf-card-val">${fBRL(totalPend+totalRec)}</div>
      <div class="vf-card-sub">desde 2021</div>
    </div>
  </div>

  <div style="display:flex;align-items:center;gap:10px;margin-bottom:10px">
    <div class="vf-sec" style="margin:0;flex:1">📋 Despesas pendentes de reembolso (${pendentes.length})</div>
    <button onclick="reembNovaDesp()" 
      style="background:var(--vinho);border:none;border-radius:5px;color:#fff;padding:6px 12px;font-size:12px;cursor:pointer">
      ＋ Nova despesa
    </button>
  </div>

  <div style="overflow-x:auto;margin-bottom:20px">
    <table style="width:100%;border-collapse:collapse">
      <thead>
        <tr style="background:var(--sf2)">
          <th style="padding:7px 6px;font-size:10px;font-weight:700;color:var(--mu);text-align:left">Data</th>
          <th style="padding:7px 6px;font-size:10px;font-weight:700;color:var(--mu);text-align:left">Descrição</th>
          <th style="padding:7px 6px;font-size:10px;font-weight:700;color:var(--mu);text-align:left">Valor</th>
          <th style="padding:7px 6px;font-size:10px;font-weight:700;color:var(--mu);text-align:left">Obs</th>
          <th style="padding:7px 6px;font-size:10px;font-weight:700;color:var(--mu);text-align:left">Cliente</th>
          <th style="padding:7px 6px;font-size:10px;font-weight:700;color:var(--mu);text-align:left">Ação</th>
        </tr>
      </thead>
      <tbody>${linhas(pendentes, true)}</tbody>
    </table>
  </div>

  ${reembolsados.length>0?`
  <details style="margin-top:10px">
    <summary style="cursor:pointer;font-size:12px;color:var(--mu);padding:6px">
      ✓ Já reembolsados (${reembolsados.length}) — ${fBRL(totalRec)}
    </summary>
    <div style="overflow-x:auto;margin-top:8px">
      <table style="width:100%;border-collapse:collapse">
        <tbody style="opacity:.6">${linhas(reembolsados, false)}</tbody>
      </table>
    </div>
  </details>`:''}`;
}

function reembVincularCliente(id){
  const dep = despesasProcesso.find(d=>d.id===id);
  if(!dep) return;
  
  const opts = CLIENTS.map(c=>`<option value="${c.cliente}" ${dep.cliente_vinc===c.cliente?'selected':''}>${c.cliente} (Pasta ${c.pasta})</option>`).join('');
  
  abrirModal('👤 Vincular cliente — '+dep.desc,`
    <div style="font-size:12px;color:var(--mu);margin-bottom:10px">
      Valor: <strong style="color:var(--of)">R$ ${dep.valor.toFixed(2).replace('.',',')}</strong> · ${dep.data}
    </div>
    <label class="fm-lbl">Cliente</label>
    <select class="fm-inp" id="reemb-cli">
      <option value="">— selecionar —</option>
      ${opts}
    </select>
    <div style="margin-top:10px">
      <label class="fm-lbl">Observação (opcional)</label>
      <input class="fm-inp" id="reemb-obs" value="${dep.obs||''}" placeholder="Detalhes sobre esta despesa">
    </div>
  `,()=>{
    const cli = document.getElementById('reemb-cli')?.value;
    const obs = document.getElementById('reemb-obs')?.value||dep.obs||'';
    const idx = despesasProcesso.findIndex(d=>d.id===id);
    if(idx>=0){ despesasProcesso[idx].cliente_vinc=cli; despesasProcesso[idx].obs=obs; }
    sbSet('co_desp_proc', despesasProcesso);
    marcarAlterado(); fecharModal();
    vfRender(); showToast('Cliente vinculado ✓');
  },'Salvar');
}

function reembMarcarPago(id){
  const idx = despesasProcesso.findIndex(d=>d.id===id);
  if(idx<0) return;
  const dep = despesasProcesso[idx];
  abrirModal('Marcar como reembolsado',
    '<div style="font-size:13px;color:var(--mu)">Marcar como reembolsado: <strong>'+escapeHtml(dep.desc)+'</strong><br>R$ '+dep.valor.toFixed(2).replace('.',',')+' ?</div>',
    function(){
      despesasProcesso[idx].reembolsado = true;
      despesasProcesso[idx].dt_reembolso = new Date().toISOString().slice(0,10);
      sbSet('co_desp_proc', despesasProcesso);
      fecharModal(); marcarAlterado(); vfRender(); showToast('Marcado como reembolsado ✓');
    }, 'Confirmar'
  );
}

function reembDesfazer(id){
  const idx = despesasProcesso.findIndex(d=>d.id===id);
  if(idx>=0){ despesasProcesso[idx].reembolsado=false; delete despesasProcesso[idx].dt_reembolso; }
  sbSet('co_desp_proc', despesasProcesso);
  marcarAlterado(); vfRender(); showToast('Revertido para pendente');
}

function reembNovaDesp(){
  abrirModal('➕ Nova Despesa de Processo',`
    <div style="font-size:11px;color:var(--mu);margin-bottom:10px">Despesa adiantada pelo escritório a cobrar do cliente</div>
    <div class="fm-row">
      <div style="flex:2"><label class="fm-lbl">Descrição *</label>
        <input class="fm-inp" id="rd-desc" placeholder="Ex: Custas finais, Perito, Correios...">
      </div>
      <div><label class="fm-lbl">Data *</label>
        <input class="fm-inp" type="date" id="rd-data" value="${new Date().toISOString().slice(0,10)}">
      </div>
    </div>
    <div class="fm-row" style="margin-top:8px">
      <div><label class="fm-lbl">Categoria</label>
        <select class="fm-inp" id="rd-cat">
          ${['Custas Judiciais','Correios','Autenticações','Cartório','Despesas de viagem',
             'Honorários Perito','Outras despesas processuais'].map(c=>`<option>${c}</option>`).join('')}
        </select>
      </div>
      <div><label class="fm-lbl">Valor (R$) *</label>
        <input class="fm-inp" type="number" id="rd-valor" min="0" step="0.01" placeholder="0,00">
      </div>
    </div>
    <div style="margin-top:8px"><label class="fm-lbl">Cliente</label>
      <select class="fm-inp" id="rd-cli">
        <option value="">— identificar depois —</option>
        ${CLIENTS.map(c=>`<option value="${c.cliente}">${c.cliente} (Pasta ${c.pasta})</option>`).join('')}
      </select>
    </div>
    <div style="margin-top:8px"><label class="fm-lbl">Observação</label>
      <input class="fm-inp" id="rd-obs" placeholder="Nota fiscal, referência, fornecedor...">
    </div>
  `,()=>{
    const desc  = document.getElementById('rd-desc')?.value.trim();
    const valor = parseFloat(document.getElementById('rd-valor')?.value)||0;
    const data  = document.getElementById('rd-data')?.value;
    if(!desc||!valor||!data){ showToast('Preencha descrição, valor e data'); return; }
    despesasProcesso.push({
      id: genId(),
      desc, valor, data,
      cat:  document.getElementById('rd-cat')?.value||'',
      cliente_vinc: document.getElementById('rd-cli')?.value||'',
      obs:  document.getElementById('rd-obs')?.value||'',
      reembolsado: false,
      origem: 'manual'
    });
    sbSet('co_desp_proc', despesasProcesso);
    marcarAlterado(); fecharModal(); vfRender();
    showToast('Despesa registrada ✓');
  },'💾 Salvar');
}
function vfBaixar(id){
  // Validar: já pago?
  const todos = vfTodos();
  const lanc  = todos.find(l=>l.id===id);
  if(lanc && (lanc.status==='pago' || lanc.pago)){
    showToast('Este lançamento já foi baixado'); return;
  }

  // Resolver dados do lançamento
  let descLanc='', valorLanc=0, clienteLanc='', tipoDir='receber', processLanc='';
  if(id.startsWith('g')){
    const rawId = id.slice(1);
    const fl = finLancs.find(l=>String(l.id)===rawId);
    if(!fl){showToast('Lançamento não encontrado');return;}
    descLanc=fl.desc||''; valorLanc=parseFloat(fl.valor)||0;
    clienteLanc=fl.cliente||''; tipoDir=fl.tipo||'receber';
  } else if(id.startsWith('l')){
    const rawId = id.slice(1);
    const ll = (localLanc||[]).find(l=>String(l.id)===rawId);
    if(!ll){showToast('Lançamento não encontrado');return;}
    descLanc=ll.desc||ll.descricao||''; valorLanc=parseFloat(ll.valor)||0;
    clienteLanc=ll.cliente||''; tipoDir=ll.tipo||ll.direcao||'receber';
    processLanc = ll.id_processo ? (CLIENTS.find(c=>c.id===ll.id_processo)?.cliente||'') : '';
  } else if(id.startsWith('p')){
    const rawNum = id.slice(1);
    const orig = (FIN_XLSX||[]).find(l=>String(l.id)===rawNum);
    if(!orig){showToast('Projuris não encontrado');return;}
    const pm={}; CLIENTS.forEach(c=>{pm[String(c.pasta)]=c.cliente;});
    descLanc=orig.desc||orig.mov_projuris||orig.cat||'Honorário Projuris'; valorLanc=orig.val||0;
    clienteLanc=pm[String(orig.pasta)]||orig.pasta||'';
    tipoDir=orig.tipo==='receber'?'receber':'pagar';
    processLanc=clienteLanc;
  }

  const _tiposReceber = new Set(['receber','acordo','honorario','honorario_direto','sucumbencia','alvara','reembolso','assessoria','consulta']);
  const isRec   = _tiposReceber.has(tipoDir) || (tipoDir!=='pagar' && tipoDir!=='repasse' && tipoDir!=='despesa' && tipoDir!=='despint');
  const hoje    = new Date().toISOString().slice(0,10);
  const corVal  = isRec ? '#4ade80' : '#f87676';
  const CONTAS  = ['Inter','CEF','Dinheiro','Outra'];
  const FORMAS  = ['PIX','TED / Depósito','Boleto','Dinheiro','Cheque','Cartão de Crédito','Cartão de Débito','Alvará judicial'];

  const bodyHtml =
    '<div style="background:var(--sf3);border-radius:8px;padding:12px 14px;margin-bottom:14px">'
      +'<div style="font-size:11px;color:var(--mu);margin-bottom:2px">Lançamento</div>'
      +'<div style="font-size:14px;font-weight:700;color:var(--tx)">'+(descLanc||'—')+'</div>'
      +(clienteLanc?'<div style="font-size:11px;color:var(--mu);margin-top:2px">Cliente: '+clienteLanc+'</div>':'')
      +(processLanc&&processLanc!==clienteLanc?'<div style="font-size:11px;color:var(--mu)">Processo: '+processLanc+'</div>':'')
    +'</div>'
    +'<div class="fm-row">'
      +'<div><label class="fm-lbl">Valor '+(isRec?'recebido':'pago')+' (R$)</label>'
        +'<input class="fm-inp" type="number" id="vfb-valor" value="'+valorLanc.toFixed(2)+'" min="0.01" step="0.01">'
        +'<div style="font-size:10px;color:var(--mu);margin-top:2px">Valor original: '+fBRL(valorLanc)+'</div>'
      +'</div>'
      +'<div><label class="fm-lbl">Data '+(isRec?'de recebimento':'de pagamento')+'</label>'
        +'<input class="fm-inp" type="date" id="vfb-data" value="'+hoje+'">'
      +'</div>'
    +'</div>'
    +'<div class="fm-row" style="margin-top:10px">'
      +'<div><label class="fm-lbl">Conta de destino</label>'
        +'<select class="fm-inp" id="vfb-conta">'
          +'<option value="">— selecionar —</option>'
          +CONTAS.map(c=>'<option>'+c+'</option>').join('')
        +'</select>'
      +'</div>'
      +'<div><label class="fm-lbl">Forma de pagamento</label>'
        +'<select class="fm-inp" id="vfb-forma">'
          +'<option value="">— selecionar —</option>'
          +FORMAS.map(f=>'<option>'+f+'</option>').join('')
        +'</select>'
      +'</div>'
    +'</div>'
    +'<div style="margin-top:10px"><label class="fm-lbl">Observação (opcional)</label>'
      +'<input class="fm-inp" id="vfb-obs" placeholder="Comprovante, referência, nº nota...">'
    +'</div>';

  // Para receitas: verificar se já tem repasse gerado (acordo)
  if(isRec){
    // Se é acordo com repasse já gerado, ir direto para recebimento simples
    var temRepasseGerado = false;
    if(id.startsWith('l')){
      var _ll2 = (localLanc||[]).find(function(x){return String(x.id)===id.slice(1);});
      if(_ll2 && _ll2._grupo_acordo){
        temRepasseGerado = (localLanc||[]).some(function(x){return x._grupo_acordo===_ll2._grupo_acordo && x._repasse_acordo;});
      }
    }

    if(temRepasseGerado){
      // Acordo: recebimento simples direto (repasse já existe)
      abrirModal('\u2705 Confirmar Recebimento', bodyHtml, function(){
        var valorBaixa2 = parseFloat((document.getElementById('vfb-valor')||{}).value)||valorLanc;
        var dtBaixa2 = (document.getElementById('vfb-data')||{}).value||hoje;
        var conta2 = (document.getElementById('vfb-conta')||{}).value||'';
        var forma2 = (document.getElementById('vfb-forma')||{}).value||'';
        var obs2 = ((document.getElementById('vfb-obs')||{}).value||'').trim();
        if(valorBaixa2<=0){showToast('Informe valor');return;}
        _executarBaixa(id,valorBaixa2,dtBaixa2,forma2,obs2,lanc);
        fecharModal(); marcarAlterado(); vfInvalidarCache();
        if(document.getElementById('vf')?.classList.contains('on')) vfRender();
        renderFinDash();
        showToast('\u2705 Recebimento registrado!');
      }, '\u2705 Confirmar');
    } else {
      // Outros: escolha simples ou com repasse
      var escolhaHtml = bodyHtml
      +'<div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-top:14px">'
        +'<button onclick="vfBaixarSimples(&quot;'+id+'&quot;)" style="padding:12px;border-radius:8px;border:1px solid rgba(76,175,125,.4);background:rgba(76,175,125,.08);color:#4ade80;font-size:12px;font-weight:700;cursor:pointer;font-family:inherit">'
          +'✅ Recebimento simples<br><span style="font-size:10px;font-weight:400;color:var(--mu)">100% para o escritório<br>(honorários, consultoria, sucumbência pura)</span>'
        +'</button>'
        +'<button onclick="vfBaixarComRepasse(&quot;'+id+'&quot;)" style="padding:12px;border-radius:8px;border:1px solid rgba(212,175,55,.4);background:rgba(212,175,55,.08);color:#D4AF37;font-size:12px;font-weight:700;cursor:pointer;font-family:inherit">'
          +'⚖️ Recebimento com repasse<br><span style="font-size:10px;font-weight:400;color:var(--mu)">Alvará/acordo com divisão<br>(sucumbência + honorários + cliente)</span>'
        +'</button>'
      +'</div>';
    abrirModal('💰 Confirmar Recebimento', escolhaHtml, null, null);
    }
    return;
  }
  abrirModal('✅ Confirmar Pagamento', bodyHtml, ()=>{
    const valorBaixa = parseFloat(document.getElementById('vfb-valor')?.value)||valorLanc;
    const dtBaixa    = document.getElementById('vfb-data')?.value||hoje;
    const conta      = document.getElementById('vfb-conta')?.value||'';
    const forma      = document.getElementById('vfb-forma')?.value||'';
    const obs        = document.getElementById('vfb-obs')?.value.trim()||'';

    if(valorBaixa <= 0){ showToast('Informe um valor válido'); return; }

    // ── A. Atualizar o lançamento original ─────────────────
    function _atualizarLanc(obj){
      return {...obj,
        status:'pago', pago:true,
        dt_baixa: dtBaixa,
        valor_baixa: valorBaixa,
        conta_destino: conta,
        forma: forma||obj.forma||'',
        obs: obs ? ((obj.obs?obj.obs+' | ':'')+obs) : (obj.obs||''),
        parcial: valorBaixa < (parseFloat(obj.valor)||0)
      };
    }

    // ── B. Inserir no Monte Mor (fluxo de caixa global) ────
    function _inserirMonteMor(lancRef){
      const entradaMM = {
        id: 'mm'+genId(),
        id_lancamento_ref: id,
        tipo: isRec ? 'entrada' : 'saida',
        valor: valorBaixa,
        data: dtBaixa,
        desc: descLanc,
        cliente: clienteLanc,
        conta: conta,
        forma: forma,
        obs: obs,
        criado_em: new Date().toISOString()
      };
      if(!monteMor) monteMor=[];
      monteMor.push(entradaMM);
      sbSet('co_monte_mor', monteMor);
    }

    // ── C. Sync pasta do cliente ────────────────────────────
    function _syncPasta(){
      if(!clienteLanc) return;
      const cli = findClientByName(clienteLanc);
      if(!cli) return;
      if(!cli.lancamentos) cli.lancamentos=[];
      // Evitar duplicata
      if(cli.lancamentos.some(l=>l._baixa_id===id)) return;
      cli.lancamentos.push({
        id: genId(), _baixa_id: id,
        tipo: tipoDir, desc: descLanc,
        valor: valorBaixa, data: dtBaixa,
        status: 'pago', conta, forma,
        origem: 'baixa_financeiro'
      });
      // Mover lançamento de pendentes → histórico (flag)
      cli._ultimo_recebimento = { valor: valorBaixa, data: dtBaixa, desc: descLanc };
      // Andamento na pasta
      const cid = cli.id;
      if(!localMov[cid]) localMov[cid]=[];
      localMov[cid].unshift({
        data: dtBaixa,
        movimentacao: '['+(isRec?'Recebimento':'Pagamento')+'] '+descLanc
          +' — '+fBRL(valorBaixa)
          +(forma?' via '+forma:'')
          +(conta?' → '+conta:'')
          +(obs?' | '+obs:''),
        tipo_movimentacao: 'Financeiro',
        origem: 'baixa_fin'
      });
      sbSet('co_localMov', localMov);
      // Atualizar histórico Projuris na ficha do cliente
      if(typeof renderFinXlsx==='function') renderFinXlsx(cli);
      if(typeof _reRenderFinPasta==='function') _reRenderFinPasta(cid);
    }

    // ── D. Executar transação ───────────────────────────────
    if(id.startsWith('g')){
      const rawId = id.slice(1);
      const i = finLancs.findIndex(l=>String(l.id)===rawId);
      if(i===-1){showToast('Não encontrado');return;}
      finLancs[i] = _atualizarLanc(finLancs[i]);
      _inserirMonteMor(finLancs[i]);
      _syncPasta();
      sbSet('co_fin', finLancs);
      if(clienteLanc){ const _cG=findClientByName(clienteLanc); if(_cG) _reRenderFinPasta(_cG.id); }
    } else if(id.startsWith('l')){
      const rawId = id.slice(1);
      const i = (localLanc||[]).findIndex(l=>String(l.id)===rawId);
      if(i===-1){showToast('Não encontrado');return;}
      localLanc[i] = _atualizarLanc(localLanc[i]);
      _inserirMonteMor(localLanc[i]);
      _syncPasta();
      sbSet('co_localLanc', localLanc);
      const _cidL = localLanc[(localLanc||[]).findIndex(l=>String(l.id)===id.slice(1))]?.id_processo;
      if(_cidL) _reRenderFinPasta(_cidL);
      else if(clienteLanc){ const _cL=findClientByName(clienteLanc); if(_cL) _reRenderFinPasta(_cL.id); }
    } else if(id.startsWith('p')){
      const rawNum = id.slice(1);
      const pm={}; CLIENTS.forEach(c=>{pm[String(c.pasta)]=c.cliente;});
      const orig = (FIN_XLSX||[]).find(l=>String(l.id)===rawNum);
      if(!orig){showToast('Não encontrado');return;}
      const ex = finLancs.find(l=>String(l._projuris_id)===rawNum);
      if(ex){
        const i = finLancs.indexOf(ex);
        finLancs[i] = _atualizarLanc(finLancs[i]);
        _inserirMonteMor(finLancs[i]);
        _syncPasta();
      } else {
        const nl = _atualizarLanc({
          id:genId(), _projuris_id:rawNum,
          tipo:tipoDir, desc:descLanc,
          cliente:clienteLanc, valor:valorLanc,
          data:orig.dt_venc||orig.dt_comp||hoje,
          cat:'Honorarios'
        });
        finLancs.push(nl);
        _inserirMonteMor(nl);
        _syncPasta();
      }
      sbSet('co_fin', finLancs);
      if(clienteLanc){ const _cP=findClientByName(clienteLanc); if(_cP) _reRenderFinPasta(_cP.id); }
    }

    marcarAlterado();
    fecharModal();
    vfRender();
    // ── E. Atualizar dashboard ──────────────────────────────
    atualizarStats();
    if(typeof renderFinDash==='function') renderFinDash();
    if(typeof renderHomeAlerts==='function') renderHomeAlerts();
    audit('baixa',(isRec?'Recebimento':'Pagamento')+': '+descLanc+' — '+fBRL(valorBaixa),'lancamento');
    showToast((isRec?'✅ Recebimento':'✅ Pagamento')+' confirmado'+( valorBaixa<valorLanc?' (parcial)':''));
  }, '✅ Confirmar e Sincronizar');
}


// ── Recebimento simples: 100% para o escritório ──
// ── Buscar dados bancários do cliente ──
function getDadosBancarios(nomeCliente){
  const c = findClientByName(nomeCliente);
  if(!c) return null;
  const ex = (tasks[c.id]||{}).extra || {};
  // Também verifica campos diretos do cliente (campo 'banco' inline)
  const banco    = ex.banco    || c.banco    || '';
  const ag       = ex.ag       || c.ag       || '';
  const conta    = ex.conta    || c.conta    || '';
  const tconta   = ex.tconta   || c.tconta   || '';
  const operacao = ex.operacao || c.operacao || '';
  const pix      = ex.pix      || c.pix      || '';
  const nomebenef= ex.nomebenef|| c.nomebenef|| nomeCliente;
  const cpfbenef = ex.cpfbenef || c.cpfbenef || '';
  if(!banco && !pix && !conta) return null;
  return { banco, ag, conta, tconta, operacao, pix, nomebenef, cpfbenef };
}

// ── Formatar bloco de dados bancários para WPP ──
function formatarDadosBancarios(dados){
  if(!dados) return '_Dados bancários não cadastrados. Acesse a ficha do processo → Dados Sensíveis → Banco._';
  var linhas = [];
  if(dados.banco)    linhas.push('Banco: ' + dados.banco);
  if(dados.ag)       linhas.push('Agência: ' + dados.ag);
  if(dados.conta)    linhas.push('Conta: ' + dados.conta + (dados.operacao?' (Op. '+dados.operacao+')':''));
  if(dados.tconta)   linhas.push('Tipo: ' + dados.tconta);
  if(dados.pix)      linhas.push('PIX: ' + dados.pix);
  if(dados.cpfbenef) linhas.push('CPF/CNPJ: ' + dados.cpfbenef);
  if(dados.nomebenef)linhas.push('Beneficiário: ' + dados.nomebenef);
  return linhas.join('\n');
}


function vfBaixarSimples(id){
  const todos = vfTodos();
  const lanc = todos.find(function(t){ return t.id===id; });
  if(!lanc){ showToast('Lançamento não encontrado'); return; }
  const hoje = new Date().toISOString().slice(0,10);
  const fBRL3 = function(v){ return 'R$ '+Math.abs(v).toLocaleString('pt-BR',{minimumFractionDigits:2,maximumFractionDigits:2}); };

  abrirModal('✅ Confirmar Recebimento',
    '<div style="background:var(--sf3);border-radius:8px;padding:12px 14px;margin-bottom:14px">'
      +'<div style="font-size:14px;font-weight:700;color:var(--tx)">'+escapeHtml(lanc.desc||'—')+'</div>'
      +(lanc.cliente?'<div style="font-size:11px;color:var(--mu);margin-top:2px">'+escapeHtml(lanc.cliente)+'</div>':'')
    +'</div>'
    +'<div class="fm-row">'
      +'<div><label class="fm-lbl">Valor recebido (R$)</label>'
        +'<input class="fm-inp" type="number" id="vfbs-valor" value="'+lanc.valor.toFixed(2)+'" min="0.01" step="0.01"></div>'
      +'<div><label class="fm-lbl">Data de recebimento</label>'
        +'<input class="fm-inp" type="date" id="vfbs-data" value="'+hoje+'"></div>'
    +'</div>'
    +'<div class="fm-row" style="margin-top:8px">'
      +'<div><label class="fm-lbl">Forma</label>'
        +'<select class="fm-inp" id="vfbs-forma">'
          +'<option>PIX</option><option>TED / Depósito</option><option>Boleto</option>'
          +'<option>Dinheiro</option><option>Alvará judicial</option>'
        +'</select></div>'
      +'<div style="flex:2"><label class="fm-lbl">Observação</label>'
        +'<input class="fm-inp" id="vfbs-obs" placeholder="Comprovante, referência..."></div>'
    +'</div>',
  finGuard(function(){
    const valorBaixa = parseFloat(document.getElementById('vfbs-valor')?.value)||lanc.valor;
    if(valorBaixa <= 0){ showToast('Valor deve ser positivo'); return; }
    const dtBaixa    = document.getElementById('vfbs-data')?.value||hoje;
    const forma      = document.getElementById('vfbs-forma')?.value||'';
    const obs        = document.getElementById('vfbs-obs')?.value.trim()||'';
    _executarBaixa(id, valorBaixa, dtBaixa, forma, obs, lanc);
    fecharModal();
    if(document.getElementById('vf')?.classList.contains('on')) vfRender();
    renderFinDash();
    if(typeof atualizarStats==='function') atualizarStats();
    showToast('✅ Recebimento registrado');
  }), '✅ Confirmar recebimento');
}

// ── Recebimento com repasse: calculadora de alvará/acordo ──
function vfBaixarComRepasse(id){
  const todos = vfTodos();
  const lanc = todos.find(function(t){ return t.id===id; });
  if(!lanc){ showToast('Lançamento não encontrado'); return; }
  const hoje = new Date().toISOString().slice(0,10);
  const fBRL3 = function(v){ return 'R$ '+Math.abs(v).toLocaleString('pt-BR',{minimumFractionDigits:2,maximumFractionDigits:2}); };

  // Buscar despesas reembolsáveis pendentes deste processo
  const cliObj = findClientByName(lanc.cliente);
  const despReimbPend = cliObj
    ? (localLanc||[]).filter(function(l){
        return l.id_processo===cliObj.id && l.tipo==='despesa' && !l.reembolsado && l.status!=='pago';
      })
    : [];
  const totDespPend = despReimbPend.reduce(function(s,l){return s+(l.valor||0);},0);

  const despBanner = despReimbPend.length
    ? '<div style="background:rgba(251,146,60,.08);border:1px solid rgba(251,146,60,.3);border-radius:8px;padding:10px 14px;margin-bottom:10px">'
        +'<div style="font-size:10px;font-weight:700;color:#fb923c;text-transform:uppercase;margin-bottom:6px">🧾 Despesas adiantadas a reembolsar ('+despReimbPend.length+')</div>'
        +despReimbPend.map(function(d){return '<div style="display:flex;justify-content:space-between;font-size:11px;margin-bottom:3px"><span style="color:var(--tx)">'+escapeHtml(d.desc||'—')+'</span><span style="color:#fb923c;font-weight:600">'+fBRL(d.valor||0)+'</span></div>';}).join('')
        +'<div style="border-top:1px solid rgba(251,146,60,.3);margin-top:6px;padding-top:6px;display:flex;justify-content:space-between"><span style="font-size:11px;font-weight:700;color:#fb923c">Total a reembolsar</span><span style="font-size:13px;font-weight:800;color:#fb923c">'+fBRL(totDespPend)+'</span></div>'
        +'<div style="font-size:10px;color:var(--mu);margin-top:4px">Já preenchido no campo de despesas abaixo.</div>'
      +'</div>'
    : '';

  abrirModal('⚖️ Recebimento com Repasse',
    '<div style="background:var(--sf3);border-radius:8px;padding:12px 14px;margin-bottom:14px">'
      +'<div style="font-size:14px;font-weight:700;color:var(--tx)">'+escapeHtml(lanc.desc||'—')+'</div>'
      +(lanc.cliente?'<div style="font-size:11px;color:var(--mu);margin-top:2px">'+escapeHtml(lanc.cliente)+'</div>':'')
    +'</div>'
    +despBanner
    +'<div class="fm-row">'
      +'<div><label class="fm-lbl">Valor total recebido (R$)</label>'
        +'<input class="fm-inp" type="number" id="vfbr-total" value="'+lanc.valor.toFixed(2)+'" min="0.01" step="0.01" oninput="vfCalcRepasse()"></div>'
      +'<div><label class="fm-lbl">Data de recebimento</label>'
        +'<input class="fm-inp" type="date" id="vfbr-data" value="'+hoje+'"></div>'
    +'</div>'
    // Sucumbência
    +'<div style="margin-top:12px;background:rgba(76,175,125,.06);border:1px solid rgba(76,175,125,.2);border-radius:8px;padding:12px 14px">'
      +'<div style="font-size:10px;font-weight:700;color:#4ade80;text-transform:uppercase;letter-spacing:.07em;margin-bottom:8px">Sucumbência (100% sua)</div>'
      +'<div class="fm-row">'
        +'<div><label class="fm-lbl">Valor da sucumbência (R$)</label>'
          +'<input class="fm-inp" type="number" id="vfbr-sucumb" value="0" min="0" step="0.01" oninput="vfCalcRepasse()" placeholder="0,00 se não houver"></div>'
        +'<div><label class="fm-lbl">Despesas a reembolsar (R$)</label>'
          +'<input class="fm-inp" type="number" id="vfbr-desp" value="'+totDespPend.toFixed(2)+'" min="0" step="0.01" oninput="vfCalcRepasse()" placeholder="0,00"></div>'
      +'</div>'
    +'</div>'
    // Honorários contratuais
    +'<div style="margin-top:10px;background:rgba(212,175,55,.06);border:1px solid rgba(212,175,55,.2);border-radius:8px;padding:12px 14px">'
      +'<div style="font-size:10px;font-weight:700;color:#D4AF37;text-transform:uppercase;letter-spacing:.07em;margin-bottom:8px">Honorários contratuais sobre o valor do cliente</div>'
      +'<div class="fm-row">'
        +'<div><label class="fm-lbl">Seu percentual (%)</label>'
          +'<input class="fm-inp" type="number" id="vfbr-perc" value="30" min="0" max="100" step="0.5" oninput="vfCalcRepasse()" style="max-width:100px"></div>'
        +'<div><label class="fm-lbl">Valor do cliente (calculado)</label>'
          +'<input class="fm-inp" id="vfbr-vcli" readonly style="color:var(--mu)"></div>'
        +'<div><label class="fm-lbl">Seus honorários (calculado)</label>'
          +'<input class="fm-inp" id="vfbr-hon" readonly style="color:#D4AF37;font-weight:700"></div>'
      +'</div>'
    +'</div>'
    // Resumo
    +'<div style="margin-top:10px;display:grid;grid-template-columns:1fr 1fr;gap:8px">'
      +'<div style="background:rgba(76,175,125,.08);border:1px solid rgba(76,175,125,.25);border-radius:7px;padding:10px 14px;text-align:center">'
        +'<div style="font-size:10px;color:#4ade80;font-weight:700;text-transform:uppercase;margin-bottom:4px">Total que fica no escritório</div>'
        +'<div id="vfbr-meu" style="font-size:18px;font-weight:800;color:#4ade80">—</div>'
      +'</div>'
      +'<div style="background:rgba(201,72,74,.08);border:1px solid rgba(201,72,74,.25);border-radius:7px;padding:10px 14px;text-align:center">'
        +'<div style="font-size:10px;color:#c9484a;font-weight:700;text-transform:uppercase;margin-bottom:4px">Repasse ao cliente (2 dias)</div>'
        +'<div id="vfbr-rep" style="font-size:18px;font-weight:800;color:#c9484a">—</div>'
      +'</div>'
    +'</div>'
    +'<div class="fm-row" style="margin-top:10px">'
      +'<div><label class="fm-lbl">Forma</label>'
        +'<select class="fm-inp" id="vfbr-forma">'
          +'<option>PIX</option><option>TED / Depósito</option>'
          +'<option>Alvará judicial</option><option>Dinheiro</option>'
        +'</select></div>'
      +'<div style="flex:2"><label class="fm-lbl">Observação</label>'
        +'<input class="fm-inp" id="vfbr-obs" placeholder="Referência, processo..."></div>'
    +'</div>',
  finGuard(function(){
    const total   = parseFloat(document.getElementById('vfbr-total')?.value)||0;
    const sucumb  = parseFloat(document.getElementById('vfbr-sucumb')?.value)||0;
    const desp    = parseFloat(document.getElementById('vfbr-desp')?.value)||0;
    const perc    = Math.max(0, Math.min(100, parseFloat(document.getElementById('vfbr-perc')?.value)||0));
    const dtBaixa = document.getElementById('vfbr-data')?.value||hoje;
    const forma   = document.getElementById('vfbr-forma')?.value||'';
    const obs     = document.getElementById('vfbr-obs')?.value.trim()||'';
    if(total <= 0){ showToast('Informe o valor'); return; }
    if(sucumb > total){ showToast('Sucumbência não pode ser maior que o valor recebido'); return; }
    if(perc <= 0 || perc > 100){ showToast('Percentual deve estar entre 0% e 100%'); return; }
    const vCli    = roundMoney(Math.max(0, total - sucumb));
    const hon     = roundMoney(vCli * perc / 100);
    const repasse = roundMoney(Math.max(0, vCli - hon - desp));
    const meu     = roundMoney(sucumb + hon + desp);

    // 1. Dar baixa no lançamento original pelo valor total
    _executarBaixa(id, total, dtBaixa, forma, obs, lanc);

    // 2. Se houver repasse, gerar lançamento de repasse (obrigação ao cliente)
    var localLancDirty = false;
    if(repasse > 0.01){
      const dtRep = new Date(dtBaixa);
      dtRep.setDate(dtRep.getDate() + 2);
      const dtRepStr = dtRep.toISOString().slice(0,10);
      var cid2 = cliObj ? cliObj.id : 0;
      localLanc.push({
        id: genId(),
        id_processo: cid2,
        tipo: 'repasse',
        direcao: 'pagar',
        desc: 'Repasse ao cliente' + (cliObj ? ' — ' + cliObj.cliente : ''),
        valor: roundMoney(repasse),
        data: dtBaixa,
        venc: dtRepStr,
        status: 'pendente',
        pago: false,
        cliente: cliObj ? cliObj.cliente : '',
        _repasse_acordo: true,
        obs: 'Gerado automaticamente ao receber com repasse'
      });
      localLancDirty = true;
    }

    // 3. Marcar despesas adiantadas como reembolsadas
    if(desp > 0 && cliObj){
      var restDesp = desp;
      (localLanc||[]).forEach(function(l){
        if(l.id_processo===cliObj.id && l.tipo==='despesa' && !l.reembolsado && l.status!=='pago' && restDesp > 0){
          l.reembolsado = true;
          l.dt_reembolso = dtBaixa;
          restDesp -= (l.valor||0);
        }
      });
      localLancDirty = true;
    }
    // Salvar localLanc uma única vez após todas as mutações
    if(localLancDirty) sbSet('co_localLanc', localLanc);

    // 4. Registrar andamento na pasta
    if(cliObj){
      if(!localMov[cliObj.id]) localMov[cliObj.id]=[];
      const dtRepStr2 = repasse>0.01 ? (function(){ const d=new Date(dtBaixa); d.setDate(d.getDate()+2); return d.toISOString().slice(0,10); })() : '';
      const resumo = '[Financeiro] Recebimento '+fBRL(total)
        +(sucumb?' · Sucumb. '+fBRL(sucumb):'')
        +(desp?' · Reimb. desp. '+fBRL(desp):'')
        +' · Honorários ('+perc+'%) '+fBRL(hon)
        +' · Escritório: '+fBRL(meu)
        +(repasse>0.01?' · Repasse cliente: '+fBRL(repasse)+' até '+dtRepStr2:'');
      localMov[cliObj.id].unshift({ data:dtBaixa, movimentacao:resumo, tipo_movimentacao:'Financeiro', origem:'baixa_repasse' });
      sbSet('co_localMov', localMov);
      _reRenderFinPasta(cliObj.id);
    }
    renderFinDash(); atualizarStats();
    fecharModal();
    vfRender();

    // 5. Recibo WhatsApp
    const dtRepStrWpp = repasse>0.01 ? (function(){ const d=new Date(dtBaixa); d.setDate(d.getDate()+2); return d.toISOString().slice(0,10).split('-').reverse().join('/'); })() : '';
    const _sep = '\u2501'.repeat(21);
    const _dadosBanc = getDadosBancarios(lanc.cliente);
    const _dadosBancStr = repasse > 0.01 ? formatarDadosBancarios(_dadosBanc) : '';

    // Recibo completo (para arquivo / andamento)
    const recibo = [
      '\u2705 *RECIBO DE RECEBIMENTO*',
      _sep,
      '*' + escapeHtml(lanc.desc||'\u2014') + '*',
      lanc.cliente ? 'Cliente: ' + escapeHtml(lanc.cliente) : '',
      'Data: ' + dtBaixa.split('-').reverse().join('/'),
      'Valor recebido: *' + fBRL(total) + '*',
      _sep,
      sucumb ? 'Sucumb\u00EAncia: ' + fBRL(sucumb) : '',
      desp   ? 'Reimb. despesas: ' + fBRL(desp) : '',
      'Honor\u00E1rios (' + perc + '%): ' + fBRL(hon),
      '*Total escrit\u00F3rio: ' + fBRL(meu) + '*',
      repasse > 0.01 ? _sep : '',
      repasse > 0.01 ? '*Repasse ao cliente: ' + fBRL(repasse) + '*' : '',
      repasse > 0.01 ? 'Prazo: at\u00E9 ' + dtRepStrWpp : '',
      _sep,
      '_Clarissa Oliveira Advogada_'
    ].filter(function(s){ return s !== ''; }).join('\n');

    // Mensagem para o financeiro (foco no pagamento)
    const msgFinanceiro = repasse > 0.01 ? [
      '*REPASSE — ' + escapeHtml(lanc.cliente||lanc.desc) + '*',
      'Data limite: ' + dtRepStrWpp,
      '',
      'Valor a transferir: *' + fBRL(repasse) + '*',
      '',
      _sep,
      '*Dados banc\u00E1rios*',
      _dadosBancStr || '_Cadastrar na ficha: Dados Sens\u00EDveis \u2192 Banco_',
      _sep,
      '_Escrit\u00F3rio Clarissa Oliveira_'
    ].join('\n') : null;

    // Mostrar modal com duas abas: Recibo + Mensagem para Financeiro
    const _reciboFinal = recibo;
    const _msgFin = msgFinanceiro;
    const _temDadosBanc = !!_dadosBanc;

    window._copiarTexto = function(txt){
      if(navigator.clipboard && navigator.clipboard.writeText){
        navigator.clipboard.writeText(txt).then(function(){ showToast('📲 Copiado!'); })
          .catch(function(){ var ta=document.createElement('textarea'); ta.value=txt; document.body.appendChild(ta); ta.select(); document.execCommand('copy'); document.body.removeChild(ta); showToast('Copiado!'); });
      }
    };

    setTimeout(function(){
      const hasFin = !!_msgFin;
      const modalHtml =
        '<div id="modal-tabs" style="display:flex;gap:6px;margin-bottom:12px">'
          +'<button id="tbtn-rec" onclick="_tabRec()" style="flex:1;padding:8px;border-radius:6px;border:1px solid var(--bd);background:var(--sf2);color:var(--tx);font-size:12px;font-weight:700;cursor:pointer">Recibo</button>'
          +(hasFin?'<button id="tbtn-fin" onclick="_tabFin()" style="flex:1;padding:8px;border-radius:6px;border:1px solid rgba(37,211,102,.4);background:rgba(37,211,102,.08);color:#25D366;font-size:12px;cursor:pointer">Mensagem Financeiro</button>':'')
        +'</div>'
        +'<div id="tab-rec">'
          +'<div style="background:var(--sf3);border:1px solid var(--bd);border-radius:8px;padding:14px;font-family:monospace;font-size:11px;line-height:1.8;white-space:pre-wrap;color:var(--tx);max-height:280px;overflow-y:auto">'+escapeHtml(_reciboFinal)+'</div>'
          +'<button onclick="window._cpRec()" style="margin-top:10px;width:100%;padding:10px;border-radius:6px;border:none;background:#25D366;color:#fff;font-size:13px;font-weight:600;cursor:pointer">Copiar recibo</button>'
        +'</div>'
        +(hasFin
          ?'<div id="tab-fin" style="display:none">'
            +(!_temDadosBanc?'<div style="background:rgba(245,158,11,.1);border:1px solid rgba(245,158,11,.3);border-radius:6px;padding:8px 12px;margin-bottom:8px;font-size:11px;color:#f59e0b">Dados bancarios nao cadastrados. Acesse a ficha do processo em Dados Sensiveis para adicionar.</div>':'')
            +'<div style="background:var(--sf3);border:1px solid var(--bd);border-radius:8px;padding:14px;font-family:monospace;font-size:11px;line-height:1.8;white-space:pre-wrap;color:var(--tx);max-height:280px;overflow-y:auto">'+escapeHtml(_msgFin||'')+'</div>'
            +'<button onclick="window._cpFin()" style="margin-top:10px;width:100%;padding:10px;border-radius:6px;border:none;background:#25D366;color:#fff;font-size:13px;font-weight:600;cursor:pointer">Copiar e enviar ao financeiro</button>'
          +'</div>'
          :'')
      window._tabRec = function(){ var r=document.getElementById('tab-rec'); var f=document.getElementById('tab-fin'); var b1=document.getElementById('tbtn-rec'); var b2=document.getElementById('tbtn-fin'); if(r) r.style.display=''; if(f) f.style.display='none'; if(b1) b1.style.fontWeight='700'; if(b2) b2.style.fontWeight='400'; };
      window._tabFin = function(){ var r=document.getElementById('tab-rec'); var f=document.getElementById('tab-fin'); var b1=document.getElementById('tbtn-rec'); var b2=document.getElementById('tbtn-fin'); if(r) r.style.display='none'; if(f) f.style.display=''; if(b1) b1.style.fontWeight='400'; if(b2) b2.style.fontWeight='700'; };
      window._cpRec = function(){ _copiarTexto(_reciboFinal); };
      window._cpFin = function(){ _copiarTexto(_msgFin||''); };
      abrirModal('✅ Recebimento Confirmado', modalHtml, null, 'Fechar');
    }, 500);

    audit('baixa','Recebimento com repasse: '+lanc.desc+' — '+fBRL(total),'lancamento');
  }), '✅ Confirmar e gerar repasse');
}

function vfCalcRepasse(){
  const total  = parseFloat(document.getElementById('vfbr-total')?.value)||0;
  const sucumb = parseFloat(document.getElementById('vfbr-sucumb')?.value)||0;
  const desp   = parseFloat(document.getElementById('vfbr-desp')?.value)||0;
  const perc   = Math.max(0, Math.min(100, parseFloat(document.getElementById('vfbr-perc')?.value)||0));
  const vCli   = roundMoney(Math.max(0, total - sucumb));
  const hon    = roundMoney(vCli * perc / 100);
  const rep    = roundMoney(Math.max(0, vCli - hon - desp));
  const meu    = roundMoney(sucumb + hon + desp);
  const fmt    = function(v){ return 'R$ '+(isFinite(v)?v:0).toLocaleString('pt-BR',{minimumFractionDigits:2,maximumFractionDigits:2}); };
  var e1=document.getElementById('vfbr-vcli'); if(e1) e1.value=fmt(vCli);
  var e2=document.getElementById('vfbr-hon');  if(e2) e2.value=fmt(hon);
  var e3=document.getElementById('vfbr-meu');  if(e3) e3.textContent=fmt(meu);
  var e4=document.getElementById('vfbr-rep');  if(e4) e4.textContent=fmt(rep);
}

// Executar a baixa real em qualquer tipo de lançamento
function _executarBaixa(id, valorBaixa, dtBaixa, forma, obs, lancRef){
  valorBaixa = roundMoney(valorBaixa);
  if(!isFinite(valorBaixa) || valorBaixa <= 0){ showToast('Valor de baixa inválido'); return; }
  function _atualizarObj(obj){
    var valOrig = parseFloat(obj.valor)||0;
    if(valorBaixa > valOrig * 1.05 && valOrig > 0){
      showToast('⚠ Valor de baixa ('+fBRL(valorBaixa)+') excede o original ('+fBRL(valOrig)+') em mais de 5%');
    }
    return {...obj, status:'pago', pago:true, dt_baixa:dtBaixa,
      valor_baixa:valorBaixa, forma:forma||obj.forma||'',
      obs:obs?((obj.obs?obj.obs+' | ':'')+obs):(obj.obs||''),
      parcial: valorBaixa < valOrig};
  }
  if(id.startsWith('g')){
    const rawId=parseInt(id.slice(1));
    const i=finLancs.findIndex(function(l){return l.id===rawId;});
    if(i!==-1){ finLancs[i]=_atualizarObj(finLancs[i]); sbSet('co_fin',finLancs); }
  } else if(id.startsWith('l')){
    const rawId=id.slice(1);
    const i=(localLanc||[]).findIndex(function(l){return String(l.id)===rawId;});
    if(i!==-1){ localLanc[i]=_atualizarObj(localLanc[i]); sbSet('co_localLanc',localLanc);
      const cid=localLanc[i].id_processo; if(cid) _reRenderFinPasta(cid); }
  } else if(id.startsWith('p')){
    const rawNum=id.slice(1);
    const ex=(finLancs||[]).find(function(l){return String(l._projuris_id)===rawNum;});
    const reg={id:genId(),_projuris_id:rawNum,tipo:'receber',
      desc:lancRef?lancRef.desc:'',cliente:lancRef?lancRef.cliente:'',
      valor:valorBaixa,data:dtBaixa,dt_baixa:dtBaixa,forma:forma,
      status:'pago',pago:true,obs:obs||''};
    if(!ex) finLancs.push(reg);
    else { const fi=finLancs.indexOf(ex); finLancs[fi]={...finLancs[fi],...reg}; }
    sbSet('co_fin',finLancs);
    const c2=findClientByName(lancRef?lancRef.cliente:'');
    if(c2){if(!localMov[c2.id])localMov[c2.id]=[];localMov[c2.id].unshift({data:dtBaixa,movimentacao:'[Financeiro] '+fBRL(valorBaixa)+' via '+(forma||'—'),tipo_movimentacao:'Financeiro',origem:'baixa'});sbSet('co_localMov',localMov);_reRenderFinPasta(c2.id);}
  }
  marcarAlterado();
}


function vfEditarLocal(lid){
  // lid = 'l' + original id
  const rawId = String(lid).startsWith('l') ? lid.slice(1) : lid;
  const idx = (localLanc||[]).findIndex(function(l){ return String(l.id)===rawId; });
  if(idx===-1){ showToast('Lançamento não encontrado'); return; }
  const l = localLanc[idx];
  const hoje = new Date().toISOString().slice(0,10);
  abrirModal('✏️ Editar Lançamento',
    '<div class="fm-row"><div style="flex:2"><label class="fm-lbl">Descrição</label>'
      +'<input class="fm-inp" id="vel-desc" value="'+escapeHtml(l.desc||l.descricao||'')+'"></div>'
      +'<div><label class="fm-lbl">Valor (R$)</label>'
        +'<input class="fm-inp" type="number" id="vel-valor" value="'+(l.valor||0)+'" step="0.01"></div></div>'
    +'<div class="fm-row" style="margin-top:8px">'
      +'<div><label class="fm-lbl">Data</label>'
        +'<input class="fm-inp" type="date" id="vel-data" value="'+(l.data||hoje)+'"></div>'
      +'<div><label class="fm-lbl">Vencimento</label>'
        +'<input class="fm-inp" type="date" id="vel-venc" value="'+(l.venc||l.data||hoje)+'"></div>'
      +'<div><label class="fm-lbl">Status</label>'
        +'<select class="fm-inp" id="vel-status">'
          +'<option value="pendente"'+(l.status==='pendente'?' selected':'')+'>Pendente</option>'
          +'<option value="pago"'+(l.status==='pago'?' selected':'')+'>Pago</option>'
        +'</select></div></div>'
    +'<div style="margin-top:8px"><label class="fm-lbl">Observação</label>'
      +'<input class="fm-inp" id="vel-obs" value="'+escapeHtml(l.obs||'')+'"></div>',
  function(){
    const desc = document.getElementById('vel-desc')?.value.trim();
    const valor = parseFloat(document.getElementById('vel-valor')?.value)||0;
    const data = document.getElementById('vel-data')?.value||hoje;
    const venc = document.getElementById('vel-venc')?.value||data;
    const status = document.getElementById('vel-status')?.value||'pendente';
    const obs = document.getElementById('vel-obs')?.value.trim()||'';
    if(!desc||valor<=0){ showToast('Preencha descrição e valor'); return; }
    localLanc[idx] = { ...localLanc[idx], desc, valor, data, venc, status, pago:status==='pago', obs };
    sbSet('co_localLanc', localLanc);
    marcarAlterado(); fecharModal();
    // Sync pasta do cliente
    const cid = localLanc[idx].id_processo;
    if(cid) _reRenderFinPasta(cid);
    else {
      // Tentar achar por nome do cliente
      const cli = findClientByName(localLanc[idx].cliente);
      if(cli) _reRenderFinPasta(cli.id);
    }
    if(document.getElementById('vf')?.classList.contains('on')) vfRender();
    renderFinDash();
    showToast('Lançamento atualizado ✓');
    audit('edicao','Lançamento editado: '+desc+' — '+fBRL(valor),'lancamento');
  }, '💾 Salvar alterações');
}

function vfDelLocal(lid){
  const rawId = String(lid).startsWith('l') ? lid.slice(1) : lid;
  const l = (localLanc||[]).find(function(x){ return String(x.id)===rawId; });
  if(!l){ showToast('Não encontrado'); return; }
  abrirModal('🗑 Excluir lançamento',
    '<div style="padding:12px;background:var(--sf3);border-radius:8px;margin-bottom:10px">'
      +'<div style="font-size:13px;font-weight:600;color:var(--tx)">'+escapeHtml(l.desc||'—')+'</div>'
      +'<div style="font-size:16px;font-weight:800;color:#c9484a;margin-top:4px">'+fBRL(l.valor||0)+'</div>'
    +'</div>'
    +'<div style="font-size:12px;color:var(--mu)">Esta ação não pode ser desfeita.</div>',
  function(){
    const cid_del = l.id_processo;
    // Tombstone por ID — anti-zombificação via sync merge do Supabase
    _tombstoneAdd('co_localLanc', String(rawId));
    // Tombstone adicional: se o item foi migrado do Projuris, marcar para a migração não reinserir
    if(l._migrado_projuris){
      var _key = l._migrado_projuris+'|'+l.tipo;
      _projurisDeletados.add(_key);
      try{ lsSet('co_projuris_del', JSON.stringify(Array.from(_projurisDeletados))); }catch{}
      try{ sbSet('co_projuris_del', Array.from(_projurisDeletados)); }catch{}
    }
    localLanc = (localLanc||[]).filter(function(x){ return String(x.id)!==rawId; });
    sbSet('co_localLanc', localLanc);
    marcarAlterado(); fecharModal();
    if(cid_del) _reRenderFinPasta(cid_del);
    else {
      const cli_del = findClientByName(l.cliente);
      if(cli_del) _reRenderFinPasta(cli_del.id);
    }
    if(document.getElementById('vf')?.classList.contains('on')) vfRender();
    renderFinDash(); showToast('Lançamento excluído');
    audit('exclusao','Lançamento excluído: '+(l.desc||'—'),'lancamento');
  }, '🗑 Confirmar exclusão');
}

// ═══════════════════════════════════════════════════════
// FLUXO COMPLETO DE ALVARÁ — Clarissa Oliveira Advocacia
// ═══════════════════════════════════════════════════════

function abrirFluxoRepasse(cid, lid){
  const c = findClientById(cid);
  if(!c) return;
  const rep = (localLanc||[]).find(function(l){return Number(l.id)===Number(lid);});
  if(!rep){ showToast('Repasse não encontrado'); return; }

  const fmtV = function(v){ return 'R$ '+Math.abs(v||0).toLocaleString('pt-BR',{minimumFractionDigits:2,maximumFractionDigits:2}); };
  const ex = c.extra||{};
  const hoje = new Date().toISOString().slice(0,10);

  // Build data object compatible with abrirMensagemFinanceiro
  const d = {
    cliente: c.cliente,
    valRec: rep._alv_valor_total || (parseFloat(rep.valor)||0) + (parseFloat(rep._alv_hon)||0),
    hon:    parseFloat(rep._alv_hon) || 0,
    rep:    parseFloat(rep.valor) || 0,
    despVal: parseFloat(rep._alv_desp) || 0,
    percHon: rep._alv_perc_hon ? (parseFloat(rep._alv_perc_hon)||0)*100 : (c._hon_contrato?.perc||30),
    parcela: rep._alv_parcela || rep.parcela || '',
    dtRec:  rep.data || hoje,
    banco: ex.banco||'', ag: ex.ag||'',
    conta: ex.conta||'', tconta: ex.tconta||'',
    pix: ex.pix||'', cpf: ex.cpf||c.cpf||''
  };

  abrirModal('✓ Confirmar repasse — '+c.cliente,
    '<div style="background:rgba(201,72,74,.07);border:1px solid rgba(201,72,74,.25);border-radius:8px;padding:12px;margin-bottom:14px">'
      +'<div style="font-size:11px;font-weight:700;color:#c9484a;margin-bottom:4px">📤 Repasse ao cliente</div>'
      +'<div style="font-size:22px;font-weight:800;color:#c9484a">'+fmtV(rep.valor)+'</div>'
      +(d.parcela?'<div style="font-size:10px;color:var(--mu);margin-top:2px">Parcela '+d.parcela+'</div>':'')
    +'</div>'
    +'<div class="fm-row">'
      +'<div><label class="fm-lbl">Data do repasse</label>'
        +'<input class="fm-inp" type="date" id="rep2-data" value="'+hoje+'"></div>'
      +'<div><label class="fm-lbl">Forma</label>'
        +'<select class="fm-inp" id="rep2-forma"><option>PIX</option><option>TED</option><option>Depósito</option><option>Dinheiro</option></select></div>'
    +'</div>'
    +'<div style="margin-bottom:10px">'
      +'<label class="fm-lbl">Comprovante / observação</label>'
      +'<input class="fm-inp" id="rep2-obs" placeholder="Opcional — ex: comprovante recebido">'
    +'</div>',
  function(){
    var dtRep = document.getElementById('rep2-data')?.value||hoje;
    var forma = document.getElementById('rep2-forma')?.value||'PIX';
    var obs   = document.getElementById('rep2-obs')?.value||'';

    var i = localLanc.findIndex(function(l){return Number(l.id)===Number(lid);});
    if(i!==-1){
      localLanc[i] = Object.assign({},localLanc[i],{
        pago:true, status:'pago', dt_baixa:dtRep, forma:forma, obs:obs
      });
    }
    sbSet('co_localLanc', localLanc);
    marcarAlterado();
    fecharModal();
    renderFinResumo(cid);
    var el = document.getElementById('finunif-'+cid);
    if(el) el.innerHTML = renderFinUnificado(cid);
    vfRender(); renderFinDash();
    showToast('✓ Repasse registrado!');

    // Generate WPP prestação de contas
    setTimeout(function(){ abrirPrestacaoContas(cid, d, dtRep, forma); }, 350);
  }, '✓ Confirmar repasse feito');
}


function abrirFluxoAlvara(cid, lid){
  const c = findClientById(cid);
  if(!c) return;
  const lanc = (localLanc||[]).find(function(l){return l.id===lid;});
  if(!lanc) return;

  const ex = c.extra||{};
  const fmtV = function(v){ return 'R$ '+Math.abs(v||0).toLocaleString('pt-BR',{minimumFractionDigits:2,maximumFractionDigits:2}); };
  const honPerc = c._hon_contrato ? parseFloat(c._hon_contrato) : 30;

  // Despesas reembolsáveis pendentes desta pasta
  const despPendentes = (localLanc||[]).filter(function(l){
    return Number(l.id_processo)===Number(cid) && (l.tipo==='despesa'||l.tipo==='despesa_reimb') && !l.pago;
  });
  const totalDesp = despPendentes.reduce(function(s,l){return s+(parseFloat(l.valor)||0);},0);

  const despRows = despPendentes.length
    ? despPendentes.map(function(d){
        return '<div style="display:flex;justify-content:space-between;align-items:center;padding:5px 0;border-bottom:1px solid var(--bd)">'
          +'<span style="font-size:12px;color:var(--tx)">'+escapeHtml(d.desc||'—')+'</span>'
          +'<span style="font-size:12px;font-weight:700;color:#fb923c">'+fmtV(d.valor||0)+'</span>'
        +'</div>';
      }).join('')
    : '<div style="font-size:11px;color:var(--mu);font-style:italic">Nenhuma despesa cadastrada nesta pasta</div>';

  const valorEsperado = parseFloat(lanc.valor||0);

  abrirModal('⚖️ Confirmar recebimento — '+c.cliente,
    '<div style="padding:4px 0">'

    // Banner de aviso
    +'<div style="background:rgba(76,175,125,.08);border:1px solid rgba(76,175,125,.3);border-radius:8px;padding:10px 12px;margin-bottom:14px">'
      +'<div style="font-size:12px;font-weight:700;color:#4ade80;margin-bottom:3px">📥 Valor esperado neste processo</div>'
      +'<div style="font-size:22px;font-weight:800;color:#4ade80">'+fmtV(valorEsperado)+'</div>'
      +'<div style="font-size:10px;color:var(--mu);margin-top:2px">'+escapeHtml(lanc.desc||'—')+'</div>'
    +'</div>'

    // Valor real recebido
    +'<div class="fm-row">'
      +'<div style="flex:2"><label class="fm-lbl">Valor real recebido (R$) <span class="req">*</span></label>'
        +'<input class="fm-inp" type="number" id="alv-valor" value="'+valorEsperado+'" step="0.01" oninput="alvCalc()" placeholder="0,00"></div>'
      +'<div><label class="fm-lbl">Data do recebimento</label>'
        +'<input class="fm-inp" type="date" id="alv-data" value="'+new Date().toISOString().slice(0,10)+'"></div>'
    +'</div>'

    // Honorários
    +'<div class="fm-row">'
      +'<div><label class="fm-lbl">% Honorários contrato</label>'
        +'<input class="fm-inp" type="number" id="alv-hon-perc" value="'+honPerc+'" min="0" max="100" step="0.5" oninput="alvCalc()"></div>'
      +'<div><label class="fm-lbl">Esta parcela</label>'
        +'<input class="fm-inp" type="text" id="alv-parcela" value="'+escapeHtml(lanc.parcela||'1/1')+'" placeholder="Ex: 1/5"></div>'
      +'<div><label class="fm-lbl">Total de parcelas</label>'
        +'<input class="fm-inp" type="number" id="alv-total-parc" min="1" max="120" value="'+(lanc._total_parcelas||1)+'" placeholder="1"></div>'
    +'</div>'

    // Despesas reembolsáveis
    +'<div style="margin-bottom:12px">'
      +'<div style="font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.07em;color:var(--mu);margin-bottom:6px">Despesas reembolsáveis da pasta</div>'
      +'<div style="background:var(--sf3);border-radius:6px;padding:8px 10px;margin-bottom:6px">'+despRows+'</div>'
      +'<div class="fm-row" style="margin-bottom:0">'
        +'<div><label class="fm-lbl">Total reembolsos a descontar</label>'
          +'<input class="fm-inp" type="number" id="alv-desp" value="'+totalDesp+'" min="0" step="0.01" oninput="alvCalc()"></div>'
      +'</div>'
    +'</div>'

    // Calculadora automática — resultado
    +'<div id="alv-resultado" style="background:var(--sf3);border:1px solid var(--bd);border-radius:10px;padding:14px;margin-bottom:4px">'
      +'<div style="font-size:11px;color:var(--mu);margin-bottom:10px">Aguardando preenchimento...</div>'
    +'</div>'

    +'</div>',

  function(){
    // Salvar recebimento do alvará
    var valRec = parseFloat(document.getElementById('alv-valor')?.value||0);
    var dtRec  = document.getElementById('alv-data')?.value||new Date().toISOString().slice(0,10);
    var percHon = parseFloat(document.getElementById('alv-hon-perc')?.value||30)/100;
    var despVal = parseFloat(document.getElementById('alv-desp')?.value||0);
    var parcela = document.getElementById('alv-parcela')?.value||'1/1';
    var totalParc = parseInt(document.getElementById('alv-total-parc')?.value||1);
    // If parcela = "1/1" and totalParc > 1, update to "1/N"
    if(totalParc > 1 && (parcela==='1/1'||parcela==='Única'||parcela==='unica'))
      parcela = '1/'+totalParc;

    var hon  = roundMoney(valRec * percHon);
    var rep  = Math.max(0, roundMoney(valRec - hon - despVal));

    // Marca o lançamento original como recebido
    var i = localLanc.findIndex(function(l){return String(l.id)===String(lid);});
    if(i!==-1){
      localLanc[i] = Object.assign({}, localLanc[i], {
        pago: true, status: 'pago', dt_baixa: dtRec,
        valor_real: valRec, valor_hon: hon, valor_rep: rep,
        valor_desp: despVal
      });
    }

    // Cria lançamento de honorários no caixa do escritório
    var idHon = genId();
    localLanc.push({
      id: idHon, id_processo: cid,
      tipo: 'honorario', direcao: 'receber',
      desc: 'Honorários '+(percHon*100).toFixed(0)+'%'+(parcela?' — '+parcela:''),
      valor: hon, data: dtRec, venc: dtRec,
      pago: true, status: 'pago', dt_baixa: dtRec, forma: 'Alvará',
      cliente: c.cliente, natureza: 'honorario_escritorio'
    });

    // Cria obrigação de repasse ao cliente
    if(rep > 0.01){
      var dtRepasse = new Date(dtRec);
      dtRepasse.setDate(dtRepasse.getDate()+2);
      var dtRepasseStr = dtRepasse.toISOString().slice(0,10);
      var idRep = genId();
      localLanc.push({
        id: idRep, id_processo: cid,
        tipo: 'repasse', direcao: 'pagar',
        desc: 'Repasse ao cliente'+(parcela?' — '+parcela:''),
        valor: rep, data: dtRepasseStr, venc: dtRepasseStr,
        pago: false, status: 'pendente',
        cliente: c.cliente, natureza: 'valor_cliente',
        _repasse_alvara: true, _alv_valor_total: valRec,
        _alv_hon: hon, _alv_perc_hon: percHon, _alv_desp: despVal,
        _alv_parcela: parcela
      });
    }

    sbSet('co_localLanc', localLanc);
    marcarAlterado();
    fecharModal();
    renderFicha(AC);
    vfRender();
    renderFinDash();
    showToast('✓ Recebimento registrado. '+( rep>0.01?'Repasse de '+fmtV(rep)+' criado.':''));

    // Abrir próximo passo: mensagem ao financeiro
    if(rep > 0.01){
      setTimeout(function(){
        abrirMensagemFinanceiro(cid, {
          cliente: c.cliente, valRec: valRec, hon: hon,
          rep: rep, despVal: despVal, percHon: percHon*100,
          parcela: parcela, dtRec: dtRec,
          banco: ex.banco||'', ag: ex.ag||'',
          conta: ex.conta||'', tconta: ex.tconta||'',
          pix: ex.pix||'', cpf: ex.cpf||c.cpf||''
        });
      }, 400);
    }
  }, '✓ Confirmar recebimento');

  // Calcular preview automaticamente
  setTimeout(function(){ alvCalc(); }, 100);
}

function alvCalc(){
  var val   = parseFloat(document.getElementById('alv-valor')?.value||0);
  var perc  = parseFloat(document.getElementById('alv-hon-perc')?.value||30)/100;
  var desp  = parseFloat(document.getElementById('alv-desp')?.value||0);
  var el    = document.getElementById('alv-resultado');
  if(!el) return;
  if(!val){ el.innerHTML='<div style="font-size:11px;color:var(--mu)">Informe o valor recebido.</div>'; return; }
  var hon = roundMoney(val*perc);
  var rep = Math.max(0, roundMoney(val-hon-desp));
  var fmtV = function(v){ return 'R$ '+Math.abs(v).toLocaleString('pt-BR',{minimumFractionDigits:2,maximumFractionDigits:2}); };
  el.innerHTML = ''
    +'<div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-bottom:10px">'
      +'<div style="background:rgba(76,175,125,.1);border-radius:8px;padding:10px 12px">'
        +'<div style="font-size:10px;font-weight:700;color:#4ade80;text-transform:uppercase;letter-spacing:.06em;margin-bottom:4px">✅ Fica no escritório</div>'
        +'<div style="font-size:20px;font-weight:800;color:#4ade80">'+fmtV(hon)+'</div>'
        +(perc>0?'<div style="font-size:10px;color:var(--mu)">'+(perc*100).toFixed(0)+'% honorários</div>':'')
      +'</div>'
      +'<div style="background:rgba(201,72,74,.08);border-radius:8px;padding:10px 12px">'
        +'<div style="font-size:10px;font-weight:700;color:#c9484a;text-transform:uppercase;letter-spacing:.06em;margin-bottom:4px">📤 Repasse ao cliente</div>'
        +'<div style="font-size:20px;font-weight:800;color:#c9484a">'+fmtV(rep)+'</div>'
        +(desp>0?'<div style="font-size:10px;color:var(--mu)">(-'+fmtV(desp)+' ressarcimento)</div>':'')
      +'</div>'
    +'</div>'
    +'<div style="display:flex;gap:8px;font-size:11px;color:var(--mu);justify-content:flex-end">'
      +'<span>Total: '+fmtV(val)+'</span>'
      +'<span>·</span>'
      +'<span>Hon: '+fmtV(hon)+'</span>'
      +(desp>0?'<span>·</span><span>Ressarc: '+fmtV(desp)+'</span>':'')
      +'<span>·</span>'
      +'<span>Cliente: '+fmtV(rep)+'</span>'
    +'</div>';
}

function abrirMensagemFinanceiro(cid, d){
  var fmtV = function(v){ return 'R$ '+Math.abs(v||0).toLocaleString('pt-BR',{minimumFractionDigits:2,maximumFractionDigits:2}); };
  var nomeP = d.cliente.split(' ')[0];
  var msg = 'Setor Financeiro\n'
    +'📤 Solicitação de Repasse\n\n'
    +'Favor efetuar PIX/TED ao(à) cliente '+d.cliente+' referente à liquidação processual'+(d.parcela?' (parcela '+d.parcela+')':'')+':\n\n'
    +'💰 Valor recebido no processo: '+fmtV(d.valRec)+'\n'
    +'📍 Desconto honorários ('+d.percHon.toFixed(0)+'%): -'+fmtV(d.hon)+'\n'
    +(d.despVal>0?'📍 Ressarcimento de despesas: -'+fmtV(d.despVal)+'\n':'')
    +'➡️ VALOR A TRANSFERIR: '+fmtV(d.rep)+'\n\n'
    +'Dados bancários:\n'
    +(d.pix?'Chave PIX: '+d.pix+'\n':'')
    +(d.banco?'Banco: '+d.banco+'\n':'')
    +(d.ag?'Agência: '+d.ag+'\n':'')
    +(d.conta?'Conta ('+( d.tconta||'CC')+'): '+d.conta+'\n':'')
    +(d.cpf?'CPF/CNPJ: '+d.cpf+'\n':'')
    +(!d.pix&&!d.banco?'⚠️ Dados bancários não cadastrados — consultar ficha do cliente\n':'')
    +'\nFavor retornar o comprovante.\nData limite: '+fDt(d.dtRep||new Date(new Date(d.dtRec).setDate(new Date(d.dtRec).getDate()+2)).toISOString().slice(0,10));

  abrirModal('📤 Mensagem ao Financeiro',
    '<div style="margin-bottom:8px;font-size:11px;color:var(--mu)">Copie e envie ao responsável financeiro:</div>'
    +'<textarea id="fin-msg-txt" rows="14" style="width:100%;font-size:12px;font-family:monospace;line-height:1.6;background:var(--sf2);border:1px solid var(--bd);border-radius:8px;padding:10px;color:var(--tx);resize:vertical">'+escapeHtml(msg)+'</textarea>',
  function(){
    var txt = document.getElementById('fin-msg-txt')?.value||msg;
    if(navigator.clipboard&&navigator.clipboard.writeText){
      navigator.clipboard.writeText(txt).then(function(){showToast('📲 Copiado!');}).catch(function(){mvCopiarFallback(txt);});
    } else { mvCopiarFallback(txt); }
    fecharModal();
    // Próximo passo: confirmar repasse
    setTimeout(function(){ abrirConfirmarRepasse(cid, d); }, 350);
  }, '📲 Copiar mensagem');
}

function abrirConfirmarRepasse(cid, d){
  var fmtV = function(v){ return 'R$ '+Math.abs(v||0).toLocaleString('pt-BR',{minimumFractionDigits:2,maximumFractionDigits:2}); };
  var hoje = new Date().toISOString().slice(0,10);
  abrirModal('✅ Confirmar repasse ao cliente',
    '<div style="background:rgba(201,72,74,.07);border:1px solid rgba(201,72,74,.3);border-radius:8px;padding:12px;margin-bottom:14px">'
      +'<div style="font-size:12px;font-weight:700;color:#c9484a;margin-bottom:4px">📤 Repasse pendente</div>'
      +'<div style="font-size:24px;font-weight:800;color:#c9484a">'+fmtV(d.rep)+'</div>'
      +'<div style="font-size:11px;color:var(--mu);margin-top:2px">'+escapeHtml(d.cliente)+(d.parcela?' · parcela '+d.parcela:'')+'</div>'
    +'</div>'
    +'<div class="fm-row">'
      +'<div><label class="fm-lbl">Data do repasse</label>'
        +'<input class="fm-inp" type="date" id="rep-data" value="'+hoje+'"></div>'
      +'<div><label class="fm-lbl">Forma</label>'
        +'<select class="fm-inp" id="rep-forma"><option>PIX</option><option>TED</option><option>Depósito</option></select></div>'
    +'</div>'
    +'<div style="margin-bottom:10px">'
      +'<label class="fm-lbl">Observação (ex: comprovante recebido, banco, etc.)</label>'
      +'<input class="fm-inp" id="rep-obs" placeholder="Opcional">'
    +'</div>',
  function(){
    var dtRep  = document.getElementById('rep-data')?.value||hoje;
    var forma  = document.getElementById('rep-forma')?.value||'PIX';
    var obs    = document.getElementById('rep-obs')?.value||'';

    // Marcar repasse como pago
    var rIdx = localLanc.findIndex(function(l){
      return Number(l.id_processo)===Number(cid) && l.tipo==='repasse' && !l.pago &&
             l._repasse_alvara && Math.abs((l.valor||0)-d.rep)<1;
    });
    if(rIdx!==-1){
      localLanc[rIdx] = Object.assign({},localLanc[rIdx],{
        pago:true,status:'pago',dt_baixa:dtRep,forma:forma,obs:obs,valor_baixa:d.rep
      });
    }
    sbSet('co_localLanc', localLanc);
    marcarAlterado();
    fecharModal();
    renderFicha(AC);
    vfRender();
    renderFinDash();
    showToast('✓ Repasse registrado!');

    // Gerar prestação de contas WPP
    setTimeout(function(){ abrirPrestacaoContas(cid, d, dtRep, forma); }, 350);
  }, '✓ Confirmar repasse feito');
}

function abrirPrestacaoContas(cid, d, dtRep, forma){
  var fmtV = function(v){ return 'R$ '+Math.abs(v||0).toLocaleString('pt-BR',{minimumFractionDigits:2,maximumFractionDigits:2}); };
  var nomeP = d.cliente.split(' ')[0];
  var parcTxt = d.parcela ? 'referente à '+d.parcela+' do acordo recebido em seu processo' : 'referente ao seu processo';
  var msg = 'Setor Financeiro\n'
    +'📍 Prestação de Contas\n\n'
    +'Olá '+nomeP+', segue a prestação de contas '+parcTxt+':\n\n'
    +'💰 Valores recebidos no processo: '+fmtV(d.valRec)+'\n'
    +'📍 Desconto contratual (honorários de '+d.percHon.toFixed(0)+'%): -'+fmtV(d.hon)+'\n'
    +(d.despVal>0?'📍 Ressarcimento de despesas adiantadas: -'+fmtV(d.despVal)+'\n':'')
    +'_➡️ Valor líquido repassado à cliente: '+fmtV(d.rep)+'\n\n'
    +'Caso precise de qualquer orientação, estamos à disposição.\n\n'
    +'Atenciosamente, Clarissa Oliveira Advocacia';

  abrirModal('📲 Prestação de Contas — WhatsApp',
    '<div style="margin-bottom:8px;font-size:11px;color:var(--mu)">Mensagem para enviar ao cliente:</div>'
    +'<textarea id="pc-msg-txt" rows="12" style="width:100%;font-size:12px;font-family:monospace;line-height:1.7;background:var(--sf2);border:1px solid var(--bd);border-radius:8px;padding:10px;color:var(--tx);resize:vertical">'+escapeHtml(msg)+'</textarea>',
  function(){
    var txt = document.getElementById('pc-msg-txt')?.value||msg;
    if(navigator.clipboard&&navigator.clipboard.writeText){
      navigator.clipboard.writeText(txt).then(function(){showToast('📲 Prestação de contas copiada!');}).catch(function(){mvCopiarFallback(txt);});
    } else { mvCopiarFallback(txt); }
    fecharModal();
    showToast('✅ Fluxo concluído!');
    // Offer recibo
    if(d.hon>0) setTimeout(function(){
      abrirModal('Gerar recibo?','<div style="font-size:13px;color:var(--mu)">Gerar recibo de honorários para arquivar?</div>',function(){fecharModal();gerarReciboHonorarios(cid,d);},'Gerar recibo');
    }, 400);
  }, '📲 Copiar para WhatsApp');
}

function gerarReciboHonorarios(cid, d){
  var fmtV = function(v){ return 'R$ '+Math.abs(v||0).toLocaleString('pt-BR',{minimumFractionDigits:2,maximumFractionDigits:2}); };
  var hoje = new Date().toLocaleDateString('pt-BR');
  var nl = '\n';
  var recibo = 'RECIBO DE HONORARIOS ADVOCATICIOS'+nl
    +'-----------------------------------'+nl+nl
    +'Escritorio: Clarissa Oliveira Advocacia'+nl
    +'Data: '+hoje+nl+nl
    +'Cliente: '+d.cliente+nl
    +(d.parcela?'Referente a: '+d.parcela+nl:'')
    +nl+'DECLARO ter recebido a quantia de:'+nl+nl
    +'  '+fmtV(d.hon)+nl+nl
    +'A titulo de honorarios advocaticios ('+(d.percHon||30).toFixed(0)+'% sobre '+fmtV(d.valRec)+').'+nl+nl
    +(d.despVal>0?'Ressarcimento de despesas: '+fmtV(d.despVal)+nl+nl:'')
    +'-----------------------------------'+nl
    +'Clarissa Oliveira Advocacia'+nl
    +'OAB/MG ________'+nl;

  abrirModal('🧾 Recibo de Honorários',
    '<div style="margin-bottom:8px;font-size:11px;color:var(--mu)">Copie e guarde ou envie ao cliente:</div>'
    +'<textarea id="rcb-txt" rows="14" style="width:100%;font-size:11px;font-family:monospace;line-height:1.7;background:var(--sf2);border:1px solid var(--bd);border-radius:8px;padding:10px;color:var(--tx);resize:vertical">'+escapeHtml(recibo)+'</textarea>',
  function(){
    var txt = document.getElementById('rcb-txt')?.value||recibo;
    if(navigator.clipboard&&navigator.clipboard.writeText){
      navigator.clipboard.writeText(txt).then(function(){showToast('🧾 Recibo copiado!');}).catch(function(){mvCopiarFallback(txt);});
    } else { mvCopiarFallback(txt); }
    fecharModal();
  }, '🧾 Copiar recibo');
}


function finDelGlobal(lid){
  const l = (finLancs||[]).find(function(x){ return String(x.id)===String(Number(lid)||lid); });
  abrirModal('Excluir lançamento?',
    '<div style="padding:10px 12px;background:var(--sf3);border-radius:8px;margin-bottom:10px">'
      +'<div style="font-size:13px;font-weight:600;color:var(--tx)">'+(l?escapeHtml(l.desc||'—'):'Lançamento')+'</div>'
      +(l?'<div style="font-size:15px;font-weight:800;color:#c9484a;margin-top:4px">'+fBRL(l.valor||0)+'</div>':'')
    +'</div>'
    +'<div style="font-size:12px;color:var(--mu)">Esta ação não pode ser desfeita.</div>',
    function(){
      var lidN = Number(lid)||lid;
      _tombstoneAdd('co_fin', String(lidN)); // anti-zombificação via sync merge
      finLancs = (finLancs||[]).filter(function(x){ return String(x.id) !== String(lidN); });
      sbSet('co_fin', finLancs);
      invalidarCacheVfTodos();
      marcarAlterado(); fecharModal(); vfRender();
      audit('exclusao','Lançamento global excluído: '+(l?l.desc:''),'lancamento');
      showToast('Lançamento excluído');
    }, '🗑 Confirmar exclusão'
  );
  setTimeout(()=>{ const btn=document.getElementById('modal-save'); if(btn){btn.style.background='var(--red)';btn.textContent='Confirmar exclusão';} },50);
}

function finIgnorarProjuris(pid, cid){
  abrirModal('Ignorar lançamento',
    '<div style="font-size:13px;color:var(--tx);margin-bottom:10px">Este lançamento do Projuris será <strong>ocultado</strong> da pasta. Ele não é excluído — pode ser reativado depois.</div>'
    +'<div style="font-size:12px;color:var(--mu)">Use esta opção para lançamentos incorretos, duplicados ou que não se aplicam a este processo.</div>',
  function(){
    _finIgnorados.add(pid);
    try{ lsSet('co_fin_ignorados', JSON.stringify([..._finIgnorados])); }catch{}
    fecharModal();
    if(cid) _reRenderFinPasta(cid);
    showToast('Lançamento ocultado. Para reativar, vá em Configurações.');
  }, 'Ocultar lançamento');
}

function despFixaPagar(gid){
  const rawId = gid.replace('g','');
  const l = (finLancs||[]).find(function(x){ return String(x.id)===rawId; });
  if(!l){ showToast('Lançamento não encontrado'); return; }
  const hoje = new Date().toISOString().slice(0,10);
  abrirModal('✓ Confirmar pagamento',
    '<div style="padding:10px;background:var(--sf3);border-radius:8px;margin-bottom:12px">'
      +'<div style="font-size:13px;font-weight:600">'+escapeHtml(l.desc||'—')+'</div>'
      +'<div style="font-size:12px;color:var(--mu);margin-top:3px">'+fBRL(l.valor||0)+'</div>'
    +'</div>'
    +'<div class="fm-row">'
      +'<div><label class="fm-lbl">Data do pagamento</label><input class="fm-inp" type="date" id="dpg-dt" value="'+hoje+'"></div>'
      +'<div><label class="fm-lbl">Forma</label><select class="fm-inp" id="dpg-forma"><option>PIX</option><option>TED / Depósito</option><option>Boleto</option><option>Dinheiro</option><option>Débito automático</option></select></div>'
    +'</div>',
  function(){
    var dt = document.getElementById('dpg-dt')?.value||hoje;
    var forma = document.getElementById('dpg-forma')?.value||'';
    var i = finLancs.findIndex(function(x){ return String(x.id)===rawId; });
    if(i!==-1){
      finLancs[i] = Object.assign({}, finLancs[i], {pago:true,status:'pago',dt_baixa:dt,forma:forma,valor_baixa:l.valor});
      sbSet('co_fin', finLancs);
      marcarAlterado(); fecharModal(); vfRender(); renderFinDash();
      showToast('✓ '+escapeHtml(l.desc||'')+'  marcada como paga');
    }
  }, '✓ Confirmar');
}

function vfEstornarGlobal(gid){
  const rawId = gid.replace('g','');
  const l = (finLancs||[]).find(function(x){ return String(x.id)===rawId; });
  if(!l){ showToast('Lançamento não encontrado'); return; }
  abrirModal('↩ Estornar pagamento',
    '<div style="font-size:13px;color:var(--tx);margin-bottom:8px">Estornar pagamento de <strong>'+escapeHtml(l.desc||'—')+'</strong>?</div>'
    +'<div style="font-size:12px;color:#f59e0b">O lançamento voltará para PENDENTE.</div>',
  function(){
    var i = finLancs.findIndex(function(x){ return String(x.id)===rawId; });
    if(i!==-1){
      finLancs[i] = Object.assign({}, finLancs[i], {pago:false,status:'pendente',dt_baixa:'',valor_baixa:0});
      sbSet('co_fin', finLancs);
      marcarAlterado(); fecharModal(); vfRender(); renderFinDash();
      showToast('↩ Estorno registrado');
    }
  }, '↩ Confirmar estorno');
}


function finEstornarLocal(cid, lid){
  var lidN = Number(lid);
  var l = (localLanc||[]).find(function(x){return Number(x.id)===lidN;});
  if(!l){ showToast('Lançamento não encontrado'); return; }

  var isRepasse = l.tipo==='repasse'||l._repasse_alvara||l._repasse_acordo;
  var aviso = isRepasse
    ? '⚠️ ATENÇÃO: Este repasse já foi pago ao cliente.\n\nEstornar pode criar inconsistência contábil. Faça isso apenas se o pagamento não foi realizado de fato.\n\nConfirmar estorno?'
    : 'Estornar este lançamento? Ele voltará para pendente.';

  abrirModal('Estornar lançamento',
    '<div style="font-size:13px;color:var(--mu);line-height:1.6">'+aviso.replace(/\n/g,'<br>')+'</div>',
    function(){
      var i = localLanc.findIndex(function(x){return Number(x.id)===lidN;});
      if(i!==-1){
        localLanc[i] = Object.assign({},localLanc[i],{pago:false,status:'pendente',dt_baixa:'',forma:'',valor_baixa:0});
        sbSet('co_localLanc', localLanc);
        marcarAlterado();
        var el = document.getElementById('finunif-'+cid);
        if(el) el.innerHTML = renderFinUnificado(cid);
        renderFinResumo(cid); vfRender(); renderFinDash();
        fecharModal(); showToast('↩ Estorno registrado');
      }
    }, 'Confirmar estorno'
  );
  setTimeout(function(){var b=document.getElementById('modal-save');if(b){b.style.background='var(--red)';b.textContent='Confirmar estorno';}},50);
}


function vfEstornarProjuris(lid){
  // Estornar uma baixa de item Projuris
  const rawNum = String(lid).startsWith('p') ? lid.slice(1) : lid;
  const orig = (FIN_XLSX||[]).find(function(l){ return String(l.id)===rawNum; });
  if(!orig){ showToast('Item Projuris não encontrado'); return; }
  abrirModal('↩ Estornar Recebimento',
    '<div style="padding:12px;background:var(--sf3);border-radius:8px;margin-bottom:10px">'
      +'<div style="font-size:13px;font-weight:600;color:var(--tx)">'+escapeHtml(orig.desc||'—')+'</div>'
      +'<div style="font-size:12px;color:var(--mu);margin-top:4px">Pasta '+orig.pasta+' · '+fBRL(orig.val||0)+'</div>'
    +'</div>'
    +'<div style="font-size:12px;color:#f59e0b">O lançamento voltará para status PENDENTE.</div>',
  function(){
    // Remover de finLancs
    finLancs = (finLancs||[]).filter(function(l){ return String(l._projuris_id)!==rawNum; });
    // Remover de localLanc
    localLanc = (localLanc||[]).filter(function(l){ return l.proj_ref!==lid; });
    // Restaurar status no FIN_XLSX in-memory
    const xlxIdx = (FIN_XLSX||[]).findIndex(function(l){ return String(l.id)===rawNum; });
    if(xlxIdx!==-1){ FIN_XLSX[xlxIdx].status='pendente'; FIN_XLSX[xlxIdx].dt_pago=''; }
    sbSet('co_fin', finLancs);
    sbSet('co_localLanc', localLanc);
    marcarAlterado(); fecharModal();
    if(document.getElementById('vf')?.classList.contains('on')) vfRender();
    renderFinDash();
    // Atualizar pasta do cliente
    const pasta_map2={}; CLIENTS.forEach(function(c){pasta_map2[String(c.pasta)]=c;});
    const cli2 = pasta_map2[String(orig.pasta)];
    if(cli2){ _reRenderFinPasta(cli2.id); }
    showToast('↩ Baixa estornada — item voltou para pendente');
    audit('estorno','Baixa estornada: '+(orig.desc||'—'),'lancamento');
  }, '↩ Confirmar estorno');
}


// ══════════════════════════════════════════════════════════════
// ══ MÓDULO: EXTRATO BANCÁRIO — Conciliação automática ══
// ══════════════════════════════════════════════════════════════

let _extratoLinhas = [];
let _finIgnorados = new Set();
let _vfMes = ''; // initialized in sbInit after HOJE is ready
var _navHistory = []; // navigation history stack
var _navCurrent = null;
try{ var _ig=JSON.parse(lsGet('co_fin_ignorados')||'[]'); _finIgnorados=new Set(_ig); }catch{} // linhas parseadas do CSV
let _saldoInicial = 0;
let _saldoInicialData = '';
try{ var _si=JSON.parse(lsGet('co_caixa_saldo')||'null'); if(_si){_saldoInicial=_si.valor||0;_saldoInicialData=_si.data||'';}}catch{}
let _extratoRevisar = {}; // classificação manual por índice

function abrirGuiaFinanceiro(){
  const guia = [
    {
      ico:'💵', tab:'Caixa Real', cor:'#D4AF37',
      titulo:'Caixa Real — o saldo real da sua conta',
      uso:'Mostra cada transação bancária com saldo corrido, fechando exatamente com o banco.',
      como:[
        '1. Clique em <strong>Definir saldo</strong> e informe o saldo da conta na data de início (ex: R$ 18.484,73 em 27/02/2026)',
        '2. Vá para <strong>🏦 Conciliação</strong> e importe o CSV do Inter',
        '3. Volte aqui — a tabela aparece completa com saldo linha a linha'
      ]
    },
    {
      ico:'📥', tab:'A Receber', cor:'#4ade80',
      titulo:'A Receber — honorários e parcelas pendentes',
      uso:'Lista todos os valores que o escritório ainda vai receber — do Projuris e lançamentos manuais.',
      como:[
        'Quando o cliente pagar: clique em <strong>✓ Receber</strong>',
        'Para <strong>honorários/consultoria</strong>: escolha "Recebimento simples" — 100% entra no caixa',
        'Para <strong>alvarás e acordos com repasse</strong>: escolha "Com repasse" — informe sucumbência e % de honorários. O sistema calcula o que fica no escritório e gera a obrigação de repasse automaticamente'
      ]
    },
    {
      ico:'⚠️', tab:'Inadimplência', cor:'#c9484a',
      titulo:'Inadimplência — recebimentos em atraso',
      uso:'Mostra tudo que estava para receber mas passou da data de vencimento sem ser pago.',
      como:[
        'Quatro faixas de atraso: 1-30 dias, 31-60, 61-90 e acima de 90',
        'Clique <strong>✓ Receber</strong> quando o cliente pagar',
        'Use para cobranças — você vê quem deve e há quanto tempo'
      ]
    },
    {
      ico:'📤', tab:'A Pagar', cor:'#f87676',
      titulo:'A Pagar — despesas e repasses pendentes',
      uso:'Todas as saídas pendentes: repasses ao cliente gerados automaticamente + despesas avulsas.',
      como:[
        '<strong>Repasses ao cliente</strong> são gerados automaticamente quando você dá baixa em um alvará/acordo com repasse',
        'Clique <strong>Baixar</strong> quando fizer o Pix ao cliente',
        'Para lançar uma despesa nova: clique <strong>+ Lançamento</strong> no topo'
      ]
    },
    {
      ico:'🏢', tab:'Desp. Fixas', cor:'#fb923c',
      titulo:'Despesas Fixas — custos mensais do escritório',
      uso:'Aluguel, contador, condomínio, internet e outros custos que se repetem todo mês.',
      como:[
        'Clique <strong>+ Lançamento</strong> → escolha a categoria (Aluguel, Contador…) → marque "lançar automaticamente todo mês"',
        'O sistema gera as parcelas automaticamente até a data que você definir',
        'Quando pagar: clique <strong>Baixar</strong> na parcela do mês'
      ]
    },
    {
      ico:'📈', tab:'DRE', cor:'#a78bfa',
      titulo:'DRE — resultado financeiro do mês',
      uso:'Demonstrativo de Resultado: receitas − despesas = lucro. Com margem percentual.',
      como:[
        'Selecione o mês no topo',
        'Veja receitas por categoria e despesas agrupadas',
        'O resultado acumulado do ano aparece no card da direita',
        'Clique <strong>⬇ PDF</strong> para exportar'
      ]
    },
    {
      ico:'🏦', tab:'Conciliação', cor:'#60a5fa',
      titulo:'Conciliação — conferência com o banco',
      uso:'Cruza o extrato bancário com os lançamentos do sistema. Use uma vez por mês.',
      como:[
        'No Inter: Extrato → Exportar → CSV',
        'Clique <strong>Selecionar arquivo CSV</strong> para importar',
        '<span style="color:#4ade80">✅ Conciliado</span> = já está registrado, nada a fazer',
        '<span style="color:#f59e0b">⚠ Baixa pendente</span> = existe mas sem baixa → clique "Confirmar baixa"',
        '<span style="color:#c9484a">❌ Não encontrado</span> = clique "+ Registrar" para classificar',
        'Transferências pessoais → clique <strong>Ignorar</strong>'
      ]
    }
  ];

  var html = '<div style="max-height:70vh;overflow-y:auto;padding:4px 2px">';
  var tabAtual = document.querySelector('.vf-tab.on')?.textContent?.trim()||'';

  guia.forEach(function(g){
    var isAtual = tabAtual.includes(g.tab) || tabAtual.includes(g.ico);
    html += '<div style="border:1px solid '+(isAtual?g.cor:'var(--bd)')+';border-radius:8px;padding:14px 16px;margin-bottom:10px;background:'+(isAtual?'rgba(212,175,55,.04)':'var(--sf2)')+'">'
      +'<div style="display:flex;align-items:center;gap:8px;margin-bottom:6px">'
        +'<span style="font-size:18px">'+g.ico+'</span>'
        +'<div>'
          +'<div style="font-size:13px;font-weight:700;color:'+g.cor+'">'+g.titulo+'</div>'
          +'<div style="font-size:11px;color:var(--mu)">'+g.uso+'</div>'
        +'</div>'
      +'</div>'
      +'<div style="font-size:11px;line-height:1.8;color:var(--tx);padding-left:4px">'
        +g.como.map(function(c){return '<div style="margin-bottom:2px">'+c+'</div>';}).join('')
      +'</div>'
    +'</div>';
  });

  html += '</div>';
  abrirModal('📖 Guia — Módulo Financeiro', html, null, 'Fechar');
}



function caixaDefinirSaldo(){
  const hoje = new Date().toISOString().slice(0,10);
  abrirModal('💵 Saldo de Abertura',
    '<div style="font-size:12px;color:var(--mu);margin-bottom:12px">Informe o saldo da conta bancária na data de início do controle.<br>Exemplo: saldo do dia 27/02/2026 = R$ 18.484,73</div>'
    +'<div class="fm-row">'
      +'<div><label class="fm-lbl">Valor do saldo (R$) *</label>'
        +'<input class="fm-inp" type="number" id="si-valor" value="'+(_saldoInicial||'').toString()+'" min="0" step="0.01" placeholder="0,00"></div>'
      +'<div><label class="fm-lbl">Data de referência</label>'
        +'<input class="fm-inp" type="date" id="si-data" value="'+(_saldoInicialData||hoje)+'"></div>'
    +'</div>',
  function(){
    var v = parseFloat(document.getElementById('si-valor')?.value)||0;
    var d = document.getElementById('si-data')?.value||hoje;
    _saldoInicial = v;
    _saldoInicialData = d;
    lsSet('co_caixa_saldo', JSON.stringify({valor:v, data:d}));
    fecharModal();
    vfRender();
    showToast('✅ Saldo de abertura definido: '+fBRL(v));
  }, '✅ Salvar saldo');
}


function vfExtrato(){
  const totalLinhas = _extratoLinhas.length;
  const conciliados = _extratoLinhas.filter(function(l){ return l._status==='conciliado'; }).length;
  const vincPend    = _extratoLinhas.filter(function(l){ return l._status==='pendente_vinculo'; }).length;
  const naoEncontr  = _extratoLinhas.filter(function(l){ return !l._status && l._status!=='ignorado'; }).length;
  const ignorados   = _extratoLinhas.filter(function(l){ return l._status==='ignorado'; }).length;
  const importados  = _extratoLinhas.filter(function(l){ return l._status==='importado'; }).length;

  let html = '<div style="padding:14px">';

  if(!totalLinhas){
    // Tela inicial
    html += '<div style="background:var(--sf2);border:2px dashed var(--bd);border-radius:12px;padding:36px;text-align:center;margin-bottom:16px">'
      +'<div style="font-size:36px;margin-bottom:12px">🏦</div>'
      +'<div style="font-size:15px;font-weight:700;color:var(--tx);margin-bottom:6px">Conciliação Bancária — Banco Inter</div>'
      +'<div style="font-size:12px;color:var(--mu);margin-bottom:6px;line-height:1.7">'
        +'Suba o extrato mensal do Inter para conferir se todos os recebimentos<br>'
        +'e pagamentos estão registrados corretamente no sistema.'
      +'</div>'
      +'<div style="font-size:11px;color:var(--mu);margin-bottom:20px;background:var(--sf3);border-radius:6px;padding:8px 14px;display:inline-block;text-align:left">'
        +'No Inter: <strong style="color:var(--tx)">Extrato → Exportar → CSV</strong>'
      +'</div><br>'
      +'<label style="display:inline-block;padding:10px 24px;background:rgba(96,165,250,.15);border:1px solid rgba(96,165,250,.4);border-radius:8px;color:#60a5fa;font-size:13px;font-weight:700;cursor:pointer">'
        +'📂 Selecionar arquivo CSV'
        +'<input type="file" accept=".csv,.txt" style="display:none" onchange="extratoCarregarCSV(this)">'
      +'</label>'
    +'</div>'
    +'<div style="background:var(--sf2);border:1px solid var(--bd);border-radius:8px;padding:14px 16px">'
      +'<div style="font-size:11px;font-weight:700;color:var(--mu);text-transform:uppercase;letter-spacing:.07em;margin-bottom:10px">Como funciona a conciliação</div>'
      +'<div style="display:grid;grid-template-columns:repeat(3,1fr);gap:10px">'
        +'<div style="text-align:center;padding:10px">'
          +'<div style="font-size:22px;margin-bottom:6px">✅</div>'
          +'<div style="font-size:11px;font-weight:700;color:#4ade80;margin-bottom:4px">Conciliado</div>'
          +'<div style="font-size:10px;color:var(--mu)">O sistema já tinha esse lançamento baixado com o valor e data correspondentes</div>'
        +'</div>'
        +'<div style="text-align:center;padding:10px">'
          +'<div style="font-size:22px;margin-bottom:6px">⚠️</div>'
          +'<div style="font-size:11px;font-weight:700;color:#f59e0b;margin-bottom:4px">Baixa pendente</div>'
          +'<div style="font-size:10px;color:var(--mu)">Existe o lançamento mas ainda não foi dado baixa. Clique para confirmar.</div>'
        +'</div>'
        +'<div style="text-align:center;padding:10px">'
          +'<div style="font-size:22px;margin-bottom:6px">❌</div>'
          +'<div style="font-size:11px;font-weight:700;color:#c9484a;margin-bottom:4px">Não encontrado</div>'
          +'<div style="font-size:10px;color:var(--mu)">Entrou/saiu dinheiro sem lançamento no sistema. Decida se registra ou ignora.</div>'
        +'</div>'
      +'</div>'
    +'</div>';

  } else {
    // Barra de status
    html += '<div style="display:grid;grid-template-columns:repeat(5,1fr);gap:8px;margin-bottom:14px">'
      +'<div style="background:var(--sf2);border:1px solid rgba(76,175,125,.3);border-radius:8px;padding:10px 12px">'
        +'<div style="font-size:9px;color:#4ade80;font-weight:700;text-transform:uppercase;margin-bottom:3px">✅ Conciliados</div>'
        +'<div style="font-size:20px;font-weight:800;color:#4ade80">'+conciliados+'</div>'
        +'<div style="font-size:9px;color:var(--mu)">de '+totalLinhas+' transações</div>'
      +'</div>'
      +'<div style="background:var(--sf2);border:1px solid rgba(245,158,11,.3);border-radius:8px;padding:10px 12px">'
        +'<div style="font-size:9px;color:#f59e0b;font-weight:700;text-transform:uppercase;margin-bottom:3px">⚠ Baixa pendente</div>'
        +'<div style="font-size:20px;font-weight:800;color:#f59e0b">'+vincPend+'</div>'
        +'<div style="font-size:9px;color:var(--mu)">lançados, sem baixa</div>'
      +'</div>'
      +'<div style="background:var(--sf2);border:1px solid rgba(201,72,74,.3);border-radius:8px;padding:10px 12px">'
        +'<div style="font-size:9px;color:#c9484a;font-weight:700;text-transform:uppercase;margin-bottom:3px">❌ Não encontrado</div>'
        +'<div style="font-size:20px;font-weight:800;color:#c9484a">'+naoEncontr+'</div>'
        +'<div style="font-size:9px;color:var(--mu)">sem lançamento</div>'
      +'</div>'
      +'<div style="background:var(--sf2);border:1px solid rgba(212,175,55,.3);border-radius:8px;padding:10px 12px">'
        +'<div style="font-size:9px;color:#D4AF37;font-weight:700;text-transform:uppercase;margin-bottom:3px">📥 Importados</div>'
        +'<div style="font-size:20px;font-weight:800;color:#D4AF37">'+importados+'</div>'
        +'<div style="font-size:9px;color:var(--mu)">criados agora</div>'
      +'</div>'
      +'<div style="background:var(--sf2);border:1px solid var(--bd);border-radius:8px;padding:10px 12px">'
        +'<div style="font-size:9px;color:var(--mu);font-weight:700;text-transform:uppercase;margin-bottom:3px">Ignorados</div>'
        +'<div style="font-size:20px;font-weight:800;color:var(--mu)">'+ignorados+'</div>'
      +'</div>'
    +'</div>';

    // Barra de ações
    html += '<div style="display:flex;gap:8px;margin-bottom:14px;align-items:center;flex-wrap:wrap">'
      +'<label style="padding:6px 14px;background:rgba(96,165,250,.1);border:1px solid rgba(96,165,250,.3);border-radius:6px;color:#60a5fa;font-size:11px;font-weight:700;cursor:pointer">'
        +'📂 Novo arquivo<input type="file" accept=".csv,.txt" style="display:none" onchange="extratoCarregarCSV(this)">'
      +'</label>'
      +(vincPend>0 ? '<button onclick="extratoBaixarTodosPendentes()" style="padding:6px 14px;background:rgba(245,158,11,.15);border:1px solid rgba(245,158,11,.3);border-radius:6px;color:#f59e0b;font-size:11px;font-weight:700;cursor:pointer">⚡ Confirmar todas as baixas pendentes ('+vincPend+')</button>' : '')
      +'<button onclick="_extratoLinhas=[];_extratoRevisar={};vfRender();" style="padding:6px 14px;background:transparent;border:1px solid var(--bd);border-radius:6px;color:var(--mu);font-size:11px;cursor:pointer">Limpar</button>'
      +'<span style="font-size:10px;color:var(--mu);margin-left:4px">Período: '+(_extratoLinhas.length?_extratoLinhas[_extratoLinhas.length-1].dataFmt+' a '+_extratoLinhas[0].dataFmt:'')+'</span>'
    +'</div>';

    // Tabela
    html += '<div style="background:var(--sf2);border:1px solid var(--bd);border-radius:8px;overflow:hidden">'
      +'<table style="width:100%;border-collapse:collapse">'
      +'<thead><tr style="background:var(--sf3)">'
      +'<th style="padding:8px 12px;text-align:left;font-size:10px;font-weight:700;text-transform:uppercase;color:var(--mu)">Data</th>'
      +'<th style="padding:8px 12px;text-align:left;font-size:10px;font-weight:700;text-transform:uppercase;color:var(--mu)">Descrição no extrato</th>'
      +'<th style="padding:8px 12px;text-align:right;font-size:10px;font-weight:700;text-transform:uppercase;color:var(--mu)">Valor</th>'
      +'<th style="padding:8px 12px;text-align:center;font-size:10px;font-weight:700;text-transform:uppercase;color:var(--mu)">Situação</th>'
      +'<th style="padding:8px 12px;text-align:left;font-size:10px;font-weight:700;text-transform:uppercase;color:var(--mu)">No sistema</th>'
      +'<th style="padding:8px 12px;text-align:center;font-size:10px;font-weight:700;text-transform:uppercase;color:var(--mu)">Ação</th>'
      +'</tr></thead><tbody>';

    _extratoLinhas.forEach(function(l, i){
      const isRec = l.valor > 0;
      const corVal = isRec ? '#4ade80' : '#f87676';
      const valFmt = (isRec?'+':'') + 'R$\u00a0' + Math.abs(l.valor).toLocaleString('pt-BR',{minimumFractionDigits:2});
      let situacao = '', noSistema = '', acao = '';

      if(l._status==='conciliado'){
        situacao = '<span style="font-size:10px;font-weight:700;padding:2px 8px;border-radius:10px;background:rgba(76,175,125,.15);color:#4ade80">✅ Conciliado</span>';
        noSistema = '<div style="font-size:11px;color:#4ade80;font-weight:500">'+escapeHtml((l._match_desc||'').slice(0,35))+'</div>'
          +(l._match_cliente?'<div style="font-size:10px;color:var(--mu)">'+escapeHtml(l._match_cliente)+'</div>':'');
        acao = '';
      } else if(l._status==='pendente_vinculo'){
        situacao = '<span style="font-size:10px;font-weight:700;padding:2px 8px;border-radius:10px;background:rgba(245,158,11,.15);color:#f59e0b">⚠ Baixa pendente</span>';
        noSistema = '<div style="font-size:11px;color:#f59e0b;font-weight:500">'+escapeHtml((l._match_desc||'').slice(0,35))+'</div>'
          +(l._match_cliente?'<div style="font-size:10px;color:var(--mu)">'+escapeHtml(l._match_cliente)+'</div>':'');
        acao = '<button onclick="extratoBaixarVinculo('+i+')" style="font-size:10px;font-weight:700;padding:4px 10px;border-radius:5px;background:rgba(245,158,11,.15);border:1px solid rgba(245,158,11,.35);color:#f59e0b;cursor:pointer">✓ Confirmar baixa</button>';
      } else if(l._status==='importado'){
        situacao = '<span style="font-size:10px;font-weight:700;padding:2px 8px;border-radius:10px;background:rgba(212,175,55,.12);color:#D4AF37">📥 Importado</span>';
        noSistema = '<div style="font-size:11px;color:#D4AF37">Lançamento criado</div>';
        acao = '<button onclick="extratoEstornar('+i+')" style="font-size:10px;padding:2px 7px;border-radius:4px;background:transparent;border:1px solid var(--bd);color:var(--mu);cursor:pointer">↩</button>';
      } else if(l._status==='ignorado'){
        situacao = '<span style="font-size:10px;padding:2px 8px;border-radius:10px;background:var(--sf3);color:var(--mu)">Ignorado</span>';
        noSistema = '';
        acao = '<button onclick="extratoReativar('+i+')" style="font-size:10px;padding:2px 7px;border-radius:4px;background:transparent;border:1px solid var(--bd);color:var(--mu);cursor:pointer">Reativar</button>';
      } else {
        // Não encontrado
        situacao = '<span style="font-size:10px;font-weight:700;padding:2px 8px;border-radius:10px;background:rgba(201,72,74,.12);color:#c9484a">❌ Não encontrado</span>';
        noSistema = '<div style="font-size:10px;color:var(--mu);font-style:italic">Sem lançamento correspondente</div>';
        acao = '<div style="display:flex;gap:4px">'
          +'<button onclick="extratoClassificar('+i+')" style="font-size:10px;font-weight:600;padding:3px 9px;border-radius:5px;background:rgba(96,165,250,.1);border:1px solid rgba(96,165,250,.3);color:#60a5fa;cursor:pointer">+ Registrar</button>'
          +'<button onclick="extratoIgnorar('+i+')" style="font-size:10px;padding:3px 7px;border-radius:5px;background:transparent;border:1px solid var(--bd);color:var(--mu);cursor:pointer">Ignorar</button>'
        +'</div>';
      }

      const rowBg = l._status==='pendente_vinculo'?'rgba(245,158,11,.04)':'';
      html += '<tr style="border-top:1px solid var(--bd);'+(rowBg?'background:'+rowBg:'')+'">'
        +'<td style="padding:8px 12px;font-size:11px;color:var(--mu);white-space:nowrap">'+l.dataFmt+'</td>'
        +'<td style="padding:8px 12px"><div style="font-size:12px;color:var(--tx);font-weight:500">'+escapeHtml(l.desc||'')+'</div><div style="font-size:10px;color:var(--mu)">'+escapeHtml(l.historico||'')+'</div></td>'
        +'<td style="padding:8px 12px;text-align:right;font-size:13px;font-weight:700;color:'+corVal+'">'+valFmt+'</td>'
        +'<td style="padding:8px 12px;text-align:center">'+situacao+'</td>'
        +'<td style="padding:8px 12px">'+noSistema+'</td>'
        +'<td style="padding:8px 12px;text-align:center">'+acao+'</td>'
      +'</tr>';
    });

    html += '</tbody></table></div>';

    // ── Lançamentos no sistema NÃO encontrados no extrato ──
    if(totalLinhas > 0){
      const todos = vfTodos();
      const pagosNoSistema = todos.filter(function(t){ return t.status==='pago'; });
      const extratoValores = _extratoLinhas.map(function(l){ return {v:Math.abs(l.valor), d:l.data}; });
      const naoNoExtrato = pagosNoSistema.filter(function(t){
        return !extratoValores.some(function(e){
          return Math.abs(e.v - t.valor) < 0.02 && Math.abs(new Date(e.d) - new Date(t.dt_baixa||t.data||'')) / 86400000 <= 5;
        });
      });
      if(naoNoExtrato.length){
        html += '<div style="margin-top:16px;background:var(--sf2);border:1px solid rgba(201,72,74,.3);border-radius:8px;overflow:hidden">'
          +'<div style="background:rgba(201,72,74,.08);padding:10px 14px;border-bottom:1px solid rgba(201,72,74,.2)">'
            +'<div style="font-size:11px;font-weight:700;color:#c9484a;text-transform:uppercase;letter-spacing:.07em">⚠ Baixados no sistema mas não localizados no extrato ('+naoNoExtrato.length+')</div>'
            +'<div style="font-size:10px;color:var(--mu);margin-top:2px">Verifique se foram lançados na data correta ou em outra conta</div>'
          +'</div>'
          +'<table style="width:100%;border-collapse:collapse">'
          +'<tbody>'
          +naoNoExtrato.slice(0,15).map(function(t){
            return '<tr style="border-top:1px solid var(--bd)">'
              +'<td style="padding:7px 12px;font-size:11px;color:var(--mu)">'+(t.dt_baixa||t.data||'—')+'</td>'
              +'<td style="padding:7px 12px;font-size:12px;color:var(--tx)">'+escapeHtml(t.desc||'—')+'</td>'
              +'<td style="padding:7px 12px;font-size:11px;color:var(--mu)">'+escapeHtml(t.cliente||'')+'</td>'
              +'<td style="padding:7px 12px;text-align:right;font-size:12px;font-weight:700;color:'+(t.tipo==='receber'?'#4ade80':'#f87676')+'">'+fBRL(t.valor)+'</td>'
            +'</tr>';
          }).join('')
          +'</tbody></table>'
        +'</div>';
      }
    }
  }

  html += '</div>';
  return html;
}


function extratoBaixarVinculo(i){
  // Confirmar baixa de item que está no sistema mas ainda pendente
  const l = _extratoLinhas[i];
  if(!l || !l._match_id) return;
  const vid = l._match_id;
  const forma = l.historico&&l.historico.toLowerCase().includes('pix') ? 'PIX'
    : l.historico&&l.historico.toLowerCase().includes('ted') ? 'TED / Depósito'
    : 'PIX';
  if(vid.startsWith('p')){
    const rawNum=vid.slice(1);
    const existInFin=(finLancs||[]).find(function(x){return String(x._projuris_id)===rawNum;});
    const reg={id:genId(),_projuris_id:rawNum,tipo:'receber',desc:l._match_desc,cliente:l._match_cliente,valor:Math.abs(l.valor),data:l.data,dt_baixa:l.data,forma:forma,status:'pago',pago:true,obs:'Conciliado extrato Inter '+l.dataFmt};
    if(!existInFin) finLancs.push(reg);
    else { var fi=finLancs.indexOf(existInFin); finLancs[fi]={...finLancs[fi],...reg}; }
    sbSet('co_fin',finLancs);
    const c2=findClientByName(l._match_cliente);
    if(c2){if(!localMov[c2.id])localMov[c2.id]=[];localMov[c2.id].unshift({data:l.data,movimentacao:'[Conciliação] Baixa confirmada via extrato: '+l._match_desc+' — '+fBRL(Math.abs(l.valor)),tipo_movimentacao:'Financeiro',origem:'conciliacao'});sbSet('co_localMov',localMov);_reRenderFinPasta(c2.id);}
  } else if(vid.startsWith('l')){
    const rawId=vid.slice(1);
    const li=(localLanc||[]).findIndex(function(x){return String(x.id)===rawId;});
    if(li!==-1){localLanc[li]={...localLanc[li],status:'pago',pago:true,dt_baixa:l.data,forma:forma,obs:'Conciliado extrato Inter '+l.dataFmt};sbSet('co_localLanc',localLanc);const cid=localLanc[li].id_processo;if(cid)_reRenderFinPasta(cid);}
  } else if(vid.startsWith('g')){
    const rawId=parseInt(vid.slice(1));
    const gi=finLancs.findIndex(function(x){return x.id===rawId;});
    if(gi!==-1){finLancs[gi]={...finLancs[gi],status:'pago',pago:true,dt_baixa:l.data,forma:forma};sbSet('co_fin',finLancs);}
  }
  _extratoLinhas[i]._status='conciliado';
  _extratoLinhas[i]._match_tipo='confirmado';
  invalidarCacheVfTodos();
  marcarAlterado(); vfRender(); renderFinDash();
  showToast('✅ Baixa confirmada: '+l._match_desc);
}

function extratoBaixarTodosPendentes(){
  const pendentes = _extratoLinhas.filter(function(l){ return l._status==='pendente_vinculo'; });
  if(!pendentes.length){ showToast('Nenhuma baixa pendente'); return; }
  abrirModal('⚡ Confirmar todas as baixas pendentes',
    '<div style="padding:12px;background:var(--sf3);border-radius:8px;margin-bottom:10px">'
      +'<div style="font-size:13px;font-weight:700;color:var(--tx);margin-bottom:4px">'+pendentes.length+' lançamentos serão baixados</div>'
      +'<div style="font-size:11px;color:var(--mu)">Todos os itens com "⚠ Baixa pendente" serão confirmados com a data e forma do extrato.</div>'
    +'</div>',
  function(){
    var count = 0;
    _extratoLinhas.forEach(function(l, i){
      if(l._status==='pendente_vinculo'){ extratoBaixarVinculo(i); count++; }
    });
    // extratoBaixarVinculo já invalida cache e re-renderiza a cada item.
    // Garantir invalidação final para o caso de haver interações entre itens.
    invalidarCacheVfTodos();
    fecharModal();
    vfRender(); renderFinDash(); atualizarStats();
    showToast('✅ '+count+' baixas confirmadas');
  }, '✅ Confirmar tudo');
}


function extratoCarregarCSV(input){
  const file = input.files[0];
  if(!file){ return; }
  const reader = new FileReader();
  reader.onload = function(e){
    const text = e.target.result;
    const linhas = text.split('\n');
    _extratoLinhas = [];
    _extratoRevisar = {};
    let headerFound = false;
    linhas.forEach(function(linha){
      // Detectar linha de header
      if(linha.includes('Data Lançamento') && linha.includes('Histórico')) { headerFound=true; return; }
      if(!headerFound) return;
      const cols = linha.split(';');
      if(cols.length < 4) return;
      const dataStr = (cols[0]||'').trim();
      if(!dataStr || !dataStr.match(/^\d{2}\/\d{2}\/\d{4}$/)) return;
      // Converter data DD/MM/YYYY → YYYY-MM-DD
      const partes = dataStr.split('/');
      const dataISO = partes[2]+'-'+partes[1]+'-'+partes[0];
      const historico = (cols[1]||'').trim();
      const desc = (cols[2]||'').trim();
      const valorStr = (cols[3]||'').trim().replace(/\./g,'').replace(',','.');
      const valor = parseFloat(valorStr)||0;
      if(valor===0) return;
      _extratoLinhas.push({
        data: dataISO, dataFmt: dataStr, historico, desc, valor,
        _status: null // null = pendente
      });
    });
    // Auto-conciliar: cruzar com lançamentos existentes
    extratoConciliarAutomatico();
    vfSetTab('extrato', document.querySelector('.vf-tab:last-child'));
    vfRender();
    showToast('Extrato carregado: '+_extratoLinhas.length+' transações · '+_extratoLinhas.filter(function(l){return l._status==='conciliado';}).length+' conciliadas automaticamente');
  };
  reader.readAsText(file, 'UTF-8');
}

function extratoConciliarAutomatico(){
  const todos = vfTodos();
  _extratoLinhas.forEach(function(linha){
    if(linha._status) return;
    const dataL = new Date(linha.data);
    const valorAbs = Math.abs(linha.valor);
    // Primeiro: buscar nos JÁ PAGOS (conciliação de conferência)
    const matchPago = todos.find(function(l){
      if(l.status!=='pago') return false;
      if(Math.abs(Math.abs(l.valor) - valorAbs) > 0.02) return false;
      if(linha.valor > 0 && l.tipo!=='receber') return false;
      if(linha.valor < 0 && l.tipo!=='pagar') return false;
      const dataRef = new Date(l.dt_baixa||l.data||'');
      const diffDias = Math.abs((dataL - dataRef) / 86400000);
      return diffDias <= 3;
    });
    if(matchPago){
      linha._status = 'conciliado';
      linha._match_id = matchPago.id;
      linha._match_desc = matchPago.desc;
      linha._match_cliente = matchPago.cliente;
      linha._match_tipo = 'pago';
      linha._cat = matchPago.desc + (matchPago.cliente?' — '+matchPago.cliente:'');
      return;
    }
    // Segundo: buscar nos pendentes (pode ter sido baixado errado)
    const matchPend = todos.find(function(l){
      if(l.status==='pago') return false;
      if(Math.abs(Math.abs(l.valor) - valorAbs) > 0.02) return false;
      if(linha.valor > 0 && l.tipo!=='receber') return false;
      if(linha.valor < 0 && l.tipo!=='pagar') return false;
      const dataRef = new Date(l.data||l.venc||'');
      const diffDias = Math.abs((dataL - dataRef) / 86400000);
      return diffDias <= 5;
    });
    if(matchPend){
      linha._status = 'pendente_vinculo'; // está no extrato mas ainda não baixado no sistema
      linha._match_id = matchPend.id;
      linha._match_desc = matchPend.desc;
      linha._match_cliente = matchPend.cliente;
      linha._match_tipo = 'pendente';
    }
    // Se não encontrou nada: fica null (não registrado)
  });
}

function extratoClassificar(i){
  const l = _extratoLinhas[i];
  if(!l) return;
  const isRec = l.valor > 0;
  const valorAbs = Math.abs(l.valor);
  const tipoDir = isRec ? 'receber' : 'pagar';

  // Todos os nomes: processos + contatos
  const todosNomes = [
    ...CLIENTS.map(function(c){ return {nome:c.cliente, pasta:c.pasta, id:c.id, src:'processo'}; }),
    ...(localContatos||[]).map(function(c){ return {nome:c.nome, pasta:'', id:c.id, src:'contato'}; })
  ];

  // Lançamentos pendentes do sistema (A Receber / A Pagar)
  const todos = vfTodos();
  const pendentes = todos.filter(function(t){
    return t.status!=='pago' && t.tipo===tipoDir;
  });

  const catOpts = Object.keys(isRec ? CAT_RECEITA : CAT_DESPESA)
    .map(function(k){ return '<option value="'+k+'">'+k+'</option>'; }).join('');

  // Sugestão de match por valor (sem filtro de data — deixar usuário escolher)
  const sugestoesOpts = pendentes
    .filter(function(t){ return Math.abs(t.valor - valorAbs) < 0.02; })
    .slice(0,10)
    .map(function(t){
      return '<option value="'+t.id+'">'+escapeHtml(t.desc.slice(0,40))+' — '+fBRL(t.valor)+' ('+t.cliente+')</option>';
    }).join('');

  abrirModal((isRec?'📥 Classificar Entrada':'📤 Classificar Saída'),
    '<div style="background:var(--sf3);border-radius:8px;padding:10px 14px;margin-bottom:12px;display:flex;justify-content:space-between;align-items:center">'
      +'<div>'
        +'<div style="font-size:12px;font-weight:600;color:var(--tx)">'+escapeHtml(l.desc||l.historico||'—')+'</div>'
        +'<div style="font-size:10px;color:var(--mu);margin-top:2px">'+l.dataFmt+' · '+l.historico+'</div>'
      +'</div>'
      +'<div style="font-size:20px;font-weight:800;color:'+(isRec?'#4ade80':'#f87676')+'">'+fBRL(valorAbs)+'</div>'
    +'</div>'

    // ── Vincular a lançamento existente ──
    +(sugestoesOpts
      ? '<div style="background:rgba(212,175,55,.08);border:1px solid rgba(212,175,55,.3);border-radius:8px;padding:10px 12px;margin-bottom:12px">'
          +'<div style="font-size:10px;font-weight:700;color:#D4AF37;text-transform:uppercase;letter-spacing:.07em;margin-bottom:6px">⚡ Lançamentos com valor correspondente</div>'
          +'<select class="fm-inp" id="ec-vincular" onchange="extratoAtualizarVinculo(this.value)">'
            +'<option value="">— Não vincular (criar novo) —</option>'
            +sugestoesOpts
          +'</select>'
        +'</div>'
      : '')

    // ── Campos de classificação ──
    +'<div id="ec-campos-novos">'
    +'<div class="fm-row">'
      +'<div style="flex:2"><label class="fm-lbl">Cliente / Processo *</label>'
        +'<input class="fm-inp" id="ec-cli-txt" list="ec-cli-list" placeholder="Digite nome do cliente..." autocomplete="off">'
        +'<datalist id="ec-cli-list">'
          +todosNomes.map(function(n){ return '<option value="'+escapeHtml(n.nome)+'">'+(n.pasta?'Pasta '+n.pasta:'Contato')+'</option>'; }).join('')
        +'</datalist>'
      +'</div>'
      +'<div><label class="fm-lbl">Categoria</label>'
        +'<select class="fm-inp" id="ec-cat">'+catOpts+'</select>'
      +'</div>'
    +'</div>'
    +'<div class="fm-row" style="margin-top:8px">'
      +'<div><label class="fm-lbl">Forma</label>'
        +'<select class="fm-inp" id="ec-forma">'
          +'<option>PIX</option><option>TED / Depósito</option><option>Boleto</option>'
          +'<option>Dinheiro</option><option>Cartão de Débito</option><option>Alvará judicial</option>'
        +'</select>'
      +'</div>'
      +'<div style="flex:2"><label class="fm-lbl">Descrição</label>'
        +'<input class="fm-inp" id="ec-desc" value="'+escapeHtml(l.desc||'')+'" placeholder="Descrição...">'
      +'</div>'
    +'</div>'
    +'</div>',

  function(){
    const vinculo = document.getElementById('ec-vincular')?.value||'';
    const cliTxt  = document.getElementById('ec-cli-txt')?.value.trim()||'';
    const cat     = document.getElementById('ec-cat')?.value||'';
    const forma   = document.getElementById('ec-forma')?.value||'PIX';
    const desc    = document.getElementById('ec-desc')?.value.trim()||l.desc||'';

    if(vinculo){
      // ── Vincular a lançamento existente ──
      const matchT = todos.find(function(t){ return t.id===vinculo; });
      if(!matchT){ showToast('Lançamento não encontrado'); return; }

      if(vinculo.startsWith('p')){
        const rawNum = vinculo.slice(1);
        const existInFin = (finLancs||[]).find(function(x){ return String(x._projuris_id)===rawNum; });
        const reg = { id:genId(), _projuris_id:rawNum, tipo:tipoDir,
          desc:matchT.desc, cliente:matchT.cliente, valor:valorAbs,
          data:l.data, dt_baixa:l.data, forma:forma, status:'pago', pago:true,
          obs:'Extrato Inter '+l.dataFmt };
        if(!existInFin) finLancs.push(reg);
        else { var fi=finLancs.indexOf(existInFin); finLancs[fi]={...finLancs[fi],...reg}; }
        sbSet('co_fin', finLancs);
        const c2=findClientByName(matchT.cliente);
        if(c2){
          if(!localMov[c2.id]) localMov[c2.id]=[];
          // De-dup: não criar [Financeiro] Recebimento via extrato se já existe [Recebimento] ou [Financeiro] equivalente
          var jaExiste = localMov[c2.id].some(function(m){
            if(m.data!==l.data) return false;
            var mov = String(m.movimentacao||'');
            return mov.indexOf(matchT.desc)!==-1 && mov.indexOf(fBRL(valorAbs))!==-1;
          });
          if(!jaExiste){
            localMov[c2.id].unshift({data:l.data,movimentacao:'[Financeiro] Recebimento via extrato: '+matchT.desc+' — '+fBRL(valorAbs)+' via '+forma,tipo_movimentacao:'Financeiro',origem:'extrato'});
            sbSet('co_localMov',localMov);
          }
          _reRenderFinPasta(c2.id);
        }
      } else if(vinculo.startsWith('l')){
        const rawId=vinculo.slice(1);
        const li=(localLanc||[]).findIndex(function(x){return String(x.id)===rawId;});
        if(li!==-1){ localLanc[li]={...localLanc[li],status:'pago',pago:true,dt_baixa:l.data,forma:forma,obs:'Extrato Inter '+l.dataFmt}; sbSet('co_localLanc',localLanc); const cid=localLanc[li].id_processo; if(cid) _reRenderFinPasta(cid); }
      } else if(vinculo.startsWith('g')){
        const rawId=parseInt(vinculo.slice(1));
        const gi=finLancs.findIndex(function(x){return x.id===rawId;});
        if(gi!==-1){ finLancs[gi]={...finLancs[gi],status:'pago',pago:true,dt_baixa:l.data,forma:forma}; sbSet('co_fin',finLancs); }
      }
      _extratoLinhas[i]._status='conciliado';
      _extratoLinhas[i]._match_id=vinculo;
      _extratoLinhas[i]._match_desc=matchT.desc;
      marcarAlterado(); fecharModal(); vfRender(); renderFinDash();
      showToast('✓ Vinculado: '+matchT.desc);

    } else {
      // ── Criar novo lançamento ──
      if(!cliTxt){ showToast('Informe o cliente ou origem'); return; }
      const novoLanc = {
        id:genId(), tipo:tipoDir, desc:desc, valor:valorAbs,
        data:l.data, cat:cat, forma:forma, cliente:cliTxt,
        status:'pago', pago:true, dt_baixa:l.data,
        obs:'Importado do extrato Inter · '+l.dataFmt,
        _extrato:true
      };
      finLancs.push(novoLanc);
      sbSet('co_fin', finLancs);
      const cliP=findClientByName(cliTxt);
      if(cliP){ if(!localMov[cliP.id]) localMov[cliP.id]=[]; localMov[cliP.id].unshift({data:l.data,movimentacao:'[Financeiro] Extrato: '+desc+' — '+fBRL(valorAbs)+' via '+forma,tipo_movimentacao:'Financeiro',origem:'extrato'}); sbSet('co_localMov',localMov); _reRenderFinPasta(cliP.id); }
      _extratoLinhas[i]._status='importado';
      _extratoLinhas[i]._lanc_id=novoLanc.id;
      marcarAlterado(); fecharModal(); vfRender(); renderFinDash();
      showToast('✓ Lançamento criado: '+cliTxt);
    }
  }, '✅ Confirmar e importar');
}

function extratoAtualizarVinculo(val){
  const campos = document.getElementById('ec-campos-novos');
  if(campos) campos.style.opacity = val ? '0.4' : '1';
}

function extratoIgnorar(i){
  _extratoLinhas[i]._status = 'ignorado';
  vfRender();
}
function extratoReativar(i){
  _extratoLinhas[i]._status = null;
  vfRender();
}
function extratoEstornar(i){
  const l = _extratoLinhas[i];
  if(l._lanc_id){
    _tombstoneAdd('co_fin', String(l._lanc_id));
    finLancs = (finLancs||[]).filter(function(x){ return x.id !== l._lanc_id; });
    sbSet('co_fin', finLancs);
  }
  _extratoLinhas[i]._status = null;
  _extratoLinhas[i]._lanc_id = null;
  vfRender();
  renderFinDash();
  showToast('↩ Importação estornada');
}
function extratoConfirmarTodos(){
  // Importar todos que têm _status='conciliado' mas ainda não marcados
  // (conciliados são apenas cruzamentos — não duplicam)
  const pendentes = _extratoLinhas.filter(function(l){ return !l._status; });
  if(pendentes.length > 0){
    showToast('Ainda há '+pendentes.length+' transações pendentes de classificação');
    return;
  }
  vfRender();
  showToast('✅ Todos os lançamentos foram processados');
}


function vfDelGlobal(id){
  abrirModal('Excluir lançamento','<div style="font-size:13px;color:var(--mu)">Excluir este lançamento permanentemente?</div>',function(){
    fecharModal();
    const rawId = id.startsWith('g') ? parseInt(id.slice(1)) : id;
    _tombstoneAdd('co_fin', String(rawId)); // anti-zombificação via sync merge
    finLancs = finLancs.filter(l=>l.id!==rawId);
    sbSet('co_fin', finLancs);
    marcarAlterado();
    vfRender();
    showToast('Lançamento excluído');
  }, 'Excluir');
}

// ── Formatador de data BR (DD/MM/AAAA) ──────────────────────
function fmtDataBR(d){
  if(!d) return '—';
  const s = String(d).replace('T',' ');
  const dt = s.slice(0,10);
  const hr = s.length > 10 ? s.slice(11,16) : '';
  const p  = dt.split('-');
  if(p.length < 3 || p[0].length < 4) return d;
  return p[2]+'/'+p[1]+'/'+p[0]+(hr&&hr!=='00:00'?' '+hr:'');
}


function vfExportarPDF(){
  const tab = _vfTab;
  const nomes = {
    resumo:'Resumo', recebimentos:'Recebimentos', receita:'Receita Escritório',
    valclientes:'Valores Clientes', repasses:'Repasses', despesas:'Despesas', extrato:'Extrato'
  };
  const titulo = 'Relatório Financeiro — ' + (nomes[tab]||tab);
  const conteudo = document.getElementById('vf-content')?.innerHTML||'';
  const win = window.open('','_blank');
  if(!win){ showToast('Permita popups para gerar PDF'); return; }
  win.document.write('<!DOCTYPE html><html><head>'
    +'<meta charset="utf-8">'
    +'<title>'+titulo+'</title>'
    +'<style>'
      +'body{font-family:Calibri,sans-serif;font-size:12px;color:#111;padding:24px}'
      +'h1{font-size:16px;margin-bottom:4px}'
      +'h2{font-size:13px;color:#510f10;margin:16px 0 6px}'
      +'.vf-cards{display:flex;gap:10px;margin-bottom:16px;flex-wrap:wrap}'
      +'.vf-card{border:1px solid #ccc;border-radius:6px;padding:10px 14px;min-width:120px}'
      +'.vf-card-lbl{font-size:9px;font-weight:700;text-transform:uppercase;color:#666;margin-bottom:2px}'
      +'.vf-card-val{font-size:18px;font-weight:700}'
      +'.vf-table{width:100%;border-collapse:collapse;font-size:11px}'
      +'.vf-table th{background:#510f10;color:#fff;padding:5px 8px;text-align:left;font-size:10px}'
      +'.vf-table td{padding:5px 8px;border-bottom:1px solid #eee}'
      +'.vf-table tr:nth-child(even) td{background:#f9f9f9}'
      +'.td-val{text-align:right}'
      +'.pos{color:#16a34a}.neg{color:#dc2626}'
      +'.vf-pill{font-size:9px;padding:1px 5px;border-radius:10px}'
      +'.vf-pill.pago{background:#dcfce7;color:#166534}'
      +'.vf-pill.pendente{background:#fef3c7;color:#92400e}'
      +'.vf-pill.vencido{background:#fee2e2;color:#991b1b}'
      +'.vf-sec{font-size:10px;font-weight:700;text-transform:uppercase;color:#510f10;border-bottom:1px solid #ccc;margin:14px 0 8px;padding-bottom:3px}'
      +'button,.vf-tab,.fin-new-btn,.vf-del-btn,.tp-btn,.vf-filtros,.vf-filtros-bar,.vf-acoes{display:none!important}'
      +'@media print{body{padding:0}}'
    +'</style></head><body>'
    +'<h1>'+titulo+'</h1>'
    +'<div style="font-size:11px;color:#666;margin-bottom:16px">CO Advocacia · Gerado em '+fmtDataBR(getTodayKey())+'</div>'
    +conteudo
    +'</body></html>');
  win.document.close();
  setTimeout(function(){ win.print(); }, 600);
}
function novoLancamentoDir(tipoOrEl){
  document.getElementById('novo-menu').style.display='none';
  const tipo = (typeof tipoOrEl === 'string') ? tipoOrEl : (tipoOrEl?.dataset?.tipo||'pagar');
  _renderModalLanc({tipo});
}

function novoLancamentoGlobal(){
  document.getElementById('novo-menu').style.display='none';
  _renderModalLanc({});
}

function _renderModalLanc(dados){
  const isEdit = !!dados.id;
  const dir = dados.tipo||'pagar';
  
  // Grupos de categorias
  const catGroups = (d) => {
    const cats = d==='pagar' ? CAT_DESPESA : CAT_RECEITA;
    const grupos = {};
    Object.entries(cats).forEach(([k,v])=>{
      const g = v.grupo||'Geral';
      if(!grupos[g]) grupos[g]=[];
      grupos[g].push(k);
    });
    return Object.entries(grupos).map(([g,items])=>
      `<optgroup label="${g}">${items.map(i=>`<option value="${i}" ${dados.cat===i?'selected':''}>${(CAT_DESPESA[i]||CAT_RECEITA[i])?.icone||''} ${i}</option>`).join('')}</optgroup>`
    ).join('');
  };

  abrirModal(isEdit?'✏️ Editar Lançamento':'💰 Novo Lançamento',`
  <!-- Direção -->
  <div style="display:flex;gap:6px;margin-bottom:14px">
    <button id="gln-dir-pag" onclick="glnDir('pagar')" 
      class="fm-chip${dir==='pagar'?' on':''}" style="flex:1;justify-content:center;padding:8px">
      📤 Despesa / Saída
    </button>
    <button id="gln-dir-rec" onclick="glnDir('receber')"
      class="fm-chip${dir==='receber'?' on':''}" style="flex:1;justify-content:center;padding:8px">
      📥 Receita / Entrada
    </button>
  </div>

  <div class="fm-row">
    <div style="flex:2">
      <label class="fm-lbl">Descrição *</label>
      <input class="fm-inp" id="gln-desc" value="${dados.desc||''}" placeholder="Ex: Aluguel março, Honorários...">
    </div>
    <div>
      <label class="fm-lbl">Data *</label>
      <input class="fm-inp" type="date" id="gln-data" value="${dados.data||new Date().toISOString().slice(0,10)}">
    </div>
  </div>

  <div class="fm-row" style="margin-top:8px">
    <div>
      <label class="fm-lbl">Categoria *</label>
      <select class="fm-inp" id="gln-cat" onchange="glnUpdateCat()">${catGroups(dir)}</select>
    </div>
    <div>
      <label class="fm-lbl">Valor (R$) *</label>
      <input class="fm-inp" type="number" id="gln-valor" value="${dados.valor||''}" min="0" step="0.01" placeholder="0,00" oninput="glnCalcAlvara()">
    </div>
  </div>

  <!-- Bloco colaborador — aparece quando cat = salário -->
  <div id="gln-bl-colab" style="display:none;margin-top:8px">
    <label class="fm-lbl">Colaborador</label>
    <select class="fm-inp" id="gln-colab">
      <option value="">— selecionar —</option>
      ${_colaboradores.map(c=>`<option value="${c.nome}" ${dados.colab===c.nome?'selected':''}>${c.nome}</option>`).join('')}
      <option value="__novo">＋ Cadastrar novo colaborador...</option>
    </select>
  </div>

  <!-- Bloco Alvará — aparece quando cat = Alvará judicial (repasse) -->
  <div id="gln-bl-alvara" style="display:none;margin-top:10px;background:rgba(107,20,22,.12);border:1px solid rgba(107,20,22,.35);border-radius:8px;padding:12px 14px">
    <div style="font-size:11px;font-weight:700;color:#D4AF37;text-transform:uppercase;letter-spacing:.07em;margin-bottom:10px">🏦 Divisão do Alvará</div>
    <div class="fm-row">
      <div>
        <label class="fm-lbl">Seu percentual (%)</label>
        <input class="fm-inp" type="number" id="gln-alv-perc" value="${dados.alv_perc||30}" min="1" max="100" step="0.5" oninput="glnCalcAlvara()" style="max-width:100px">
      </div>
      <div>
        <label class="fm-lbl">Seus honorários (calculado)</label>
        <input class="fm-inp" id="gln-alv-hon" readonly style="background:rgba(76,175,125,.08);color:#4ade80;font-weight:700">
      </div>
      <div>
        <label class="fm-lbl">Repasse ao cliente (calculado)</label>
        <input class="fm-inp" id="gln-alv-rep" readonly style="background:rgba(201,72,74,.08);color:#c9484a;font-weight:700">
      </div>
    </div>
    <div style="font-size:10px;color:var(--mu);margin-top:8px">
      O sistema vai gerar automaticamente a obrigação de repasse com vencimento em <strong style="color:var(--tx)">2 dias</strong> após a data de recebimento.
    </div>
  </div>

  <div class="fm-row" style="margin-top:8px">
    <div>
      <label class="fm-lbl">Forma de pagamento</label>
      <select class="fm-inp" id="gln-forma">
        <option value="">—</option>
        ${['PIX','TED / Depósito','Boleto','Dinheiro','Cheque','Cartão de Crédito','Cartão de Débito','Débito automático','Alvará judicial'].map(f=>`<option ${dados.forma===f?'selected':''}>${f}</option>`).join('')}
      </select>
    </div>
    <div>
      <label class="fm-lbl">Competência (mês ref.)</label>
      <input class="fm-inp" type="month" id="gln-comp" value="${dados.comp||new Date().toISOString().slice(0,7)}">
    </div>
    <div>
      <label class="fm-lbl">Status</label>
      <select class="fm-inp" id="gln-status">
        <option value="pendente" ${dados.status==='pendente'?'selected':''}>⏳ Pendente</option>
        <option value="pago" ${dados.status==='pago'||!dados.id?'':''} ${dados.status==='pago'?'selected':''}>✓ Pago / Recebido</option>
      </select>
    </div>
  </div>

  <!-- Recorrência -->
  <div style="margin-top:10px;padding:10px;background:var(--sf3);border-radius:7px" id="gln-bl-recorr">
    <label style="display:flex;align-items:center;gap:8px;cursor:pointer;font-size:12px;color:var(--mu)">
      <input type="checkbox" id="gln-recorr" ${dados.recorr?'checked':''} onchange="glnToggleRecorr()" style="accent-color:var(--vinho)">
      Lançar automaticamente todo mês (despesa fixa)
    </label>
    <div id="gln-recorr-det" style="display:${dados.recorr?'block':'none'};margin-top:8px">
      <div class="fm-row">
        <div>
          <label class="fm-lbl">Dia de vencimento</label>
          <input class="fm-inp" type="number" id="gln-dia" value="${dados.dia||5}" min="1" max="31" style="max-width:80px">
        </div>
        <div>
          <label class="fm-lbl">Gerar até</label>
          <select class="fm-inp" id="gln-ate">
            ${['2026-06','2026-12','2027-06','2027-12'].map(m=>`<option value="${m}" ${dados.ate===m?'selected':''}>${m.slice(5)==='06'?'Jun':'Dez'}/${m.slice(0,4)}</option>`).join('')}
          </select>
        </div>
      </div>
    </div>
  </div>

  <div style="margin-top:8px">
    <label class="fm-lbl">Observação</label>
    <input class="fm-inp" id="gln-obs" value="${dados.obs||''}" placeholder="Nº nota fiscal, referência, fornecedor...">
  </div>
  `,()=>{
    const desc  = document.getElementById('gln-desc')?.value.trim();
    const valor = parseFloat(document.getElementById('gln-valor')?.value)||0;
    const data  = document.getElementById('gln-data')?.value;
    const cat   = document.getElementById('gln-cat')?.value;
    if(!desc) { showToast('Informe a descrição'); return; }
    if(!valor){ showToast('Informe o valor'); return; }
    if(!data) { showToast('Informe a data'); return; }
    const dir2  = document.getElementById('gln-dir-pag')?.classList.contains('on') ? 'pagar' : 'receber';
    const recorr= document.getElementById('gln-recorr')?.checked;
    const base = {
      desc, valor, data, cat,
      tipo:   dir2,
      forma:  document.getElementById('gln-forma')?.value||'',
      comp:   document.getElementById('gln-comp')?.value||'',
      status: document.getElementById('gln-status')?.value||'pendente',
      obs:    document.getElementById('gln-obs')?.value.trim()||'',
      colab:  document.getElementById('gln-colab')?.value||'',
      pago:   document.getElementById('gln-status')?.value==='pago',
      recorr: recorr,
      dia:    parseInt(document.getElementById('gln-dia')?.value)||5,
      ate:    document.getElementById('gln-ate')?.value||'',
    };
    if(isEdit){
      const idx = finLancs.findIndex(l=>l.id===dados.id);
      if(idx>=0) finLancs[idx]={...finLancs[idx],...base};
    } else if(recorr){
      // Gerar parcelas mensais
      const ate = base.ate||'2026-12';
      const [ateAno,ateMes] = ate.split('-').map(Number);
      const [iniAno,iniMes] = data.slice(0,7).split('-').map(Number);
      let ano=iniAno, mes=iniMes;
      while(ano<ateAno||(ano===ateAno&&mes<=ateMes)){
        const dt = `${ano}-${String(mes).padStart(2,'0')}-${String(base.dia).padStart(2,'0')}`;
        finLancs.push({...base, id:genId(), data:dt, recorr_grupo: data});
        mes++; if(mes>12){mes=1;ano++;}
      }
    } else {
      finLancs.push({...base, id:genId()});
    }
    // ── Alvará: gerar obrigação de repasse automaticamente ──
    if(cat && cat.includes('Alvará judicial') && !isEdit){
      const perc = parseFloat(document.getElementById('gln-alv-perc')?.value)||30;
      const valorTotal = parseFloat(document.getElementById('gln-valor')?.value)||0;
      const valorRepasse = valorTotal * (1 - perc/100);
      if(valorRepasse > 0){
        // Data de repasse = data de recebimento + 2 dias
        const dtRec = document.getElementById('gln-data')?.value || data;
        const dtRep = new Date(dtRec);
        dtRep.setDate(dtRep.getDate() + 2);
        const dtRepStr = dtRep.toISOString().slice(0,10);
        const cliNomeAlv = document.getElementById('gln-desc')?.value.trim() || base.desc;
        const cliRep = cliNomeAlv || base.cliente || '';
        // Dedup: não criar outro repasse se já existe um com mesmo cliente/valor/data
        const jaExisteRep = (finLancs||[]).some(function(x){
          return (x._repasse_alvara||x._repasse_acordo||x.cat==='Repasse ao cliente')
            && (x.cliente||'')===cliRep
            && Math.abs((parseFloat(x.valor)||0) - valorRepasse) < 0.02
            && (x.data||'')===dtRepStr;
        });
        if(jaExisteRep){
          showToast('⚠ Repasse já existente para '+cliRep+' em '+dtRepStr+' — não duplicado');
        } else {
          const repasse = {
            id: genId(),
            tipo: 'repasse',
            direcao: 'pagar',
            cat: 'Repasse ao cliente',
            desc: 'Repasse alvará — ' + (cliNomeAlv||'cliente'),
            cliente: cliRep,
            valor: valorRepasse,
            data: dtRepStr,
            status: 'pendente',
            pago: false,
            obs: 'Gerado automaticamente — Alvará de ' + fBRL(valorTotal) + ' (' + perc + '% honorários)',
            _repasse_alvara: true,
            _alvara_id: Date.now()
          };
          finLancs.push(repasse);
          showToast('⚖️ Repasse de ' + fBRL(valorRepasse) + ' gerado para ' + dtRepStr);
        }
      }
    }
    // Salvar template de despesa fixa se recorrente
    if(recorr && !isEdit){
      _despFixas.push({...base, id:genId()});
      sbSet('co_despfixas', _despFixas);
    }
    // Cadastrar colaborador se novo
    const colabVal = document.getElementById('gln-colab')?.value;
    if(colabVal==='__novo'){
      // Reabre modal de colaborador após salvar (não bloqueia com prompt)
      setTimeout(()=>{ cadastrarColaboradorModal(); }, 200);
      return; // não salva ainda, aguarda colaborador ser cadastrado
    }
    sbSet('co_fin', finLancs);
    marcarAlterado(); fecharModal();
    // Sync pasta do cliente (finLancs global) — usar dados.cliente se editando
    const _cliNome = dados && dados.cliente ? dados.cliente : (base && base.cliente ? base.cliente : null);
    if(_cliNome && _cliNome !== '—' && _cliNome !== 'Escritório'){
      const cliGlob = findClientByName(_cliNome);
      if(cliGlob) _reRenderFinPasta(cliGlob.id);
    }
    vfRender(); renderFinDash();
    showToast(recorr?`Despesa fixa criada — ${finLancs.filter(l=>l.recorr_grupo===data).length} parcelas geradas ✓`:'Lançamento salvo ✓');
  }, isEdit?'💾 Salvar alterações':'💾 Salvar');
  setTimeout(()=>glnUpdateCat(),80);
}

function glnDir(dir){
  document.getElementById('gln-dir-rec')?.classList.toggle('on', dir==='receber');
  document.getElementById('gln-dir-pag')?.classList.toggle('on', dir==='pagar');
  const cat = document.getElementById('gln-cat');
  if(cat){
    const cats = dir==='pagar' ? CAT_DESPESA : CAT_RECEITA;
    const grupos = {};
    Object.entries(cats).forEach(([k,v])=>{const g=v.grupo||'Geral';if(!grupos[g])grupos[g]=[];grupos[g].push(k);});
    cat.innerHTML = Object.entries(grupos).map(([g,items])=>
      `<optgroup label="${g}">${items.map(i=>`<option>${(CAT_DESPESA[i]||CAT_RECEITA[i])?.icone||''} ${i}</option>`).join('')}</optgroup>`
    ).join('');
  }
  glnUpdateCat();
}

function glnUpdateCat(){
  const cat = document.getElementById('gln-cat')?.value||'';
  const blColab = document.getElementById('gln-bl-colab');
  if(blColab) blColab.style.display = cat.includes('Salário')||cat.includes('Pro-labore') ? 'block' : 'none';
  const blAlv = document.getElementById('gln-bl-alvara');
  if(blAlv) blAlv.style.display = cat.includes('Alvará judicial') ? 'block' : 'none';
  if(cat.includes('Alvará judicial')) glnCalcAlvara();
  // Auto-marcar recorrente se categoria fixa
  const info = CAT_DESPESA[cat];
  const chk = document.getElementById('gln-recorr');
  if(chk && info?.recorrente && !chk.checked){ chk.checked=true; glnToggleRecorr(); }
}

function glnCalcAlvara(){
  const valor = parseFloat(document.getElementById('gln-valor')?.value)||0;
  const perc  = parseFloat(document.getElementById('gln-alv-perc')?.value)||30;
  const hon   = valor * perc / 100;
  const rep   = valor - hon;
  const fmt   = v => 'R$ ' + v.toLocaleString('pt-BR',{minimumFractionDigits:2,maximumFractionDigits:2});
  const elH = document.getElementById('gln-alv-hon'); if(elH) elH.value = fmt(hon);
  const elR = document.getElementById('gln-alv-rep'); if(elR) elR.value = fmt(rep);
}

function glnToggleRecorr(){
  const det = document.getElementById('gln-recorr-det');
  const chk = document.getElementById('gln-recorr');
  if(det) det.style.display = chk?.checked ? 'block' : 'none';
}


function novoLancamento(){ novoLancamentoGlobal(); }

// Chamar ao entrar na view
function setFinTab(){ vfRender(); }
function renderFinGlobal(){ vfRender(); }

// ═══════════════════════════════════════════════════════════════
// ══ MÓDULO FINANCEIRO v2 — lançamento inteligente ══
// ═══════════════════════════════════════════════════════════════

// ── Estado do modal ──
let _fl = {};

function fmChip(id, val, lbl, cls=''){
  const on = (_fl[id]||[]).includes(val);
  return `<span class="fm-chip${cls?' '+cls:''}${on?' on':''}"
    onclick="fmToggle('${id}','${val}',this)">${lbl}</span>`;
}
function fmToggle(id, val, el){
  // Alguns grupos são single-select (formaPag, centro, direcao, intervalo)
  const single = ['tipo','formaPag','centro','direcao','intervalo'];
  if(single.includes(id)){
    _fl[id] = [val];
    // Para tipo, desmarcar todos os chips de tipo (em ambos containers)
    if(id==='tipo'){
      document.querySelectorAll('#fm-tipos-entrada .fm-chip, #fm-tipos-saida .fm-chip').forEach(function(c){c.classList.remove('on');});
    } else {
      var parent = el.closest('.fm-chips');
      if(parent) parent.querySelectorAll('.fm-chip').forEach(function(c){c.classList.remove('on');});
    }
    el.classList.add('on');
  } else {
    _fl[id] = _fl[id]||[];
    if(_fl[id].includes(val)){ _fl[id]=_fl[id].filter(x=>x!==val); el.classList.remove('on'); }
    else { _fl[id].push(val); el.classList.add('on'); }
  }
  fmAtualizar();
}
function fmVal(id){ return document.getElementById('fm-'+id)?.value||''; }
function fmNum(id){ return parseFloat(document.getElementById('fm-'+id)?.value)||0; }
function fmSet(id,v){ const el=document.getElementById('fm-'+id); if(el) el.value=v; }

function fmAtualizar(){
  const tipo = (_fl.tipo||[])[0]||'';
  const dir  = (_fl.direcao||[])[0]||'receber';

  // Mostrar/ocultar blocos
  const bl = id => { const e=document.getElementById('fm-bl-'+id); if(e) e.className='fm-bloco on'; };
  const hl = id => { const e=document.getElementById('fm-bl-'+id); if(e) e.className='fm-bloco'; };

  // Bloco valores — sempre visível
  bl('valores');

  // Split block — mostrar para entradas
  var splitEl = document.getElementById('fm-bl-split');
  if(splitEl) splitEl.style.display = dir==='receber' ? 'block' : 'none';

  fmPreviewParcelas();
}

function fmCalcAcordo(){
  const bruto   = fmNum('vbruto');
  const liquido = fmNum('vliquido');
  const sucumb  = fmNum('vsucumb');
  const desp    = fmNum('vdesp');
  const honPerc = fmNum('honperc');
  const honFix  = fmNum('honfixo');

  const el = document.getElementById('fm-calc');
  if(!el) return;
  if(!bruto && !liquido){ el.style.display='none'; return; }
  el.style.display='';

  const base    = liquido || bruto;
  const vCliente= base - sucumb;
  const honCalc = honFix || (vCliente * honPerc / 100);
  const repasse = Math.max(0, vCliente - honCalc - desp);
  const escritorio = sucumb + honCalc + desp;

  let rows = '';
  rows += `<div class="fm-calc-row"><span style="color:var(--mu)">Valor total do acordo</span><span>${fBRL(bruto)}</span></div>`;
  if(sucumb)
    rows += `<div class="fm-calc-row"><span style="color:#4ade80">+ Sucumbência (100% escritório)</span><span style="color:#4ade80">${fBRL(sucumb)}</span></div>`;
  if(honCalc)
    rows += `<div class="fm-calc-row"><span style="color:#4ade80">+ Honorários (${honFix?'fixo':honPerc+'%'} sobre valor cliente)</span><span style="color:#4ade80">${fBRL(honCalc)}</span></div>`;
  if(desp)
    rows += `<div class="fm-calc-row"><span style="color:#4ade80">+ Reimb. despesas</span><span style="color:#4ade80">${fBRL(desp)}</span></div>`;

  rows += `<div class="fm-calc-row" style="border-top:1px solid rgba(76,175,125,.3);margin-top:6px;padding-top:6px">
    <span style="font-weight:700;color:#4ade80">✅ FICA NO ESCRITÓRIO</span>
    <span style="font-weight:800;color:#4ade80;font-size:15px">${fBRL(escritorio)}</span>
  </div>`;
  rows += `<div class="fm-calc-row" style="margin-top:4px">
    <span style="color:#c9484a">📤 Repasse ao cliente</span>
    <span style="color:#c9484a;font-weight:700">${fBRL(repasse)}</span>
  </div>`;

  el.innerHTML = rows;
}

function fmPreviewParcelas(){
  const n     = parseInt(fmVal('nparc'))||1;
  const val   = fmNum('vparc');
  const venc1 = fmVal('venc1');
  const intv  = (_fl.intervalo||[])[0]||'mensal';
  const el    = document.getElementById('fm-parc-preview');
  if(!el||n<=1||!val||!venc1){ if(el) el.innerHTML=''; return; }

  const addTempo = (dt, i) => {
    const d = new Date(dt+'T12:00:00');
    if(intv==='mensal')    d.setMonth(d.getMonth()+i);
    else if(intv==='quinzenal') d.setDate(d.getDate()+15*i);
    else if(intv==='semanal')   d.setDate(d.getDate()+7*i);
    return d.toISOString().slice(0,10);
  };
  // fDt defined globally above

  const items = Array.from({length:n},(_,i)=>
    `<div class="fm-parc-item">
      <span class="fm-parc-n">${i+1}/${n}</span>
      <span class="fm-parc-venc">${fDt(addTempo(venc1,i))}</span>
      <span class="fm-parc-val">${fBRL(val)}</span>
    </div>`).join('');
  el.innerHTML = `<div class="fm-parc-list">${items}</div>`;
}

function abrirModalFin(cid, direcao_default){
  var c = findClientById(cid);
  if(!c) return;
  var honPerc = c._hon_contrato ? parseFloat(c._hon_contrato.perc||c._hon_contrato||30) : 30;
  _fl = { tipo:[], direcao:[direcao_default||'receber'], formaPag:[], centro:[], intervalo:['mensal'] };
  var hoje = new Date().toISOString().slice(0,10);
  var isEnt = (direcao_default||'receber') === 'receber';

  // Buscar despesas reembolsáveis pendentes deste cliente
  var despReemb = (localLanc||[]).filter(function(l){
    return Number(l.id_processo)===Number(cid) && (l.tipo==='despesa'||l.tipo==='despesa_reimb') && !l.reembolsado && !l.pago;
  });
  var totalReemb = despReemb.reduce(function(s,l){return s+(parseFloat(l.valor)||0);},0);
  var reembHtml = totalReemb > 0
    ? '<div style="font-size:10px;color:var(--mu);margin-top:4px">'
      +'Despesas adiantadas a ressarcir: <strong style="color:#f59e0b">R$ '+totalReemb.toLocaleString('pt-BR',{minimumFractionDigits:2})+'</strong>'
      +' (ser\u00e1 descontado do repasse)</div>'
    : '';

  abrirModal((isEnt ? '+ Entrada' : '- Sa\u00edda') + ' \u2014 ' + c.cliente,

    // === DIRE\u00c7\u00c3O ===
    '<div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-bottom:14px">'
      +'<button id="btn-dir-entrada" onclick="fmSetDir(\'receber\')" style="padding:10px 0;border-radius:7px;font-size:13px;font-weight:700;cursor:pointer;border:2px solid '+(isEnt?'rgba(76,175,125,.7)':'var(--bd)')+';background:'+(isEnt?'rgba(76,175,125,.12)':'var(--sf3)')+';color:'+(isEnt?'#4ade80':'var(--mu)')+'">+ Entrada</button>'
      +'<button id="btn-dir-saida" onclick="fmSetDir(\'pagar\')" style="padding:10px 0;border-radius:7px;font-size:13px;font-weight:700;cursor:pointer;border:2px solid '+(!isEnt?'rgba(248,118,118,.7)':'var(--bd)')+';background:'+(!isEnt?'rgba(248,118,118,.1)':'var(--sf3)')+';color:'+(!isEnt?'#f87676':'var(--mu)')+'">- Sa\u00edda</button>'
    +'</div>'

    // === TIPO ===
    +'<div style="margin-bottom:14px">'
      +'<div style="font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.07em;color:var(--mu);margin-bottom:8px">O que \u00e9?</div>'
      +'<div id="fm-tipos-entrada" style="display:'+(isEnt?'flex':'none')+';flex-wrap:wrap;gap:6px">'
        +fmChip('tipo','acordo','\u2696 Acordo / Condena\u00e7\u00e3o')
        +fmChip('tipo','honorario_direto','\ud83d\udcbc Honor\u00e1rio fixo/\u00eanito')
        +fmChip('tipo','alvara','\ud83c\udfdb Alvar\u00e1')
        +fmChip('tipo','sucumbencia','\ud83c\udfc6 Sucumb\u00eancia')
        +fmChip('tipo','assessoria','\ud83d\udcc5 Assessoria mensal')
        +fmChip('tipo','consulta','\ud83d\udcac Consulta')
        +fmChip('tipo','reembolso','\ud83d\udd04 Ressarcimento')
        +fmChip('tipo','outro','\ud83d\udccb Outro')
      +'</div>'
      +'<div id="fm-tipos-saida" style="display:'+(!isEnt?'flex':'none')+';flex-wrap:wrap;gap:6px">'
        +fmChip('tipo','despesa','\ud83e\uddfe Despesa reembols\u00e1vel')
        +fmChip('tipo','despint','\ud83d\udcb8 Despesa do escrit\u00f3rio')
        +fmChip('tipo','honorario_pag','\ud83d\udcbc Paguei parceiro')
        +fmChip('tipo','outro','\ud83d\udccb Outro')
      +'</div>'
    +'</div>'

    // === VALOR INTEGRAL + DESCRI\u00c7\u00c3O ===
    +'<div class="fm-row">'
      +'<div style="flex:2"><label class="fm-lbl">Valor integral (R$) *</label>'
        +'<input class="fm-inp" type="number" id="fm-valor" min="0" step="0.01" placeholder="0,00" style="font-size:16px;font-weight:700" oninput="fmAutoCalc('+cid+')"></div>'
      +'<div><label class="fm-lbl">Data *</label>'
        +'<input class="fm-inp" type="date" id="fm-data" value="'+hoje+'"></div>'
    +'</div>'
    +'<div style="margin-bottom:10px"><label class="fm-lbl">Descri\u00e7\u00e3o *</label>'
      +'<input class="fm-inp" id="fm-desc" placeholder="Ex: Acordo Trabalhista, Honor\u00e1rios mensais..."></div>'

    // === PARCELAS (sempre vis\u00edvel) ===
    +'<div style="border:1px solid var(--bd);border-radius:8px;padding:12px;margin-bottom:12px;background:var(--sf2)">'
      +'<div style="font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.06em;color:var(--mu);margin-bottom:8px">Pagamento</div>'
      +'<div class="fm-row">'
        +'<div><label class="fm-lbl">Intervalo</label>'
          +'<select class="fm-inp" id="fm-intervalo" onchange="fmPreviewParcelas()">'
            +'<option value="unico">\u00danica</option>'
            +'<option value="mensal" selected>Mensal</option>'
            +'<option value="quinzenal">Quinzenal</option>'
            +'<option value="semanal">Semanal</option>'
          +'</select></div>'
        +'<div><label class="fm-lbl">Ocorr\u00eancias</label>'
          +'<input class="fm-inp" type="number" id="fm-nparc" min="1" max="120" value="1" oninput="fmPreviewParcelas()"></div>'
        +'<div><label class="fm-lbl">Valor parcela (R$)</label>'
          +'<input class="fm-inp" type="number" id="fm-vparc" min="0" step="0.01" placeholder="auto" oninput="fmPreviewParcelas()"></div>'
        +'<div><label class="fm-lbl">1\u00aa parcela em</label>'
          +'<input class="fm-inp" type="date" id="fm-venc1" value="'+hoje+'" oninput="fmPreviewParcelas()"></div>'
      +'</div>'
      +'<div style="display:flex;align-items:center;gap:10px;margin-top:8px">'
        +'<label class="fm-lbl" style="margin:0">Status</label>'
        +'<select class="fm-inp" id="fm-status" style="width:auto">'
          +'<option value="pendente">\u23f3 Pendente</option>'
          +'<option value="pago">\u2713 J\u00e1 recebido / pago</option>'
        +'</select>'
      +'</div>'
      +'<div id="fm-parc-preview" style="margin-top:6px"></div>'
    +'</div>'

    // === SEPARA\u00c7\u00c3O HONOR\u00c1RIOS (aparece para entradas) ===
    +'<div id="fm-bl-split" style="display:'+(isEnt?'block':'none')+';border:1px solid rgba(76,175,125,.25);border-radius:8px;padding:14px;margin-bottom:12px;background:rgba(76,175,125,.04)">'
      +'<div style="font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.06em;color:#4ade80;margin-bottom:10px">\u2696 Separa\u00e7\u00e3o de valores</div>'
      +'<div class="fm-row">'
        +'<div><label class="fm-lbl">Seus honor\u00e1rios (%)</label>'
          +'<input class="fm-inp" type="number" id="fm-honperc" min="0" max="100" step="0.5" value="'+honPerc+'" oninput="fmAutoCalc('+cid+')"></div>'
        +'<div><label class="fm-lbl">Ou valor fixo (R$)</label>'
          +'<input class="fm-inp" type="number" id="fm-honfixo" min="0" step="0.01" placeholder="0,00" oninput="fmAutoCalc('+cid+')"></div>'
        +'<div><label class="fm-lbl">Sucumb\u00eancia (R$)</label>'
          +'<input class="fm-inp" type="number" id="fm-vsucumb" min="0" step="0.01" value="0" oninput="fmAutoCalc('+cid+')"></div>'
      +'</div>'
      +reembHtml
      // Parceiro
      +'<div style="margin-top:8px;border-top:1px solid var(--bd);padding-top:8px">'
        +'<label style="display:flex;align-items:center;gap:8px;font-size:11px;cursor:pointer;margin-bottom:6px">'
          +'<input type="checkbox" id="fm-tem-parceiro" onchange="fmToggleParceiro('+cid+')" style="cursor:pointer">'
          +'<span style="font-weight:600">\ud83e\udd1d Tem parceiro?</span>'
        +'</label>'
        +'<div id="fm-parceiro-fields" style="display:none" class="fm-row">'
          +'<div style="flex:2"><label class="fm-lbl">Nome</label>'
            +'<input class="fm-inp" id="fm-parceiro-nome" placeholder="Ex: Vivian..." oninput="fmAutoCalc('+cid+')"></div>'
          +'<div><label class="fm-lbl">% do parceiro</label>'
            +'<input class="fm-inp" type="number" id="fm-parceiro-perc" min="0" max="100" step="1" value="60" oninput="fmAutoCalc('+cid+')"></div>'
        +'</div>'
      +'</div>'
      // Preview calculado
      +'<div id="fm-split-preview" style="margin-top:10px"></div>'
    +'</div>'

    // === PLANO + CENTRO + CONTA ===
    +'<div class="fm-row" style="margin-bottom:12px">'
      +'<div><label class="fm-lbl">Plano de Contas</label>'
        +'<select class="fm-inp" id="fm-plano">'
          +'<option value="">\u2014</option>'
          +'<optgroup label="Receitas">'
            +'<option value="honorario_inicial">Honor\u00e1rio inicial</option>'
            +'<option value="honorario_exito">Honor\u00e1rio \u00eaxito</option>'
            +'<option value="acordo">Acordo / Condena\u00e7\u00e3o</option>'
            +'<option value="sucumbencia">Sucumb\u00eancia</option>'
            +'<option value="consulta">Consulta</option>'
            +'<option value="assessoria">Assessoria mensal</option>'
            +'<option value="reembolso_rec">Reembolso</option>'
          +'</optgroup>'
          +'<optgroup label="Despesas">'
            +'<option value="aluguel">Aluguel</option>'
            +'<option value="internet">Internet/Telefone</option>'
            +'<option value="energia">Energia/\u00c1gua</option>'
            +'<option value="salario">Sal\u00e1rio/Pr\u00f3-labore</option>'
            +'<option value="imposto">Impostos</option>'
            +'<option value="custas">Custas processuais</option>'
            +'<option value="software">Software</option>'
            +'<option value="honorario_parceiro">Honor\u00e1rio parceiro</option>'
            +'<option value="outro_desp">Outro</option>'
          +'</optgroup>'
        +'</select></div>'
      +'<div><label class="fm-lbl">Centro de Custo</label>'
        +'<select class="fm-inp" id="fm-centro">'
          +'<option value="">\u2014</option>'
          +'<option value="trabalhista">Trabalhista</option>'
          +'<option value="previdenciario">Previdenci\u00e1rio</option>'
          +'<option value="civel">C\u00edvel</option>'
          +'<option value="familia">Fam\u00edlia</option>'
          +'<option value="escritorio">Escrit\u00f3rio</option>'
        +'</select></div>'
      +'<div><label class="fm-lbl">Conta</label>'
        +'<select class="fm-inp" id="fm-conta">'
          +'<option value="">\u2014</option>'
          +'<option value="inter">Inter</option>'
          +'<option value="cef">CEF</option>'
          +'<option value="dinheiro">Dinheiro</option>'
          +'<option value="outra">Outra</option>'
        +'</select></div>'
    +'</div>'

    // === OBSERVA\u00c7\u00c3O ===
    +'<div style="margin-bottom:8px"><label class="fm-lbl">Observa\u00e7\u00e3o</label>'
      +'<textarea class="fm-inp" id="fm-obs" rows="2" placeholder="Detalhes..."></textarea></div>'

    +'<input type="hidden" id="fm-venc" value="'+hoje+'">'
    +'<input type="hidden" id="fm-vbruto" value="0">',

  function(){ fmSalvar(cid); }, '\ud83d\udcbe Salvar');

  // Auto-preencher centro de custo pela natureza do processo
  setTimeout(function(){
    var sel = document.getElementById('fm-centro');
    if(sel && c.natureza){
      var n = c.natureza.toLowerCase();
      if(n.includes('trabalh')) sel.value='trabalhista';
      else if(n.includes('previd')) sel.value='previdenciario';
      else if(n.includes('c\u00edv')||n.includes('civel')) sel.value='civel';
      else if(n.includes('fam\u00edl')||n.includes('familia')) sel.value='familia';
    }
  },50);
}

function fmSetDir(dir){
  _fl.direcao = [dir];
  var bE = document.getElementById('btn-dir-entrada');
  var bS = document.getElementById('btn-dir-saida');
  var tE = document.getElementById('fm-tipos-entrada');
  var tS = document.getElementById('fm-tipos-saida');
  if(bE){ bE.style.borderColor=dir==='receber'?'rgba(76,175,125,.7)':'var(--bd)'; bE.style.background=dir==='receber'?'rgba(76,175,125,.12)':'var(--sf3)'; bE.style.color=dir==='receber'?'#4ade80':'var(--mu)'; }
  if(bS){ bS.style.borderColor=dir==='pagar'?'rgba(248,118,118,.7)':'var(--bd)'; bS.style.background=dir==='pagar'?'rgba(248,118,118,.1)':'var(--sf3)'; bS.style.color=dir==='pagar'?'#f87676':'var(--mu)'; }
  if(tE) tE.style.display = dir==='receber'?'flex':'none';
  if(tS) tS.style.display = dir==='pagar'?'flex':'none';
  // Reset tipo chips
  document.querySelectorAll('.fm-chip').forEach(function(c){ if(c.dataset.group==='tipo') c.classList.remove('on'); });
  _fl.tipo = [];
  // Hide split box when switching to pagar
  var sb = document.getElementById('fm-split-box');
  if(sb && dir==='pagar') sb.style.display='none';
}

function fmAutoCalc(cid){
  var val    = parseFloat((document.getElementById('fm-valor')||{}).value||0);
  var honP   = parseFloat((document.getElementById('fm-honperc')||{}).value||30)/100;
  var honFix = parseFloat((document.getElementById('fm-honfixo')||{}).value||0);
  var sucumb = parseFloat((document.getElementById('fm-vsucumb')||{}).value||0);
  var prev   = document.getElementById('fm-split-preview');
  var splitBox = document.getElementById('fm-bl-split');
  var dir    = (_fl.direcao||[])[0]||'receber';

  // Mostrar bloco split só para entradas com valor
  if(splitBox) splitBox.style.display = (dir==='receber' && val>0) ? 'block' : 'none';
  if(dir!=='receber' || val<=0 || !prev) return;

  // Atualizar hidden vbruto
  var vbrEl = document.getElementById('fm-vbruto');
  if(vbrEl) vbrEl.value = val;

  var hon = honFix > 0 ? honFix : roundMoney(val * honP);
  var totalEsc = roundMoney(sucumb + hon);
  var rep = Math.max(0, roundMoney(val - totalEsc));
  var fV = function(v){ return 'R$ '+(isFinite(v)?Math.abs(v):0).toLocaleString('pt-BR',{minimumFractionDigits:2,maximumFractionDigits:2}); };

  // Parceiro
  var temParceiro = (document.getElementById('fm-tem-parceiro')||{}).checked;
  var parcPerc    = parseFloat((document.getElementById('fm-parceiro-perc')||{}).value||0)/100;
  var parcNome    = (document.getElementById('fm-parceiro-nome')||{}).value||'Parceiro';
  var parcVal     = temParceiro ? roundMoney(hon * parcPerc) : 0;
  var liquido     = hon - parcVal + sucumb;

  // Preview
  var html = '<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:6px">';
  html += '<div style="padding:8px;background:rgba(76,175,125,.1);border-radius:6px;text-align:center">'
    +'<div style="font-size:8px;font-weight:700;color:#4ade80;text-transform:uppercase;margin-bottom:2px">\u2705 Escrit\u00f3rio</div>'
    +'<div style="font-size:16px;font-weight:800;color:#4ade80">'+fV(liquido)+'</div></div>';
  if(temParceiro && parcVal > 0){
    html += '<div style="padding:8px;background:rgba(212,175,55,.08);border-radius:6px;text-align:center">'
      +'<div style="font-size:8px;font-weight:700;color:#D4AF37;text-transform:uppercase;margin-bottom:2px">'+escapeHtml(parcNome)+'</div>'
      +'<div style="font-size:16px;font-weight:800;color:#D4AF37">'+fV(parcVal)+'</div></div>';
  }
  if(rep > 0){
    html += '<div style="padding:8px;background:rgba(201,72,74,.06);border-radius:6px;text-align:center">'
      +'<div style="font-size:8px;font-weight:700;color:#c9484a;text-transform:uppercase;margin-bottom:2px">\ud83d\udce4 Repasse cliente</div>'
      +'<div style="font-size:16px;font-weight:800;color:#c9484a">'+fV(rep)+'</div></div>';
  }
  html += '</div>';
  prev.innerHTML = html;
}

function fmToggleParceiro(cid){
  var checked = document.getElementById('fm-tem-parceiro')?.checked;
  var fields  = document.getElementById('fm-parceiro-fields');
  if(fields) fields.style.display = checked ? 'block' : 'none';
  fmAutoCalc(cid);
}

function fmUpdateTipoLabel(){
  // nothing extra needed — tipo is read in fmSalvar
}

function fmUpdateBruto(){
  var vbruto = parseFloat(document.getElementById('fm-vbruto')?.value||0);
  var nparc  = parseInt(document.getElementById('fm-nparc')?.value||1);
  if(vbruto > 0 && nparc > 0){
    var perParc = roundMoney(vbruto/nparc);
    var vparcEl = document.getElementById('fm-vparc');
    if(vparcEl && !vparcEl.value) vparcEl.value = perParc;
    var valorEl = document.getElementById('fm-valor');
    if(valorEl && !valorEl.value) { valorEl.value = vbruto; }
  }
}

var _fmSaving = false;
function fmSalvar(cid){
  if(_fmSaving) return; _fmSaving = true;
  setTimeout(function(){ _fmSaving = false; }, 1000);
  const c = findClientById(cid);
  if(!c){ _fmSaving=false; return; }

  const desc    = fmVal('desc');
  if(!desc){ showToast('Informe a descrição'); return; }

  let tipo      = (_fl.tipo||[])[0]||'outro';
  if(tipo==='honorario_direto') tipo='honorario';
  const dir     = (_fl.direcao||[])[0]||'receber';
  const forma   = (_fl.formaPag||[])[0]||'';
  const centro  = fmVal('centro')||(_fl.centro||[])[0]||'';
  const plano   = fmVal('plano')||'';
  const conta   = fmVal('conta')||'';
  const intv    = (_fl.intervalo||[])[0]||'unico';
  const nparc   = parseInt(fmVal('nparc'))||1;
  const vparc   = fmNum('vparc');
  const venc1   = fmVal('venc1');
  const statusLanc = fmVal('status')||'pendente';
  const obs     = fmVal('obs')||'';

  const addTempo = function(dt, i){
    const d = new Date(dt+'T12:00:00');
    if(intv==='mensal')      d.setMonth(d.getMonth()+i);
    else if(intv==='quinzenal') d.setDate(d.getDate()+15*i);
    else if(intv==='semanal')   d.setDate(d.getDate()+7*i);
    return d.toISOString().slice(0,10);
  };

  // ── ACORDO / CONDENAÇÃO — split automático ──────────────────
  if(tipo==='acordo'){
    const vbruto  = fmNum('vbruto')||fmNum('valor')||0;
    const vliq    = fmNum('vliquido')||vbruto;
    const vsucumb = fmNum('vsucumb')||0;
    const vdesp   = fmNum('vdesp')||0;
    const honperc = fmNum('honperc')||0;
    const honfixo = fmNum('honfixo')||0;
    if(!vbruto){ showToast('Informe o valor bruto do acordo'); return; }

    const vBase   = roundMoney(vliq - vsucumb);            // valor do cliente (sem sucumb)
    const hon     = honfixo || roundMoney(vBase * honperc / 100);  // honorários contratuais
    const repasse = Math.max(0, roundMoney(vBase - hon - vdesp));    // o que vai pro cliente

    // Valor que fica no escritório por parcel
    const totalEscritorio = roundMoney(vsucumb + hon);
    const valorParc = (nparc>1 && vparc) ? vparc : vbruto;
    // proporcional por parcela
    const escPorParc  = nparc>1 ? roundMoney(totalEscritorio / nparc) : totalEscritorio;
    const repPorParc  = nparc>1 ? roundMoney(repasse / nparc) : repasse;

    const grupoId = genId();
    let lancamentosCriados = 0;

    for(let i=0; i<nparc; i++){
      const dt = (nparc>1 && venc1) ? addTempo(venc1, i) : (fmVal('venc')||fmVal('data'));
      const lbl = nparc>1 ? ' ('+(i+1)+'/'+nparc+')' : '';

      // 1. Receita do escritório (honorários + sucumb)
      if(escPorParc > 0){
        localLanc.push({
          id: grupoId+i*10+1, tipo:'acordo', direcao:'receber',
          desc: desc+lbl, valor: roundMoney(escPorParc),
          vbruto_parc: roundMoney(valorParc/nparc),
          vsucumb_parc: roundMoney(vsucumb/nparc),
          hon_parc: roundMoney(hon/nparc),
          honperc, vdesp_parc: roundMoney(vdesp/nparc),
          data: dt, venc: dt, status: statusLanc,
          forma, centro, plano, conta, obs, id_processo: cid, cliente: c.cliente,
          _grupo_acordo: grupoId, _parcela: i+1, _total_parc: nparc,
          pago: statusLanc==='pago',
        });
        lancamentosCriados++;
      }

      // 2. Obrigação de repasse (o que vai pro cliente)
      if(repPorParc > 0.01){
        const dtRep = new Date((dt||new Date().toISOString().slice(0,10))+'T12:00:00');
        dtRep.setDate(dtRep.getDate()+2);
        localLanc.push({
          id: grupoId+i*10+2, tipo:'repasse', direcao:'pagar',
          desc: 'Repasse — '+desc+lbl, valor: roundMoney(repPorParc),
          data: dtRep.toISOString().slice(0,10), venc: dtRep.toISOString().slice(0,10),
          status:'pendente', pago:false,
          forma, centro, obs:'Repasse de acordo: '+desc,
          id_processo: cid, cliente: c.cliente,
          _grupo_acordo: grupoId, _parcela: i+1, _repasse_acordo: true,
        });
      }
    }

    sbSet('co_localLanc', localLanc);
    marcarAlterado(); fecharModal();
    _reRenderFinPasta(cid);
    if(document.getElementById('vf')?.classList.contains('on')) vfRender();
    renderFinDash();

    // Resumo no toast
    const msg = 'Acordo lançado: '+fBRL(totalEscritorio)+' para escritório'
      +(repasse>0?' · Repasse '+fBRL(repasse)+' gerado':'')
      +(nparc>1?' — '+nparc+' parcelas':'');
    showToast('✅ '+msg);

    // Copiar mensagem de repasse silenciosamente (não abre modal)
    if(repasse > 0){
      var dadosB = typeof getDadosBancarios==='function' ? getDadosBancarios(c.cliente) : null;
      var dtR = (function(){ var d2=new Date(); d2.setDate(d2.getDate()+2); return fDt(d2.toISOString().slice(0,10)); })();
      var wpp = '*REPASSE \u2014 '+c.cliente+'*\n'
        +'Acordo: '+desc+'\n'
        +'Valor total: '+fBRL(vbruto)+'\n'
        +(vsucumb?'Sucumb\u00eancia: '+fBRL(vsucumb)+'\n':'')
        +'Honor\u00e1rios ('+honperc+'%): '+fBRL(hon)+'\n'
        +'*Repasse ao cliente: '+fBRL(repasse)+'*\n'
        +'Prazo: at\u00e9 '+dtR+'\n'
        +(dadosB ? '\n'+formatarDadosBancarios(dadosB) : '');
      navigator.clipboard.writeText(wpp).then(function(){
        showToast('\ud83d\udcf2 Mensagem de repasse copiada!');
      }).catch(function(){});
    }
    return;
  }
  // ↑↑↑ ACORDO termina aqui — SEMPRE retorna ↑↑↑

  // ── HONORÁRIO DIRETO com split ──────────────────────────────
  if(tipo==='honorario' && dir==='receber'){
    const valor  = fmNum('valor');
    if(!valor){ showToast('Informe o valor'); return; }
    const perc   = fmNum('honperc')/100 || 1; // default 100% = sem repasse
    const desp   = fmNum('vsucumb') || 0;
    const hon    = roundMoney(valor * perc);
    const rep    = Math.max(0, roundMoney(valor - hon - desp));
    const dt     = fmVal('data') || new Date().toISOString().slice(0,10);
    const venc   = fmVal('venc') || dt;

    // Ler campos de parceria e tipo
    var temParceiro2  = document.getElementById('fm-tem-parceiro')?.checked || false;
    var parcNome2     = document.getElementById('fm-parceiro-nome')?.value?.trim() || '';
    var parcPerc2     = parseFloat(document.getElementById('fm-parceiro-perc')?.value||0);
    var parcVal2      = temParceiro2 ? roundMoney(hon*(parcPerc2/100)) : 0;
    var liquido2      = hon - parcVal2;
    var tipoParc2     = document.getElementById('fm-tipo-parc')?.value || 'unica';
    var vbruto2       = parseFloat(document.getElementById('fm-vbruto')?.value||0)||valor;

    // 1. Honorários — líquido após parceiro
    localLanc.push({
      id: genId(), tipo:'honorario', direcao:'receber',
      desc: desc, valor: liquido2,
      data: dt, venc: venc, status: statusLanc,
      pago: statusLanc==='pago', dt_baixa: statusLanc==='pago'?dt:'',
      forma, centro, plano, conta, obs, id_processo: cid, cliente: c.cliente,
      natureza: 'honorario_escritorio',
      _honperc: perc*100, _vbruto: vbruto2,
      _tipo_parc: tipoParc2,
      _parceiro: temParceiro2 ? parcNome2 : '',
      _parceiro_perc: temParceiro2 ? parcPerc2 : 0,
      _parceiro_val: parcVal2,
    });

    // 2. Repasse — o que vai pro cliente (se houver)
    if(rep > 0.01){
      const dtRep = new Date(dt+'T12:00:00');
      dtRep.setDate(dtRep.getDate()+2);
      localLanc.push({
        id: genId(), tipo:'repasse', direcao:'pagar',
        desc: 'Repasse — '+desc, valor: rep,
        data: dtRep.toISOString().slice(0,10),
        venc: dtRep.toISOString().slice(0,10),
        status:'pendente', pago:false,
        forma, centro, obs:'Repasse de: '+desc,
        id_processo: cid, cliente: c.cliente,
        _repasse_acordo: true,
      });
    }

    sbSet('co_localLanc', localLanc);
    marcarAlterado(); fecharModal(); _reRenderFinPasta(cid);
    if(document.getElementById('vf')?.classList.contains('on')) vfRender();
    renderFinDash();

    const msg = 'Honorários lançados: '+fBRL(hon)+(rep>0?' · Repasse '+fBRL(rep)+' pendente':'');
    showToast('✅ '+msg);

    // WPP se tiver repasse
    if(rep > 0){
      const dadosB = getDadosBancarios(c.cliente);
      const dtRStr = (function(){ const d=new Date(dt+'T12:00:00'); d.setDate(d.getDate()+2); return fDt(d.toISOString().slice(0,10)); })();
      const wpp = '*REPASSE — '+c.cliente+'*\n'
        +'Referente: '+desc+'\n'
        +'Valor recebido: '+fBRL(valor)+'\n'
        +'Honorários ('+Math.round(perc*100)+'%): '+fBRL(hon)+'\n'
        +'*Repasse ao cliente: '+fBRL(rep)+'*\n'
        +'Prazo: até '+dtRStr+'\n'
        +(dadosB?'\n'+formatarDadosBancarios(dadosB):'_Cadastrar dados bancários na ficha_');
      setTimeout(function(){
        abrirModal('📋 Resumo',
          '<div style="background:var(--sf3);border-radius:8px;padding:12px;font-family:monospace;font-size:11px;line-height:1.8;white-space:pre-wrap;color:var(--tx)">'+escapeHtml(wpp)+'</div>',
          function(){ navigator.clipboard.writeText(wpp).then(function(){showToast('📲 Copiado!');}).catch(function(){var t=document.createElement('textarea');t.value=wpp;document.body.appendChild(t);t.select();document.execCommand('copy');document.body.removeChild(t);showToast('📲 Copiado!');}); },
          '📲 Copiar para WhatsApp','#25D366');
      }, 400);
    }
    return;
  }

  // ── OUTROS TIPOS (sucumbência, despesa, repasse, etc.) ──
  const valor = fmNum('valor');
  if(!valor){ showToast('Informe o valor'); return; }

  const base = {
    tipo, direcao: dir, desc, valor,
    data: fmVal('data'), venc: fmVal('venc'),
    status: statusLanc, pago: statusLanc==='pago',
    forma, centro, plano, conta, obs,
    id_processo: cid, cliente: c.cliente,
  };

  if(nparc > 1 && vparc && venc1){
    for(let i=0; i<nparc; i++){
      localLanc.push({
        ...base, id: genId(),
        desc: desc+' ('+(i+1)+'/'+nparc+')',
        valor: vparc,
        venc: addTempo(venc1, i), data: addTempo(venc1, i),
        parcela: (i+1)+'/'+nparc,
      });
    }
    sbSet('co_localLanc', localLanc);
    marcarAlterado(); fecharModal(); _reRenderFinPasta(cid);
    if(document.getElementById('vf')?.classList.contains('on')) vfRender();
    renderFinDash();
    showToast(nparc+' parcelas criadas ✓');
    return;
  }

  localLanc.push({...base, id: genId()});
  sbSet('co_localLanc', localLanc);
  marcarAlterado(); fecharModal(); _reRenderFinPasta(cid);
  if(document.getElementById('vf')?.classList.contains('on')) vfRender();
  renderFinDash();
  showToast('Lançamento salvo ✓');
}

// ═══════════════════════════════════════════════════════════════
// ══ FINANCEIRO PASTA DO CLIENTE — 8 ABAS INTERNAS ══
// ═══════════════════════════════════════════════════════════════

var _finCurTab = 'resumo';

// Cache de lançamentos por cliente — evita reprocessar a cada troca de aba
var _finLocaisCache = {};
var _finLocaisCacheVer = 0;
function _finGetLocais(cid){
  var ver = (localLanc||[]).length;
  if(_finLocaisCache._cid===cid && _finLocaisCache._ver===ver) return _finLocaisCache._data;
  var data = (localLanc||[]).filter(function(l){return Number(l.id_processo)===Number(cid) && !l.proj_ref && !l.origem_proj;});
  _finLocaisCache = {_cid:cid, _ver:ver, _data:data};
  return data;
}

function _finTab(tab, cid, btn){
  _finCurTab = tab;
  // Toggle buttons
  var nav = document.getElementById('fin-nav-'+cid);
  if(nav) nav.querySelectorAll('.fin-nav-btn').forEach(function(b){b.classList.remove('on');});
  if(btn) btn.classList.add('on');
  // Render content
  var el = document.getElementById('fin-tab-content-'+cid);
  if(!el) return;
  var fV = function(v){return 'R$ '+Math.abs(v||0).toLocaleString('pt-BR',{minimumFractionDigits:2,maximumFractionDigits:2});};
  var hoje = new Date().toISOString().slice(0,10);
  var c = findClientById(cid);
  if(!c){ el.innerHTML=''; return; }
  var locais = _finGetLocais(cid);

  requestAnimationFrame(function(){
    var html;
    if(tab==='resumo')        html = _finResumoTab2(cid, c, locais, fV, hoje);
    else if(tab==='honorarios') html = _finHonorariosTab(cid, c, locais, fV, hoje);
    else if(tab==='despesas')  html = _finDespesasTab2(cid, c, locais, fV, hoje);
    else if(tab==='repasses')  html = _finRepassesBancoTab(cid, c, locais, fV, hoje);
    else html = '<div style="padding:20px;color:var(--mu)">Em desenvolvimento</div>';
    el.innerHTML = html;
  });
}

// ═══════════════════════════════════════════════════════════════
// ══ MÓDULO FINANCEIRO v2 — PASTA DO CLIENTE (REFATORADO) ══════
// ═══════════════════════════════════════════════════════════════

// ── MOTOR DE CÁLCULO ──
function _finCalcLanc(l){
  var vi = parseFloat(l.valor_integral)||0;
  var vp = parseFloat(l.valor_parcela)||0;
  var base = vp > 0 ? vp : vi;
  var perc = parseFloat(l.percentual_honorarios)||0;
  // ── Compat: dados antigos/migrados do Projuris só têm `valor` (+ às vezes `_vbruto`/`_perc_hon`) ──
  if(base === 0){
    var vBruto = parseFloat(l._vbruto)||0;
    var valor = parseFloat(l.valor)||0;
    if(vBruto > 0){
      base = vBruto;
      if(!perc) perc = parseFloat(l._perc_hon)||0;
    } else if(valor > 0){
      base = valor;
      // Sem percentual informado → honorário direto, 100% escritório (honorario_escritorio)
      if(!perc) perc = 100;
    }
  }
  var ress = parseFloat(l.ressarcimento)||0;
  var hon = roundMoney(base * perc / 100);
  var ppn = (l.parceiro_nome||'').trim();
  var ppc = parseFloat(l.parceiro_percentual)||0;
  var vparc = ppn && ppc > 0 ? roundMoney(hon * ppc / 100) : 0;
  var liq = roundMoney(hon - vparc);
  var vcli = roundMoney(Math.max(0, base - hon - ress));
  return { base_calculo:base, honorarios_contratuais:hon, valor_parceiro:vparc, honorarios_liquidos_escritorio:liq, valor_cliente:vcli };
}

// ── CLASSIFICAR LANÇAMENTOS ──
function _finClassificar2(locais){
  var hon=[], desp=[], rep=[];
  locais.forEach(function(l){
    var isRep = l.tipo==='repasse'||l._repasse_acordo||l._repasse_alvara;
    var isDesp = l.tipo==='despesa'||l.tipo==='despint';
    if(isRep) rep.push(l);
    else if(isDesp) desp.push(l);
    else hon.push(l);
  });
  return {honorarios:hon, despesas:desp, repasses:rep};
}

// ── TOGGLE RECEBIDO ──
function _finToggleRecebido(cid, lid){
  var i = (localLanc||[]).findIndex(function(l){return String(l.id)===String(lid);});
  if(i===-1) return;
  var rec = !localLanc[i].recebido;
  localLanc[i].recebido = rec;
  localLanc[i].pago = rec;
  localLanc[i].status = rec ? 'pago' : 'pendente';
  localLanc[i].dt_baixa = rec ? (localLanc[i].data||new Date().toISOString().slice(0,10)) : '';
  localLanc[i].updated_at = new Date().toISOString();
  sbSet('co_localLanc', localLanc);
  marcarAlterado();
  _finLocaisCache = {};
  _finTab(_finCurTab, cid, null);
  showToast(rec ? 'Marcado como recebido \u2713' : 'Marcado como pendente');
}

// ── EDITAR HONORÁRIO ──
function _finEditarHonorario(cid, lid){
  var i = (localLanc||[]).findIndex(function(l){return String(l.id)===String(lid);});
  if(i===-1){ showToast('Lan\u00e7amento n\u00e3o encontrado'); return; }
  var l = localLanc[i];
  var c = findClientById(cid);
  if(!c) return;
  var hoje = new Date().toISOString().slice(0,10);
  var nparc = l._total_parc||1;
  abrirModal('\u270f Editar Honor\u00e1rio',
    '<div class="fm-row"><div style="flex:2"><label class="fm-lbl">Descri\u00e7\u00e3o</label><input class="fm-inp" id="eh-desc" value="'+escapeHtml(l.desc||'')+'"></div></div>'
    +'<div class="fm-row">'
      +'<div><label class="fm-lbl">Valor integral (R$)</label><input class="fm-inp" type="number" id="eh-vi" value="'+(l.valor_integral||l.valor||0)+'" min="0" step="0.01" oninput="_finPreviewEditDebounced()"></div>'
      +'<div><label class="fm-lbl">Valor parcela (R$)</label><input class="fm-inp" type="number" id="eh-vp" value="'+(l.valor_parcela||0)+'" min="0" step="0.01" oninput="_finPreviewEditDebounced()"></div>'
      +'<div><label class="fm-lbl">Ressarcimento (R$)</label><input class="fm-inp" type="number" id="eh-ress" value="'+(l.ressarcimento||0)+'" min="0" step="0.01" oninput="_finPreviewEditDebounced()"></div>'
    +'</div>'
    +'<div class="fm-row">'
      +'<div><label class="fm-lbl">% Honor\u00e1rios</label><input class="fm-inp" type="number" id="eh-perc" value="'+(l.percentual_honorarios||30)+'" min="0" max="100" step="0.5" oninput="_finPreviewEditDebounced()"></div>'
      +'<div><label class="fm-lbl">Parceiro (nome)</label><input class="fm-inp" id="eh-pnome" value="'+escapeHtml(l.parceiro_nome||'')+'" oninput="_finPreviewEditDebounced()"></div>'
      +'<div><label class="fm-lbl">% Parceiro</label><input class="fm-inp" type="number" id="eh-pperc" value="'+(l.parceiro_percentual||0)+'" min="0" max="100" step="0.5" oninput="_finPreviewEditDebounced()"></div>'
    +'</div>'
    +'<div id="eh-preview" style="margin:12px 0;padding:10px;background:var(--sf3);border-radius:8px"></div>'
    +'<div class="fm-row">'
      +'<div><label class="fm-lbl">Data</label><input class="fm-inp" type="date" id="eh-data" value="'+(l.data||hoje)+'"></div>'
      +'<div><label class="fm-lbl">Forma</label><select class="fm-inp" id="eh-forma"><option>PIX</option><option>TED</option><option>Boleto</option><option>Dinheiro</option><option>Alvar\u00e1 judicial</option><option>Dep\u00f3sito</option></select></div>'
      +'<div style="display:flex;align-items:center;gap:6px;padding-top:18px"><input type="checkbox" id="eh-recebido" '+(l.recebido||l.pago?'checked':'')+'><label for="eh-recebido" style="font-size:11px;color:var(--tx)">Recebido</label></div>'
    +'</div>'
    +'<div class="fm-row"><div style="flex:2"><label class="fm-lbl">Observa\u00e7\u00e3o</label><input class="fm-inp" id="eh-obs" value="'+escapeHtml(l.obs||'')+'"></div></div>',
  function(){
    var desc = (document.getElementById('eh-desc')?.value||'').trim();
    var vi = parseFloat(document.getElementById('eh-vi')?.value)||0;
    var vp = parseFloat(document.getElementById('eh-vp')?.value)||0;
    var ress = parseFloat(document.getElementById('eh-ress')?.value)||0;
    var perc = parseFloat(document.getElementById('eh-perc')?.value)||0;
    var pnome = (document.getElementById('eh-pnome')?.value||'').trim();
    var pperc = parseFloat(document.getElementById('eh-pperc')?.value)||0;
    var data = document.getElementById('eh-data')?.value||hoje;
    var forma = document.getElementById('eh-forma')?.value||'';
    var recebido = document.getElementById('eh-recebido')?.checked||false;
    var obs = (document.getElementById('eh-obs')?.value||'').trim();
    if(!desc){ showToast('Informe a descri\u00e7\u00e3o'); return; }
    if(!vi && !vp){ showToast('Informe o valor'); return; }
    var calc = _finCalcLanc({valor_integral:vi,valor_parcela:vp,ressarcimento:ress,percentual_honorarios:perc,parceiro_nome:pnome,parceiro_percentual:pperc});
    localLanc[i].desc = desc;
    localLanc[i].valor_integral = vi;
    localLanc[i].valor_parcela = vp;
    localLanc[i].valor = calc.base_calculo;
    localLanc[i].ressarcimento = ress;
    localLanc[i].percentual_honorarios = perc;
    localLanc[i].parceiro_nome = pnome;
    localLanc[i].parceiro_percentual = pperc;
    localLanc[i].data = data;
    localLanc[i].forma = forma;
    localLanc[i].recebido = recebido;
    localLanc[i].pago = recebido;
    localLanc[i].status = recebido ? 'pago' : 'pendente';
    localLanc[i].dt_baixa = recebido ? data : '';
    localLanc[i].obs = obs;
    // Carimbar timestamp de edição — crítico para _sbMergeArrays não reverter
    localLanc[i].updated_at = new Date().toISOString();
    sbSet('co_localLanc', localLanc);
    marcarAlterado(); fecharModal();
    _finLocaisCache = {};
    _reRenderFinPasta(cid);
    showToast('Honor\u00e1rio atualizado \u2713');
  }, '\ud83d\udcbe Salvar altera\u00e7\u00f5es');
  // Set forma select
  setTimeout(function(){
    var sel = document.getElementById('eh-forma');
    if(sel && l.forma) sel.value = l.forma;
    _finPreviewEdit();
  }, 100);
}

function _finPreviewEditDebounced(){ _debounce('prevEdit', _finPreviewEdit, 150); }
function _finPreviewEdit(){
  var vi = parseFloat(document.getElementById('eh-vi')?.value)||0;
  var vp = parseFloat(document.getElementById('eh-vp')?.value)||0;
  var ress = parseFloat(document.getElementById('eh-ress')?.value)||0;
  var perc = parseFloat(document.getElementById('eh-perc')?.value)||0;
  var pn = (document.getElementById('eh-pnome')?.value||'').trim();
  var pp = parseFloat(document.getElementById('eh-pperc')?.value)||0;
  var calc = _finCalcLanc({valor_integral:vi,valor_parcela:vp,ressarcimento:ress,percentual_honorarios:perc,parceiro_nome:pn,parceiro_percentual:pp});
  var fmt = function(v){return 'R$ '+(isFinite(v)?v:0).toLocaleString('pt-BR',{minimumFractionDigits:2,maximumFractionDigits:2});};
  var el = document.getElementById('eh-preview');
  if(!el) return;
  var pc = function(lbl,val,cor){return '<div style="padding:6px 8px;background:var(--sf3);border-radius:4px"><div style="font-size:8px;font-weight:700;text-transform:uppercase;color:var(--mu)">'+lbl+'</div><div style="font-size:12px;font-weight:700;color:'+cor+'">'+fmt(val)+'</div></div>';};
  el.innerHTML = '<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(120px,1fr));gap:6px">'
    +pc('Base',calc.base_calculo,'var(--tx)')
    +pc('Honor\u00e1rios',calc.honorarios_contratuais,'#D4AF37')
    +(pn?pc('Parceiro',calc.valor_parceiro,'#fb923c'):'')
    +pc('L\u00edq. escrit.',calc.honorarios_liquidos_escritorio,'#4ade80')
    +pc('Valor cliente',calc.valor_cliente,'#60a5fa')
  +'</div>';
}

// ── Debounce helper ──
var _debounceTimers = {};
function _debounce(key, fn, ms){
  clearTimeout(_debounceTimers[key]);
  _debounceTimers[key] = setTimeout(fn, ms||150);
}

// ── PREVIEW HONORÁRIO (MODAL) ──
function _finPreviewHonDebounced(){ _debounce('prevHon', _finPreviewHon, 150); }
function _finPreviewHon(){
  var vi = parseFloat(document.getElementById('fh-vi')?.value)||0;
  var nparc = parseInt(document.getElementById('fh-nparc')?.value)||1;
  var vp = nparc > 1 ? roundMoney(vi / nparc) : 0;
  var ress = parseFloat(document.getElementById('fh-ress')?.value)||0;
  var perc = parseFloat(document.getElementById('fh-perc')?.value)||0;
  var pn = (document.getElementById('fh-pnome')?.value||'').trim();
  var pp = parseFloat(document.getElementById('fh-pperc')?.value)||0;
  var calc = _finCalcLanc({valor_integral:vi,valor_parcela:vp,ressarcimento:ress,percentual_honorarios:perc,parceiro_nome:pn,parceiro_percentual:pp});
  var fmt = function(v){return 'R$ '+(isFinite(v)?v:0).toLocaleString('pt-BR',{minimumFractionDigits:2,maximumFractionDigits:2});};
  var el = document.getElementById('fh-preview');
  if(!el) return;
  var pcard = function(lbl,val,cor){ return '<div style="padding:6px 8px;background:var(--sf3);border-radius:4px"><div style="font-size:8px;font-weight:700;text-transform:uppercase;color:var(--mu)">'+lbl+'</div><div style="font-size:12px;font-weight:700;color:'+cor+'">'+fmt(val)+'</div></div>'; };
  el.innerHTML = (nparc>1?'<div style="font-size:10px;color:#D4AF37;font-weight:700;margin-bottom:6px">'+nparc+' parcelas de '+fmt(vp)+' (total '+fmt(vi)+')</div>':'')
    +'<div style="font-size:9px;color:var(--mu);margin-bottom:4px">'+(nparc>1?'Valores por parcela:':'')+'</div>'
    +'<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(120px,1fr));gap:6px">'
    +pcard('Base c\u00e1lculo',calc.base_calculo,'var(--tx)')
    +pcard('Honor\u00e1rios ('+perc+'%)',calc.honorarios_contratuais,'#D4AF37')
    +(pn?pcard('Parceiro',calc.valor_parceiro,'#fb923c'):'')
    +pcard('L\u00edq. escrit\u00f3rio',calc.honorarios_liquidos_escritorio,'#4ade80')
    +pcard('Valor cliente',calc.valor_cliente,'#60a5fa')
  +'</div>'
  +(nparc>1?'<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(120px,1fr));gap:6px;margin-top:6px;padding-top:6px;border-top:1px solid var(--bd)">'
    +pcard('TOTAL honor\u00e1rios',roundMoney(calc.honorarios_contratuais*nparc),'#D4AF37')
    +pcard('TOTAL l\u00edq. escrit.',roundMoney(calc.honorarios_liquidos_escritorio*nparc),'#4ade80')
    +pcard('TOTAL cliente',roundMoney(calc.valor_cliente*nparc + ress*(nparc>1?nparc-1:0)),'#60a5fa')
  +'</div>':'');
  // show/hide parceiro fields
  var pf = document.getElementById('fh-pfields');
  if(pf) pf.style.display = pn ? 'block' : 'none';
}

// ── MODAL NOVO HONORÁRIO ──
function _finNovoHonorario(cid){
  var c = findClientById(cid);
  if(!c) return;
  var hoje = new Date().toISOString().slice(0,10);
  var honPerc = c._hon_contrato ? (c._hon_contrato.perc||30) : 30;

  // Puxar parceiro da parceria cadastrada (se houver)
  var parcs = getParceriasDoProcesso(c);
  var parcNome = '', parcPerc = '';
  if(parcs.length > 0){
    var p0 = parcs[0];
    parcNome = p0.nome||'';
    parcPerc = p0.percDel||p0.percMeu||'';
  }

  abrirModal('\ud83d\udcb0 Lan\u00e7ar Honor\u00e1rio \u2014 '+escapeHtml(c.cliente),
    '<div class="fm-row">'
      +'<div style="flex:2"><label class="fm-lbl">Descri\u00e7\u00e3o *</label><input class="fm-inp" id="fh-desc" placeholder="Ex: Acordo trabalhista, Alvar\u00e1..."></div>'
    +'</div>'
    +'<div class="fm-row">'
      +'<div><label class="fm-lbl">Valor integral (R$)</label><input class="fm-inp" type="number" id="fh-vi" min="0" step="0.01" oninput="_finPreviewHonDebounced()"></div>'
      +'<div><label class="fm-lbl">N\u00ba de parcelas</label><input class="fm-inp" type="number" id="fh-nparc" min="1" max="120" value="1" placeholder="1 = \u00e0 vista" oninput="_finPreviewHonDebounced()"></div>'
      +'<div><label class="fm-lbl">Ressarcimento (R$)</label><input class="fm-inp" type="number" id="fh-ress" min="0" step="0.01" value="0" oninput="_finPreviewHonDebounced()"></div>'
    +'</div>'
    +'<div class="fm-row">'
      +'<div><label class="fm-lbl">% Honor\u00e1rios *</label><input class="fm-inp" type="number" id="fh-perc" value="'+honPerc+'" min="0" max="100" step="0.5" oninput="_finPreviewHonDebounced()"></div>'
      +'<div><label class="fm-lbl">Parceiro (nome)</label><input class="fm-inp" id="fh-pnome" value="'+escapeHtml(parcNome)+'" placeholder="Opcional" oninput="_finPreviewHonDebounced()"></div>'
    +'</div>'
    +'<div id="fh-pfields" style="display:'+(parcNome?'block':'none')+'"><div class="fm-row">'
      +'<div><label class="fm-lbl">% Parceiro *</label><input class="fm-inp" type="number" id="fh-pperc" value="'+(parcPerc||50)+'" min="0" max="100" step="0.5" oninput="_finPreviewHonDebounced()"></div>'
    +'</div></div>'
    +(parcNome?'<div style="font-size:10px;color:#4ade80;margin-bottom:8px">\u2713 Parceiro preenchido a partir da parceria cadastrada</div>':'')
    +'<div id="fh-preview" style="margin:12px 0;padding:10px;background:var(--sf3);border-radius:8px"></div>'
    +'<div class="fm-row">'
      +'<div><label class="fm-lbl">Data</label><input class="fm-inp" type="date" id="fh-data" value="'+hoje+'"></div>'
      +'<div><label class="fm-lbl">Forma pagamento</label><select class="fm-inp" id="fh-forma"><option>PIX</option><option>TED</option><option>Boleto</option><option>Dinheiro</option><option>Alvar\u00e1 judicial</option><option>Dep\u00f3sito</option></select></div>'
      +'<div style="display:flex;align-items:center;gap:6px;padding-top:18px"><input type="checkbox" id="fh-recebido"><label for="fh-recebido" style="font-size:11px;color:var(--tx)">Recebido</label></div>'
    +'</div>'
    +'<div class="fm-row"><div style="flex:2"><label class="fm-lbl">Observa\u00e7\u00e3o</label><input class="fm-inp" id="fh-obs" placeholder="Refer\u00eancia, processo..."></div></div>',
  function(){
    var desc = (document.getElementById('fh-desc')?.value||'').trim();
    var vi = parseFloat(document.getElementById('fh-vi')?.value)||0;
    var nparc = parseInt(document.getElementById('fh-nparc')?.value)||1;
    var vp = nparc > 1 ? roundMoney(vi / nparc) : 0;
    var ress = parseFloat(document.getElementById('fh-ress')?.value)||0;
    var perc = parseFloat(document.getElementById('fh-perc')?.value)||0;
    var pnome = (document.getElementById('fh-pnome')?.value||'').trim();
    var pperc = parseFloat(document.getElementById('fh-pperc')?.value)||0;
    var data = document.getElementById('fh-data')?.value||hoje;
    var forma = document.getElementById('fh-forma')?.value||'';
    var recebido = document.getElementById('fh-recebido')?.checked||false;
    var obs = (document.getElementById('fh-obs')?.value||'').trim();
    if(!desc){ showToast('Informe a descri\u00e7\u00e3o'); return; }
    if(!vi || vi <= 0){ showToast('Informe o valor integral'); return; }
    if(perc <= 0){ showToast('Informe o % de honor\u00e1rios'); return; }
    if(pnome && pperc <= 0){ showToast('Informe o % do parceiro'); return; }
    var grupoId = nparc > 1 ? genId() : null;
    for(var p = 0; p < nparc; p++){
      var descP = nparc > 1 ? desc+' ('+(p+1)+'/'+nparc+')' : desc;
      var dtP = data;
      if(nparc > 1 && p > 0){
        var d = new Date(data+'T12:00:00');
        d.setMonth(d.getMonth()+p);
        dtP = d.toISOString().slice(0,10);
      }
      // Ressarcimento só na primeira parcela
      var ressParc = (p===0) ? ress : 0;
      var calc = _finCalcLanc({valor_integral:vi,valor_parcela:vp,ressarcimento:ressParc,percentual_honorarios:perc,parceiro_nome:pnome,parceiro_percentual:pperc});
      localLanc.push({
        id: genId(), tipo:'honorario', direcao:'receber',
        id_processo: cid, cliente: c.cliente,
        desc:descP, valor_integral:vi, valor_parcela:vp, valor:calc.base_calculo,
        ressarcimento:ressParc, percentual_honorarios:perc,
        parceiro_nome:pnome, parceiro_percentual:pperc,
        data:dtP, forma:forma, recebido:false,
        status:'pendente', pago:false, dt_baixa:'', obs:obs,
        _grupo: grupoId, _parcela:p+1, _total_parc:nparc
      });
    }
    sbSet('co_localLanc', localLanc);
    // Se informou parceiro e não tem parceria cadastrada, criar automaticamente
    if(pnome && parcs.length===0){
      var lista = getParceriasDoProcesso(c);
      lista.push({
        nome: pnome, oab:'', tipo:'parceiro',
        percMeu: String(100 - (pperc||0)), percDel: String(pperc||0),
        base:'', repasse:'', repasse_data:'', repasse_status:'pendente',
        obs:'Criado automaticamente ao lan\u00e7ar honor\u00e1rio'
      });
      setParceriasDoProcesso(c, lista);
    }
    marcarAlterado(); fecharModal();
    _finLocaisCache = {};
    _reRenderFinPasta(cid);
    showToast(nparc > 1 ? nparc+' parcelas lan\u00e7adas \u2713' : 'Honor\u00e1rio lan\u00e7ado \u2713');
  }, '\ud83d\udcbe Salvar honor\u00e1rio');
  setTimeout(_finPreviewHon, 100);
}

// ── ABA RESUMO v2 ──
function _finResumoTab2(cid, c, locais, fV, hoje){
  var cls = _finClassificar2(locais);
  var totHon=0, totParc=0, totLiq=0, totCli=0, totRec=0, totPend=0, totBase=0;
  cls.honorarios.forEach(function(l){
    var calc = _finCalcLanc(l);
    totHon += calc.honorarios_contratuais;
    totParc += calc.valor_parceiro;
    totLiq += calc.honorarios_liquidos_escritorio;
    totCli += calc.valor_cliente;
    totBase += calc.base_calculo;
    if(isRec(l)) totRec += calc.base_calculo;
    else totPend += calc.base_calculo;
  });
  var totDesp = cls.despesas.reduce(function(s,l){return s+(parseFloat(l.valor)||0);},0);
  var totRepPago = cls.repasses.filter(isRec).reduce(function(s,l){return s+(parseFloat(l.valor)||0);},0);
  var totRepPend = cls.repasses.filter(function(l){return !isRec(l);}).reduce(function(s,l){return s+(parseFloat(l.valor)||0);},0);
  var maxVal = Math.max(totBase, totHon, totLiq, totCli, 1);
  var percRec = totBase>0 ? Math.round(totRec/totBase*100) : 0;

  function card(lbl, val, cor, sub, destaque){
    var pct = Math.min(100, Math.round(Math.abs(val)/maxVal*100));
    return '<div style="flex:1;min-width:130px;padding:12px 14px;background:'+(destaque?'linear-gradient(135deg,var(--sf2),'+cor+'15)':'var(--sf2)')+';border:1px solid '+(destaque?cor+'40':'var(--bd)')+';border-radius:10px">'
      +'<div style="font-size:9px;font-weight:700;text-transform:uppercase;color:var(--mu);margin-bottom:4px">'+lbl+'</div>'
      +'<div style="font-size:16px;font-weight:800;color:'+cor+'">'+fV(val)+'</div>'
      +'<div style="height:3px;background:var(--sf3);border-radius:2px;margin-top:6px;overflow:hidden"><div style="width:'+pct+'%;height:100%;background:'+cor+';border-radius:2px"></div></div>'
      +(sub?'<div style="font-size:9px;color:var(--mu);margin-top:3px">'+sub+'</div>':'')
    +'</div>';
  }

  return '<div style="padding:14px">'
    // Valor integral total
    +(totBase>0?'<div style="background:var(--sf2);border:1px solid var(--bd);border-radius:8px;padding:12px 16px;margin-bottom:12px;display:flex;justify-content:space-between;align-items:center">'
      +'<div><div style="font-size:9px;font-weight:700;text-transform:uppercase;color:var(--mu)">Valor integral total</div>'
        +'<div style="font-size:22px;font-weight:800;color:var(--tx)">'+fV(totBase)+'</div></div>'
      +'<div style="text-align:right"><div style="font-size:9px;color:var(--mu)">Recebido: '+percRec+'%</div>'
        +'<div style="height:6px;width:120px;background:var(--sf3);border-radius:4px;overflow:hidden;margin-top:4px"><div style="width:'+percRec+'%;height:100%;background:#4ade80;border-radius:4px"></div></div></div>'
    +'</div>':'')
    +'<div style="display:flex;flex-wrap:wrap;gap:8px;margin-bottom:12px">'
      +card('Honor\u00e1rios', totHon, '#D4AF37', '', false)
      +card('Parceiro', totParc, totParc>0?'#fb923c':'var(--mu)', '', false)
      +card('L\u00edq. escrit\u00f3rio', totLiq, '#4ade80', '', true)
      +card('Valor cliente', totCli, '#60a5fa', '', false)
    +'</div>'
    +'<div style="display:flex;flex-wrap:wrap;gap:8px;margin-bottom:12px">'
      +card('Recebido', totRec, '#4ade80', '', false)
      +card('Pendente', totPend, totPend>0?'#f59e0b':'var(--mu)', '', false)
      +card('Despesas', totDesp, totDesp>0?'#f87676':'var(--mu)', '', false)
      +card('Repasses', totRepPago, totRepPago>0?'var(--tx)':'var(--mu)', totRepPend>0?'<span style="color:#c9484a">'+fV(totRepPend)+' pendente</span>':'', totRepPend>0)
    +'</div>'
    +'<div style="display:flex;gap:6px;flex-wrap:wrap">'
      +'<button onclick="_finNovoHonorario('+cid+')" style="font-size:11px;font-weight:700;padding:6px 14px;border-radius:6px;background:rgba(212,175,55,.12);border:1px solid rgba(212,175,55,.3);color:#D4AF37;cursor:pointer">+ Lan\u00e7ar Honor\u00e1rio</button>'
      +'<button onclick="_finNovaDespesa('+cid+')" style="font-size:11px;font-weight:700;padding:6px 14px;border-radius:6px;background:rgba(248,118,118,.08);border:1px solid rgba(248,118,118,.3);color:#f87676;cursor:pointer">+ Despesa</button>'
      +'<button onclick="_finGerarRepasse('+cid+')" style="font-size:11px;font-weight:700;padding:6px 14px;border-radius:6px;background:rgba(201,72,74,.1);border:1px solid rgba(201,72,74,.3);color:#c9484a;cursor:pointer">\ud83d\udce4 Gerar Repasse</button>'
      +'<button onclick="_finRelatorioPDF('+cid+')" style="font-size:11px;font-weight:700;padding:6px 14px;border-radius:6px;background:rgba(96,165,250,.1);border:1px solid rgba(96,165,250,.3);color:#60a5fa;cursor:pointer">\ud83d\udcc4 Relat\u00f3rio PDF</button>'
    +'</div>'
  +'</div>';
}


// ── RELATÓRIO PDF DA PASTA DO CLIENTE ──
function _finRelatorioPDF(cid){
  var c = findClientById(cid);
  if(!c) return;
  var locais = _finGetLocais(cid);
  var cls = _finClassificar2(locais);
  var fV = function(v){return 'R$ '+Math.abs(v||0).toLocaleString('pt-BR',{minimumFractionDigits:2,maximumFractionDigits:2});};
  var hoje = getTodayKey();

  // Totais do resumo
  var totHon=0, totParc=0, totLiq=0, totCli=0, totRec=0, totPend=0;
  cls.honorarios.forEach(function(l){
    var calc = _finCalcLanc(l);
    totHon += calc.honorarios_contratuais;
    totParc += calc.valor_parceiro;
    totLiq += calc.honorarios_liquidos_escritorio;
    totCli += calc.valor_cliente;
    if(isRec(l)) totRec += calc.base_calculo; else totPend += calc.base_calculo;
  });
  var totDesp = cls.despesas.reduce(function(s,l){return s+(parseFloat(l.valor)||0);},0);
  var totRepPago = cls.repasses.filter(isRec).reduce(function(s,l){return s+(parseFloat(l.valor)||0);},0);

  // Linhas de honorários
  var honRows = cls.honorarios.map(function(l){
    var calc = _finCalcLanc(l);
    return '<tr>'
      +'<td>'+fDt(l.data)+'</td>'
      +'<td>'+escapeHtml(l.desc||'\u2014')+'</td>'
      +'<td class="r">'+fV(calc.base_calculo)+'</td>'
      +'<td class="r">'+(l.percentual_honorarios||0)+'%</td>'
      +'<td class="r">'+fV(calc.honorarios_contratuais)+'</td>'
      +'<td class="r">'+fV(calc.valor_parceiro)+'</td>'
      +'<td class="r">'+fV(calc.honorarios_liquidos_escritorio)+'</td>'
      +'<td class="r">'+fV(calc.valor_cliente)+'</td>'
      +'<td>'+(isRec(l)?'\u2713 Recebido':'Pendente')+'</td>'
    +'</tr>';
  }).join('');

  // Linhas de despesas
  var despRows = cls.despesas.map(function(l){
    return '<tr><td>'+fDt(l.data)+'</td><td>'+escapeHtml(l.desc||'\u2014')+'</td><td class="r">'+fV(l.valor)+'</td><td>'+(l.tipo==='despint'?'Interno':'Reembols\u00e1vel')+'</td></tr>';
  }).join('');

  // Linhas de repasses
  var repRows = cls.repasses.map(function(l){
    return '<tr><td>'+fDt(l.dt_baixa||l.data)+'</td><td>'+escapeHtml(l.desc||'Repasse')+'</td><td class="r">'+fV(l.valor)+'</td><td>'+(l.forma||l.conta||'')+'</td><td>'+(isRec(l)?'\u2713 Pago':'Pendente')+'</td></tr>';
  }).join('');

  // Dados bancários
  var dadosBanc = getDadosBancarios(c.cliente);
  var bancHtml = dadosBanc
    ? '<h2>\ud83c\udfe6 Dados Banc\u00e1rios</h2><p>'
      +(dadosBanc.nomebenef?'Benefici\u00e1rio: '+dadosBanc.nomebenef+'<br>':'')
      +(dadosBanc.banco?'Banco: '+dadosBanc.banco+' ':'')+(dadosBanc.ag?'Ag: '+dadosBanc.ag+' ':'')+(dadosBanc.conta?'Conta: '+dadosBanc.conta+'<br>':'')
      +(dadosBanc.pix?'PIX: <strong>'+escapeHtml(dadosBanc.pix)+'</strong>':'')
    +'</p>' : '';

  var win = window.open('','_blank');
  win.document.write('<!DOCTYPE html><html><head><meta charset="utf-8">'
    +'<title>Relat\u00f3rio Financeiro \u2014 '+escapeHtml(c.cliente)+'</title>'
    +'<style>'
      +'body{font-family:Calibri,sans-serif;font-size:11px;color:#111;padding:24px;max-width:900px;margin:0 auto}'
      +'h1{font-size:16px;color:#510f10;margin-bottom:2px}'
      +'h2{font-size:13px;color:#510f10;margin:18px 0 6px;border-bottom:1px solid #ddd;padding-bottom:4px}'
      +'.sub{font-size:11px;color:#666;margin-bottom:16px}'
      +'.cards{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:16px}'
      +'.card{border:1px solid #ddd;border-radius:6px;padding:8px 12px;min-width:100px;text-align:center}'
      +'.card-v{font-size:16px;font-weight:700}'
      +'.card-l{font-size:8px;font-weight:700;text-transform:uppercase;color:#666;margin-top:2px}'
      +'.grn{color:#16a34a}.red{color:#dc2626}.org{color:#9a3412}.blu{color:#1d4ed8}'
      +'table{width:100%;border-collapse:collapse;margin-bottom:12px}'
      +'th{background:#510f10;color:#fff;padding:4px 6px;text-align:left;font-size:9px;text-transform:uppercase}'
      +'td{padding:4px 6px;border-bottom:1px solid #eee;font-size:10px}'
      +'tr:nth-child(even) td{background:#f9f9f9}'
      +'.r{text-align:right}'
      +'.footer{margin-top:20px;font-size:9px;color:#999;border-top:1px solid #eee;padding-top:8px}'
      +'@media print{body{padding:12px}}'
    +'</style></head><body>'
    +'<h1>Relat\u00f3rio Financeiro</h1>'
    +'<div class="sub">'+escapeHtml(c.cliente)+(c.numero?' \u00b7 '+c.numero:'')+' \u00b7 Gerado em '+fDt(hoje)+'</div>'
    +'<div class="cards">'
      +'<div class="card"><div class="card-v">'+fV(totHon)+'</div><div class="card-l">Honor\u00e1rios</div></div>'
      +'<div class="card"><div class="card-v org">'+fV(totParc)+'</div><div class="card-l">Parceiro</div></div>'
      +'<div class="card"><div class="card-v grn">'+fV(totLiq)+'</div><div class="card-l">L\u00edq. escrit\u00f3rio</div></div>'
      +'<div class="card"><div class="card-v blu">'+fV(totCli)+'</div><div class="card-l">Valor cliente</div></div>'
      +'<div class="card"><div class="card-v grn">'+fV(totRec)+'</div><div class="card-l">Recebido</div></div>'
      +'<div class="card"><div class="card-v org">'+fV(totPend)+'</div><div class="card-l">Pendente</div></div>'
      +'<div class="card"><div class="card-v red">'+fV(totDesp)+'</div><div class="card-l">Despesas</div></div>'
      +'<div class="card"><div class="card-v">'+fV(totRepPago)+'</div><div class="card-l">Repasses</div></div>'
    +'</div>'
    +(honRows?'<h2>\ud83d\udcb0 Honor\u00e1rios</h2><table><tr><th>Data</th><th>Descri\u00e7\u00e3o</th><th class="r">Base</th><th class="r">%</th><th class="r">Honor.</th><th class="r">Parceiro</th><th class="r">L\u00edq.</th><th class="r">Cliente</th><th>Status</th></tr>'+honRows+'</table>':'')
    +(despRows?'<h2>\ud83d\udcdd Despesas</h2><table><tr><th>Data</th><th>Descri\u00e7\u00e3o</th><th class="r">Valor</th><th>Tipo</th></tr>'+despRows+'</table>':'')
    +(repRows?'<h2>\ud83d\udce4 Repasses</h2><table><tr><th>Data</th><th>Descri\u00e7\u00e3o</th><th class="r">Valor</th><th>Forma</th><th>Status</th></tr>'+repRows+'</table>':'')
    +bancHtml
    +'<div class="footer">CO Advocacia \u00b7 Clarissa Oliveira \u00b7 Gerado automaticamente</div>'
    +'</body></html>');
  win.document.close();
  setTimeout(function(){ win.print(); }, 500);
}

// ── ABA HONORÁRIOS ──
function _finHonorariosTab(cid, c, locais, fV, hoje){
  var cls = _finClassificar2(locais);
  var lista = cls.honorarios.sort(function(a,b){return (b.data||'').localeCompare(a.data||'');});

  var html = '<div style="padding:10px 0">'
    +'<button onclick="_finNovoHonorario('+cid+')" style="font-size:11px;font-weight:700;padding:6px 14px;border-radius:6px;background:rgba(212,175,55,.12);border:1px solid rgba(212,175,55,.3);color:#D4AF37;cursor:pointer;margin-bottom:12px">+ Lan\u00e7ar Honor\u00e1rio</button>';

  if(!lista.length) return html+'<div style="padding:30px;text-align:center;color:var(--mu)">Nenhum honor\u00e1rio lan\u00e7ado.<br>Clique no bot\u00e3o acima para come\u00e7ar.</div></div>';

  lista.forEach(function(l){
    var calc = _finCalcLanc(l);
    var rec = isRec(l);
    var corStatus = rec?'#4ade80':'#fb923c';
    var lblStatus = rec?'\u2713 Recebido':'\u23f3 Pendente';

    function mini(lbl, val, cor){
      return '<div style="padding:6px 8px;background:var(--sf3);border-radius:4px">'
        +'<div style="font-size:8px;font-weight:700;text-transform:uppercase;color:var(--mu)">'+lbl+'</div>'
        +'<div style="font-size:12px;font-weight:700;color:'+cor+'">'+fV(val)+'</div>'
      +'</div>';
    }

    html += '<div style="background:var(--sf2);border:1px solid var(--bd);border-radius:8px;padding:12px;margin-bottom:8px">'
      +'<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px">'
        +'<div style="font-size:13px;font-weight:700;color:var(--tx)">'+escapeHtml(l.desc||'\u2014')+'</div>'
        +'<div style="display:flex;gap:6px;align-items:center">'
          +'<span style="font-size:10px;font-weight:700;color:'+corStatus+'">'+lblStatus+'</span>'
          +'<button onclick="_finToggleRecebido('+cid+',\''+l.id+'\')" style="font-size:10px;padding:3px 8px;border-radius:4px;background:'+(rec?'rgba(251,146,60,.1)':'rgba(76,175,125,.1)')+';border:1px solid '+(rec?'rgba(251,146,60,.3)':'rgba(76,175,125,.3)')+';color:'+(rec?'#fb923c':'#4ade80')+';cursor:pointer">'+(rec?'\u21a9 Pendente':'\u2713 Recebido')+'</button>'
          +'<button onclick="_finEditarHonorario('+cid+',\''+l.id+'\')" style="font-size:10px;padding:3px 8px;border-radius:4px;background:rgba(212,175,55,.1);border:1px solid rgba(212,175,55,.3);color:#D4AF37;cursor:pointer">\u270f</button>'
          +'<button onclick="finDelLanc('+cid+',\''+l.id+'\')" style="font-size:10px;padding:3px 6px;border-radius:4px;background:var(--sf3);border:1px solid rgba(201,72,74,.3);color:#c9484a;cursor:pointer">\u2715</button>'
        +'</div>'
      +'</div>'
      +'<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(120px,1fr));gap:6px">'
        +mini('Base c\u00e1lculo', calc.base_calculo, 'var(--tx)')
        +mini('% Honor\u00e1rios', 0, '#D4AF37').replace(fV(0), (l.percentual_honorarios||0)+'%')
        +mini('Honor\u00e1rios', calc.honorarios_contratuais, '#D4AF37')
        +(calc.valor_parceiro>0?mini('Parceiro '+(l.parceiro_nome||''), calc.valor_parceiro, '#fb923c'):'')
        +mini('L\u00edq. escrit\u00f3rio', calc.honorarios_liquidos_escritorio, '#4ade80')
        +mini('Valor cliente', calc.valor_cliente, '#60a5fa')
      +'</div>'
      +'<div style="font-size:10px;color:var(--mu);margin-top:6px">'
        +fDt(l.data)+(l.forma?' \u00b7 '+l.forma:'')+(l.obs?' \u00b7 '+escapeHtml(l.obs):'')
        +(l.valor_parcela>0?' \u00b7 Parcela: '+fV(l.valor_parcela):'')
        +(l.ressarcimento>0?' \u00b7 Ressarc: '+fV(l.ressarcimento):'')
      +'</div>'
    +'</div>';
  });
  return html+'</div>';
}

// ── MODAL NOVA DESPESA ──
function _finNovaDespesa(cid){
  var c = findClientById(cid);
  if(!c) return;
  var hoje = new Date().toISOString().slice(0,10);
  abrirModal('\ud83d\udcdd Nova Despesa \u2014 '+escapeHtml(c.cliente),
    '<div class="fm-row"><div style="flex:2"><label class="fm-lbl">Descri\u00e7\u00e3o *</label><input class="fm-inp" id="fd-desc" placeholder="Ex: Custas judiciais, dilig\u00eancia..."></div></div>'
    +'<div class="fm-row">'
      +'<div><label class="fm-lbl">Valor (R$) *</label><input class="fm-inp" type="number" id="fd-valor" min="0.01" step="0.01"></div>'
      +'<div><label class="fm-lbl">Data</label><input class="fm-inp" type="date" id="fd-data" value="'+hoje+'"></div>'
    +'</div>'
    +'<div class="fm-row">'
      +'<div><label class="fm-lbl">Tipo de despesa</label><select class="fm-inp" id="fd-tipo"><option value="custa">Custa</option><option value="diligencia">Dilig\u00eancia</option><option value="deslocamento">Deslocamento</option><option value="copia">C\u00f3pia</option><option value="emolumento">Emolumento</option><option value="operacional">Operacional</option><option value="outro">Outro</option></select></div>'
      +'<div><label class="fm-lbl">Forma pagamento</label><select class="fm-inp" id="fd-forma"><option>PIX</option><option>Dinheiro</option><option>Cart\u00e3o</option><option>Boleto</option><option>TED</option></select></div>'
    +'</div>'
    +'<div class="fm-row">'
      +'<div style="display:flex;align-items:center;gap:6px;padding-top:4px"><input type="checkbox" id="fd-reimb" checked><label for="fd-reimb" style="font-size:11px;color:var(--tx)">Reembols\u00e1vel</label></div>'
      +'<div><label class="fm-lbl">Pago por</label><input class="fm-inp" id="fd-pago" placeholder="Escrit\u00f3rio, cliente..."></div>'
    +'</div>'
    +'<div class="fm-row"><div style="flex:2"><label class="fm-lbl">Observa\u00e7\u00e3o</label><input class="fm-inp" id="fd-obs" placeholder="Detalhes, comprovante..."></div></div>',
  function(){
    var desc = (document.getElementById('fd-desc')?.value||'').trim();
    var valor = parseFloat(document.getElementById('fd-valor')?.value)||0;
    if(!desc){ showToast('Informe a descri\u00e7\u00e3o'); return; }
    if(valor <= 0){ showToast('Informe o valor'); return; }
    var data = document.getElementById('fd-data')?.value||hoje;
    var tipod = document.getElementById('fd-tipo')?.value||'outro';
    var forma = document.getElementById('fd-forma')?.value||'';
    var reimb = document.getElementById('fd-reimb')?.checked;
    var pago = (document.getElementById('fd-pago')?.value||'').trim();
    var obs = (document.getElementById('fd-obs')?.value||'').trim();
    localLanc.push({
      id: genId(), tipo: reimb?'despesa':'despint', direcao:'pagar',
      id_processo: cid, cliente: c.cliente,
      desc:desc, valor:valor, data:data,
      tipo_despesa:tipod, reembolsavel:reimb, pago_por:pago,
      forma:forma, obs:obs, status:'pendente', pago:false
    });
    sbSet('co_localLanc', localLanc);
    marcarAlterado(); fecharModal();
    _finLocaisCache = {};
    _reRenderFinPasta(cid);
    showToast('Despesa lan\u00e7ada \u2713');
  }, '\ud83d\udcbe Salvar despesa');
}

// ── ABA DESPESAS v2 ──
function _finDespesasTab2(cid, c, locais, fV, hoje){
  var cls = _finClassificar2(locais);
  var lista = cls.despesas.sort(function(a,b){return (b.data||'').localeCompare(a.data||'');});
  var totDesp = lista.reduce(function(s,l){return s+(parseFloat(l.valor)||0);},0);
  var totReimb = lista.filter(function(l){return l.tipo!=='despint';}).reduce(function(s,l){return s+(parseFloat(l.valor)||0);},0);
  var totInt = lista.filter(function(l){return l.tipo==='despint';}).reduce(function(s,l){return s+(parseFloat(l.valor)||0);},0);
  var tipoLabels = {custa:'Custa',diligencia:'Dilig\u00eancia',deslocamento:'Deslocamento',copia:'C\u00f3pia',emolumento:'Emolumento',operacional:'Operacional',outro:'Outro'};

  var html = '<div style="padding:10px 0">'
    +'<button onclick="_finNovaDespesa('+cid+')" style="font-size:11px;font-weight:700;padding:6px 14px;border-radius:6px;background:rgba(248,118,118,.08);border:1px solid rgba(248,118,118,.3);color:#f87676;cursor:pointer;margin-bottom:12px">+ Nova Despesa</button>'
    +'<div style="display:flex;flex-wrap:wrap;gap:6px;margin-bottom:12px">'
      +'<div style="flex:1;min-width:100px;padding:8px 10px;background:var(--sf2);border:1px solid var(--bd);border-radius:6px"><div style="font-size:9px;font-weight:700;text-transform:uppercase;color:var(--mu)">Total</div><div style="font-size:14px;font-weight:800;color:#f87676">'+fV(totDesp)+'</div></div>'
      +'<div style="flex:1;min-width:100px;padding:8px 10px;background:var(--sf2);border:1px solid var(--bd);border-radius:6px"><div style="font-size:9px;font-weight:700;text-transform:uppercase;color:var(--mu)">Reembols\u00e1vel</div><div style="font-size:14px;font-weight:800;color:#f59e0b">'+fV(totReimb)+'</div></div>'
      +'<div style="flex:1;min-width:100px;padding:8px 10px;background:var(--sf2);border:1px solid var(--bd);border-radius:6px"><div style="font-size:9px;font-weight:700;text-transform:uppercase;color:var(--mu)">Custo interno</div><div style="font-size:14px;font-weight:800;color:var(--mu)">'+fV(totInt)+'</div></div>'
    +'</div>';

  if(!lista.length) return html+'<div style="padding:30px;text-align:center;color:var(--mu)">Nenhuma despesa registrada.</div></div>';

  lista.forEach(function(l){
    var isReimb = l.tipo!=='despint';
    var tipoLbl = tipoLabels[l.tipo_despesa]||l.tipo_despesa||'Outro';
    html += '<div style="display:flex;align-items:center;gap:10px;padding:8px 0;border-bottom:1px solid var(--bd)">'
      +'<div style="flex:1"><div style="font-size:12px;font-weight:600;color:var(--tx)">'+escapeHtml(l.desc||'\u2014')+'</div>'
        +'<div style="font-size:10px;color:var(--mu)">'+fDt(l.data)+' \u00b7 '+tipoLbl+' \u00b7 <span style="color:'+(isReimb?'#f59e0b':'var(--mu)')+'">'+(isReimb?'Reembols\u00e1vel':'Custo interno')+'</span>'+(l.pago_por?' \u00b7 Pago por: '+escapeHtml(l.pago_por):'')+(l.obs?' \u00b7 '+escapeHtml(l.obs):'')+'</div></div>'
      +'<span style="font-size:13px;font-weight:700;color:#f87676">'+fV(l.valor)+'</span>'
      +'<button onclick="_finToggleTipoDesp('+cid+',\''+l.id+'\')" style="font-size:10px;padding:3px 8px;border-radius:4px;background:var(--sf3);border:1px solid var(--bd);color:var(--mu);cursor:pointer">'+(l.tipo==='despint'?'\u2191 Reimb.':'\u2193 Interno')+'</button>'
      +'<button onclick="_finEditarDespCaso('+cid+',\''+l.id+'\')" style="font-size:10px;padding:3px 8px;border-radius:4px;background:rgba(212,175,55,.1);border:1px solid rgba(212,175,55,.3);color:#D4AF37;cursor:pointer">\u270f</button>'
      +'<button onclick="finDelLanc('+cid+',\''+l.id+'\')" style="font-size:10px;padding:3px 6px;border-radius:4px;background:var(--sf3);border:1px solid rgba(201,72,74,.3);color:#c9484a;cursor:pointer">\u2715</button>'
    +'</div>';
  });
  return html+'</div>';
}

// ── TOGGLE TIPO DESPESA (reembolsável ↔ custo interno) ──
function _finToggleTipoDesp(cid, lid){
  var i = (localLanc||[]).findIndex(function(l){return String(l.id)===String(lid);});
  if(i===-1) return;
  localLanc[i].tipo = localLanc[i].tipo==='despint' ? 'despesa' : 'despint';
  sbSet('co_localLanc', localLanc);
  marcarAlterado();
  _finLocaisCache = {};
  _finTab(_finCurTab, cid, null);
  showToast('Tipo alterado para '+(localLanc[i].tipo==='despint'?'custo interno':'reembols\u00e1vel'));
}

// ── EDITAR DESPESA DO CASO ──
function _finEditarDespCaso(cid, lid){
  var i = (localLanc||[]).findIndex(function(l){return String(l.id)===String(lid);});
  if(i===-1){ showToast('N\u00e3o encontrado'); return; }
  var l = localLanc[i];
  var hoje = new Date().toISOString().slice(0,10);
  var tipoLabels = {custa:'Custa',diligencia:'Dilig\u00eancia',deslocamento:'Deslocamento',copia:'C\u00f3pia',emolumento:'Emolumento',operacional:'Operacional',outro:'Outro'};
  var tipoOpts = Object.keys(tipoLabels).map(function(k){return '<option value="'+k+'"'+(k===(l.tipo_despesa||'outro')?' selected':'')+'>'+tipoLabels[k]+'</option>';}).join('');
  abrirModal('\u270f Editar Despesa',
    '<div class="fm-row"><div style="flex:2"><label class="fm-lbl">Descri\u00e7\u00e3o</label><input class="fm-inp" id="edc-desc" value="'+escapeHtml(l.desc||'')+'"></div></div>'
    +'<div class="fm-row">'
      +'<div><label class="fm-lbl">Valor (R$)</label><input class="fm-inp" type="number" id="edc-valor" value="'+(l.valor||0)+'" min="0.01" step="0.01"></div>'
      +'<div><label class="fm-lbl">Data</label><input class="fm-inp" type="date" id="edc-data" value="'+(l.data||hoje)+'"></div>'
    +'</div>'
    +'<div class="fm-row">'
      +'<div><label class="fm-lbl">Tipo</label><select class="fm-inp" id="edc-tipo">'+tipoOpts+'</select></div>'
      +'<div><label class="fm-lbl">Forma</label><select class="fm-inp" id="edc-forma"><option>PIX</option><option>Dinheiro</option><option>Cart\u00e3o</option><option>Boleto</option><option>TED</option></select></div>'
    +'</div>'
    +'<div class="fm-row">'
      +'<div style="display:flex;align-items:center;gap:6px"><input type="checkbox" id="edc-reimb" '+(l.tipo!=='despint'?'checked':'')+'><label for="edc-reimb" style="font-size:11px;color:var(--tx)">Reembols\u00e1vel</label></div>'
      +'<div><label class="fm-lbl">Pago por</label><input class="fm-inp" id="edc-pago" value="'+escapeHtml(l.pago_por||'')+'"></div>'
    +'</div>'
    +'<div class="fm-row"><div style="flex:2"><label class="fm-lbl">Observa\u00e7\u00e3o</label><input class="fm-inp" id="edc-obs" value="'+escapeHtml(l.obs||'')+'"></div></div>',
  function(){
    var desc = (document.getElementById('edc-desc')?.value||'').trim();
    var valor = parseFloat(document.getElementById('edc-valor')?.value)||0;
    if(!desc||valor<=0){ showToast('Preencha descri\u00e7\u00e3o e valor'); return; }
    localLanc[i].desc = desc;
    localLanc[i].valor = valor;
    localLanc[i].data = document.getElementById('edc-data')?.value||hoje;
    localLanc[i].tipo_despesa = document.getElementById('edc-tipo')?.value||'outro';
    localLanc[i].forma = document.getElementById('edc-forma')?.value||'';
    localLanc[i].tipo = document.getElementById('edc-reimb')?.checked ? 'despesa' : 'despint';
    localLanc[i].pago_por = (document.getElementById('edc-pago')?.value||'').trim();
    localLanc[i].obs = (document.getElementById('edc-obs')?.value||'').trim();
    sbSet('co_localLanc', localLanc);
    marcarAlterado(); fecharModal();
    _finLocaisCache = {};
    _reRenderFinPasta(cid);
    showToast('Despesa atualizada \u2713');
  }, '\ud83d\udcbe Salvar');
  setTimeout(function(){
    var sf = document.getElementById('edc-forma'); if(sf&&l.forma) sf.value=l.forma;
  }, 100);
}

// ── ABA REPASSES + DADOS BANCÁRIOS ──
function _finRepassesBancoTab(cid, c, locais, fV, hoje){
  var cls = _finClassificar2(locais);
  var ex = c.extra||{};
  var dadosBanc = getDadosBancarios(c.cliente);

  // ── SEÇÃO 1: DADOS BANCÁRIOS ──
  var html = '<div style="padding:10px 0">'
    +'<div style="font-size:12px;font-weight:700;color:var(--tx);margin-bottom:10px">Dados Banc\u00e1rios do Cliente</div>'
    +'<div style="background:var(--sf2);border:1px solid var(--bd);border-radius:8px;padding:14px;margin-bottom:16px">'
      +'<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(180px,1fr));gap:8px">'
        +'<div><label class="fm-lbl">Nome favorecido</label><input class="fm-inp" id="rb-nome-'+cid+'" value="'+escapeHtml(ex.nomebenef||c.cliente||'')+'"></div>'
        +'<div><label class="fm-lbl">Banco</label><input class="fm-inp" id="rb-banco-'+cid+'" value="'+escapeHtml(ex.banco||'')+'"></div>'
        +'<div><label class="fm-lbl">Ag\u00eancia</label><input class="fm-inp" id="rb-ag-'+cid+'" value="'+escapeHtml(ex.ag||'')+'"></div>'
        +'<div><label class="fm-lbl">Conta</label><input class="fm-inp" id="rb-conta-'+cid+'" value="'+escapeHtml(ex.conta||'')+'"></div>'
        +'<div><label class="fm-lbl">Tipo conta</label><input class="fm-inp" id="rb-tconta-'+cid+'" value="'+escapeHtml(ex.tconta||'')+'" placeholder="Corrente, Poupan\u00e7a..."></div>'
        +'<div><label class="fm-lbl">Chave PIX</label><input class="fm-inp" id="rb-pix-'+cid+'" value="'+escapeHtml(ex.pix||'')+'"></div>'
        +'<div><label class="fm-lbl">CPF/CNPJ</label><input class="fm-inp" id="rb-cpf-'+cid+'" value="'+escapeHtml(ex.cpfbenef||'')+'"></div>'
        +'<div><label class="fm-lbl">Observa\u00e7\u00f5es</label><input class="fm-inp" id="rb-obs-'+cid+'" value="'+escapeHtml(ex.obs_banco||'')+'"></div>'
      +'</div>'
      +'<div style="margin-top:10px"><button onclick="_finSalvarBanco('+cid+')" style="font-size:11px;font-weight:700;padding:6px 14px;border-radius:6px;background:rgba(76,175,125,.12);border:1px solid rgba(76,175,125,.3);color:#4ade80;cursor:pointer">\ud83d\udcbe Salvar dados banc\u00e1rios</button></div>'
    +'</div>';

  // ── SEÇÃO 2: REPASSES ──
  html += '<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:10px">'
    +'<div style="font-size:12px;font-weight:700;color:var(--tx)">Repasses</div>'
    +'<button onclick="_finGerarRepasse('+cid+')" style="font-size:11px;font-weight:700;padding:5px 12px;border-radius:6px;background:rgba(201,72,74,.1);border:1px solid rgba(201,72,74,.3);color:#c9484a;cursor:pointer">\ud83d\udce4 Gerar Repasse</button>'
  +'</div>';

  if(!cls.repasses.length){
    html += '<div style="padding:20px;text-align:center;color:var(--mu);font-style:italic">Nenhum repasse registrado.</div>';
  } else {
    cls.repasses.sort(function(a,b){return (b.data||'').localeCompare(a.data||'');}).forEach(function(l){
      var pago = isRec(l);
      html += '<div style="display:flex;align-items:center;gap:10px;padding:8px 0;border-bottom:1px solid var(--bd)">'
        +'<div style="flex:1"><div style="font-size:12px;font-weight:600;color:var(--tx)">'+escapeHtml(l.desc||'Repasse')+'</div>'
          +'<div style="font-size:10px;color:var(--mu)">'+fDt(l.data)+(l.forma?' \u00b7 '+l.forma:'')+(l.conta?' \u00b7 '+l.conta:'')+(l.dt_baixa?' \u00b7 Pago '+fDt(l.dt_baixa):'')+(l.obs?' \u00b7 '+escapeHtml(l.obs):'')+'</div></div>'
        +'<span style="font-size:10px;font-weight:700;color:'+(pago?'#4ade80':'#c9484a')+'">'+(pago?'\u2713 Pago':'\u23f3 Pendente')+'</span>'
        +'<span style="font-size:13px;font-weight:700;color:#c9484a">'+fV(l.valor)+'</span>'
        +(!pago?'<button onclick="vfBaixar(\'l'+l.id+'\')" style="font-size:10px;padding:3px 8px;border-radius:4px;background:rgba(201,72,74,.1);border:1px solid rgba(201,72,74,.3);color:#c9484a;cursor:pointer">\u2713 Pagar</button>':'')
        +'<button onclick="finDelLanc('+cid+',\''+l.id+'\')" style="font-size:10px;padding:3px 6px;border-radius:4px;background:var(--sf3);border:1px solid rgba(201,72,74,.3);color:#c9484a;cursor:pointer">\u2715</button>'
      +'</div>';
    });
  }

  // ── SEÇÃO 3: WHATSAPP ──
  html += '<div style="margin-top:16px"><button onclick="_finCopiarPrestacao('+cid+')" style="font-size:11px;font-weight:700;padding:6px 14px;border-radius:6px;background:rgba(37,211,102,.1);border:1px solid rgba(37,211,102,.3);color:#4ade80;cursor:pointer">\ud83d\udcf2 Copiar presta\u00e7\u00e3o de contas (WhatsApp)</button></div>';

  return html+'</div>';
}

// ── GERAR REPASSE ──
function _finGerarRepasse(cid){
  var c = findClientById(cid);
  if(!c) return;
  var locais = _finGetLocais(cid);
  var cls = _finClassificar2(locais);
  var totCli = 0;
  cls.honorarios.forEach(function(l){
    var calc = _finCalcLanc(l);
    if(isRec(l)) totCli += calc.valor_cliente;
  });
  var jaRep = cls.repasses.filter(function(l){return isRec(l);}).reduce(function(s,l){return s+(parseFloat(l.valor)||0);},0);
  var saldo = roundMoney(Math.max(0, totCli - jaRep));
  if(saldo <= 0){ showToast('Nenhum repasse pendente'); return; }
  var fV2 = function(v){return 'R$ '+Math.abs(v||0).toLocaleString('pt-BR',{minimumFractionDigits:2,maximumFractionDigits:2});};
  var dadosBanc = getDadosBancarios(c.cliente);
  var bancHtml = dadosBanc
    ? '<div style="background:rgba(96,165,250,.06);border:1px solid rgba(96,165,250,.2);border-radius:6px;padding:10px 12px;margin-bottom:12px">'
      +'<div style="font-size:9px;font-weight:700;text-transform:uppercase;color:#60a5fa;margin-bottom:4px">Dados banc\u00e1rios</div>'
      +'<div style="font-size:11px;color:var(--tx)">'
        +(dadosBanc.nomebenef||'')+(dadosBanc.banco?' \u00b7 '+dadosBanc.banco:'')+(dadosBanc.pix?'<br>PIX: <strong>'+escapeHtml(dadosBanc.pix)+'</strong>':'')
      +'</div></div>'
    : '';
  abrirModal('\ud83d\udce4 Gerar Repasse \u2014 '+escapeHtml(c.cliente),
    '<div style="background:var(--sf3);border-radius:8px;padding:12px;margin-bottom:12px">'
      +'<div style="font-size:11px;color:var(--mu)">Valor do cliente (recebido): <strong style="color:#60a5fa">'+fV2(totCli)+'</strong></div>'
      +'<div style="font-size:11px;color:var(--mu)">J\u00e1 repassado: '+fV2(jaRep)+'</div>'
      +'<div style="font-size:11px;color:var(--mu)">Saldo a repassar: <strong style="color:#c9484a">'+fV2(saldo)+'</strong></div>'
    +'</div>'
    +bancHtml
    +'<div class="fm-row">'
      +'<div><label class="fm-lbl">Valor do repasse (R$)</label><input class="fm-inp" type="number" id="rep-valor" value="'+saldo.toFixed(2)+'" min="0.01" step="0.01"></div>'
      +'<div><label class="fm-lbl">Data</label><input class="fm-inp" type="date" id="rep-data" value="'+new Date().toISOString().slice(0,10)+'"></div>'
    +'</div>'
    +'<div class="fm-row" style="margin-top:8px">'
      +'<div><label class="fm-lbl">Forma de envio</label><select class="fm-inp" id="rep-conta"><option>PIX</option><option>TED</option><option>Dep\u00f3sito</option><option>Dinheiro</option></select></div>'
      +'<div><label class="fm-lbl">Observa\u00e7\u00e3o</label><input class="fm-inp" id="rep-obs" placeholder="Comprovante, refer\u00eancia..."></div>'
    +'</div>',
  function(){
    var val = parseFloat(document.getElementById('rep-valor')?.value)||0;
    var data = document.getElementById('rep-data')?.value||new Date().toISOString().slice(0,10);
    var conta = document.getElementById('rep-conta')?.value||'';
    var obs = (document.getElementById('rep-obs')?.value||'').trim();
    if(val <= 0){ showToast('Informe o valor'); return; }
    if(val > saldo + 0.01){ showToast('Valor excede o saldo ('+fV2(saldo)+')'); return; }
    localLanc.push({
      id: genId(), tipo:'repasse', direcao:'pagar',
      id_processo: cid, cliente: c.cliente,
      desc:'Repasse ao cliente', valor: roundMoney(val),
      data:data, venc:data, status:'pago', pago:true, dt_baixa:data,
      forma:conta, conta:conta, obs:obs, _repasse_acordo:true
    });
    sbSet('co_localLanc', localLanc);
    marcarAlterado(); fecharModal();
    _finLocaisCache = {};
    _reRenderFinPasta(cid);
    var comprovante = '*COMPROVANTE DE REPASSE*\nCliente: '+c.cliente+'\nData: '+fDt(data)+'\nValor: '+fV2(val)+'\nForma: '+(conta||'\u2014')+'\n'+(obs?'Ref: '+obs+'\n':'')+'\n_CO Advocacia_';
    navigator.clipboard.writeText(comprovante).then(function(){
      showToast('\u2713 Repasse de '+fV2(val)+' registrado. Comprovante copiado!');
    }).catch(function(){
      showToast('\u2713 Repasse de '+fV2(val)+' registrado');
    });
  }, '\ud83d\udce4 Confirmar Repasse');
}

// ── SALVAR DADOS BANCÁRIOS ──
function _finSalvarBanco(cid){
  var c = findClientById(cid);
  if(!c) return;
  if(!c.extra) c.extra = {};
  c.extra.nomebenef = document.getElementById('rb-nome-'+cid)?.value||'';
  c.extra.banco = document.getElementById('rb-banco-'+cid)?.value||'';
  c.extra.ag = document.getElementById('rb-ag-'+cid)?.value||'';
  c.extra.conta = document.getElementById('rb-conta-'+cid)?.value||'';
  c.extra.tconta = document.getElementById('rb-tconta-'+cid)?.value||'';
  c.extra.pix = document.getElementById('rb-pix-'+cid)?.value||'';
  c.extra.cpfbenef = document.getElementById('rb-cpf-'+cid)?.value||'';
  c.extra.obs_banco = document.getElementById('rb-obs-'+cid)?.value||'';
  sbSet('co_clientes', CLIENTS);
  marcarAlterado();
  showToast('Dados banc\u00e1rios salvos \u2713');
}

// ── COPIAR PRESTAÇÃO DE CONTAS ──
function _finCopiarPrestacao(cid){
  var c = findClientById(cid);
  if(!c) return;
  var locais = _finGetLocais(cid);
  var cls = _finClassificar2(locais);
  var fV2 = function(v){return 'R$ '+Math.abs(v||0).toLocaleString('pt-BR',{minimumFractionDigits:2,maximumFractionDigits:2});};
  var totHon=0, totLiq=0, totCli=0, totRec=0, totBase=0;
  cls.honorarios.forEach(function(l){
    var calc = _finCalcLanc(l);
    totHon += calc.honorarios_contratuais;
    totLiq += calc.honorarios_liquidos_escritorio;
    totCli += calc.valor_cliente;
    totBase += calc.base_calculo;
    if(isRec(l)) totRec += calc.base_calculo;
  });
  var totDesp = cls.despesas.reduce(function(s,l){return s+(parseFloat(l.valor)||0);},0);
  var totRepPago = cls.repasses.filter(function(l){return isRec(l);}).reduce(function(s,l){return s+(parseFloat(l.valor)||0);},0);
  var dadosBanc = getDadosBancarios(c.cliente);
  var bancTxt = dadosBanc ? formatarDadosBancarios(dadosBanc) : '';

  var msg = '*PRESTA\u00c7\u00c3O DE CONTAS*\n'
    +'Cliente: '+c.cliente+'\n'
    +(c.numero?'Processo: '+c.numero+'\n':'')
    +'\nValor total lan\u00e7ado: '+fV2(totBase)
    +'\nHonor\u00e1rios contratuais: '+fV2(totHon)
    +'\nL\u00edquido escrit\u00f3rio: '+fV2(totLiq)
    +'\nValor do cliente: '+fV2(totCli)
    +'\nRecebido efetivamente: '+fV2(totRec)+(totRec<totBase?' (pendente: '+fV2(totBase-totRec)+')':'')
    +'\nDespesas: '+fV2(totDesp)
    +'\nRepasses pagos: '+fV2(totRepPago)
    +(bancTxt?'\n\n'+bancTxt:'')
    +'\n\n_CO Advocacia_';

  navigator.clipboard.writeText(msg).then(function(){
    showToast('\u2713 Presta\u00e7\u00e3o copiada para WhatsApp!');
  }).catch(function(){});
}
// ── HISTÓRICO FINANCEIRO ──
function _finHistoricoTab(cid, c, locais, fV, hoje){
  var eventos = [];
  locais.forEach(function(l){
    var pago = isRec(l);
    var isRep = l._repasse_acordo||l._repasse_alvara||l.tipo==='repasse';
    var isDesp = l.tipo==='despesa'||l.tipo==='despint'||l.tipo==='despesa_reimb';
    var isSucumb = l.tipo==='sucumbencia';
    var tipo = isRep?'repasse':isDesp?'despesa':isSucumb?'sucumbencia':'parcela';
    var dt = l.data||l.venc||'';
    eventos.push({dt:dt, tipo:tipo, desc:l.desc||'\u2014', valor:l.valor||0, status:pago?'pago':'pendente', id:l.id});
    if(pago && l.dt_baixa && l.dt_baixa!==dt){
      eventos.push({dt:l.dt_baixa, tipo:tipo+'_baixa', desc:'Baixa: '+(l.desc||'\u2014'), valor:l.valor||0, status:'baixa', id:l.id});
    }
  });
  eventos.sort(function(a,b){return (b.dt||'').localeCompare(a.dt||'');});
  if(!eventos.length) return '<div style="padding:20px;text-align:center;color:var(--mu)">Nenhum evento registrado.</div>';
  var icoMap = {parcela:'\ud83d\udcb0',despesa:'\ud83d\udcb8',repasse:'\ud83d\udce4',sucumbencia:'\ud83c\udfc6',parcela_baixa:'\u2713',despesa_baixa:'\u2713',repasse_baixa:'\u2713',sucumbencia_baixa:'\u2713'};
  var html = '<div style="padding:10px 0">';
  eventos.forEach(function(e){
    var ico = icoMap[e.tipo]||'\ud83d\udccb';
    var cor = e.tipo.includes('repasse')?'#c9484a':e.tipo.includes('despesa')?'#f87676':e.tipo.includes('sucumb')?'#4ade80':'var(--tx)';
    html += '<div style="display:flex;align-items:center;gap:10px;padding:6px 0;border-bottom:1px solid var(--bd)">'
      +'<span style="font-size:14px">'+ico+'</span>'
      +'<div style="flex:1"><div style="font-size:11px;color:var(--tx)">'+escapeHtml(e.desc)+'</div>'
        +'<div style="font-size:9px;color:var(--mu)">'+fDt(e.dt)+' \u00b7 '+e.status+'</div></div>'
      +'<span style="font-size:12px;font-weight:700;color:'+cor+'">'+fV(e.valor)+'</span>'
    +'</div>';
  });
  return html+'</div>';
}
function _finInitTab(cid){
  _finCurTab = 'resumo';
  _finTab('resumo', cid, null);
  var nav = document.getElementById('fin-nav-'+cid);
  if(nav){
    var btns = nav.querySelectorAll('.fin-nav-btn');
    btns.forEach(function(b){b.classList.remove('on');});
    if(btns[0]) btns[0].classList.add('on');
  }
}
// ── Render financeiro na ficha do processo ──
function renderFinLocal(cid){
  const locais = (localLanc||[]).filter(function(l){return Number(l.id_processo)===Number(cid);});
  if(!locais.length) return '<div style="font-size:12px;color:var(--mu);padding:10px 0;font-style:italic">Nenhum lançamento. Clique em + Novo lançamento.</div>';

  const hoje = new Date().toISOString().slice(0,10);
  const fmtV = function(v,pos){
    var s = (pos?'+':'-')+' R$ '+Math.abs(v||0).toLocaleString('pt-BR',{minimumFractionDigits:2,maximumFractionDigits:2});
    return '<span style="color:'+(pos?'#4ade80':'#f87676')+'">'+s+'</span>';
  };

  const isPos = function(l){ return l.tipo!=='repasse'&&l.tipo!=='despesa'&&l.tipo!=='despint'&&l.direcao!=='pagar'; };

  const sorted = locais.slice().sort(function(a,b){return (b.data||b.venc||'').localeCompare(a.data||a.venc||'');});

  var rows = sorted.map(function(l){
    const pos = isPos(l);
    const isPago = isRec(l);
    const vencido = !isPago&&(l.venc||l.data)&&(l.venc||l.data)<hoje;
    const statusCor = isPago?'#4ade80':vencido?'#c9484a':'#f59e0b';
    const statusTxt = isPago?'PAGO':vencido?'VENCIDO':'PENDENTE';
    const tipo = (l.tipo||'outro').replace(/_/g,' ');
    const sub = [l.forma?'via '+l.forma:'', l.parcela?l.parcela:'', l.obs||''].filter(Boolean).join(' · ');
    const acoes = isPago
      ? '<span style="font-size:10px;color:#4ade80">'+statusTxt+(l.dt_baixa?' em '+fDt(l.dt_baixa):'')+'</span>'
      : '<div style="display:flex;gap:6px;flex-wrap:wrap">'
          +'<button onclick="vfBaixar(&quot;l'+l.id+'&quot;)" style="font-size:11px;font-weight:600;padding:5px 10px;border-radius:5px;background:rgba(76,175,125,.12);border:1px solid rgba(76,175,125,.3);color:#4ade80;cursor:pointer">'+(pos?'✓ Receber':'✓ Pagar')+'</button>'
          +'<button onclick="finEditarLanc('+cid+','+JSON.stringify(l.id)+')" style="font-size:11px;padding:5px 8px;border-radius:5px;background:var(--sf3);border:1px solid var(--bd);color:var(--mu);cursor:pointer">✏</button>'
          +'<button onclick="finDelLanc('+cid+',\''+l.id+'\')" style="font-size:11px;padding:5px 8px;border-radius:5px;background:rgba(201,72,74,.08);border:1px solid rgba(201,72,74,.3);color:#c9484a;cursor:pointer">✕</button>'
        +'</div>';
    return '<div style="display:flex;align-items:center;gap:10px;padding:9px 0;border-bottom:1px solid var(--bd)">'
      +'<div style="flex:1;min-width:0">'
        +'<div style="display:flex;align-items:center;gap:6px;margin-bottom:2px">'
          +'<span style="font-size:9px;font-weight:700;text-transform:uppercase;letter-spacing:.06em;padding:1px 6px;border-radius:4px;background:var(--sf3);color:var(--mu)">'+tipo+'</span>'
          +'<span style="font-size:12px;font-weight:600;color:var(--tx)">'+escapeHtml(l.desc||'—')+'</span>'
        +'</div>'
        +(sub?'<div style="font-size:10px;color:var(--mu);margin-bottom:4px">'+escapeHtml(sub)+'</div>':'')
        +acoes
      +'</div>'
      +'<div style="text-align:right;flex-shrink:0;min-width:90px">'
        +'<div style="font-size:14px;font-weight:800">'+fmtV(l.valor,pos)+'</div>'
        +'<div style="font-size:10px;color:'+statusCor+';font-weight:600;margin-top:2px">'+statusTxt+'</div>'
        +'<div style="font-size:10px;color:var(--mu)">'+fDt(l.venc||l.data)+'</div>'
      +'</div>'
    +'</div>';
  }).join('');

  return rows;
}

function finDelLanc(cid, lid){
  // Delega para vfDelLocal que já tem modal de confirmação, audit e re-render completo
  vfDelLocal('l'+String(lid));
}

function finEditarLanc(cid, lid){
  var l = (localLanc||[]).find(function(x){return x.id_processo===cid && String(x.id)===String(lid);});
  if(!l){ showToast('Lançamento não encontrado'); return; }
  var fmtDt = function(d){return d||'';};
  var fmtV2 = function(v){return Math.abs(v||0).toFixed(2);};

  abrirModal('✏ Editar — '+escapeHtml(l.desc||''),
    '<div class="fm-row">'
      +'<div style="flex:2"><label class="fm-lbl">Descrição *</label>'
        +'<input class="fm-inp" id="fel-desc" value="'+escapeHtml((l.desc||'').replace(/"/g,'&quot;'))+'"></div>'
      +'<div><label class="fm-lbl">Tipo</label>'
        +'<select class="fm-inp" id="fel-tipo">'
          +'<option value="honorario"'+(l.tipo==='honorario'?' selected':'')+'>Honorários</option>'
          +'<option value="acordo"'+(l.tipo==='acordo'?' selected':'')+'>Acordo</option>'
          +'<option value="sucumbencia"'+(l.tipo==='sucumbencia'?' selected':'')+'>Sucumbência</option>'
          +'<option value="repasse"'+(l.tipo==='repasse'?' selected':'')+'>Repasse</option>'
          +'<option value="despesa"'+(l.tipo==='despesa'?' selected':'')+'>Despesa reimb.</option>'
          +'<option value="outro"'+(l.tipo==='outro'?' selected':'')+'>Outro</option>'
        +'</select></div>'
    +'</div>'
    +'<div class="fm-row">'
      +'<div><label class="fm-lbl">Valor líquido (R$) *</label>'
        +'<input class="fm-inp" type="number" id="fel-valor" value="'+fmtV2(l.valor)+'" step="0.01" min="0"></div>'
      +'<div><label class="fm-lbl">Valor bruto (R$)</label>'
        +'<input class="fm-inp" type="number" id="fel-vbruto" value="'+fmtV2(l._vbruto||l.valor)+'" step="0.01" min="0"></div>'
      +'<div><label class="fm-lbl">Hon. %</label>'
        +'<input class="fm-inp" type="number" id="fel-honperc" value="'+(l._honperc||100)+'" min="0" max="100" step="0.5"></div>'
    +'</div>'
    +'<div class="fm-row">'
      +'<div><label class="fm-lbl">Data</label>'
        +'<input class="fm-inp" type="date" id="fel-data" value="'+fmtDt(l.data||l.venc)+'"></div>'
      +'<div><label class="fm-lbl">Vencimento</label>'
        +'<input class="fm-inp" type="date" id="fel-venc" value="'+fmtDt(l.venc||l.data)+'"></div>'
      +'<div><label class="fm-lbl">Status</label>'
        +'<select class="fm-inp" id="fel-status">'
          +'<option value="pendente"'+((!l.pago&&l.status!=='pago')?' selected':'')+'>Pendente</option>'
          +'<option value="pago"'+((isRec(l))?' selected':'')+'>Pago / Recebido</option>'
        +'</select></div>'
    +'</div>'
    +'<div class="fm-row">'
      +'<div><label class="fm-lbl">Parcela tipo</label>'
        +'<select class="fm-inp" id="fel-tipo-parc">'
          +'<option value="unica"'+(l._tipo_parc==='unica'?' selected':'')+'>Única</option>'
          +'<option value="parcelado"'+(l._tipo_parc==='parcelado'?' selected':'')+'>Parcelado</option>'
          +'<option value="sucumbencia"'+(l._tipo_parc==='sucumbencia'?' selected':'')+'>Sucumbência</option>'
          +'<option value="mensalidade"'+(l._tipo_parc==='mensalidade'?' selected':'')+'>Mensalidade</option>'
        +'</select></div>'
      +'<div><label class="fm-lbl">Parcela N</label>'
        +'<input class="fm-inp" type="number" id="fel-parc-n" value="'+(l._parcela||1)+'" min="1"></div>'
      +'<div><label class="fm-lbl">De total</label>'
        +'<input class="fm-inp" type="number" id="fel-parc-tot" value="'+(l._total_parc||1)+'" min="1"></div>'
    +'</div>'
    +'<div class="fm-row">'
      +'<div style="flex:2"><label class="fm-lbl">Parceiro</label>'
        +'<input class="fm-inp" id="fel-parceiro" value="'+escapeHtml(l._parceiro||'')+'" placeholder="Nome do parceiro (ou vazio)"></div>'
      +'<div><label class="fm-lbl">% parceiro</label>'
        +'<input class="fm-inp" type="number" id="fel-parc-perc" value="'+(l._parceiro_perc||0)+'" min="0" max="100"></div>'
    +'</div>'
    +'<div><label class="fm-lbl">Observação</label>'
      +'<input class="fm-inp" id="fel-obs" value="'+escapeHtml(l.obs||'').replace(/"/g,'&quot;')+'" placeholder="Opcional"></div>',
  function(){
    var valLiq  = parseFloat(document.getElementById('fel-valor')?.value||0);
    var vbruto  = parseFloat(document.getElementById('fel-vbruto')?.value||0);
    var honperc = parseFloat(document.getElementById('fel-honperc')?.value||100);
    var pNome   = document.getElementById('fel-parceiro')?.value?.trim()||'';
    var pPerc   = parseFloat(document.getElementById('fel-parc-perc')?.value||0);
    var pVal    = pNome ? roundMoney(valLiq*(pPerc/100)) : 0;
    var statusV = document.getElementById('fel-status')?.value||'pendente';
    var dataV   = document.getElementById('fel-data')?.value||'';
    if(!valLiq){ showToast('Informe o valor'); return; }

    var i = localLanc.findIndex(function(x){return x.id_processo===cid && String(x.id)===String(lid);});
    if(i===-1){ showToast('Não encontrado'); return; }
    localLanc[i] = Object.assign({},localLanc[i],{
      desc:   document.getElementById('fel-desc')?.value?.trim()||localLanc[i].desc,
      tipo:   document.getElementById('fel-tipo')?.value||localLanc[i].tipo,
      valor:  valLiq,
      data:   dataV,
      venc:   document.getElementById('fel-venc')?.value||dataV,
      pago:   statusV==='pago',
      status: statusV,
      dt_baixa: statusV==='pago'?(localLanc[i].dt_baixa||dataV):'',
      obs:    document.getElementById('fel-obs')?.value||'',
      _vbruto:    vbruto,
      _honperc:   honperc,
      _tipo_parc: document.getElementById('fel-tipo-parc')?.value||'unica',
      _parcela:   parseInt(document.getElementById('fel-parc-n')?.value||1),
      _total_parc:parseInt(document.getElementById('fel-parc-tot')?.value||1),
      _parceiro:  pNome,
      _parceiro_perc: pPerc,
      _parceiro_val:  pVal,
      updated_at: new Date().toISOString(),
    });
    sbSet('co_localLanc', localLanc);
    marcarAlterado(); fecharModal();
    _reRenderFinPasta(cid);
    if(document.getElementById('vf')?.classList.contains('on')) vfRender();
    showToast('✓ Lançamento atualizado');
  }, '💾 Salvar alterações');
}

// ═══════════════════════════════════════════════════
// ── NOVO PROCESSO DIRETO ──
// ═══════════════════════════════════════════════════
function finBaixarLanc(cid, lid, direcao){
  const hoje = new Date().toISOString().slice(0,10);
  const label = direcao==='receber' ? 'Recebimento' : 'Pagamento';

  // Resolver lançamento — pode ser Projuris (FIN_XLSX) ou local (localLanc/finLancs)
  const isProjuris = String(lid).startsWith('p');
  const isGlobal   = String(lid).startsWith('g');
  let lanc = null;
  let localIdx = -1;

  if(isProjuris){
    // id = 'p' + l.id original
    const origId = String(lid).slice(1);
    const xlxIdx = (FIN_XLSX||[]).findIndex(function(l){ return String(l.id)===origId; });
    if(xlxIdx !== -1) lanc = {
      id: lid, desc: FIN_XLSX[xlxIdx].desc||'—',
      valor: FIN_XLSX[xlxIdx].val||0, forma: FIN_XLSX[xlxIdx].forma||'',
      obs: FIN_XLSX[xlxIdx].obs||'', cliente: FIN_XLSX[xlxIdx].pasta||'',
      _xlxIdx: xlxIdx, origem:'projuris'
    };
  } else if(isGlobal){
    // id = 'g' + l.id original
    const origId = String(lid).slice(1);
    const fIdx = (finLancs||[]).findIndex(function(l){ return String(l.id)===origId; });
    if(fIdx !== -1) lanc = {
      id: lid, desc: finLancs[fIdx].desc||'—',
      valor: parseFloat(finLancs[fIdx].valor)||0, forma: finLancs[fIdx].forma||'',
      obs: finLancs[fIdx].obs||'', cliente: finLancs[fIdx].cliente||'Escritório',
      _fIdx: fIdx, origem:'global'
    };
  } else {
    localIdx = (localLanc||[]).findIndex(function(l){ return l.id===lid||String(l.id)===String(lid); });
    if(localIdx !== -1) lanc = { ...localLanc[localIdx], origem:'local' };
  }

  if(!lanc){ showToast('Lançamento não encontrado'); return; }

  abrirModal('Dar Baixa — '+label,
    '<div style="margin-bottom:8px;padding:10px 12px;background:var(--sf3);border-radius:8px">'
      +'<div style="font-size:11px;color:var(--mu);margin-bottom:4px">'+(isProjuris?'Projuris · Pasta '+lanc.cliente:lanc.cliente||'')+'</div>'
      +'<div style="font-size:13px;font-weight:600;color:var(--tx)">'+(lanc.desc||'Lançamento')+'</div>'
      +'<div style="font-size:24px;font-weight:800;color:'+(direcao==='receber'?'#4ade80':'#f87676')+';margin-top:4px">'
        +fBRL(lanc.valor||0)+'</div>'
    +'</div>'
    +'<div class="fm-row" style="margin-top:10px">'
      +'<div><label class="fm-lbl">Data da baixa</label>'
        +'<input class="fm-inp" type="date" id="fb-data" value="'+hoje+'"></div>'
      +'<div><label class="fm-lbl">Forma de pagamento</label>'
        +'<select class="fm-inp" id="fb-forma">'
          +'<option value="">—</option>'
          +'<option>PIX</option><option>TED / Depósito</option>'
          +'<option>Boleto</option><option>Dinheiro</option>'
          +'<option>Cheque</option><option>Cartão de Crédito</option>'
          +'<option>Cartão de Débito</option><option>Alvará judicial</option>'
        +'</select>'
      +'</div>'
    +'</div>'
    +'<div style="margin-top:8px"><label class="fm-lbl">Observação (opcional)</label>'
      +'<input class="fm-inp" id="fb-obs" placeholder="Comprovante, referência, nº alvará..."></div>',
  function(){
    const dtBaixa = document.getElementById('fb-data')?.value||hoje;
    const forma   = document.getElementById('fb-forma')?.value||'';
    const obs     = document.getElementById('fb-obs')?.value.trim()||'';

    if(isProjuris){
      // 1. Marcar no FIN_XLSX (in-memory — dados do arquivo)
      const xlxIdx = lanc._xlxIdx;
      FIN_XLSX[xlxIdx].status = 'pago';
      FIN_XLSX[xlxIdx].dt_pago = dtBaixa;
      FIN_XLSX[xlxIdx].forma = forma;
      // 2. Criar registro em localLanc para persistir a baixa no Supabase
      const existing = (localLanc||[]).findIndex(function(l){ return l.proj_ref===String(lid); });
      const baixaReg = {
        id: 'baixa_'+lid+'_'+genId(),
        proj_ref: String(lid),
        desc: lanc.desc, valor: lanc.valor,
        tipo: direcao==='receber'?'honorario':'despesa',
        direcao: direcao,
        status: 'pago', pago: true,
        data: dtBaixa, dt_baixa: dtBaixa,
        forma: forma, obs: obs,
        cliente: lanc.cliente, origem_proj: true
      };
      if(existing === -1) localLanc.push(baixaReg);
      else localLanc[existing] = baixaReg;
      sbSet('co_localLanc', localLanc);
      // 3. Andamento na pasta do cliente
      const c = CLIENTS.find(function(x){ return String(x.pasta)===String(lanc.cliente); });
      const clienteId = c ? c.id : null;
      if(clienteId){
        if(!localMov[clienteId]) localMov[clienteId]=[];
        localMov[clienteId].unshift({
          data: dtBaixa,
          movimentacao: '[Financeiro] '+label+' Projuris baixado: '+lanc.desc+' — '+fBRL(lanc.valor)+(forma?' via '+forma:''),
          tipo_movimentacao:'Financeiro', origem:'baixa_projuris'
        });
        sbSet('co_localMov', localMov);
        _reRenderFinPasta(clienteId);
      }
    } else if(isGlobal){
      // Global (finLancs)
      const fIdx = lanc._fIdx;
      finLancs[fIdx] = { ...finLancs[fIdx], pago:true, status:'pago', dt_baixa:dtBaixa, forma:forma };
      sbSet('co_fin', finLancs);
    } else {
      // Local (localLanc)
      localLanc[localIdx] = {
        ...localLanc[localIdx],
        status:'pago', pago:true, dt_baixa:dtBaixa,
        forma: forma||lanc.forma||'',
        obs: obs?(lanc.obs?lanc.obs+' | '+obs:obs):(lanc.obs||'')
      };
      sbSet('co_localLanc', localLanc);
      if(cid){
        if(!localMov[cid]) localMov[cid]=[];
        localMov[cid].unshift({
          data: dtBaixa,
          movimentacao: '[Financeiro] '+label+' baixado: '+(lanc.desc||'')+' — '+fBRL(lanc.valor||0)+(forma?' via '+forma:''),
          tipo_movimentacao:'Financeiro', origem:'baixa_manual'
        });
        sbSet('co_localMov', localMov);
        _reRenderFinPasta(cid);
      }
    }

    marcarAlterado();
    fecharModal();
    if(document.getElementById('vf')?.classList.contains('on')) vfRender();
    renderFinDash();
    audit('baixa',(direcao==='receber'?'Recebimento':'Pagamento')+': '+(lanc.desc||'')+' — '+fBRL(lanc.valor||0),'lancamento');
    showToast(direcao==='receber'?'✅ Recebimento registrado':'✅ Pagamento registrado');
  }, 'Confirmar baixa');
}

function _poloAdverso(polo){
  var mapa = {'Autor':'R\u00e9u','R\u00e9u':'Autor','Requerente':'Requerido','Requerido':'Requerente','Reclamante':'Reclamado','Reclamado':'Reclamante','Apelante':'Apelado'};
  return mapa[polo]||'R\u00e9u';
}

function novoProcesso(prefill){
  var menu = document.getElementById('novo-menu');
  if(menu) menu.style.display='none';
  abrirModal('\u2696 Novo Processo',
    '<div style="margin-bottom:14px;background:var(--sf3);border-radius:8px;padding:12px 14px">'
      +'<div style="font-size:11px;color:var(--mu);margin-bottom:8px">Digite o n\u00famero e o nome. O sistema busca os dados no tribunal automaticamente.</div>'
    +'</div>'
    // Campos principais
    +'<div class="fm-row">'
      +'<div style="flex:2"><label class="fm-lbl">N\u00famero do processo <span class="req">*</span></label>'
        +'<input class="fm-inp" id="np-num" placeholder="0000000-00.0000.0.00.0000"></div>'
      +'<div><label class="fm-lbl">&nbsp;</label>'
        +'<button onclick="_npBuscarDataJud()" class="btn-bordo" style="width:100%;padding:8px 12px">\ud83d\udd0d Buscar tribunal</button></div>'
    +'</div>'
    +'<div class="fm-row" style="margin-top:8px">'
      +'<div style="flex:2"><label class="fm-lbl">Nome do cliente <span class="req">*</span></label>'
        + _contatoPickerHtml('np', {
            placeholder: 'Busque ou digite um nome novo...',
            onPick: function(ctc){
              var e = document.getElementById('np-cpf');
              if(e && !e.value && (ctc.doc || ctc.cpf)) e.value = ctc.doc || ctc.cpf;
            }
          })
      + '</div>'
      +'<div><label class="fm-lbl">CPF</label>'
        +'<input class="fm-inp" id="np-cpf" placeholder="000.000.000-00"></div>'
    +'</div>'
    // Status da busca
    +'<div id="np-dj-status" style="margin-top:8px"></div>'
    // Campos preenchidos pelo DataJud (ou manual)
    +'<div id="np-dj-fields" style="margin-top:10px">'
      +'<div class="fm-row">'
        +'<div><label class="fm-lbl">Natureza</label>'
          +'<select class="fm-inp" id="np-nat"><option>Trabalhista</option><option>Previdenci\u00e1rio</option><option>C\u00edvel</option><option>Fam\u00edlia</option><option>Administrativo</option><option>Penal</option><option>Banc\u00e1rio</option><option>Outro</option></select></div>'
        +'<div><label class="fm-lbl">Polo do cliente</label>'
          +'<select class="fm-inp" id="np-polo"><option>Autor</option><option>R\u00e9u</option><option>Reclamante</option><option>Reclamado</option><option>Requerente</option><option>Requerido</option></select></div>'
      +'</div>'
      +'<div class="fm-row" style="margin-top:8px">'
        +'<div style="flex:2"><label class="fm-lbl">Vara / Ju\u00edzo</label>'
          +'<input class="fm-inp" id="np-vara" placeholder="Preenchido automaticamente"></div>'
        +'<div><label class="fm-lbl">Data distribui\u00e7\u00e3o</label>'
          +'<input class="fm-inp" type="date" id="np-dt" value="'+new Date().toISOString().slice(0,10)+'"></div>'
      +'</div>'
      +'<div class="fm-row" style="margin-top:8px">'
        +'<div style="flex:2"><label class="fm-lbl">Parte adversa</label>'
          +'<input class="fm-inp" id="np-adv" placeholder="Preenchido automaticamente"></div>'
        +'<div><label class="fm-lbl">Tipo de a\u00e7\u00e3o</label>'
          +'<input class="fm-inp" id="np-tipo-acao" placeholder="Preenchido automaticamente"></div>'
      +'</div>'
      +'<div style="margin-top:8px"><label class="fm-lbl">Observa\u00e7\u00f5es</label>'
        +'<input class="fm-inp" id="np-obs" placeholder="Notas, estrat\u00e9gia..."></div>'
    +'</div>',
  function(){
    var g = function(id){ return (document.getElementById('np-'+id)||{}).value?.trim()||''; };
    if(!g('nome')){ showToast('Nome do cliente obrigatório'); return; }
    if(!g('num')){ showToast('Número do processo obrigatório'); return; }

    var existente = findClientByName(g('nome'));
    if(existente && !confirm('Cliente "'+g('nome')+'" j\u00e1 existe (Pasta '+existente.pasta+'). Criar novo processo mesmo assim?')) return;

    var id = genId();
    var novoCliente = {
      id:id, pasta:'', cliente:g('nome'), natureza:g('nat'),
      numero:g('num'), comarca:g('vara'), tipo_acao:g('tipo-acao'),
      adverso:g('adv'), polo:g('polo'), data_inicio:g('dt'),
      advogado:'Clarissa de Oliveira', tipo:'processo', status_consulta:'processo',
      partes:[
        {nome:g('nome'), condicao:g('polo'), cliente:'Sim'},
        {nome:g('adv'), condicao:_poloAdverso(g('polo')), cliente:'N\u00e3o'}
      ],
      movimentacoes:[], agenda:[],
      updated_at: new Date().toISOString()
    };

    tasks[id] = { extra:{ cpf:g('cpf') }};
    if(g('obs')) notes[id] = g('obs');

    // Double-save atômico: cliente (processo) + pessoa (contato) com mesmo
    // updated_at, salvos no mesmo tick. Ordem:
    //  1. Se o usuário picou um contato existente via picker, usa o id dele
    //  2. Senão, se há contato com nome fuzzy-igual em localContatos, usa ele
    //  3. Senão, cria um novo contato inline aqui
    var pickedCtcId = (document.getElementById('np-contato-id')||{}).value || '';
    var ctcVinc = null;
    if(pickedCtcId){
      ctcVinc = (localContatos||[]).find(function(c){ return String(c.id)===pickedCtcId; });
    }
    if(!ctcVinc){
      ctcVinc = (localContatos||[]).find(function(c){ return _fuzzyNorm(c.nome)===_fuzzyNorm(g('nome')); });
    }
    if(!ctcVinc && g('nome')){
      ctcVinc = {
        id: 'ctc'+genId(),
        nome: g('nome'),
        tipo: 'pf',
        doc: g('cpf'), cpf: g('cpf'),
        criado: novoCliente.updated_at.slice(0,10),
        updated_at: novoCliente.updated_at
      };
      localContatos.push(ctcVinc);
    }
    // Linka contato ao processo (tanto novo quanto existente) com o mesmo timestamp
    if(ctcVinc){
      ctcVinc.id_processo = id;
      ctcVinc.processo = g('nome')+' (Pasta —)';
      ctcVinc.updated_at = novoCliente.updated_at;
      // Se não tinha CPF e o form tem, preserva no contato
      if(!ctcVinc.doc && !ctcVinc.cpf && g('cpf')){
        ctcVinc.doc = g('cpf');
        ctcVinc.cpf = g('cpf');
      }
      if(typeof invalidarCtcCache==='function') invalidarCtcCache();
      sbSet('co_ctc', localContatos);
    }

    CLIENTS.push(novoCliente);
    sbSet('co_tasks', tasks);
    sbSet('co_notes', notes);
    sbSalvarClientesDebounced();
    marcarAlterado();
    montarClientesAgrupados();
    fecharModal();
    doSearch();
    // Reload state: notifica outras views (contatos, dashboard) para atualizar
    // contadores/listas sem F5. Supabase Realtime cuida de outros PCs/abas.
    try { window.dispatchEvent(new CustomEvent('co:reloadState', {detail:{source:'novoProcesso', id:id}})); } catch(e){}
    showToast('Processo + contato cadastrados ✓');
  }, '\u2696 Cadastrar processo');
  // Pr\u00e9-preenche a partir de um contato rec\u00e9m-criado (fluxo p\u00f3s-cadastro)
  if(prefill){
    setTimeout(function(){
      var s = function(id, val){ var e=document.getElementById('np-'+id); if(e && val) e.value=val; };
      s('nome', prefill.nome);
      s('cpf',  prefill.cpf || prefill.doc);
      s('obs',  prefill.obs);
    }, 50);
  }
}

// Buscar dados do tribunal ao cadastrar processo
// Novo processo a partir de cliente existente (como Autor ou Réu)
function _novoProcessoDoCliente(cid, polo){
  var c = findClientById(cid);
  if(!c) return;
  // Fechar menu de opções
  var dd = document.querySelector('.pj-opcoes-dd'); if(dd) dd.style.display='none';

  abrirModal('\u2696 Novo Processo \u2014 '+escapeHtml(c.cliente)+' como '+polo,
    '<div style="margin-bottom:12px;background:var(--sf3);border-radius:8px;padding:10px 14px">'
      +'<div style="font-size:12px;font-weight:700;color:var(--tx)">'+escapeHtml(c.cliente)+'</div>'
      +'<div style="font-size:10px;color:var(--mu)">Polo: <strong style="color:var(--ouro)">'+polo+'</strong></div>'
    +'</div>'
    +'<div class="fm-row">'
      +'<div style="flex:2"><label class="fm-lbl">N\u00famero do processo <span class="req">*</span></label>'
        +'<input class="fm-inp" id="npc-num" placeholder="0000000-00.0000.0.00.0000"></div>'
      +'<div><label class="fm-lbl">&nbsp;</label>'
        +'<button onclick="_npcBuscarDJ()" class="btn-bordo" style="width:100%;padding:8px 12px">\ud83d\udd0d Buscar</button></div>'
    +'</div>'
    +'<div id="npc-dj-status" style="margin-top:8px"></div>'
    +'<div class="fm-row" style="margin-top:8px">'
      +'<div><label class="fm-lbl">Natureza</label>'
        +'<select class="fm-inp" id="npc-nat"><option>Trabalhista</option><option>Previdenci\u00e1rio</option><option>C\u00edvel</option><option>Fam\u00edlia</option><option>Outro</option></select></div>'
      +'<div style="flex:2"><label class="fm-lbl">Vara</label>'
        +'<input class="fm-inp" id="npc-vara" placeholder="Preenchido automaticamente"></div>'
    +'</div>'
    +'<div class="fm-row" style="margin-top:8px">'
      +'<div style="flex:2"><label class="fm-lbl">Parte adversa</label>'
        +'<input class="fm-inp" id="npc-adv" placeholder="Preenchido automaticamente"></div>'
      +'<div><label class="fm-lbl">Tipo de a\u00e7\u00e3o</label>'
        +'<input class="fm-inp" id="npc-tipo" placeholder="Preenchido automaticamente"></div>'
    +'</div>',
  function(){
    var num = (document.getElementById('npc-num')||{}).value?.trim();
    if(!num){ showToast('Informe o n\u00famero do processo'); return; }
    var id = genId();
    var novoProc = {
      id:id, pasta:'', cliente:c.cliente, natureza:document.getElementById('npc-nat')?.value||'',
      numero:num, comarca:document.getElementById('npc-vara')?.value||'',
      tipo_acao:document.getElementById('npc-tipo')?.value||'',
      adverso:document.getElementById('npc-adv')?.value||'',
      polo:polo, data_inicio:new Date().toISOString().slice(0,10),
      advogado:'Clarissa de Oliveira', tipo:'processo', status_consulta:'processo',
      partes:[
        {nome:c.cliente, condicao:polo, cliente:'Sim'},
        {nome:document.getElementById('npc-adv')?.value||'', condicao:_poloAdverso(polo), cliente:'N\u00e3o'}
      ],
      movimentacoes:[], agenda:[]
    };
    // Copiar dados extras do cliente original
    if(tasks[cid]?.extra) tasks[id] = {extra:Object.assign({},tasks[cid].extra)};
    CLIENTS.push(novoProc);
    sbSet('co_tasks', tasks);
    sbSalvarClientesDebounced();
    marcarAlterado();
    montarClientesAgrupados();
    fecharModal();
    doSearch();
    showToast('Processo cadastrado para '+c.cliente+' como '+polo+' \u2713');
  }, '\u2696 Cadastrar');
}

function _npcBuscarDJ(){
  var num = (document.getElementById('npc-num')||{}).value?.trim();
  if(!num){ showToast('Informe o n\u00famero'); return; }
  var el = document.getElementById('npc-dj-status');
  if(el) el.innerHTML = '<div style="text-align:center;padding:6px;color:var(--mu)">\u23f3 Consultando...</div>';
  djConsultar(num, function(proc, erro){
    if(erro){ if(el) el.innerHTML = '<div style="padding:6px;color:#f59e0b;font-size:11px">\u26a0 '+escapeHtml(erro)+'</div>'; return; }
    if(el) el.innerHTML = '<div style="padding:6px;color:#4ade80;font-size:11px">\u2713 Dados encontrados</div>';
    if(proc.classe?.nome){
      var inp = document.getElementById('npc-tipo'); if(inp) inp.value=proc.classe.nome;
      var cls=proc.classe.nome.toLowerCase(), sel=document.getElementById('npc-nat');
      if(sel){ if(/trabalh|reclama/.test(cls)) sel.value='Trabalhista'; else if(/previden/.test(cls)) sel.value='Previdenci\u00e1rio'; else sel.value='C\u00edvel'; }
    }
    if(proc.orgaoJulgador?.nome){ var v=document.getElementById('npc-vara'); if(v) v.value=proc.orgaoJulgador.nome; }
    if(proc.partes?.length){
      var advs = proc.partes.filter(function(p){return p.polo!=='ATIVO';});
      if(advs.length){ var a=document.getElementById('npc-adv'); if(a) a.value=advs[0].nome||''; }
    }
  });
}

function _npBuscarDataJud(){
  var num = (document.getElementById('np-num')||{}).value?.trim();
  if(!num){ showToast('Informe o n\u00famero do processo'); return; }
  var el = document.getElementById('np-dj-status');
  if(el) el.innerHTML = '<div style="text-align:center;padding:8px;color:var(--mu)"><span style="font-size:16px">\u23f3</span> Consultando tribunal...</div>';

  djConsultar(num, function(proc, erro){
    if(erro){
      if(el) el.innerHTML = '<div style="padding:8px;color:#f59e0b;font-size:11px">\u26a0 '+escapeHtml(erro)+' \u2014 preencha manualmente</div>';
      return;
    }
    if(el) el.innerHTML = '<div style="padding:8px;color:#4ade80;font-size:11px">\u2713 Dados encontrados no tribunal</div>';

    // Preencher campos
    if(proc.classe && proc.classe.nome){
      var inp = document.getElementById('np-tipo-acao');
      if(inp) inp.value = proc.classe.nome;
      // Detectar natureza pela classe
      var cls = proc.classe.nome.toLowerCase();
      var sel = document.getElementById('np-nat');
      if(sel){
        if(/trabalh|reclama/i.test(cls)) sel.value='Trabalhista';
        else if(/previden|aposentad|auxilio|beneficio|inss/i.test(cls)) sel.value='Previdenci\u00e1rio';
        else if(/fam|divor|aliment|guard|invent/i.test(cls)) sel.value='Fam\u00edlia';
        else if(/penal|crim/i.test(cls)) sel.value='Penal';
        else sel.value='C\u00edvel';
      }
      // Polo baseado no tipo
      var polSel = document.getElementById('np-polo');
      if(polSel){
        if(/reclam/i.test(cls)) polSel.value='Reclamante';
        else if(/requer/i.test(cls)) polSel.value='Requerente';
      }
    }

    if(proc.orgaoJulgador && proc.orgaoJulgador.nome){
      var vara = document.getElementById('np-vara');
      if(vara) vara.value = proc.orgaoJulgador.nome;
    }

    if(proc.dataAjuizamento){
      var dt = document.getElementById('np-dt');
      if(dt) dt.value = proc.dataAjuizamento.slice(0,10);
    }

    // Preencher adverso a partir das partes
    if(proc.partes && proc.partes.length){
      var nomeCliente = (document.getElementById('np-nome')||{}).value?.toLowerCase().trim()||'';
      var adversos = proc.partes.filter(function(p){
        return (p.nome||'').toLowerCase()!==nomeCliente && p.polo!=='ATIVO';
      });
      if(adversos.length){
        var advInp = document.getElementById('np-adv');
        if(advInp) advInp.value = adversos[0].nome||'';
      }
      // Se não preencheu nome do cliente, tentar da parte ativa
      if(!nomeCliente){
        var ativos = proc.partes.filter(function(p){ return p.polo==='ATIVO'; });
        if(ativos.length){
          var nomeInp = document.getElementById('np-nome');
          if(nomeInp && !nomeInp.value) nomeInp.value = ativos[0].nome||'';
        }
      }
    }

    // Movimentações recentes
    if(proc.movimentos && proc.movimentos.length){
      var ultMov = proc.movimentos[0];
      var dtMov = (ultMov.dataHora||'').slice(0,10);
      if(el) el.innerHTML += '<div style="font-size:10px;color:var(--mu);margin-top:4px">\u00daltima mov: '+fDt(dtMov)+' \u2014 '+(ultMov.nome||'')+'</div>';
    }
  });
}


// ═══════════════════════════════════════════════════
// ── DASHBOARD FINANCEIRO — HOME ──
// ═══════════════════════════════════════════════════
let finDashMesOffset = 0; // 0 = mês atual, -1 = anterior, +1 = próximo


// ── Alertas e Stats do painel home ──
// ── PIPELINE DE ATENDIMENTOS ─────────────────────────────────
const AT_STATUS = {
  'inicial':         { lbl:'Atendimento inicial',  cor:'#60a5fa', bg:'color-mix(in srgb,#60a5fa 12%,var(--sf2))' },
  'analise':         { lbl:'Em análise',            cor:'#f59e0b', bg:'color-mix(in srgb,#f59e0b 12%,var(--sf2))' },
  'proposta':        { lbl:'Proposta enviada',      cor:'#a78bfa', bg:'color-mix(in srgb,#a78bfa 12%,var(--sf2))' },
  'contratou':       { lbl:'Cliente contratou',     cor:'#4ade80', bg:'color-mix(in srgb,#4ade80 12%,var(--sf2))' },
  'nao-prosseguiu':  { lbl:'Não prosseguiu',        cor:'#9ca3af', bg:'color-mix(in srgb,#9ca3af 10%,var(--sf2))' },
};

function renderPipeline(){
  const el = document.getElementById('home-pipeline');
  if(!el) return;

  const contagem = {};
  Object.keys(AT_STATUS).forEach(k => contagem[k]=0);
  localAtend.forEach(a => { if(contagem[a.status]!==undefined) contagem[a.status]++; else contagem['inicial']++; });
  const total = localAtend.length;

  if(!total){
    el.innerHTML = `<div class="pipe-empty" style="padding:18px 16px;font-size:12px;color:var(--mu);text-align:center">
      Nenhum atendimento registrado ainda.<br>
      <button class="tp-btn" style="margin-top:10px" onclick="novoAtendimento()">＋ Registrar atendimento</button>
    </div>`;
    return;
  }

  el.innerHTML = `
    <div class="pipe-status-row">
      ${Object.entries(AT_STATUS).map(([k,s])=>`
        <button class="pipe-status-btn ${contagem[k]>0?'':'op50'}" 
          style="--pipe-cor:${s.cor}" onclick="atListarPorStatus('${k}')">
          <span class="pipe-status-dot"></span>
          <span style="color:var(--of)">${s.lbl}</span>
          <span class="pipe-status-num">${contagem[k]}</span>
        </button>`).join('')}
    </div>
    <div class="pipe-footer-row">
      <span style="color:var(--mu);font-size:10px">${total} atendimento${total!==1?'s':''}</span>
      <button class="hp-action-btn hp-action-ghost" onclick="atListarTodos()">Ver todos →</button>
    </div>
    <div id="pipe-detail"></div>
  `;
}

function _pipeCardHTML(a){
  const s = AT_STATUS[a.status||'inicial'];
  const jaProcesso = CLIENTS.some(c=>String(c.id)===String(a.id_cliente)&&c.status_consulta==='processo'&&c.tipo!=='consulta');
  return `
    <div class="pipe-card">
      <div class="pipe-card-top">
        <span class="pipe-card-nome">${escapeHtml(a.cliente)}</span>
        <span class="pipe-card-tag" style="background:${s.bg};color:${s.cor}">${s.lbl}</span>
      </div>
      <div class="pipe-card-meta">
        <span>${a.assunto||''}</span>
        ${a.data?`<span>· ${a.data}</span>`:''}
        ${a.honorarios?`<span style="color:var(--ouro)">· ${a.honorarios}</span>`:''}
      </div>
      ${a.resumo?`<div class="pipe-card-resumo">${a.resumo}</div>`:''}
      <div class="pipe-card-actions">
        <select onchange="atAlterarStatus('${a.id}',this.value)">
          ${Object.entries(AT_STATUS).map(([k,st])=>`<option value="${k}" ${(a.status||'inicial')===k?'selected':''}>${st.lbl}</option>`).join('')}
        </select>
        ${jaProcesso
          ? `<button class="pipe-btn-det" onclick="atVerDetalhes('${a.id}')">📁 Abrir pasta</button>`
          : `<button class="pipe-btn-proc" onclick="atEvoluirParaProcesso('${a.id}')">⚖️ Evoluir para processo</button>`
        }
        <button class="pipe-btn-det" onclick="atVerDetalhes('${a.id}')">Ver detalhes</button>
      </div>
    </div>`;
}

function atListarPorStatus(status){
  const det = document.getElementById('pipe-detail');
  if(!det) return;
  const s = AT_STATUS[status];
  const lista = localAtend.filter(a=>(a.status||'inicial')===status)
    .sort((a,b)=>(b.criado_em||'').localeCompare(a.criado_em||''));
  
  // Toggle: se já está mostrando este status, fecha
  if(det._statusAtivo === status){
    det.innerHTML=''; det._statusAtivo=null; return;
  }
  det._statusAtivo = status;
  
  det.innerHTML = `
    <div class="pipe-detail-wrap">
      <div class="pipe-section-lbl">
        <span style="color:${s.cor}">${s.lbl} (${lista.length})</span>
        <button onclick="this.closest('#pipe-detail').innerHTML='';this.closest('#pipe-detail')._statusAtivo=null"
          style="background:none;border:none;color:var(--mu);cursor:pointer;font-size:13px;line-height:1">✕</button>
      </div>
      ${lista.length
        ? lista.map(a=>_pipeCardHTML(a)).join('')
        : `<div style="font-size:11px;color:var(--mu);padding:8px 0">Nenhum atendimento neste status.</div>`
      }
    </div>`;
}

function atListarTodos(){
  const det = document.getElementById('pipe-detail');
  if(!det) return;
  // Toggle
  if(det._statusAtivo === '__todos__'){
    det.innerHTML=''; det._statusAtivo=null; return;
  }
  det._statusAtivo = '__todos__';
  const lista = [...localAtend].sort((a,b)=>(b.criado_em||'').localeCompare(a.criado_em||''));
  det.innerHTML = `
    <div class="pipe-detail-wrap">
      <div class="pipe-section-lbl">
        <span>Todos os atendimentos (${lista.length})</span>
        <button onclick="this.closest('#pipe-detail').innerHTML='';this.closest('#pipe-detail')._statusAtivo=null"
          style="background:none;border:none;color:var(--mu);cursor:pointer;font-size:13px;line-height:1">✕</button>
      </div>
      ${lista.map(a=>_pipeCardHTML(a)).join('')}
    </div>`;
}

function atConfirm(titulo, corpo, cbSim, lblSim, cbNao, lblNao){
  abrirModal(titulo, corpo + `
    <div style="display:flex;gap:8px;margin-top:4px">
      <button class="tp-btn" style="flex:1" onclick="fecharModal();setTimeout(()=>{(${cbSim})()},100)">${lblSim}</button>
      <button class="tp-btn ghost" style="flex:1" onclick="fecharModal()">${lblNao}</button>
    </div>`, null, null);
}

function atAlterarStatus(id, novoStatus){
  const at = localAtend.find(a=>a.id===id);
  if(!at) return;
  at.status = novoStatus;
  sbSet('co_atend', localAtend);
  if(novoStatus==='contratou'){
    showToast('Status atualizado ✓');
    const jaTemProcesso = CLIENTS.some(c=>String(c.id)===String(at.id_cliente)&&c.status_consulta==='processo');
    if(!jaTemProcesso){
      setTimeout(()=>{
        abrirModal('🎉 Cliente contratou!',
          `<div style="text-align:center;padding:8px 0">
            <div style="font-size:32px;margin-bottom:12px">⚖️</div>
            <div style="font-size:14px;font-weight:600;color:var(--of);margin-bottom:8px">${at.cliente}</div>
            <div style="font-size:12px;color:var(--mu);margin-bottom:16px">Deseja criar um processo vinculado a este cliente agora?</div>
            <div style="display:flex;gap:8px;margin-top:12px">
              <button class="tp-btn" style="flex:1" onclick="fecharModal();setTimeout(novoProcesso,150)">⚖️ Criar processo</button>
              <button class="tp-btn ghost" style="flex:1" onclick="fecharModal()">Agora não</button>
            </div>
          </div>`,
          null, null
        );
      }, 300);
    }
  } else {
    showToast('Status atualizado ✓');
  }
}

// ── Timestamp de última atualização do dashboard ──
var _dshLastUpdate = null;
function _dshUpdateTimestamp(){
  _dshLastUpdate = new Date();
  var el = document.getElementById('dsc-lastupd');
  if(el) el.textContent = _dshLastUpdate.toLocaleTimeString('pt-BR',{hour:'2-digit',minute:'2-digit'});
}
// Fechar dropdown ao clicar fora
document.addEventListener('click',function(e){
  var dd = document.getElementById('dsh-novo-dd');
  if(dd && dd.style.display==='block' && !e.target.closest('[onclick*="dsh-novo-dd"]') && !dd.contains(e.target)){
    dd.style.display='none';
  }
});

// \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550
// \u2550\u2550 DASHBOARD MINIMALISTA \u2014 renders \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550
// \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550
// Selectors otimizados sobre estado j\u00e1 em mem\u00f3ria (sem hit no KV/Supabase).
// allPendCached() / vfTodos() / ctcTodos() s\u00e3o memoizados; tombstones
// universais filtram itens deletados (deleted:true ou em _arrayTombstones).

function _dshClienteIdDeEvt(p){
  if(p.id_processo) return p.id_processo;
  if(p.cliente && typeof findClientByName==='function'){
    var m = findClientByName(p.cliente);
    if(m) return m.id;
  }
  return 0;
}

// Coluna 1 \u2014 Timeline vertical: Hoje \u00b7 Amanh\u00e3 \u00b7 pr\u00f3ximo grande marco.
// Pontos: audi\u00eancia (lil\u00e1s), prazo (vermelho, pulsante se atrasado).
function dshRenderTimeline(){
  var el = document.getElementById('dsh-timeline');
  if(!el) return;
  var hoje = getTodayKey();
  var amanhaD = new Date(HOJE); amanhaD.setDate(amanhaD.getDate()+1);
  var amanhaStr = amanhaD.toISOString().slice(0,10);

  var todos = allPendCached().filter(function(p){
    if(p.realizado || p.deleted) return false;
    return true;
  });

  function rowsFor(dt){
    return todos.filter(function(p){ return eventoNoDia(p, dt); })
      .sort(function(a,b){ return (a.inicio||a.dt_raw||'').localeCompare(b.inicio||b.dt_raw||''); });
  }

  // Vencidos n\u00e3o cumpridos \u2014 entram no bloco "Hoje" para n\u00e3o sumir
  var vencidos = todos.filter(function(p){
    var dt = (p.dt_fim||p.dt_raw||'');
    return dt && dt < hoje;
  }).sort(function(a,b){ return (a.dt_raw||'').localeCompare(b.dt_raw||''); });

  var hojeEvts = vencidos.concat(rowsFor(hoje));
  var amanhaEvts = rowsFor(amanhaStr);

  // Pr\u00f3ximo grande marco (prazo ou audi\u00eancia) entre +2 e +30 dias
  var proxMarco = null;
  for(var i=2; i<=30 && !proxMarco; i++){
    var d = new Date(HOJE); d.setDate(d.getDate()+i);
    var ds = d.toISOString().slice(0,10);
    var hits = todos.filter(function(p){
      var tp = agTipo(p);
      return (tp==='prazo'||tp==='audiencia') && eventoNoDia(p, ds);
    }).sort(function(a,b){ return (a.dt_raw||'').localeCompare(b.dt_raw||''); });
    if(hits.length) proxMarco = hits[0];
  }

  function dotClass(p){
    var tp = agTipo(p);
    if(tp==='audiencia') return 'audiencia';
    if(tp==='prazo'){
      var venc = (p.dt_fim||p.dt_raw||'') < hoje;
      return 'prazo' + (venc ? ' atrasado' : '');
    }
    return '';
  }
  function row(p){
    var hr = (p.inicio && p.inicio.includes('T')) ? p.inicio.slice(11,16) : '\u2014';
    var cid = _dshClienteIdDeEvt(p);
    var click = cid ? 'openC('+cid+')' : "calEvtClick('"+(p.id||p.id_agenda||'')+"')";
    var titulo = p.titulo||p.tipo_compromisso||'Compromisso';
    var dtMeta = (p.dt_raw||'') < hoje ? ' \u00b7 venceu '+fDt(p.dt_raw) : '';
    return '<div class="dsh-tl-item" onclick="'+click+'">'
      + '<span class="dsh-tl-dot '+dotClass(p)+'"></span>'
      + '<span class="dsh-tl-hora">'+hr+'</span>'
      + '<div class="dsh-tl-body">'
        + '<div class="dsh-tl-titulo">'+escapeHtml(titulo)+'</div>'
        + (p.cliente||dtMeta?'<div class="dsh-tl-meta">'+escapeHtml(p.cliente||'')+dtMeta+'</div>':'')
      + '</div>'
    + '</div>';
  }
  function group(lbl, evts, cls){
    var inner = evts.length
      ? evts.map(row).join('')
      : '<div class="dsh-tl-empty">Nada agendado</div>';
    return '<div class="dsh-tl-group">'
      + '<div class="dsh-tl-grouplbl '+(cls||'')+'">'+lbl+'</div>' + inner
    + '</div>';
  }

  var html = group('Hoje', hojeEvts, 'hoje')
           + group('Amanh\u00e3', amanhaEvts);
  if(proxMarco){
    html += group('Pr\u00f3ximo marco \u00b7 '+fDt(proxMarco.dt_raw), [proxMarco]);
  }
  el.innerHTML = html;
}

// Coluna 2 \u2014 Top 3 urg\u00eancias do Kanban.
// Crit\u00e9rios: atrasada > prazo mais pr\u00f3ximo > sem prazo (cai no fim).
// Desempate: updatedAt mais recente primeiro.
function dshRenderTop3(){
  var el = document.getElementById('dsh-top3');
  if(!el) return;
  var hoje = getTodayKey();

  var pend = (vkTasks||[]).filter(function(t){
    if(t.deleted) return false;
    if(typeof _tombstoneHas==='function' && _tombstoneHas('co_vktasks', t.id)) return false;
    var done = t.status==='done' || t.status==='concluido';
    return !done;
  });

  pend.sort(function(a,b){
    var ap = a.prazo||a.paraHoje||''; var bp = b.prazo||b.paraHoje||'';
    var aAtr = ap && ap < hoje, bAtr = bp && bp < hoje;
    if(aAtr !== bAtr) return aAtr ? -1 : 1;
    if(ap && bp && ap !== bp) return ap.localeCompare(bp);
    if(ap && !bp) return -1;
    if(!ap && bp) return 1;
    var au = a.updated_at||a.status_since||a.criado_em||'';
    var bu = b.updated_at||b.status_since||b.criado_em||'';
    return bu.localeCompare(au);
  });

  var top = pend.slice(0,3);
  if(!top.length){
    el.innerHTML = '<div class="dsh-top3-empty">Nenhuma urg\u00eancia. Respire.</div>';
    return;
  }

  var amanhaStr = new Date(new Date(HOJE).getTime()+86400000).toISOString().slice(0,10);
  el.innerHTML = top.map(function(t){
    var prazo = t.prazo || t.paraHoje || '';
    var atr = prazo && prazo < hoje;
    var isHoje = prazo === hoje;
    var isAmanha = prazo === amanhaStr;
    var prazoCls = atr ? 'atrasado' : isHoje ? 'hoje' : isAmanha ? 'amanha' : '';
    var prazoLbl = !prazo ? 'Sem prazo'
                 : atr ? 'Atrasada \u00b7 '+fDt(prazo)
                 : isHoje ? 'Hoje'
                 : isAmanha ? 'Amanh\u00e3'
                 : fDt(prazo);
    var cli = t.cliente && t.cliente!=='-' ? t.cliente : '';
    var match = cli && typeof findClientByName==='function' ? findClientByName(cli) : null;
    var click = match ? 'openC('+match.id+')'
                      : "goView('vk',document.getElementById('nav-tasks'));vkRender()";
    return '<div class="dsh-top3-card '+(atr?'atrasado':'')+'" onclick="'+click+'">'
      + '<div class="dsh-top3-titulo">'+escapeHtml(t.titulo||'(sem t\u00edtulo)')+'</div>'
      + '<div class="dsh-top3-meta">'
        + '<span class="dsh-top3-prazo '+prazoCls+'">'+prazoLbl+'</span>'
        + (cli?'<span>\u00b7 '+escapeHtml(cli)+'</span>':'')
      + '</div>'
    + '</div>';
  }).join('');
}

// Coluna 3 \u2014 Saldo Livre (saldo escrit\u00f3rio - cust\u00f3dia de clientes)
function dshRenderSaldoLivre(){
  var el = document.getElementById('dsh-saldo-livre');
  if(!el) return;
  var saldo = 0, custodia = 0;
  try { saldo = (_vfConsolidar(null)||{}).saldo || 0; } catch(e){}
  try {
    custodia = (localLanc||[]).filter(function(l){
      if(typeof _tombstoneHas==='function' && _tombstoneHas('co_localLanc', l.id)) return false;
      return (l.tipo==='repasse'||l._repasse_alvara||l._repasse_acordo) && !l.pago && l.status!=='pago';
    }).reduce(function(s,l){return s+(l.valor||0);},0);
  } catch(e){}
  var livre = saldo - custodia;
  var cls = livre >= 0 ? 'green' : '';
  el.innerHTML = '<div class="dsh-cx-lbl">Saldo Livre</div>'
    + '<div class="dsh-cx-val '+cls+'">'+fBRL(livre)+'</div>'
    + '<div class="dsh-cx-sub">Caixa do escrit\u00f3rio, descontada a cust\u00f3dia de clientes</div>';
  el.style.cursor = 'pointer';
  el.onclick = function(){
    goView('vf', document.getElementById('nav-fin'));
    if(typeof vfRender==='function') vfRender();
  };
}

// Coluna 3 \u2014 Pr\u00f3ximo Alvar\u00e1 aguardando (com bot\u00e3o Confirmar Chegada)
function dshRenderProxAlvara(){
  var el = document.getElementById('dsh-prox-alvara');
  if(!el) return;
  var aguard = (localLanc||[]).filter(function(l){
    if(l.deleted) return false;
    if(typeof _tombstoneHas==='function' && _tombstoneHas('co_localLanc', l.id)) return false;
    return l.tipo==='alvara' && !l.pago && l.status!=='pago';
  }).sort(function(a,b){
    var av = a.venc||a.data||'9999', bv = b.venc||b.data||'9999';
    return av.localeCompare(bv);
  });

  if(!aguard.length){
    el.innerHTML = '<div class="dsh-cx-lbl">Pr\u00f3ximo Alvar\u00e1</div>'
      + '<div class="dsh-cx-val" style="font-size:13px;color:var(--dsh-min-mu);font-weight:400">Nenhum aguardando</div>';
    el.onclick = null; el.style.cursor = '';
    return;
  }
  var l = aguard[0];
  var cid = l.id_processo || 0;
  var dataLbl = (l.venc||l.data) ? fDt(l.venc||l.data) : '\u2014';
  el.innerHTML = '<div class="dsh-cx-lbl">Pr\u00f3ximo Alvar\u00e1</div>'
    + '<div class="dsh-cx-val ouro">'+fBRL(l.valor||0)+'</div>'
    + '<div class="dsh-cx-sub">'+escapeHtml(l.cliente||'\u2014')+' \u00b7 prev. '+dataLbl
    + (aguard.length>1?' \u00b7 +'+(aguard.length-1)+' aguardando':'')+'</div>'
    + '<button class="dsh-cx-action primary" onclick="event.stopPropagation();abrirFluxoAlvara('+cid+','+l.id+')">\ud83d\udcb0 Confirmar chegada</button>';
  el.onclick = function(){ if(cid) openC(cid); };
  el.style.cursor = cid ? 'pointer' : '';
}

// Coluna 3 \u2014 Repasses Pendentes (com bot\u00e3o pagar por linha)
function dshRenderRepassesPend(){
  var el = document.getElementById('dsh-repasses-pend');
  if(!el) return;
  var rep = (localLanc||[]).filter(function(l){
    if(l.deleted) return false;
    if(typeof _tombstoneHas==='function' && _tombstoneHas('co_localLanc', l.id)) return false;
    return (l.tipo==='repasse'||l._repasse_alvara||l._repasse_acordo) && !l.pago && l.status!=='pago';
  }).sort(function(a,b){
    var av = a.venc||a.data||'9999', bv = b.venc||b.data||'9999';
    return av.localeCompare(bv);
  });
  var total = rep.reduce(function(s,l){return s+(l.valor||0);},0);

  if(!rep.length){
    el.innerHTML = '<div class="dsh-cx-lbl">Repasses Pendentes</div>'
      + '<div class="dsh-cx-val" style="font-size:13px;color:var(--dsh-min-mu);font-weight:400">Nenhum aberto</div>';
    el.onclick = null;
    return;
  }
  var topRep = rep.slice(0,3);
  var rows = topRep.map(function(l){
    return '<div class="dsh-cx-row" onclick="event.stopPropagation();vfBaixar(\'l'+l.id+'\')" title="Pagar este repasse">'
      + '<span class="dsh-cx-row-nome">'+escapeHtml(l.cliente||'\u2014')+'</span>'
      + '<span class="dsh-cx-row-val">'+fBRL(l.valor||0)+'</span>'
    + '</div>';
  }).join('');
  el.innerHTML = '<div class="dsh-cx-lbl">Repasses Pendentes \u00b7 '+rep.length+'</div>'
    + '<div class="dsh-cx-val ouro">'+fBRL(total)+'</div>'
    + '<div style="margin-top:10px">'+rows+'</div>'
    + (rep.length>3?'<div style="font-size:10px;color:var(--dsh-min-mu);margin-top:6px">+'+(rep.length-3)+' adicionais</div>':'')
    + '<button class="dsh-cx-action" style="margin-top:10px" onclick="goView(\'vf\',document.getElementById(\'nav-fin\'));setTimeout(function(){vfSetTab(\'repasses\',null);},80)">Ver todos \u2192</button>';
  el.onclick = null;
}

// CRM \u2014 Contatos sem resposta (atendimentos no pipeline parados h\u00e1 4+ dias)
function dshRenderContatosSemResposta(){
  var el = document.getElementById('dsh-contatos-sr');
  if(!el) return;
  var hojeMs = new Date(HOJE).getTime();
  var pend = (typeof localAtend!=='undefined' ? localAtend : [] ).filter(function(a){
    if(!a) return false;
    if(a.deleted) return false;
    if(typeof _tombstoneHas==='function' && _tombstoneHas('co_atend', a.id)) return false;
    var st = a.status || 'inicial';
    if(st !== 'inicial' && st !== 'proposta') return false;
    var ref = a.criado_em || a.data || '';
    if(!ref) return true;
    var dias = (hojeMs - new Date(ref).getTime()) / 86400000;
    return dias >= 4;
  }).sort(function(a,b){ return (a.criado_em||'').localeCompare(b.criado_em||''); });

  if(!pend.length){
    el.innerHTML = '<div class="dsh-cx-lbl">Contatos sem Resposta</div>'
      + '<div class="dsh-cx-val" style="font-size:13px;color:var(--dsh-min-mu);font-weight:400">Tudo respondido.</div>';
    return;
  }
  var top = pend.slice(0,4);
  var rows = top.map(function(a){
    var dias = a.criado_em
      ? Math.max(0, Math.round((hojeMs - new Date(a.criado_em).getTime())/86400000))
      : '?';
    var click = (typeof atVerDetalhes==='function')
      ? "atVerDetalhes('"+a.id+"')"
      : "goView('vct',document.getElementById('nav-contatos'));ctcRender()";
    return '<div class="dsh-cx-row" onclick="event.stopPropagation();'+click+'">'
      + '<span class="dsh-cx-row-nome">'+escapeHtml(a.cliente||'\u2014')+'</span>'
      + '<span class="dsh-cx-row-val">'+dias+'d</span>'
    + '</div>';
  }).join('');
  el.innerHTML = '<div class="dsh-cx-lbl">Contatos sem Resposta \u00b7 '+pend.length+'</div>'
    + '<div style="margin-top:6px">'+rows+'</div>'
    + (pend.length>4?'<div style="font-size:10px;color:var(--dsh-min-mu);margin-top:6px">+'+(pend.length-4)+' aguardando retorno</div>':'');
}

// Busca universal \u2014 preview ao digitar (clientes + contatos)
function dshSearchPreview(){
  var inp = document.getElementById('dsh-search');
  var prev = document.getElementById('dsh-search-preview');
  if(!inp || !prev) return;
  var q = (inp.value||'').toLowerCase().trim();
  if(q.length < 2){ prev.innerHTML=''; return; }
  var hits = [];
  (CLIENTS||[]).slice().sort(function(a,b){return (a.cliente||'').localeCompare(b.cliente||'');}).forEach(function(c){
    if(hits.length>=8) return;
    var nome = (c.cliente||'').toLowerCase();
    var num = (c.numero||'').toLowerCase();
    if(nome.includes(q) || (num && num.includes(q))){
      hits.push({label: c.cliente + (c.pasta?' \u00b7 Pasta '+c.pasta:''), click:'openC('+c.id+')', tipo:'\u2696\ufe0f'});
    }
  });
  var ctcs = (typeof ctcTodos==='function') ? ctcTodos() : [];
  ctcs.forEach(function(c){
    if(hits.length>=12) return;
    var nome = (c.nome||'').toLowerCase();
    if(nome && nome.includes(q)){
      hits.push({label:c.nome, click:"goView('vct',document.getElementById('nav-contatos'));ctcRender();ctcAbrirFicha('"+c.id+"')", tipo:'\ud83d\udc64'});
    }
  });
  if(!hits.length){
    prev.innerHTML = '<div class="dsh-search-row" style="cursor:default;color:var(--dsh-min-mu)">Nada encontrado para "'+escapeHtml(q)+'"</div>';
    return;
  }
  prev.innerHTML = hits.map(function(h){
    return '<div class="dsh-search-row" onclick="document.getElementById(\'dsh-search-preview\').innerHTML=\'\';'+h.click+'">'
      + h.tipo + ' ' + escapeHtml(h.label)
    + '</div>';
  }).join('');
}

// Submit (Enter) \u2014 leva para a view de Clientes com a query
function dshSearchSubmit(){
  var inp = document.getElementById('dsh-search');
  var prev = document.getElementById('dsh-search-preview');
  if(!inp) return;
  var q = (inp.value||'').trim();
  if(prev) prev.innerHTML='';
  if(!q) return;
  goView('vcl', document.getElementById('nav-clientes'));
  var s = document.getElementById('srch');
  if(s){ s.value = q; if(typeof doSearch==='function') doSearch(); }
}

// Esconder preview ao clicar fora
document.addEventListener('click', function(e){
  var prev = document.getElementById('dsh-search-preview');
  var inp = document.getElementById('dsh-search');
  if(!prev || !inp) return;
  if(e.target===inp || prev.contains(e.target)) return;
  prev.innerHTML = '';
});

// Render unificado do dashboard minimalista \u2014 barato, opera s\u00f3 sobre cache em mem\u00f3ria
function dshRenderMin(){
  if(!document.getElementById('dsh-timeline')) return;
  try { dshRenderTimeline(); }            catch(e){ console.warn('[dsh] timeline', e); }
  try { dshRenderTop3(); }                catch(e){ console.warn('[dsh] top3', e); }
  try { dshRenderSaldoLivre(); }          catch(e){ console.warn('[dsh] saldo', e); }
  try { dshRenderProxAlvara(); }          catch(e){ console.warn('[dsh] alvara', e); }
  try { dshRenderRepassesPend(); }        catch(e){ console.warn('[dsh] repasses', e); }
  try { dshRenderContatosSemResposta(); } catch(e){ console.warn('[dsh] crm', e); }
  if(typeof _dshUpdateTimestamp==='function') _dshUpdateTimestamp();
}

function _dshRefresh(){
  invalidarAllPend();
  _finLocaisCache = {};
  _clientByIdCache = {};
  if(typeof invalidarCacheVfTodos==='function') invalidarCacheVfTodos();
  if(typeof invalidarCtcCache==='function') invalidarCtcCache();
  // Re-fetch fresco do localStorage para vkTasks (tarefas rec\u00e9m-criadas em outra aba)
  try {
    var vkFresh = JSON.parse(lsGet('co_vktasks')||'[]');
    if(Array.isArray(vkFresh)){
      vkTasks = vkFresh.filter(function(x){ return !_tombstoneHas('co_vktasks', x.id); });
    }
  } catch(e){}
  // Renders legados (mantidos caso outros containers ainda existam)
  if(typeof renderHomeAlerts==='function') try{ renderHomeAlerts(); }catch(e){}
  if(typeof renderChecklist==='function')  try{ renderChecklist(); }catch(e){}
  if(typeof renderHomeWeek==='function')   try{ renderHomeWeek(); }catch(e){}
  if(typeof renderFinDash==='function')    try{ renderFinDash(); }catch(e){}
  if(typeof renderHomeIniciais==='function') try{ renderHomeIniciais(); }catch(e){}
  if(typeof atualizarStats==='function')   try{ atualizarStats(); }catch(e){}
  // Render minimalista
  dshRenderMin();
  showToast('\u2713 Dashboard atualizado');
}
// Atualizar timestamp a cada 60s para mostrar "há X min"
setInterval(function(){
  if(!_dshLastUpdate) return;
  var el = document.getElementById('dsc-lastupd');
  if(!el) return;
  var diff = Math.round((new Date()-_dshLastUpdate)/60000);
  if(diff < 1) el.textContent = 'Agora';
  else if(diff < 60) el.textContent = 'h\u00e1 '+diff+'min';
  else el.textContent = _dshLastUpdate.toLocaleTimeString('pt-BR',{hour:'2-digit',minute:'2-digit'});
}, 30000);

function renderHomeAlerts(){
  _dshUpdateTimestamp();
  var el = document.getElementById('home-alerts');
  if(!el) return;
  const hoje = new Date(HOJE).toISOString().slice(0,10);
  const encIds = getEncIds();
  const em7 = new Date(HOJE); em7.setDate(em7.getDate()+7);
  const em7str = em7.toISOString().slice(0,10);
  const todos = vfTodos();

  // Cache único de allPend para todo o dashboard
  const _ap = allPendCached();
  var prazos=[], audiencias=[];
  _ap.forEach(function(p){
    if(p.realizado) return;
    var emRange = (p.dt_raw>=hoje&&p.dt_raw<=em7str)||eventoNoDia(p,hoje);
    if(!emRange) return;
    var tp = agTipo(p);
    if(tp==='prazo') prazos.push(p);
    else if(tp==='audiencia') audiencias.push(p);
  });

  // Single-pass para vencidos e despesas
  var vencidos=[], despVencer=[], totalVenc=0, totalDesp=0;
  todos.forEach(function(l){
    if(l.tipo==='receber'&&l.status==='vencido'){ vencidos.push(l); totalVenc+=l.valor; }
    if(l.tipo==='pagar'&&l.status==='pendente'&&(l.data||'')>=hoje&&(l.data||'')<=em7str){ despVencer.push(l); totalDesp+=l.valor; }
  });

  // KPI cards
  const kpi = (cor, ico, lbl, val, sub, click) => `
    <div class="ha-kpi" style="--kpi-cor:${cor}" onclick="${click}">
      <div class="ha-kpi-ico">${ico}</div>
      <div class="ha-kpi-lbl">${lbl}</div>
      <div class="ha-kpi-val" style="color:${cor}">${val}</div>
      ${sub?`<div class="ha-kpi-sub">${sub}</div>`:''}
    </div>`;

  // Alerta banner
  const alerta = (bg, brd, cor, ico, txt, btnTxt, btnClick) => `
    <div class="ha-alerta" style="background:${bg};border-color:${brd};color:${cor}">
      <span>${ico}</span>
      <span>${txt}</span>
      <button class="ha-alerta-btn" style="color:${cor};border-color:${brd}" onclick="${btnClick}">${btnTxt}</button>
    </div>`;

  let alertasHtml = '';
  // Repasses pendentes (obrigação gerada, não paga)
  const repassesPend = todos.filter(function(l){
    return l.tipo==='pagar' && l.status!=='pago' &&
           (l.subtipo==='Repasse ao cliente' || (l.desc||'').toLowerCase().includes('repasse'));
  });
  const totalRepasse = repassesPend.reduce(function(s,l){return s+l.valor;},0);

  if(prazos.length)    alertasHtml += alerta('color-mix(in srgb,#f59e0b 8%,var(--sf2))','#7c4a00','#f59e0b','⚠',`<strong>${prazos.length} prazo${prazos.length>1?'s':''}</strong> nos próximos 7 dias`,'Ver agenda →','goView(\'va\',document.getElementById(\'nav-agenda\'))');
  if(audiencias.length) alertasHtml += alerta('color-mix(in srgb,#f87676 8%,var(--sf2))','#7c1a1a','#f87676','🏛',`<strong>${audiencias.length} audiência${audiencias.length>1?'s':''}</strong> nos próximos 7 dias`,'Ver agenda →','goView(\'va\',document.getElementById(\'nav-agenda\'))');
  if(totalVenc>0)       alertasHtml += alerta('color-mix(in srgb,#c9484a 6%,var(--sf2))','#7f1d1d','#c9484a','💸',`<strong>${fBRL(totalVenc)}</strong> em recebimentos vencidos — ${vencidos.length} lançamento${vencidos.length>1?'s':''}  `,'Cobrar →','goView(\'vf\',document.getElementById(\'nav-fin\'));setTimeout(function(){vfSetTab(\'recebimentos\',null);},100)');
  if(totalRepasse>0)    alertasHtml += alerta('color-mix(in srgb,#D4AF37 6%,var(--sf2))','#7c5a00','#D4AF37','📤',`<strong>${fBRL(totalRepasse)}</strong> em repasses pendentes — ${repassesPend.length} cliente${repassesPend.length>1?'s':''}`,'Pagar →','goView(\'vf\',document.getElementById(\'nav-fin\'));setTimeout(function(){vfSetTab(\'pagar\',null);},100)');
  if(despVencer.length) alertasHtml += alerta('color-mix(in srgb,#f87676 5%,var(--sf2))','#5a1a1a','#f87676','🏢',`<strong>${fBRL(totalDesp)}</strong> em despesas vencem em 7 dias`,'Ver →','goView(\'vf\',document.getElementById(\'nav-fin\'));setTimeout(function(){vfSetTab(\'despesas\',null);},100)');

  // Notificação financeira no título da aba
  if(typeof atualizarStats==='function') atualizarStats();

  // Alertas em grid compacto (2 colunas)
  el.innerHTML = alertasHtml
    ? '<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:6px;margin-bottom:8px">'+alertasHtml+'</div>'
    : '';

  // Atualizar KPIs novos
  var e5=document.getElementById('dsc-prazos7'); if(e5) e5.textContent=prazos.length;
  var e6=document.getElementById('dsc-aud7'); if(e6) e6.textContent=audiencias.length;

  // Saldo escritório
  try {
    var cons = _vfConsolidar(null);
    var e7=document.getElementById('dsc-saldo'); if(e7) e7.textContent=fK(cons.saldo);
  } catch(se){}

  // Próximos compromissos (lista)
  renderProximosCompromissos(_ap, hoje);
}

// ── PRÓXIMOS COMPROMISSOS (lista para o dashboard) ──
function renderProximosCompromissos(allEvts, hoje){
  var el = document.getElementById('home-proximos');
  if(!el) return;
  var em14 = new Date(HOJE); em14.setDate(em14.getDate()+14);
  var em14str = em14.toISOString().slice(0,10);

  var prox = allEvts.filter(function(p){
    return !p.realizado && p.dt_raw >= hoje && p.dt_raw <= em14str;
  }).sort(function(a,b){ return (a.dt_raw||'').localeCompare(b.dt_raw||''); }).slice(0,8);

  if(!prox.length){
    el.innerHTML = '<div style="padding:12px;text-align:center;font-size:11px;color:var(--mu)">Nenhum compromisso nos próximos 14 dias</div>';
    return;
  }

  var html = '';
  prox.forEach(function(p){
    var isHoje = p.dt_raw === hoje;
    var diasAte = Math.ceil((new Date(p.dt_raw)-new Date(hoje))/86400000);
    var tp = agTipo(p);
    var corTp = tp==='prazo'?'#f59e0b':tp==='audiencia'?'#f87676':'#60a5fa';
    var icoTp = tp==='prazo'?'\u26a0':tp==='audiencia'?'\ud83c\udfdb':'\ud83d\udcc5';
    var diasLbl = isHoje?'HOJE':diasAte===1?'Amanhã':diasAte+'d';
    var corDias = isHoje?'#f87676':diasAte<=3?'#f59e0b':'var(--mu)';

    html += '<div style="display:flex;align-items:center;gap:8px;padding:6px 0;border-bottom:1px solid var(--bd)">'
      +'<div style="min-width:36px;text-align:center"><span style="font-size:10px;font-weight:800;color:'+corDias+'">'+diasLbl+'</span></div>'
      +'<span style="font-size:12px">'+icoTp+'</span>'
      +'<div style="flex:1;min-width:0">'
        +'<div style="font-size:11px;font-weight:600;color:var(--tx);overflow:hidden;text-overflow:ellipsis;white-space:nowrap">'+escapeHtml(p.titulo||p.tipo_compromisso||'\u2014')+'</div>'
        +'<div style="font-size:9px;color:var(--mu)">'+escapeHtml(p.cliente||'')+' \u00b7 '+fDt(p.dt_raw)+'</div>'
      +'</div>'
      +'<span style="font-size:9px;font-weight:700;color:'+corTp+';text-transform:uppercase">'+tp+'</span>'
    +'</div>';
  });
  el.innerHTML = html;
}

function gerarResumoWpp(){
  var hoje=getTodayKey(), NL='\n';
  var MA=['Jan','Fev','Mar','Abr','Mai','Jun','Jul','Ago','Set','Out','Nov','Dez'];
  var dObj=new Date(HOJE);
  var dataFmt=dObj.getDate()+' de '+MA[dObj.getMonth()]+' de '+dObj.getFullYear();

  // Force re-fetch: lê localStorage fresco + invalida caches de agenda/financeiro.
  // Garante que tarefa criada segundos atrás (em qualquer aba) apareça aqui,
  // mesmo se Realtime ainda não propagou pra memória desta aba.
  try {
    var vkFresh = JSON.parse(lsGet('co_vktasks')||'[]');
    if(Array.isArray(vkFresh)){
      vkTasks = vkFresh.filter(function(x){ return !_tombstoneHas('co_vktasks', x.id); });
    }
  } catch(e){}
  try { if(typeof invalidarAllPend==='function') invalidarAllPend(); } catch(e){}
  try { if(typeof invalidarCacheVfTodos==='function') invalidarCacheVfTodos(); } catch(e){}

  // 1. FATAIS — prazos fatais de hoje + vencidos não cumpridos
  var fatais=[];
  if(typeof prazos!=='undefined'&&prazos){
    Object.entries(prazos).forEach(function(e){
      var cid=e[0], lista=e[1]||[];
      lista.forEach(function(p){
        if(p.cumprido||p.deleted) return;
        if(p.data<=hoje){
          var c=(CLIENTS||[]).find(function(x){return String(x.id)===String(cid);});
          var nome=c?c.cliente:'';
          var vencLabel=p.data<hoje?' - venceu '+fDt(p.data):'';
          fatais.push(nome+' - '+p.titulo+vencLabel);
        }
      });
    });
  }

  // 2. TAREFAS — Kanban filtro ampliado:
  //    - para hoje / prazo hoje (padrão)
  //    - atrasadas pendentes (padrão)
  //    - recém-criadas ou alteradas hoje (status_since==hoje) — NOVO
  //    - sem prazo definido (tarefa "aberta") — NOVO
  //    Se ficar grande, usuária edita no modal antes de copiar.
  var tarefasHj=vkTasks.filter(function(t){
    if(t.status==='done'||t.status==='concluido') return false;
    if(t.prazo===hoje||t.paraHoje===hoje) return true;
    if(t.prazo&&t.prazo<hoje) return true;
    if(t.status_since===hoje) return true;
    if(!t.prazo && !t.paraHoje) return true;
    return false;
  }).map(function(t){
    var cli=t.cliente&&t.cliente!=='-'?t.cliente+' - ':'';
    return cli+t.titulo;
  });

  // 3. COMPROMISSOS — eventos de hoje incluindo ranges
  var compHj=allPendCached().filter(function(p){
    return !p.realizado&&eventoNoDia(p,hoje);
  }).map(function(p){
    var titulo=p.tipo_compromisso||p.titulo||'Compromisso';
    var cli=p.cliente?' - '+p.cliente:'';
    var dtIni=(p.dt_raw||'').slice(0,10), dtFim=(p.dt_fim||dtIni).slice(0,10);
    var range=dtIni!==dtFim?' (de '+fDt(dtIni)+' a '+fDt(dtFim)+')':'';
    return titulo+cli+range;
  });

  // 4. FINANCEIRO — recebimentos vencendo hoje + cobranças (2 dias antes)
  var fV4=function(v){return 'R$ '+Math.abs(v||0).toLocaleString('pt-BR',{minimumFractionDigits:2,maximumFractionDigits:2});};
  var em2d=new Date(new Date(HOJE).getTime()+2*86400000).toISOString().slice(0,10);
  var recebHoje=[], cobrar=[];
  // Incluir lançamentos locais (pasta) e globais (escritório)
  var _todosFin = (localLanc||[]).concat((finLancs||[]).filter(function(l){return !l._projuris_id&&!l.proj_ref&&!l.origem_proj;}));
  _todosFin.forEach(function(l){
    if(isRec(l)) return;
    if(l.tipo==='repasse'||l.tipo==='despesa'||l.tipo==='despint') return;
    var venc=(l.venc||l.data||'').slice(0,10);
    if(!venc) return;
    var cNome=l.cliente||'';
    var desc=l.desc||'Honorários';
    if(venc===hoje){
      recebHoje.push(cNome+' - '+desc+' — '+fV4(l.valor));
    } else if(venc>hoje&&venc<=em2d){
      cobrar.push(cNome+' - '+desc+' — '+fV4(l.valor)+' (vence '+fDt(venc)+')');
    }
  });

  // 5. PAGAMENTOS do dia (despesas/repasses vencendo hoje)
  var pagHoje=[];
  _todosFin.forEach(function(l){
    if(isRec(l)) return;
    if(l.tipo!=='repasse'&&l.tipo!=='despesa'&&l.tipo!=='despint'&&l.direcao!=='pagar') return;
    var venc=(l.venc||l.data||'').slice(0,10);
    if(venc===hoje){
      pagHoje.push((l.cliente||'Escritório')+' - '+(l.desc||'Pagamento')+' — '+fV4(l.valor));
    }
  });

  var txt='*Prazos/Tarefas de hoje — '+dataFmt+'*'+NL+NL;
  if(fatais.length){txt+='🔴 *Fatais*'+NL;fatais.forEach(function(f){txt+='- '+f+NL;});txt+=NL;}
  if(tarefasHj.length){txt+='📌 *Tarefas*'+NL;tarefasHj.forEach(function(t){txt+='- '+t+NL;});txt+=NL;}
  if(compHj.length){txt+='📅 *Compromissos*'+NL;compHj.forEach(function(c){txt+='- '+c+NL;});txt+=NL;}
  if(recebHoje.length){txt+='💰 *Recebimentos de hoje*'+NL;recebHoje.forEach(function(r){txt+='- '+r+NL;});txt+=NL;}
  if(pagHoje.length){txt+='💸 *Pagamentos de hoje*'+NL;pagHoje.forEach(function(r){txt+='- '+r+NL;});txt+=NL;}
  if(cobrar.length){txt+='📣 *Cobrar (vencem em 2 dias)*'+NL;cobrar.forEach(function(c){txt+='- '+c+NL;});txt+=NL;}
  if(!fatais.length&&!tarefasHj.length&&!compHj.length&&!recebHoje.length&&!pagHoje.length&&!cobrar.length){txt+='✅ _Nenhuma pendência para hoje._'+NL;}
  txt+=NL+'_CO Advocacia App_';
  // Abrir modal editável — usuário pode apagar linhas, digitar, reorganizar antes de copiar.
  abrirModal('📲 Resumo do Dia — WhatsApp',
    '<div style="font-size:11px;color:var(--mu);margin-bottom:8px;line-height:1.5">Edite livremente antes de copiar: remova linhas, adicione notas ou reorganize. Mantém a formatação do WhatsApp (*negrito*, _itálico_).</div>'+
    '<textarea id="wpp-resumo-txt" style="width:100%;box-sizing:border-box;min-height:360px;background:var(--sf3);border:1px solid var(--bd);border-radius:8px;padding:12px;font-family:monospace;font-size:12px;line-height:1.6;color:var(--tx);resize:vertical;white-space:pre">'+escapeHtml(txt)+'</textarea>',
    function(){
      var finalTxt = (document.getElementById('wpp-resumo-txt')||{}).value || '';
      function _fallbackCopy(){
        var ta = document.getElementById('wpp-resumo-txt');
        if(ta){ ta.focus(); ta.select(); try{ document.execCommand('copy'); }catch(e){} }
      }
      if(navigator && navigator.clipboard && navigator.clipboard.writeText){
        navigator.clipboard.writeText(finalTxt).then(function(){
          showToast('✓ Copiado! Cole no WhatsApp.');
          fecharModal();
        }).catch(function(){
          _fallbackCopy();
          showToast('✓ Copiado (fallback)! Cole no WhatsApp.');
          fecharModal();
        });
      } else {
        _fallbackCopy();
        showToast('✓ Copiado! Cole no WhatsApp.');
        fecharModal();
      }
    },
    '📋 Copiar para WhatsApp'
  );
}
function mostrarTxtModal(txt){
  abrirModal('Resumo do Dia',
    '<div style="background:var(--sf3);border-radius:8px;padding:12px;font-size:11px;font-family:monospace;white-space:pre-wrap;color:var(--tx);max-height:300px;overflow-y:auto">'+txt.replace(/&/g,'&amp;').replace(/</g,'&lt;')+'</div>',
    null,null);
}

// ── Iniciais pendentes no dashboard ──
function renderHomeIniciais(){
  var el = document.getElementById('home-iniciais');
  if(!el) return;
  var pend = (_iniciais||[]).filter(function(i){return i.status==='pendente'||i.status==='fazendo';});
  if(!pend.length){
    el.innerHTML = '<div style="padding:12px;text-align:center;font-size:11px;color:var(--mu)">Nenhuma inicial pendente</div>';
    return;
  }
  var html = '';
  pend.slice(0,5).forEach(function(i){
    var corSt = i.status==='fazendo'?'#60a5fa':'#f59e0b';
    var lblSt = i.status==='fazendo'?'Fazendo':'Pendente';
    html += '<div style="display:flex;align-items:center;gap:8px;padding:6px 0;border-bottom:1px solid var(--bd)">'
      +'<span style="font-size:9px;font-weight:700;color:'+corSt+';min-width:50px">'+lblSt+'</span>'
      +'<span style="flex:1;font-size:11px;color:var(--tx);overflow:hidden;text-overflow:ellipsis;white-space:nowrap">'+escapeHtml(i.cliente||'\u2014')+'</span>'
      +'<span style="font-size:9px;color:var(--mu)">'+escapeHtml(i.area||'')+'</span>'
    +'</div>';
  });
  if(pend.length>5) html += '<div style="font-size:10px;color:var(--mu);text-align:center;padding:4px">+' +(pend.length-5)+' mais</div>';
  el.innerHTML = html;
}

function renderFinDash(){
  // Compact home summary
  var hfd=document.getElementById('home-fin-dash');
  if(hfd){
    var hoje2=new Date(HOJE), mes2=hoje2.getMonth()+1, ano2=hoje2.getFullYear();
    var mesStr2=String(mes2).padStart(2,'0');
    var MA3=['Jan','Fev','Mar','Abr','Mai','Jun','Jul','Ago','Set','Out','Nov','Dez'];
    var lbl2=document.getElementById('fin-mes-lbl');
    if(lbl2) lbl2.textContent='Financeiro — '+MA3[mes2-1]+' '+ano2;
    var locais2=(localLanc||[]).filter(function(l){return (l.data||l.venc||'').slice(0,7)===ano2+'-'+mesStr2;});
    var _isDespFn = function(l){ return l.direcao==='pagar'||l.tipo==='despesa'||l.tipo==='despint'||l.tipo==='repasse'; };
    var aRec=locais2.filter(function(l){return l.status!=='pago'&&!_isDespFn(l);}).reduce(function(s,l){return s+(l.valor||0);},0);
    var venc2=locais2.filter(function(l){return l.status!=='pago'&&!_isDespFn(l)&&l.venc&&l.venc<new Date(HOJE).toISOString().slice(0,10);}).reduce(function(s,l){return s+(l.valor||0);},0);
    var desp2=locais2.filter(function(l){return _isDespFn(l);}).reduce(function(s,l){return s+(l.valor||0);},0);
    var fBRL2=function(v){return 'R$ '+Math.round(v).toLocaleString('pt-BR');};
    // Compact 3-stat widget (only show, don't duplicate full table)
    // Repasses vencendo/vencidos
    var hojeDash = new Date(HOJE).toISOString().slice(0,10);
    var em3dias = new Date(HOJE); em3dias.setDate(em3dias.getDate()+3);
    var em3Str = em3dias.toISOString().slice(0,10);
    var repVenc = (localLanc||[]).filter(function(l){
      return (l.tipo==='repasse'||l._repasse_alvara)&&!l.pago&&l.venc&&l.venc<=em3Str;
    });
    var repVencTotal = repVenc.reduce(function(s,l){return s+(l.valor||0);},0);
    var repAlert = repVenc.length>0
      ? '<div style="display:flex;align-items:center;justify-content:space-between;padding:6px 14px;background:rgba(201,72,74,.08);border-bottom:1px solid rgba(201,72,74,.2)">'
          +'<span style="font-size:10px;font-weight:700;color:#c9484a">⚠️ '+repVenc.length+' repasse'+(repVenc.length>1?'s':'')+' venc'+(repVenc.length>1?'endo':'endo')+' — '+fBRL2(repVencTotal)+'</span>'
          +'<button onclick="goView(\'vf\',document.getElementById(\'nav-fin\'));setTimeout(function(){vfSetTab(\'repasses\',null);},100)" style="font-size:10px;padding:2px 8px;border-radius:4px;border:none;background:#c9484a;color:#fff;cursor:pointer">Ver</button>'
        +'</div>'
      : '';
    // Receitas e Despesas previstas para HOJE
    var fV6=function(v){return 'R$ '+Math.abs(v||0).toLocaleString('pt-BR',{minimumFractionDigits:2,maximumFractionDigits:2});};
    var recHoje=[], despHoje=[], cobrar3=[];
    var em2dDash=new Date(new Date(HOJE).getTime()+2*86400000).toISOString().slice(0,10);
    (localLanc||[]).forEach(function(l){
      if(isRec(l)) return;
      var venc=(l.venc||l.data||'').slice(0,10);
      if(!venc) return;
      var isDesp=l.tipo==='repasse'||l.tipo==='despesa'||l.tipo==='despint'||l.direcao==='pagar';
      if(venc===hojeDash){
        (isDesp?despHoje:recHoje).push({cli:l.cliente||'—',desc:l.desc||'—',val:l.valor||0});
      } else if(!isDesp&&venc>hojeDash&&venc<=em2dDash){
        cobrar3.push({cli:l.cliente||'—',desc:l.desc||'—',val:l.valor||0,venc:venc});
      }
    });
    var finHoje='';
    if(recHoje.length||despHoje.length||cobrar3.length){
      finHoje+='<div style="border-top:1px solid #2a2a2a;padding:10px 14px">';
      if(recHoje.length){
        var totR3=recHoje.reduce(function(s,r){return s+r.val;},0);
        finHoje+='<div style="font-size:10px;font-weight:700;color:#4ade80;text-transform:uppercase;letter-spacing:.05em;margin-bottom:6px">💰 Receitas previstas hoje — '+fV6(totR3)+'</div>';
        recHoje.forEach(function(r){
          finHoje+='<div style="display:flex;justify-content:space-between;padding:3px 0;font-size:11px"><span style="color:var(--tx)">'+escapeHtml(r.cli)+' — '+escapeHtml(r.desc)+'</span><span style="font-weight:700;color:#4ade80">'+fV6(r.val)+'</span></div>';
        });
        finHoje+='<div style="height:8px"></div>';
      }
      if(despHoje.length){
        var totD3=despHoje.reduce(function(s,r){return s+r.val;},0);
        finHoje+='<div style="font-size:10px;font-weight:700;color:#f87676;text-transform:uppercase;letter-spacing:.05em;margin-bottom:6px">💸 Despesas de hoje — '+fV6(totD3)+'</div>';
        despHoje.forEach(function(r){
          finHoje+='<div style="display:flex;justify-content:space-between;padding:3px 0;font-size:11px"><span style="color:var(--tx)">'+escapeHtml(r.cli)+' — '+escapeHtml(r.desc)+'</span><span style="font-weight:700;color:#f87676">'+fV6(r.val)+'</span></div>';
        });
        finHoje+='<div style="height:8px"></div>';
      }
      if(cobrar3.length){
        finHoje+='<div style="font-size:10px;font-weight:700;color:#f59e0b;text-transform:uppercase;letter-spacing:.05em;margin-bottom:6px">📣 Cobrar (vencem em 2 dias)</div>';
        cobrar3.forEach(function(r){
          finHoje+='<div style="display:flex;justify-content:space-between;padding:3px 0;font-size:11px"><span style="color:var(--tx)">'+escapeHtml(r.cli)+' — '+escapeHtml(r.desc)+'</span><span style="font-weight:700;color:#f59e0b">'+fV6(r.val)+' <span style="font-size:9px;opacity:.7">vence '+fDt(r.venc)+'</span></span></div>';
        });
      }
      finHoje+='</div>';
    }
    hfd.innerHTML= repAlert + '<div style="display:grid;grid-template-columns:repeat(3,1fr);gap:8px;padding:10px 14px">'
      +'<div style="padding:8px 10px"><div style="font-size:9px;color:#9E9E9E;text-transform:uppercase;letter-spacing:.05em;font-weight:700;margin-bottom:3px">A receber</div><div style="font-size:15px;font-weight:700;color:#4caf7d">'+fBRL2(aRec)+'</div></div>'
      +'<div style="padding:8px 10px"><div style="font-size:9px;color:#9E9E9E;text-transform:uppercase;letter-spacing:.05em;font-weight:700;margin-bottom:3px">Inadimplente</div><div style="font-size:15px;font-weight:700;color:#c9484a">'+fBRL2(venc2)+'</div></div>'
      +'<div style="padding:8px 10px"><div style="font-size:9px;color:#9E9E9E;text-transform:uppercase;letter-spacing:.05em;font-weight:700;margin-bottom:3px">Desp. mês</div><div style="font-size:15px;font-weight:700;color:#f87676">'+fBRL2(desp2)+'</div></div>'
      +'</div>' + finHoje;
    // Update stat card on dashboard
    var dscFin2=document.getElementById('dsc-fin');if(dscFin2) dscFin2.textContent=fBRL2(aRec);
    return;
  }

  const el = document.getElementById('home-fin-dash');
  if(!el) return;

  const hoje = new Date(HOJE);
  const ano  = hoje.getFullYear();
  const mes  = hoje.getMonth() + 1 + finDashMesOffset;
  const d    = new Date(ano, mes - 1, 1);
  const mesReal = d.getMonth() + 1;
  const anoReal = d.getFullYear();
  const mesStr  = String(mesReal).padStart(2,'0');
  const prefixo = `${anoReal}-${mesStr}`;

  const pasta_map = {};
  CLIENTS.forEach(c=>{ pasta_map[String(c.pasta)] = c.cliente; });

  const lancsXlsx  = (FIN_XLSX||[]).filter(l=>l.dt_venc && l.dt_venc.startsWith(prefixo));
  const lancsLocal = (localLanc||[]).filter(l=>l.data && l.data.startsWith(prefixo) && l.tipo!=='pagar' && l.direcao!=='pagar');

  const todos = [
    ...lancsXlsx.map(l=>({
      id:'x'+l.id, data:l.dt_venc,
      desc:l.desc,
      cliente: pasta_map[String(l.pasta)] || l.pasta,
      val:l.val, status:l.status,
      vencido: l.status==='pendente' && l.dt_venc < new Date(HOJE).toISOString().slice(0,10)
    })),
    ...lancsLocal.map(l=>({
      id:'l'+l.id, data:l.data||l.venc,
      desc:l.desc, cliente:l.cliente||'—',
      val:parseFloat(l.valor||0),
      status:l.status||'pendente',
      vencido:!l.pago && (l.venc||l.data) < new Date(HOJE).toISOString().slice(0,10)
    }))
  ].sort((a,b)=>a.data.localeCompare(b.data));

  const totalPrev = todos.reduce((s,l)=>s+l.val, 0);
  const totalPago = todos.filter(l=>l.status==='pago').reduce((s,l)=>s+l.val, 0);
  const totalPend = todos.filter(l=>l.status!=='pago').reduce((s,l)=>s+l.val, 0);
  const totalVenc = todos.filter(l=>l.vencido).reduce((s,l)=>s+l.val, 0);
  var dscFin=document.getElementById('dsc-fin'); if(dscFin) dscFin.textContent='R$ '+(totalPend/1000).toFixed(0)+'k';

  const fmt = v => 'R$ ' + v.toLocaleString('pt-BR',{minimumFractionDigits:2,maximumFractionDigits:2});
  const fmtDate = d => fDt(d);
  const nomesMes = ['Janeiro','Fevereiro','Março','Abril','Maio','Junho','Julho','Agosto','Setembro','Outubro','Novembro','Dezembro'];
  const nomeMes  = nomesMes[mesReal-1] + ' ' + anoReal;

  // Estado de visibilidade — salvo por sessão
  // Custódia: repasses pendentes de clientes em caixa
  const custodia = (localLanc||[]).filter(function(l){
    return (l.tipo==='repasse'||l._repasse_alvara||l._repasse_acordo)&&!l.pago&&l.status!=='pago';
  }).reduce(function(s,l){return s+(l.valor||0);},0);

  const visivel = window._finDashVisivel === true;
  const olho = visivel ? '👁' : '👁‍🗨';
  const mascara = v => visivel ? fmt(v) : '••••••';

  const rows = todos.length ? todos.map(l=>`
    <div class="fin-row">
      <span class="fin-row-data">${fmtDate(l.data)}</span>
      <span class="fin-row-desc" title="${l.desc}">${l.desc}</span>
      <span class="fin-row-cliente" title="${l.cliente}">${l.cliente}</span>
      <span class="fin-row-val ${l.status}" style="${!visivel?'filter:blur(5px);user-select:none':''}">
        ${fmt(l.val)}
      </span>
      <span class="fin-row-badge ${l.vencido?'vencido':l.status}">
        ${l.vencido?'VENCIDO':l.status==='pago'?'✓ PAGO':'PENDENTE'}
      </span>
    </div>`).join('')
  : '<div class="fin-empty">Nenhum lançamento neste mês</div>';

  el.innerHTML = `
  <div class="fin-dash">
    <div class="fin-dash-title" style="display:flex;align-items:center;justify-content:space-between">
      <span>💰 Recebimentos — ${nomeMes}</span>
      <button onclick="finDashToggleVis()" title="${visivel?'Ocultar':'Revelar'} valores"
        style="background:none;border:none;cursor:pointer;font-size:16px;color:var(--mu);padding:0 4px">${olho}</button>
    </div>
    <div class="fin-dash-cards">
      ${custodia>0?`<div class="fin-card" style="background:rgba(251,146,60,.07);border:1px solid rgba(251,146,60,.4);border-radius:8px;padding:8px 12px;cursor:pointer" onclick="vfSetTab('despesas')">
        <div class="fin-card-lbl" style="color:#fb923c;font-size:9px;font-weight:700;text-transform:uppercase;letter-spacing:.06em;margin-bottom:3px">💼 Custódia clientes</div>
        <div class="fin-card-val" style="color:#fb923c">${mascara(custodia)}</div>
        <div style="font-size:9px;color:#fb923c;opacity:.7;margin-top:2px">Dinheiro de clientes em caixa</div>
      </div>`:''}
      <div class="fin-card cinza">
        <div class="fin-card-lbl">Previsto no mês</div>
        <div class="fin-card-val">${mascara(totalPrev)}</div>
      </div>
      <div class="fin-card verde">
        <div class="fin-card-lbl">✓ Já recebido</div>
        <div class="fin-card-val">${mascara(totalPago)}</div>
      </div>
      <div class="fin-card laranja">
        <div class="fin-card-lbl">⏳ A receber</div>
        <div class="fin-card-val">${mascara(totalPend)}</div>
      </div>
      ${totalVenc>0?`<div class="fin-card" style="background:#2d0a0a;border-color:#7f1d1d">
        <div class="fin-card-lbl" style="color:#f87676">⚠ Vencido</div>
        <div class="fin-card-val" style="color:#f87676">${mascara(totalVenc)}</div>
      </div>`:''}
    </div>
    <div class="fin-list">
      <div class="fin-list-head">
        <span class="fin-list-title">${todos.length} lançamento${todos.length!==1?'s':''}</span>
        <div class="fin-list-nav">
          <button class="fin-nav-btn" onclick="finDashNav(-1)">‹</button>
          <span class="fin-nav-mes">${nomeMes}</span>
          <button class="fin-nav-btn" onclick="finDashNav(+1)">›</button>
        </div>
      </div>
      ${rows}
    </div>
  </div>`;
}

function finDashToggleVis(){
  window._finDashVisivel = !window._finDashVisivel;
  renderFinDash();
}


function finDashNav(delta){
  finDashMesOffset += delta;
  renderFinDash();
}


// ═══════════════════════════════════════════════════
// ── CADASTRO COMPLETO DE CLIENTE ──
// ═══════════════════════════════════════════════════
function cadHtml(pfx, opts={}){
  // opts: { tipoField: true, processoField: true, naturezaField: true, pendField: true }
  const req = '<span class="cad-req">*</span>';
  return `
  <div class="cad-tabs">
    <button class="cad-tab on"  onclick="cadSwTab(this,'${pfx}-s1')">👤 Identificação</button>
    <button class="cad-tab"     onclick="cadSwTab(this,'${pfx}-s2')">📍 Contato / Endereço</button>
    <button class="cad-tab"     onclick="cadSwTab(this,'${pfx}-s3')">💼 Profissional</button>
    <button class="cad-tab"     onclick="cadSwTab(this,'${pfx}-s4')">🔒 Dados Privados</button>
  </div>

  <!-- ABA 1: IDENTIFICAÇÃO -->
  <div class="cad-sec on" id="${pfx}-s1">
    <div class="cad-row">
      <div class="cad-field full">
        <label class="cad-lbl">Nome completo ${req}</label>
        <input class="cad-inp req" id="${pfx}-nome" placeholder="Nome completo">
      </div>
    </div>
    <div class="cad-row">
      <div class="cad-field">
        <label class="cad-lbl">CPF ${req}</label>
        <input class="cad-inp req" id="${pfx}-cpf" placeholder="000.000.000-00" maxlength="14">
      </div>
      <div class="cad-field">
        <label class="cad-lbl">Data de nascimento</label>
        <input class="cad-inp" id="${pfx}-nasc" type="date">
      </div>
    </div>
    <div class="cad-row">
      <div class="cad-field">
        <label class="cad-lbl">Naturalidade (cidade/UF)</label>
        <input class="cad-inp" id="${pfx}-natural" placeholder="Ex: Belo Horizonte / MG">
      </div>
      <div class="cad-field sm">
        <label class="cad-lbl">Nacionalidade</label>
        <input class="cad-inp" id="${pfx}-nacion" placeholder="Brasileira" value="Brasileira">
      </div>
    </div>
    <div class="cad-row">
      <div class="cad-field">
        <label class="cad-lbl">Estado civil</label>
        <select class="cad-inp" id="${pfx}-ecivil">
          <option value="">—</option>
          <option>Solteiro(a)</option>
          <option>Casado(a)</option>
          <option>Divorciado(a)</option>
          <option>Viúvo(a)</option>
          <option>União estável</option>
          <option>Separado(a)</option>
        </select>
      </div>
      <div class="cad-field">
        <label class="cad-lbl">Nome da mãe</label>
        <input class="cad-inp" id="${pfx}-mae" placeholder="Nome completo da mãe">
      </div>
    </div>
    ${opts.tipoField ? `
    <div class="cad-row">
      <div class="cad-field">
        <label class="cad-lbl">Tipo de contato</label>
        <select class="cad-inp" id="${pfx}-tipo">
          <option value="Cliente">Cliente</option>
          <option value="Consulta">Consulta</option>
          <option value="Testemunha">Testemunha</option>
          <option value="Perito">Perito</option>
          <option value="Advogado adverso">Advogado adverso</option>
          <option value="Contador">Contador</option>
          <option value="Outro">Outro</option>
        </select>
      </div>
    </div>` : ''}
  </div>

  <!-- ABA 2: CONTATO / ENDEREÇO -->
  <div class="cad-sec" id="${pfx}-s2">
    <div class="cad-sep">📞 Contato</div>
    <div class="cad-row">
      <div class="cad-field">
        <label class="cad-lbl">Telefone / WhatsApp</label>
        <input class="cad-inp" id="${pfx}-tel" placeholder="(31) 9 0000-0000">
      </div>
      <div class="cad-field">
        <label class="cad-lbl">E-mail</label>
        <input class="cad-inp" id="${pfx}-email" placeholder="email@...">
      </div>
    </div>
    <div class="cad-sep">📍 Endereço</div>
    <div class="cad-row">
      <div class="cad-field" style="flex:2">
        <label class="cad-lbl">Rua / Logradouro</label>
        <input class="cad-inp" id="${pfx}-rua" placeholder="Nome da rua, avenida...">
      </div>
      <div class="cad-field sm">
        <label class="cad-lbl">Número</label>
        <input class="cad-inp" id="${pfx}-num" placeholder="123">
      </div>
    </div>
    <div class="cad-row">
      <div class="cad-field">
        <label class="cad-lbl">Complemento</label>
        <input class="cad-inp" id="${pfx}-comp" placeholder="Apto, Bloco...">
      </div>
      <div class="cad-field">
        <label class="cad-lbl">Bairro</label>
        <input class="cad-inp" id="${pfx}-bairro" placeholder="">
      </div>
    </div>
    <div class="cad-row">
      <div class="cad-field sm">
        <label class="cad-lbl">CEP</label>
        <div style="display:flex;gap:4px">
          <input class="cad-inp" id="${pfx}-cep" placeholder="00000-000" maxlength="9" style="flex:1" onblur="_preencherCepFields('${pfx}')">
          <button type="button" id="${pfx}-cep-btn" onclick="_preencherCepFields('${pfx}')" style="padding:0 8px;border-radius:6px;background:var(--sf3);border:1px solid var(--bd);color:var(--tx);cursor:pointer" title="Buscar CEP">🔍</button>
        </div>
      </div>
      <div class="cad-field">
        <label class="cad-lbl">Cidade</label>
        <input class="cad-inp" id="${pfx}-cidade" placeholder="">
      </div>
      <div class="cad-field sm">
        <label class="cad-lbl">Estado</label>
        <select class="cad-inp" id="${pfx}-uf">
          <option value="">UF</option>
          ${['AC','AL','AP','AM','BA','CE','DF','ES','GO','MA','MT','MS','MG','PA','PB','PR','PE','PI','RJ','RN','RS','RO','RR','SC','SP','SE','TO'].map(u=>`<option>${u}</option>`).join('')}
        </select>
      </div>
    </div>
    <div class="cad-sep">📢 Origem</div>
    <div class="cad-row">
      <div class="cad-field full">
        <label class="cad-lbl">Origem do contato</label>
        <select class="cad-inp" id="${pfx}-origem">${_origemOptionsHtml('')}</select>
      </div>
    </div>
    ${opts.processoField ? `
    <div class="cad-sep">🔗 Vínculo</div>
    <div class="cad-row">
      <div class="cad-field full">
        <label class="cad-lbl">Vincular a processo</label>
        <input class="cad-inp" id="${pfx}-proc" list="${pfx}-proclist" placeholder="Nome do cliente ou pasta">
        <datalist id="${pfx}-proclist">${CLIENTS.map(c=>`<option value="${c.cliente}">${c.cliente} (Pasta ${c.pasta})</option>`).join('')}</datalist>
      </div>
    </div>` : ''}
  </div>

  <!-- ABA 3: PROFISSIONAL -->
  <div class="cad-sec" id="${pfx}-s3">
    <div class="cad-row">
      <div class="cad-field">
        <label class="cad-lbl">Profissão</label>
        <input class="cad-inp" id="${pfx}-prof" placeholder="Ex: Pedreiro, Enfermeira...">
      </div>
    </div>
    <div class="cad-row">
      <div class="cad-field">
        <label class="cad-lbl">NIT / PIS</label>
        <input class="cad-inp" id="${pfx}-nit" placeholder="000.00000.00-0">
      </div>
      <div class="cad-field">
        <label class="cad-lbl">CTPS (número/série)</label>
        <input class="cad-inp" id="${pfx}-ctps" placeholder="000000 / 000">
      </div>
    </div>
    ${opts.naturezaField ? `
    <div class="cad-sep">⚖️ Caso</div>
    <div class="cad-row">
      <div class="cad-field">
        <label class="cad-lbl">Assunto / Natureza</label>
        <input class="cad-inp" id="${pfx}-nat" placeholder="Ex: Trabalhista, Previdenciário...">
      </div>
    </div>
    ${opts.pendField ? `
    <div class="cad-row">
      <div class="cad-field full">
        <label class="cad-lbl">Pendência inicial</label>
        <input class="cad-inp" id="${pfx}-pend" placeholder="Ex: Assinar procuração, trazer CTPS...">
      </div>
    </div>
    <div class="cad-row">
      <div class="cad-field full">
        <label class="cad-lbl">Observações</label>
        <textarea class="cad-inp" id="${pfx}-obs" rows="3" placeholder="Resumo da consulta, contexto do caso..."></textarea>
      </div>
    </div>` : ''}` : ''}
  </div>

  <!-- ABA 4: DADOS PRIVADOS -->
  <div class="cad-sec" id="${pfx}-s4">
    <div class="cad-sep">🏦 Dados Bancários</div>
    <div class="cad-row">
      <div class="cad-field" style="flex:2">
        <label class="cad-lbl">Banco</label>
        <input class="cad-inp" id="${pfx}-banco" placeholder="Ex: Nubank, Itaú, Caixa...">
      </div>
      <div class="cad-field sm">
        <label class="cad-lbl">Tipo de conta</label>
        <select class="cad-inp" id="${pfx}-tconta">
          <option value="">—</option>
          <option>Corrente</option>
          <option>Poupança</option>
          <option>Pagamento</option>
        </select>
      </div>
    </div>
    <div class="cad-row">
      <div class="cad-field sm">
        <label class="cad-lbl">Agência</label>
        <input class="cad-inp" id="${pfx}-ag" placeholder="0000">
      </div>
      <div class="cad-field">
        <label class="cad-lbl">Conta + dígito</label>
        <input class="cad-inp" id="${pfx}-conta" placeholder="000000-0">
      </div>
    </div>
    <div class="cad-row">
      <div class="cad-field full">
        <label class="cad-lbl">Chave PIX</label>
        <input class="cad-inp" id="${pfx}-pix" placeholder="CPF, e-mail, celular ou chave aleatória">
      </div>
    </div>
    <div class="cad-sep">🔐 Acesso Meu INSS</div>
    <div class="cad-row">
      <div class="cad-field full">
        <label class="cad-lbl">Senha Meu INSS</label>
        <div class="pwd-wrap">
          <input class="cad-inp" type="password" id="${pfx}-inss" placeholder="••••••••" autocomplete="new-password">
          <button type="button" class="pwd-eye" onclick="toggleCadPwd('${pfx}-inss',this)">👁</button>
        </div>
      </div>
    </div>
  </div>`;
}

function cadSwTab(btn, secId){
  const modal = btn.closest('.modal-box')||btn.closest('[id]').parentElement;
  btn.parentElement.querySelectorAll('.cad-tab').forEach(b=>b.classList.remove('on'));
  btn.classList.add('on');
  // Encontrar todas as cad-sec no mesmo contexto
  const allSecs = document.querySelectorAll(`[id^="${secId.split('-s')[0]}-s"]`);
  allSecs.forEach(s=>s.classList.remove('on'));
  const target = document.getElementById(secId);
  if(target) target.classList.add('on');
}

function toggleCadPwd(id, btn){
  const inp = document.getElementById(id);
  if(!inp) return;
  inp.type = inp.type==='password' ? 'text' : 'password';
  btn.textContent = inp.type==='password' ? '👁' : '🙈';
}

function getCadValues(pfx){
  const g = id => { const el=document.getElementById(pfx+'-'+id); return el?el.value.trim():''; };
  return {
    nome:    g('nome'),   cpf:     g('cpf'),    nasc:    g('nasc'),
    natural: g('natural'),nacion:  g('nacion'),  ecivil:  g('ecivil'),
    mae:     g('mae'),    tipo:    g('tipo'),
    tel:     g('tel'),    email:   g('email'),
    rua:     g('rua'),    num:     g('num'),     comp:    g('comp'),
    bairro:  g('bairro'), cep:     g('cep'),     cidade:  g('cidade'),
    uf:      g('uf'),     proc:    g('proc'),
    prof:    g('prof'),   nit:     g('nit'),     ctps:    g('ctps'),
    nat:     g('nat'),    pend:    g('pend'),    obs:     g('obs'),
    banco:   g('banco'),  tconta:  g('tconta'),  ag:      g('ag'),
    conta:   g('conta'),  pix:     g('pix'),     inss:    g('inss'),
    origem:  g('origem'),
  };
}


// ══════════════════════════════════════════════════
// ── CONSULTAS / STATUS PENDENTE ──
// ══════════════════════════════════════════════════
function novoAtendimento(prefill){
  var menu = document.getElementById('novo-menu');
  if(menu) menu.style.display='none';
  abrirModal('💬 Novo Atendimento', `
    <!-- BUSCA / SELEÇÃO DE CLIENTE -->
    <div class="at-section">
      <div class="at-sec-title">👤 Cliente</div>
      <div style="position:relative">
        <input class="fm-inp" id="at-busca-inp"
          placeholder="Buscar cliente cadastrado..."
          autocomplete="off"
          oninput="atBuscaCliente(this.value)"
          onfocus="atBuscaCliente(this.value)">
        <div id="at-busca-lista" class="at-dropdown" style="display:none"></div>
      </div>
      <div id="at-cliente-chip" style="display:none" class="at-chip">
        <span id="at-cliente-nome-chip"></span>
        <button onclick="atLimparCliente()" class="at-chip-del">✕</button>
      </div>
      <input type="hidden" id="at-cliente-id">

      <!-- Mini-form novo cliente -->
      <div id="at-novo-cliente-wrap" style="display:none" class="at-mini-form">
        <div class="at-mini-title">＋ Novo cliente</div>
        <div class="at-mini-row">
          <div class="at-mini-field" style="flex:2">
            <label class="fm-lbl">Nome completo <span class="req">*</span></label>
            <input class="fm-inp" id="atnc-nome" placeholder="Nome completo">
          </div>
        </div>
        <div class="at-mini-row">
          <div class="at-mini-field">
            <label class="fm-lbl">Área jurídica <span class="req">*</span></label>
            <select class="fm-inp" id="atnc-area">
              <option value="">Selecione...</option>
              <option>Trabalhista</option>
              <option>Previdenciário</option>
              <option>Cível</option>
              <option>Família</option>
              <option>Penal</option>
              <option>Administrativo</option>
              <option>Bancário</option>
              <option>Consultoria</option>
            </select>
          </div>
          <div class="at-mini-field">
            <label class="fm-lbl">Telefone / WhatsApp</label>
            <input class="fm-inp" id="atnc-tel" placeholder="(31) 9 0000-0000">
          </div>
        </div>
        <div class="at-mini-row">
          <div class="at-mini-field">
            <label class="fm-lbl">E-mail</label>
            <input class="fm-inp" id="atnc-email" placeholder="email@...">
          </div>
        </div>
        <div class="at-mini-row">
          <div class="at-mini-field">
            <label class="fm-lbl">Observações</label>
            <textarea class="fm-inp" id="atnc-obs" rows="2" placeholder="Informações iniciais..."></textarea>
          </div>
        </div>
        <button class="tp-btn" style="margin-top:4px" onclick="atSalvarNovoCliente()">💾 Salvar cliente</button>
      </div>
    </div>

    <!-- STATUS PIPELINE -->
    <div class="at-section">
      <div class="at-sec-title">📊 Status do Atendimento</div>
      <select class="fm-inp" id="at-status">
        <option value="inicial">Atendimento inicial</option>
        <option value="analise">Em análise</option>
        <option value="proposta">Proposta enviada</option>
        <option value="contratou">Cliente contratou</option>
        <option value="nao-prosseguiu">Cliente não prosseguiu</option>
      </select>
    </div>

    <!-- ASSUNTO -->
    <div class="at-section">
      <div class="at-sec-title">📋 Assunto</div>
      <div class="at-mini-row">
        <div class="at-mini-field">
          <label class="fm-lbl">Tipo</label>
          <select class="fm-inp" id="ns-assunto" onchange="toggleAtAssuntoCustom()">
            <option value="analise">Análise de caso</option>
            <option value="assessoria">Assessoria</option>
            <option value="consultoria">Consultoria</option>
            <option value="contrato">Contrato</option>
            <option value="parecer">Parecer</option>
            <option value="outros">Outros</option>
          </select>
        </div>
        <div class="at-mini-field">
          <label class="fm-lbl">Data</label>
          <input class="fm-inp" id="ns-data-at" type="date" value="${getTodayKey()}">
        </div>
      </div>
      <div id="at-assunto-custom" style="display:none;margin-bottom:8px">
        <label class="fm-lbl">Descreva o assunto</label>
        <input class="fm-inp" id="ns-assunto-txt" placeholder="Descreva o assunto...">
      </div>
      <div>
        <label class="fm-lbl">Resumo / Descrição</label>
        <textarea class="fm-inp" id="ns-resumo" rows="3" placeholder="Descreva o atendimento..."></textarea>
      </div>
    </div>

    <!-- PODE VIRAR PROCESSO? (só para novo cliente) -->
    <div id="at-proc-pergunta" style="display:none" class="at-section">
      <div class="at-sec-title">⚖️ Processo</div>
      <div class="at-proc-toggle">
        <label class="fm-lbl" style="margin:0">Este atendimento pode virar um processo?</label>
        <div style="display:flex;gap:8px;margin-top:8px">
          <button class="at-proc-btn" id="at-proc-sim" onclick="atToggleProc(true)">Sim</button>
          <button class="at-proc-btn on" id="at-proc-nao" onclick="atToggleProc(false)">Não</button>
        </div>
      </div>
      <div id="at-proc-campos" style="display:none;margin-top:10px">
        <div class="at-mini-row">
          <div class="at-mini-field">
            <label class="fm-lbl">Parte contrária</label>
            <input class="fm-inp" id="at-proc-adverso" placeholder="Nome da parte contrária">
          </div>
          <div class="at-mini-field">
            <label class="fm-lbl">Tipo de ação</label>
            <input class="fm-inp" id="at-proc-tipo" placeholder="Ex: Indenização por danos morais">
          </div>
        </div>
        <div class="at-mini-row">
          <div class="at-mini-field">
            <label class="fm-lbl">Número do processo</label>
            <input class="fm-inp" id="at-proc-num" placeholder="0000000-00.0000.0.00.0000 (opcional)">
          </div>
          <div class="at-mini-field">
            <label class="fm-lbl">Vara</label>
            <input class="fm-inp" id="at-proc-vara" placeholder="Ex: 2ª Vara do Trabalho">
          </div>
        </div>
        <div class="at-mini-row">
          <div class="at-mini-field">
            <label class="fm-lbl">Cidade / Comarca</label>
            <input class="fm-inp" id="at-proc-cidade" placeholder="Ex: Belo Horizonte">
          </div>
        </div>
      </div>
    </div>

    <!-- HONORÁRIOS -->
    <div class="at-section">
      <div class="at-sec-title">💰 Honorários (opcional)</div>
      <input class="fm-inp" id="ns-hon" type="text" placeholder="R$ 0,00">
    </div>
  `, salvarAtendimento, 'Salvar atendimento');
  // Pré-preenche a partir de um contato recém-criado: abre a mini-form de
  // "novo cliente" já preenchida. Assim o atendimento fica vinculado ao
  // contato sem precisar buscar/criar de novo.
  if(prefill){
    setTimeout(function(){
      var wrap = document.getElementById('at-novo-cliente-wrap');
      if(wrap) wrap.style.display = 'block';
      var s = function(id, val){ var e=document.getElementById('atnc-'+id); if(e && val) e.value=val; };
      s('nome',  prefill.nome);
      s('tel',   prefill.tel);
      s('email', prefill.email);
      s('obs',   prefill.obs);
    }, 50);
  }
}
function toggleAtAssuntoCustom(){
  const v = document.getElementById('ns-assunto')?.value;
  const wrap = document.getElementById('at-assunto-custom');
  if(wrap) wrap.style.display = v==='outros' ? 'block' : 'none';
}
function atBuscaCliente(q){
  var lista = document.getElementById('at-busca-lista');
  if(!lista) return;
  var sel = document.getElementById('at-cliente-id')?.value;
  if(sel){ lista.style.display='none'; return; }
  var term = (q||'').toLowerCase().trim();
  if(!term){ lista.style.display='none'; return; }

  // Buscar em CLIENTS (processos)
  var matchesProc = CLIENTS
    .filter(function(c){ return c.cliente && c.cliente.toLowerCase().includes(term); })
    .slice(0,8);

  // Buscar em contatos (localContatos)
  var matchesCtc = ctcTodos()
    .filter(function(c){ return (c.nome||'').toLowerCase().includes(term) || (c.tel||'').includes(term); })
    .slice(0,5);

  if(!matchesProc.length && !matchesCtc.length){
    var qEsc = (q||'').replace(/'/g,"\\'");
    lista.innerHTML = '<div style="padding:9px 13px;font-size:12px;color:var(--mu);font-style:italic">Nenhum cliente ou contato encontrado</div>'
      +'<div onclick="atMostrarNovoCliente(\''+qEsc+'\')" style="padding:9px 13px;cursor:pointer;border-top:1px solid var(--bd);font-size:12px;color:var(--ouro);font-weight:600" onmouseover="this.style.background=\'var(--sf3)\'" onmouseout="this.style.background=\'\'">\uff0b Cadastrar <b>'+escapeHtml(q)+'</b> como novo cliente</div>';
    lista.style.display='block';
    return;
  }

  var html = '';
  // Processos existentes
  matchesProc.forEach(function(c){
    html += '<div onclick="atSelecionarCliente('+c.id+',\''+c.cliente.replace(/'/g,"\\'")+'\',\''+( c.pasta||'')+'\')" style="padding:9px 13px;cursor:pointer;border-bottom:1px solid var(--bd);font-size:12px;color:var(--of)" onmouseover="this.style.background=\'var(--sf3)\'" onmouseout="this.style.background=\'\'">'
      +'<div style="font-weight:600">'+escapeHtml(c.cliente)+'</div>'
      +'<div style="font-size:10px;color:var(--mu)">Pasta '+(c.pasta||'\u2014')+' \u00b7 '+(c.natureza||'')+'</div>'
    +'</div>';
  });

  // Contatos (com badge "Contato")
  if(matchesCtc.length){
    html += '<div style="padding:5px 13px;font-size:9px;font-weight:700;text-transform:uppercase;color:var(--mu);letter-spacing:.05em;background:var(--sf3)">Contatos</div>';
    matchesCtc.forEach(function(c){
      var nomeEsc = (c.nome||'').replace(/'/g,"\\'");
      html += '<div onclick="atSelecionarContato(\''+c.id+'\',\''+nomeEsc+'\')" style="padding:9px 13px;cursor:pointer;border-bottom:1px solid var(--bd);font-size:12px;color:var(--of)" onmouseover="this.style.background=\'var(--sf3)\'" onmouseout="this.style.background=\'\'">'
        +'<div style="display:flex;align-items:center;gap:6px"><span style="font-weight:600">'+escapeHtml(c.nome)+'</span><span style="font-size:9px;padding:1px 5px;border-radius:3px;background:rgba(168,130,255,.15);color:#a78bfa">Contato</span></div>'
        +'<div style="font-size:10px;color:var(--mu)">'+(c.tel||'')+(c.tel&&c.email?' \u00b7 ':'')+(c.email||'')+'</div>'
      +'</div>';
    });
  }

  lista.innerHTML = html;
  lista.style.display='block';
}

// Selecionar contato existente → auto-preencher campos do novo cliente
function atSelecionarContato(ctcId, nome){
  var c = ctcTodos().find(function(x){return String(x.id)===String(ctcId);});
  if(!c) return;
  // Mostrar form de novo cliente com dados preenchidos
  atMostrarNovoCliente(c.nome||'');
  setTimeout(function(){
    var inp = document.getElementById('atnc-nome'); if(inp) inp.value = c.nome||'';
    var tel = document.getElementById('atnc-tel'); if(tel) tel.value = c.tel||'';
    var email = document.getElementById('atnc-email'); if(email) email.value = c.email||'';
    var obs = document.getElementById('atnc-obs'); if(obs && c.obs) obs.value = c.obs;
  }, 50);
  var lista = document.getElementById('at-busca-lista');
  if(lista) lista.style.display='none';
}
function atLimparCliente(){
  document.getElementById('at-cliente-id').value = '';
  document.getElementById('at-busca-inp').value  = '';
  const chip = document.getElementById('at-cliente-chip');
  if(chip) chip.style.display='none';
  const procPerg = document.getElementById('at-proc-pergunta');
  if(procPerg) procPerg.style.display='none';
}

// ── Helpers do modal de atendimento ──────────────────────────
function atMostrarNovoCliente(nomeInicial){
  const lista = document.getElementById('at-busca-lista');
  if(lista) lista.style.display='none';
  const wrap = document.getElementById('at-novo-cliente-wrap');
  if(wrap) wrap.style.display='block';
  const nomeInp = document.getElementById('atnc-nome');
  if(nomeInp && nomeInicial) nomeInp.value = nomeInicial;
  const pq = document.getElementById('at-proc-pergunta');
  if(pq) pq.style.display='block';
}

function atSelecionarCliente(id, nome, pasta){
  document.getElementById('at-cliente-id').value = id;
  document.getElementById('at-busca-inp').value  = nome;
  const chip = document.getElementById('at-cliente-chip');
  const lbl  = document.getElementById('at-cliente-nome-chip');
  if(chip) chip.style.display='flex';
  if(lbl)  lbl.textContent = nome + (pasta?' · Pasta '+pasta:'');
  const lista = document.getElementById('at-busca-lista');
  if(lista) lista.style.display='none';
  // Ocultar mini-form novo cliente
  const w = document.getElementById('at-novo-cliente-wrap');
  if(w) w.style.display='none';
  // Ocultar pergunta processo (só para novo cliente)
  const pq = document.getElementById('at-proc-pergunta');
  if(pq) pq.style.display='none';
}

function atSalvarNovoCliente(){
  const nome  = document.getElementById('atnc-nome')?.value.trim();
  const area  = document.getElementById('atnc-area')?.value;
  const tel   = document.getElementById('atnc-tel')?.value.trim()||'';
  const email = document.getElementById('atnc-email')?.value.trim()||'';
  const obs   = document.getElementById('atnc-obs')?.value.trim()||'';
  if(!nome){ showToast('Informe o nome do cliente'); return; }
  if(!area){ showToast('Selecione a área jurídica'); return; }
  const id = genId();
  const novoCliente = {
    id, pasta: 'AT'+String(id).slice(-6),
    cliente: nome, natureza: area,
    tel, email,
    tipo: 'consulta', status_consulta: 'consulta',
    condicao:'', comarca:'', instancia:'',
    numero:'', data_inicio: getTodayKey(),
    ultima_mov_dias: 0,
    movimentacoes:[], agenda:[], partes:[]
  };
  if(obs) notes[id] = obs;
  tasks[id] = { extra: { tel, email } };
    CLIENTS.push(novoCliente);
  sbSet('co_tasks', tasks);
  sbSet('co_notes', notes);
  sbSalvarClientesDebounced();
  marcarAlterado();
  montarClientesAgrupados();
  doSearch();
  // Selecionar automaticamente
  atSelecionarCliente(id, nome, novoCliente.pasta);
  document.getElementById('at-novo-cliente-wrap').style.display='none';
  // Manter pergunta do processo visível
  const pq = document.getElementById('at-proc-pergunta');
  if(pq) pq.style.display='block';
  showToast('Cliente cadastrado ✓');
}
function atToggleProc(sim){
  document.getElementById('at-proc-campos').style.display = sim ? 'block' : 'none';
  document.getElementById('at-proc-sim').classList.toggle('on', sim);
  document.getElementById('at-proc-nao').classList.toggle('on', !sim);
}
function salvarAtendimento(){
  var clienteIdSel = document.getElementById('at-cliente-id')?.value;
  var clienteMatch = clienteIdSel ? CLIENTS.find(function(c){return String(c.id)===String(clienteIdSel);}) : null;
  var nomeVal = clienteMatch ? clienteMatch.cliente
    : (document.getElementById('at-busca-inp')?.value.trim()||'');

  if(!nomeVal){ showToast('Informe o nome do cliente'); return; }

  // Se não encontrou por ID, tentar por nome (evita duplicata)
  if(!clienteMatch && nomeVal){
    clienteMatch = findClientByName(nomeVal);
    if(clienteMatch) clienteIdSel = String(clienteMatch.id);
  }
  // Se realmente não existe, criar entrada (contato → cliente)
  if(!clienteMatch && nomeVal){
    var novoId = genId();
    var novoCliente = {
      id: novoId, cliente: nomeVal, pasta: '',
      tipo: 'consulta', status_consulta: 'consulta',
      natureza: '', data_inicio: getTodayKey()
    };
    CLIENTS.push(novoCliente);
    _clientByIdCache = {};
    _clientByNameCache = {};
    if(typeof montarClientesAgrupados==='function') montarClientesAgrupados();
    sbSet('co_clientes', CLIENTS);
    clienteIdSel = String(novoId);
    clienteMatch = novoCliente;
  }

  const assunto    = document.getElementById('ns-assunto')?.value||'consultoria';
  const assuntoTxt = assunto==='outros'
    ? (document.getElementById('ns-assunto-txt')?.value.trim()||'Outros') : assunto;
  const resumo  = document.getElementById('ns-resumo')?.value.trim()||'';
  const dataAt  = document.getElementById('ns-data-at')?.value||getTodayKey();
  const honRaw  = document.getElementById('ns-hon')?.value.trim()||'';
  const status  = document.getElementById('at-status')?.value||'inicial';

  const ASSUNTO_LABEL = {
    analise:'Análise de caso', assessoria:'Assessoria',
    consultoria:'Consultoria', contrato:'Contrato',
    parecer:'Parecer'
  };
  const assuntoLabel = ASSUNTO_LABEL[assunto]||assuntoTxt;
  const descricao = `[Atendimento] ${assuntoLabel}${resumo?': '+resumo:''}`;

  // Salvar em localAtend (pipeline CRM)
  var idAt = 'at'+genId();
  const registro = {
    id: idAt, cliente: nomeVal, id_cliente: clienteIdSel,
    assunto: assuntoLabel, resumo, data: dataAt,
    status, honorarios: honRaw||null,
    criado_em: new Date().toISOString()
  };
  localAtend.push(registro);
  sbSet('co_atend', localAtend);

  // Andamento no processo
  if(clienteMatch){
    if(!localMov[clienteMatch.id]) localMov[clienteMatch.id]=[];
    localMov[clienteMatch.id].unshift({
      data: dataAt, movimentacao: descricao,
      tipo_movimentacao: 'Atendimento', origem: 'atendimento'
    });
    sbSet('co_localMov', localMov);
  }

  // Agenda local
  localAg.push({
    id: idAt, titulo: assuntoLabel, descricao: resumo,
    tipo_compromisso: 'Atendimento', cliente: nomeVal,
    id_processo: clienteMatch?.id||null,
    dt_raw: dataAt, inicio: dataAt+'T09:00',
    realizado: true, origem: 'atendimento'
  });
  sbSet('co_ag', localAg); invalidarAllPend();

  // Honorários
  if(honRaw){
    const valor=parseFloat(honRaw.replace(/[^\d,]/g,'').replace(',','.'));
    if(valor>0){
      localLanc.push({
        id:'hon'+genId(), descricao:`Honorários — ${assuntoLabel} (${nomeVal})`,
        valor, tipo:'receber', direcao:'receber', data:dataAt, dt_venc:dataAt,
        status:'pendente', cliente:nomeVal, id_processo:clienteMatch?.id||null, origem:'atendimento'
      });
      sbSet('co_localLanc', localLanc);
    }
  }

  // Processo opcional (novo cliente)
  const procSim = document.getElementById('at-proc-sim')?.classList.contains('on');
  if(procSim){
    const adverso = document.getElementById('at-proc-adverso')?.value.trim()||'';
    const tipo    = document.getElementById('at-proc-tipo')?.value.trim()||'';
    const num     = document.getElementById('at-proc-num')?.value.trim()||'';
    const vara    = document.getElementById('at-proc-vara')?.value.trim()||'';
    const cidade  = document.getElementById('at-proc-cidade')?.value.trim()||'';
    if(clienteMatch){
      clienteMatch.numero  = clienteMatch.numero||num;
      clienteMatch.comarca = clienteMatch.comarca||vara||cidade;
      clienteMatch.adverso = clienteMatch.adverso||adverso;
      clienteMatch.tipo_acao = clienteMatch.tipo_acao||tipo;
      clienteMatch.status_consulta = 'processo';
      marcarAlterado();
      montarClientesAgrupados();
      doSearch();
    }
  }

  // Se "Cliente contratou" → sugerir processo
  if(status==='contratou'){
    fecharModal();
    renderChecklist(); renderHomeWeek(); renderHomeAlerts();
    showToast('Atendimento salvo ✓');
    setTimeout(()=>{
      abrirModal('🎉 Cliente contratou!',
        `<div style="text-align:center;padding:8px 0">
          <div style="font-size:32px;margin-bottom:12px">⚖️</div>
          <div style="font-size:14px;font-weight:600;color:var(--of);margin-bottom:8px">${nomeVal}</div>
          <div style="font-size:12px;color:var(--mu);margin-bottom:16px">Deseja criar um processo vinculado a este cliente agora?</div>
          <div style="display:flex;gap:8px;margin-top:12px">
            <button class="tp-btn" style="flex:1" onclick="fecharModal();setTimeout(novoProcesso,150)">⚖️ Criar processo</button>
            <button class="tp-btn ghost" style="flex:1" onclick="fecharModal()">Agora não</button>
          </div>
        </div>`,
        null, null
      );
    }, 400);
    return;
  }

  fecharModal();
  renderChecklist(); renderHomeWeek(); renderHomeAlerts();
  audit('criacao','Atendimento: '+assuntoLabel+' — '+nomeVal,'atendimento');
  showToast('Atendimento registrado ✓');
}
function renderPendencias(c){
  const pends = (tasks[c.id]||{}).pendencias||[];
  const fmt = p=>`
    <div class="pend-item" id="pend-${c.id}-${p.id}">
      <input type="checkbox" ${p.done?'checked':''} onchange="togglePend(${c.id},${p.id})" style="accent-color:var(--ouro);width:15px;height:15px;flex-shrink:0">
      <span class="pend-txt${p.done?' done':''}">${p.texto}</span>
      <button onclick="delPend(${c.id},${p.id})" class="hc-item-del">✕</button>
    </div>`;
  return `
    <div class="pend-wrap">
      <div class="dp-sep">📋 Pendências</div>
      <div id="pend-list-${c.id}">${pends.length?pends.map(fmt).join(''):'<div style="font-size:12px;color:var(--mu);font-style:italic">Nenhuma pendência cadastrada</div>'}</div>
      <div style="display:flex;gap:8px;margin-top:10px">
        <input class="dp-input" id="pend-inp-${c.id}" placeholder="Nova pendência..." style="flex:1" onkeydown="if(event.key==='Enter')addPend(${c.id})">
        <button onclick="addPend(${c.id})" style="background:var(--vinho);border:none;border-radius:5px;padding:7px 14px;color:#fff;cursor:pointer;font-size:12px">＋</button>
      </div>
    </div>`;
}

function addPend(cid){
  const inp = document.getElementById('pend-inp-'+cid);
  const txt = inp.value.trim();
  if(!txt) return;
  if(!tasks[cid]) tasks[cid]={};
  if(!tasks[cid].pendencias) tasks[cid].pendencias=[];
  tasks[cid].pendencias.push({id:genId(),texto:txt,done:false});
  inp.value='';
  sbSet('co_tasks', tasks);
  marcarAlterado();
  // Re-render lista
  const el = document.getElementById('pend-list-'+cid);
  if(el) el.innerHTML = tasks[cid].pendencias.map(p=>`
    <div class="pend-item">
      <input type="checkbox" ${p.done?'checked':''} onchange="togglePend(${cid},${p.id})" style="accent-color:var(--ouro);width:15px;height:15px;flex-shrink:0">
      <span class="pend-txt${p.done?' done':''}">${p.texto}</span>
      <button onclick="delPend(${cid},${p.id})" class="hc-item-del">✕</button>
    </div>`).join('');
}

function togglePend(cid,pid){
  const p = (tasks[cid]||{}).pendencias||[];
  const item = p.find(x=>x.id===pid);
  if(item){ item.done=!item.done; sbSet('co_tasks', tasks); marcarAlterado(); }
}

function delPend(cid,pid){
  abrirModal('Excluir pendência','<div style="font-size:13px;color:var(--mu)">Excluir esta pendência?</div>',function(){
    fecharModal();
    if(!tasks[cid]?.pendencias) return;
    tasks[cid].pendencias = tasks[cid].pendencias.filter(function(p){return p.id!==pid;});
    sbSet('co_tasks', tasks);
    marcarAlterado();
    const el = document.getElementById('pend-list-'+cid);
    if(el) el.innerHTML = tasks[cid].pendencias.length
      ? tasks[cid].pendencias.map(p=>`<div class="pend-item">
          <input type="checkbox" ${p.done?'checked':''} onchange="togglePend(${cid},${p.id})" style="accent-color:var(--ouro);width:15px;height:15px;flex-shrink:0">
          <span class="pend-txt${p.done?' done':''}">${p.texto}</span>
          <button onclick="delPend(${cid},${p.id})" class="hc-item-del">✕</button>
        </div>`).join('')
      : '<div style="font-size:12px;color:var(--mu);font-style:italic">Nenhuma pendência</div>';
  }, 'Excluir');
}

function converterEmProcesso(cid){
  const c = findClientById(cid);
  if(!c) return;

  const inp = (id,ph='',cls='') =>
    `<input id="cp-${id}" class="dist-inp${cls?' '+cls:''}" placeholder="${ph}">`;
  const sel = (id, opts) =>
    `<select id="cp-${id}" class="dist-inp">${opts.map(o=>
      typeof o==='string'?`<option>${o}</option>`:`<option value="${o.v}">${o.l}</option>`
    ).join('')}</select>`;

  abrirModal('⚖️ Distribuição de Processo', `
    <div class="dist-alerta">
      📋 Consultante: <strong>${c.cliente}</strong> — todo o histórico será mantido
    </div>

    <!-- IDENTIFICAÇÃO DO PROCESSO -->
    <div class="dist-sec">📁 Identificação do Processo</div>
    <div class="dist-grid dist-grid-2">
      <div class="dist-field">
        <label class="dist-lbl">Número do processo <span class="dist-req">*</span></label>
        ${inp('num','0000000-00.0000.0.00.0000','req')}
      </div>
      <div class="dist-field">
        <label class="dist-lbl">Data de distribuição</label>
        <input id="cp-dt" class="dist-inp" type="date" value="${new Date().toISOString().slice(0,10)}">
      </div>
    </div>
    <div class="dist-grid dist-grid-2" style="margin-top:8px">
      <div class="dist-field">
        <label class="dist-lbl">Natureza <span class="dist-req">*</span></label>
        ${sel('nat',['Trabalhista','Previdenciário','Cível','Família','Administrativo','Penal','Bancário','Outro'])}
      </div>
      <div class="dist-field">
        <label class="dist-lbl">Tipo de ação</label>
        ${inp('tipo_acao','Ex: Reclamação Trabalhista, Aposentadoria...')}
      </div>
    </div>

    <!-- COMPETÊNCIA -->
    <div class="dist-sec">🏛️ Competência</div>
    <div class="dist-grid dist-grid-3">
      <div class="dist-field">
        <label class="dist-lbl">Comarca <span class="dist-req">*</span></label>
        ${inp('comarca','Ex: Belo Horizonte','req')}
      </div>
      <div class="dist-field">
        <label class="dist-lbl">Vara / Juízo</label>
        ${inp('vara','Ex: 3ª Vara do Trabalho')}
      </div>
      <div class="dist-field">
        <label class="dist-lbl">Instância</label>
        ${sel('instancia',['1ª instância','2ª instância','TST','STJ','STF'])}
      </div>
    </div>

    <!-- PARTES -->
    <div class="dist-sec">👥 Partes</div>
    <div class="dist-grid dist-grid-2">
      <div class="dist-field">
        <label class="dist-lbl">Cliente é o polo</label>
        ${sel('polo',[
          {v:'Autor',l:'Autor (quem propõe)'},
          {v:'Réu',l:'Réu (quem responde)'},
          {v:'Requerente',l:'Requerente'},
          {v:'Requerido',l:'Requerido'},
          {v:'Reclamante',l:'Reclamante (trabalhista)'},
          {v:'Reclamado',l:'Reclamado (trabalhista)'},
          {v:'Apelante',l:'Apelante'},
        ])}
      </div>
      <div class="dist-field">
        <label class="dist-lbl">Parte adversa <span class="dist-req">*</span></label>
        ${inp('adv','Nome da empresa ou pessoa adversa','req')}
      </div>
    </div>
    <div class="dist-grid dist-grid-2" style="margin-top:8px">
      <div class="dist-field">
        <label class="dist-lbl">CPF / CNPJ do adverso</label>
        ${inp('adv_doc','000.000.000-00 ou 00.000.000/0000-00')}
      </div>
      <div class="dist-field">
        <label class="dist-lbl">Advogado adverso</label>
        ${inp('adv_adv','Nome do advogado da outra parte')}
      </div>
    </div>

    <!-- PEDIDOS E CONTEXTO -->
    <div class="dist-sec">📝 Pedidos e Contexto</div>
    <div class="dist-grid" style="grid-template-columns:1fr">
      <div class="dist-field">
        <label class="dist-lbl">Valor da causa</label>
        <input id="cp-valor" class="dist-inp" placeholder="R$ 0,00" type="text">
      </div>
    </div>
    <div class="dist-field" style="margin-top:8px">
      <label class="dist-lbl">Pedidos principais</label>
      <textarea id="cp-pedidos" class="dist-inp" rows="2"
        placeholder="Ex: Reconhecimento de vínculo, horas extras, FGTS, dano moral..."></textarea>
    </div>
    <div class="dist-field" style="margin-top:8px">
      <label class="dist-lbl">Observações / Estratégia inicial</label>
      <textarea id="cp-obs" class="dist-inp" rows="2"
        placeholder="Contexto do caso, pontos de atenção, estratégia..."></textarea>
    </div>
  `, ()=>{
    const g = id => document.getElementById('cp-'+id)?.value.trim()||'';
    const num     = g('num');
    const comarca = g('comarca');
    const adv     = g('adv');
    if(!num)    { showToast('Número do processo obrigatório'); return; }
    if(!comarca){ showToast('Comarca obrigatória'); return; }
    if(!adv)    { showToast('Parte adversa obrigatória'); return; }

    // Atualizar o cliente — mantém id, histórico, pendências, obs, dados privados
    c.numero      = num;
    c.comarca     = comarca + (g('vara') ? ' — ' + g('vara') : '');
    c.natureza    = g('nat');
    c.adverso     = adv;
    c.data_inicio = g('dt');
    c.polo        = g('polo');
    c.instancia   = g('instancia');
    c.tipo_acao   = g('tipo_acao');
    c.adv_doc     = g('adv_doc');
    c.adv_adv     = g('adv_adv');
    c.valor_causa = g('valor');
    c.pedidos     = g('pedidos');
    c.status_consulta = 'processo';
    c.tipo        = 'processo';

    // Acrescentar nas observações sem apagar o histórico
    const partes = [];
    if(g('polo')) partes.push({nome:c.cliente, condicao:g('polo'), cliente:'Sim'});
    if(adv)       partes.push({nome:adv, condicao:g('polo')==='Autor'?'Réu':'Autor', cliente:'Não'});
    c.partes = [...(c.partes||[]), ...partes];

    const notas = [];
    if(g('pedidos'))  notas.push('Pedidos: '+g('pedidos'));
    if(g('obs'))      notas.push('Obs: '+g('obs'));
    if(notas.length){
      notes[c.id] = (notes[c.id] ? notes[c.id]+'\n\n' : '')
        + '── Distribuição '+new Date().toLocaleDateString('pt-BR')+' ──\n'
        + notas.join('\n');
    }

    sbSet('co_tasks', tasks);
    sbSet('co_notes', notes);
    sbSalvarClientesDebounced();
    marcarAlterado();
    fecharModal();
    montarClientesAgrupados();
    doSearch();
    setTimeout(()=>renderFicha(c), 200);
  }, 'Distribuir processo', '#1d4ed8');
}



function renderFinUnificado(cid){
  const c = findClientById(cid);
  if(!c) return '<div style="font-size:12px;color:var(--mu);padding:20px;text-align:center;font-style:italic">Processo não encontrado.</div>';

  const hoje = new Date().toISOString().slice(0,10);
  const fV   = function(v){ return 'R$ '+Math.abs(v||0).toLocaleString('pt-BR',{minimumFractionDigits:2,maximumFractionDigits:2}); };
  const catMap = {
    alvara:'Aguardando Alvará', acordo:'Acordo', honorario:'Honorários',
    honorario_direto:'Honorários', sucumbencia:'Sucumbência',
    despesa:'Despesa', despint:'Despesa', repasse:'Repasse',
    honorario_pag:'Pag. parceiro', reembolso:'Reembolso', outro:'Outros'
  };

  const todos = _finGetLocais(cid)
    .slice().sort(function(a,b){ return (b.data||b.venc||'').localeCompare(a.data||a.venc||''); });

  if(!todos.length)
    return '<div style="font-size:12px;color:var(--mu);padding:20px;text-align:center;font-style:italic">Nenhum lançamento. Clique em + Entrada ou + Saída.</div>';

  // Group acordos
  var grupos = {}, avulsos = [];
  todos.forEach(function(l){
    if(l._grupo_acordo){
      if(!grupos[l._grupo_acordo]) grupos[l._grupo_acordo]=[];
      grupos[l._grupo_acordo].push(l);
    } else {
      avulsos.push(l);
    }
  });

  function menuHtml(l, extraItems){
    var mid = 'fmm-'+l.id;
    var isPago   = isRec(l);
    var isAguard = l.tipo==='alvara';
    var isPos    = l.tipo!=='repasse'&&l.tipo!=='despesa'&&l.tipo!=='despint'&&l.direcao!=='pagar';
    var items = [];
    if(isAguard)      items.push({t:'💰 Chegou',       fn:'abrirFluxoAlvara('+cid+','+l.id+')'});
    else if(!isPago)  items.push({t:(isPos?'✓ Receber':'✓ Pagar'), fn:'vfBaixar(\'l'+l.id+'\')'});
    else              items.push({t:'↩ Estornar',       fn:'finEstornarLocal('+cid+','+l.id+')'});
    items.push({t:'✏ Editar', fn:'finEditarLanc('+cid+','+l.id+')'});
    if(!isPago) items.push({t:'✕ Excluir', fn:'finDelLanc('+cid+',\''+l.id+'\')'});
    if(extraItems) items = items.concat(extraItems);
    return '<div style="position:relative;display:inline-block">'
      +'<button onclick="var m=document.getElementById(\''+mid+'\');m.style.display=m.style.display===\'none\'?\'block\':\'none\'"'
        +' style="font-size:16px;line-height:1;padding:0 6px;border:none;background:transparent;color:var(--mu);cursor:pointer">⋮</button>'
      +'<div id="'+mid+'" style="display:none;position:absolute;right:0;top:100%;z-index:99;background:var(--sf2);border:1px solid var(--bd);border-radius:6px;box-shadow:0 4px 16px rgba(0,0,0,.4);min-width:140px;overflow:hidden">'
        +items.map(function(it){
          return '<div onclick="document.getElementById(\''+mid+'\').style.display=\'none\';'+it.fn+'"'
            +' style="padding:9px 14px;font-size:12px;cursor:pointer;color:var(--tx);white-space:nowrap"'
            +' onmouseover="this.style.background=\'var(--sf3)\'" onmouseout="this.style.background=\'transparent\'">'+it.t+'</div>';
        }).join('')
      +'</div></div>';
  }

  function singleRow(l){
    var isPago   = isRec(l);
    var isAguard = l.tipo==='alvara';
    var isRep    = l.tipo==='repasse'||l._repasse_alvara||l._repasse_acordo;
    var isDesp   = l.tipo==='despesa'||l.tipo==='despint';
    var isPos    = !isRep&&!isDesp&&l.direcao!=='pagar';
    var vencido  = !isPago&&!isAguard&&(l.venc||l.data)&&(l.venc||l.data)<hoje;
    var corVal   = isAguard?'#fb923c':isPos?(isPago?'#4ade80':'var(--tx)'):'#f87676';
    var bgRow    = isAguard?'rgba(251,146,60,.04)':'transparent';
    var catLabel = escapeHtml(catMap[l.tipo]||l.tipo);
    var catCor   = isAguard?'rgba(251,146,60,.15)':isRep?'rgba(201,72,74,.12)':isDesp?'rgba(201,72,74,.12)':'rgba(76,175,125,.12)';
    var catText  = isAguard?'#fb923c':isRep||isDesp?'#f87676':'#4ade80';

    var statusIcon = isPago
      ? '<span style="color:#4ade80;font-size:11px">✓</span>'
      : vencido ? '<span style="font-size:9px;font-weight:700;color:#c9484a">!</span>'
      : '';

    // Remove nome do cliente repetido na descrição (ex: "Honorários 30% — 1/1 ADAO CRISTINO")
    var _cliNome = (c.cliente||'').trim();
    var descLimpa = (l.desc||'—');
    if(_cliNome) {
      descLimpa = descLimpa
        .replace(new RegExp('\\s*—\\s*\\d+\/\\d+\\s+' + _cliNome.replace(/[.*+?^${}()|[\]\\]/g,'\\$&') + '\\s*$','i'),'')
        .replace(new RegExp('\\s*—\\s*' + _cliNome.replace(/[.*+?^${}()|[\]\\]/g,'\\$&') + '\\s*$','i'),'')
        .trim();
    }
    if(!descLimpa) descLimpa = l.desc||'—';

    // Projuris-style row: [data+badge | descrição | valor+status+menu]
    return '<div class="fin-lanc-row" style="background:'+bgRow+'">'
      +'<div class="fin-lanc-col-date">'
        +'<div class="fin-lanc-date">'+fDt(l.data||l.venc)+'</div>'
        +'<span class="fin-lanc-badge" style="background:'+catCor+';color:'+catText+'">'
          +catLabel+(isAguard?' ⏳':'')
        +'</span>'
      +'</div>'
      +'<div class="fin-lanc-col-desc">'
        +'<div class="fin-lanc-desc" title="'+escapeHtml(l.desc||'')+'">'+escapeHtml(descLimpa)+'</div>'
        +(isPago&&l.dt_baixa?'<div class="fin-lanc-obs">Pago em '+fDt(l.dt_baixa)+'</div>':'')
        +(vencido?'<div class="fin-lanc-obs" style="color:#c9484a">Vencido</div>':'')
      +'</div>'
      +'<div class="fin-lanc-col-valor">'
        +'<span class="fin-lanc-status">'+statusIcon+'</span>'
        +'<span class="fin-lanc-valor" style="color:'+corVal+'">'+(isPos?'+':'−')+' '+fV(l.valor)+'</span>'
        +menuHtml(l)
      +'</div>'
    +'</div>';
  }

  var html = '<div>'
    +'<div class="fin-lanc-header">'
      +'<span style="width:110px;min-width:110px">Data / Tipo</span>'
      +'<span style="flex:1">Descrição</span>'
      +'<span style="width:200px;min-width:200px;text-align:right">Valor</span>'
    +'</div>';

  // Acordos agrupados — UMA linha por grupo
  Object.keys(grupos).forEach(function(gid){
    var lancs  = grupos[gid].sort(function(a,b){return (a.data||'').localeCompare(b.data||'');});
    var hon    = lancs.filter(function(l){return l.tipo!=='repasse'&&!l._repasse_acordo;});
    var reps   = lancs.filter(function(l){return l.tipo==='repasse'||l._repasse_acordo;});
    var nPago  = hon.filter(function(l){return isRec(l);}).length;
    var nTot   = hon[0]?._total_parc || hon.length;
    var vTot   = hon.reduce(function(s,l){return s+(parseFloat(l.valor)||0);},0);
    var vbruto = hon[0]?._vbruto || 0;
    var tudo   = nPago===nTot && nTot>0;
    var dtUlt  = hon[nPago-1]?.data || hon[0]?.data || '';
    var expandId = 'grp-'+gid;
    var desc   = hon[0]?.desc?.replace(/ — honorários \d+%/,'').replace(/ \(\d+\/\d+\)/,'') || 'Acordo';
    var cliente= hon[0]?.cliente || c.cliente || '—';

    html += '<div class="fin-lanc-row" style="cursor:pointer" onclick="var d=document.getElementById(\''+expandId+'\');d.style.display=d.style.display===\'none\'?\'block\':\'none\';this.querySelector(\'.grp-arr\').textContent=d.style.display===\'none\'?\'›\':\'∨\'">'
      +'<div class="fin-lanc-col-date">'
        +'<div class="fin-lanc-date">'+fDt(dtUlt)+'</div>'
        +'<span class="fin-lanc-badge" style="background:rgba(251,146,60,.12);color:#fb923c">Acordo</span>'
      +'</div>'
      +'<div class="fin-lanc-col-desc">'
        +'<div class="fin-lanc-desc"><span style="margin-right:8px">'+escapeHtml(desc)+'</span>'
          +'<span style="font-size:10px;background:var(--sf3);border:1px solid var(--bd);border-radius:4px;padding:1px 6px;color:var(--mu)">'+nPago+'/'+nTot+' parcelas</span>'
          +(vbruto>0?' <span style="font-size:10px;color:var(--mu)">· '+fV(vbruto)+' bruto</span>':'')
        +'</div>'
      +'</div>'
      +'<div class="fin-lanc-col-valor">'
        +(tudo?'<span style="color:#4ade80;font-size:12px">✓</span>':'')
        +'<span class="fin-lanc-valor" style="color:'+(tudo?'#4ade80':'#fb923c')+'">+ '+fV(vTot)+'</span>'
        +'<span class="grp-arr" style="font-size:11px;color:var(--mu);width:20px;text-align:center">›</span>'
      +'</div>'
    +'</div>';

    // Parcelas individuais — ocultas por padrão
    html += '<div id="'+expandId+'" style="display:none">';
    lancs.forEach(function(l){ html += singleRow(l); });
    html += '</div>';
  });

  // Lançamentos avulsos
  avulsos.forEach(function(l){ html += singleRow(l); });

  html += '</div>';
  return html;
}

function renderFinResumo(cid){
  const el = document.getElementById('fin-resumo-'+cid);
  if(!el) return;
  const c = findClientById(cid);
  if(!c) return;
  const fmtV = function(v){return 'R$ '+Math.abs(v||0).toLocaleString('pt-BR',{minimumFractionDigits:2,maximumFractionDigits:2});};
  const hoje = new Date().toISOString().slice(0,10);
  const locais = _finGetLocais(cid);

  var honRec=0, outrosRec=0, desp=0, repassePago=0, repassePend=0;
  var repPassos=[], acordos=[];

  locais.forEach(function(l){
    var val  = parseFloat(l.valor||0);
    var pago = isRec(l);
    var isRep= l.tipo==='repasse'||l._repasse_alvara||l._repasse_acordo;
    var isDesp= l.tipo==='despesa'||l.tipo==='despint'||l.tipo==='despesa_reimb';

    if(isRep){
      if(pago) repassePago+=val; else { repPassos.push(l); repassePend+=val; }
    } else if(isDesp){
      if(pago) desp+=val;
    } else if(l.tipo==='honorario'||l.tipo==='sucumbencia'||l.tipo==='acordo'){
      if(pago) honRec+=val; else outrosRec+=val; // outrosRec = honPend aqui
      // Collect acordo groups for progress bar
      if((l.tipo==='honorario'||l.tipo==='acordo') && l._grupo_acordo){
        var g = acordos.find(function(a){return a.grupo===l._grupo_acordo;});
        if(!g){ g={grupo:l._grupo_acordo,total:l._total_parc||1,pago:0,pendente:0,vbruto:l._vbruto||0,desc:l.desc}; acordos.push(g); }
        if(pago) g.pago++; else g.pendente++;
      }
    } else {
      if(pago) outrosRec+=val;
    }
  });

  var totalRec = honRec + outrosRec;
  var html = '';

  // ── Alertas urgentes de repasse ──
  repPassos.forEach(function(rp){
    if(!rp.venc) return;
    var d = Math.ceil((new Date(rp.venc)-new Date(hoje))/(1000*60*60*24));
    if(d<=3){
      var urg=d<=0;
      html += '<div style="display:flex;align-items:center;justify-content:space-between;padding:6px 10px;'
        +'background:rgba(201,72,74,'+(urg?'.12':'.07')+');border:1px solid rgba(201,72,74,'+(urg?'.4':'.2')+');border-radius:6px;margin-bottom:8px">'
        +'<span style="font-size:11px;font-weight:700;color:#c9484a">'+(urg?'🔴 Repasse vencido':'⚠ Repasse vence em '+d+'d')+' — '+fmtV(rp.valor)+'</span>'
        +'<button onclick="abrirFluxoRepasse('+cid+','+rp.id+')" style="font-size:10px;font-weight:700;padding:3px 10px;border-radius:4px;border:none;background:#c9484a;color:#fff;cursor:pointer">Pagar agora</button>'
      +'</div>';
    }
  });

  // ── 3 chips compactos em linha ──
  function chip(label, valor, cor, badge){
    return '<div style="flex:1;min-width:0;padding:8px 10px;background:var(--sf2);border:1px solid var(--bd);border-radius:8px">'
      +'<div style="font-size:9px;font-weight:700;text-transform:uppercase;letter-spacing:.06em;color:var(--mu);margin-bottom:4px">'+label+'</div>'
      +'<div style="font-size:13px;font-weight:700;color:'+cor+'">'+fmtV(valor)+'</div>'
      +(badge?'<div style="font-size:9px;margin-top:2px;color:var(--mu)">'+badge+'</div>':'')
    +'</div>';
  }

  var repBadge = repassePend>0
    ? '<span style="color:#c9484a">'+fmtV(repassePend)+' pendente</span>'
    : (repassePago>0?'<span style="color:#4ade80">✓ pago</span>':'');

  html += '<div style="display:flex;gap:6px;margin-bottom:10px">'
    + chip('Honorários', honRec, honRec>0?'#4ade80':'var(--mu)', outrosRec>0?'<span style="color:#f59e0b">'+fmtV(outrosRec)+' pendente</span>':(honRec>0?'\u2713 recebido':'\u2014'))
    + chip('Repasse', repassePago, repassePago>0?'var(--tx)':'var(--mu)', repBadge||'—')
    + chip('Despesas', desp, desp>0?'#f87676':'var(--mu)', desp>0?'registrado':'—')
  +'</div>';

  // ── Alerta repasse pendente (não urgente) ──
  if(repPassos.length && repPassos.every(function(r){var d=Math.ceil((new Date(r.venc||hoje)-new Date(hoje))/(1000*60*60*24));return d>3;})){
    html += '<div style="display:flex;align-items:center;justify-content:space-between;padding:6px 10px;background:rgba(201,72,74,.06);border:1px solid rgba(201,72,74,.2);border-radius:6px;margin-bottom:8px">'
      +'<span style="font-size:11px;color:#c9484a">📤 Repasse pendente: '+fmtV(repassePend)+'</span>'
      +'<button onclick="abrirFluxoRepasse('+cid+','+repPassos[0].id+')" style="font-size:10px;font-weight:700;padding:3px 10px;border-radius:4px;border:none;background:#c9484a;color:#fff;cursor:pointer">Registrar</button>'
    +'</div>';
  }

  // ── Acordo progress (compacto) ──
  acordos.forEach(function(a){
    var tot=a.total||1, rec=a.pago, pct=Math.round((rec/tot)*100);
    html += '<div style="padding:6px 0;border-top:1px solid var(--bd)">'
      +'<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:5px">'
        +'<span style="font-size:11px;font-weight:600;color:var(--tx)">Acordo '+rec+'/'+tot+(a.vbruto>0?' · '+fmtV(a.vbruto)+' bruto':'')+'</span>'
        +(rec===tot?'<span style="font-size:10px;color:#4ade80;font-weight:700">✓ completo</span>':'<span style="font-size:10px;color:var(--mu)">'+a.pendente+' faltam</span>')
      +'</div>'
      +'<div style="height:5px;background:var(--sf3);border-radius:3px;overflow:hidden">'
        +'<div style="height:100%;width:'+pct+'%;background:'+(rec===tot?'#4ade80':'#fb923c')+';border-radius:3px;transition:width .4s"></div>'
      +'</div>'
    +'</div>';
  });

  el.innerHTML = html;
}


function renderFinXlsx(c){
  // Now renders into finxlsx2-cid (inside tp4) AND old finxlsx-cid
  ['finxlsx-'+c.id, 'finxlsx2-'+c.id].forEach(function(eid){
    const el = document.getElementById(eid);
    if(!el) return;
    const pasta = String(c.pasta||'');
    const lancs = (FIN_XLSX||[]).filter(function(l){
      return String(l.pasta)===pasta ||
        (l.pasta||'').toLowerCase()===c.cliente.toLowerCase().substring(0,10);
    });
    if(!lancs.length){ el.innerHTML=''; return; }
    const baixasMap = {};
    (finLancs||[]).forEach(function(b){ if(b._projuris_id) baixasMap['p'+b._projuris_id]=b; });
    (localLanc||[]).forEach(function(b){ if(b.proj_ref) baixasMap[b.proj_ref]=b; });
    lancs.forEach(function(l){
      const b=baixasMap['p'+l.id];
      if(b&&(b.pago||b.status==='pago')) l.status='pago';
    });
    const hoje = new Date().toISOString().slice(0,10);
    const sorted = lancs.slice().sort(function(a,b){return (b.dt_venc||'').localeCompare(a.dt_venc||'');});
    const totalPend = sorted.filter(function(l){return l.status!=='pago';}).reduce(function(s,l){return s+l.val;},0);
    const totalPago = sorted.filter(function(l){return l.status==='pago';}).reduce(function(s,l){return s+l.val;},0);
    const fmtV = function(v){return 'R$ '+Math.abs(v||0).toLocaleString('pt-BR',{minimumFractionDigits:2,maximumFractionDigits:2});};

    var rows = sorted.map(function(l){
      const isPago = l.status==='pago';
      const vencido = !isPago && l.dt_venc && l.dt_venc < hoje;
      const statusCor = isPago?'#4ade80':vencido?'#c9484a':'#f59e0b';
      const statusTxt = isPago?'PAGO':vencido?'VENCIDO':'PENDENTE';
      return '<div style="display:flex;align-items:center;gap:10px;padding:8px 0;border-bottom:1px solid var(--bd)">'
        +'<div style="flex:1;min-width:0">'
          +'<div style="font-size:12px;color:var(--tx);font-weight:500;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">'+(l.desc||l.mov_projuris||'Honorário')+'</div>'
          +'<div style="font-size:10px;color:var(--mu);margin-top:1px">Venc: '+fDt(l.dt_venc)+'</div>'
        +'</div>'
        +'<div style="text-align:right;flex-shrink:0">'
          +'<div style="font-size:13px;font-weight:700;color:'+statusCor+'">'+fmtV(l.val)+'</div>'
          +'<div style="font-size:10px;color:'+statusCor+';font-weight:600">'+statusTxt+'</div>'
        +'</div>'
        +(isPago
          ?'<span style="font-size:10px;color:#4ade80;min-width:70px;text-align:center">✓ Recebido</span>'
          :'<button onclick="vfBaixar(\'p'+l.id+'\')" style="min-width:70px;font-size:11px;font-weight:600;padding:5px 10px;border-radius:5px;background:rgba(76,175,125,.12);border:1px solid rgba(76,175,125,.3);color:#4ade80;cursor:pointer">✓ Receber</button>'
        )
      +'</div>';
    }).join('');

    el.innerHTML = (totalPend>0||totalPago>0?
      '<div style="display:flex;gap:8px;margin-bottom:10px">'
        +(totalPend>0?'<div style="font-size:11px;color:#f59e0b"><span style="color:var(--mu)">A receber: </span><strong>'+fmtV(totalPend)+'</strong></div>':'')
        +(totalPago>0?'<div style="font-size:11px;color:#4ade80"><span style="color:var(--mu)">Recebido: </span><strong>'+fmtV(totalPago)+'</strong></div>':'')
      +'</div>':''
    )+rows;
  });
}


function renderDpPopover(c, aba){
  const ex = (tasks[c.id]||{}).extra || {};
  const v  = k => ex[k]||'';
  if(aba==='banco') return `
    <div class="dp-pop-section">
      <div class="cad-row">
        <div class="cad-field" style="flex:2">
          <label class="dp-lbl">Banco</label>
          <input class="dp-input" data-k="banco" value="${v('banco')}" placeholder="Ex: Nubank, Itaú..." onblur="saveDpField(${c.id},this)">
        </div>
        <div class="cad-field sm">
          <label class="dp-lbl">Tipo de conta</label>
          <select class="dp-input" data-k="tconta" onchange="saveDpField(${c.id},this)">
            <option value="">—</option>
            ${['Corrente','Poupança','Pagamento'].map(o=>`<option ${v('tconta')===o?'selected':''}>${o}</option>`).join('')}
          </select>
        </div>
      </div>
      <div class="cad-row">
        <div class="cad-field sm">
          <label class="dp-lbl">Agência</label>
          <input class="dp-input" data-k="ag" value="${v('ag')}" placeholder="0000" onblur="saveDpField(${c.id},this)">
        </div>
        <div class="cad-field">
          <label class="dp-lbl">Conta + dígito</label>
          <div class="pwd-wrap">
            <input class="dp-input" type="password" data-k="conta" id="dp-pop-conta-${c.id}"
              value="${v('conta')}" placeholder="000000-0"
              onblur="saveDpField(${c.id},this)" style="flex:1;font-family:monospace">
            <button class="pwd-eye" onclick="toggleDpPwd('dp-pop-conta-${c.id}',this)">👁</button>
          </div>
        </div>
      </div>
      <div class="cad-row">
        <div class="cad-field sm">
          <label class="dp-lbl">Operação</label>
          <input class="dp-input" data-k="operacao" value="${v('operacao')}" placeholder="Ex: 1288" onblur="saveDpField(${c.id},this)">
        </div>
        <div class="cad-field">
          <label class="dp-lbl">Chave PIX</label>
          <input class="dp-input" data-k="pix" value="${v('pix')}" placeholder="CPF, e-mail, celular ou chave aleatória" onblur="saveDpField(${c.id},this)">
        </div>
      </div>
      <div class="cad-row">
        <div class="cad-field" style="flex:2">
          <label class="dp-lbl">Nome do beneficiário</label>
          <input class="dp-input" data-k="nomebenef" value="${v('nomebenef')}" placeholder="Nome completo como no banco" onblur="saveDpField(${c.id},this)">
        </div>
        <div class="cad-field">
          <label class="dp-lbl">CPF / CNPJ</label>
          <input class="dp-input" data-k="cpfbenef" value="${v('cpfbenef')}" placeholder="000.000.000-00" onblur="saveDpField(${c.id},this)">
        </div>
      </div>
      <div id="dp-saved-pop-${c.id}" style="font-size:10px;color:var(--ouro);opacity:0;transition:opacity .3s;margin-top:6px">✓ Salvo automaticamente</div>
    </div>`;
  if(aba==='inss') return `
    <div class="dp-pop-section">
      <div class="cad-row">
        <div class="cad-field full">
          <label class="dp-lbl">Usuário / CPF Meu INSS</label>
          <input class="dp-input" data-k="inss_user" value="${v('inss_user')}" placeholder="CPF ou usuário de acesso" onblur="saveDpField(${c.id},this)">
        </div>
      </div>
      <div class="cad-row">
        <div class="cad-field full">
          <label class="dp-lbl">Senha Meu INSS</label>
          <div class="pwd-wrap">
            <input class="dp-input" type="password" data-k="inss" id="dp-pop-inss-${c.id}"
              value="${v('inss')}" placeholder="••••••••" autocomplete="new-password"
              onblur="saveDpField(${c.id},this)" style="flex:1;font-family:monospace">
            <button class="pwd-eye" onclick="toggleDpPwd('dp-pop-inss-${c.id}',this)">👁</button>
          </div>
        </div>
      </div>
      <div class="cad-row">
        <div class="cad-field full">
          <label class="dp-lbl">Observação de acesso</label>
          <input class="dp-input" data-k="inss_obs" value="${v('inss_obs')}" placeholder="Ex: benefício nº, senha diferente..." onblur="saveDpField(${c.id},this)">
        </div>
      </div>
      <div id="dp-saved-pop-${c.id}" style="font-size:10px;color:var(--ouro);opacity:0;transition:opacity .3s;margin-top:6px">✓ Salvo automaticamente</div>
    </div>`;
  return '';
}
function toggleProcExtra(cid){
  const body = document.getElementById('proc-extra-body-'+cid);
  const lbl  = document.getElementById('proc-extra-lbl-'+cid);
  if(!body) return;
  const open = body.style.display !== 'none';
  body.style.display = open ? 'none' : 'block';
  if(lbl) lbl.textContent = open ? '▸ Ver detalhes do processo' : '▾ Ocultar detalhes';
}

function toggleDpPopover(cid){
  const pop = document.getElementById('dp-pop-'+cid);
  const btn = document.getElementById('dp-btn-'+cid);
  if(!pop) return;
  const visible = pop.style.display !== 'none';
  pop.style.display = visible ? 'none' : 'block';
  if(btn) btn.classList.toggle('active', !visible);
  // Fechar ao clicar fora
  if(!visible){
    setTimeout(()=>{
      const handler = e => {
        if(!pop.contains(e.target) && e.target !== btn){
          pop.style.display = 'none';
          btn && btn.classList.remove('active');
          document.removeEventListener('click', handler);
        }
      };
      document.addEventListener('click', handler);
    }, 50);
  }
}
function dpPopTab(cid, aba, btn){
  // Trocar aba ativa
  const header = btn.closest('.dp-pop-header');
  header.querySelectorAll('.dp-pop-tab').forEach(b=>b.classList.remove('on'));
  btn.classList.add('on');
  const body = document.getElementById('dp-pop-body-'+cid);
  // Precisamos do objeto c — pegar do AC global
  if(body && AC) body.innerHTML = renderDpPopover(AC, aba);
}

function renderDadosPrivados(c){
  const ex = (tasks[c.id]||{}).extra || {};
  const v = k => ex[k]||'';

  // Mascarar conta bancária
  const contaMask = v('conta') ? v('conta').replace(/^(.+)(\d)$/, (_, p, d) => '•'.repeat(Math.max(0,p.length-2)) + p.slice(-2) + d) : '';

  return `
  <div class="dp-form" id="dp-${c.id}">
    <div class="dp-sep">🏦 Dados Bancários</div>
    <div class="cad-row">
      <div class="cad-field" style="flex:2">
        <label class="dp-lbl">Banco</label>
        <input class="dp-input" data-k="banco" value="${v('banco')}" placeholder="Ex: Nubank, Itaú..." onblur="saveDpField(${c.id},this)">
      </div>
      <div class="cad-field sm">
        <label class="dp-lbl">Tipo de conta</label>
        <select class="dp-input" data-k="tconta" onchange="saveDpField(${c.id},this)">
          <option value="">—</option>
          ${['Corrente','Poupança','Pagamento'].map(o=>`<option ${v('tconta')===o?'selected':''}>${o}</option>`).join('')}
        </select>
      </div>
    </div>
    <div class="cad-row">
      <div class="cad-field sm">
        <label class="dp-lbl">Agência</label>
        <input class="dp-input" data-k="ag" value="${v('ag')}" placeholder="0000" onblur="saveDpField(${c.id},this)">
      </div>
      <div class="cad-field" style="position:relative">
        <label class="dp-lbl">Conta + dígito</label>
        <div class="pwd-wrap">
          <input class="dp-input" type="password" data-k="conta" id="dp-conta-${c.id}"
            value="${v('conta')}" placeholder="000000-0"
            onblur="saveDpField(${c.id},this)" style="flex:1;font-family:monospace">
          <button class="pwd-eye" onclick="toggleDpPwd('dp-conta-${c.id}',this)">👁</button>
        </div>
      </div>
    </div>
    <div class="cad-row">
      <div class="cad-field full">
        <label class="dp-lbl">Chave PIX</label>
        <input class="dp-input" data-k="pix" value="${v('pix')}" placeholder="CPF, e-mail, celular ou chave aleatória" onblur="saveDpField(${c.id},this)">
      </div>
    </div>

    <div class="dp-sep" style="margin-top:18px">🔐 Acesso Meu INSS</div>
    <div class="cad-row">
      <div class="cad-field full">
        <label class="dp-lbl">Senha Meu INSS</label>
        <div class="pwd-wrap">
          <input class="dp-input" type="password" data-k="inss" id="dp-inss-${c.id}"
            value="${v('inss')}" placeholder="••••••••" autocomplete="new-password"
            onblur="saveDpField(${c.id},this)" style="flex:1;font-family:monospace">
          <button class="pwd-eye" onclick="toggleDpPwd('dp-inss-${c.id}',this)">👁</button>
        </div>
      </div>
    </div>

    <div id="dp-saved-${c.id}" style="font-size:11px;color:var(--ouro);opacity:0;transition:opacity .3s;margin-top:8px">✓ Salvo automaticamente</div>
  </div>`;
}

function toggleDpPwd(id, btn){
  const inp = document.getElementById(id);
  if(!inp) return;
  inp.type = inp.type==='password' ? 'text' : 'password';
  btn.textContent = inp.type==='password' ? '👁' : '🙈';
  // Auto-ocultar após 30s
  if(inp.type==='text'){
    clearTimeout(inp._timer);
    inp._timer = setTimeout(()=>{ inp.type='password'; btn.textContent='👁'; }, 30000);
  }
}


function saveDpField(cid, el){
  const k = el.dataset.k;
  const v = el.value;
  if(!tasks[cid]) tasks[cid]={};
  if(!tasks[cid].extra) tasks[cid].extra={};
  tasks[cid].extra[k] = v;
  sbSet('co_tasks', tasks);
  marcarAlterado();
  // Flash confirmação
  const saved = document.getElementById('dp-saved-'+cid);
  if(saved){ saved.style.opacity='1'; setTimeout(()=>saved.style.opacity='0',2000); }
}

function togglePwd(btn){
  const inp = btn.previousElementSibling;
  inp.type = inp.type==='password'?'text':'password';
  btn.textContent = inp.type==='password'?'👁':'🙈';
}


function toggleTema(){
  const isLight = document.body.classList.toggle('light');
  document.getElementById('btn-tema').textContent = isLight ? '☀️' : '🌙';
  localStorage.setItem('co_tema', isLight ? 'light' : 'dark');
}
// Carregar tema salvo
(function(){
  const t = localStorage.getItem('co_tema');
  if(t==='light'){ document.body.classList.add('light'); 
    setTimeout(()=>{ const b=document.getElementById('btn-tema'); if(b) b.textContent='☀️'; },100); }
})();


// Dados carregados do servidor (dados.json)
var CLIENTS=[], ALL_LANC=[], PEND=[], FIN_XLSX=[];
const MOV_INDEX={};
// Despesas de processo (reembolso) — variável que era usada sem declaração (ReferenceError)
var despesasProcesso = [];
try{ var _dp = JSON.parse(lsGet('co_desp_proc')||'[]'); if(Array.isArray(_dp)) despesasProcesso=_dp; }catch{}

// ── Salvar CLIENTS no Supabase ──
function sbSalvarClientes(){
  // Usar debounce para evitar múltiplos POSTs em cascata (ex: novoProcesso chama sbSet + montarClientes + doSearch)
  sbSetDebounced('co_clientes', CLIENTS);
}
// Debounce de alto nível para operações de edição que disparam múltiplos salvamentos em sequência
function sbSalvarClientesDebounced(){ _debounce('sbClientes', sbSalvarClientes, 200); }

// ── Carregar CLIENTS do Supabase (sobrescreve embutidos se existir) ──
async function sbCarregarClientes(){
  try{
    var r = await fetch(
      _SB_URL+'/rest/v1/'+_SB_TBL+'?chave=in.(co_clientes,co_clientes_consulta)&select=chave,valor',
      {headers:_sbH(), signal:AbortSignal.timeout(6000)}
    );
    if(!r.ok) return false;
    var rows = await r.json();
    if(!rows.length) return false;
    var remoto = [];
    rows.forEach(function(row){
      if(Array.isArray(row.valor)) remoto = remoto.concat(row.valor);
    });
    if(!remoto.length) return false;
    // MERGE com dados locais — preservar novos processos que ainda não chegaram ao Supabase.
    // Passa 'co_clientes' como chave para que tombstones filtrem clientes deletados.
    var merged = _sbMergeArrays(CLIENTS, remoto, 'co_clientes');
    CLIENTS.length = 0;
    merged.forEach(function(c){ CLIENTS.push(c); });
    _clientByIdCache={}; _clientByNameCache={};
    return true;
  }catch(e){ return false; }
}

async function carregarDados(){
  // Dados embutidos extraídos para data-embedded.json (reduzir tamanho do app.js)
  // Fallback: objeto vazio se o JSON falhar (Supabase preenche depois)
  let d = {versao:"1.0", clientes:[], agenda:[], all_lanc:[], mutavel:{}, financeiro_xlsx:[], despesas_processo:[]};
  try {
    const r = await fetch('dados.json?v=59');
    if(r.ok) d = await r.json();
  } catch(e) { console.warn('[carregarDados] dados.json indisponível:', e.message); }
  carregarDadosObj(d);
}

function carregarDadosObj(d){
  // Tentar carregar CLIENTS do localStorage primeiro (preserva novos processos)
  var localClients = null;
  try { localClients = JSON.parse(lsGet('co_clientes')||'null'); } catch(e){}
  var embutidos = d.clientes || d.clients || [];
  if(Array.isArray(localClients) && localClients.length > 0){
    // Merge: local tem prioridade, embutidos completam
    CLIENTS = localClients;
    var localIds = new Set(CLIENTS.map(function(c){return String(c.id);}));
    embutidos.forEach(function(c){
      if(!localIds.has(String(c.id))) CLIENTS.push(c);
    });
  } else {
    CLIENTS = embutidos;
  }
  ALL_LANC  = d.all_lanc  || [];
  FIN_XLSX  = d.financeiro_xlsx || [];
  PEND      = (d.agenda   || d.agenda_pendentes || []).map(p=>({...p,
    dt_raw: p.dt_raw||p.data||p.dt_inicio||'',
    inicio: p.inicio||(p.data?(p.data+' '+(p.hora||'08:00')+':00'):'')
  }));
  // Dados mutáveis — prioridade localStorage (mais recente), fallback arquivo
  const m = d.mutavel || {};
  function loadKey(lsKey, fileVal, def){
    try{
      var ls = lsGet(lsKey);
      if(ls){
        var parsed = JSON.parse(ls);
        if(Array.isArray(parsed)?parsed.length>0:Object.keys(parsed).length>0) return parsed;
      }
    }catch(e){}
    return fileVal && (Array.isArray(fileVal)?fileVal.length>0:Object.keys(fileVal).length>0) ? fileVal : def;
  }
  tasks         = loadKey('co_tasks',        m.tasks,         {});
  encerrados    = loadKey('co_encerrados',    m.encerrados,    {});
  notes         = loadKey('co_notes',         m.notes,         {});
  localAg       = loadKey('co_ag',             m.localAg,       []);
  localMov      = loadKey('co_localMov',      m.localMov,      {});
  localLanc     = loadKey('co_localLanc',     m.localLanc,     []);
  localContatos = loadKey('co_ctc', m.localContatos, []);
  tarefasDia    = loadKey('co_td',             m.tarefasDia,    {});
  // Filtrar arrays carregados por tombstones (anti-zombificação — itens deletados
  // num PC podem ainda estar no snapshot carregado se chegaram antes do tombstone).
  if(typeof _tombstoneHas==='function'){
    localLanc = (localLanc||[]).filter(function(x){ return !_tombstoneHas('co_localLanc', x.id); });
    localContatos = (localContatos||[]).filter(function(x){ return !_tombstoneHas('co_ctc', x.id); });
    localAg = (localAg||[]).filter(function(x){ return !_tombstoneHas('co_ag', x.id) && !_tombstoneHas('co_localAg', x.id); });
  }
  // Carregar dados financeiros globais do localStorage (persistidos via sbSet)
  try{ const _fin=JSON.parse(lsGet('co_fin')||'null'); if(Array.isArray(_fin)&&_fin.length) finLancs=_fin.filter(function(x){ return typeof _tombstoneHas!=='function' || !_tombstoneHas('co_fin', x.id); }); }catch{}
  try{ const _clb=JSON.parse(lsGet('co_colab')||'null'); if(Array.isArray(_clb)) _colaboradores=_clb; }catch{}
  try{ const _dpf=JSON.parse(lsGet('co_despfixas')||'null'); if(Array.isArray(_dpf)) _despFixas=_dpf; }catch{}
  // Adicionar consultas locais aos clientes
  try{
    const consultas = JSON.parse(lsGet('co_consultas')||'[]');
    consultas.forEach(c=>{ if(!findClientById(c.id)) CLIENTS.push(c); });
  }catch{}
  // Montar CLIENTES_AGRUPADOS por nome
  montarClientesAgrupados();
}

function montarClientesAgrupados(){
  // Deduplicar CLIENTS por ID (mesmo processo aparece 1x)
  var seenIds = new Set();
  var dedupClients = [];
  CLIENTS.forEach(function(c){
    var k = String(c.id);
    if(seenIds.has(k)) return;
    seenIds.add(k);
    dedupClients.push(c);
  });
  if(dedupClients.length < CLIENTS.length){
    CLIENTS.length = 0;
    dedupClients.forEach(function(c){ CLIENTS.push(c); });
    _clientByIdCache = {};
    _clientByNameCache = {};
  }
  // Agrupar por nome
  var mapa = {};
  CLIENTS.forEach(function(c){
    var nome = (c.cliente||'').trim();
    if(!mapa[nome]) mapa[nome] = { id: c.id, nome:nome, processos: [] };
    mapa[nome].processos.push(c);
  });
  CLIENTES_AGRUPADOS = Object.values(mapa).sort(function(a,b){return a.nome.localeCompare(b.nome,'pt-BR');});
  // Renumerar pastas — cada processo recebe número único sequencial
  var pastaNum = 1;
  CLIENTES_AGRUPADOS.forEach(function(grp){
    grp.processos.forEach(function(c){
      c.pasta = String(pastaNum);
      pastaNum++;
    });
  });
  _rebuildClientsIndex();
  invalidarCacheVfTodos();
}


const HOJE = new Date(); HOJE.setHours(0,0,0,0);
if(!_vfMes) _vfMes = new Date(HOJE).toISOString().slice(0,7);
const HS = HOJE.toISOString().slice(0,10);
const SEMANA = new Date(HOJE); SEMANA.setDate(SEMANA.getDate()+7);
const MESFIM = new Date(2026,2,31);

let AC=null, AC_PROC=null, _grupoAtual=null, filtro='todos', agF='todos';

// ── PERF: índice de clientes por id (O(1) lookup) ─────────────────────
// Substitui findClientById(id) chamado em loops — de O(n) para O(1)
let _clientsById = new Map();
function _rebuildClientsIndex(){
  _clientsById = new Map();
  (CLIENTS||[]).forEach(function(c){ _clientsById.set(String(c.id), c); });
}
function clientById(id){
  const r = _clientsById.get(String(id));
  if(r) return r;
  return (CLIENTS||[]).find(function(c){ return String(c.id)===String(id); });
}

// ── PERF: string de hoje cacheada — evita new Date(HOJE).toISOString() em loops ──
const _HOJE_STR = new Date(HOJE).toISOString().slice(0,10);

// ── PERF: cache do resultado de vfTodos() ─────────────────────────────
// Invalida quando marcarAlterado() é chamado; a função vfTodos() devolve o cache quando válido
let _vfTodosCache = null;
let _vfTodosInvalido = true;
function invalidarCacheVfTodos(){ _vfTodosInvalido = true; _vfTodosCache = null; }

let CLIENTES_AGRUPADOS=[];
let tasks={}, notes={}, localAg=[], localMov={}, localLanc=[], encerrados={}, localContatos=[], tarefasDia={};
// Tombstone list: keys `_migrado_projuris|tipo` de lançamentos migrados que foram excluídos pelo usuário.
// Usado pelo bloco de migração (bundle.js:~371) para não re-inserir itens deletados.
var _projurisDeletados = new Set();
try{ var _pd = JSON.parse(lsGet('co_projuris_del')||'[]'); if(Array.isArray(_pd)) _pd.forEach(function(k){ _projurisDeletados.add(k); }); }catch{}

// ═══════════════════════════════════════════════════════════════
// ══ TOMBSTONES UNIVERSAIS PARA SINCRONIZAÇÃO ═════════════════
// ═══════════════════════════════════════════════════════════════
// Sem isso, quando o usuário deleta um item localmente, o Supabase realtime
// recebe o remoto (que ainda tem o item) e o _sbMergeArrays re-insere (união cega).
// Este mapa armazena IDs deletados por chave (ex: co_fin, co_localLanc).
// Persistido em localStorage + Supabase sob `<chave>_del` (ex: co_fin_del).
var _arrayTombstones = {};
function _tombstoneLoad(chave){
  if(_arrayTombstones[chave]) return _arrayTombstones[chave];
  var set = new Set();
  try{ var raw = JSON.parse(lsGet(chave+'_del')||'[]'); if(Array.isArray(raw)) raw.forEach(function(id){ set.add(String(id)); }); }catch{}
  _arrayTombstones[chave] = set;
  return set;
}
function _tombstoneAdd(chave, id){
  var set = _tombstoneLoad(chave);
  set.add(String(id));
  try{ lsSet(chave+'_del', JSON.stringify(Array.from(set))); }catch{}
  try{ sbSet(chave+'_del', Array.from(set)); }catch{}
}
function _tombstoneHas(chave, id){
  return _tombstoneLoad(chave).has(String(id));
}
// Carregar tombstones dos arrays financeiros no boot
_tombstoneLoad('co_fin');
_tombstoneLoad('co_localLanc');

// Cleanup: arrays carregados ANTES dos helpers de tombstone existirem
// (como vkTasks, já lido em linha ~2256) podem conter itens deletados em outro PC.
// Filtrar agora garante que a UI nunca mostra "fantasmas" no primeiro render.
if(Array.isArray(vkTasks)){
  vkTasks = vkTasks.filter(function(x){ return !_tombstoneHas('co_vktasks', x.id); });
}

var localAtend=[];
try{
  localAtend=JSON.parse(lsGet('co_atend')||'[]');
  if(!Array.isArray(localAtend)) localAtend=[];
  localAtend = localAtend.filter(function(x){ return !_tombstoneHas('co_atend', x.id); });
}catch{}

// Carregar comentários do localStorage
var comentarios = {};
try { const _c = JSON.parse(lsGet('co_coments')||'null'); comentarios = (_c&&typeof _c==='object'&&!Array.isArray(_c)) ? _c : {}; } catch{}

let modalCb=null, mvVisto={}, finTab='pagar';
var finLancs=[];
try{
  finLancs=JSON.parse(lsGet('co_fin')||'[]');
  if(typeof _tombstoneHas==='function'){
    finLancs = finLancs.filter(function(x){ return !_tombstoneHas('co_fin', x.id); });
  }
}catch{}

// Fluxo de caixa global (Monte Mor) — co_monte_mor
var monteMor=[];
try{monteMor=JSON.parse(lsGet('co_monte_mor')||'[]');}catch{}

function nc(n){return{Trabalhista:'nt',Previdenciário:'np',Cível:'nc',Família:'nf',Administrativo:'na',Consultoria:'nco',Penal:'npe',Bancário:'nba'}[n]||'na';}
function fBRL(v){var n=Number(v);return'R$ '+(isFinite(n)?n:0).toLocaleString('pt-BR',{minimumFractionDigits:2,maximumFractionDigits:2});}
function diasAte(dtStr){const d=new Date(dtStr);return Math.ceil((d-HOJE)/(86400000));}


// ── EXCLUIR PROCESSO ──
function excluirProcesso(cid){
  const c=findClientById(cid);
  if(!c)return;
  abrirModal(`Excluir — ${c.cliente}`,
    `<div style="color:var(--mu);font-size:12px;line-height:1.8">
      <p>⚠ Tem certeza que deseja <strong style="color:#f87676">excluir permanentemente</strong> este processo do app?</p>
      <p style="margin-top:8px;color:#f59e0b">Esta ação não pode ser desfeita. Os dados do Projuris não são afetados.</p>
      <p style="margin-top:8px">Processo: <strong style="color:var(--fg)">${c.cliente} — Pasta ${c.pasta}</strong></p>
    </div>`,
    ()=>{
      // Tombstone: registra antes de splice local, pra que outro PC que tenha o
      // cliente ainda no array receba a marca de exclusão e NÃO ressuscite.
      _tombstoneAdd('co_clientes', cid);
      // Remover do CLIENTS
      const idx=CLIENTS.findIndex(x=>x.id===cid);
      if(idx>=0) CLIENTS.splice(idx,1);
      sbSalvarClientes();
      // Remover do CLIENTES_AGRUPADOS
      const gi=CLIENTES_AGRUPADOS.findIndex(g=>g.processos&&g.processos.some(p=>p.id===cid));
      if(gi>=0){
        const g=CLIENTES_AGRUPADOS[gi];
        g.processos=g.processos.filter(p=>p.id!==cid);
        if(g.processos.length===0) CLIENTES_AGRUPADOS.splice(gi,1);
        else g.id=g.processos[0].id;
      }
      // Limpar dados deste id em todos os stores
      delete encerrados[cid]; delete tasks[cid]; delete notes[cid]; delete localMov[cid];
      sbSet('co_encerrados', encerrados);
      sbSet('co_tasks', tasks);
      sbSet('co_notes', notes);
      sbSet('co_localMov', localMov);
      marcarAlterado();
      // Atualizar UI
      fecharModal();
      AC=null; AC_PROC=null; _grupoAtual=null;
      const _fOld=document.getElementById('ficha'); if(_fOld) _fOld.classList.remove('on');
      const _fvcl=document.getElementById('ficha-vcl'); if(_fvcl){_fvcl.classList.remove('on');_fvcl.innerHTML='';}
      const _e2b=document.getElementById('emp2'); if(_e2b) _e2b.style.display='flex';
      var _st1=document.getElementById('st1'); if(_st1) _st1.textContent=CLIENTS.filter(function(c){return !getEncIds().has(c.id)&&c.tipo!=='consulta';}).length;
      atualizarBadgeEnc();
      doSearch()
      atualizarStats();
      showToast('Processo excluído do app');
    },
    'Excluir', '#7a1010'
  );
}



// ══════════════════════════════════════════════════
// ── SALVAR / EXPORTAR / IMPORTAR ──
// ══════════════════════════════════════════════════
let _salvando = false;

function getMutavel(){
  return { tasks, encerrados, notes, localAg, localMov, localLanc, localContatos, tarefasDia };
}

function getDadosCompletos(){
  return {
    clientes: CLIENTS.filter(c=>c.tipo!=='consulta'&&c.status_consulta!=='consulta'),
    consultas_locais: CLIENTS.filter(c=>c.tipo==='consulta'||c.status_consulta==='consulta'),
    agenda: PEND,
    all_lanc: ALL_LANC,
    financeiro_xlsx: FIN_XLSX,
    mutavel: getMutavel()
  };
}

function salvarArquivo(){
  if(_salvando) return;
  _salvando = true;
  const btn = document.getElementById('btn-salvar');
  if(btn){ btn.textContent='⏳ Salvando...'; btn.disabled=true; }

  try{
    const dados = getDadosCompletos();
    const dadosStr = JSON.stringify(dados, null, 0);
    
    // Pegar o HTML atual e substituir o bloco de dados dentro de carregarDados
    const src = document.documentElement.outerHTML;
    // Substituir o JSON embutido dentro de carregarDados
    const updated = src.replace(
      /const d = \{[\s\S]*?\};\/\/ FIM_DADOS/,
      'const d = ' + dadosStr.replace(/\\/g,'\\\\') + ';// FIM_DADOS'
    );
    
    const blob = new Blob([updated], {type:'text/html;charset=utf-8'});
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement('a');
    a.href = url;
    a.download = 'Escritorio_Clarissa_App.html';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    
    _unsaved = false;
    if(btn){ btn.textContent='✓ Salvo!'; btn.style.background='#14532d'; btn.disabled=false; }
    setTimeout(()=>{ if(btn){ btn.textContent='💾 Salvar'; btn.style.background=''; }}, 2500);
  } catch(e) {
    console.error('Erro ao salvar:', e);
    if(btn){ btn.textContent='⚠ Erro'; btn.style.background='#7f1d1d'; btn.disabled=false; }
    setTimeout(()=>{ if(btn){ btn.textContent='💾 Salvar'; btn.style.background=''; }}, 3000);
  }
  _salvando = false;
}

function exportarDados(){
  const dados = getDadosCompletos();
  const blob = new Blob([JSON.stringify(dados, null, 2)], {type:'application/json'});
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement('a');
  a.href = url;
  a.download = 'dados_escritorio_' + new Date().toISOString().slice(0,10) + '.json';
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
  alert('✓ Dados exportados! Compartilhe o arquivo .json para sincronizar com outro computador.');
}

function importarDados(){
  const inp = document.createElement('input');
  inp.type = 'file';
  inp.accept = '.json';
  inp.onchange = e => {
    const file = e.target.files[0];
    if(!file) return;
    const reader = new FileReader();
    reader.onload = ev => {
      try{
        const d = JSON.parse(ev.target.result);
        // Mesclar consultas locais
        if(d.consultas_locais){
          d.clientes = [...(d.clientes||[]), ...(d.consultas_locais||[])];
        }
        carregarDadosObj(d);
        // Salvar mutável no localStorage
        sbSet('co_tasks', tasks);
        sbSet('co_encerrados', encerrados);
        sbSet('co_notes', notes);
        sbSet('co_ag', localAg); invalidarAllPend();
        sbSet('co_localMov', localMov);
        sbSet('co_localLanc', localLanc);
        sbSet('co_ctc', localContatos); invalidarCtcCache();
        sbSet('co_td', tarefasDia);
        marcarAlterado();
        montarClientesAgrupados(); atualizarStats(); renderChecklist(); renderHomeWeek(); doSearch();
        alert('✓ Dados importados com sucesso!');
      }catch(err){
        alert('Erro ao importar: ' + err.message);
      }
    };
    reader.readAsText(file);
  };
  inp.click();
}

// ═══════════════════════════════════════════════════════════════
// ══ LIMPEZA DE PASTAS VAZIAS + RENUMERAÇÃO ══
// ═══════════════════════════════════════════════════════════════

function _pastaEhVazia(c){
  // Pasta é vazia se não tem: movimentações, lançamentos, agenda, tarefas, comentários
  var temMov = (c.movimentacoes && c.movimentacoes.length > 0)
    || (localMov[c.id] && localMov[c.id].length > 0)
    || (MOV_INDEX && MOV_INDEX[String(c.id)] && MOV_INDEX[String(c.id)].length > 0);
  var temLanc = (localLanc||[]).some(function(l){ return l.id_processo === c.id; });
  var temAg = (c.agenda && c.agenda.length > 0)
    || (typeof localAg !== 'undefined' && localAg.some(function(a){ return a.id_processo === c.id; }));
  var temTask = tasks[c.id] && tasks[c.id].length > 0;
  var temNota = notes[c.id] && notes[c.id].length > 0;
  var temComent = (typeof comentarios !== 'undefined') && comentarios[c.id] && comentarios[c.id].length > 0;
  var temPrazo = (typeof prazos !== 'undefined') && prazos[c.id] && prazos[c.id].length > 0;

  return !temMov && !temLanc && !temAg && !temTask && !temNota && !temComent && !temPrazo;
}

function limparPastasVazias(){
  var vazias = CLIENTS.filter(function(c){ return _pastaEhVazia(c); });

  if(!vazias.length){
    showToast('Nenhuma pasta vazia encontrada');
    return;
  }

  var nomes = vazias.slice(0, 20).map(function(c){
    return 'Pasta ' + c.pasta + ' — ' + (c.cliente||'sem nome');
  }).join('\n');
  var mais = vazias.length > 20 ? '\n... e mais ' + (vazias.length - 20) : '';

  abrirModal('🗑 Limpar ' + vazias.length + ' pasta' + (vazias.length>1?'s':'') + ' vazia' + (vazias.length>1?'s':''),
    '<div style="color:var(--mu);font-size:12px;line-height:1.6">'
      +'<p>Foram encontradas <strong style="color:#f59e0b">' + vazias.length + ' pastas</strong> sem nenhum dado (sem movimentações, lançamentos, agenda, tarefas ou comentários).</p>'
      +'<div style="max-height:200px;overflow-y:auto;background:var(--sf3);border-radius:6px;padding:8px 12px;margin:10px 0;font-size:11px;white-space:pre-line;color:var(--tx)">' + escapeHtml(nomes + mais) + '</div>'
      +'<p style="color:#c9484a;font-weight:600">Deseja excluir todas?</p>'
    +'</div>',
    function(){
      var ids = new Set(vazias.map(function(c){ return c.id; }));
      CLIENTS = CLIENTS.filter(function(c){ return !ids.has(c.id); });
      // Limpar dados vinculados
      ids.forEach(function(id){
        delete encerrados[id]; delete tasks[id]; delete notes[id]; delete localMov[id];
      });
      sbSalvarClientes();
      sbSet('co_encerrados', encerrados);
      sbSet('co_tasks', tasks);
      sbSet('co_notes', notes);
      sbSet('co_localMov', localMov);
      marcarAlterado();
      montarClientesAgrupados();
      fecharModal();
      AC = null; AC_PROC = null;
      doSearch();
      atualizarStats();
      showToast('✓ ' + vazias.length + ' pasta' + (vazias.length>1?'s':'') + ' vazia' + (vazias.length>1?'s':'') + ' removida' + (vazias.length>1?'s':''));
      audit('limpar_pastas', 'sistema', vazias.length + ' pastas vazias removidas');
    },
    '🗑 Sim, excluir vazias', '#c9484a'
  );
}

function renumerarPastas(){
  var ativos = CLIENTS.filter(function(c){
    return !isEncerrado(c.id);
  }).sort(function(a,b){
    return (a.cliente||'').localeCompare(b.cliente||'', 'pt-BR');
  });
  var encerr = CLIENTS.filter(function(c){
    return isEncerrado(c.id);
  }).sort(function(a,b){
    return (a.cliente||'').localeCompare(b.cliente||'', 'pt-BR');
  });

  // Ativos: 1, 2, 3...  Encerrados: continuam depois
  var n = 1;
  ativos.forEach(function(c){ c.pasta = n; n++; });
  encerr.forEach(function(c){ c.pasta = n; n++; });

  sbSalvarClientesDebounced();
  marcarAlterado();
  montarClientesAgrupados();
  doSearch();
  atualizarStats();
  showToast('✓ ' + CLIENTS.length + ' pastas renumeradas (1 a ' + (n-1) + ')');
  audit('renumerar_pastas', 'sistema', CLIENTS.length + ' pastas renumeradas');
}

let _unsaved = false;
function marcarAlterado(){
  _unsaved = true;
  invalidarCacheVfTodos(); // PERF: invalidar cache de lançamentos
  vfInvalidarCache();      // Phase 3: invalidar cache de abas pesadas
  const btn = document.getElementById('btn-salvar');
  if(btn && btn.textContent === '💾 Salvar') btn.textContent = '💾 Salvar *';
  // Reatividade — re-render do dashboard minimalista quando algo muda e ele está visível
  if(typeof dshRenderMin==='function' && document.getElementById('vc')?.classList.contains('on')){
    try { dshRenderMin(); } catch(e){}
  }
}

// PERF: debounce — evita rerender a cada tecla em inputs de busca
// Uso: oninput="_db(function(){ vkRender(); }, 220)"
const _dbTimers = {};
function _db(fn, delay, key){
  const k = key || (fn.toString().slice(0,40));
  clearTimeout(_dbTimers[k]);
  _dbTimers[k] = setTimeout(fn, delay || 220);
}




// ══════════════════════════════════════════════════
// ── MENU + NOVO ──
// ══════════════════════════════════════════════════
function toggleNovoMenu(){
  const m=document.getElementById('novo-menu');
  m.style.display=m.style.display==='none'?'block':'none';
}
document.addEventListener('click',function(e){
  const wrap=document.getElementById('novo-menu-wrap');
  if(wrap&&!wrap.contains(e.target)) document.getElementById('novo-menu').style.display='none';
});

// ══════════════════════════════════════════════════
// ── TAREFA DO DIA (checklist) ──
// ══════════════════════════════════════════════════






function deleteTarefa(key,idx){
  if(!tarefasDia[key]) return;
  tarefasDia[key].splice(idx,1);
  sbSet('co_td', tarefasDia);
    marcarAlterado();
  renderChecklist();
}



// ══════════════════════════════════════════════════
// ── NOVO COMPROMISSO (global) ──
// ══════════════════════════════════════════════════
function novoCompromisso(){
  document.getElementById('novo-menu').style.display='none';
  _abrirModalCompromisso(null);
}

// Modal unificado de compromisso — chamado do menu global OU da pasta do cliente
function _abrirModalCompromisso(cid_fixo){
  const proc = cid_fixo ? CLIENTS.find(x=>String(x.id)===String(cid_fixo)) : null;
  const clientesOpts = CLIENTS.map(c=>'<option value="'+c.cliente+'" data-id="'+c.id+'">'+c.cliente+' (Pasta '+c.pasta+')</option>').join('');

  const TIPOS_COMP = ['Audiência','Prazo','Reunião','Perícia','Despacho','Diligência','Conciliação','Julgamento','Publicação','Recesso','Outro'];

  const clienteRow = proc
    ? '<div class="comp-modal-proc-chip">'+proc.cliente+'</div>'
    : '<div class="fm-row" style="margin-bottom:0">'
        +'<div style="flex:1"><label class="fm-lbl">Cliente / Pasta (opcional)</label>'
          +'<input class="fm-inp" id="cm-cli" list="cm-cli-list" placeholder="Nome do cliente..." oninput="cmCliChange()">'
          +'<datalist id="cm-cli-list">'+clientesOpts+'</datalist></div>'
      +'</div>';

  const bodyHtml = clienteRow
    +'<div class="fm-row" style="margin-top:10px">'
      +'<div style="flex:2"><label class="fm-lbl">Título / Tipo *</label>'
        +'<input class="fm-inp" id="cm-titulo" list="cm-tipo-list" placeholder="Ex: Audiência de instrução...">'
        +'<datalist id="cm-tipo-list">'+TIPOS_COMP.map(t=>'<option>'+t+'</option>').join('')+'</datalist>'
      +'</div>'
    +'</div>'
    +'<div class="fm-row" style="margin-top:10px">'
      +'<div><label class="fm-lbl">Data início *</label>'
        +'<input class="fm-inp" type="date" id="cm-dt-ini" oninput="cmValidarDatas()"></div>'
      +'<div><label class="fm-lbl">Hora início</label>'
        +'<input class="fm-inp" type="time" id="cm-hr-ini" value="09:00"></div>'
      +'<div><label class="fm-lbl">Data fim</label>'
        +'<input class="fm-inp" type="date" id="cm-dt-fim" oninput="cmValidarDatas()"></div>'
      +'<div><label class="fm-lbl">Hora fim</label>'
        +'<input class="fm-inp" type="time" id="cm-hr-fim" value="10:00"></div>'
    +'</div>'
    +'<div id="cm-dt-erro" style="color:#f87676;font-size:11px;margin-top:3px;display:none">Data fim não pode ser anterior à data início</div>'
    // Recorrência
    +'<div style="margin-top:12px;padding:10px 12px;background:var(--sf3);border-radius:8px">'
      +'<label style="display:flex;align-items:center;gap:8px;cursor:pointer;font-size:12px;color:var(--tx);font-weight:600">'
        +'<input type="checkbox" id="cm-recorr" onchange="cmToggleRecorr()" style="accent-color:var(--vinho);width:15px;height:15px"> '
        +'Compromisso recorrente'
      +'</label>'
      +'<div id="cm-recorr-det" style="display:none;margin-top:10px">'
        +'<div class="fm-row">'
          +'<div><label class="fm-lbl">Repetir a cada</label>'
            +'<div style="display:flex;gap:6px;align-items:center">'
              +'<input class="fm-inp" type="number" id="cm-rec-qtd" value="1" min="1" max="365" style="width:70px">'
              +'<select class="fm-inp" id="cm-rec-unit" style="flex:1">'
                +'<option value="day">Dia(s)</option>'
                +'<option value="week" selected>Semana(s)</option>'
                +'<option value="month">Mês(es)</option>'
                +'<option value="year">Ano(s)</option>'
              +'</select>'
            +'</div>'
          +'</div>'
          +'<div><label class="fm-lbl">Repetir até</label>'
            +'<input class="fm-inp" type="date" id="cm-rec-ate">'
          +'</div>'
          +'<div><label class="fm-lbl">Ou nº de ocorrências</label>'
            +'<input class="fm-inp" type="number" id="cm-rec-ocorr" value="12" min="1" max="365" placeholder="ex: 12">'
          +'</div>'
        +'</div>'
        +'<div id="cm-rec-preview" style="font-size:11px;color:var(--mu);margin-top:6px"></div>'
      +'</div>'
    +'</div>'
    // Também lançar como prazo
    +'<div style="margin-top:10px;display:flex;align-items:center;gap:8px">'
      +'<input type="checkbox" id="cm-eh-prazo" style="accent-color:var(--vinho);width:14px;height:14px">'
      +'<label for="cm-eh-prazo" style="font-size:12px;color:var(--mu);cursor:pointer">Também lançar como prazo na pasta do cliente</label>'
    +'</div>'
    +'<div style="margin-top:10px"><label class="fm-lbl">Observações</label>'
      +'<textarea class="fm-inp" id="cm-obs" rows="2" placeholder="Local, link, detalhes..."></textarea>'
    +'</div>';

  abrirModal('Novo Compromisso', bodyHtml, ()=>{
    const titulo = document.getElementById('cm-titulo')?.value.trim();
    const dtIni  = document.getElementById('cm-dt-ini')?.value;
    const hrIni  = document.getElementById('cm-hr-ini')?.value||'09:00';
    const dtFim  = document.getElementById('cm-dt-fim')?.value||dtIni;
    const hrFim  = document.getElementById('cm-hr-fim')?.value||'10:00';
    const obs    = document.getElementById('cm-obs')?.value.trim()||'';
    const recorr = document.getElementById('cm-recorr')?.checked;
    const ehPrazo= document.getElementById('cm-eh-prazo')?.checked;

    if(!titulo){ showToast('Informe o título'); return; }
    if(!dtIni) { showToast('Informe a data de início'); return; }
    if(dtFim && dtFim < dtIni){ showToast('Data fim anterior à data início'); return; }

    // Resolver cliente
    let cid = cid_fixo;
    let clienteNome = proc?.cliente||'';
    if(!cid_fixo){
      const cliVal = document.getElementById('cm-cli')?.value.trim()||'';
      const opt    = document.querySelector('#cm-cli-list option[value="'+cliVal+'"]');
      const foundC = findClientByName(cliVal);
      cid = foundC?.id||null;
      clienteNome = cliVal;
    }

    const recUnit  = document.getElementById('cm-rec-unit')?.value||'week';
    const recQtd   = parseInt(document.getElementById('cm-rec-qtd')?.value)||1;
    const recAte   = document.getElementById('cm-rec-ate')?.value||'';
    const recOcorr = parseInt(document.getElementById('cm-rec-ocorr')?.value)||12;
    const recGrupo = recorr ? 'rg'+Date.now() : null;

    // Gerar datas da série
    const datas = [];
    if(!recorr){
      datas.push({ini:dtIni, fim:dtFim});
    } else {
      let cur = new Date(dtIni+'T12:00:00');
      let count = 0;
      const limiteAte = recAte ? new Date(recAte+'T23:59:59') : null;
      while(count < recOcorr){
        const isoIni = cur.toISOString().slice(0,10);
        if(limiteAte && cur > limiteAte) break;
        // Calcular fim proporcionalmente
        const durDias = dtFim ? Math.round((new Date(dtFim)-new Date(dtIni))/86400000) : 0;
        const curFim  = new Date(cur); curFim.setDate(curFim.getDate()+durDias);
        datas.push({ini:isoIni, fim:curFim.toISOString().slice(0,10)});
        // Avançar
        const prox = new Date(cur);
        if(recUnit==='day')   prox.setDate(prox.getDate()+recQtd);
        else if(recUnit==='week')  prox.setDate(prox.getDate()+recQtd*7);
        else if(recUnit==='month') prox.setMonth(prox.getMonth()+recQtd);
        else if(recUnit==='year')  prox.setFullYear(prox.getFullYear()+recQtd);
        cur = prox;
        count++;
      }
    }

    // Criar eventos
    let criados = 0;
    datas.forEach((d,i)=>{
      const ev = {
        id: 'cm'+genId(), id_agenda: genId(),
        titulo, tipo_compromisso: titulo,
        inicio: d.ini+'T'+hrIni, fim: d.fim+'T'+hrFim,
        dt_raw: d.ini, dt_fim: d.fim,
        obs, cliente: clienteNome,
        id_processo: cid||null,
        realizado: false, cumprido: 'Não',
        recorrente: !!recorr, recorr_grupo: recGrupo,
        natureza: (findClientById(cid)||{}).natureza||''
      };
      localAg.push(ev); invalidarAllPend();
      // Andamento na pasta
      if(cid){
        if(!localMov[cid]) localMov[cid]=[];
        localMov[cid].unshift({
          data:d.ini,
          movimentacao: '[Compromisso] '+titulo+(recorr?' (recorrente)':'')+' — '+fmtDataBR(d.ini)+(d.fim!==d.ini?' a '+fmtDataBR(d.fim):''),
          tipo_movimentacao:'Agenda', origem:'agenda_add'
        });
      }
      criados++;
    });

    sbSet('co_ag', localAg);
    if(cid) sbSet('co_localMov', localMov);

    // Lançar como prazo
    if(ehPrazo && cid){
      if(!prazos[cid]) prazos[cid]=[];
      datas.forEach((d,i)=>{
        prazos[cid].push({
          id:'cp'+genId(),
          titulo, tipo: titulo.toLowerCase().includes('audiencia')||titulo.toLowerCase().includes('audiência')?'audiencia'
            : titulo.toLowerCase().includes('prazo')||titulo.toLowerCase().includes('recurso')?'fatal':'outro',
          data: d.fim||d.ini,
          obs: obs||'Criado junto com compromisso',
          cumprido: false
        });
      });
      prazosSalvar(); // salva em co_prazos + co_td (legado)
    }

    marcarAlterado();
    fecharModal();
    _render_agenda_all();
    atualizarStats();
    // Re-renderizar aba de compromissos da pasta sem recarregar ficha inteira
    if(cid_fixo){
      const cidN = typeof cid_fixo === 'number' ? cid_fixo : parseInt(cid_fixo)||cid_fixo;
      const elTp = document.getElementById('tp-agenda-proc-'+cidN);
      if(elTp) elTp.innerHTML = renderAgendaProc(cidN);
      if(typeof AC !== 'undefined' && AC && String(AC.id)===String(cid_fixo))
        renderFicha(AC, _grupoAtual);
    } else if(cid){
      const elTp = document.getElementById('tp-agenda-proc-'+cid);
      if(elTp) elTp.innerHTML = renderAgendaProc(cid);
    }
    audit('compromisso',(criados>1?criados+'x ':'')+'Compromisso: '+titulo+(recorr?' (recorrente)':''),'agenda');
    showToast(criados > 1 ? criados+' compromissos criados ✓' : 'Compromisso adicionado ✓');
  }, 'Salvar');

  // Default data = hoje
  setTimeout(()=>{
    const di = document.getElementById('cm-dt-ini');
    if(di && !di.value) di.value = new Date().toISOString().slice(0,10);
    cmPreviewRecorr();
  }, 60);
}

// Validação datas
function cmValidarDatas(){
  const ini = document.getElementById('cm-dt-ini')?.value||'';
  const fim = document.getElementById('cm-dt-fim')?.value||'';
  const err = document.getElementById('cm-dt-erro');
  if(err) err.style.display = (fim && fim < ini) ? 'block' : 'none';
  cmPreviewRecorr();
}

// Toggle recorrência
function cmToggleRecorr(){
  const on = document.getElementById('cm-recorr')?.checked;
  const det = document.getElementById('cm-recorr-det');
  if(det) det.style.display = on ? 'block' : 'none';
  if(on) cmPreviewRecorr();
}

// Preview das datas recorrentes
function cmPreviewRecorr(){
  const prev = document.getElementById('cm-rec-preview');
  if(!prev) return;
  const dtIni = document.getElementById('cm-dt-ini')?.value;
  if(!dtIni){ prev.textContent=''; return; }
  const recorr = document.getElementById('cm-recorr')?.checked;
  if(!recorr){ prev.textContent=''; return; }
  const unit  = document.getElementById('cm-rec-unit')?.value||'week';
  const qtd   = parseInt(document.getElementById('cm-rec-qtd')?.value)||1;
  const ate   = document.getElementById('cm-rec-ate')?.value||'';
  const ocorr = parseInt(document.getElementById('cm-rec-ocorr')?.value)||12;
  const limite = ate ? new Date(ate+'T23:59:59') : null;
  const datas = [];
  let cur = new Date(dtIni+'T12:00:00');
  let count = 0;
  while(count < Math.min(ocorr,5)){
    if(limite && cur > limite) break;
    datas.push(fmtDataBR(cur.toISOString().slice(0,10)));
    const prox = new Date(cur);
    if(unit==='day') prox.setDate(prox.getDate()+qtd);
    else if(unit==='week') prox.setDate(prox.getDate()+qtd*7);
    else if(unit==='month') prox.setMonth(prox.getMonth()+qtd);
    else prox.setFullYear(prox.getFullYear()+qtd);
    cur = prox; count++;
  }
  const total = Math.min(ocorr, limite ? count : ocorr);
  prev.textContent = 'Ocorrências: '+datas.join(', ')+(total > 5 ? ' ... (+' + (total-5) + ' mais)' : '') + ' — Total: '+total;
}

// Autopreenchimento de cliente ao digitar
function cmCliChange(){
  const val = document.getElementById('cm-cli')?.value||'';
  const found = findClientByName(val);
  if(found){
    const chip = document.getElementById('cm-cli')?.parentElement;
    // apenas registrar que foi selecionado
  }
  cmPreviewRecorr();
}


// Contato tem pelo menos um processo vinculado? Usado para o badge "Sem Processo".
function _ctcTemProcesso(c){
  if(!c) return false;
  return (CLIENTS||[]).some(function(cl){
    return (cl.partes||[]).some(function(p){ return p.nome===c.nome; })
      || String(cl.id)===String(c.id_processo);
  });
}

// Resumo financeiro do contato — agrega localLanc de todos os processos
// vinculados a ele (via partes ou id_processo). Retorna {aReceber, recebido,
// despesasPagas, proxVencimentos:[{desc,valor,venc,cliente,cid}]}.
function _ctcResumoFinanceiro(contato){
  if(!contato) return null;
  var linked = (CLIENTS||[]).filter(function(cl){
    return (cl.partes||[]).some(function(p){ return p.nome===contato.nome; })
      || String(cl.id)===String(contato.id_processo);
  });
  if(!linked.length) return null;
  var out = {aReceber:0, recebido:0, despesasPagas:0, proxVencimentos:[], nProcs:linked.length};
  linked.forEach(function(cl){
    var locais = _finGetLocais(cl.id);
    (locais||[]).forEach(function(l){
      var v = parseFloat(l.valor||0);
      if(!v) return;
      var pago = isRec(l);
      var isDesp = l.tipo==='despesa' || l.tipo==='despint' || l.tipo==='despesa_reimb';
      var isRep  = l.tipo==='repasse' || l._repasse_alvara || l._repasse_acordo;
      if(isRep) return;  // repasse é OUT, não entra no balanço do cliente
      if(isDesp){
        if(pago) out.despesasPagas += v;
        return;
      }
      // Honorários/acordo/sucumbência/outros = entradas do cliente
      if(pago){
        out.recebido += v;
      } else {
        out.aReceber += v;
        if(l.venc){
          out.proxVencimentos.push({
            desc: l.desc||'—', valor: v, venc: l.venc,
            cliente: cl.cliente, cid: cl.id
          });
        }
      }
    });
  });
  out.proxVencimentos.sort(function(a,b){ return (a.venc||'').localeCompare(b.venc||''); });
  return out;
}

// Dropdown de origem do contato \u2014 reuso entre novoContato e cadHtml.
var _ORIGEM_OPTS = ['Instagram','Direct/WhatsApp','Indica\u00e7\u00e3o de cliente','Google','An\u00fancio','Site','LinkedIn','Outro'];
function _origemOptionsHtml(selecionado){
  return '<option value="">\u2014 Origem do contato \u2014</option>'
    + _ORIGEM_OPTS.map(function(o){
        return '<option'+(o===selecionado?' selected':'')+'>'+o+'</option>';
      }).join('');
}
window._origemOptionsHtml = _origemOptionsHtml;

function novoContato(){
  document.getElementById('novo-menu').style.display='none';
  abrirModal('\ud83d\udc64 Novo Contato', ''
    // Toggle PF/PJ
    +'<div style="display:flex;gap:8px;margin-bottom:14px">'
      +'<button class="ctc-tipo-btn on" id="ctc-pf-btn" onclick="setCtcTipo(\'pf\')">\ud83e\uddd1 Pessoa F\u00edsica</button>'
      +'<button class="ctc-tipo-btn" id="ctc-pj-btn" onclick="setCtcTipo(\'pj\')">\ud83c\udfe2 Pessoa Jur\u00eddica</button>'
    +'</div>'
    // Nome
    +'<div style="margin-bottom:10px"><label class="fm-lbl">Nome completo <span class="req">*</span></label>'
      +'<input class="fm-inp" id="nc-nome" placeholder="Nome..."></div>'
    // Documento + bot\u00e3o de lookup CNPJ (vis\u00edvel s\u00f3 em PJ)
    +'<div style="display:flex;gap:8px;margin-bottom:10px">'
      +'<div style="flex:1"><label class="fm-lbl" id="ctc-doc-lbl">CPF</label>'
        +'<div style="display:flex;gap:4px">'
          +'<input class="fm-inp" id="nc-doc" placeholder="000.000.000-00" oninput="fmtDocContato()" style="flex:1">'
          +'<button type="button" id="nc-cnpj-btn" onclick="_preencherCnpjFields(\'nc\')" style="display:none;padding:0 10px;border-radius:6px;background:var(--sf3);border:1px solid var(--bd);color:var(--tx);cursor:pointer" title="Buscar CNPJ na Receita">\ud83d\udd0d</button>'
        +'</div>'
      +'</div>'
      +'<div style="flex:1" id="nc-rg-row"><label class="fm-lbl">RG</label>'
        +'<input class="fm-inp" id="nc-rg" placeholder="MG-00.000.000"></div>'
    +'</div>'
    // Data de nascimento (s\u00f3 PF)
    +'<div style="display:flex;gap:8px;margin-bottom:10px" id="nc-nasc-row">'
      +'<div style="flex:1"><label class="fm-lbl">Data de nascimento</label>'
        +'<input class="fm-inp" id="nc-nasc" type="date"></div>'
      +'<div style="flex:1" id="nc-pis-row2"><label class="fm-lbl">PIS/PASEP/NIT</label>'
        +'<input class="fm-inp" id="nc-pis" placeholder="000.00000.00-0"></div>'
    +'</div>'
    // Contato
    +'<div style="display:flex;gap:8px;margin-bottom:10px">'
      +'<div style="flex:1"><label class="fm-lbl">Telefone</label>'
        +'<input class="fm-inp" id="nc-tel" placeholder="(00) 00000-0000"></div>'
      +'<div style="flex:1"><label class="fm-lbl">E-mail</label>'
        +'<input class="fm-inp" id="nc-email" type="email" placeholder="email@exemplo.com"></div>'
    +'</div>'
    // Endere\u00e7o (estruturado, com lookup via CEP)
    +'<div style="border-top:1px solid var(--bd);margin:12px 0 8px;padding-top:10px">'
      +'<div style="font-size:11px;color:var(--mu);text-transform:uppercase;letter-spacing:.06em;margin-bottom:8px;font-weight:600">\ud83d\udccd Endere\u00e7o</div>'
      +'<div style="display:flex;gap:8px;margin-bottom:8px">'
        +'<div style="flex:0 0 140px"><label class="fm-lbl">CEP</label>'
          +'<div style="display:flex;gap:4px">'
            +'<input class="fm-inp" id="nc-cep" placeholder="00000-000" maxlength="9" style="flex:1" onblur="_preencherCepFields(\'nc\')">'
            +'<button type="button" id="nc-cep-btn" onclick="_preencherCepFields(\'nc\')" style="padding:0 8px;border-radius:6px;background:var(--sf3);border:1px solid var(--bd);color:var(--tx);cursor:pointer" title="Buscar CEP">\ud83d\udd0d</button>'
          +'</div>'
        +'</div>'
        +'<div style="flex:1"><label class="fm-lbl">Rua</label>'
          +'<input class="fm-inp" id="nc-rua" placeholder="Logradouro"></div>'
        +'<div style="flex:0 0 90px"><label class="fm-lbl">N\u00ba</label>'
          +'<input class="fm-inp" id="nc-num" placeholder="123"></div>'
      +'</div>'
      +'<div style="display:flex;gap:8px">'
        +'<div style="flex:1"><label class="fm-lbl">Bairro</label>'
          +'<input class="fm-inp" id="nc-bairro" placeholder=""></div>'
        +'<div style="flex:1"><label class="fm-lbl">Cidade</label>'
          +'<input class="fm-inp" id="nc-cidade" placeholder=""></div>'
        +'<div style="flex:0 0 80px"><label class="fm-lbl">UF</label>'
          +'<select class="fm-inp" id="nc-uf"><option value="">\u2014</option>'
            +['AC','AL','AP','AM','BA','CE','DF','ES','GO','MA','MT','MS','MG','PA','PB','PR','PE','PI','RJ','RN','RS','RO','RR','SC','SP','SE','TO'].map(function(u){return '<option>'+u+'</option>';}).join('')
          +'</select></div>'
      +'</div>'
    +'</div>'
    // Origem do contato
    +'<div style="margin-bottom:10px"><label class="fm-lbl">\ud83d\udce2 Origem do contato</label>'
      +'<select class="fm-inp" id="nc-origem">'+_origemOptionsHtml('')+'</select></div>'
    // Observa\u00e7\u00f5es
    +'<div style="margin-bottom:10px"><label class="fm-lbl">Observa\u00e7\u00f5es</label>'
      +'<input class="fm-inp" id="nc-obs" placeholder="Cargo, rela\u00e7\u00e3o, notas, resumo do problema..."></div>',
  function(){
    var nome = (document.getElementById('nc-nome')?.value||'').trim();
    if(!nome){ showToast('Informe o nome'); return; }
    // Verificar duplicata por nome
    var dup = ctcTodos().find(function(c){ return (c.nome||'').toLowerCase().trim()===nome.toLowerCase(); });
    if(dup && !confirm('Contato "'+nome+'" j\u00e1 existe. Criar mesmo assim?')) return;
    var tipo = document.getElementById('ctc-pj-btn')?.classList.contains('on') ? 'pj' : 'pf';
    var get = function(id){ return (document.getElementById(id)?.value||'').trim(); };
    // Endere\u00e7o formatado para exibi\u00e7\u00e3o r\u00e1pida (campo legado "endereco")
    var rua = get('nc-rua'), num = get('nc-num'), bairro = get('nc-bairro'),
        cidade = get('nc-cidade'), uf = get('nc-uf');
    var enderecoTxt = [rua + (num?', '+num:''), bairro, cidade+(uf?'/'+uf:'')].filter(Boolean).join(', ');
    var novoCtc = {
      id:'ctc'+genId(), nome:nome, tipo:tipo,
      doc: get('nc-doc'),
      cpf: tipo==='pf' ? get('nc-doc') : '',
      rg:  get('nc-rg'),
      pis: get('nc-pis'),
      tel: get('nc-tel'),
      email: get('nc-email'),
      origem: get('nc-origem'),
      endereco: enderecoTxt,  // compat com leitura antiga
      extra: {
        nasc: get('nc-nasc'),
        cep: get('nc-cep'),
        rua: rua, num: num, bairro: bairro,
        cidade: cidade, uf: uf
      },
      obs: get('nc-obs'),
      criado: new Date().toISOString().slice(0,10)
    };
    localContatos.push(novoCtc); invalidarCtcCache();
    sbSet('co_ctc', localContatos);
    marcarAlterado(); fecharModal();
    ctcRender();
    showToast('Contato adicionado \u2713');
    // Fluxo passo-a-passo: pergunta o que fazer com o contato rec\u00e9m-criado.
    setTimeout(function(){ _promptPosCadastroContato(novoCtc); }, 250);
  }, 'Salvar');
}

// Modal que aparece ap\u00f3s salvar um novo contato.
// Oferece 3 caminhos naturais: vira processo, vira atendimento, ou fica parado.
function _promptPosCadastroContato(ctc){
  if(!ctc) return;
  var btnStyle = 'width:100%;padding:14px 16px;border-radius:8px;cursor:pointer;font-size:13px;font-weight:600;text-align:left;margin-bottom:8px;transition:transform .1s';
  abrirModal('\ud83c\udfaf Pr\u00f3ximo passo',
    '<div style="margin-bottom:14px;font-size:13px;color:var(--tx);line-height:1.5">'
      +'<strong>'+escapeHtml(ctc.nome||'Contato')+'</strong> foi cadastrado com sucesso. O que voc\u00ea quer fazer agora?'
    +'</div>'
    +'<button onclick="_posCadProcesso()" style="'+btnStyle+';background:rgba(81,15,16,.25);border:1px solid var(--vinho);color:var(--tx)">'
      +'\u2696\ufe0f Criar processo vinculado'
      +'<div style="font-size:10px;opacity:.7;font-weight:400;margin-top:4px">J\u00e1 tem o contrato assinado? Cria a pasta do processo com o nome e CPF j\u00e1 preenchidos.</div>'
    +'</button>'
    +'<button onclick="_posCadAtendimento()" style="'+btnStyle+';background:rgba(212,175,55,.1);border:1px solid rgba(212,175,55,.4);color:var(--tx)">'
      +'\ud83d\udcac Criar atendimento (CRM)'
      +'<div style="font-size:10px;opacity:.7;font-weight:400;margin-top:4px">Ainda em an\u00e1lise? Registra no pipeline (an\u00e1lise \u2192 proposta \u2192 contratou).</div>'
    +'</button>'
    +'<button onclick="fecharModal()" style="'+btnStyle+';background:var(--sf3);border:1px solid var(--bd);color:var(--mu)">'
      +'\ud83d\uddc2 S\u00f3 salvar o contato por enquanto'
      +'<div style="font-size:10px;opacity:.7;font-weight:400;margin-top:4px">Fica na lista com a tag "Sem Processo" at\u00e9 virar algo.</div>'
    +'</button>',
    null, null);
  window._pendingCtc = ctc;
}

function _posCadProcesso(){
  var c = window._pendingCtc || {};
  fecharModal();
  novoProcesso({ nome: c.nome, cpf: c.doc || c.cpf, obs: c.obs });
  window._pendingCtc = null;
}

function _posCadAtendimento(){
  var c = window._pendingCtc || {};
  fecharModal();
  novoAtendimento({ nome: c.nome, tel: c.tel, email: c.email, obs: c.obs });
  window._pendingCtc = null;
}

window._promptPosCadastroContato = _promptPosCadastroContato;
window._posCadProcesso = _posCadProcesso;
window._posCadAtendimento = _posCadAtendimento;
function fmtDocContato(){
  const inp = document.getElementById('nc-doc'); if(!inp) return;
  const tipo = document.getElementById('ctc-pj-btn')?.classList.contains('on') ? 'pj' : 'pf';
  let v = inp.value.replace(/\D/g,'');
  if(tipo==='pj'){
    v = v.slice(0,14);
    v = v.replace(/(\d{2})(\d{3})(\d{3})(\d{4})(\d{1,2}).*/, '$1.$2.$3/$4-$5')
         .replace(/(\d{2})(\d{3})(\d{3})(\d{1,4})/, '$1.$2.$3/$4')
         .replace(/(\d{2})(\d{3})(\d{1,3})/, '$1.$2.$3')
         .replace(/(\d{2})(\d{1,3})/, '$1.$2');
  } else {
    v = v.slice(0,11);
    v = v.replace(/(\d{3})(\d{3})(\d{3})(\d{1,2}).*/, '$1.$2.$3-$4')
         .replace(/(\d{3})(\d{3})(\d{1,3})/, '$1.$2.$3')
         .replace(/(\d{3})(\d{1,3})/, '$1.$2');
  }
  inp.value = v;
}

function renderHomeWeek(){
  const hw = document.getElementById('home-week');
  if(!hw) return;

  const dObj = new Date(HOJE);
  const mes = dObj.getMonth(), ano = dObj.getFullYear(), diaHoje = dObj.getDate();
  const MA=['Jan','Fev','Mar','Abr','Mai','Jun','Jul','Ago','Set','Out','Nov','Dez'];

  // Update header label
  var dHwLbl=document.getElementById('hw-date-lbl');
  if(dHwLbl) dHwLbl.textContent=MA[mes]+' '+ano;

  // Compact calendar grid
  const primDia = new Date(ano,mes,1).getDay(); // 0=Dom
  const ultDia  = new Date(ano,mes+1,0).getDate();
  const dias = ['D','S','T','Q','Q','S','S'];
  let calHtml = '<div style="padding:10px 12px 6px">'
    + '<div style="display:grid;grid-template-columns:repeat(7,1fr);gap:2px;text-align:center;margin-bottom:4px">'
    + dias.map(d=>'<div style="font-size:9px;color:#9E9E9E;font-weight:600;padding:2px 0">'+d+'</div>').join('')
    + '</div>'
    + '<div style="display:grid;grid-template-columns:repeat(7,1fr);gap:2px;text-align:center">';
  // empty cells before first day
  for(var i=0;i<primDia;i++) calHtml+='<div></div>';
  for(var d=1;d<=ultDia;d++){
    const isHoje = d===diaHoje;
    const ds2 = ano+'-'+String(mes+1).padStart(2,'0')+'-'+String(d).padStart(2,'0');
    const temEvt = allPendCached().some(function(p){return eventoNoDia(p,ds2)&&!p.realizado;});
    calHtml+='<div style="font-size:10px;padding:4px 2px;border-radius:4px;cursor:default;'
      +(isHoje?'background:#D4AF37;color:#111;font-weight:700;'
               :(temEvt?'color:#E0E0E0;font-weight:600;':'color:#9E9E9E;'))
      +'">'+d+'</div>';
  }
  calHtml += '</div></div>';

  // Events for today
  const TIPO_DOT = {audiencia:'#f87676',prazo:'#c9484a',compromisso:'#c9484a',tarefa:'#D4AF37',reuniao:'#60a5fa'};
  const evts = allPendCached()
    .filter(function(p){return !p.realizado && eventoNoDia(p, HS);})
    .sort(function(a,b){return (a.inicio||a.dt_raw||'').localeCompare(b.inicio||b.dt_raw||'');});

  const BD = 'border-bottom:1px solid #202020;';
  const MAX_EVTS = 3;
  const evtsVisiveis = evts.slice(0, MAX_EVTS);
  const evtsHtml = evts.length ? evtsVisiveis.map(function(p){
    const hr = p.inicio ? p.inicio.slice(11,16) : '—';
    const cor = TIPO_DOT[agTipo(p)]||'#9E9E9E';
    const onclick = `calEvtClick('${p.id||p.id_agenda||''}')`;
    return '<div onclick="'+onclick+'" style="display:flex;gap:8px;padding:7px 12px;'+BD+'align-items:flex-start;cursor:'+(onclick?'pointer':'default')+'">'
      +'<span style="font-size:10px;color:#9E9E9E;width:36px;flex-shrink:0;padding-top:1px">'+hr+'</span>'
      +'<span style="width:6px;height:6px;border-radius:50%;background:'+cor+';flex-shrink:0;margin-top:4px"></span>'
      +'<div style="min-width:0;flex:1">'
        +'<div style="font-size:11px;color:#E0E0E0;font-weight:500;font-family:Inter,sans-serif;white-space:nowrap;overflow:hidden;text-overflow:ellipsis">'+escapeHtml(p.titulo||p.descricao||'Compromisso')+'</div>'
        +(p.cliente?'<div style="font-size:10px;color:#9E9E9E;white-space:nowrap;overflow:hidden;text-overflow:ellipsis">'+escapeHtml(p.cliente)+'</div>':'')
      +'</div>'
    +'</div>';
  }).join('')
  + (evts.length > MAX_EVTS
    ? '<div class="hw-ver-mais" style="padding:8px 12px;font-size:11px;color:#D4AF37;cursor:pointer;font-weight:600;font-family:Inter,sans-serif">Ver mais ('+(evts.length - MAX_EVTS)+' restantes) →</div>'
    : '')
  : '<div style="padding:12px;text-align:center;font-size:11px;color:#9E9E9E">Nenhum compromisso hoje</div>';

  hw.innerHTML = calHtml
    + '<div style="border-top:1px solid #2a2a2a">' + evtsHtml + '</div>';
  var vmBtn = hw.querySelector('.hw-ver-mais');
  if(vmBtn) vmBtn.onclick = function(){ goView('va', document.getElementById('nav-agenda')); };
}

// ── AUTO-STATUS: marcar lançamentos vencidos como "vencido" ──
function _finAutoStatusVencidos(){
  var hoje = new Date(HOJE).toISOString().slice(0,10);
  var alterados = 0;
  (localLanc||[]).forEach(function(l){
    if(!l.pago && l.status!=='pago' && l.status!=='vencido' && l.venc && l.venc < hoje){
      l.status = 'vencido';
      alterados++;
    }
  });
  (finLancs||[]).forEach(function(l){
    if(!l.pago && l.status!=='pago' && l.status!=='vencido' && l.venc && l.venc < hoje){
      l.status = 'vencido';
      alterados++;
    }
  });
  if(alterados > 0){
    sbSet('co_localLanc', localLanc);
    sbSet('co_fin', finLancs);
    invalidarCacheVfTodos();
  }
}

// Executar auto-status ao carregar
try { _finAutoStatusVencidos(); } catch(e){}

// ── Limpeza: remover registros de teste de todos os módulos ──
(function _limparTestes(){
  var testRe = /\bteste?\b/i;
  var changed = false;

  // localLanc (honorários, despesas, repasses da pasta)
  var llAntes = (localLanc||[]).length;
  localLanc = (localLanc||[]).filter(function(l){ return !testRe.test(l.desc||''); });
  if(localLanc.length < llAntes){ sbSet('co_localLanc', localLanc); changed=true; }

  // finLancs (financeiro global)
  var flAntes = (finLancs||[]).length;
  finLancs = (finLancs||[]).filter(function(l){ return !testRe.test(l.desc||'') && !testRe.test(l.cliente||''); });
  if(finLancs.length < flAntes){ sbSet('co_fin', finLancs); changed=true; }

  // localAg (compromissos/prazos)
  var agAntes = (localAg||[]).length;
  localAg = (localAg||[]).filter(function(l){ return !testRe.test(l.titulo||'') && !testRe.test(l.descricao||''); });
  if(localAg.length < agAntes){ sbSet('co_ag', localAg); invalidarAllPend(); changed=true; }

  // vkTasks (tarefas)
  var tkAntes = (vkTasks||[]).length;
  vkTasks = (vkTasks||[]).filter(function(t){ return !testRe.test(t.titulo||''); });
  if(vkTasks.length < tkAntes){ vkSalvar(); changed=true; }

  // localMov (andamentos) — por cid
  if(localMov && typeof localMov==='object'){
    Object.keys(localMov).forEach(function(cid){
      var antes = (localMov[cid]||[]).length;
      localMov[cid] = (localMov[cid]||[]).filter(function(m){ return !testRe.test(m.movimentacao||''); });
      if(localMov[cid].length < antes) changed=true;
    });
    if(changed) sbSet('co_localMov', localMov);
  }

  // vkTasks — remover tarefas sem título (undefined)
  var tkAntes2 = (vkTasks||[]).length;
  vkTasks = (vkTasks||[]).filter(function(t){ return t.titulo && t.titulo!=='undefined'; });
  if(vkTasks.length < tkAntes2){ vkSalvar(); changed=true; }

  if(changed) _finLocaisCache={};
})();

// ── Limpeza: remover clientes duplicados criados por salvarAtendimento ──
(function _limparClientesDuplicados(){
  if(!CLIENTS||!CLIENTS.length) return;
  // Clientes com tipo='consulta' criados automaticamente que duplicam processos existentes
  var processosIds = new Set();
  var nomesProcesso = {};
  // Primeiro: mapear nomes que já têm processo real (não consulta)
  CLIENTS.forEach(function(c){
    if(c.tipo!=='consulta' && c.status_consulta!=='consulta'){
      processosIds.add(c.id);
      var nome = (c.cliente||'').toLowerCase().trim();
      if(!nomesProcesso[nome]) nomesProcesso[nome]=[];
      nomesProcesso[nome].push(c.id);
    }
  });
  // Remover consultas duplicadas (mesmo nome de um processo real)
  var antes = CLIENTS.length;
  var idsRemover = new Set();
  CLIENTS.forEach(function(c){
    if(c.tipo!=='consulta' && c.status_consulta!=='consulta') return;
    var nome = (c.cliente||'').toLowerCase().trim();
    if(nomesProcesso[nome] && nomesProcesso[nome].length > 0){
      idsRemover.add(c.id); // consulta duplicada de processo existente
    }
  });
  if(idsRemover.size > 0){
    var novos = CLIENTS.filter(function(c){ return !idsRemover.has(c.id); });
    CLIENTS.length = 0;
    novos.forEach(function(c){ CLIENTS.push(c); });
    _clientByIdCache = {};
    _clientByNameCache = {};
    sbSet('co_clientes', CLIENTS);
    if(typeof montarClientesAgrupados==='function') montarClientesAgrupados();
  }
})();

// Lançamentos de Fevereiro 2026
(function lancarFevereiro(){
  // ── Run-once: este seed só roda na primeira vez. Sem isso, o IIFE re-insere
  // itens deletados pelo usuário toda vez que a página carrega.
  try{ if(lsGet('co_seed_fev2026_done')==='1') return 0; }catch{}
  var hoje = '2026-02-28';
  var added = 0;

  // Helper para não duplicar — checa tanto localLanc quanto finLancs
  function jaExiste(desc, data, valor){
    var hit = function(arr){
      return (arr||[]).some(function(l){
        return l.desc===desc && l.data===data && Math.abs((l.valor||0)-valor)<0.02;
      });
    };
    return hit(localLanc) || hit(finLancs);
  }

  function addHon(cliente, desc, valor, perc, data, forma, parcNome, parcPerc){
    if(jaExiste(desc, data, valor)) return;
    var calc = _finCalcLanc({valor_integral:valor, valor_parcela:0, ressarcimento:0, percentual_honorarios:perc, parceiro_nome:parcNome||'', parceiro_percentual:parcPerc||0});
    var cMatch = findClientByName(cliente);
    localLanc.push({
      id:genId(), tipo:'honorario', direcao:'receber',
      id_processo: cMatch?cMatch.id:0, cliente:cliente,
      desc:desc, valor_integral:valor, valor_parcela:0, valor:calc.base_calculo,
      ressarcimento:0, percentual_honorarios:perc,
      parceiro_nome:parcNome||'', parceiro_percentual:parcPerc||0,
      data:data, forma:forma||'PIX', recebido:true,
      status:'pago', pago:true, dt_baixa:data, obs:'Importado extrato fev/2026'
    });
    added++;
  }

  function addRepasse(cliente, desc, valor, data, forma){
    if(jaExiste(desc, data, valor)) return;
    var cMatch = findClientByName(cliente);
    localLanc.push({
      id:genId(), tipo:'repasse', direcao:'pagar',
      id_processo: cMatch?cMatch.id:0, cliente:cliente,
      desc:desc, valor:roundMoney(valor), data:data, venc:data,
      status:'pago', pago:true, dt_baixa:data, recebido:true,
      forma:forma||'PIX', _repasse_acordo:true,
      obs:'Importado extrato fev/2026'
    });
    added++;
  }

  function addDespesa(desc, valor, data, cat, forma){
    if(jaExiste(desc, data, valor)) return;
    finLancs.push({
      id:genId(), tipo:'pagar', desc:desc, valor:roundMoney(valor),
      data:data, cat:cat||'Outros', forma:forma||'PIX',
      status:'pago', pago:true, dt_baixa:data,
      _desp_escritorio:true, obs:'Importado extrato fev/2026'
    });
    added++;
  }

  // ── RECEITAS (honorários) ──
  addHon('MARY LUCIA DE OLIVEIRA', 'Consultoria', 400, 100, '2026-02-05', 'PIX', '', 0);
  addHon('ADEGA 13 COMÉRCIO DE BEBIDAS LTDA', 'Consultoria Carnaval', 300, 100, '2026-02-06', 'PIX', '', 0);
  addHon('CAMILA ESTANISLAU XAVIER', 'Honorários', 400, 100, '2026-02-09', 'PIX', '', 0);
  addHon('MARY LUCIA DE OLIVEIRA', 'Consultoria', 400, 100, '2026-02-12', 'PIX', '', 0);
  addHon('ADEGA 13 COMÉRCIO DE BEBIDAS LTDA', 'Consultoria Eduarda', 300, 100, '2026-02-20', 'PIX', '', 0);
  addHon('LORRANY LEMOS DA SILVA', 'Consultoria', 150, 100, '2026-02-23', 'PIX', '', 0);
  addHon('CLARISSA RATZINGER', 'Cálculos', 37, 100, '2026-02-13', 'PIX', '', 0);
  // Victor Dias — 50% honorários (parceiro Alessandro)
  addHon('VICTOR DIAS GOMES', 'Honorários', 4679.35, 50, '2026-02-25', 'PIX', 'Alessandro Dias', 50);

  // ── REPASSES ──
  addRepasse('ANA CAROLINA OLIVEIRA SANTOS', 'Repasse ao cliente — Alvará', 7318, '2026-02-03', 'TED');
  addRepasse('EDNA DE FATIMA ALVES DOS REIS', 'Repasse ao cliente — Acordo', 20860, '2026-02-03', 'TED');
  addRepasse('RENAN DA SILVA GOMES SOUZA', 'Repasse ao cliente', 1130, '2026-02-12', 'PIX');

  // ── ESTORNO (Ana Carolina devolvida + reenvio) — lançar como movimentação neutra
  // O estorno +7318 e o reenvio -7318 se anulam, não precisa lançar

  // ── ENTRADA SEM HONORÁRIOS (Natali Cristina — 100% cliente) ──
  addRepasse('NATALI CRISTINA DE FARIA', 'Recebimento em nome do cliente', 2761.36, '2026-02-12', 'TED');

  // ── DESPESAS DO ESCRITÓRIO ──
  addDespesa('Sistema escritório — Camila Shimomura', 500, '2026-02-06', 'Sistemas', 'PIX');
  addDespesa('Fatura cartão Inter', 509, '2026-02-12', 'Outros', 'Débito');
  addDespesa('Aluguel — AMO Imóveis', 972.98, '2026-02-18', 'Estrutura', 'Boleto');
  addDespesa('IPTU — PM Belo Horizonte', 620.93, '2026-02-19', 'Impostos', 'Boleto');
  addDespesa('Calculista — Vanessa Cecília (proc. Washington Diniz)', 320, '2026-02-23', 'Custas processuais', 'PIX');
  addDespesa('Pro-labore — Clarissa de Oliveira', 5000, '2026-02-24', 'Pessoal', 'TED');

  if(added > 0){
    sbSet('co_localLanc', localLanc);
    sbSet('co_fin', finLancs);
    _finLocaisCache = {};
  }
  // Marcar seed como executado para nunca mais rodar nesta instalação
  try{ lsSet('co_seed_fev2026_done', '1'); }catch{}
  return added;
})();

function atualizarStats(){
  const hoje = HS;
  const semFim = new Date(HOJE); semFim.setDate(semFim.getDate()+7);
  const semFimStr = semFim.toISOString().slice(0,10);
  const _allP = allPendCached();
  // Single-pass: classificar futuros, semana, passados
  var fut=[], sem=[], pass=[], hojeCount=0;
  _allP.forEach(function(p){
    if(p.realizado||p.cumprido==='Sim') return;
    var dt = p.dt_fim||p.dt_raw||'';
    if(dt>=hoje){ fut.push(p); if(p.dt_raw<=semFimStr) sem.push(p); }
    else pass.push(p);
    if(p.dt_raw===hoje) hojeCount++;
  });
  var encIds2 = getEncIds();
  var ativosCount = 0;
  if(typeof CLIENTES_AGRUPADOS!=='undefined' && CLIENTES_AGRUPADOS){
    ativosCount = CLIENTES_AGRUPADOS.filter(function(grp){
      return grp.processos && grp.processos.some(function(p){ return !encIds2.has(p.id); });
    }).length;
  } else {
    var _nomes = {};
    (CLIENTS||[]).forEach(function(c){ if(!encIds2.has(c.id)&&c.tipo!=='consulta') _nomes[(c.cliente||'').toLowerCase()]=1; });
    ativosCount = Object.keys(_nomes).length;
  }
  // KPIs dashboard (layout B)
  var bfutEl=document.getElementById('bfut'); if(bfutEl) bfutEl.textContent=fut.length;
  var dscAt=document.getElementById('dsc-ativos'); if(dscAt) dscAt.textContent=ativosCount;
  var dscV=document.getElementById('dsc-vencidos'); if(dscV) dscV.textContent=pass.length;

  // Atualizar KPI financeiro no dashboard
  try {
    var todosF = vfTodos();
    // Single-pass para KPIs financeiros
    var aRecF=0, vencF=0, vencFVal=0;
    todosF.forEach(function(l){
      if(l.tipo==='receber'&&l.status!=='pago') aRecF+=l.valor;
      if(l.tipo==='receber'&&l.status==='vencido'){ vencF++; vencFVal+=l.valor; }
    });
    var fK = function(v){ return v>=1000?'R$ '+(v/1000).toFixed(0)+'k':'R$ '+Math.round(v); };
    // dsc-fin removido no layout B — saldo atualizado em renderHomeAlerts
    var k1=document.getElementById('vfkpi-rec'); if(k1) k1.textContent=fK(aRecF);
    var k3=document.getElementById('vfkpi-inad'); if(k3) k3.textContent=fK(vencFVal);
    // Badge no botão de Financeiro
    var badge=document.getElementById('fin-badge');
    if(badge){ badge.style.display=vencF>0?'inline':'none'; if(vencF>0) badge.textContent=vencF; }
  } catch(e){}

  // Notificacao no titulo da aba (reusar hojeCount já calculado)
  var vencidos2 = pass.length;
  var dt3 = new Date(new Date(HOJE).getTime()+3*86400000).toISOString().slice(0,10);
  var venc3dias2 = _allP.filter(function(p){return p.dt_raw>=hoje&&p.dt_raw<=dt3&&p.cumprido!=='Sim'&&!p.realizado;}).length;
  if(vencidos2>0){
    document.title = '\u26a0\ufe0f '+vencidos2+' vencido'+(vencidos2>1?'s':'')+' \u2014 CO Advocacia';
  } else if(hojeCount>0){
    document.title = '\ud83d\udfe1 HOJE: '+hojeCount+' prazo'+(hojeCount>1?'s':'')+' \u2014 CO Advocacia';
  } else if(venc3dias2>0){
    document.title = '\ud83d\udfe0 '+venc3dias2+' prazo'+(venc3dias2>1?'s':'')+' em 3 dias \u2014 CO Advocacia';
  } else {
    document.title = 'CO Advocacia \u2014 Escrit\u00f3rio Digital';
  }
}



// ── Seletor de usuário ──

// ── Forçar sincronização completa ──
async function sbForcaSync(){
  showToast('Sincronizando...');
  await sbPing();
  if(!_sbOnline){ showToast('Sem conexão — dados salvos localmente'); return; }
  
  // Push tudo para o Supabase
  const pares = [
    ['co_tasks', tasks],
    ['co_vktasks', vkTasks],
    ['co_fin', finLancs],
    ['co_localLanc', localLanc],
    ['co_ag', localAg],
    ['co_encerrados', encerrados],
    ['co_notes', notes],
    ['co_ctc', localContatos],
    ['co_td', prazos],
    ['co_atend', localAtend],
    ['co_monte_mor', monteMor],
  ];
  let ok = 0;
  for(const [k,v] of pares){
    if(await sbSet(k,v)) ok++;
  }
  showToast(`Sincronizado — ${ok}/${pares.length} conjuntos enviados ✓`);
}
function sbSetarUsuario(){
  abrirModal('👤 Quem está usando?', `
    <p style="font-size:12px;color:var(--mu);margin-bottom:14px">
      Identifique-se para que as outras pessoas saibam quem fez cada alteração.
    </p>
    <div style="display:flex;flex-direction:column;gap:8px">
      ${[
        {id:'clarissa',   label:'Clarissa',   desc:'Advogada responsável',   cor:'var(--vinho)'},
        {id:'assistente', label:'Assistente', desc:'Assistente jurídico',     cor:'#1a4a2e'},
        {id:'financeiro', label:'Financeiro', desc:'Responsável financeiro',  cor:'#1a2a4a'},
      ].map(u=>`
        <button onclick="sbConfirmarUsuario('${u.id}')" style="
          background:${_sbUsuario===u.id?u.cor:'var(--sf2)'};
          border:2px solid ${_sbUsuario===u.id?u.cor:'var(--bd)'};
          border-radius:8px;padding:12px 16px;cursor:pointer;text-align:left;
          color:${_sbUsuario===u.id?'#fff':'var(--of)'};transition:all .15s">
          <div style="font-weight:700;font-size:14px">${u.label}</div>
          <div style="font-size:11px;opacity:.8">${u.desc}</div>
        </button>`).join('')}
    </div>
  `, null, null);
}

function sbConfirmarUsuario(id){
  sbSetUsuario(id);
  fecharModal();
  const nomes = {clarissa:'Clarissa', assistente:'Assistente', financeiro:'Financeiro'};
  showToast(`Logado como ${nomes[id]} ✓`);
  sbAtualizarIndicador();
}

function sbEscolherUsuario(){
  abrirModal('👤 Quem está usando?',`
    <p style="font-size:12px;color:var(--mu);margin-bottom:14px">Identifique-se para sincronizar com a nuvem.</p>
    <div style="display:flex;flex-direction:column;gap:8px">
      ${[
        {id:'clarissa',   label:'Clarissa',   cargo:'Advogada',             cor:'#510f10'},
        {id:'assistente', label:'Assistente', cargo:'Assistente jurídico',  cor:'#1a4a2e'},
        {id:'financeiro', label:'Financeiro', cargo:'Responsável financeiro',cor:'#1a2a4a'},
      ].map(u=>`
        <button onclick="sbSetUsuario('${u.id}');fecharModal()" style="
          background:${_sbUsuario===u.id?u.cor:'var(--sf2)'};
          border:2px solid ${_sbUsuario===u.id?u.cor:'var(--bd)'};
          border-radius:8px;padding:12px 16px;cursor:pointer;text-align:left;
          color:${_sbUsuario===u.id?'#fff':'var(--of)'};transition:all .15s">
          <div style="font-weight:700;font-size:14px">${u.label}</div>
          <div style="font-size:11px;opacity:.7">${u.cargo}</div>
        </button>`).join('')}
    </div>
  `, null, null);
}

// ══════════════════════════════════════════════════
// ══ PRAZOS DA PASTA ══
// ══════════════════════════════════════════════════
var prazos = {};
try { const _p = JSON.parse(lsGet('co_prazos')||'null'); prazos = (_p&&typeof _p==='object'&&!Array.isArray(_p)) ? _p : {}; } catch{}

const _SB_SYNC_OLD = _SB_SYNC;
_SB_SYNC.add('co_prazos');

function prazosSalvar(){
  sbSet('co_prazos', prazos);
  // NÃO escrever em co_td — essa chave é de tarefasDia, não de prazos.
  // A linha anterior (sbSet('co_td', prazos)) sobrescrevia tarefasDia com
  // dados de prazos, corrompendo o checklist de tarefas do dia.
}

// ── Helpers de prazo ──
var _hojeTs = new Date(_HOJE_STR).getTime();
function prazoDiasAte(p){
  if(!p.data) return null;
  return Math.ceil((new Date(p.data).getTime() - _hojeTs) / 86400000);
}
function prazoIsVencido(p){ var d=prazoDiasAte(p); return d!==null && d<0 && !p.cumprido; }
function prazoIsHoje(p){ return prazoDiasAte(p)===0 && !p.cumprido; }
function prazoStatusLbl(p){
  if(p.cumprido) return 'Concluido';
  var d=prazoDiasAte(p);
  if(d===null) return 'Pendente';
  if(d<0) return 'Vencido';
  if(d===0) return 'Hoje';
  if(d===1) return 'Amanha';
  return 'Pendente';
}
function prazoStatusCor(p){
  if(p.cumprido) return 'var(--mu)';
  var d=prazoDiasAte(p);
  if(d!==null&&d<0) return '#ef4444';
  if(d!==null&&d<=1) return '#f59e0b';
  return 'var(--mu)';
}

// togglePrazo — alterna prazo entre cumprido/pendente (chamada pelo botão de status)
function togglePrazo(cid, pid){
  var lista = prazos[cid]||[];
  var p = lista.find(function(x){ return x.id===pid||String(x.id)===String(pid); });
  if(!p) return;
  if(p.cumprido){
    // Desfazer conclusão → voltar para pendente
    p.cumprido = false;
    p.cumprido_em = '';
    p.obs_conclusao = '';
  } else {
    p.cumprido = true;
    p.cumprido_em = new Date().toISOString().slice(0,10);
  }
  prazosSalvar();
  marcarAlterado();
  if(AC && String(AC.id)===String(cid)) renderFicha(AC, _grupoAtual);
  showToast(p.cumprido ? 'Prazo concluído ✓' : 'Prazo reaberto');
}

// prazosConcluirComDesfecho — conclui prazo com modal de desfecho (chamada pelo botão de status)
// Prazos na aba "Prazos" da pasta são SEMPRE judiciais → exige protocolo/ID do documento.
function prazosConcluirComDesfecho(cid, pid){
  var lista = prazos[cid]||[];
  var p = lista.find(function(x){ return x.id===pid||String(x.id)===String(pid); });
  if(!p){ showToast('Prazo não encontrado'); return; }
  abrirModal('⚖️ Cumprimento de Prazo — '+(p.titulo||''),
    '<div style="margin-bottom:10px">'
      +'<div style="font-size:13px;font-weight:600;color:var(--tx)">'+(p.titulo||'Prazo')+'</div>'
      +'<div style="font-size:11px;color:var(--mu);margin-top:3px">Vencimento: '+fDt(p.data)+'</div>'
    +'</div>'
    +'<div style="font-size:12px;color:var(--mu);margin-bottom:10px;line-height:1.5">'
      +'Informe a <strong>prova do cumprimento</strong>. Isso fica registrado no histórico da pasta.'
    +'</div>'
    +'<div>'
      +'<label class="fm-lbl">Link do protocolo ou ID do documento <span class="req">*</span></label>'
      +'<input class="fm-inp" id="pcd-protocolo" value="'+escapeHtml(p.protocolo||'')+'" placeholder="Ex: PRJ-12345 · 0012345-67.2026.5.03.0001 · https://...">'
    +'</div>'
    +'<div style="margin-top:8px">'
      +'<label class="fm-lbl">Desfecho / observação (opcional)</label>'
      +'<textarea class="fm-inp" id="pcd-obs" rows="2" placeholder="O que foi feito para cumprir o prazo..."></textarea>'
    +'</div>',
  function(){
    var prot = (document.getElementById('pcd-protocolo')?.value||'').trim();
    if(!prot){ showToast('Informe o link ou ID do protocolo'); return; }
    var obs = (document.getElementById('pcd-obs')?.value||'').trim();
    p.cumprido = true;
    p.cumprido_em = new Date().toISOString().slice(0,10);
    p.obs_conclusao = obs;
    p.protocolo = prot;
    prazosSalvar();
    marcarAlterado();
    fecharModal();
    if(AC && String(AC.id)===String(cid)) renderFicha(AC, _grupoAtual);
    // Registrar andamento na pasta (com protocolo)
    if(!localMov[cid]) localMov[cid]=[];
    var msg = 'Prazo "'+(p.titulo||'')+'" cumprido — protocolo: '+prot;
    if(obs) msg += ' · '+obs;
    localMov[cid].unshift({
      data: new Date().toISOString().slice(0,10),
      movimentacao: msg,
      tipo_movimentacao: 'Judicial',
      origem: 'prazo_cumprido'
    });
    sbSet('co_localMov', localMov);
    showToast('Prazo cumprido ✓');
  }, '✅ Confirmar Cumprimento');
}

function editarPrazo(cid,pid){
  const p=(prazos[cid]||[]).find(x=>x.id===pid||String(x.id)===String(pid));
  if(!p){showToast('Prazo nao encontrado');return;}
  abrirModal('Editar Prazo',
    '<div class="fm-row">'
      +'<div style="flex:2"><label class="fm-lbl">Descricao *</label>'
        +'<input class="fm-inp" id="ep-titulo" value="'+(p.titulo||'').replace(/"/g,'&quot;')+'"></div>'
      +'<div><label class="fm-lbl">Tipo</label>'
        +'<select class="fm-inp" id="ep-tipo">'
        +['fatal','protocolo','audiencia','pericia','recurso','contestacao','outro'].map(t=>'<option value="'+t+'"'+(p.tipo===t?' selected':'')+'>'+t.charAt(0).toUpperCase()+t.slice(1)+'</option>').join('')
        +'</select></div>'
    +'</div>'
    +'<div class="fm-row" style="margin-top:8px"><div><label class="fm-lbl">Data *</label><input class="fm-inp" type="date" id="ep-data" value="'+(p.data||'')+'"></div></div>'
    +'<div style="margin-top:8px"><label class="fm-lbl">Obs</label><textarea class="fm-inp" id="ep-obs" rows="2">'+(p.obs||'')+'</textarea></div>',
  ()=>{
    const titulo=document.getElementById('ep-titulo')?.value.trim();
    const data=document.getElementById('ep-data')?.value;
    if(!titulo){showToast('Informe a descricao');return;}
    if(!data){showToast('Informe a data');return;}
    const tipo=document.getElementById('ep-tipo')?.value;
    const obs=document.getElementById('ep-obs')?.value.trim()||'';
    const idx=(prazos[cid]||[]).findIndex(x=>x.id===pid||String(x.id)===String(pid));
    if(idx>=0) prazos[cid][idx]={...prazos[cid][idx],titulo:titulo,data:data,tipo:tipo,obs:obs};
    prazosSalvar(); marcarAlterado(); fecharModal();
    const wrap=document.getElementById('prazo-'+cid+'-'+pid)?.closest('.prazos-wrap')?.parentElement;
    if(wrap) wrap.innerHTML=renderPrazos(cid);
    showToast('Prazo atualizado');
  },'Salvar');
}

// ── Calculadora de prazos (para frente e reverso) ──
function _addDiasUteis(dataInicial, dias, estado){
  var dt = new Date(dataInicial+'T12:00:00');
  var contados = 0;
  var direcao = dias >= 0 ? 1 : -1;
  var total = Math.abs(dias);
  while(contados < total){
    dt.setDate(dt.getDate()+direcao);
    var info = calcEhFeriado(dt, estado||'MG', '');
    if(!info.eh) contados++;
  }
  return dt.toISOString().slice(0,10);
}

function _contarDiasUteis(dataInicial, dataFinal, estado){
  var dt = new Date(dataInicial+'T12:00:00');
  var fim = new Date(dataFinal+'T12:00:00');
  var contados = 0;
  if(dt >= fim) return 0;
  while(dt < fim){
    dt.setDate(dt.getDate()+1);
    var info = calcEhFeriado(dt, estado||'MG', '');
    if(!info.eh) contados++;
  }
  return contados;
}

function _abrirCalcPrazo(cid){
  var hoje = getTodayKey();
  abrirModal('\ud83d\uddd3 Calcular Prazo',
    '<div style="display:flex;gap:6px;margin-bottom:14px">'
      +'<button id="cp-tab-frente" class="btn-bordo btn-bordo-sm" onclick="_cpSetTab(\'frente\')" style="flex:1">Para frente \u2192</button>'
      +'<button id="cp-tab-reverso" class="btn-bordo btn-bordo-sm" onclick="_cpSetTab(\'reverso\')" style="flex:1;background:var(--sf3);color:var(--mu);border-color:var(--bd)">\u2190 Reverso</button>'
    +'</div>'
    // Para frente
    +'<div id="cp-frente">'
      +'<div class="fm-row">'
        +'<div><label class="fm-lbl">Data inicial</label><input class="fm-inp" type="date" id="cp-f-data" value="'+hoje+'" onchange="_cpCalcFrente()"></div>'
        +'<div><label class="fm-lbl">Dias \u00fateis</label><input class="fm-inp" type="number" id="cp-f-dias" value="15" min="1" onchange="_cpCalcFrente()" oninput="_debounce(\'cpf\',_cpCalcFrente,300)"></div>'
        +'<div><label class="fm-lbl">Estado</label><select class="fm-inp" id="cp-f-uf" onchange="_cpCalcFrente()"><option>MG</option><option>SP</option><option>RJ</option><option>RS</option><option>PR</option><option>SC</option><option>BA</option><option>DF</option></select></div>'
      +'</div>'
      +'<div id="cp-f-result" style="margin-top:12px"></div>'
    +'</div>'
    // Reverso
    +'<div id="cp-reverso" style="display:none">'
      +'<div class="fm-row">'
        +'<div><label class="fm-lbl">Data final (prazo/audi\u00eancia)</label><input class="fm-inp" type="date" id="cp-r-data" onchange="_cpCalcReverso()"></div>'
        +'<div><label class="fm-lbl">Dias \u00fateis antes</label><input class="fm-inp" type="number" id="cp-r-dias" value="5" min="0" onchange="_cpCalcReverso()" oninput="_debounce(\'cpr\',_cpCalcReverso,300)"></div>'
        +'<div><label class="fm-lbl">Estado</label><select class="fm-inp" id="cp-r-uf" onchange="_cpCalcReverso()"><option>MG</option><option>SP</option><option>RJ</option><option>RS</option><option>PR</option><option>SC</option><option>BA</option><option>DF</option></select></div>'
      +'</div>'
      +'<div id="cp-r-result" style="margin-top:12px"></div>'
    +'</div>',
  null, 'Fechar');
  setTimeout(_cpCalcFrente, 100);
}

function _cpSetTab(tab){
  var bf = document.getElementById('cp-tab-frente');
  var br = document.getElementById('cp-tab-reverso');
  var df = document.getElementById('cp-frente');
  var dr = document.getElementById('cp-reverso');
  if(tab==='frente'){
    if(bf){ bf.style.background=''; bf.style.color=''; bf.style.borderColor=''; }
    if(br){ br.style.background='var(--sf3)'; br.style.color='var(--mu)'; br.style.borderColor='var(--bd)'; }
    if(df) df.style.display='block';
    if(dr) dr.style.display='none';
  } else {
    if(br){ br.style.background=''; br.style.color=''; br.style.borderColor=''; }
    if(bf){ bf.style.background='var(--sf3)'; bf.style.color='var(--mu)'; bf.style.borderColor='var(--bd)'; }
    if(df) df.style.display='none';
    if(dr) dr.style.display='block';
  }
}

function _cpCalcFrente(){
  var data = document.getElementById('cp-f-data')?.value;
  var dias = parseInt(document.getElementById('cp-f-dias')?.value)||0;
  var uf = document.getElementById('cp-f-uf')?.value||'MG';
  var el = document.getElementById('cp-f-result');
  if(!el||!data||!dias) return;
  var resultado = _addDiasUteis(data, dias, uf);
  var diasCorridos = Math.ceil((new Date(resultado)-new Date(data))/86400000);
  el.innerHTML = '<div style="background:var(--sf2);border:1px solid var(--bd);border-radius:8px;padding:14px;text-align:center">'
    +'<div style="font-size:10px;font-weight:700;text-transform:uppercase;color:var(--mu);margin-bottom:4px">Prazo final</div>'
    +'<div style="font-size:24px;font-weight:800;color:#4ade80">'+fDt(resultado)+'</div>'
    +'<div style="font-size:11px;color:var(--mu);margin-top:4px">'+dias+' dias \u00fateis = '+diasCorridos+' dias corridos</div>'
  +'</div>';
}

function _cpCalcReverso(){
  var dataFinal = document.getElementById('cp-r-data')?.value;
  var diasAntes = parseInt(document.getElementById('cp-r-dias')?.value)||0;
  var uf = document.getElementById('cp-r-uf')?.value||'MG';
  var el = document.getElementById('cp-r-result');
  if(!el||!dataFinal) return;
  var hoje = getTodayKey();
  var diasRestantes = _contarDiasUteis(hoje, dataFinal, uf);
  var dataLimite = diasAntes > 0 ? _addDiasUteis(dataFinal, -diasAntes, uf) : dataFinal;
  var diasAteLimite = _contarDiasUteis(hoje, dataLimite, uf);
  var corLimite = diasAteLimite <= 0 ? '#c9484a' : diasAteLimite <= 3 ? '#f59e0b' : '#4ade80';

  el.innerHTML = '<div style="display:grid;grid-template-columns:1fr 1fr;gap:8px">'
    +'<div style="background:var(--sf2);border:1px solid var(--bd);border-radius:8px;padding:12px;text-align:center">'
      +'<div style="font-size:9px;font-weight:700;text-transform:uppercase;color:var(--mu)">Restam at\u00e9 '+fDt(dataFinal)+'</div>'
      +'<div style="font-size:22px;font-weight:800;color:'+(diasRestantes<=3?'#f59e0b':'var(--tx)')+'">'+diasRestantes+' dias \u00fateis</div>'
    +'</div>'
    +(diasAntes>0?'<div style="background:var(--sf2);border:1px solid var(--bd);border-radius:8px;padding:12px;text-align:center">'
      +'<div style="font-size:9px;font-weight:700;text-transform:uppercase;color:var(--mu)">Limite ('+diasAntes+'d \u00fateis antes)</div>'
      +'<div style="font-size:22px;font-weight:800;color:'+corLimite+'">'+fDt(dataLimite)+'</div>'
      +'<div style="font-size:10px;color:var(--mu)">'+diasAteLimite+' dias \u00fateis a partir de hoje</div>'
    +'</div>':'')
  +'</div>';
}

// ── Migrar prazos legados (prazos[cid]) para localAg ──
function _migrarPrazosParaAg(){
  if(!prazos||typeof prazos!=='object') return;
  var migrados = 0;
  var existentes = new Set((localAg||[]).map(function(p){ return String(p._prazo_legado_id||''); }));
  Object.keys(prazos).forEach(function(cid){
    var lista = prazos[cid]||[];
    var c = findClientById(Number(cid))||findClientById(cid);
    lista.forEach(function(p){
      if(existentes.has(String(p.id))) return; // já migrado
      localAg.push({
        id: 'mig_'+p.id, titulo: p.titulo||'Prazo', tipo_compromisso: p.tipo||'Outro',
        cliente: c?c.cliente:'', id_processo: Number(cid)||cid,
        dt_raw: p.data, dt_fim: p.data, inicio: p.data,
        obs: p.obs||'', realizado: !!p.cumprido, cumprido: p.cumprido?'Sim':'',
        dt_conclusao: p.cumprido_em||'',
        _prazo: true, _prazo_legado_id: p.id, origem: 'prazo_migrado'
      });
      migrados++;
    });
  });
  if(migrados>0){
    sbSet('co_ag', localAg); invalidarAllPend();
  }
}
try { _migrarPrazosParaAg(); } catch(e){}

function renderPrazos(cid){
  // Filtra tombstones inline (prazos excluídos não devem reaparecer via sync)
  const lista=(prazos[cid]||[]).filter(function(p){return !p.deleted;}), hoje=getTodayKey();
  const pend=lista.filter(p=>!p.cumprido).sort((a,b)=>a.data.localeCompare(b.data));
  const done=lista.filter(p=>p.cumprido).sort((a,b)=>b.data.localeCompare(a.data));
  const MA=['Jan','Fev','Mar','Abr','Mai','Jun','Jul','Ago','Set','Out','Nov','Dez'];
  const fD=d=>{if(!d)return'-';const[y,m,di]=d.split('-');return di+'/'+m+'/'+y;};
  const TP={'fatal':'Fatal','protocolo':'Protocolo','audiencia':'Audiencia',
    'pericia':'Pericia','recurso':'Recurso','contestacao':'Contestacao','outro':'Outro'};
  const row=p=>{
    const isDone=!!p.cumprido;
    const diff=prazoDiasAte(p);
    const isV=prazoIsVencido(p), isH=prazoIsHoje(p);
    const sLbl=prazoStatusLbl(p);
    const sCls=isDone?'comp-st-done':isV?'comp-st-venc':(isH||(diff===1&&!isDone))?'comp-st-hoje':'comp-st-pend';
    const dp=(p.data||'').split('-');
    const calCls=isDone?'comp-cal-done':isV?'comp-cal-venc':isH?'comp-cal-hoje':'';
    const diffTxt=isDone?('Cumprido '+fD(p.cumprido_em)):isV?('Vencido ha '+(-diff)+'d'):isH?'HOJE':(diff!==null?diff+'d':'\u2014');
    const dColor=prazoStatusCor(p);
    const pidQ=isNaN(p.id)?('\''+p.id+'\''):p.id;
    const onSt=isDone?('togglePrazo('+cid+','+pidQ+')'):'prazosConcluirComDesfecho('+cid+','+pidQ+')';
    const obsHtml=p.obs?(' <span title="'+p.obs.replace(/"/g,'&quot;')+'">&#x1F4AC;</span>'):'';
    return '<div class="comp-card '+(isDone?'comp-card-done':'')+'" id="prazo-'+cid+'-'+p.id+'">'
      +'<div class="comp-cal '+calCls+'">'
        +'<div class="comp-cal-dia">'+(dp[2]||'?')+'</div>'
        +'<div class="comp-cal-mes">'+(dp[1]?MA[parseInt(dp[1],10)-1]||'':'')+'</div>'
      +'</div>'
      +'<div class="comp-card-body">'
        +'<div class="comp-card-titulo '+(isDone?'done':'')+'">'+p.titulo+'</div>'
        +'<div class="comp-card-meta">'
          +'<span style="font-size:10px;opacity:.7">'+(TP[p.tipo]||p.tipo||'Prazo')+'</span>'
          +' &middot; <span style="font-size:10px;color:var(--mu)">'+fD(p.data)+'</span>'
          +' &middot; <span style="font-size:10px;color:'+dColor+'">'+diffTxt+'</span>'+obsHtml
        +'</div>'
      +'</div>'
      +'<div class="comp-card-right">'
        +'<button class="comp-st-btn '+sCls+'" onclick="'+onSt+'">'+sLbl+' &#x25be;</button>'
        +'<button class="comp-edit-btn" onclick="editarPrazo('+cid+','+p.id+')" title="Editar">&#x270F;</button>'
        +'<button class="comp-edit-btn" onclick="deletarPrazo('+cid+','+p.id+')" style="color:#ef4444">&#x2715;</button>'
      +'</div>'
    +'</div>';
  };
  let out='<div class="prazos-wrap">'
    +'<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:12px">'
      +'<span class="dp-sep" style="margin:0">Prazos da Pasta</span>'
      +'<div style="display:flex;gap:6px">'
        +'<button class="btn-bordo btn-bordo-sm" onclick="abrirModalPrazo('+cid+')">+ Novo Prazo</button>'
        +'<button class="btn-bordo btn-bordo-sm" style="background:var(--sf3);color:var(--mu);border-color:var(--bd)" onclick="_abrirCalcPrazo('+cid+')">\ud83d\uddd3 Calcular prazo</button>'
      +'</div>'
    +'</div>';
  if(!pend.length&&!done.length){
    out+='<div style="font-size:12px;color:var(--mu);font-style:italic;padding:12px 0">Nenhum prazo cadastrado.</div>';
  } else {
    out+=pend.map(p=>row(p)).join('');
    if(done.length){
      out+='<div class="dp-sep" style="margin-top:14px;margin-bottom:8px;font-size:10px;opacity:.7">Cumpridos ('+done.length+')</div>';
      out+=done.slice(0,5).map(p=>row(p)).join('');
      if(done.length>5) out+='<div style="font-size:11px;color:var(--mu);text-align:center;padding:6px">+ '+(done.length-5)+' mais</div>';
    }
  }
  return out+'</div>';
}


function renderAgendaProc(cid){
  const hoje=getTodayKey();
  const todos=allPendCached().filter(p=>
    String(p.id_processo)===String(cid)
    && p.tipo_compromisso!=='Atendimento'
    && p.origem!=='atendimento'
    && p.origem!=='baixa_fin'
  ).sort((a,b)=>(a.dt_raw||'').localeCompare(b.dt_raw||''));
  const MA=['Jan','Fev','Mar','Abr','Mai','Jun','Jul','Ago','Set','Out','Nov','Dez'];
  const fmtDtAg=p=>{
    const s=p.inicio||p.dt_raw||'';if(!s)return'-';
    const[dt,hr='']= s.replace('T',' ').split(' ');
    if(dt.includes('/')) return s.slice(0,16);
    const[y,m,di]=dt.split('-'), h=hr.slice(0,5);
    return (di||'?')+'/'+(m||'?')+'/'+(y||'?')+(h&&h!=='00:00'?' '+h:'');
  };
  const diasAte=dt=>dt?Math.ceil((new Date(dt)-new Date(hoje))/86400000):999;
  const noItem='<div class="prazos-wrap" style="margin-bottom:0">'
    +'<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:8px">'
      +'<span class="dp-sep" style="margin:0">📅 Compromissos</span>'
      +'<button class="btn-bordo btn-bordo-sm" onclick="abrirModalPrazo('+cid+')">＋ Novo</button>'
    +'</div>'
    +'<div style="font-size:12px;color:var(--mu);font-style:italic;padding:4px 0">Nenhum compromisso cadastrado.</div>'
  +'</div><div style="height:1px;background:var(--bd);margin:6px 0 12px"></div>';
  if(!todos.length) return noItem;
  const row=p=>{
    const item_real_data = p.realizado && p.dt_conclusao
      ? 'em '+fmtDataBR(p.dt_conclusao) : '';
    const dtFim=(p.dt_fim||p.dt_raw||'').slice(0,10);
    const d=diasAte(dtFim);
    const pass=dtFim<hoje&&!p.realizado, isDone=p.realizado;
    const emAndam=(p.dt_raw||'')<hoje&&dtFim>=hoje&&!p.realizado;
    const sLbl=isDone?'Concluido':pass?'Vencido':emAndam?'Em andamento':d===0?'Hoje':d===1?'Amanha':'Pendente';
    const sCls=isDone?'comp-st-done':pass?'comp-st-venc':d<=1?'comp-st-hoje':'comp-st-pend';
    const dtP=(p.dt_raw||'').slice(0,10).split('-');
    const calCls=isDone?'comp-cal-done':pass?'comp-cal-venc':d<=1?'comp-cal-hoje':'';
    const pid=String(p.id||p.id_agenda);
    const onSt='agendaConcluirComDesfecho(\''+pid+'\','+cid+')';
    const onEd='editarAgCliente(\''+pid+'\','+cid+')';
    return '<div class="comp-card '+(isDone?'comp-card-done':'')+'">'
      +'<div class="comp-cal '+calCls+'">'
        +'<div class="comp-cal-dia">'+(dtP[2]||'?')+'</div>'
        +'<div class="comp-cal-mes">'+(dtP[1]?MA[parseInt(dtP[1],10)-1]||'':'')+'</div>'
      +'</div>'
      +'<div class="comp-card-body">'
        +'<div class="comp-card-titulo '+(isDone?'done':'')+'">'+( p.tipo_compromisso||p.titulo||'Compromisso')
          +(p._prazo?' <span style="font-size:8px;padding:1px 5px;border-radius:3px;background:rgba(245,158,11,.15);color:#f59e0b;font-weight:700;vertical-align:middle">PRAZO</span>':'')
          +(p.hora?' <span style="font-size:9px;color:var(--mu)">\u23f0 '+p.hora+'</span>':'')
          +(!isDone&&!pass&&d>0&&d<999?' <span style="font-size:9px;color:'+(d<=3?'#f59e0b':'var(--mu)')+'">'+d+'d</span>':'')
        +'</div>'
        +(()=>{
          const fmD=d=>d?fDt(d):'';
          const dur=eventoDuracao(p);
          if(dur>1){
            return '<div class="comp-card-meta"><span style="color:var(--ouro);font-weight:600">⟷ '+fmD(p.dt_raw)+' a '+fmD(p.dt_fim)+'</span>'
              +' <span style="font-size:9px;opacity:.6">('+dur+' dias)</span></div>';
          }
          return '<div class="comp-card-meta">'+fmtDtAg(p)+'</div>';
        })()
        +(p.obs?'<div class="comp-card-meta" style="font-style:italic">'+p.obs+'</div>':'')
      +'</div>'
      +'<div class="comp-card-right">'
        +(isDone
          ? '<span class="comp-st-btn comp-st-done" style="cursor:default">&#x2705; Concluido</span>'
            +(item_real_data ? '<div style="font-size:9px;color:var(--mu);margin-top:2px">'+item_real_data+'</div>' : '')
          : '<button class="comp-st-btn '+sCls+'" onclick="'+onSt+'">'+sLbl+' &#x25be;</button>'
            +'<button class="comp-edit-btn" onclick="'+onEd+'" title="Editar">&#x270F;</button>'
            +'<button class="comp-edit-btn" onclick="excluirAgCliente(\''+pid+'\','+cid+')" title="Excluir" style="color:#ef4444">&#x2715;</button>'
        )
      +'</div>'
    +'</div>';
  };
  // Eventos em andamento (começou antes de hoje mas ainda não terminou)
  const andamento=todos.filter(p=>!p.realizado&&(p.dt_raw||'')<hoje&&(p.dt_fim||p.dt_raw||'')>=hoje);
  const fut=todos.filter(p=>!p.realizado&&(p.dt_raw||'')>=hoje);
  const past=todos.filter(p=>!p.realizado&&(p.dt_fim||p.dt_raw||'')<hoje);
  const real=todos.filter(p=>p.realizado);
  let out='<div class="prazos-wrap" style="margin-bottom:4px">'
    +'<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:8px">'
      +'<span class="dp-sep" style="margin:0">📅 Compromissos</span>'
      +'<button class="btn-bordo btn-bordo-sm" onclick="abrirModalPrazo('+cid+')">＋ Novo</button>'
    +'</div>';
  if(andamento.length) out+='<div class="dp-sep" style="margin:0 0 6px;font-size:10px;color:var(--ouro)">⏳ Em andamento ('+andamento.length+')</div>'+andamento.map(p=>row(p)).join('');
  out+=fut.map(p=>row(p)).join('');
  if(past.length) out+='<div class="dp-sep" style="margin:8px 0 6px;font-size:10px;color:#ef4444">Vencidos ('+past.length+')</div>'+past.map(p=>row(p)).join('');
  if(real.length) out+='<div class="dp-sep" style="margin:8px 0 6px;font-size:10px;opacity:.55">Realizados ('+real.length+')</div>'+real.slice(0,3).map(p=>row(p)).join('');
  return out+'</div><div style="height:1px;background:var(--bd);margin:6px 0 12px"></div>';
}


function abrirModalAgCliente(cid){ abrirModalPrazo(cid); }

function excluirAgCliente(agId, cid){
  const raw = String(agId).replace(/^ag/,'');
  const item = (localAg||[]).find(a=>String(a.id)===raw||String(a.id_agenda)===raw)
            || (PEND||[]).find(p=>String(p.id)===raw||String(p.id_agenda)===raw);
  const titulo = item?.titulo||item?.tipo_compromisso||'este compromisso';
  abrirModal('Excluir compromisso',
    `<div style="font-size:13px;color:var(--mu);line-height:1.6">
      Excluir <strong style="color:var(--tx)">"${titulo}"</strong>?<br>
      <span style="font-size:11px">Esta ação não pode ser desfeita.</span>
    </div>`,
    ()=>{
      // Tombstone o id real (e id_agenda se houver) — cobre os dois caminhos
      // de resolução no sbAplicar.
      _tombstoneAdd('co_ag', raw);
      _tombstoneAdd('co_localAg', raw);
      localAg = (localAg||[]).filter(function(a){return String(a.id)!==raw&&String(a.id_agenda)!==raw;});
      sbSet('co_ag', localAg); invalidarAllPend();
      marcarAlterado();
      fecharModal();
      var el = document.getElementById('tp-agenda-proc-'+cid);
      if(el) el.innerHTML = renderAgendaProc(cid);
      _render_agenda_all();
      atualizarStats();
      showToast('Compromisso excluído');
    }, 'Excluir'
  );
  setTimeout(()=>{
    const btn = document.getElementById('modal-save');
    if(btn){ btn.style.background='var(--red)'; btn.textContent='Confirmar exclusão'; }
  }, 50);
}

function editarAgCliente(agId,cid){
  const raw=String(agId).replace(/^ag/,'');
  let item=(localAg||[]).find(a=>String(a.id)===raw||String(a.id_agenda)===raw);
  if(!item) item=(PEND||[]).find(p=>String(p.id)===raw||String(p.id_agenda)===raw);
  if(!item){showToast('Compromisso nao encontrado');return;}
  const fDate=d=>d?(d.includes('T')?d.slice(0,10):d.slice(0,10)):'';
  const fTime=d=>d&&d.includes('T')?d.slice(11,16):'';
  abrirModal('Editar Compromisso',
    '<div class="fm-row">'
      +'<div style="flex:2"><label class="fm-lbl">Descricao *</label>'
        +'<input class="fm-inp" id="eag-titulo" value="'+(item.titulo||item.descricao||item.tipo_compromisso||'').replace(/"/g,'&quot;')+'"></div>'
      +'<div><label class="fm-lbl">Tipo</label>'
        +'<select class="fm-inp" id="eag-tipo">'
        +['Audiencia','Prazo','Reuniao','Pericia','Despacho','Outro'].map(t=>'<option'+(( item.tipo_compromisso||item.tipo||'')=== t?' selected':'')+'>'+t+'</option>').join('')
        +'</select></div>'
    +'</div>'
    +'<div class="fm-row" style="margin-top:8px">'
      +'<div><label class="fm-lbl">Data *</label><input class="fm-inp" type="date" id="eag-data" value="'+fDate(item.inicio||item.dt_raw)+'"></div>'
      +'<div><label class="fm-lbl">Hora</label><input class="fm-inp" type="time" id="eag-hora" value="'+fTime(item.inicio||item.dt_raw)+'"></div>'
    +'</div>'
    +'<div style="margin-top:8px"><label class="fm-lbl">Obs</label>'
      +'<textarea class="fm-inp" id="eag-obs" rows="2">'+(item.obs||'')+'</textarea></div>',
  ()=>{
    const titulo=document.getElementById('eag-titulo')?.value.trim();
    if(!titulo){showToast('Informe a descricao');return;}
    const data=document.getElementById('eag-data')?.value;
    const hora=document.getElementById('eag-hora')?.value||'';
    const tipo=document.getElementById('eag-tipo')?.value||'';
    const obs=document.getElementById('eag-obs')?.value.trim()||'';
    const dt=hora?data+'T'+hora:data;
    const updated={...item,titulo,descricao:titulo,tipo_compromisso:tipo,inicio:dt,dt_raw:dt,obs};
    const idxL=(localAg||[]).findIndex(a=>String(a.id)===raw||String(a.id_agenda)===raw);
    if(idxL>=0) localAg[idxL]=updated;
    else{if(!localAg)localAg=[];localAg.push({...updated,id:raw,id_agenda:raw});}
    sbSet('co_ag',localAg); invalidarAllPend(); marcarAlterado(); fecharModal();
    const el=document.getElementById('tp-agenda-proc-'+cid);
    if(el) el.innerHTML=renderAgendaProc(cid);
    showToast('Compromisso atualizado');
  },'Salvar');
}

function excluirMovimentacao(cid, idx){
  const lista = localMov[cid]||[];
  const m = lista[idx];
  if(!m) return;
  const desc = (m.movimentacao||m.desc||'').slice(0,60);
  abrirModal('Excluir movimentação',
    `<div style="font-size:13px;color:var(--mu);line-height:1.6">
      Tem certeza que deseja excluir este andamento?<br>
      <span style="color:var(--tx);font-weight:600">"${desc}${desc.length>=60?'…':''}"</span>
    </div>`,
    ()=>{
      localMov[cid].splice(idx, 1);
      sbSet('co_localMov', localMov);
      marcarAlterado(); fecharModal();
      if(AC?.id===cid) renderFicha(AC, _grupoAtual);
      showToast('Andamento exclu\u00eddo');
    }, 'Excluir'
  );
  setTimeout(()=>{
    const btn=document.getElementById('modal-save');
    if(btn){btn.style.background='var(--red)';btn.textContent='Confirmar exclusão';}
  },50);
}

function editarMovimentacao(cid, idx){
  const lista = localMov[cid]||[];
  const m = lista[idx];
  if(!m) return;
  const form = mInput('emov-data','Data','date', m.data||getTodayKey())
    + mTextarea('emov-desc','Descrição', m.movimentacao||m.desc||'');
  abrirModal('Editar movimentação', form, ()=>{
    const data = document.getElementById('emov-data')?.value||m.data;
    const desc = document.getElementById('emov-desc')?.value.trim();
    if(!desc){ showToast('Informe a descrição'); return; }
    lista[idx] = {...m, data, movimentacao:desc, desc};
    sbSet('co_localMov', localMov);
    fecharModal();
    if(AC?.id===cid) renderFicha(AC, _grupoAtual);
    showToast('Movimentação atualizada ✓');
  }, 'Salvar');
}

function novoConsulta(){ novoAtendimento(); }
function setCtcTipo(tipo){
  var pfBtn = document.getElementById('ctc-pf-btn');
  var pjBtn = document.getElementById('ctc-pj-btn');
  var lbl = document.getElementById('ctc-doc-lbl');
  var inp = document.getElementById('nc-doc');
  var cnpjBtn = document.getElementById('nc-cnpj-btn');
  var nascRow = document.getElementById('nc-nasc-row');
  var rgRow = document.getElementById('nc-rg-row');
  if(tipo==='pf'){
    pfBtn?.classList.add('on'); pjBtn?.classList.remove('on');
    if(lbl) lbl.textContent='CPF';
    if(inp) inp.placeholder='000.000.000-00';
    if(cnpjBtn) cnpjBtn.style.display='none';
    if(nascRow) nascRow.style.display='flex';
    if(rgRow) rgRow.style.display='block';
  } else {
    pjBtn?.classList.add('on'); pfBtn?.classList.remove('on');
    if(lbl) lbl.textContent='CNPJ';
    if(inp) inp.placeholder='00.000.000/0000-00';
    if(cnpjBtn) cnpjBtn.style.display='block';
    if(nascRow) nascRow.style.display='none';
    if(rgRow) rgRow.style.display='none';
  }
}

function updateObsCount(cid){
  const el = document.getElementById('obs-'+cid);
  const counter = document.getElementById('obs-count-'+cid);
  if(el && counter) counter.textContent = (el.value||'').length + '/2000';
}

function toggleSidebar(){
  const aside = document.getElementById('sidebar-aside');
  const btn = document.getElementById('sb-toggle');
  const isOpen = aside.classList.toggle('sb-open');
  btn.classList.toggle('sb-active', isOpen);
  localStorage.setItem('co_sidebar', isOpen?'1':'0');
}
function initSidebar(){
  const saved = localStorage.getItem('co_sidebar');
  if(saved==='1'||saved===null){
    document.getElementById('sidebar-aside')?.classList.add('sb-open');
    document.getElementById('sb-toggle')?.classList.add('sb-active');
  }
}

// ═══════════════════════════════════════════
// SISTEMA DE COMENTÁRIOS (aba Comentários)
// ═══════════════════════════════════════════
// (comentarios carregado do localStorage no init)

function abrirModalComentario(cid){
  abrirModal('💬 Novo Comentário', `
    <div style="margin-bottom:10px">
      <label class="fm-lbl">Comentário</label>
      <textarea class="fm-inp" id="mc-txt" rows="4" placeholder="Escreva seu comentário..."></textarea>
    </div>
  `, ()=>{
    const txt = document.getElementById('mc-txt')?.value.trim();
    if(!txt){ showToast('Escreva um comentário'); return; }
    if(!comentarios[cid]) comentarios[cid] = [];
    comentarios[cid].push({ texto:txt, data:getTodayKey(), autor: _sbUsuario||'Clarissa' });
    sbSet('co_coments', comentarios);
    const el = document.getElementById('coment-list-'+cid);
    if(el) el.innerHTML = renderComentarios(cid);
    fecharModal();
    showToast('Comentário adicionado ✓');
  }, 'Salvar');
}

function salvarComentarioInline(cid){
  const ta = document.getElementById('coment-ta-'+cid);
  if(!ta) return;
  const txt = ta.value.trim();
  if(!txt){ showToast('Escreva um comentário antes de salvar'); return; }
  const agora = new Date();
  const hora = agora.toTimeString().slice(0,5);
  if(!comentarios[cid]) comentarios[cid] = [];
  comentarios[cid].push({
    texto: txt,
    data: getTodayKey(),
    hora: hora,
    autor: _sbUsuario||'Clarissa'
  });
  sbSet('co_coments', comentarios);
  ta.value = '';
  updateComentCount(cid);
  const lista = document.getElementById('coment-list-'+cid);
  if(lista) lista.innerHTML = renderComentarios(cid);
  showToast('Comentário salvo ✓');
}
function renderComentarios(cid){
  const lista = (comentarios[cid]||[]).slice().reverse();
  if(!lista.length) return `<div class="tp-empty">Nenhum comentário ainda. Use o campo acima para registrar uma anotação.</div>`;
  return lista.map((c,i)=>`
    <div class="coment-item">
      <div class="coment-meta">
        <span class="coment-autor">${c.autor||_sbUsuario||'Clarissa'}</span>
        <span class="coment-data">
          ${fmtDataBR(c.data)}${c.hora ? ' · '+c.hora : ''}
        </span>
        <button class="coment-del" onclick="deletarComentario(${cid},${lista.length-1-i})" title="Excluir comentário">✕</button>
      </div>
      <div class="coment-txt">${(c.texto||'').replace(/\n/g,'<br>')}</div>
    </div>`).join('');
}

function adicionarComentario(cid){
  const inp = document.getElementById('coment-inp-'+cid);
  const txt = inp?.value.trim();
  if(!txt){ showToast('Digite um comentário'); return; }
  if(txt.length>2000){ showToast('Máximo 2000 caracteres'); return; }
  if(!comentarios[cid]) comentarios[cid]=[];
  const agora = new Date();
  comentarios[cid].push({
    texto:txt, autor:_sbUsuario||'Clarissa',
    data:getTodayKey(),
    hora:agora.toLocaleTimeString('pt-BR',{hour:'2-digit',minute:'2-digit'})
  });
  sbSet('co_coments', comentarios);
  inp.value='';
  updateComentCount(cid);
  const wrap = document.getElementById('coments-'+cid);
  if(wrap) wrap.innerHTML = renderComentarios(cid);
  showToast('Comentário adicionado ✓');
}

function deletarComentario(cid, idx){
  abrirModal('Excluir comentário','<div style="font-size:13px;color:var(--mu)">Excluir este comentário?</div>',function(){
    fecharModal();
    (comentarios[cid]||[]).splice(idx,1);
    sbSet('co_coments', comentarios);
    marcarAlterado();
    var wrap = document.getElementById('coment-list-'+cid);
    if(wrap) wrap.innerHTML = renderComentarios(cid);
    showToast('Coment\u00e1rio exclu\u00eddo');
  }, 'Excluir');
}

function updateComentCount(cid){
  const inp = document.getElementById('coment-inp-'+cid);
  const cnt = document.getElementById('coment-cnt-'+cid);
  if(cnt && inp) cnt.textContent = (inp.value.length)+'/2000';
}

// ═══════════════════════════════════════════
// AGENDA — CALENDÁRIO
// ═══════════════════════════════════════════

function gerarRelatorioAgPDF(){
  const hoje = getTodayKey();
  abrirModal('📄 Relatório PDF — Compromissos', `
    <div class="fm-row">
      <div><label class="fm-lbl">Data início</label><input class="fm-inp" id="pdf-ini" type="date" value="${hoje}"></div>
      <div><label class="fm-lbl">Data fim</label><input class="fm-inp" id="pdf-fim" type="date" value="${(()=>{const d=new Date(hoje);d.setDate(d.getDate()+30);return d.toISOString().slice(0,10);})()}"></div>
    </div>
    <div style="margin-top:10px">
      <label class="fm-lbl">Filtro</label>
      <select class="fm-inp" id="pdf-filtro">
        <option value="todos">Todos os compromissos</option>
        <option value="fut">Apenas futuros</option>
        <option value="pend">Apenas pendentes/passados</option>
        <option value="real">Apenas realizados</option>
      </select>
    </div>
    <div style="margin-top:10px">
      <label class="fm-lbl">Cliente (opcional)</label>
      <input class="fm-inp" id="pdf-cli" placeholder="Deixe em branco para todos">
    </div>
  `, ()=>{
    const ini = document.getElementById('pdf-ini')?.value;
    const fim = document.getElementById('pdf-fim')?.value;
    const filtro = document.getElementById('pdf-filtro')?.value;
    const cli = document.getElementById('pdf-cli')?.value.trim().toLowerCase();
    let lista = allPendCached().filter(p=>{
      const dt = (p.dt_raw||'').slice(0,10);
      if(ini && dt < ini) return false;
      if(fim && dt > fim) return false;
      if(cli && !(p.cliente||'').toLowerCase().includes(cli)) return false;
      if(filtro==='fut') return dt>=hoje && !p.realizado;
      if(filtro==='pend') return dt<hoje && !p.realizado;
      if(filtro==='real') return p.realizado;
      return true;
    }).sort((a,b)=>(a.dt_raw||'').localeCompare(b.dt_raw||''));

    const linhas = lista.map(p=>`
      <tr>
        <td>${fmtDataBR(p.dt_raw)}</td>
        <td>${p.tipo_compromisso||p.titulo||'—'}</td>
        <td>${p.cliente||'—'}</td>
        <td>${p.realizado?'✓ Realizado':((p.dt_raw||'')<hoje?'⚠ Pendente':'Aguardando')}</td>
      </tr>`).join('');

    const win = window.open('','_blank');
    win.document.write(`<!DOCTYPE html><html><head><meta charset="utf-8">
    <title>Relatório de Compromissos — Clarissa Oliveira Advogada</title>
    <style>
      body{font-family:Arial,sans-serif;font-size:12px;color:#1a0f0f;padding:32px;max-width:900px;margin:0 auto}
      h1{font-size:18px;color:#6b1416;border-bottom:2px solid #6b1416;padding-bottom:8px;margin-bottom:4px}
      .sub{font-size:11px;color:#555;margin-bottom:20px}
      table{width:100%;border-collapse:collapse;margin-top:16px}
      th{background:#6b1416;color:#fff;padding:8px 10px;text-align:left;font-size:11px;letter-spacing:.04em}
      td{padding:7px 10px;border-bottom:1px solid #e5e0d8;vertical-align:top}
      tr:nth-child(even) td{background:#faf8f5}
      .footer{margin-top:24px;font-size:10px;color:#888;border-top:1px solid #e5e0d8;padding-top:10px}
      @media print{body{padding:16px}}
    </style></head><body>
    <h1>Relatório de Compromissos</h1>
    <div class="sub">Clarissa Oliveira Advogada &nbsp;·&nbsp; Período: ${fmtDataBR(ini)} a ${fmtDataBR(fim)} &nbsp;·&nbsp; Gerado em ${new Date().toLocaleDateString('pt-BR')}</div>
    <table><thead><tr><th>Data</th><th>Compromisso</th><th>Cliente</th><th>Status</th></tr></thead>
    <tbody>${linhas||'<tr><td colspan="4" style="text-align:center;color:#888;font-style:italic">Nenhum compromisso no período.</td></tr>'}</tbody></table>
    <div class="footer">Total: ${lista.length} compromisso(s) &nbsp;·&nbsp; Clarissa Oliveira Advogada &nbsp;·&nbsp; Sistema de Gestão Jurídica</div>
    </body></html>`);
    win.document.close(); win.focus();
    fecharModal();
    setTimeout(()=>{ try{ win.print(); }catch(e){ showToast('PDF aberto em nova aba'); } },600);
  }, '⬇ Gerar PDF');
}

function gerarRelatorioTarefasPDF(){
  const hoje = getTodayKey();
  abrirModal('\ud83d\udcc4 Relat\u00f3rio PDF \u2014 Tarefas',
    '<div class="fm-row">'+'<div><label class="fm-lbl">Data in\u00edcio</label><input class="fm-inp" id="tpdf-ini" type="date" value="'+hoje+'"></div>'+'<div><label class="fm-lbl">Data fim</label><input class="fm-inp" id="tpdf-fim" type="date"></div>'+'</div>'+'<div style="margin-top:10px"><label class="fm-lbl">Status</label>'+'<select class="fm-inp" id="tpdf-status">'+'<option value="todos">Todas</option>'+'<option value="todo">A Fazer</option>'+'<option value="andamento">Em Andamento</option>'+'<option value="done">Conclu\u00eddas</option>'+'</select></div>',
  function(){
    const ini = document.getElementById('tpdf-ini')?.value;
    const fim = document.getElementById('tpdf-fim')?.value;
    const status = document.getElementById('tpdf-status')?.value;
    var lista = vkFiltrados().filter(function(t){
      if(status!=='todos' && !isDone(t) && t.status!==status) return false;
      if(status==='done' && !isDone(t)) return false;
      if(ini && t.prazo && t.prazo<ini) return false;
      if(fim && t.prazo && t.prazo>fim) return false;
      return true;
    });
    const STATUS_L = {todo:'A Fazer',andamento:'Em Andamento',done:'Conclu\u00edda',concluido:'Conclu\u00edda'};
    const linhas = lista.map(function(t){
      return '<tr>'        +'<td>'+escapeHtml(t.titulo||'\u2014')+'</td>'        +'<td>'+escapeHtml(t.cliente||'\u2014')+'</td>'        +'<td>'+(STATUS_L[t.status]||t.status)+'</td>'        +'<td>'+(t.prazo?fmtDataBR(t.prazo):'\u2014')+'</td>'        +'<td>'+escapeHtml(t.responsavel||'\u2014')+'</td>'      +'</tr>';
    }).join('');
    const win = window.open('','_blank');
    if(!win){ showToast('Permita popups para gerar PDF'); return; }
    win.document.write('<!DOCTYPE html><html><head><meta charset="utf-8">'      +'<title>Relat\u00f3rio de Tarefas \u2014 Clarissa Oliveira Advogada</title>'      +'<style>'        +'body{font-family:Arial,sans-serif;font-size:12px;color:#1a0f0f;padding:32px;max-width:900px;margin:0 auto}'        +'h1{font-size:18px;color:#6b1416;border-bottom:2px solid #6b1416;padding-bottom:8px;margin-bottom:4px}'        +'.sub{font-size:11px;color:#555;margin-bottom:20px}'        +'table{width:100%;border-collapse:collapse}'        +'th{background:#6b1416;color:#fff;padding:8px 10px;text-align:left;font-size:11px}'        +'td{padding:7px 10px;border-bottom:1px solid #e5e0d8}'        +'tr:nth-child(even) td{background:#faf8f5}'        +'.footer{margin-top:24px;font-size:10px;color:#888;border-top:1px solid #e5e0d8;padding-top:10px}'        +'@media print{.no-print{display:none}body{padding:12px}}'      +'</style></head><body>'      +'<h1>\ud83d\udccb Relat\u00f3rio de Tarefas</h1>'      +'<div class="sub">Gerado em '+fmtDataBR(hoje)+(ini||fim?' \u00b7 Per\u00edodo: '+(ini?fmtDataBR(ini):'in\u00edcio')+' a '+(fim?fmtDataBR(fim):'hoje'):'')+'</div>'      +'<table>'        +'<thead><tr>'          +'<th>T\u00edtulo</th><th>Cliente</th><th>Status</th><th>Prazo</th><th>Respons\u00e1vel</th>'        +'</tr></thead>'        +'<tbody>'+linhas+'</tbody>'      +'</table>'      +(lista.length?'':'<p style="color:#888;font-style:italic">Nenhuma tarefa encontrada.</p>')      +'<div class="footer">CO Advocacia \u00b7 '+fmtDataBR(hoje)+'</div>'      +'</body></html>');
    win.document.close();
    setTimeout(function(){ win.print(); }, 600);
  }, '\u2b07 Gerar PDF');
}
function _setFiltroTipo(v, menu){ _agFiltroTipo=v; menu?.remove(); renderCal(); renderSem(); renderAgLista(); }

function _setFiltroSit(v, menu){ _agFiltroSit=v; menu?.remove(); renderCal(); renderSem(); renderAgLista(); }


// ═══════════════════════════════════════════════════════
// AGENDA v3 — PADRÃO FINANCEIRO
// ═══════════════════════════════════════════════════════
let _agView   = 'cal';
let _calDate  = new Date();
let _agFiltroTipo = 'todos';
let _agFiltroSit  = 'todos';

function calVoltarHoje(){ _calDate = new Date(); _render_agenda_all(); }

function calNavMes(d){
  if(_agView==='sem') _calDate.setDate(_calDate.getDate()+(d*7));
  else _calDate.setMonth(_calDate.getMonth()+d);
  _render_agenda_all();
}

function _atualizarTituloMes(){
  const el = document.getElementById('ag-cal-titulo'); if(!el) return;
  if(_agView==='sem'){
    const ini = new Date(_calDate); ini.setDate(ini.getDate()-ini.getDay());
    const fim = new Date(ini); fim.setDate(fim.getDate()+6);
    el.textContent = ini.toLocaleDateString('pt-BR',{day:'2-digit',month:'short'})+
      ' – '+fim.toLocaleDateString('pt-BR',{day:'2-digit',month:'short',year:'numeric'});
  } else {
    const s = _calDate.toLocaleDateString('pt-BR',{month:'long',year:'numeric'});
    el.textContent = s.charAt(0).toUpperCase()+s.slice(1);
  }
}

function setAgView(v,btn){
  _agView = v;
  document.querySelectorAll('.fin-tab[id^="ag-vt"]').forEach(b=>b.classList.remove('on'));
  if(btn) btn.classList.add('on');
  document.getElementById('ag-cal-wrap').style.display  = v==='cal'   ? 'block':'none';
  document.getElementById('ag-sem-wrap').style.display  = v==='sem'   ? 'block':'none';
  document.getElementById('agbody').style.display       = v==='lista' ? 'block':'none';
  const diawrap = document.getElementById('ag-dia-wrap');
  if(diawrap) diawrap.style.display = v==='dia' ? 'block':'none';
  _render_agenda_all();
}
function setAgViewSem(btn){ setAgView('sem',btn); }

function _render_agenda_all(){
  _atualizarTituloMes();
  _atualizarStats();
  if(_agView==='cal')   renderCal();
  else if(_agView==='sem')  renderSem();
  else if(_agView==='dia')  renderAgDia();
  else renderAgLista();
}

function _filtrarEvt(todos){
  const hoje = getTodayKey();
  return todos.filter(p=>{
    if(_agFiltroTipo!=='todos' && agTipo(p)!==_agFiltroTipo) return false;
    if(_agFiltroSit==='fut')  return (p.dt_fim||p.dt_raw||'')>=hoje && !p.realizado;
    if(_agFiltroSit==='pend') return (p.dt_fim||p.dt_raw||'')<hoje  && !p.realizado;
    if(_agFiltroSit==='real') return !!p.realizado;
    return true;
  });
}

function _atualizarStats(){
  const hoje   = getTodayKey();
  const todos  = allPendCached();
  const em7    = new Date(); em7.setDate(em7.getDate()+7);
  const em7str = em7.toISOString().slice(0,10);
  const mesFim = (()=>{ const d=new Date(hoje.slice(0,7)+'-01'); d.setMonth(d.getMonth()+1); d.setDate(0); return d.toISOString().slice(0,10); })();
  const s = (id,v) => { const el=document.getElementById(id); if(el) el.textContent=v; };
  s('as1', todos.filter(p=>!p.realizado&&(eventoNoDia(p,hoje)||(p.dt_raw>=hoje&&p.dt_raw<=em7str))).length);
  s('as2', todos.filter(p=>!p.realizado&&(p.dt_fim||p.dt_raw||'')>=hoje&&p.dt_raw<=mesFim).length);
  s('as3', todos.filter(p=>!p.realizado&&(p.dt_fim||p.dt_raw||'')>=hoje).length);
  s('as4', todos.filter(p=>!p.realizado&&(p.dt_fim||p.dt_raw||'')<hoje).length);
}

function renderCal(){
  const grid = document.getElementById('ag-cal-grid'); if(!grid) return;
  const hoje = getTodayKey();
  const ano  = _calDate.getFullYear(), mes = _calDate.getMonth();
  const todos = _filtrarEvt(allPendCached());
  const primeiroDia = new Date(ano,mes,1).getDay();
  const diasNoMes   = new Date(ano,mes+1,0).getDate();

  const _tagCls = (p) => {
    const t = agTipo(p);
    if(p.realizado) return 'ag2-tag ag2-tag-'+t+' ag2-tag-done';
    if(!p.realizado&&(p.dt_fim||p.dt_raw||'')<hoje) return 'ag2-tag ag2-tag-'+t+' ag2-tag-pend';
    return 'ag2-tag ag2-tag-'+t;
  };

  let out = '';
  for(let i=0;i<primeiroDia;i++) out+=`<div class="ag2-cel ag2-vazio"></div>`;
  for(let d=1;d<=diasNoMes;d++){
    const dt    = `${ano}-${String(mes+1).padStart(2,'0')}-${String(d).padStart(2,'0')}`;
    const evts  = todos.filter(p=>eventoNoDia(p, dt));
    const hoje_ = dt===hoje;
    const fds   = [0,6].includes(new Date(dt+'T12:00').getDay());
    out += `<div class="ag2-cel${hoje_?' ag2-hoje':''}${fds?' ag2-fds':''}">
      <div class="ag2-dia-num">${d}</div>
      ${evts.slice(0,3).map(e=>`<span class="${_tagCls(e)}"
        title="${e.cliente?e.cliente+' — ':''} ${e.tipo_compromisso||e.titulo||''}"
        onclick="calEvtClick('${e.id||e.id_agenda||''}')"
      >${(e.tipo_compromisso||e.titulo||'Compromisso').slice(0,20)}</span>`).join('')}
      ${evts.length>3?`<div class="ag2-cel-mais">+${evts.length-3} mais</div>`:''}
    </div>`;
  }
  grid.innerHTML = out;
}

function renderSem(){
  const grid = document.getElementById('ag-sem-grid'); if(!grid) return;
  const hoje = getTodayKey();
  const todos = _filtrarEvt(allPendCached());
  const ini = new Date(_calDate); ini.setDate(ini.getDate()-ini.getDay());
  let out = '';
  for(let i=0;i<7;i++){
    const d  = new Date(ini); d.setDate(ini.getDate()+i);
    const dt = d.toISOString().slice(0,10);
    const evts = todos.filter(p=>eventoNoDia(p, dt));
    const fds  = [0,6].includes(d.getDay());
    out += `<div class="ag2-sem-col${dt===hoje?' ag2-hoje':''}${fds?' ag2-fds':''}">
      <div class="ag2-sem-header">${d.toLocaleDateString('pt-BR',{weekday:'short',day:'2-digit',month:'2-digit'})}</div>
      ${evts.map(e=>{const _d=eventoDuracao(e),_dx=_d>1?eventoDiaX(e,dt):null;return`<div class="ag2-sem-evt${_d>1?' ag2-sem-range':''}" onclick="calEvtClick('${e.id||e.id_agenda||''}')">
        <div class="ag2-sem-titulo">${e.tipo_compromisso||e.titulo||'Compromisso'}${_dx?` <span style="font-size:9px;opacity:.7">(${_dx.x}/${_dx.total})</span>`:''}</div>
        ${e.cliente?`<div class="ag2-sem-cli">${e.cliente}</div>`:''}
      </div>`}).join('')}
      ${!evts.length?`<div style="font-size:10px;color:var(--mu);opacity:.3;text-align:center;margin-top:12px">—</div>`:''}
    </div>`;
  }
  grid.innerHTML = out;
}

function renderAgDia(){
  const el = document.getElementById('ag-dia-wrap');
  if(!el) return;

  const dt = _calDate.toISOString().slice(0,10);
  const hoje = getTodayKey();
  const MA   = ['Jan','Fev','Mar','Abr','Mai','Jun','Jul','Ago','Set','Out','Nov','Dez'];
  const dObj = new Date(dt+'T12:00');
  const diasNm = ['Domingo','Segunda','Terça','Quarta','Quinta','Sexta','Sábado'];
  const isHoje = dt === hoje;

  const evts = _filtrarEvt(allPendCached()).filter(p => eventoNoDia(p, dt))
    .sort((a,b)=>(a.inicio||a.dt_raw||'').localeCompare(b.inicio||b.dt_raw||''));

  const COR = {audiencia:'#7c3aed',prazo:'var(--vinho)',compromisso:'var(--vinho)',tarefa:'var(--ouro)',reuniao:'#0ea5e9',outro:'var(--mu)'};

  const navBtn = (dir, label) =>
    `<button onclick="agDiaNav(${dir})" style="background:#252525;border:1px solid #444;color:#9E9E9E;
      padding:5px 10px;border-radius:5px;cursor:pointer;font-size:11px;font-family:Inter,DM Sans,sans-serif">${label}</button>`;

  const header = `
    <div style="display:flex;align-items:center;gap:10px;margin-bottom:14px;flex-wrap:wrap">
      ${navBtn(-1,'← Anterior')}
      <div style="flex:1;text-align:center">
        <div style="font-size:16px;font-weight:700;color:${isHoje?'var(--ouro)':'var(--tx)'}">
          ${isHoje?'Hoje — ':''}${diasNm[dObj.getDay()]}, ${dObj.getDate()} de ${MA[dObj.getMonth()]} de ${dObj.getFullYear()}
        </div>
        ${!isHoje?`<button onclick="agDiaHoje()" style="background:none;border:none;color:var(--ouro);font-size:11px;cursor:pointer;font-family:Inter,DM Sans,sans-serif">Ir para hoje</button>`:''}
      </div>
      ${navBtn(1,'Próximo →')}
    </div>`;

  const realizados = evts.filter(p=>p.realizado);
  const pendentes  = evts.filter(p=>!p.realizado);

  const rowEvt = p => {
    const t   = agTipo(p);
    const cor = COR[t]||COR.outro;
    const hr  = p.inicio ? p.inicio.slice(11,16) : '';
    const dur = eventoDuracao(p);
    const dx  = dur > 1 ? eventoDiaX(p, dt) : null;
    const venc = !p.realizado && (p.dt_raw||'') < hoje && (p.dt_fim||p.dt_raw||'') < hoje;
    return `
      <div style="display:flex;align-items:center;gap:10px;padding:9px 12px;
                  background:${venc?'rgba(201,72,74,.08)':p.realizado?'rgba(76,175,125,.05)':'var(--sf3)'};
                  border:1px solid ${venc?'rgba(201,72,74,.3)':p.realizado?'rgba(76,175,125,.2)':'var(--bd)'};
                  border-left:3px solid ${p.realizado?'#4caf7d':venc?'var(--red)':cor};
                  border-radius:7px;margin-bottom:6px;cursor:pointer"
           onclick="calEvtClick('${p.id||p.id_agenda||''}')">
        <div style="min-width:34px;text-align:center;font-size:11px;font-weight:700;color:${p.realizado?'#4caf7d':cor}">
          ${dx?`${dx.x}/${dx.total}`:hr||'—'}
        </div>
        <div style="flex:1">
          <div style="font-size:13px;font-weight:600;color:var(--tx);${p.realizado?'text-decoration:line-through;opacity:.6':''}">${p.titulo||p.tipo_compromisso||'Compromisso'}</div>
          ${p.cliente?`<div style="font-size:11px;color:var(--mu)">${p.cliente}${dur>1?` · Prazo ${fmtDataBR(p.dt_raw)} a ${fmtDataBR(p.dt_fim)}`:`${hr?' · '+hr:''}`}</div>`:''}
          ${p.obs?`<div style="font-size:10px;color:var(--mu);margin-top:2px;font-style:italic">${p.obs}</div>`:''}
        </div>
        <span style="font-size:9px;font-weight:700;padding:2px 7px;border-radius:4px;
          background:${p.realizado?'rgba(76,175,125,.15)':venc?'rgba(201,72,74,.15)':'rgba(255,255,255,.05)'};
          color:${p.realizado?'#4caf7d':venc?'var(--red)':'var(--mu)'}">
          ${p.realizado?'FEITO':venc?'VENCIDO':t.toUpperCase()}
        </span>
      </div>`;
  };

  const body = pendentes.length || realizados.length
    ? (pendentes.length ? `
        <div style="font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.07em;color:var(--mu);margin-bottom:8px">
          ${pendentes.length} compromisso${pendentes.length!==1?'s':''}
        </div>
        ${pendentes.map(rowEvt).join('')}`
        : '')
      + (realizados.length ? `
        <div style="font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.07em;color:var(--mu);margin:12px 0 8px;opacity:.6">
          Realizados (${realizados.length})
        </div>
        ${realizados.map(rowEvt).join('')}` : '')
    : `<div style="text-align:center;padding:40px 20px;color:var(--mu)">
        <div style="font-size:32px;margin-bottom:8px">🗓</div>
        <div style="font-size:13px">Nenhum compromisso neste dia</div>
      </div>`;

  el.innerHTML = header + body;
}

function agDiaNav(dir){
  _calDate.setDate(_calDate.getDate() + dir);
  renderAgDia();
}
function agDiaHoje(){
  _calDate = new Date();
  renderAgDia();
}


function renderAgLista(){
  const el = document.getElementById('agbody'); if(!el) return;
  const hoje = getTodayKey();
  const todos = _filtrarEvt(allPendCached());
  // Ativos: começou antes de hoje mas ainda não terminou (em andamento), ou começa hoje/futuro
  const emAndamento = todos.filter(p=>!p.realizado
    && (p.dt_raw||'')<hoje
    && (p.dt_fim||p.dt_raw||'')>=hoje
  ).sort((a,b)=>a.dt_raw.localeCompare(b.dt_raw));
  const passados  = todos.filter(p=>!p.realizado
    && (p.dt_fim||p.dt_raw||'')<hoje
  ).sort((a,b)=>b.dt_raw.localeCompare(a.dt_raw));
  const futuros   = todos.filter(p=>!p.realizado&&(p.dt_raw||'')>=hoje).sort((a,b)=>a.dt_raw.localeCompare(b.dt_raw));
  const realizados= todos.filter(p=>p.realizado).sort((a,b)=>b.dt_raw.localeCompare(a.dt_raw)).slice(0,40);

  const COR = {audiencia:'#7c3aed',prazo:'var(--vinho)',compromisso:'var(--vinho)',
               tarefa:'var(--ouro)',reuniao:'#0ea5e9',outro:'var(--mu)'};
  const fmtDt = p => fmtDataBR(p.dt_raw);
  const diasL = dt => {
    const d = Math.ceil((new Date(dt)-new Date(hoje))/86400000);
    if(d<0)  return `<span style="color:var(--red)">vencido ${-d}d</span>`;
    if(d===0) return `<span style="color:#f59e0b;font-weight:700">HOJE</span>`;
    if(d===1) return `<span style="color:#f59e0b">amanhã</span>`;
    return `<span>em ${d}d</span>`;
  };
  const head = `<div class="ag2-list-row fin-row-head">
    <div>Data</div><div>Compromisso</div><div>Cliente</div><div>Tipo</div><div style="text-align:right">Prazo</div>
  </div>`;
  const row = p => {
    const t   = agTipo(p);
    const cor = COR[t]||COR.outro;
    const venc= !p.realizado&&(p.dt_fim||p.dt_raw||'')<hoje;
    return `<div class="ag2-list-row${venc?' ag2-urg':''}" onclick="calEvtClick('${p.id||p.id_agenda||''}')">
      <div class="ag2-list-data">${fmtDt(p)}</div>
      <div class="ag2-list-titulo">${p.tipo_compromisso||p.titulo||'Compromisso'}</div>
      <div class="ag2-list-cli">${p.cliente||'—'}</div>
      <div><span class="ag2-list-badge" style="background:color-mix(in srgb,${cor} 15%,transparent);color:${cor}">${t}</span></div>
      <div class="ag2-list-dias">${p.realizado?'<span style="color:#4ade80">✓ Realizado</span>':diasL(p.dt_raw)}</div>
    </div>`;
  };

  let out = '';
  if(emAndamento.length) out+=`<div class="ag2-list-section fin-card" style="padding:0 12px 8px;border-left:3px solid var(--ouro)">
    <div class="ag2-list-head" style="color:var(--ouro)">⏳ Em andamento (${emAndamento.length})</div>${head}${emAndamento.map(row).join('')}</div>`;
  if(passados.length) out+=`<div class="ag2-list-section fin-card" style="padding:0 12px 8px;margin-top:12px">
    <div class="ag2-list-head" style="color:var(--red)">⚠ Vencidos (${passados.length})</div>${head}${passados.map(row).join('')}</div>`;
  if(futuros.length) out+=`<div class="ag2-list-section fin-card" style="padding:0 12px 8px;margin-top:12px">
    <div class="ag2-list-head">Próximos (${futuros.length})</div>${head}${futuros.map(row).join('')}</div>`;
  if(realizados.length) out+=`<div class="ag2-list-section fin-card" style="padding:0 12px 8px;margin-top:12px;opacity:.7">
    <div class="ag2-list-head">Realizados (${realizados.length})</div>${head}${realizados.map(row).join('')}</div>`;
  if(!out) out=`<div style="text-align:center;padding:48px;color:var(--mu);font-style:italic">Nenhum compromisso encontrado.</div>`;
  el.innerHTML = out;
}

function renderAg(){ _render_agenda_all(); }

function calEvtClick(id){
  if(!id) return;
  const ev = allPendCached().find(p=>String(p.id||p.id_agenda)===String(id));
  if(!ev) return;

  // Se tem processo vinculado, também oferece navegar para a pasta
  const c = ev.id_processo ? findClientById(ev.id_processo) : null;
  const tipo = agTipo(ev);
  const COR = {audiencia:'#a78bfa',prazo:'#f87676',compromisso:'#f87676',tarefa:'var(--ouro)',reuniao:'#60a5fa',outro:'var(--mu)'};
  const cor = COR[tipo]||COR.outro;
  const hoje = getTodayKey();
  const venc = !ev.realizado && (ev.dt_fim||ev.dt_raw||'') < hoje;
  const isLocal = !!(localAg||[]).find(a=>String(a.id||a.id_agenda)===String(id));

  const body = `
    <div style="border-left:3px solid ${cor};padding:10px 14px;background:var(--sf3);border-radius:0 8px 8px 0;margin-bottom:14px">
      <div style="font-size:15px;font-weight:700;color:var(--tx);margin-bottom:4px">${ev.tipo_compromisso||ev.titulo||'Compromisso'}</div>
      ${ev.cliente?`<div style="font-size:12px;color:var(--mu)">👤 ${ev.cliente}</div>`:''}
      <div style="font-size:12px;color:var(--mu);margin-top:4px">📅 ${fmtDataBR(ev.dt_raw)}${ev.dt_fim&&ev.dt_fim!==ev.dt_raw?' → '+fmtDataBR(ev.dt_fim):''}${ev.inicio&&ev.inicio.includes('T')?' · '+ev.inicio.slice(11,16):''}</div>
      ${ev.obs?`<div style="font-size:11px;color:var(--mu);margin-top:4px;font-style:italic">📎 ${ev.obs}</div>`:''}
      ${venc?`<div style="font-size:11px;color:var(--red);margin-top:6px;font-weight:700">⚠ Prazo vencido</div>`:''}
      ${ev.realizado?`<div style="font-size:11px;color:#4ade80;margin-top:6px;font-weight:700">✓ Realizado</div>`:''}
    </div>
    <div style="display:flex;flex-direction:column;gap:8px">
      ${!ev.realizado?`<button onclick="calEvtConcluir('${id}');fecharModal()" style="padding:8px 14px;border-radius:6px;border:1px solid #1a4a2e;background:rgba(74,222,128,.1);color:#4ade80;font-size:12px;font-weight:600;cursor:pointer;text-align:left">✓ Marcar como realizado</button>`:''}
      ${isLocal?`<button onclick="fecharModal();editarAgCliente('${id}',${ev.id_processo||0})" style="padding:8px 14px;border-radius:6px;border:1px solid var(--bd);background:var(--sf3);color:var(--mu);font-size:12px;font-weight:600;cursor:pointer;text-align:left">✏ Editar compromisso</button>`:''}
      ${c?`<button onclick="fecharModal();openC(${c.id})" style="padding:8px 14px;border-radius:6px;border:1px solid var(--bd-o);background:rgba(212,175,55,.08);color:var(--ouro);font-size:12px;font-weight:600;cursor:pointer;text-align:left">📁 Abrir pasta: ${c.cliente}</button>`:''}
      ${isLocal?`<button onclick="calEvtExcluir('${id}',${ev.id_processo||0})" style="padding:8px 14px;border-radius:6px;border:1px solid #5a1a1a;background:rgba(201,72,74,.08);color:#f87676;font-size:12px;font-weight:600;cursor:pointer;text-align:left">🗑 Excluir</button>`:''}
    </div>`;

  abrirModal(tipo.charAt(0).toUpperCase()+tipo.slice(1), body, null, null);
  // Esconder botão salvar padrão
  setTimeout(()=>{ const b=document.getElementById('modal-save'); if(b) b.style.display='none'; const bc=document.querySelector('.mbtn-cancel'); if(bc) bc.textContent='Fechar'; }, 30);
}

function calEvtConcluir(id){
  const raw = String(id);
  const idx = (localAg||[]).findIndex(a=>String(a.id||a.id_agenda)===raw);
  if(idx>=0){
    localAg[idx].realizado=true; localAg[idx].cumprido='Sim';
  } else {
    const orig = (PEND||[]).find(p=>String(p.id||p.id_agenda)===raw);
    if(orig){ if(!localAg) localAg=[]; localAg.push({...orig,id:raw,id_agenda:raw,realizado:true,cumprido:'Sim',_origem_pend:raw}); }
  }
  sbSet('co_ag',localAg); invalidarAllPend(); marcarAlterado();
  _render_agenda_all(); atualizarStats();
  showToast('Compromisso marcado como realizado ✓');
}

function calEvtExcluir(id, cid){
  const raw = String(id);
  const item = (localAg||[]).find(a=>String(a.id||a.id_agenda)===raw);
  const titulo = item?.titulo||item?.tipo_compromisso||'este compromisso';
  fecharModal();
  setTimeout(()=>{
    abrirModal('Excluir compromisso',
      `<div style="font-size:13px;color:var(--mu);line-height:1.6">
        Excluir <strong style="color:var(--tx)">"${titulo}"</strong>?<br>
        <span style="font-size:11px">Esta ação não pode ser desfeita.</span>
      </div>`,
      ()=>{
        _tombstoneAdd('co_ag', raw);
        _tombstoneAdd('co_localAg', raw);
        localAg=(localAg||[]).filter(a=>String(a.id||a.id_agenda)!==raw);
        sbSet('co_ag',localAg); invalidarAllPend(); marcarAlterado(); fecharModal();
        if(cid){ const el=document.getElementById('tp-agenda-proc-'+cid); if(el) el.innerHTML=renderAgendaProc(cid); }
        _render_agenda_all(); atualizarStats();
        showToast('Compromisso excluído');
      }, 'Excluir'
    );
    setTimeout(()=>{ const b=document.getElementById('modal-save'); if(b){b.style.background='var(--red)';b.textContent='Confirmar exclusão';} },50);
  },200);
}

function abrirFiltroTipo(btn){
  const itens = [['todos','Todos os tipos'],['audiencia','Audiência'],
    ['prazo','Compromisso/Prazo'],['tarefa','Tarefa'],['reuniao','Reunião'],['outro','Outros']];
  const m = document.createElement('div'); m.className='cal-dropdown';
  m.innerHTML = itens.map(([v,l])=>`<div class="cal-dd-item${_agFiltroTipo===v?' on':''}"
    onclick="_agFiltroTipo='${v}';this.parentNode.remove();_render_agenda_all()">${l}</div>`).join('');
  _showDropdown(m,btn);
}
function abrirFiltroSit(btn){
  const itens = [['todos','Todos'],['fut','Futuros'],['pend','Pendentes/Passados'],['real','Realizados']];
  const m = document.createElement('div'); m.className='cal-dropdown';
  m.innerHTML = itens.map(([v,l])=>`<div class="cal-dd-item${_agFiltroSit===v?' on':''}"
    onclick="_agFiltroSit='${v}';this.parentNode.remove();_render_agenda_all()">${l}</div>`).join('');
  _showDropdown(m,btn);
}
function _showDropdown(m,btn){
  document.querySelectorAll('.cal-dropdown').forEach(x=>x.remove());
  document.body.appendChild(m);
  const r=btn.getBoundingClientRect();
  m.style.top=r.bottom+4+'px'; m.style.left=r.left+'px';
  setTimeout(()=>document.addEventListener('click',()=>m.remove(),{once:true}),10);
}

async function init(){
  setTimeout(initSidebar,50);
  await carregarDados(); // carrega dados embutidos via fetch — precisa de await agora
  atualizarStats();
  renderHomeAlerts();
  renderFinDash();
  renderChecklist();
  renderHomeWeek();
  doSearch();
  setTimeout(()=>{ renderCal(); _atualizarTituloMes(); _atualizarStats(); }, 150);
  _auditInit();
  // Inicializa Supabase e, se tiver co_clientes lá, sobrescreve o CLIENTS embutido
  setTimeout(async ()=>{
    await sbInit();
    // Após sbInit (que já carrega outros dados), tenta carregar CLIENTS do Supabase
    const sbClientes = await sbCarregarClientes();
    if(sbClientes){
      // CLIENTS atualizado do Supabase — re-renderizar
      montarClientesAgrupados();
      doSearch();
      atualizarStats();
    } else {
      // Primeira vez: migrar dados embutidos para Supabase
      sbSalvarClientes();
      showToast('Clientes migrados para nuvem ✓');
    }
  }, 600);
  setTimeout(()=>audit('login','Sessão iniciada','sistema'),1200);
}


// Combina compromissos do Projuris + locais
// ── Cache de allPendCached() — invalidado por mudanças em PEND/localAg ──
var _allPendCache = null;
var _allPendVer = 0;
function allPendCached(){
  var ver = (PEND||[]).length * 1000 + (localAg||[]).length;
  if(_allPendCache && _allPendVer===ver) return _allPendCache;
  _allPendCache = allPend();
  _allPendVer = ver;
  return _allPendCache;
}
function invalidarAllPend(){ _allPendCache=null; }

function allPend(){
  // Build localAg index first — both by id and by _origem_pend
  const localIdx  = new Map();
  const origemIdx = new Map();
  (localAg||[]).forEach(function(p){
    var k = String(p.id||p.id_agenda||'');
    if(k) localIdx.set(k, p);
    if(p._origem_pend) origemIdx.set(String(p._origem_pend), p);
  });

  // Deduplicate localAg itself (user may have clicked concluir twice)
  var localDedup = new Map();
  (localAg||[]).forEach(function(p){
    var k = p._origem_pend
      ? 'orig_'+String(p._origem_pend)
      : String(p.id||p.id_agenda||Math.random());
    if(!localDedup.has(k)) localDedup.set(k, p);
    else if(p.realizado) localDedup.set(k, p); // prefer realized version
  });
  var localClean = Array.from(localDedup.values());

  // Merge PEND + clean localAg
  var seen = new Map();
  // PEND first
  (PEND||[]).forEach(function(p){
    var k = String(p.id||p.id_agenda||'');
    if(!k) return;
    // Skip if localAg has a copy (by id or by _origem_pend)
    if(localIdx.has(k) || origemIdx.has(k)) return;
    seen.set(k, p);
  });
  // localAg (deduped) second — overwrites any matching PEND
  localClean.forEach(function(p){
    var k = String(p.id||p.id_agenda||'');
    if(!k) seen.set('_r_'+Math.random(), p);
    else seen.set(k, p);
  });
  // Filter out permanently excluded clients
  var EXCL_CLI = /amanda.?fabiane/i;
  return Array.from(seen.values()).filter(function(p){
    return !EXCL_CLI.test(p.cliente||'');
  });
}

// ── Evento cobre um determinado dia? ──
// Retorna true se o dia 'dt' (YYYY-MM-DD) está dentro do intervalo do evento
function eventoNoDia(p, dt){
  const ini = (p.dt_raw||p.inicio||'').slice(0,10);
  const fim = (p.dt_fim||p.fim||ini).slice(0,10);
  return dt >= ini && dt <= fim;
}

// Quantos dias de duração tem o evento (1 = evento de um dia)
function eventoDuracao(p){
  const ini = (p.dt_raw||'').slice(0,10);
  const fim = (p.dt_fim||ini).slice(0,10);
  if(!ini||!fim||fim<=ini) return 1;
  return Math.round((new Date(fim)-new Date(ini))/86400000)+1;
}

// "Dia X de Y" — qual dia do intervalo é 'dt'
function eventoDiaX(p, dt){
  const ini = (p.dt_raw||'').slice(0,10);
  const x = Math.round((new Date(dt)-new Date(ini))/86400000)+1;
  const total = eventoDuracao(p);
  return {x, total};
}

function goView(v,btn){
  if(typeof _gNavHistory!=='undefined'&&typeof navPush==='function') navPush(navCapture());
  document.querySelectorAll('.view').forEach(x=>x.classList.remove('on'));
  document.querySelectorAll('.hnav-btn').forEach(x=>x.classList.remove('on'));
  // Sidebar vertical — reset all, then highlight active
  document.querySelectorAll('.vsb-btn').forEach(function(b){
    b.style.background='transparent'; b.classList.remove('vsb-on');
  });
  document.getElementById(v).classList.add('on');
  if(btn){ btn.classList.add('on'); }
  // Sidebar: highlight matching vsb-btn by title
  var viewToTitle={'vc':'Dashboard','vcl':'Clientes','va':'Agenda','vf':'Financeiro',
    'vk':'Tarefas','vini':'Iniciais','vct':'Contatos','vcalc':'Prazos','vaudit':'Auditoria'};
  var activeTitle=viewToTitle[v];
  if(activeTitle){
    document.querySelectorAll('.vsb-btn').forEach(function(b){
      if(b.getAttribute('title')===activeTitle){
        b.style.background='#2a2a2a'; b.classList.add('vsb-on');
      }
    });
  }
  // Also mark the hidden nav button
  var navMap={'vc':'nav-home','vcl':'nav-clientes','va':'nav-agenda','vf':'nav-fin',
    'vk':'nav-tasks','vct':'nav-contatos','vcalc':'nav-calc','vaudit':'nav-audit'};
  var navId=navMap[v];
  if(navId){ var nb=document.getElementById(navId); if(nb) nb.classList.add('on'); }
  if(v==='vc'){
    if(typeof renderHomeAlerts==='function')   try{ renderHomeAlerts(); }catch(e){}
    if(typeof renderChecklist==='function')    try{ renderChecklist(); }catch(e){}
    if(typeof renderHomeWeek==='function')     try{ renderHomeWeek(); }catch(e){}
    if(typeof renderFinDash==='function')      try{ renderFinDash(); }catch(e){}
    if(typeof renderHomeIniciais==='function') try{ renderHomeIniciais(); }catch(e){}
    if(typeof dshRenderMin==='function')       try{ dshRenderMin(); }catch(e){}
  }
  if(v==='vcl'){
    // Restaurar sidebar de clientes se estava escondida
    var vclWrap=document.querySelector('.vcl-wrap');
    if(vclWrap) vclWrap.classList.remove('fin-hidden');
    var fichaVcl=document.getElementById('ficha-vcl');
    if(fichaVcl&&!AC){ fichaVcl.classList.remove('on'); fichaVcl.innerHTML=''; var emp2=document.getElementById('emp2'); if(emp2) emp2.style.display='flex'; }
    doSearch();
  }
  if(v==='vf'){ renderFinGlobal(); var baj=document.getElementById('btn-ajuda-fin'); if(baj) baj.style.display='flex'; }
  else { var baj2=document.getElementById('btn-ajuda-fin'); if(baj2) baj2.style.display='none'; }
  if(v==='vcalc'){ calcRender(); }
  if(v==='vaudit'){ auditRender(); }
  if(v==='va'){
    // Restaurar view ativa (não resetar sempre para 'cal')
    _render_agenda_all();
    // Garantir que a aba correta está visível
    setAgView(_agView||'cal', document.getElementById('ag-vt-'+(_agView||'cal')));
  }
}

function atualizarBadgeEnc(){
  const encIds=new Set([...Object.keys(encerrados).map(Number),...Object.keys(encerrados)]);
  // Contar grupos com algum processo encerrado
  const nEnc=CLIENTES_AGRUPADOS.filter(g=>g.processos&&g.processos.some(p=>encIds.has(p.id))).length;
  const el=document.getElementById('enc-count');
  if(el) el.textContent=nEnc;
  // Dormentes: grupos com algum ativo e +1000 dias
  const nd=CLIENTES_AGRUPADOS.filter(g=>g.processos&&g.processos.some(p=>!encIds.has(p.id)&&p.ultima_mov_dias>=1000)).length;
  const ed=document.getElementById('dorm-count');
  if(ed) ed.textContent=nd;
}


function setFiltro(btn, nome){
  document.querySelectorAll('.fb').forEach(b=>b.classList.remove('on'));
  if(btn) btn.classList.add('on');
  filtro = nome;
  doSearch();
}

// ── Cache de encIds — evita recriar Set a cada busca ──
var _encIdsCache = null;
var _encIdsVer = 0;
function getEncIds(){
  var ver = Object.keys(encerrados||{}).length;
  if(_encIdsCache && _encIdsVer===ver) return _encIdsCache;
  _encIdsCache = new Set([...Object.keys(encerrados).map(Number),...Object.keys(encerrados)]);
  _encIdsVer = ver;
  return _encIdsCache;
}
function isEncerrado(id){ return getEncIds().has(id)||getEncIds().has(String(id)); }
// ── Painel resumo na área vazia de clientes ──
function renderVclEmpty(){
  var el = document.getElementById('vcl-empty-dashboard');
  if(!el) return;
  var fV = function(v){return 'R$ '+Math.abs(v||0).toLocaleString('pt-BR',{minimumFractionDigits:2,maximumFractionDigits:2});};
  var hoje = getTodayKey();
  var encIds = getEncIds();

  // Stats rápidos — contar CLIENTES (agrupados), não processos
  var totalAtivos = 0;
  if(typeof CLIENTES_AGRUPADOS!=='undefined' && CLIENTES_AGRUPADOS){
    totalAtivos = CLIENTES_AGRUPADOS.filter(function(grp){
      return grp.processos && grp.processos.some(function(p){ return !encIds.has(p.id); });
    }).length;
  } else {
    var _n = {};
    (CLIENTS||[]).forEach(function(c){ if(!encIds.has(c.id)&&c.tipo!=='consulta') _n[(c.cliente||'').toLowerCase()]=1; });
    totalAtivos = Object.keys(_n).length;
  }

  var _ap = allPendCached();
  var prazosHoje=0, prazos7d=0, audiencias7d=0;
  var em7 = new Date(HOJE); em7.setDate(em7.getDate()+7); var em7s=em7.toISOString().slice(0,10);
  _ap.forEach(function(p){
    if(p.realizado) return;
    if(p.dt_raw===hoje) prazosHoje++;
    if(p.dt_raw>=hoje&&p.dt_raw<=em7s){
      var tp=agTipo(p);
      if(tp==='prazo') prazos7d++;
      else if(tp==='audiencia') audiencias7d++;
    }
  });

  // Tarefas pendentes
  var tarefasPend = vkTasks.filter(function(t){ return !isDone(t); }).length;
  var tarefasAtrasadas = vkTasks.filter(function(t){ return !isDone(t)&&t.prazo&&t.prazo<hoje; }).length;

  // Financeiro
  var cons = {saldo:0, totEntrou:0, totHon:0};
  try { cons = _vfConsolidar(hoje.slice(0,7)); } catch(e){}

  // Próximos compromissos
  var prox = _ap.filter(function(p){ return !p.realizado&&p.dt_raw>=hoje&&p.dt_raw<=em7s; })
    .sort(function(a,b){return (a.dt_raw||'').localeCompare(b.dt_raw||'');}).slice(0,5);

  function card(lbl,val,cor){
    return '<div style="padding:10px 12px;background:var(--sf2);border:1px solid var(--bd);border-radius:8px;text-align:center">'
      +'<div style="font-size:20px;font-weight:800;color:'+cor+'">'+val+'</div>'
      +'<div style="font-size:9px;font-weight:700;text-transform:uppercase;color:var(--mu);margin-top:2px">'+lbl+'</div>'
    +'</div>';
  }

  var html = '<div style="text-align:center;margin-bottom:16px">'
    +'<div style="font-size:28px;margin-bottom:4px">\u2696</div>'
    +'<div style="font-size:14px;font-weight:700;color:var(--tx)">Clarissa Oliveira Advocacia</div>'
    +'<div style="font-size:11px;color:var(--mu)">Selecione um cliente ou veja o resumo abaixo</div>'
  +'</div>';

  // KPIs grid
  html += '<div style="display:grid;grid-template-columns:repeat(4,1fr);gap:8px;margin-bottom:14px">'
    +card('Clientes ativos', totalAtivos, 'var(--tx)')
    +card('Tarefas pendentes', tarefasPend, tarefasAtrasadas>0?'#f59e0b':'var(--tx)')
    +card('Prazos 7 dias', prazos7d, prazos7d>0?'#f59e0b':'var(--mu)')
    +card('Audiências 7d', audiencias7d, audiencias7d>0?'#f87676':'var(--mu)')
  +'</div>';

  // Financeiro resumo
  html += '<div style="display:grid;grid-template-columns:repeat(3,1fr);gap:8px;margin-bottom:14px">'
    +card('Entrou no m\u00eas', fV(cons.totEntrou), 'var(--tx)')
    +card('Receita escrit.', fV(cons.totHon), '#4ade80')
    +card('Saldo', fV(cons.saldo), cons.saldo>=0?'#4ade80':'#c9484a')
  +'</div>';

  // Alertas
  if(tarefasAtrasadas>0){
    html += '<div style="background:rgba(245,158,11,.08);border:1px solid rgba(245,158,11,.3);border-radius:6px;padding:8px 12px;margin-bottom:10px;font-size:11px;color:#f59e0b">'
      +'\u26a0 <strong>'+tarefasAtrasadas+' tarefa'+(tarefasAtrasadas>1?'s':'')+' atrasada'+(tarefasAtrasadas>1?'s':'')+'</strong> \u2014 '
      +'<span style="cursor:pointer;text-decoration:underline" onclick="goView(\'vk\',document.getElementById(\'nav-tasks\'));vkRender()">Ver kanban</span>'
    +'</div>';
  }

  // Próximos compromissos
  if(prox.length){
    html += '<div style="font-size:10px;font-weight:700;text-transform:uppercase;color:var(--mu);margin-bottom:6px;letter-spacing:.05em">Pr\u00f3ximos compromissos</div>';
    prox.forEach(function(p){
      var diasAte = Math.ceil((new Date(p.dt_raw)-new Date(hoje))/86400000);
      var diasLbl = diasAte===0?'HOJE':diasAte===1?'Amanh\u00e3':diasAte+'d';
      var corD = diasAte<=1?'#f87676':diasAte<=3?'#f59e0b':'var(--mu)';
      html += '<div style="display:flex;align-items:center;gap:8px;padding:5px 0;border-bottom:1px solid var(--bd)">'
        +'<span style="font-size:10px;font-weight:800;color:'+corD+';min-width:40px">'+diasLbl+'</span>'
        +'<span style="flex:1;font-size:11px;color:var(--tx)">'+escapeHtml(p.titulo||p.tipo_compromisso||'\u2014')+'</span>'
        +'<span style="font-size:9px;color:var(--mu)">'+escapeHtml(p.cliente||'')+'</span>'
      +'</div>';
    });
  }

  el.innerHTML = html;
}

// Versão com debounce para oninput do campo de busca (evita _vfConsolidar a cada tecla)
function doSearchDebounced(){ _debounce('doSearch', doSearch, 200); }

function doSearch(){
  renderVclEmpty(); // Preencher painel vazio com resumo
  const q=document.getElementById('srch').value.toLowerCase();
  const encIds=getEncIds();
  if(filtro==='dormentes'){
    const lista=CLIENTES_AGRUPADOS.filter(grp=>{
      const ativos=grp.processos.filter(p=>!encIds.has(p.id));
      if(!ativos.length) return false;
      const dorm=ativos.some(p=>p.ultima_mov_dias>=1000);
      if(!dorm) return false;
      const nome=(grp.nome||'').toLowerCase();
      return !q||nome.includes(q)||ativos.some(p=>(p.adverso||'').toLowerCase().includes(q));
    }).sort((a,b)=>{
      const ma=Math.max(...a.processos.map(p=>p.ultima_mov_dias||0));
      const mb=Math.max(...b.processos.map(p=>p.ultima_mov_dias||0));
      return mb-ma;
    });
    renderList(lista); return;
  }
  if(filtro==='encerrados'){
    const lista=CLIENTES_AGRUPADOS.filter(grp=>{
      const temEnc=grp.processos.some(p=>encIds.has(p.id));
      if(!temEnc) return false;
      const nome=(grp.nome||'').toLowerCase();
      return !q||nome.includes(q)||grp.processos.some(p=>(p.adverso||'').toLowerCase().includes(q)||(p.numero||'').toLowerCase().includes(q));
    });
    renderList(lista, true); return;
  }
  // Filtro atendimentos (pipeline CRM)
  if(filtro==='consulta'){
    const encIds2 = new Set(Object.keys(encerrados).map(Number));
    // Mostrar clientes que estão no pipeline de atendimentos
    const atendIds = new Set(localAtend.map(a=>String(a.id_cliente)).filter(Boolean));
    // Também incluir clientes com tipo='consulta' na CLIENTS
    const lista = CLIENTES_AGRUPADOS.filter(grp=>{
      const match = grp.processos.some(p=>
        p.tipo==='consulta' || p.status_consulta==='consulta' || atendIds.has(String(p.id))
      );
      if(!match) return false;
      if(!q) return true;
      const nome=(grp.nome||'').toLowerCase();
      return nome.includes(q)||grp.processos.some(p=>(p.adverso||'').toLowerCase().includes(q));
    });
    renderList(lista); return;
  }

  // Filtro consultas (legado)
  if(filtro==='consultas'){
    const consArr = (typeof consLocais!=='undefined'?consLocais:[]);
    const lista = consArr.filter(c=>{
      if(!q) return true;
      return (c.nome||'').toLowerCase().includes(q)||(c.tel||'').includes(q);
    });
    document.getElementById('clist').innerHTML = lista.length===0
      ? `<div style="padding:20px;text-align:center;font-size:12px;color:var(--mu)">Nenhuma consulta.<br><br>Use <strong>＋ Novo → 💬 Nova consulta</strong></div>`
      : lista.map(c=>`
        <div class="citem" onclick="abrirConsulta(${c.id})">
          <div class="ci-nome">${c.nome}</div>
          <div class="ci-sub" style="font-size:10px;color:var(--mu)">${c.tel||''} ${c.area?'· '+c.area:''}</div>
        </div>`).join('');
    return;
  }
  // Filtro normal (área jurídica)
  renderList(CLIENTES_AGRUPADOS.filter(grp=>{
    const ativos=grp.processos.filter(p=>!encIds.has(p.id));
    if(!ativos.length) return false;
    if(filtro!=='todos'&&!ativos.some(p=>p.natureza===filtro)) return false;
    if(!q) return true;
    const nome=(grp.nome||'').toLowerCase();
    return nome.includes(q)||ativos.some(p=>
      (p.adverso||'').toLowerCase().includes(q)||
      (p.numero||'').toLowerCase().includes(q)||
      (p.tel&&p.tel.includes(q))
    );
  }));
}

function encerrarProcesso(cid){
  const c=findClientById(cid);
  if(!c)return;
  // Confirmar
  abrirModal(`Encerrar processo — ${c.cliente}`,
    `<div style="color:var(--mu);font-size:12px;line-height:1.7">
      <p>Tem certeza que deseja marcar este processo como <strong style="color:#f87676">encerrado</strong>?</p>
      <p style="margin-top:8px">O processo sairá da lista de ativos e poderá ser consultado no filtro <strong>🗂 Encerrados</strong>.</p>
      ${mInput('enc-data','Data de encerramento','date',new Date().toISOString().slice(0,10))}
      ${mTextarea('enc-motivo','Motivo / observação (opcional)')}
    </div>`,
    ()=>{
      const data=document.getElementById('enc-data').value;
      const motivo=document.getElementById('enc-motivo').value;
      encerrados[cid]={data, motivo, cliente:c.cliente};
      sbSet('co_encerrados', encerrados);
    marcarAlterado();
      atualizarBadgeEnc();
      fecharModal()
      atualizarStats();
      // Se estava vendo esse cliente, limpar ficha
      if(AC&&AC.id===cid){
        AC=null;
        const _f2=document.getElementById('ficha-vcl'); if(_f2){_f2.classList.remove('on');_f2.innerHTML='';}
        const _e2=document.getElementById('emp2'); if(_e2) _e2.style.display='flex';
      }
      doSearch();
      showToast('Processo encerrado');
    }
  );
  // Mudar texto do botão salvar para vermelho
  setTimeout(()=>{
    const btn=document.getElementById('modal-save');
    if(btn){btn.style.background='var(--red)';btn.textContent='Confirmar encerramento';}
  },50);
}

function reativarProcesso(cid){
  const c=findClientById(cid);
  if(!c)return;
  delete encerrados[cid];
  sbSet('co_encerrados', encerrados);
    marcarAlterado();
  atualizarBadgeEnc();
  doSearch()
      atualizarStats();
  renderFicha(c, AC_PROC);
  showToast('Processo reativado!');
}

// ══ VIEW TOGGLE: cards / tabela ══
var _vclView = localStorage.getItem('co_vclView') || 'cards';

function _vclSetView(mode){
  _vclView = mode;
  localStorage.setItem('co_vclView', mode);
  document.getElementById('vcl-vb-cards')?.classList.toggle('vcl-vb-on', mode==='cards');
  document.getElementById('vcl-vb-table')?.classList.toggle('vcl-vb-on', mode==='table');
  // Tabela precisa de largura total
  var wrap = document.querySelector('.vcl-wrap');
  if(wrap) wrap.classList.toggle('vcl-full', mode==='table');
  doSearch();
}

function _natClass(nat){
  var n = (nat||'').toLowerCase();
  if(n.includes('trabalh')) return 'tbl-nat-trab';
  if(n.includes('previd')) return 'tbl-nat-prev';
  if(n.includes('cív') || n.includes('civel')) return 'tbl-nat-civ';
  if(n.includes('famíl') || n.includes('familia')) return 'tbl-nat-fam';
  return 'tbl-nat-out';
}

function renderListTable(lst, isEncView){
  var el = document.getElementById('clist');
  if(!el) return;
  var encIds = new Set([...Object.keys(encerrados).map(Number),...Object.keys(encerrados)]);

  var html = '<table class="vcl-table"><thead><tr>'
    +'<th style="width:30px"></th>'
    +'<th>Pasta</th>'
    +'<th>Nº Processo</th>'
    +'<th>Cliente</th>'
    +'<th>Envolvido</th>'
    +'<th>Natureza</th>'
    +'<th>Última Mov.</th>'
  +'</tr></thead><tbody>';

  lst.forEach(function(grp){
    var procs = grp.processos || [grp];
    var encProcs = procs.filter(function(p){ return encIds.has(p.id)||encIds.has(String(p.id)); });
    var allEnc = encProcs.length === procs.length;
    var someEnc = encProcs.length > 0;
    if(isEncView && !someEnc) return;
    if(!isEncView && allEnc) return;

    var ativosP = procs.filter(function(p){ return !encIds.has(p.id)&&!encIds.has(String(p.id)); });
    var proc = ativosP[0] || procs[0];
    var maxDorm = procs.reduce(function(m,p){ return Math.max(m, p.ultima_mov_dias||0); }, 0);
    var statusCls = allEnc ? 'tbl-status-enc' : (maxDorm>=1000 ? 'tbl-status-dorm' : 'tbl-status-ativo');
    var pasta = proc.pasta || grp.id || '—';
    var numero = proc.numero || '';
    var cliente = grp.nome || proc.cliente || '—';
    var adverso = proc.adverso || '';
    var nats = [...new Set(ativosP.map(function(p){ return p.natureza; }).filter(Boolean))];
    var ultMov = proc.ultima_mov ? fDt(proc.ultima_mov) : '—';
    var ultDias = proc.ultima_mov_dias;
    var ultCor = !ultDias ? 'var(--mu)' : ultDias > 365 ? '#c9484a' : ultDias > 90 ? '#f59e0b' : 'var(--mu)';

    html += '<tr onclick="openC('+proc.id+')">'
      +'<td><span class="tbl-status '+statusCls+'"></span></td>'
      +'<td class="tbl-pasta">'+pasta+'</td>'
      +'<td class="tbl-num">'+escapeHtml(numero)+'</td>'
      +'<td class="tbl-cli">'+escapeHtml(cliente)
        +'<span class="tbl-badge-autor">Autor</span>'
      +'</td>'
      +'<td>'+escapeHtml(adverso)+'</td>'
      +'<td>'+nats.map(function(n){ return '<span class="tbl-nat '+_natClass(n)+'">'+escapeHtml(n)+'</span>'; }).join(' ')+'</td>'
      +'<td style="color:'+ultCor+'">'+ultMov+(ultDias?' <span style="font-size:9px;opacity:.7">('+ultDias+'d)</span>':'')+'</td>'
    +'</tr>';
  });

  html += '</tbody></table>';
  el.innerHTML = html;
}

// Phase 2: virtualização — altura fixa por item, renderiza só os visíveis
var _rlData=[], _rlEnc=false, _rlItemH=68, _rlBuffer=5;

function _rlBuildItem(grp, cf, isEncView){
    const procs=grp.processos||[grp];
    const isAtivo=AC&&procs.some(p=>p.id===AC.id);
    const encProcs=procs.filter(p=>isEncerrado(p.id));
    const allEnc=encProcs.length===procs.length;
    const someEnc=encProcs.length>0;
    if(isEncView&&!someEnc) return '';
    if(!isEncView&&allEnc) return '';
    const totalAg=procs.reduce((s,p)=>(s+(p.agenda||[]).length),0);
    const totalMov=procs.reduce((s,p)=>(s+(p.movimentacoes||[]).length),0);
    const totalFut=procs.reduce((s,p)=>(s+(cf[p.id]||0)),0);
    const hasTel=procs.some(p=>p.tel);
    const maxDorm=procs.reduce((m,p)=>Math.max(m,p.ultima_mov_dias||0),0);
    const nProcs=procs.filter(p=>!isEncerrado(p.id)).length;
    const nats=[...new Set(procs.filter(p=>!isEncerrado(p.id)).map(p=>p.natureza))];
    const dataLabel=allEnc?('Encerrado '+encProcs[encProcs.length-1].data):
      (procs.find(p=>!isEncerrado(p.id))?.data_inicio||'').slice(0,7);
    return`<div class="ci ${isAtivo?'on':''} ${allEnc?'enc-item':''}" onclick="openC(${grp.id})">
      <div class="cn">${grp.nome||'(sem nome)'}</div>
      <div class="cmeta">
        <span style="display:flex;gap:3px;flex-wrap:wrap">
          ${nats.map(n=>`<span class="cnat ${nc(n)}">${n}</span>`).join('')}
        </span>
        <span class="cdate">${dataLabel}</span>
      </div>
      <div class="cbadges">
        ${allEnc?`<span class="enc-badge">🗂 Enc.</span>`:''}
        ${nProcs>1?`<span class="badge" style="background:#2a1f3d;color:#c9a84c;font-size:9px">📁 ${nProcs}</span>`:''}
        ${!allEnc&&maxDorm>=1000&&maxDorm<9999?`<span class="dorm-badge">⚠ ${maxDorm}d</span>`:''}
        ${!allEnc&&maxDorm===9999?`<span class="dorm-badge">⚠ sem mov.</span>`:''}
        ${!allEnc&&totalAg?`<span class="badge bag">📅${totalAg}</span>`:''}
        ${!allEnc&&totalMov?`<span class="badge bmv">📋${totalMov}</span>`:''}
        ${!allEnc&&totalFut?`<span class="badge bfut2">⏰${totalFut}</span>`:''}
        ${hasTel?`<span class="badge btel">📞</span>`:''}
      </div>
    </div>`;
}

function _rlPaint(){
  var el=document.getElementById('clist');
  if(!el||!_rlData.length) return;
  var scrollTop=el.scrollTop, viewH=el.clientHeight;
  var total=_rlData.length, h=_rlItemH, buf=_rlBuffer;
  var first=Math.max(0,Math.floor(scrollTop/h)-buf);
  var last=Math.min(total-1,Math.ceil((scrollTop+viewH)/h)+buf);
  // Reconstruct only visible items
  var cf=_rlCf;
  var parts=[];
  parts.push('<div style="height:'+first*h+'px"></div>');
  for(var i=first;i<=last;i++){
    parts.push(_rlBuildItem(_rlData[i],cf,_rlEnc));
  }
  parts.push('<div style="height:'+(total-1-last)*h+'px"></div>');
  el.innerHTML=parts.join('');
}
var _rlCf={};

function renderList(lst, isEncView=false){
  // Cache único de allPend para todo o renderList
  var _ap = allPendCached();
  var cf={};
  _ap.forEach(function(p){
    if(p.dt_raw>=HS && p.id_processo && p.id_processo!==0)
      cf[p.id_processo]=(cf[p.id_processo]||0)+1;
  });
  _rlCf=cf;
  // Stats (usa cf já calculado — O(1) por cliente)
  var sbTxt = document.getElementById('sb-stats-txt');
  if(sbTxt){
    var total = lst.length;
    var comPend = lst.filter(function(grp){ return grp.processos&&grp.processos.some(function(p){ return cf[p.id]>0; }); }).length;
    sbTxt.innerHTML = '<span>'+total+' cliente'+(total!==1?'s':'')+'</span>'+(comPend>0?'<span style="color:var(--ouro)">\u2022 '+comPend+' c/ agenda</span>':'');
  }
  // View tabela
  if(_vclView === 'table'){
    renderListTable(lst, isEncView);
    return;
  }
  // Phase 2: virtualização — listas pequenas renderizam direto, grandes usam scroll virtual
  _rlData=lst; _rlEnc=isEncView;
  var el=document.getElementById('clist');
  if(lst.length<=50){
    // lista pequena — render direto com DocumentFragment
    var frag=document.createDocumentFragment();
    lst.forEach(function(grp){
      var html=_rlBuildItem(grp,cf,isEncView);
      if(html) frag.appendChild(_fragFromHtml(html));
    });
    el.textContent='';
    el.appendChild(frag);
    el.onscroll=null;
  } else {
    // lista grande — scroll virtual
    _rlPaint();
    el.onscroll=_rlPaint;
  }
}

// ═══════════════════════════════════════════════════════
// ══ FICHA DA PESSOA — tela intermediária antes do processo
// ═══════════════════════════════════════════════════════

function _renderFichaPessoa(grp){
  if(!grp||!grp.processos) return '';
  var nome = grp.nome||'';
  var procs = grp.processos;
  var encIds = getEncIds();

  // Pegar dados extras do primeiro processo
  var firstProc = procs[0];
  var ex = (tasks[firstProc.id]||{}).extra||{};
  var tel = ex.tel||firstProc.tel||'';
  var email = ex.email||firstProc.email||'';
  var cpf = ex.cpf||firstProc.cpf||'';
  var nasc = ex.nasc||'';

  // Iniciais para avatar
  var iniciais = (nome||'?').split(' ').filter(Boolean).map(function(p){return p[0];}).slice(0,2).join('').toUpperCase()||'?';

  var html = '<div style="padding:24px;max-width:900px;margin:0 auto">';

  // Header da pessoa
  html += '<div style="display:flex;align-items:center;gap:16px;margin-bottom:24px">'
    +'<div style="width:64px;height:64px;border-radius:50%;background:var(--vinho);display:flex;align-items:center;justify-content:center;font-size:22px;font-weight:700;color:var(--ouro);flex-shrink:0">'+iniciais+'</div>'
    +'<div style="flex:1">'
      +'<div style="font-size:20px;font-weight:800;color:var(--tx)">'+escapeHtml(nome)+'</div>'
      +'<div style="display:flex;gap:12px;margin-top:4px;flex-wrap:wrap">'
        +(cpf?'<span style="font-size:11px;color:var(--mu)">CPF: '+escapeHtml(cpf)+'</span>':'')
        +(nasc?'<span style="font-size:11px;color:var(--mu)">Nasc: '+fDt(nasc)+'</span>':'')
      +'</div>'
    +'</div>'
    +'<div style="display:flex;gap:6px;flex-shrink:0">'
      +(tel?'<a href="tel:'+escapeHtml(tel)+'" style="padding:6px 12px;border-radius:6px;background:rgba(76,175,125,.1);border:1px solid rgba(76,175,125,.3);color:#4ade80;font-size:11px;font-weight:700;text-decoration:none">\ud83d\udcde '+escapeHtml(tel)+'</a>':'')
      +(tel?'<a href="https://wa.me/55'+tel.replace(/\D/g,'')+'" target="_blank" style="padding:6px 12px;border-radius:6px;background:rgba(37,211,102,.1);border:1px solid rgba(37,211,102,.3);color:#25d366;font-size:11px;font-weight:700;text-decoration:none">\ud83d\udcac WhatsApp</a>':'')
    +'</div>'
  +'</div>';

  // Contato
  html += '<div style="background:var(--sf2);border:1px solid var(--bd);border-radius:12px;padding:16px;margin-bottom:16px">'
    +'<div style="font-size:11px;font-weight:700;text-transform:uppercase;color:var(--mu);margin-bottom:10px;letter-spacing:.05em">Informa\u00e7\u00f5es de contato</div>'
    +'<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:8px">'
      +(tel?'<div><div style="font-size:9px;color:var(--mu);text-transform:uppercase">Telefone</div><div style="font-size:13px;color:var(--tx);font-weight:600">'+escapeHtml(tel)+'</div></div>':'')
      +(email?'<div><div style="font-size:9px;color:var(--mu);text-transform:uppercase">Email</div><div style="font-size:13px;color:var(--tx);font-weight:600">'+escapeHtml(email)+'</div></div>':'')
      +(cpf?'<div><div style="font-size:9px;color:var(--mu);text-transform:uppercase">CPF</div><div style="font-size:13px;color:var(--tx);font-weight:600">'+escapeHtml(cpf)+'</div></div>':'')
      +(nasc?'<div><div style="font-size:9px;color:var(--mu);text-transform:uppercase">Nascimento</div><div style="font-size:13px;color:var(--tx);font-weight:600">'+fDt(nasc)+'</div></div>':'')
      +(ex.ecivil?'<div><div style="font-size:9px;color:var(--mu);text-transform:uppercase">Estado civil</div><div style="font-size:13px;color:var(--tx);font-weight:600">'+escapeHtml(ex.ecivil)+'</div></div>':'')
      +(ex.prof?'<div><div style="font-size:9px;color:var(--mu);text-transform:uppercase">Profiss\u00e3o</div><div style="font-size:13px;color:var(--tx);font-weight:600">'+escapeHtml(ex.prof)+'</div></div>':'')
    +'</div>'
  +'</div>';

  // Processos
  html += '<div style="background:var(--sf2);border:1px solid var(--bd);border-radius:12px;padding:16px;margin-bottom:16px">'
    +'<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:12px">'
      +'<div style="font-size:11px;font-weight:700;text-transform:uppercase;color:var(--mu);letter-spacing:.05em">'+procs.length+' Processo'+(procs.length!==1?'s':'')+'</div>'
      +'<div style="display:flex;gap:6px">'
        +'<button onclick="_novoProcessoDoCliente('+firstProc.id+',\'Autor\')" class="dsh-btn" style="font-size:10px">\u2696 Novo como Autor</button>'
        +'<button onclick="_novoProcessoDoCliente('+firstProc.id+',\'R\u00e9u\')" class="dsh-btn dsh-btn-ghost" style="font-size:10px">\u2696 Novo como R\u00e9u</button>'
      +'</div>'
    +'</div>';

  procs.forEach(function(p){
    var enc = encIds.has(p.id);
    var polo = p.polo||p.condicao||'Autor';
    var poloCor = /autor|reclamante|requerente/i.test(polo) ? '#4ade80' : '#f87676';
    var natureza = p.natureza||'';
    html += '<div onclick="openProc('+p.id+')" style="display:flex;align-items:center;gap:12px;padding:12px;margin-bottom:8px;background:var(--sf3);border:1px solid var(--bd);border-radius:10px;cursor:pointer;transition:all .15s'+(enc?';opacity:.5':'')+'" onmouseover="this.style.borderColor=\'var(--ouro)\'" onmouseout="this.style.borderColor=\'var(--bd)\'">'
      +'<div style="font-size:14px;font-weight:800;color:var(--ouro);min-width:50px">'+escapeHtml(p.pasta||'\u2014')+'</div>'
      +'<div style="flex:1;min-width:0">'
        +'<div style="font-size:12px;font-weight:600;color:var(--tx);overflow:hidden;text-overflow:ellipsis;white-space:nowrap">'+(p.numero||'Sem n\u00famero')+'</div>'
        +'<div style="display:flex;gap:6px;margin-top:3px;flex-wrap:wrap">'
          +(natureza?'<span style="font-size:9px;padding:2px 6px;border-radius:3px;background:rgba(201,72,74,.15);color:#c9484a;font-weight:700;text-transform:uppercase">'+escapeHtml(natureza)+'</span>':'')
          +'<span style="font-size:9px;padding:2px 6px;border-radius:3px;background:'+poloCor+'20;color:'+poloCor+';font-weight:700">'+escapeHtml(polo)+'</span>'
          +(p.adverso?'<span style="font-size:9px;color:var(--mu)">vs '+escapeHtml(p.adverso)+'</span>':'')
          +(enc?'<span style="font-size:9px;padding:2px 6px;border-radius:3px;background:rgba(156,163,175,.15);color:#9ca3af;font-weight:700">ENCERRADO</span>':'')
        +'</div>'
      +'</div>'
      +'<div style="font-size:16px;color:var(--mu)">\u203a</div>'
    +'</div>';
  });

  html += '</div>';

  // Botão voltar
  html += '<button onclick="voltarParaLista()" style="font-size:11px;padding:6px 14px;border-radius:6px;background:var(--sf3);border:1px solid var(--bd);color:var(--mu);cursor:pointer">\u2190 Voltar para lista</button>';

  return html+'</div>';
}

// Voltar da ficha da pessoa/processo para a lista de clientes
function voltarParaLista(){
  AC=null; AC_PROC=null; _grupoAtual=null;
  var vclWrap = document.querySelector('.vcl-wrap');
  if(vclWrap){ vclWrap.classList.remove('fin-hidden'); if(_vclView==='table') vclWrap.classList.add('vcl-full'); }
  _finRemoverSidebar();
  var vclMain = document.querySelector('.vcl-main');
  if(vclMain){ vclMain.style.display=''; vclMain.style.flexDirection=''; }
  var emp2 = document.getElementById('emp2');
  if(emp2) emp2.style.display='flex';
  var ficha = document.getElementById('ficha-vcl');
  if(ficha){ ficha.classList.remove('on'); ficha.innerHTML=''; }
  renderVclEmpty();
  doSearch();
}

// Abrir processo específico — delega para openC (unificado)
function openProc(cid){
  var c = findClientById(cid);
  if(!c) return;
  openC(cid, cid);
}

function openC(id, procId=null){
  var grp=CLIENTES_AGRUPADOS.find(function(g){return g.processos&&g.processos.some(function(p){return String(p.id)===String(id);});});
  if(!grp) return;
  _grupoAtual = grp;

  // Se foi chamado com procId, abrir processo direto
  if(procId){
    var procAlvo = grp.processos.find(function(p){return String(p.id)===String(procId);});
    if(procAlvo){ AC=procAlvo; AC_PROC=grp; }
  } else {
    AC_PROC=grp;
  }
  // Garantir view Clientes
  document.querySelectorAll('.view').forEach(function(x){x.classList.remove('on');});
  document.getElementById('vcl').classList.add('on');
  doSearch();

  var vclWrap = document.querySelector('.vcl-wrap');
  if(vclWrap){ vclWrap.classList.add('fin-hidden'); vclWrap.classList.remove('vcl-full'); }
  _finRemoverSidebar();
  var vclMain = document.querySelector('.vcl-main');
  if(vclMain){ vclMain.style.display=''; vclMain.style.flexDirection=''; }

  var emp2=document.getElementById('emp2');
  if(emp2) emp2.style.display='none';

  var fichaEl = document.getElementById('ficha-vcl');

  // Se procId fornecido → abrir processo direto
  if(procId && AC){
    renderFicha(AC, grp);
  }
  // Se só 1 processo → abrir direto também
  else if(grp.processos.length===1){
    AC = grp.processos[0];
    _grupoAtual = grp;
    renderFicha(AC, grp);
  }
  // Se múltiplos processos → abrir ficha da pessoa
  else {
    if(fichaEl){
      fichaEl.classList.add('on');
      fichaEl.innerHTML = _renderFichaPessoa(grp);
    }
  }
  setTimeout(_updateNavBtn, 100);
}

// ── MODAIS ──
function abrirModal(title, formHtml, cb, btnLabel='Salvar', btnColor=null){
  document.getElementById('modal-title').textContent=title;
  document.getElementById('modal-form').innerHTML=formHtml;
  // Wrap callback with loading guard to prevent double-submit
  document.getElementById('modal-save').onclick = cb ? async function(){
    const btn = document.getElementById('modal-save');
    if(btn && btn.disabled) return;
    if(btn){ btn.disabled=true; const orig=btn.textContent; btn.textContent='Salvando...';
      setTimeout(()=>{ if(btn){ btn.disabled=false; btn.textContent=orig; }}, 3000); }
    await cb();
  } : null;
  const ov=document.getElementById('modal-overlay');
  ov.style.display='flex';
  const saveBtn=document.getElementById('modal-save');
  saveBtn.style.display = cb ? '' : 'none';
  saveBtn.textContent=btnLabel;
  saveBtn.style.background=btnColor||'';
  saveBtn.style.color=btnColor?'#fff':'';
  if(btnColor) saveBtn.style.display='';
}
function fecharModal(){
  const ov=document.getElementById('modal-overlay');
  if(ov) ov.style.display='none';
  // Limpar callback para evitar double-submit com handler desatualizado
  const btn=document.getElementById('modal-save');
  if(btn){ btn.onclick=null; btn.style.background=''; btn.textContent='Salvar'; btn.disabled=false; }
  const form=document.getElementById('modal-form');
  if(form) form.innerHTML='';
}

function mInput(id,label,type='text',val='',extra=''){
  return `<div class="mform-row"><label>${label}</label><input class="minput" id="${id}" type="${type}" value="${val}" ${extra}></div>`;
}
function mTextarea(id,label,val=''){
  return `<div class="mform-row"><label>${label}</label><textarea class="minput mtarea" id="${id}">${val}</textarea></div>`;
}
function mSelect(id,label,opts,val=''){
  return `<div class="mform-row"><label>${label}</label><select class="minput msel" id="${id}">${opts.map(o=>`<option value="${o}" ${o===val?'selected':''}>${o}</option>`).join('')}</select></div>`;
}

// MODAL AGENDA GERAL — redireciona para modal unificado
function abrirModalAg(){
  _abrirModalCompromisso(null);
}

// MODAL AGENDA CLIENTE
// abrirModalAgCliente: ver definição unificada acima

// MODAL MOVIMENTAÇÃO
function abrirModalMov(cid){
  const c = findClientById(cid);
  if(!c) return;
  const hoje = new Date().toISOString().slice(0,10);

  const form = mInput('mv-data','Data','date',hoje)
    + mTextarea('mv-desc','Descrição da movimentação')
    + '<div style="margin-top:12px;padding:10px 12px;background:var(--sf3);border-radius:8px;border:1px solid var(--bd)">'
      + '<label style="display:flex;align-items:center;gap:8px;cursor:pointer;user-select:none">'
        + '<input type="checkbox" id="mv-wpp" style="width:16px;height:16px;cursor:pointer" onchange="mvWppPreview(this.checked)">'
        + '<span style="font-size:13px;color:var(--tx);font-weight:500">📲 Gerar mensagem para WhatsApp</span>'
      + '</label>'
      + '<div id="mv-wpp-box" style="display:none;margin-top:10px">'
        + '<div style="font-size:11px;color:var(--mu);margin-bottom:4px">Prévia da mensagem (edite se quiser):</div>'
        + '<textarea id="mv-wpp-txt" rows="8" style="width:100%;font-size:12px;font-family:monospace;line-height:1.6;background:var(--sf2);border:1px solid var(--bd);border-radius:6px;padding:8px;color:var(--tx);resize:vertical" oninput="mvWppCustom=this.value"></textarea>'
      + '</div>'
    + '</div>';

  abrirModal('Novo andamento — '+c.cliente, form, function(){
    const data = document.getElementById('mv-data').value;
    const desc = document.getElementById('mv-desc').value.trim();
    if(!desc){ showToast('Informe a descrição'); return; }
    if(!localMov[cid]) localMov[cid]=[];
    localMov[cid].push({data:data, desc:desc, novo:true});
    sbSet('co_localMov', localMov);
    marcarAlterado();
    fecharModal();
    renderFicha(AC);
    showToast('Andamento adicionado!');

    // WPP message?
    const wppCheck = document.getElementById('mv-wpp');
    if(wppCheck && wppCheck.checked){
      const msg = (typeof mvWppCustom!=='undefined' && mvWppCustom)
        ? mvWppCustom
        : mvGerarMsg(c.cliente, desc);
      setTimeout(function(){
        abrirModal('📲 Mensagem WhatsApp — '+c.cliente,
          '<div style="background:var(--sf3);border-radius:8px;padding:12px;font-size:12px;font-family:monospace;line-height:1.8;white-space:pre-wrap;color:var(--tx);border:1px solid var(--bd)">'+escapeHtml(msg)+'</div>',
          function(){
            if(navigator.clipboard && navigator.clipboard.writeText){
              navigator.clipboard.writeText(msg).then(function(){showToast('📲 Copiado!');}).catch(function(){mvCopiarFallback(msg);});
            } else { mvCopiarFallback(msg); }
          }, '📲 Copiar para WhatsApp');
      }, 300);
    }
  }, '✓ Salvar andamento');
}

let mvWppCustom = '';

function _mvEnviarWpp(cid, idx){
  var c = findClientById(cid);
  if(!c){ showToast('Cliente não encontrado'); return; }
  var movs = (localMov[cid]||[]).concat([...(c.movimentacoes||[]),...(MOV_INDEX[String(cid)]||[])]);
  var m = movs[idx];
  if(!m){ showToast('Movimentação não encontrada'); return; }
  var txt = m.movimentacao || m.desc || m.descricao || '';
  var msg = mvGerarMsg(c.cliente || 'cliente', txt);
  // Copiar para clipboard
  navigator.clipboard.writeText(msg).then(function(){
    showToast('✓ Mensagem copiada para a área de transferência');
  }).catch(function(){
    // Fallback: prompt
    prompt('Copie a mensagem abaixo:', msg);
  });
}

function mvGerarMsg(cliente, descricao){
  return '📍 Atualização Processual\n'
    + 'Prezado(a) ' + cliente.split(' ')[0] + ',\n\n'
    + 'O status do seu processo foi atualizado.\n\n'
    + '⏭️ ' + descricao + '\n\n'
    + 'Assim que houver qualquer novidade, entraremos em contato.\n\n'
    + 'Atenciosamente,\n'
    + 'Clarissa Oliveira Advocacia';
}

function mvWppPreview(checked){
  const box = document.getElementById('mv-wpp-box');
  if(!box) return;
  box.style.display = checked ? 'block' : 'none';
  if(checked){
    const desc = (document.getElementById('mv-desc')?.value||'').trim();
    const cid = AC?.id;
    const c = cid ? findClientById(cid) : null;
    const msg = mvGerarMsg(c ? c.cliente : 'cliente', desc||'[descreva a movimentação acima]');
    const ta = document.getElementById('mv-wpp-txt');
    if(ta){ ta.value = msg; mvWppCustom = msg; }
  }
}

function mvCopiarFallback(txt){
  var ta = document.createElement('textarea');
  ta.value = txt; document.body.appendChild(ta); ta.select();
  document.execCommand('copy'); document.body.removeChild(ta);
  showToast('📲 Copiado!');
}

// MODAL FINANCEIRO


// ── Lógica auxiliar dos campos ──




const HON_PRESET = {
  trabalhista:    {hint:'Trabalhista: geralmente 30% sobre a condenação', perc:30},
  previdenciario: {hint:'Previdenciário: valor fixo + % sobre benefício', perc:10},
  civel:          {hint:'Cível: geralmente 20% sobre o acordo',           perc:20},
  familia:        {hint:'Família: geralmente valor fixo',                  perc:0},
  consultoria:    {hint:'Consultoria: valor fixo por sessão/hora',         perc:0},
};






// ── AGENDA GERAL ──
function agRowGlobal(p){
  const isFut = p.dt_raw>=HS;
  const dias  = isFut ? diasAte(p.dt_raw) : null;
  const isUrg = isFut && dias<=7;
  const tipo  = agTipo(p);

  let dtag='';
  if(isFut){
    if(dias===0)      dtag=`<span class="dtag dtag-h">HOJE</span>`;
    else if(dias===1) dtag=`<span class="dtag dtag-u">amanhã</span>`;
    else if(dias<=7)  dtag=`<span class="dtag dtag-u">em ${dias}d</span>`;
    else              dtag=`<span class="dtag dtag-f">em ${dias}d</span>`;
  }

  const cliTag = p.cliente
    ? `<span class="ag-cli">${p.cliente}</span>`
    : '<span style="font-size:9px;color:var(--mu)">sem cliente vinculado</span>';

  return `<div class="ag-row tipo-${tipo}" onclick="abrirCDeAg(${p.id_processo||0})">
    <div class="ag-dot tipo-${tipo}"></div>
    <div class="ag-data">${p.inicio||p.dt_raw}${dtag}</div>
    <div style="flex:1">
      <div class="ag-titulo">
        ${p.titulo}
        <span class="ag-tipo-badge tipo-${tipo}">${TIPO_LABEL[tipo]}</span>
      </div>
      ${p.obs?`<div class="ag-obs2">📎 ${p.obs}</div>`:''}
    </div>
    ${cliTag}
    ${p.natureza?`<span class="cnat ${nc(p.natureza)}">${p.natureza}</span>`:''}
  </div>`;
}


function abrirCDeAg(pid){
  if(!pid)return;
  const c=findClientById(pid);
  if(!c)return;
  goView('vc',document.querySelector('.hnav-btn'));
  openC(c.id);
}

// ── FICHA ──

// ── Editar contato direto da ficha do cliente ──

// ── Mensagem rápida WhatsApp ──
function wppMsgRapida(cid, tel){
  const c = CLIENTS.find(x=>String(x.id)===String(cid));
  const nome = c ? c.cliente.split(' ')[0] : 'cliente';
  
  const templates = [
    { label:'Andamento do processo', msg:`Olá, ${nome}! Aqui é a Dra. Clarissa. Gostaria de informar sobre o andamento do seu processo. Podemos conversar?` },
    { label:'Solicitar documento', msg:`Olá, ${nome}! Aqui é a Dra. Clarissa. Precisamos de um documento seu para dar andamento ao processo. Poderia nos enviar? 🙏` },
    { label:'Confirmar audiência', msg:`Olá, ${nome}! Aqui é a Dra. Clarissa. Gostaria de confirmar sua presença na audiência marcada. Consegue comparecer?` },
    { label:'Retorno de ligação', msg:`Olá, ${nome}! Aqui é a Dra. Clarissa. Vi que você ligou. Como posso ajudar?` },
    { label:'Mensagem livre', msg:'' },
  ];

  const opcoesHtml = templates.map((t,i)=>
    `<div style="padding:8px 10px;border:1px solid var(--bd);border-radius:6px;cursor:pointer;margin-bottom:6px;font-size:12px;transition:background .1s"
      onclick="wppEnviar('${tel}', ${i})" 
      onmouseover="this.style.background='var(--sf3)'" 
      onmouseout="this.style.background=''"
    >
      <div style="font-weight:600;color:var(--of)">${t.label}</div>
      ${t.msg?`<div style="color:var(--mu);font-size:11px;margin-top:2px">${t.msg.slice(0,60)}...</div>`:'<div style="color:var(--mu);font-size:11px;margin-top:2px">Escrever mensagem personalizada</div>'}
    </div>`
  ).join('');

  window._wppTel = tel;
  window._wppTemplates = templates;

  abrirModal(`💬 WhatsApp — ${nome}`, `
    <div style="font-size:11px;color:var(--mu);margin-bottom:10px">Escolha uma mensagem ou escreva uma livre:</div>
    ${opcoesHtml}
    <div id="wpp-livre-wrap" style="display:none;margin-top:8px">
      <label class="fm-lbl">Sua mensagem</label>
      <textarea class="fm-inp" id="wpp-livre-txt" rows="4" placeholder="Digite sua mensagem..."></textarea>
    </div>
  `, null, null);
}

function wppEnviar(tel, templateIdx){
  const t = window._wppTemplates?.[templateIdx];
  if(!t) return;
  if(templateIdx === window._wppTemplates.length-1){
    // Mensagem livre
    const wrap = document.getElementById('wpp-livre-wrap');
    const txt  = document.getElementById('wpp-livre-txt');
    if(wrap && txt){
      if(wrap.style.display==='none'){
        wrap.style.display='block';
        txt.focus();
        return;
      }
      const msg = txt.value.trim();
      if(!msg){ alert('Digite a mensagem'); return; }
      const url = `https://wa.me/55${tel}?text=${encodeURIComponent(msg)}`;
      window.open(url,'_blank');
      fecharModal();
    }
  } else {
    const url = `https://wa.me/55${tel}?text=${encodeURIComponent(t.msg)}`;
    window.open(url,'_blank');
    fecharModal();
  }
}
function editarDadosProcesso(cid){
  const c = CLIENTS.find(x=>String(x.id)===String(cid));
  if(!c) return;
  abrirModal('✏ Editar Dados do Processo — '+c.cliente,
    `<div class="fm-row">
      <div style="flex:2"><label class="fm-lbl">Nome do cliente *</label>
        <input class="fm-inp" id="edp-nome" value="${(c.cliente||'').replace(/"/g,'&quot;')}"></div>
      <div><label class="fm-lbl">Área jurídica</label>
        <select class="fm-inp" id="edp-nat">
          ${['Trabalhista','Previdenciário','Cível','Família','Penal','Administrativo','Bancário','Consultoria'].map(n=>`<option ${c.natureza===n?'selected':''}>${n}</option>`).join('')}
        </select>
      </div>
    </div>
    <div class="fm-row" style="margin-top:8px">
      <div><label class="fm-lbl">Nº do processo</label>
        <input class="fm-inp" id="edp-num" value="${c.numero||''}"></div>
      <div><label class="fm-lbl">Data de distribuição</label>
        <input class="fm-inp" type="date" id="edp-data" value="${c.data_inicio||''}"></div>
    </div>
    <div class="fm-row" style="margin-top:8px">
      <div><label class="fm-lbl">Comarca / Vara</label>
        <input class="fm-inp" id="edp-comarca" value="${c.comarca||''}"></div>
      <div><label class="fm-lbl">Instância</label>
        <input class="fm-inp" id="edp-instancia" value="${c.instancia||''}"></div>
    </div>
    <div class="fm-row" style="margin-top:8px">
      <div style="flex:2"><label class="fm-lbl">Parte adversa</label>
        <input class="fm-inp" id="edp-adverso" value="${c.adverso||''}"></div>
           <div><label class="fm-lbl">Polo</label>
        <select class="fm-inp" id="edp-polo">
          <option value="">—</option>
          ${['Autor','Réu','Reclamante','Reclamado','Requerente','Requerido'].map(p=>`<option ${c.polo===p?'selected':''}>${p}</option>`).join('')}
        </select>
      </div>
    </div>
    <div class="fm-row" style="margin-top:8px">
      <div><label class="fm-lbl">Tipo de ação</label>
        <input class="fm-inp" id="edp-tipo" value="${c.tipo_acao||''}"></div>
      <div><label class="fm-lbl">Valor da causa</label>
        <input class="fm-inp" id="edp-valor" value="${c.valor_causa||''}"></div>
    </div>
    <div class="fm-row" style="margin-top:8px">
      <div><label class="fm-lbl">Condição</label>
        <input class="fm-inp" id="edp-cond" value="${c.condicao||''}"></div>
    </div>`,
    ()=>{
      const nome = document.getElementById('edp-nome')?.value.trim();
      if(!nome){ showToast('Informe o nome'); return; }
      c.cliente      = nome;
      c.natureza     = document.getElementById('edp-nat')?.value||c.natureza;
      c.numero       = document.getElementById('edp-num')?.value.trim();
      c.data_inicio  = document.getElementById('edp-data')?.value||c.data_inicio;
      c.comarca      = document.getElementById('edp-comarca')?.value.trim();
      c.instancia    = document.getElementById('edp-instancia')?.value.trim();
      c.adverso      = document.getElementById('edp-adverso')?.value.trim();
      c.polo         = document.getElementById('edp-polo')?.value||c.polo;
      c.tipo_acao    = document.getElementById('edp-tipo')?.value.trim();
      c.valor_causa  = document.getElementById('edp-valor')?.value.trim();
      c.condicao     = document.getElementById('edp-cond')?.value.trim();
      sbSalvarClientesDebounced();
      marcarAlterado();
      montarClientesAgrupados();
      doSearch();
      fecharModal();
      renderFicha(c, _grupoAtual);
      showToast('Dados do processo atualizados ✓');
    }, 'Salvar alterações'
  );
}

function fichaEditarContato(cid){
  const c = CLIENTS.find(x=>String(x.id)===String(cid));
  if(!c) return;
  abrirModal('📞 Contato — '+c.cliente,`
  <div style="font-size:11px;color:var(--mu);margin-bottom:12px">Edite telefone, e-mail e endereço deste cliente</div>
  <div class="fm-row">
    <div><label class="fm-lbl">Telefone principal</label>
      <input class="fm-inp" id="fec-tel" value="${c.tel||''}" placeholder="(31) 99999-9999">
    </div>
    <div><label class="fm-lbl">Telefone 2</label>
      <input class="fm-inp" id="fec-tel2" value="${c.tel2||''}" placeholder="(31) 99999-9999">
    </div>
  </div>
  <div class="fm-row" style="margin-top:8px">
    <div style="flex:2"><label class="fm-lbl">E-mail</label>
      <input class="fm-inp" type="email" id="fec-email" value="${c.email||''}" placeholder="email@exemplo.com">
    </div>
  </div>
  <div style="margin:10px 0 6px;font-size:10px;font-weight:700;color:var(--mu);text-transform:uppercase;letter-spacing:.06em">Endereço</div>
  <div class="fm-row">
    <div style="flex:3"><label class="fm-lbl">Rua / Logradouro</label>
      <input class="fm-inp" id="fec-rua" value="${c.rua||''}" placeholder="Rua, Av., Travessa...">
    </div>
    <div><label class="fm-lbl">Número</label>
      <input class="fm-inp" id="fec-num" value="${c.num||''}" placeholder="123">
    </div>
    <div><label class="fm-lbl">Complemento</label>
      <input class="fm-inp" id="fec-comp" value="${c.comp||''}" placeholder="Apto, sala...">
    </div>
  </div>
  <div class="fm-row" style="margin-top:8px">
    <div><label class="fm-lbl">Bairro</label>
      <input class="fm-inp" id="fec-bairro" value="${c.bairro||''}" placeholder="Bairro">
    </div>
    <div style="flex:2"><label class="fm-lbl">Cidade</label>
      <input class="fm-inp" id="fec-cidade" value="${c.cidade||''}" placeholder="Belo Horizonte">
    </div>
    <div><label class="fm-lbl">UF</label>
      <input class="fm-inp" id="fec-uf" value="${c.uf||''}" placeholder="MG" style="max-width:60px">
    </div>
    <div><label class="fm-lbl">CEP</label>
      <input class="fm-inp" id="fec-cep" value="${c.cep||''}" placeholder="00000-000">
    </div>
  </div>
  `,()=>{
    const g = id => document.getElementById('fec-'+id)?.value.trim()||'';
    c.tel    = g('tel');
    c.tel2   = g('tel2');
    c.email  = g('email');
    c.rua    = g('rua');
    c.num    = g('num');
    c.comp   = g('comp');
    c.bairro = g('bairro');
    c.cidade = g('cidade');
    c.uf     = g('uf');
    c.cep    = g('cep');
    // Salvar em tasks para persistir
    const key = String(c.id);
    if(!tasks[key]) tasks[key]={};
    tasks[key].contato = {tel:c.tel,tel2:c.tel2,email:c.email,
      rua:c.rua,num:c.num,comp:c.comp,bairro:c.bairro,cidade:c.cidade,uf:c.uf,cep:c.cep};
    sbSet('co_tasks', tasks);
    sbSalvarClientesDebounced();
    marcarAlterado();
    fecharModal();
    renderFicha(c);
    showToast('Contato atualizado ✓');
  },'💾 Salvar');
}
function getActiveF(){
  // Se a view clientes estiver ativa, usar ficha-vcl; senão ficha
  const vclOn = document.getElementById('vcl')?.classList.contains('on');
  return document.getElementById(vclOn ? 'ficha-vcl' : 'ficha');
}


// ═══════════════════════════════════════════════════════
// ── BANNER DE ATENDIMENTO (dentro da ficha do cliente) ──
// ═══════════════════════════════════════════════════════

const ATEND_STATUS_FICHA = {
  'inicial':      { lbl:'Atendimento inicial',    cor:'#60a5fa' },
  'analise':      { lbl:'Em análise',              cor:'#f59e0b' },
  'proposta':     { lbl:'Proposta enviada',        cor:'#a78bfa' },
  'aguardando':   { lbl:'Aguardando documentos',  cor:'#34d399' },
  'nao-prosseguiu':{ lbl:'Não prosseguiu',        cor:'#f87676' },
};

function renderAtendBanner(c){
  const ats = localAtend.filter(a=>String(a.id_cliente)===String(c.id));
  const at = ats.sort((a,b)=>(b.criado_em||'').localeCompare(a.criado_em||''))[0];
  const status = at?.status||'inicial';
  const s = ATEND_STATUS_FICHA[status]||ATEND_STATUS_FICHA['inicial'];
  const cid = c.id;

  const menuItems = Object.entries(ATEND_STATUS_FICHA).map(([k,v])=>`
    <div style="display:flex;align-items:center;gap:8px;padding:9px 13px;
                font-size:12px;font-weight:${status===k?'700':'500'};
                color:${status===k?v.cor:'#E0E0E0'};cursor:pointer;
                font-family:Inter,Roboto,sans-serif;line-height:1.5;
                border-bottom:1px solid #333;background:${status===k?'#333':'transparent'}"
         onmouseover="this.style.background='#333'" 
         onmouseout="this.style.background='${status===k?'#333':'transparent'}'"
         onclick="atdSelecionarStatus(${cid},'${k}')">
      <span style="background:${v.cor};width:7px;height:7px;border-radius:50%;flex-shrink:0;display:inline-block"></span>
      ${v.lbl}
    </div>`).join('');

  return `
    <div class="atend-inner">
      <div class="atend-inner-top">
        <div class="atend-inner-title">
          <span class="atend-dot" style="background:${s.cor}"></span>
          <span>Atendimento em andamento</span>
        </div>
        <div class="atend-inner-meta">
          ${at?.assunto?`<span>${at.assunto}</span>`:''}
          ${at?.data?`<span style="color:#9E9E9E">· ${at.data.split('-').reverse().join('/')}</span>`:''}
          ${at?.honorarios?`<span style="color:var(--ouro)">· ${at.honorarios}</span>`:''}
        </div>
      </div>
      ${at?.resumo?`<div class="atend-inner-resumo">${at.resumo}</div>`:''}
      <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-top:8px">
        <div class="atd-dd-wrap" id="atd-dd-${cid}" style="position:relative">
          <button onclick="atdToggle(${cid})"
            style="background:#252525;border:1px solid #444444;color:#E0E0E0;font-family:Inter,Roboto,sans-serif;display:inline-flex;align-items:center;gap:7px;padding:6px 12px;border-radius:6px;cursor:pointer;font-size:12px;font-weight:600;line-height:1.4">
            <span style="background:${s.cor};width:7px;height:7px;border-radius:50%;flex-shrink:0;display:inline-block"></span>
            <span>${s.lbl}</span>
            <svg width="9" height="5" viewBox="0 0 9 5"><path d="M0 0l4.5 5 4.5-5z" fill="#9E9E9E"/></svg>
          </button>
          <div id="atd-menu-${cid}" style="display:none;position:absolute;top:calc(100% + 4px);left:0;z-index:300;background:#252525;border:1px solid #333;border-radius:8px;min-width:215px;box-shadow:0 8px 28px rgba(0,0,0,.65);overflow:hidden">
            ${menuItems}
          </div>
        </div>
        <button onclick="atConverterProcesso(${cid})"
          style="background:transparent;border:1.5px solid #D4AF37;color:#D4AF37;font-family:Inter,Roboto,sans-serif;padding:6px 12px;border-radius:6px;cursor:pointer;font-size:12px;font-weight:700;line-height:1.4">⚖️ Virar processo</button>
      </div>
    </div>`;
}

function atdToggle(cid){
  const menu = document.getElementById('atd-menu-'+cid);
  if(!menu) return;
  const open = menu.style.display !== 'none';
  // close all
  document.querySelectorAll('.atd-dd-menu').forEach(m=>m.style.display='none');
  if(!open) menu.style.display='block';
}

function atdSelecionarStatus(cid, status){
  const menu = document.getElementById('atd-menu-'+cid);
  if(menu) menu.style.display='none';
  atAlterarStatusFicha(cid, status);
}

// Close dropdown on outside click
document.addEventListener('click', function(e){
  if(!e.target.closest('.atd-dd-wrap')){
    document.querySelectorAll('.atd-dd-menu').forEach(m=>m.style.display='none');
  }
});

function atAlterarStatusFicha(cid, novoStatus, atId){
  // Buscar por ID do atendimento se fornecido, senão por id_cliente (legado)
  var idx = atId ? localAtend.findIndex(function(a){return String(a.id)===String(atId);})
    : localAtend.findIndex(function(a){return String(a.id_cliente)===String(cid);});
  if(idx>=0){
    localAtend[idx].status = novoStatus;
    sbSet('co_atend', localAtend);
  }
  // Se não prosseguiu → confirmar antes de encerrar
  if(novoStatus==='nao-prosseguiu'){
    const c = findClientById(cid);
    abrirModal('Encerrar atendimento?',
      `<div style="font-size:12px;color:var(--mu);line-height:1.7">
        <p>Marcar como <strong style="color:#f87676">não prosseguiu</strong> irá encerrar o processo de <strong style="color:var(--tx)">${c?.cliente||''}</strong>.</p>
        <p style="margin-top:8px">Esta ação pode ser desfeita em Encerrados → Reativar.</p>
      </div>`,
      ()=>{
        if(idx>=0){ localAtend[idx].status = novoStatus; sbSet('co_atend', localAtend); }
        encerrados[cid] = {
          data: new Date().toISOString().slice(0,10),
          motivo: 'Atendimento: cliente não prosseguiu',
          cliente: c?.cliente||''
        };
        _encIdsCache = null;
        sbSet('co_encerrados', encerrados);
        marcarAlterado();
        atualizarBadgeEnc();
        doSearch();
        atualizarStats();
        if(AC&&AC.id===cid){
          AC=null; AC_PROC=null; _grupoAtual=null;
          const _f2=document.getElementById('ficha-vcl'); if(_f2){_f2.classList.remove('on');_f2.innerHTML='';}
          const _e2=document.getElementById('emp2'); if(_e2) _e2.style.display='flex';
        }
        fecharModal();
        showToast('Atendimento encerrado — cliente não prosseguiu');
      }, 'Confirmar encerramento'
    );
    setTimeout(()=>{
      const btn=document.getElementById('modal-save');
      if(btn){btn.style.background='var(--red)';btn.textContent='Confirmar encerramento';}
    },50);
    return;
  }
  // Atualizar banner
  const banner = document.getElementById('atend-banner-'+cid);
  if(banner){
    const c = findClientById(cid);
    if(c) banner.innerHTML = renderAtendBanner(c);
  }
}

function atConverterProcesso(cid){
  const c = findClientById(cid);
  if(!c) return;
  const at = localAtend.find(a=>String(a.id_cliente)===String(cid));

  abrirModal('⚖️ Registrar dados do processo — '+c.cliente,
    `<div style="background:var(--sf3);border-radius:8px;padding:10px 12px;margin-bottom:12px;font-size:12px;color:var(--mu)">
      Cliente: <b style="color:var(--tx)">${c.cliente}</b>
      ${at?.assunto?' · '+at.assunto:''}
    </div>
    <div class="fm-row">
      <div style="flex:2"><label class="fm-lbl">Parte contrária <span class="req">*</span></label>
        <input class="fm-inp" id="cp-adverso" placeholder="Nome da parte adversa"></div>
      <div><label class="fm-lbl">Tipo de ação</label>
        <input class="fm-inp" id="cp-tipo" placeholder="Ex: Rescisão indireta"></div>
    </div>
    <div class="fm-row" style="margin-top:8px">
      <div><label class="fm-lbl">Número do processo</label>
        <input class="fm-inp" id="cp-num" placeholder="0000000-00.0000.0.00.0000 (opcional)"></div>
      <div><label class="fm-lbl">Vara / Tribunal</label>
        <input class="fm-inp" id="cp-vara" placeholder="Ex: 3ª VT de BH"></div>
    </div>
    <div class="fm-row" style="margin-top:8px">
      <div><label class="fm-lbl">Área jurídica</label>
        <select class="fm-inp" id="cp-area">
          <option>Trabalhista</option><option>Previdenciário</option>
          <option>Cível</option><option>Família</option>
          <option>Penal</option><option>Administrativo</option>
        </select>
      </div>
      <div><label class="fm-lbl">Comarca</label>
        <input class="fm-inp" id="cp-comarca" placeholder="Ex: Belo Horizonte"></div>
    </div>
    <div class="fm-row" style="margin-top:8px">
      <div><label class="fm-lbl">Data de distribuição</label>
        <input class="fm-inp" id="cp-data" type="date" value="${new Date().toISOString().slice(0,10)}"></div>
      <div><label class="fm-lbl">Valor da causa</label>
        <input class="fm-inp" id="cp-valor" placeholder="R$ 0,00"></div>
    </div>`,
    ()=>{
      const adverso = document.getElementById('cp-adverso')?.value.trim();
      if(!adverso){ showToast('Informe a parte contrária'); return; }
      const tipo    = document.getElementById('cp-tipo')?.value.trim()||'';
      const num     = document.getElementById('cp-num')?.value.trim()||'';
      const vara    = document.getElementById('cp-vara')?.value.trim()||'';
      const area    = document.getElementById('cp-area')?.value||'Trabalhista';
      const comarca = document.getElementById('cp-comarca')?.value.trim()||'';
      const data    = document.getElementById('cp-data')?.value||'';
      const valor   = document.getElementById('cp-valor')?.value.trim()||'';

      // Promover cliente: de consulta para processo
      c.status_consulta = 'processo';
      c.tipo = undefined;
      c.adverso    = adverso;
      c.tipo_acao  = tipo;
      c.numero     = num;
      c.comarca    = vara||comarca;
      c.natureza   = area;
      c.data_inicio = data;
      if(valor) c.valor_causa = valor;

      // Registrar andamento
      if(!localMov[cid]) localMov[cid]=[];
      localMov[cid].unshift({
        data: new Date().toISOString().slice(0,10),
        movimentacao: '[Processo cadastrado] Evoluído de atendimento'+(at?.assunto?' — '+at.assunto:''),
        tipo_movimentacao:'Sistema', origem:'conversao_atendimento'
      });

      // Marcar atendimento como contratado
      const atIdx = localAtend.findIndex(a=>String(a.id_cliente)===String(cid));
      if(atIdx>=0) localAtend[atIdx].status = 'contratou';
      sbSet('co_atend', localAtend);
      sbSet('co_localMov', localMov);
      sbSalvarClientesDebounced();
      marcarAlterado();
      montarClientesAgrupados();
      doSearch();
      fecharModal();
      audit('criacao','Atendimento convertido em processo: '+c.cliente,'processo');
      showToast('⚖️ Processo registrado — '+c.cliente);
      setTimeout(()=>{ openC(cid); }, 300);
    }, '⚖️ Registrar processo'
  );
}

function renderFicha(c, grp=null){
  // FIX: fallback para _grupoAtual — muitos callers chamam renderFicha(c) sem grp,
  // o que fazia o seletor de processos sumir quando o cliente tinha múltiplos processos.
  if(!grp) grp = _grupoAtual;
  // Restaurar dados de contato editados localmente
  const _ctcSaved = tasks[String(c.id)]?.contato;
  if(_ctcSaved){ Object.assign(c, _ctcSaved); }
  // Restaurar contrato de honorarios
  const _honSaved = tasks[String(c.id)]?._hon_contrato;
  if(_honSaved && !c._hon_contrato){ c._hon_contrato = _honSaved; }
  const _emp=document.getElementById('emp')||document.getElementById('emp2'); if(_emp) _emp.style.display='none';
  const f=getActiveF();
  f.classList.add('on');
  
  // Agenda futura deste cliente
  const agFut=allPendCached().filter(p=>p.id_processo===c.id&&(p.dt_raw>=HS||(p.dt_fim&&p.dt_fim>=HS))).sort((a,b)=>a.dt_raw.localeCompare(b.dt_raw));
  const cTasks=tasks[c.id]||[];
  const note=notes[c.id]||'';
  const movProjuris=[...(c.movimentacoes||[]),...(MOV_INDEX[String(c.id)]||[])];
  const cMov=(localMov[c.id]||[]).concat(movProjuris);
  const agBadge=agFut.length?`<span class="tc gold">${agFut.length}fut</span>`:`<span class="tc">${(c.agenda||[]).length}</span>`;

  const encInfo=encerrados[c.id]||encerrados[String(c.id)]||null;

  let contato='';
  if(c.tel){
    const tc=c.tel.replace(/\D/g,'');
    const tcFull = tc.length===11?tc:tc.length===10?tc:'55'+tc;
    contato+=`<a class="cbtn ctel" href="tel:${c.tel}" title="Ligar">📞 ${c.tel}</a>`;
    if(tc.length>=10){
      contato+=`<a class="cbtn cwa" href="https://wa.me/55${tc}" target="_blank" title="Abrir WhatsApp">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="#25d366"><path d="M17.472 14.382c-.297-.149-1.758-.867-2.03-.967-.273-.099-.471-.148-.67.15-.197.297-.767.966-.94 1.164-.173.199-.347.223-.644.075-.297-.15-1.255-.463-2.39-1.475-.883-.788-1.48-1.761-1.653-2.059-.173-.297-.018-.458.13-.606.134-.133.298-.347.446-.52.149-.174.198-.298.298-.497.099-.198.05-.371-.025-.52-.075-.149-.669-1.612-.916-2.207-.242-.579-.487-.5-.669-.51-.173-.008-.371-.01-.57-.01-.198 0-.52.074-.792.372-.272.297-1.04 1.016-1.04 2.479 0 1.462 1.065 2.875 1.213 3.074.149.198 2.096 3.2 5.077 4.487.709.306 1.262.489 1.694.625.712.227 1.36.195 1.871.118.571-.085 1.758-.719 2.006-1.413.248-.694.248-1.289.173-1.413-.074-.124-.272-.198-.57-.347z"/><path d="M12 0C5.373 0 0 5.373 0 12c0 2.125.557 4.122 1.529 5.858L0 24l6.335-1.505A11.945 11.945 0 0012 24c6.627 0 12-5.373 12-12S18.627 0 12 0zm0 21.818a9.818 9.818 0 01-5.007-1.373l-.36-.213-3.757.893.954-3.658-.233-.375A9.818 9.818 0 012.182 12C2.182 6.58 6.58 2.182 12 2.182c5.42 0 9.818 4.398 9.818 9.818 0 5.42-4.398 9.818-9.818 9.818z"/></svg>
        WhatsApp</a>`;
      contato+=`<button class="cbtn" onclick="wppMsgRapida('${c.id}','${tc}')" 
        style="background:#0a2010;border:1px solid #1a4a2e;color:#4ade80;font-size:10px" 
        title="Enviar mensagem rápida">✍ Msg</button>`;
    }
  }
  if(c.tel2){
    const tc2=c.tel2.replace(/\D/g,'');
    contato+=`<a class="cbtn ctel" href="tel:${c.tel2}" style="opacity:.85" title="Ligar para ${c.tel2}">📞 ${c.tel2}</a>`;
    if(tc2.length>=10)
      contato+=`<a class="cbtn cwa" href="https://wa.me/55${tc2}" target="_blank" style="opacity:.85" title="WhatsApp ${c.tel2}">
        <svg width="12" height="12" viewBox="0 0 24 24" fill="#25d366"><path d="M17.472 14.382c-.297-.149-1.758-.867-2.03-.967-.273-.099-.471-.148-.67.15-.197.297-.767.966-.94 1.164-.173.199-.347.223-.644.075-.297-.15-1.255-.463-2.39-1.475-.883-.788-1.48-1.761-1.653-2.059-.173-.297-.018-.458.13-.606.134-.133.298-.347.446-.52.149-.174.198-.298.298-.497.099-.198.05-.371-.025-.52-.075-.149-.669-1.612-.916-2.207-.242-.579-.487-.5-.669-.51-.173-.008-.371-.01-.57-.01-.198 0-.52.074-.792.372-.272.297-1.04 1.016-1.04 2.479 0 1.462 1.065 2.875 1.213 3.074.149.198 2.096 3.2 5.077 4.487.709.306 1.262.489 1.694.625.712.227 1.36.195 1.871.118.571-.085 1.758-.719 2.006-1.413.248-.694.248-1.289.173-1.413-.074-.124-.272-.198-.57-.347z"/><path d="M12 0C5.373 0 0 5.373 0 12c0 2.125.557 4.122 1.529 5.858L0 24l6.335-1.505A11.945 11.945 0 0012 24c6.627 0 12-5.373 12-12S18.627 0 12 0zm0 21.818a9.818 9.818 0 01-5.007-1.373l-.36-.213-3.757.893.954-3.658-.233-.375A9.818 9.818 0 012.182 12C2.182 6.58 6.58 2.182 12 2.182c5.42 0 9.818 4.398 9.818 9.818 0 5.42-4.398 9.818-9.818 9.818z"/></svg>
      </a>`;
  }
  if(c.email)contato+=`<a class="cbtn cml" href="mailto:${c.email}">✉️ ${c.email}</a>`;
  if(!c.tel&&!c.email)contato=`<div class="noc" style="display:flex;align-items:center;gap:8px">
    <span>Sem contato cadastrado</span>
  </div>`;
  contato+=`<button class="cbtn" onclick="fichaEditarContato('${c.id}')" 
    style="background:none;border:1px dashed var(--bd);color:var(--mu);font-size:11px" 
    title="Editar contato">✏</button>`;

  f.innerHTML=`
    <!-- HEADER ESTILO PROJURIS -->
    <div class="pj-header">
      <div class="pj-header-top">
        <div class="pj-header-left">
          <button class="pj-back" onclick="_finVoltarClientes()" title="Voltar">←</button>
          <div class="pj-header-id">
            <span class="pj-pasta">⚖ ${c.pasta||c.id}</span>
            <span class="pj-nat-badge ${nc(c.natureza)}">${c.natureza||'—'}</span>
            ${encInfo?'<span class="pj-enc-badge">Encerrado</span>':''}
          </div>
        </div>
        <div class="pj-header-right">
          <div class="pj-opcoes-wrap">
            <button class="pj-opcoes-btn" onclick="this.nextElementSibling.style.display=this.nextElementSibling.style.display==='block'?'none':'block'">Opções ▾</button>
            <div class="pj-opcoes-menu" style="display:none" onclick="this.style.display='none'">
              <div class="pj-opcoes-group">Processo</div>
              ${!encInfo?`
              <div class="pj-opcoes-item" onclick="editarDadosProcesso(${c.id})">✏ Alterar Processo</div>
              <div class="pj-opcoes-item" onclick="encerrarProcesso(${c.id})">🗂 Encerrar Processo</div>
              `:`
              <div class="pj-opcoes-item" onclick="reativarProcesso(${c.id})">↩ Reativar Processo</div>
              `}
              ${c.numero?`<div class="pj-opcoes-item" onclick="djSincronizar(${c.id})">🔄 Verificar Tribunal</div>`:''}
              <div class="pj-opcoes-sep"></div>
              <div class="pj-opcoes-group">Novo Processo</div>
              <div class="pj-opcoes-item" onclick="_novoProcessoDoCliente(${c.id},'Autor')">\u2696 Novo processo como Autor</div>
              <div class="pj-opcoes-item" onclick="_novoProcessoDoCliente(${c.id},'R\u00e9u')">\u2696 Novo processo como R\u00e9u</div>
              <div class="pj-opcoes-sep"></div>
              <div class="pj-opcoes-group">Adicionar</div>
              <div class="pj-opcoes-item" onclick="abrirModalMov(${c.id})">📋 Adicionar Movimentação</div>
              <div class="pj-opcoes-item" onclick="abrirModalPrazo(${c.id})">\ud83d\udcc5 Adicionar Prazo / Compromisso</div>
              <div class="pj-opcoes-item" onclick="abrirModalFin(${c.id},'receber')">💰 Adicionar Recebimento</div>
              <div class="pj-opcoes-item" onclick="abrirModalFin(${c.id},'pagar')">💸 Adicionar Pagamento</div>
              <div class="pj-opcoes-sep"></div>
              <div class="pj-opcoes-item" onclick="toggleDpPopover(${c.id})">👁 Dados Sensíveis</div>
              <div class="pj-opcoes-item" style="color:#c9484a" onclick="excluirProcesso(${c.id})">🗑 Excluir Processo</div>
            </div>
          </div>
        </div>
      </div>

      <div class="pj-header-body">
        <div class="pj-header-info">
          ${c.numero?`<span class="pj-numero">${c.numero}</span>`:'<span class="pj-numero pj-numero-nd">não distribuído</span>'}
          ${c.data_inicio?` <span class="pj-data-dist">Em ${fmtDataBR(c.data_inicio)}</span>`:''}
          <div class="pj-nome">${escapeHtml(c.cliente)||'(sem nome)'}</div>

          ${!encInfo&&c.ultima_mov_dias>=30?`
          <div class="pj-alerta-dorm">
            ⚠ Este processo está sem movimentação há ${c.ultima_mov_dias===9999?'tempo indeterminado':c.ultima_mov_dias+' dias'}
          </div>`:''}

          ${(c.tipo==='consulta'||c.status_consulta==='consulta')&&!encInfo?`
          <div class="atend-banner" id="atend-banner-${c.id}">${renderAtendBanner(c)}</div>`:''}

          ${grp&&grp.processos&&grp.processos.length>1?`
          <div class="proc-selector" style="margin-top:10px">
            ${grp.processos.map(p=>`
              <button class="proc-btn ${p.id===c.id?'on':''}" onclick="openC(${grp.id},${p.id})">
                <span class="proc-btn-pasta">Pasta ${p.pasta}</span>
                <span class="proc-btn-nat ${nc(p.natureza)}">${p.natureza}</span>
                ${isEncerrado(p.id)?'<span class="proc-btn-enc">encerrado</span>':''}
              </button>`).join('')}
          </div>`:''}
        </div>
        <div class="pj-header-contato">${contato}</div>
      </div>

      <!-- Partes -->
      <div class="pj-partes">
        <span class="pj-partes-lbl">Partes</span>
        <span class="pj-parte-badge pj-parte-cli">Cliente</span>
        <span class="pj-parte-badge pj-parte-autor">${c.condicao||'Autor'}</span>
        <span class="pj-parte-nome">${escapeHtml(c.cliente)||'—'}</span>
        ${c.tel?`<span class="pj-wpp-ico" onclick="window.open('https://wa.me/55${c.tel.replace(/\\D/g,'')}','_blank')" title="WhatsApp">💬</span>`:''}
        ${c.adverso?`
        <div style="margin-top:6px">
          <span class="pj-parte-badge" style="background:rgba(201,72,74,.12);color:#c9484a">Réu</span>
          <span class="pj-parte-nome">${escapeHtml(c.adverso)}</span>
        </div>`:''}
      </div>

      <!-- Judicial -->
      <div class="pj-judicial">
        <span class="pj-judicial-lbl">Judicial</span>
        <div class="pj-judicial-grid">
          ${c.numero?`<div><span class="pj-jud-k">Número</span><span class="pj-jud-v mono">${c.numero}</span></div>`:''}
          ${c._vara_datajud||c.comarca?`<div><span class="pj-jud-k">Tribunal / Vara</span><span class="pj-jud-v">${c._vara_datajud||c.comarca}</span></div>`:''}
          ${c.instancia?`<div><span class="pj-jud-k">Instância</span><span class="pj-jud-v">${c.instancia}</span></div>`:''}
          ${c.polo?`<div><span class="pj-jud-k">Polo</span><span class="pj-jud-v">${c.polo}</span></div>`:''}
          ${c.valor_causa?`<div><span class="pj-jud-k">Valor da Causa</span><span class="pj-jud-v">${c.valor_causa}</span></div>`:''}
          ${c._assuntos_datajud?`<div><span class="pj-jud-k">Assuntos</span><span class="pj-jud-v">${c._assuntos_datajud.join(', ')}</span></div>`:''}
        </div>
      </div>
    </div>

    <!-- POPOVER DADOS SENSÍVEIS (mantido) -->
    <button class="dp-popover-btn" onclick="toggleDpPopover(${c.id})" title="Dados bancários e acessos sensíveis" id="dp-btn-${c.id}" style="display:none">👁</button>
    <!-- POPOVER DADOS SENSÍVEIS -->
    <div class="dp-popover" id="dp-pop-${c.id}" style="display:none">
      <div class="dp-pop-header">
        <div class="dp-pop-tabs">
          <button class="dp-pop-tab on" onclick="dpPopTab(${c.id},'banco',this)">🏦 Dados Bancários</button>
          <button class="dp-pop-tab" onclick="dpPopTab(${c.id},'inss',this)">🔐 Meu INSS</button>
        </div>
        <button class="dp-pop-close" onclick="toggleDpPopover(${c.id})">✕</button>
      </div>
      <div class="dp-pop-body" id="dp-pop-body-${c.id}">
        ${renderDpPopover(c,'banco')}
      </div>
    </div>

    <div class="ficha-layout">
    <div class="ficha-main-col">

    <div class="proc-extra-wrap">
      <button class="proc-extra-toggle" onclick="toggleProcExtra('${c.id}')"><span id="proc-extra-lbl-${c.id}">▸ Ver mais detalhes do processo</span></button>
      <div class="proc-extra-body" id="proc-extra-body-${c.id}" style="display:none">
        ${c.tipo_acao?`<div class="icard" style="margin-bottom:6px"><div class="ilbl">Tipo de Ação</div><div class="ival">${c.tipo_acao}</div></div>`:''}
        ${c.adverso?`<div class="icard" style="margin-bottom:6px"><div class="ilbl">⚔ Parte Adversa — detalhes</div><div class="ival" style="margin-top:4px">${c.adverso}${c.adv_doc?` · Doc: ${c.adv_doc}`:''}${c.adv_adv?`<br><span style="font-size:11px;color:var(--mu)">Adv. adverso: ${c.adv_adv}</span>`:''}</div></div>`:''}
        ${renderParceriasBloco(c)}
        ${c.pedidos?`<div class="icard" style="margin-bottom:6px"><div class="ilbl">Pedidos Principais</div><div class="ival" style="white-space:pre-line">${c.pedidos}</div></div>`:''}
        ${c.pretensoes?`<div class="icard" style="margin-bottom:6px"><div class="ilbl">Pretensões</div><div class="ival">${c.pretensoes}</div></div>`:''}
        ${c.fatos?`<div class="icard" style="margin-bottom:6px"><div class="ilbl">Fatos</div><div class="ival">${c.fatos}</div></div>`:''}
        ${c.estrategia?`<div class="icard" style="margin-bottom:6px"><div class="ilbl">Estratégia</div><div class="ival">${c.estrategia}</div></div>`:''}
        ${c.sentenca?`<div class="icard" style="margin-bottom:6px"><div class="ilbl">Sentença</div><div class="ival">${c.sentenca}</div></div>`:''}
      </div>
    </div>
    <div class="tabs">
      <button class="tab on" onclick="sw(this,'tp2')">📋 Andamentos <span class="tc">${cMov.length}</span></button>
      <button class="tab" onclick="sw(this,'tp7')">✅ Tarefas <span class="tc">${vkTasks.filter(function(t){return String(t.processo)===String(c.id)&&!isDone(t);}).length||''}</span></button>
      <button class="tab" onclick="sw(this,'tp4')">💰 Financeiro</button>
      <button class="tab" onclick="sw(this,'tp5')">📅 Compromissos</button>
      <button class="tab" onclick="sw(this,'tp6b')">💬 Comentários</button>
    </div>

    <!-- PROCESSO -->
    
    <!-- AGENDA -->
    <div class="tp" id="tp1">
      ${agFut.length?`
        <div class="sec-header"><span class="sec-lbl gold">⏰ Próximos compromissos</span><div class="sec-line"></div></div>
        ${agFut.map(p=>{const d=diasAte(p.dt_raw);const u=d<=7;return`
          <div class="ai ${u?'urg':'fut'}">
            <div class="adot ${u?'durg':'dfut'}"></div>
            <div style="flex:1"><div class="att" style="font-weight:500">${p.titulo}</div>${p.obs?`<div class="ao">📎 ${p.obs}</div>`:''}</div>
            <div class="adte" style="color:${u?'var(--red)':'var(--ouro)'}">${p.inicio||p.dt_raw}</div>
            ${d<=7?`<div style="font-size:8px;color:var(--red)">${d===0?'HOJE':d===1?'amanhã':`${d}d`}</div>`:''}
          </div>`}).join('')}
        <div style="height:10px"></div>`:''}
      <div class="sec-header">
        <span class="sec-lbl">Histórico (${(c.agenda||[]).length})</span>
        <div class="sec-line"></div>
        <button class="btn-add btn-add-ghost" style="margin-left:10px;flex-shrink:0" onclick="abrirModalPrazo(${c.id})">＋ Novo</button>
      </div>
      ${(c.agenda||[]).length?(c.agenda||[]).map(a=>`
        <div class="ai"><div class="adot ${a.cumprido==='Sim'?'dok':'dpend'}"></div>
          <div style="flex:1"><div class="att">${a.titulo}</div>${a.obs?`<div class="ao">📎 ${a.obs}</div>`:''}</div>
          <div class="adte">${a.inicio}</div>
        </div>`).join(''):`<div class="fempty">Nenhum compromisso histórico</div>`}
    </div>

    <!-- MOVIMENTAÇÕES + TIMELINE LATERAL -->
    <div class="tp on" id="tp2">
      <div class="tp-header">
        <span class="tp-title">📋 Andamentos <span class="tp-title-count">${cMov.length}</span></span>
        <button class="tp-btn" onclick="abrirModalMov(${c.id})">＋ Novo andamento</button>
      </div>
      <div class="pj-mov-layout">
        <div class="pj-mov-list">
          ${cMov.length?cMov.map((m,i)=>{
            const isLocal = m.novo || m.origem;
            const dtDisplay = m.data_movimentacao||m.data||'';
            const txtDisplay = m.movimentacao||m.desc||m.descricao||'';
            const tipoDisplay = m.tipo_movimentacao||'';
            return `<div class="pj-mov-item">
              <div class="pj-mov-ico-col">
                <div class="pj-mov-plus" onclick="abrirModalMov(${c.id})" title="Adicionar">+</div>
                ${tipoDisplay==='DataJud'?'':`<div class="pj-mov-env" onclick="_mvEnviarWpp(${c.id},${i})" title="Enviar ao cliente via WhatsApp">✉</div>`}
              </div>
              <div class="pj-mov-body">
                <span class="pj-mov-date">${fmtDataBR(dtDisplay)}</span> — ${escapeHtml(txtDisplay)}
                <div style="display:flex;gap:6px;margin-top:4px">
                  ${isLocal?`<button class="pj-mov-actbtn" onclick="editarMovimentacao(${c.id},${i})">✏ editar</button>
                  <button class="pj-mov-actbtn pj-mov-actbtn-del" onclick="excluirMovimentacao(${c.id},${i})">🗑 excluir</button>`:''}
                  <button class="pj-mov-actbtn" onclick="_criarTarefaDeAndamento(${c.id},${i})" title="Criar tarefa a partir deste andamento">📋 tarefa</button>
                </div>
              </div>
            </div>`;}).join(''):`<div class="fempty">Nenhum andamento</div>`}
        </div>
        ${cMov.length>0?`<div class="pj-timeline">
          <div class="pj-tl-title">Linha do Tempo</div>
          <div class="pj-tl-track">
            ${cMov.slice(0,15).map((m,i)=>{
              const dt = (m.data_movimentacao||m.data||'').slice(0,10);
              const txt = (m.movimentacao||m.desc||m.descricao||'').slice(0,30);
              const isAg = (m.tipo_movimentacao||'').toLowerCase().includes('audiência') || (txt||'').toLowerCase().includes('audiência');
              const MA2=['Jan','Fev','Mar','Abr','Mai','Jun','Jul','Ago','Set','Out','Nov','Dez'];
              const dtParts = dt.split('-');
              const dtLabel = dtParts.length===3 ? dtParts[2]+'/'+dtParts[1]+'/'+dtParts[0].slice(2) : dt;
              return `<div class="pj-tl-item">
                <div class="pj-tl-dot"><span class="pj-tl-icon">${isAg?'📅':'📋'}</span></div>
                <div class="pj-tl-content">
                  <div class="pj-tl-txt" title="${escapeHtml(m.movimentacao||m.desc||'')}">${escapeHtml(txt)}${txt.length>=30?'…':''}</div>
                </div>
                <div class="pj-tl-date">${dtLabel}</div>
              </div>`;
            }).join('')}
          </div>
        </div>`:''}
      </div>
    </div>

    <!-- PARTES -->
    <div class="tp" id="tp3">
      ${(c.partes||[]).length?`<div class="pgrid">${(c.partes||[]).map(p=>`
        <div class="pcard"><div class="pnome">${p.nome}</div>
          <div class="pcond ${p.condicao==='Autor'?'pa':p.condicao==='Réu'?'pr':p.condicao==='Consultante'?'pco':'pt'}">${p.condicao}${p.cliente==='Sim'?' · <strong>Cliente</strong>':''}</div>
        </div>`).join('')}</div>`:`<div class="fempty">Nenhuma parte cadastrada</div>`}
    </div>

    <!-- TAREFAS DO PROCESSO -->
    <div class="tp" id="tp7">
      <div class="tp-header">
        <span class="tp-title">✅ Tarefas vinculadas</span>
        <button class="tp-btn" onclick="vkNovaTaskPasta(${c.id})">＋ Nova tarefa</button>
      </div>
      <div id="tp7-list-${c.id}">${_renderTarefasPasta(c.id)}</div>
    </div>

    <!-- FINANCEIRO — 4 ABAS -->
    <div class="tp" id="tp4">
      <div class="fin-nav" id="fin-nav-${c.id}">
        <button class="fin-nav-btn on" onclick="_finTab('resumo',${c.id},this)">Resumo</button>
        <button class="fin-nav-btn" onclick="_finTab('honorarios',${c.id},this)">Honorários</button>
        <button class="fin-nav-btn" onclick="_finTab('despesas',${c.id},this)">Despesas</button>
        <button class="fin-nav-btn" onclick="_finTab('repasses',${c.id},this)">Repasses / Banco</button>
      </div>
      <div id="fin-tab-content-${c.id}"></div>
    </div>

    <!-- COMENTÁRIOS -->
    <div class="tp" id="tp6b">
      <div class="tp-header">
        <span class="tp-title">💬 Comentários e Anotações</span>
      </div>
      <!-- Textarea de nova entrada -->
      <div class="coment-input-wrap">
        <textarea
          class="coment-input-ta"
          id="coment-ta-${c.id}"
          placeholder="Escreva um comentário, anotação estratégica ou observação interna..."
          maxlength="1000"
          rows="3"
          oninput="updateComentCount(${c.id})"
          onkeydown="if(event.ctrlKey&&event.key==='Enter') salvarComentarioInline(${c.id})"
        ></textarea>
        <div class="coment-input-footer">
          <span id="coment-count-${c.id}" class="coment-count">0/1000</span>
          <span class="coment-hint">Ctrl+Enter para salvar</span>
          <button class="tp-btn" onclick="salvarComentarioInline(${c.id})">💾 Salvar comentário</button>
        </div>
      </div>
      <!-- Lista cronológica -->
      <div class="tp-header" style="margin-top:16px">
        <span class="tp-title">📝 Histórico</span>
        <span class="tp-title-count">${(comentarios[c.id]||[]).length}</span>
      </div>
      <div id="coment-list-${c.id}">${renderComentarios(c.id)}</div>
    </div>


    <!-- COMPROMISSOS -->
    <div class="tp" id="tp5">
      <div id="tp-agenda-proc-${c.id}">${renderAgendaProc(c.id)}</div>
    </div>
    <div class="tp" id="tp6">
      ${(c.tipo==='consulta'||c.status_consulta==='consulta')?renderPendencias(c):''}
      <div class="coments-wrap" id="coments-${c.id}">
        ${renderComentarios(c.id)}
      </div>
      <div class="coments-input-wrap">
        <textarea class="coments-input" id="coment-inp-${c.id}" maxlength="2000"
          placeholder="Adicionar comentário (máx. 2000 caracteres)..."
          oninput="updateComentCount(${c.id})"></textarea>
        <div class="coments-footer">
          <span class="coments-count" id="coment-cnt-${c.id}">0/2000</span>
          <button class="btn-bordo" onclick="adicionarComentario(${c.id})">＋ Adicionar</button>
        </div>
      </div>
    </div>
  </div><!-- /ficha-main-col -->
  </div><!-- /ficha-layout -->`;


  renderFinBusca(c.id);
  renderFinResumo(c.id);
}






function renderFinBusca(cid){
  const q=(document.getElementById(`fs-${cid}`)||{}).value||'';
  const tp=(document.getElementById(`ft-${cid}`)||{}).value||'';
  const ql=q.toLowerCase();
  const res=ALL_LANC.filter(l=>{
    const m=!ql||(l.hist||"").toLowerCase().includes(ql)||(l.mov||"").toLowerCase().includes(ql);
    return m&&(!tp||l.tipo===tp);
  }).slice(0,100);
  const totR=res.filter(l=>l.tipo==='Receita').reduce((a,l)=>a+l.valor,0);
  const totD=res.filter(l=>l.tipo==='Despesa').reduce((a,l)=>a+l.valor,0);
  const el=document.getElementById(`fbusca-${cid}`);
  if(!el)return;
  if(!res.length){el.innerHTML=`<div class="fempty">Nenhum resultado para "<em>${q}</em>"</div>`;return;}
  el.innerHTML=`${res.map(l=>`<div class="fit">
    <div class="ftp ${l.tipo==='Receita'?'ftr':'ftd'}">${l.tipo==='Receita'?'↑ REC':'↓ DESP'}</div>
    <div class="fdesc"><div class="fcat">${l.mov}</div><div class="fhist">${l.hist||'—'}</div></div>
    <div style="text-align:right"><div class="fval ${l.tipo==='Receita'?'fvp':'fvn'}">${fBRL(l.valor)}</div><div class="fdate">${l.data}</div></div>
  </div>`).join('')}
  <div class="ftotal">
    <div class="ftotitem"><div class="ftotlbl">Receitas</div><div class="ftotval" style="color:#4ade80">${fBRL(totR)}</div></div>
    <div class="ftotitem"><div class="ftotlbl">Despesas</div><div class="ftotval" style="color:#f87676">${fBRL(totD)}</div></div>
    <div class="ftotitem"><div class="ftotlbl">Saldo</div><div class="ftotval" style="color:${totR-totD>=0?'#4ade80':'#f87676'}">${fBRL(totR-totD)}</div></div>
  </div>`;
}

function sw(btn,pid){
  btn.closest('.ficha').querySelectorAll('.tab').forEach(t=>t.classList.remove('on'));
  btn.closest('.ficha').querySelectorAll('.tp').forEach(p=>p.classList.remove('on'));
  btn.classList.add('on'); document.getElementById(pid).classList.add('on');
  if(pid==='tp4' && AC) _finInitTab(AC.id);
}

function _finRemoverSidebar(){
  var sb = document.getElementById('fin-sidebar-panel');
  if(sb) sb.remove();
}

function _finVoltarClientes(){
  var vclWrap = document.querySelector('.vcl-wrap');
  if(vclWrap){
    vclWrap.classList.remove('fin-hidden');
    if(_vclView==='table') vclWrap.classList.add('vcl-full');
  }
  _finRemoverSidebar();
  var vclMain = document.querySelector('.vcl-main');
  if(vclMain){ vclMain.style.display=''; vclMain.style.flexDirection=''; }
  var emp2 = document.getElementById('emp2');
  if(emp2) emp2.style.display='';
  var ficha = document.getElementById('ficha-vcl');
  if(ficha) ficha.innerHTML='';
  AC=null; AC_PROC=null; _grupoAtual=null;
  doSearch();
}

function renderFinExpandido(cid){
  var c = findClientById(cid);
  if(!c) return;

  // Remover sidebar financeira anterior se existir
  _finRemoverSidebar();

  // Criar sidebar financeira na vcl-main
  var vclMain = document.querySelector('.vcl-main');
  if(!vclMain) return;

  var sb = document.createElement('div');
  sb.id = 'fin-sidebar-panel';
  sb.className = 'fin-sidebar';
  vclMain.insertBefore(sb, vclMain.firstChild);
  vclMain.style.display = 'flex';
  vclMain.style.flexDirection = 'row';

  // Esconder resumo inline e botões inline (já estão na sidebar)
  var ri = document.querySelector('.fin-resumo-inline');
  if(ri) ri.style.display = 'none';
  var bi = document.querySelector('.fin-btns-inline');
  if(bi) bi.style.display = 'none';

  _finRenderSidebar(cid);
  renderFinBusca(cid);
}

function _finRenderSidebar(cid){
  var sb = document.getElementById('fin-sidebar-panel');
  if(!sb) return;
  var c = findClientById(cid);
  if(!c) return;

  var fV = function(v){return 'R$ '+Math.abs(v||0).toLocaleString('pt-BR',{minimumFractionDigits:2,maximumFractionDigits:2});};
  var hoje = new Date().toISOString().slice(0,10);
  var locais = (localLanc||[]).filter(function(l){return Number(l.id_processo)===Number(cid);});

  // Cálculos
  var honRec=0, honPend=0, repassePago=0, repassePend=0, desp=0;
  var pendentes=[], recebidos=[];

  locais.forEach(function(l){
    var val  = parseFloat(l.valor||0);
    var pago = isRec(l);
    var isRep= l.tipo==='repasse'||l._repasse_alvara||l._repasse_acordo;
    var isDesp= l.tipo==='despesa'||l.tipo==='despint';

    var isAlvara = l.tipo==='alvara';

    if(isRep){
      if(pago) repassePago+=val; else repassePend+=val;
    } else if(isDesp){
      if(pago) desp+=val;
    } else if(isAlvara){
      // Alvará não entra nos honorários até ser convertido
      if(!pago) pendentes.push(l);
    } else {
      if(pago){ honRec+=val; recebidos.push(l); }
      else { honPend+=val; pendentes.push(l); }
    }
  });

  var saldo = honRec - desp; // repasse é dinheiro do cliente, não custo do escritório

  // Build sidebar HTML
  var html = '';

  // Botão voltar — restaura sidebar de clientes
  html += '<button class="fin-back-btn" onclick="_finVoltarClientes()">'
    +'← Voltar aos clientes</button>';

  // Nome do cliente
  html += '<div style="font-size:14px;font-weight:700;color:var(--tx);margin-bottom:2px">'+escapeHtml(c.cliente||'—')+'</div>';
  if(c.adverso) html += '<div style="font-size:10px;color:var(--mu)">× '+escapeHtml(c.adverso)+'</div>';

  // Card: Saldo
  html += '<div class="fin-sb-card" style="border-color:'+(saldo>=0?'rgba(76,175,125,.3)':'rgba(201,72,74,.3)')+'">'
    +'<div class="fin-sb-card-lbl">Saldo líquido</div>'
    +'<div class="fin-sb-card-val" style="color:'+(saldo>=0?'#4ade80':'#c9484a')+'">'+(saldo>=0?'+':'')+fV(saldo)+'</div>'
  +'</div>';

  // Card: Honorários
  html += '<div class="fin-sb-card">'
    +'<div class="fin-sb-card-lbl">Honorários</div>'
    +'<div class="fin-sb-card-val" style="color:#4ade80">'+fV(honRec)+'</div>'
    +(honPend>0?'<div class="fin-sb-card-sub"><span style="color:#f59e0b">'+fV(honPend)+' pendente</span></div>':'')
  +'</div>';

  // Card: Repasse
  if(repassePago>0 || repassePend>0){
    html += '<div class="fin-sb-card" style="border-color:rgba(201,72,74,.25)">'
      +'<div class="fin-sb-card-lbl">Repasse ao cliente</div>'
      +'<div class="fin-sb-card-val" style="color:#f87676">'+fV(repassePago+repassePend)+'</div>'
      +(repassePend>0?'<div class="fin-sb-card-sub"><span style="color:#c9484a">'+fV(repassePend)+' pendente</span></div>':'<div class="fin-sb-card-sub" style="color:#4ade80">✓ quitado</div>')
    +'</div>';
  }

  // Card: Despesas
  if(desp>0){
    html += '<div class="fin-sb-card">'
      +'<div class="fin-sb-card-lbl">Despesas</div>'
      +'<div class="fin-sb-card-val" style="color:#f87676">'+fV(desp)+'</div>'
    +'</div>';
  }

  // Recebíveis pendentes — lista detalhada
  if(pendentes.length){
    html += '<div style="margin-top:6px">';
    html += '<div class="fin-sb-title">Recebíveis pendentes ('+pendentes.length+')</div>';
    pendentes.sort(function(a,b){return (a.venc||a.data||'').localeCompare(b.venc||b.data||'');}).forEach(function(l){
      var vencido = l.venc && l.venc < hoje;
      html += '<div class="fin-sb-item">'
        +'<div style="min-width:0">'
          +'<div style="font-size:11px;font-weight:600;color:var(--tx);overflow:hidden;text-overflow:ellipsis;white-space:nowrap">'+escapeHtml(l.desc||'—')+'</div>'
          +'<div style="font-size:9px;color:'+(vencido?'#c9484a':'var(--mu)')+'">'+fDt(l.venc||l.data)+(vencido?' · Vencido':'')+'</div>'
        +'</div>'
        +'<span style="font-size:12px;font-weight:700;color:'+(vencido?'#c9484a':'#86efac')+'">'+fV(l.valor)+'</span>'
      +'</div>';
    });
    html += '</div>';
  }

  // Botões de ação
  html += '<div style="display:flex;gap:6px;margin-top:auto;padding-top:10px">'
    +'<button onclick="abrirModalFin('+cid+',\'receber\')" class="fin-sb-btn" style="background:rgba(76,175,125,.1);color:#4ade80">➕ Entrada</button>'
    +'<button onclick="abrirModalFin('+cid+',\'pagar\')" class="fin-sb-btn" style="background:rgba(248,118,118,.07);color:#f87676">➖ Saída</button>'
  +'</div>';

  sb.innerHTML = html;
}

function renderTasks(cid){
  const list=tasks[cid]||[];
  const visiveis = list.filter(function(t){ return !t.deleted; });
  if(!visiveis.length)return`<div class="fempty">Nenhuma tarefa adicionada</div>`;
  // Preserva o índice original (i) para que os handlers onclick acertem o item certo
  // mesmo com tombstones inline (itens com deleted:true são pulados).
  return list.map((t,i)=>{
    if(t.deleted) return '';
    return `<div class="titem">
      <input type="checkbox" class="tcb" ${t.done?'checked':''} onchange="toggleTask(${cid},${i})">
      <span class="ttxt ${t.done?'done':''}">${t.text}</span>
      <span class="tetapa ${t.etapa==='A FAZER'?'ef':t.etapa==='FAZENDO'?'ez':'eo'}">${t.etapa}</span>
      <button class="tdel" onclick="delTask(${cid},${i})">✕</button>
    </div>`;
  }).join('');
}
function addTask(cid){
  var inp=document.getElementById('ti-'+cid); if(!inp) return;
  var sel=document.getElementById('te-'+cid);
  var txt=inp.value.trim(); var et=sel?sel.value:'';
  if(!txt) return;
  if(!tasks[cid]) tasks[cid]=[];
  tasks[cid].push({text:txt,etapa:et,done:et==='FEITO'});
  sbSet('co_tasks', tasks); marcarAlterado();
  inp.value='';
  var tl=document.getElementById('tl-'+cid); if(tl) tl.innerHTML=renderTasks(cid);
  showToast('Tarefa adicionada');
}
function toggleTask(cid,i){
  if(!tasks[cid]||!tasks[cid][i]) return;
  tasks[cid][i].done=!tasks[cid][i].done;
  if(tasks[cid][i].done) tasks[cid][i].etapa='FEITO';
  sbSet('co_tasks', tasks);
    marcarAlterado();document.getElementById(`tl-${cid}`).innerHTML=renderTasks(cid);}
function delTask(cid,i){
  abrirModal('Excluir tarefa','<div style="font-size:13px;color:var(--mu)">Excluir esta tarefa?</div>',function(){
    // Inline tombstone: tasks[cid] \u00e9 nested (objeto-de-arrays), sem suporte
    // ao _tombstoneAdd array. Marca deleted:true para sobreviver ao merge
    // de sync \u2014 renderTasks filtra inline, mantendo \u00edndices.
    if(!tasks[cid]||!tasks[cid][i]){ fecharModal(); return; }
    tasks[cid][i] = Object.assign({}, tasks[cid][i], {deleted:true, deleted_at:new Date().toISOString()});
    sbSet('co_tasks',tasks);
    marcarAlterado();fecharModal();
    var el=document.getElementById('tl-'+cid);if(el)el.innerHTML=renderTasks(cid);showToast('Tarefa exclu\u00edda');
  },'Excluir');
  setTimeout(function(){var b=document.getElementById('modal-save');if(b){b.style.background='var(--red)';b.textContent='Confirmar';}},50);
}
function saveNote(cid){
  notes[cid]=document.getElementById(`obs-${cid}`)?.value||'';
  sbSet('co_notes', notes);
  marcarAlterado();
  var s=document.getElementById(`osv-${cid}`);
  if(s){ s.style.opacity='1'; setTimeout(function(){ if(s) s.style.opacity='0'; },2000); }
  showToast('Observação salva');
}
function showToast(msg){const t=document.getElementById('toast');t.textContent='✓ '+msg;t.classList.add('on');setTimeout(()=>t.classList.remove('on'),2200);}

// ═══════════════════════════════════════════════════════════════
// CALCULADORA DE PRAZOS JUDICIAIS
// ═══════════════════════════════════════════════════════════════

// ── Feriados nacionais fixos (MM-DD) ────────────────────────
const FERIADOS_NAC = [
  '01-01','04-21','05-01','09-07','10-12','11-02','11-15','11-20','12-25'
];

// ── Feriados nacionais móveis: calculados por ano ────────────
function calcFeriadosMoveis(ano){
  // Páscoa (algoritmo de Butcher)
  const a=ano%19, b=Math.floor(ano/100), c=ano%100;
  const d=Math.floor(b/4), e=b%4, f=Math.floor((b+8)/25);
  const g=Math.floor((b-f+1)/3), h=(19*a+b-d-g+15)%30;
  const i=Math.floor(c/4), k=c%4, l=(32+2*e+2*i-h-k)%7;
  const m=Math.floor((a+11*h+22*l)/451);
  const mes=Math.floor((h+l-7*m+114)/31);
  const dia=(h+l-7*m+114)%31+1;
  const pascoa = new Date(ano, mes-1, dia);

  const addDias = (d,n) => { const r=new Date(d); r.setDate(r.getDate()+n); return r; };
  const iso = d => d.toISOString().slice(5,10); // MM-DD

  return [
    iso(addDias(pascoa,-48)),  // Carnaval (segunda)
    iso(addDias(pascoa,-47)),  // Carnaval (terça)
    iso(addDias(pascoa,-2)),   // Sexta-Feira Santa
    iso(pascoa),               // Páscoa
    iso(addDias(pascoa,60)),   // Corpus Christi
  ];
}

// ── Feriados estaduais (MM-DD) ───────────────────────────────
const FERIADOS_EST = {
  MG: ['04-21','07-09'],          // Tiradentes (também nac), Revolução Constitucionalista MG
  SP: ['07-09','11-20'],
  RJ: ['01-20','04-23','11-20'],  // São Sebastião, São Jorge, Consciência Negra
  RS: ['09-20'],                   // Revolução Farroupilha
  PR: ['12-19'],                   // Emancipação PR
  SC: ['08-11'],                   // Criação SC
  BA: ['07-02'],                   // Independência BA
  ES: ['10-28'],                   // Criação ES
  GO: ['10-24'],                   // Pedra Fundamental GO
  DF: ['04-21'],                   // Fundação Brasília
  MT: ['11-14'],                   // Proclamação MT
  MS: ['10-11'],                   // Criação MS
  PA: ['08-15'],                   // Adesão PA
  CE: ['03-25'],                   // Data Magna CE
  PE: ['03-06'],                   // Revolução PE
  outro: [],
};

// ── Suspensões coletivas (YYYY-MM-DD a YYYY-MM-DD) ──────────
// Recesso forense nacional + TRTs principais
const SUSPENSOES = [
  // Recesso de fim de ano (20/dez a 06/jan aprox — varia por ano)
  { de:'2025-12-20', ate:'2026-01-06', trib:'todos', label:'Recesso fim de ano 2025/2026' },
  { de:'2026-12-20', ate:'2027-01-06', trib:'todos', label:'Recesso fim de ano 2026/2027' },
  // Recesso de julho (01 a 31/jul — TRTs e TJs estaduais)
  { de:'2025-07-01', ate:'2025-07-31', trib:'tj_trt', label:'Recesso julho 2025 (TRT/TJ)' },
  { de:'2026-07-01', ate:'2026-07-31', trib:'tj_trt', label:'Recesso julho 2026 (TRT/TJ)' },
];

// ── Verificar se data é feriado ou dia suspenso ──────────────
function calcEhFeriado(dt, estado, tribunal){
  const ano  = dt.getFullYear();
  const mmdd = dt.toISOString().slice(5,10);
  const iso  = dt.toISOString().slice(0,10);

  // Fim de semana
  const dow = dt.getDay();
  if(dow===0||dow===6) return {eh:true, motivo:'fim de semana'};

  // Feriados nacionais fixos
  if(FERIADOS_NAC.includes(mmdd)) return {eh:true, motivo:'feriado nacional'};

  // Feriados móveis
  const moveis = calcFeriadosMoveis(ano);
  if(moveis.includes(mmdd)) return {eh:true, motivo:'feriado nacional (móvel)'};

  // Feriados estaduais
  const fEst = FERIADOS_EST[estado]||[];
  if(fEst.includes(mmdd)) return {eh:true, motivo:'feriado estadual ('+estado+')'};

  // Suspensões coletivas
  for(const s of SUSPENSOES){
    if(iso>=s.de && iso<=s.ate){
      const trib = tribunal||'';
      if(s.trib==='todos') return {eh:true, motivo:s.label};
      if(s.trib==='tj_trt' && (trib.startsWith('clt')||trib.startsWith('cpc')||trib==='tst'))
        return {eh:true, motivo:s.label};
    }
  }
  return {eh:false};
}

// ── Tipos de prazo por tribunal ──────────────────────────────
const CALC_TIPOS = {
  clt: [
    {v:'contestacao',    l:'Contestação',               d:5,  unit:'uteis', obs:'Art. 847 CLT'},
    {v:'recurso_ord',    l:'Recurso Ordinário',          d:8,  unit:'uteis', obs:'Art. 895 CLT'},
    {v:'embargos_decl',  l:'Embargos de Declaração',     d:5,  unit:'uteis', obs:'Art. 897-A CLT'},
    {v:'agravo_regimental',l:'Agravo Regimental',        d:8,  unit:'uteis', obs:'CLT'},
    {v:'contrarrazoes',  l:'Contrarrazões',              d:8,  unit:'uteis', obs:'CLT'},
    {v:'impugnacao',     l:'Impugnação à sentença',      d:5,  unit:'uteis', obs:'CLT'},
    {v:'execucao',       l:'Embargos à execução',        d:5,  unit:'uteis', obs:'Art. 884 CLT'},
    {v:'calculos',       l:'Impugnação aos cálculos',    d:5,  unit:'uteis', obs:'CLT'},
    {v:'notificacao',    l:'Prazo de notificação (CLT)', d:1,  unit:'uteis', obs:'Conta a partir do recebimento'},
    {v:'quesitos',       l:'Quesitos periciais',          d:10, unit:'uteis', obs:'Art. 826 CLT'},
    {v:'impug_laudo',    l:'Impugnação ao laudo pericial', d:10, unit:'uteis', obs:'Art. 827 CLT'},
    {v:'calc_liquidacao',l:'Cálculos de liquidação',       d:10, unit:'uteis', obs:'Art. 879 CLT'},
    {v:'impug_contest',  l:'Impugnação à contestação',     d:10, unit:'uteis', obs:'Art. 351 CPC c/c CLT'},
  ],
  clt_sum: [
    {v:'contestacao',    l:'Resposta (sumaríssimo)',      d:5,  unit:'uteis', obs:'Art. 852-B CLT'},
    {v:'recurso_ord',    l:'Recurso Ordinário',           d:8,  unit:'uteis', obs:'Art. 895 CLT'},
    {v:'embargos_decl',  l:'Embargos de Declaração',      d:5,  unit:'uteis', obs:'Art. 897-A CLT'},
  ],
  tst: [
    {v:'rr_airr',        l:'RR / AIRR',                   d:8,  unit:'uteis', obs:'Art. 896 CLT'},
    {v:'embargos_tst',   l:'Embargos TST',                d:8,  unit:'uteis', obs:'Art. 894 CLT'},
    {v:'agravo_inst',    l:'Agravo de Instrumento',       d:8,  unit:'uteis', obs:'CLT'},
    {v:'embargos_decl',  l:'Embargos de Declaração TST',  d:5,  unit:'uteis', obs:'CLT'},
    {v:'contrarrazoes',  l:'Contrarrazões TST',           d:8,  unit:'uteis', obs:'CLT'},
  ],
  cpc: [
    {v:'contestacao',    l:'Contestação',                 d:15, unit:'uteis', obs:'Art. 335 CPC'},
    {v:'apelacao',       l:'Apelação',                    d:15, unit:'uteis', obs:'Art. 1003 CPC'},
    {v:'embargos_decl',  l:'Embargos de Declaração',      d:5,  unit:'uteis', obs:'Art. 1023 CPC'},
    {v:'agravo_inst',    l:'Agravo de Instrumento',       d:15, unit:'uteis', obs:'Art. 1003 CPC'},
    {v:'agravo_int',     l:'Agravo Interno',              d:15, unit:'uteis', obs:'Art. 1021 CPC'},
    {v:'contrarrazoes',  l:'Contrarrazões',               d:15, unit:'uteis', obs:'Art. 1010 CPC'},
    {v:'impugnacao_exec',l:'Impugnação ao cumprimento',   d:15, unit:'uteis', obs:'Art. 525 CPC'},
    {v:'excepcao_preexec',l:'Embargos à execução (CPC)',  d:15, unit:'uteis', obs:'Art. 915 CPC'},
    {v:'manifestacao',   l:'Manifestação geral',          d:15, unit:'uteis', obs:'CPC'},
    {v:'replica',        l:'Réplica',                     d:15, unit:'uteis', obs:'Art. 351 CPC'},
    {v:'memorial',       l:'Memorial / alegações finais', d:15, unit:'uteis', obs:'Art. 364 CPC'},
  ],
  cpc_sum: [
    {v:'contestacao',    l:'Contestação (JEC)',            d:15, unit:'uteis', obs:'Lei 9.099/95'},
    {v:'recurso_jec',    l:'Recurso Inominado (JEC)',      d:10, unit:'corridos', obs:'Art. 42 Lei 9.099/95'},
    {v:'embargos_decl',  l:'Embargos de Declaração (JEC)', d:5,  unit:'corridos', obs:'Lei 9.099/95'},
  ],
  stj: [
    {v:'resp',           l:'Recurso Especial',             d:15, unit:'uteis', obs:'Art. 1003 CPC'},
    {v:'agravo_resp',    l:'Agravo em REsp',               d:15, unit:'uteis', obs:'Art. 1042 CPC'},
    {v:'embargos_diverg',l:'Embargos de Divergência',      d:15, unit:'uteis', obs:'Art. 1043 CPC'},
    {v:'embargos_decl',  l:'Embargos de Declaração STJ',   d:5,  unit:'uteis', obs:'CPC'},
    {v:'contrarrazoes',  l:'Contrarrazões STJ',            d:15, unit:'uteis', obs:'CPC'},
  ],
  livre: [
    {v:'livre',          l:'Prazo personalizado',          d:0,  unit:'uteis', obs:''},
  ],
};

// ── Estado da calculadora ────────────────────────────────────
let _calcHistorico = [];

// ── Inicializar calculadora ──────────────────────────────────
function calcRender(){
  calcAtualizarTipos();
  // Preencher datalist de pastas
  const dl = document.getElementById('calc-pasta-list');
  if(dl) dl.innerHTML = CLIENTS.map(c=>'<option value="'+c.cliente+'">').join('');
  // Data default = hoje
  const dp = document.getElementById('calc-data-pub');
  if(dp && !dp.value) dp.value = new Date().toISOString().slice(0,10);
  calcRenderHistorico();
  calcAtualizar();
}

function calcAtualizarTipos(){
  const trib = document.getElementById('calc-tribunal')?.value||'clt';
  const sel  = document.getElementById('calc-tipo-prazo');
  if(!sel) return;
  const tipos = CALC_TIPOS[trib]||[];
  sel.innerHTML = '<option value="">— selecionar —</option>'
    + tipos.map(t=>'<option value="'+t.v+'">'+t.l+' ('+t.d+(t.unit==='uteis'?' dias úteis':' dias corridos')+')</option>').join('');
  // Mostrar/esconder campo de dias livres
  const lw = document.getElementById('calc-livre-wrap');
  if(lw) lw.style.display = trib==='livre'?'block':'none';
  calcAtualizar();
}

// ── Cálculo principal ────────────────────────────────────────
function calcAtualizar(){
  const trib  = document.getElementById('calc-tribunal')?.value||'clt';
  const tipo  = document.getElementById('calc-tipo-prazo')?.value||'';
  const dtPub = document.getElementById('calc-data-pub')?.value||'';
  const estado= document.getElementById('calc-estado')?.value||'MG';
  if(!dtPub || !tipo) { document.getElementById('calc-resultado').style.display='none'; return; }

  const tipos = CALC_TIPOS[trib]||[];
  const tipoDef = tipos.find(t=>t.v===tipo);
  if(!tipoDef) return;

  let diasTotal = tipoDef.d;
  if(trib==='livre'){
    diasTotal = parseInt(document.getElementById('calc-dias-livres')?.value)||15;
  }

  // Data de início da contagem:
  // CLT art. 775 + OJ 1 SDI-2 TST: exclui o dia da publicação, conta a partir do 1º dia útil seguinte
  // CPC art. 224: mesmo critério — exclui o dia da intimação, conta do próximo dia útil
  let inicio = new Date(dtPub + 'T12:00:00');

  // Excluir o dia da publicação/intimação (regra uniforme CLT e CPC)
  inicio.setDate(inicio.getDate() + 1);

  // Avançar se for dia não útil
  while(calcEhFeriado(inicio, estado, trib).eh){
    inicio.setDate(inicio.getDate() + 1);
  }

  const feriadosNoPeriodo = [];
  let atual = new Date(inicio);
  let diasContados = 0;

  if(tipoDef.unit === 'corridos'){
    // Dias corridos — apenas pular feriados nacionais e fins de semana
    let diasCorridos = 0;
    while(diasCorridos < diasTotal){
      const f = calcEhFeriado(atual, estado, trib);
      if(!f.eh){
        diasCorridos++;
      } else {
        feriadosNoPeriodo.push({data:new Date(atual), motivo:f.motivo});
      }
      if(diasCorridos < diasTotal) atual.setDate(atual.getDate()+1);
    }
    diasContados = diasTotal;
  } else {
    // Dias úteis
    while(diasContados < diasTotal){
      const f = calcEhFeriado(atual, estado, trib);
      if(!f.eh){
        diasContados++;
      } else {
        feriadosNoPeriodo.push({data:new Date(atual), motivo:f.motivo});
      }
      if(diasContados < diasTotal) atual.setDate(atual.getDate()+1);
    }
  }

  // O prazo vence no último dia contado (atual)
  const vencimento = new Date(atual);

  // Se vencimento cair em feriado/fim de semana, prorrogar para próximo dia útil
  while(calcEhFeriado(vencimento, estado, trib).eh){
    vencimento.setDate(vencimento.getDate()+1);
  }

  // Formatar resultado
  const fmtCompleto = d => {
    const dias = ['domingo','segunda','terça','quarta','quinta','sexta','sábado'];
    return fmtDataBR(d.toISOString().slice(0,10)) + ' (' + dias[d.getDay()] + ')';
  };

  const diasCorrTotais = Math.round((vencimento - new Date(dtPub+'T12:00:00'))/(86400000));

  // Exibir resultado
  const res = document.getElementById('calc-resultado');
  res.style.display = 'block';
  document.getElementById('calc-res-label').textContent =
    tipoDef.l + ' — ' + trib.toUpperCase() + ' · ' + estado;
  document.getElementById('calc-res-data').textContent = fmtCompleto(vencimento);
  document.getElementById('calc-res-sub').textContent =
    'Início da contagem: ' + fmtDataBR(inicio.toISOString().slice(0,10))
    + '  ·  Publicação: ' + fmtDataBR(dtPub)
    + (tipoDef.obs ? '  ·  ' + tipoDef.obs : '');
  document.getElementById('calc-res-dias').textContent = diasContados;
  document.getElementById('calc-res-feriados').textContent =
    feriadosNoPeriodo.length
      ? feriadosNoPeriodo.length + ' feriado(s)/suspensão(ões) excluído(s) · ' + diasCorrTotais + ' dias corridos no total'
      : 'Nenhum feriado no período · ' + diasCorrTotais + ' dias corridos no total';

  // Linha do tempo
  calcRenderTimeline(dtPub, inicio, vencimento, estado, trib);

  // Feriados encontrados
  const fw = document.getElementById('calc-feriados-wrap');
  const fl = document.getElementById('calc-feriados-list');
  const ferUniq = [...new Map(feriadosNoPeriodo.map(f=>[f.data.toISOString().slice(0,10),f])).values()];
  if(ferUniq.length){
    fw.style.display = 'block';
    fl.innerHTML = ferUniq.map(f=>
      '<span style="background:var(--sf3);border:1px solid var(--bd);border-radius:6px;padding:3px 9px;font-size:11px;color:var(--mu)">'
      + fmtDataBR(f.data.toISOString().slice(0,10)) + ' — ' + f.motivo + '</span>'
    ).join('');
  } else {
    fw.style.display = 'none';
  }

  // Botão salvar pasta
  const pasta = document.getElementById('calc-pasta-busca')?.value.trim();
  const btnSalvar = document.getElementById('calc-btn-salvar');
  if(btnSalvar) btnSalvar.style.display = pasta ? 'inline-flex' : 'none';

  // Guardar para histórico
  _calcUltimo = {
    trib, tipo, tipoDef, dtPub, estado,
    vencimento: vencimento.toISOString().slice(0,10),
    inicio: inicio.toISOString().slice(0,10),
    diasContados, feriados: ferUniq.length, pasta
  };
}

function calcRenderTimeline(dtPub, inicio, vencimento, estado, trib){
  const tl = document.getElementById('calc-timeline');
  const tc = document.getElementById('calc-timeline-content');
  if(!tl||!tc) return;
  tl.style.display = 'block';

  const etapas = [
    { label:'Publicação / Intimação', data:new Date(dtPub+'T12:00:00'), cor:'var(--mu)' },
    { label:'Início da contagem',      data:inicio,                       cor:'var(--ouro)' },
    { label:'Vencimento do prazo',     data:vencimento,                   cor:'#4ade80' },
  ];

  // Alertas intermediários (50% e 75% do prazo)
  const total = Math.round((vencimento - inicio)/86400000);
  if(total > 6){
    const meio = new Date(inicio); meio.setDate(meio.getDate() + Math.round(total*0.5));
    const tresq = new Date(inicio); tresq.setDate(tresq.getDate() + Math.round(total*0.75));
    etapas.splice(2, 0,
      { label:'Alerta 50%', data:meio, cor:'#fbbf24' },
      { label:'Alerta 75%', data:tresq, cor:'#f87676' },
    );
  }

  tc.innerHTML = etapas.map((e,i)=>
    '<div style="display:flex;align-items:center;gap:12px;padding:8px 0;'+(i<etapas.length-1?'border-bottom:1px solid var(--bd)':'')+'">'
      +'<div style="width:10px;height:10px;border-radius:50%;background:'+e.cor+';flex-shrink:0"></div>'
      +'<div style="flex:1;font-size:12px;color:var(--tx)">'+e.label+'</div>'
      +'<div style="font-size:12px;font-weight:600;color:'+e.cor+'">'+fmtDataBR(e.data.toISOString().slice(0,10))+'</div>'
    +'</div>'
  ).join('');
}

// ── Salvar prazo na pasta do cliente ────────────────────────
let _calcUltimo = null;
function calcSalvarPrazo(){
  if(!_calcUltimo) return;
  const pasta = _calcUltimo.pasta;
  const cli   = CLIENTS.find(c=>c.cliente===pasta);
  if(!cli){ showToast('Pasta não encontrada'); return; }
  if(!prazos[cli.id]) prazos[cli.id]=[];
  const novo = {
    id: 'calc_'+genId(),
    titulo: _calcUltimo.tipoDef.l,
    tipo: 'fatal',
    data: _calcUltimo.vencimento,
    obs: 'Calculado pelo app · '+_calcUltimo.trib.toUpperCase()+' · '+_calcUltimo.estado,
    cumprido: false,
  };
  prazos[cli.id].push(novo);
  prazosSalvar(); // salva em co_prazos + co_td (legado)
  marcarAlterado();
  // Adicionar ao histórico
  _calcHistorico.unshift({..._calcUltimo, savedPasta: pasta, ts: Date.now()});
  if(_calcHistorico.length>10) _calcHistorico.pop();
  calcRenderHistorico();
  showToast('✅ Prazo salvo na pasta de '+pasta);
}

// ── Adicionar à agenda ───────────────────────────────────────
function calcAdicionarAgenda(){
  if(!_calcUltimo) return;
  if(!localAg) localAg=[];
  const novo = {
    id: 'calc_ag_'+genId(),
    titulo: _calcUltimo.tipoDef.l,
    tipo_compromisso: 'Prazo',
    dt_raw: _calcUltimo.vencimento,
    inicio: _calcUltimo.vencimento,
    obs: _calcUltimo.trib.toUpperCase()+' · '+_calcUltimo.estado+' · '+_calcUltimo.tipoDef.obs,
    cliente: _calcUltimo.pasta||'',
  };
  localAg.push(novo); invalidarAllPend();
  sbSet('co_ag', localAg);
  marcarAlterado();
  atualizarStats();
  showToast('📅 Adicionado à Agenda: '+fmtDataBR(_calcUltimo.vencimento));
}

// ── Copiar data ──────────────────────────────────────────────
function calcCopiar(){
  if(!_calcUltimo) return;
  const txt = fmtDataBR(_calcUltimo.vencimento);
  navigator.clipboard?.writeText(txt).then(()=>showToast('Data copiada: '+txt))
    .catch(()=>showToast('Data: '+txt));
}

// ── Limpar ───────────────────────────────────────────────────
function calcLimpar(){
  ['calc-tribunal','calc-tipo-prazo','calc-estado'].forEach(id=>{
    const el=document.getElementById(id); if(el) el.selectedIndex=0;
  });
  ['calc-data-pub','calc-pasta-busca'].forEach(id=>{
    const el=document.getElementById(id); if(el) el.value='';
  });
  const dp = document.getElementById('calc-data-pub');
  if(dp) dp.value = new Date().toISOString().slice(0,10);
  document.getElementById('calc-resultado').style.display='none';
  document.getElementById('calc-timeline').style.display='none';
  document.getElementById('calc-feriados-wrap').style.display='none';
  calcAtualizarTipos();
}

// ── Histórico de cálculos ────────────────────────────────────
function calcRenderHistorico(){
  const el = document.getElementById('calc-historico');
  if(!el) return;
  if(!_calcHistorico.length){
    el.innerHTML = '<div style="font-size:12px;color:var(--mu);font-style:italic">Nenhum cálculo realizado ainda.</div>';
    return;
  }
  el.innerHTML = _calcHistorico.map(c=>
    '<div style="display:flex;align-items:center;gap:10px;padding:8px 10px;background:var(--sf2);border:1px solid var(--bd);border-radius:7px;margin-bottom:6px">'
      +'<div style="flex:1">'
        +'<div style="font-size:12px;font-weight:600;color:var(--tx)">'+c.tipoDef.l+'</div>'
        +'<div style="font-size:10px;color:var(--mu)">'+c.trib.toUpperCase()+' · '+c.estado+' · Pub: '+fmtDataBR(c.dtPub)+'</div>'
        +(c.savedPasta?'<div style="font-size:10px;color:var(--ouro)">Salvo: '+c.savedPasta+'</div>':'')
      +'</div>'
      +'<div style="text-align:right">'
        +'<div style="font-size:14px;font-weight:700;color:#4ade80">'+fmtDataBR(c.vencimento)+'</div>'
        +'<div style="font-size:10px;color:var(--mu)">'+c.diasContados+' dias úteis</div>'
      +'</div>'
    +'</div>'
  ).join('');
}

// ── goView: adicionar callback para calc ─────────────────────
// (já registrado via onclick="goView('vcalc',this);calcRender()")


// ── Funções faltantes / stubs ─────────────────────────────

// vfFiltrar — filtra tabela financeira por busca/mês/status
function vfFiltrar(){
  const q   = (document.getElementById('vf-busca')?.value||'').toLowerCase();
  const mes = document.getElementById('vf-fmes')?.value||'';
  const st  = document.getElementById('vf-fstatus')?.value||'';
  document.querySelectorAll('#vf-tabela tbody tr').forEach(tr=>{
    const ok = (!q  || (tr.dataset.desc||'').includes(q))
            && (!mes|| tr.dataset.mes===mes)
            && (!st || tr.dataset.status===st);
    tr.style.display = ok ? '' : 'none';
  });
}

// deletarPrazo — exclui prazo da pasta do cliente
function deletarPrazo(cid, pid){
  abrirModal('Excluir prazo','<div style="font-size:13px;color:var(--mu)">Excluir este prazo permanentemente?</div>',function(){
    fecharModal();
    if(!prazos[cid]) return;
    // Inline tombstone: prazos é objeto-de-arrays (nested por cid).
    // Marca deleted:true em vez de splice — evita ressurreição no merge.
    // Renders filtram !p.deleted.
    prazos[cid] = prazos[cid].map(function(p){
      if(p.id===pid || String(p.id)===String(pid)){
        return Object.assign({}, p, {deleted:true, deleted_at:new Date().toISOString()});
      }
      return p;
    });
    prazosSalvar(); // salva em co_prazos E co_td
    marcarAlterado();
    // Também remover de localAg se foi migrado — com tombstone array (flat)
    var agsRemovidos = (localAg||[]).filter(function(a){ return String(a._prazo_legado_id)===String(pid); });
    agsRemovidos.forEach(function(a){
      _tombstoneAdd('co_ag', a.id);
      _tombstoneAdd('co_localAg', a.id);
    });
    if(agsRemovidos.length){
      localAg = (localAg||[]).filter(function(a){ return String(a._prazo_legado_id)!==String(pid); });
      sbSet('co_ag', localAg); invalidarAllPend();
    }
    // Re-renderizar
    var wrap = document.querySelector('#prazo-'+cid+'-'+pid)?.closest('.prazos-wrap')?.parentElement;
    if(wrap) wrap.innerHTML = renderPrazos(cid);
    var elAg = document.getElementById('tp-agenda-proc-'+cid);
    if(elAg) elAg.innerHTML = renderAgendaProc(cid);
    showToast('Prazo exclu\u00eddo');
  }, 'Excluir');
}

// abrirModalPrazo — redireciona para modal de compromisso unificado
function abrirModalPrazo(cid){
  _abrirModalCompromisso(cid||null);
}

// abrirConsulta — abre ficha de consulta/atendimento
function abrirConsulta(id){
  const c = findClientById(id);
  if(c) openC(c.id);
  else showToast('Consulta não encontrada');
}

// vkConcluirComDesfecho — conclui tarefa do Kanban com modal de desfecho
function vkConcluirComDesfecho(id){
  const t = vkTasks.find(x=>x.id===id||String(x.id)===String(id));
  if(!t){ showToast('Tarefa nao encontrada'); return; }
  // Sem backtick aninhado — concatenacao de string
  const clienteDiv = t.cliente
    ? '<div style="font-size:11px;color:var(--mu);margin-top:3px">'+t.cliente+'</div>'
    : '';
  const bodyHtml = '<div style="margin-bottom:12px">'
    +'<div style="font-size:14px;font-weight:600;color:var(--tx)">'+(t.titulo||'Tarefa')+'</div>'
    +clienteDiv
    +'</div>'
    +'<div>'
      +'<label class="fm-lbl">Desfecho / resultado</label>'
      +'<textarea class="fm-inp" id="vkd-obs" rows="3" placeholder="Descreva o que foi feito, resultado obtido..."></textarea>'
    +'</div>'
    +'<div style="margin-top:8px">'
      +'<label class="fm-lbl">Proximo ato (opcional)</label>'
      +'<input class="fm-inp" id="vkd-prox" placeholder="Ex: Aguardar publicacao, Protocolar recurso...">'
    +'</div>';
  abrirModal('Concluir Tarefa', bodyHtml, ()=>{
    const obs  = document.getElementById('vkd-obs')?.value.trim()||'';
    const prox = document.getElementById('vkd-prox')?.value.trim()||'';
    const idx2 = vkTasks.findIndex(x=>x.id===id||String(x.id)===String(id));
    if(idx2>=0){
      vkTasks[idx2] = {...vkTasks[idx2], status:'done',
        concluido_em: new Date().toISOString().slice(0,10),
        desfecho: obs, proximo_ato: prox };
      // Se tem proximo ato, criar nova tarefa na coluna 'todo'
      if(prox){
        vkTasks.push({
          id: 'vk'+genId(),
          titulo: prox,
          tipo: vkTasks[idx2].tipo||'outro',
          status: 'todo',
          responsavel: vkTasks[idx2].responsavel||'Clarissa',
          prioridade: 'media',
          cliente: vkTasks[idx2].cliente||'',
          processo: vkTasks[idx2].processo||0,
          criado_em: new Date().toISOString().slice(0,10),
          obs: 'Proximo ato de: '+(vkTasks[idx2].titulo||'tarefa anterior')
        });
      }
    }
    vkSalvar();
    vkRender();
    fecharModal();
    audit('tarefa','Tarefa: '+(t.titulo||'')+(prox?' -> '+prox:''),'tarefa');
    showToast('Tarefa concluida' + (prox ? ' — proximo ato criado' : '') + ' ✓');
  }, 'Concluir');
}


// Painel de honorarios contratados por pasta
function renderHonorariosPasta(cid){
  const c = findClientById(cid);
  if(!c) return '';
  const h = c._hon_contrato||{};
  const perc = parseFloat(h.perc)||0;

  if(!perc){
    return ''; // Sem contrato definido — não mostrar nada
  }

  return '<div style="display:flex;align-items:center;gap:10px;padding:5px 0;margin-bottom:8px">'
    +'<span style="font-size:10px;color:var(--mu)">Honorários:</span>'
    +'<span style="font-size:13px;font-weight:700;color:#4ade80">'+perc+'%</span>'
    +'<span style="font-size:10px;color:var(--mu)">'+(h.base_calc||'sobre valor acordado')+'</span>'
    +'<button onclick="editarHonorariosPasta('+cid+')" style="font-size:10px;padding:2px 7px;border-radius:4px;background:var(--sf3);border:1px solid var(--bd);color:var(--mu);cursor:pointer">✏</button>'
    +'<button onclick="abrirModalFin('+cid+',\'receber\')" style="margin-left:auto;font-size:10px;padding:2px 9px;border-radius:4px;background:rgba(76,175,125,.1);border:1px solid rgba(76,175,125,.25);color:#4ade80;cursor:pointer">+ Acordo '+perc+'%</button>'
  +'</div>';
}

function editarHonorariosPasta(cid){
  const c = findClientById(cid);
  if(!c) return;
  const h = c._hon_contrato||{};
  abrirModal('Honorarios — '+c.cliente,
    '<div style="margin-bottom:10px">'
      +'<label class="fm-lbl">Modalidade</label>'
      +'<select class="fm-inp" id="hm-mod" onchange="document.getElementById(\'hm-perc-row\').style.display=this.value===\'percentual\'?\'flex\':\'none\'">'
        +'<option value="fixo"'+(( h.mod||'fixo')==='fixo'?' selected':'')+'>Valor fixo</option>'
        +'<option value="percentual"'+(h.mod==='percentual'?' selected':'')+'>Percentual sobre resultado</option>'
      +'</select>'
    +'</div>'
    +'<div class="fm-row">'
      +'<div><label class="fm-lbl">Valor do contrato (R$)</label>'
        +'<input class="fm-inp" type="number" id="hm-valor" value="'+(h.valor||'')+'" min="0" step="0.01" placeholder="0,00"></div>'
    +'</div>'
    +'<div class="fm-row" id="hm-perc-row" style="display:'+(h.mod==='percentual'?'flex':'none')+';margin-top:8px">'
      +'<div><label class="fm-lbl">Base de calculo (R$)</label>'
        +'<input class="fm-inp" type="number" id="hm-base" value="'+(h.base||'')+'" min="0" step="0.01" placeholder="Valor do acordo"></div>'
      +'<div><label class="fm-lbl">Percentual (%)</label>'
        +'<input class="fm-inp" type="number" id="hm-perc" value="'+(h.perc||'')+'" min="0" max="100" step="0.5" placeholder="ex: 30"></div>'
    +'</div>'
    +'<div style="margin-top:8px"><label class="fm-lbl">Descricao / observacao</label>'
      +'<input class="fm-inp" id="hm-desc" value="'+(h.desc||'').replace(/"/g,"&quot;")+'" placeholder="Ex: 30% s/ acordo..."></div>'
    +'<div style="margin-top:8px"><label class="fm-lbl">Data do contrato</label>'
      +'<input class="fm-inp" type="date" id="hm-dt" value="'+(h.dt||'')+'"></div>',
  ()=>{
    const mod   = document.getElementById('hm-mod')?.value||'fixo';
    const valor = parseFloat(document.getElementById('hm-valor')?.value)||0;
    const base  = parseFloat(document.getElementById('hm-base')?.value)||0;
    const perc2 = parseFloat(document.getElementById('hm-perc')?.value)||0;
    const desc  = document.getElementById('hm-desc')?.value.trim()||'';
    const dt    = document.getElementById('hm-dt')?.value||'';
    c._hon_contrato = {mod,valor,base,perc:perc2,desc,dt};
    if(!tasks[String(cid)]) tasks[String(cid)]={};
    tasks[String(cid)]._hon_contrato = c._hon_contrato;
    sbSet('co_tasks', tasks);
    marcarAlterado(); fecharModal();
    const el = document.getElementById('hon-pasta-'+cid);
    if(el) el.innerHTML = renderHonorariosPasta(cid);
    showToast('Contrato de honorarios salvo');
  },'Salvar');
}

function agendaConcluirComDesfecho(agId, cid){
  const raw = String(agId).replace(/^ag/,'');
  let idx = (localAg||[]).findIndex(a=>
    String(a.id)===raw||String(a.id_agenda)===raw||String(a.id)===String(agId));

  // Se não está em localAg, é um item do PEND (importado) — copiar para localAg
  if(idx===-1){
    const pendItem = (PEND||[]).find(p=>
      String(p.id)===raw||String(p.id_agenda)===raw||String(p.id)===String(agId));
    if(pendItem){
      // Check if already copied to localAg
      var existIdx = (localAg||[]).findIndex(function(a){
        return String(a._origem_pend)===String(pendItem.id)||String(a._origem_pend)===raw;
      });
      if(existIdx !== -1){
        idx = existIdx; // use existing copy
      } else {
        const copy = {...pendItem, id: 'pend_'+genId(), _origem_pend: pendItem.id};
        localAg.push(copy);
        idx = localAg.length - 1;
      }
    } else {
      showToast('Compromisso nao encontrado'); return;
    }
  }
  const item = localAg[idx];
  if(item.realizado){ showToast('Ja esta concluido'); return; }

  // Se o compromisso é do tipo "Prazo", exige protocolo/ID como prova do cumprimento.
  var tipoComp = (item.tipo_compromisso||item.tipo||'').toLowerCase();
  var isPrazo = tipoComp === 'prazo';
  var protocoloField = isPrazo
    ? '<div style="font-size:12px;color:var(--mu);margin-bottom:10px;line-height:1.5">'
       +'Este compromisso é do tipo <strong style="color:var(--ouro)">Prazo Judicial</strong>. '
       +'Informe a <strong>prova do cumprimento</strong>.'
      +'</div>'
      +'<div>'
       +'<label class="fm-lbl">Link do protocolo ou ID do documento <span class="req">*</span></label>'
       +'<input class="fm-inp" id="agcd-protocolo" value="'+escapeHtml(item.protocolo||'')+'" placeholder="Ex: PRJ-12345 · https://...">'
      +'</div>'
    : '';

  abrirModal((isPrazo?'⚖️ Cumprimento de Prazo':'Concluir Compromisso'),
    '<div style="margin-bottom:10px;font-size:13px;font-weight:600;color:var(--tx)">'+(item.titulo||'Compromisso')+'</div>'
    +protocoloField
    +'<div'+(isPrazo?' style="margin-top:8px"':'')+'><label class="fm-lbl">'+(isPrazo?'Desfecho / observações (opcional)':'Como foi? (opcional)')+'</label>'
      +'<textarea class="fm-inp" id="agcd-obs" rows="3" placeholder="Resultado, observacoes, proximo passo..."></textarea>'
    +'</div>',
  ()=>{
    var prot = '';
    if(isPrazo){
      prot = (document.getElementById('agcd-protocolo')?.value||'').trim();
      if(!prot){ showToast('Informe o link ou ID do protocolo'); return; }
    }
    const obs = document.getElementById('agcd-obs')?.value.trim()||'';
    localAg[idx] = {
      ...localAg[idx],
      realizado: true,
      cumprido: 'Sim',
      dt_conclusao: new Date().toISOString().slice(0,10),
      obs_conclusao: obs
    };
    if(prot) localAg[idx].protocolo = prot;
    sbSet('co_ag', localAg); invalidarAllPend();
    // Andamento na pasta
    if(cid){
      if(!localMov[cid]) localMov[cid]=[];
      var msg, tipoMov, origem;
      if(isPrazo){
        msg = 'Prazo "'+(item.titulo||'Compromisso')+'" cumprido — protocolo: '+prot;
        if(obs) msg += ' · '+obs;
        tipoMov = 'Judicial';
        origem = 'compromisso_prazo_cumprido';
      } else {
        msg = '[Concluido] '+(item.titulo||'Compromisso')+(obs?' — '+obs:'');
        tipoMov = 'Agenda';
        origem = 'agenda_concluido';
      }
      localMov[cid].unshift({
        data: new Date().toISOString().slice(0,10),
        movimentacao: msg,
        tipo_movimentacao: tipoMov, origem: origem
      });
      sbSet('co_localMov', localMov);
    }
    marcarAlterado();
    fecharModal();
    // Re-renderizar a aba de compromissos da pasta
    if(cid){
      const el = document.getElementById('tp-agenda-proc-'+cid);
      if(el) el.innerHTML = renderAgendaProc(cid);
    }
    _render_agenda_all();
    atualizarStats();
    audit('compromisso','Concluido: '+(item.titulo||''),'agenda');
    showToast('Compromisso concluido ✓');
  }, 'Concluir');
}


// Re-renderiza o financeiro local da pasta após qualquer baixa
function cadastrarColaboradorModal(){
  abrirModal('👤 Novo Colaborador',
    '<div class="fm-row"><div><label class="fm-lbl">Nome *</label><input class="fm-inp" id="ncb-nome" placeholder="Nome completo"></div></div>'
    +'<div class="fm-row" style="margin-top:8px">'
      +'<div><label class="fm-lbl">Cargo</label><input class="fm-inp" id="ncb-cargo" placeholder="Ex: Estagiária, Secretária..."></div>'
      +'<div><label class="fm-lbl">Salário (R$)</label><input class="fm-inp" type="number" id="ncb-sal" placeholder="0,00" min="0" step="0.01"></div>'
    +'</div>'
    +'<div class="fm-row" style="margin-top:8px">'
      +'<div><label class="fm-lbl">CPF</label><input class="fm-inp" id="ncb-cpf" placeholder="000.000.000-00"></div>'
      +'<div><label class="fm-lbl">Telefone</label><input class="fm-inp" id="ncb-tel" placeholder="(31) 99999-9999"></div>'
    +'</div>',
  ()=>{
    const nome = document.getElementById('ncb-nome')?.value.trim();
    if(!nome){ showToast('Informe o nome'); return; }
    const cargo = document.getElementById('ncb-cargo')?.value.trim()||'';
    const sal   = parseFloat(document.getElementById('ncb-sal')?.value)||0;
    const cpf   = document.getElementById('ncb-cpf')?.value.trim()||'';
    const tel   = document.getElementById('ncb-tel')?.value.trim()||'';
    _colaboradores.push({ id:genId(), nome, cargo, salario:sal, cpf, tel });
    sbSet('co_colab', _colaboradores);
    fecharModal();
    showToast('Colaborador cadastrado: '+nome);
    // Reabrir lançamento para selecionar
    setTimeout(()=>{ novoLancamentoGlobal(); }, 200);
  }, '💾 Salvar');
}


function _reRenderFinPasta(cid){
  _finLocaisCache = {}; // invalidar cache ao alterar dados
  const c = findClientById(cid);
  // 1. resumo de cards
  renderFinResumo(cid);
  // 2. lista unificada (projuris + local sem sombras)
  const finEl = document.getElementById('finunif-'+cid);
  if(finEl) finEl.innerHTML = renderFinUnificado(cid);
  // 4. honorários
  const honEl = document.getElementById('hon-pasta-'+cid);
  if(honEl) honEl.innerHTML = renderHonorariosPasta(cid);
  // 5. financeiro global (se visível)
  if(document.getElementById('vf')?.classList.contains('on')) vfRender();
  // 6. andamentos
  if(typeof AC !== 'undefined' && AC && String(AC.id)===String(cid)){
    const movEl = document.querySelector('#tp2 .mov-lista, #tp2 .hist-wrap');
    if(movEl && typeof renderMovLocal === 'function') movEl.innerHTML = renderMovLocal(cid);
  }
}

// LOG DE AUDITORIA
var _auditLog = [];

function _auditInit(){
  try { const s=localStorage.getItem('co_audit'); _auditLog=s?JSON.parse(s):[]; if(!Array.isArray(_auditLog)) _auditLog=[]; }
  catch(e){ _auditLog=[]; }
}

function audit(acao, detalhes, entidade){
  const e = {
    id:'a'+Date.now()+'_'+Math.random().toString(36).slice(2,6),
    ts: new Date().toISOString(),
    usuario: _sbUsuario||'sistema',
    acao, entidade:entidade||'', detalhes:detalhes||''
  };
  _auditLog.unshift(e);
  if(_auditLog.length>500) _auditLog=_auditLog.slice(0,500);
  lsSet('co_audit',JSON.stringify(_auditLog));
  sbSet('co_audit',_auditLog);
}

// ── Constantes de auditoria (evita recriar a cada render) ──
var _AUDIT_ICON={'baixa':'\u2705','exclusao':'\ud83d\uddd1','edicao':'\u270f','criacao':'\u2795',
  'login':'\ud83d\udd11','prazo':'\u2696','compromisso':'\ud83d\udcc5','financeiro':'\ud83d\udcb0',
  'tarefa':'\u2713','contato':'\ud83d\udc64','processo':'\ud83d\udcc2','sistema':'\u2699'};
var _AUDIT_COR={'baixa':'#4ade80','exclusao':'#f87676','edicao':'#fbbf24',
  'criacao':'#60a5fa','login':'#a78bfa','prazo':'#c9a84c',
  'compromisso':'#38bdf8','financeiro':'#4ade80','tarefa':'#a3e635',
  'contato':'#e879f9','processo':'#f97316','sistema':'#94a3b8'};

function auditRender(){
  var el=document.getElementById('audit-content');
  if(!el) return;
  var q=(document.getElementById('audit-busca')?.value||'').toLowerCase();
  var fa=document.getElementById('audit-facao')?.value||'';
  var fu=document.getElementById('audit-fuser')?.value||'';
  var lista=_auditLog.filter(function(e){
    var okQ=!q||(e.acao+e.detalhes+e.entidade+e.usuario).toLowerCase().includes(q);
    return okQ&&(!fa||e.acao===fa)&&(!fu||e.usuario===fu);
  });
  // Single-pass para KPIs + sets de usuarios/acoes
  var hojeStr=new Date().toISOString().slice(0,10);
  var kBaixas=0, kExcl=0, kHoje=0;
  var usuariosSet={}, acoesSet={};
  _auditLog.forEach(function(e){
    if(e.acao==='baixa') kBaixas++;
    if(e.acao==='exclusao') kExcl++;
    if((e.ts||'').slice(0,10)===hojeStr) kHoje++;
    if(e.usuario) usuariosSet[e.usuario]=1;
    if(e.acao) acoesSet[e.acao]=1;
  });
  var usuarios=Object.keys(usuariosSet);
  var acoes=Object.keys(acoesSet);
  var resumo='<div class="audit-resumo">'
    +'<div class="audit-kpi"><div class="audit-kpi-n">'+_auditLog.length+'</div><div class="audit-kpi-l">Total</div></div>'
    +'<div class="audit-kpi"><div class="audit-kpi-n">'+kBaixas+'</div><div class="audit-kpi-l">Baixas</div></div>'
    +'<div class="audit-kpi"><div class="audit-kpi-n">'+kExcl+'</div><div class="audit-kpi-l">Exclus\u00f5es</div></div>'
    +'<div class="audit-kpi"><div class="audit-kpi-n">'+kHoje+'</div><div class="audit-kpi-l">Hoje</div></div>'
    +'</div>';
  const filtros='<div class="audit-filtros">'
    +'<input class="vf-finp" id="audit-busca" placeholder="Buscar..." value="'+escapeHtml(q)+'" oninput="_debounce(\'auditS\',auditRender,200)" style="flex:2">'
    +'<select class="vf-finp" id="audit-facao" onchange="auditRender()"><option value="">Todas ações</option>'
      +acoes.map(function(a){return '<option value="'+a+'"'+(fa===a?' selected':'')+'>'+(_AUDIT_ICON[a]||'')+' '+a+'</option>';}).join('')+'</select>'
    +'<select class="vf-finp" id="audit-fuser" onchange="auditRender()"><option value="">Todos usuários</option>'
      +usuarios.map(function(u){return '<option'+(fu===u?' selected':'')+'>'+u+'</option>';}).join('')+'</select>'
    +'<button class="btn-bordo btn-bordo-sm" onclick="auditExportar()">⬇ CSV</button>'
    +'</div>';
  const hdr='<div class="audit-header-row"><div class="audit-ts">Data/Hora</div><div class="audit-user">Usuário</div><div class="audit-acao">Ação</div><div class="audit-entidade">Entidade</div><div class="audit-det">Detalhes</div></div>';
  const rows=lista.slice(0,200).map(e=>{
    const dt=e.ts?e.ts.slice(0,10).split('-').reverse().join('/')+' '+e.ts.slice(11,16):'—';
    return '<div class="audit-row">'
      +'<div class="audit-ts">'+dt+'</div>'
      +'<div class="audit-user">'+e.usuario+'</div>'
      +'<div class="audit-acao" style="color:'+(_AUDIT_COR[e.acao]||'var(--mu)')+'">'+(_AUDIT_ICON[e.acao]||'\ud83d\udccb')+' '+e.acao+'</div>'
      +'<div class="audit-entidade">'+(e.entidade||'—')+'</div>'
      +'<div class="audit-det">'+(e.detalhes?escapeHtml(String(e.detalhes)):'—')+'</div>'
    +'</div>';
  }).join('');
  el.innerHTML=resumo+filtros+hdr+(rows||'<div style="padding:32px;text-align:center;color:var(--mu);font-style:italic">Nenhum registro.</div>');
}

function auditExportar(){
  const linhas=[['Data/Hora','Usuario','Acao','Entidade','Detalhes']];
  _auditLog.forEach(e=>linhas.push([e.ts,e.usuario,e.acao,e.entidade||'',(e.detalhes||'').replace(/,/g,';')]));
  const csv=linhas.map(r=>r.join(',')).join('\n');
  const a=document.createElement('a');
  a.href='data:text/csv;charset=utf-8,\uFEFF'+encodeURIComponent(csv);
  a.download='auditoria_'+new Date().toISOString().slice(0,10)+'.csv';
  a.click();
  audit('exportacao','Log exportado CSV','auditoria');
}

function atVerDetalhes(atId){
  const a = (localAtend||[]).find(x=>x.id===atId||String(x.id)===String(atId));
  if(!a){ showToast('Atendimento não encontrado'); return; }
  const cli = CLIENTS.find(c=>String(c.id)===String(a.id_cliente)) || CLIENTS.find(c=>c.cliente===a.cliente);
  abrirModal('Detalhes — '+a.cliente,
    '<div style="padding:10px 12px;background:var(--sf3);border-radius:8px;margin-bottom:12px">'
      +'<div style="font-size:11px;color:var(--mu)">Atendimento registrado em '+(a.data||'—')+'</div>'
      +'<div style="font-size:14px;font-weight:700;color:var(--tx);margin-top:4px">'+(a.assunto||'—')+'</div>'
      +(a.resumo?'<div style="font-size:12px;color:var(--mu);margin-top:6px">'+a.resumo+'</div>':'')
    +'</div>'
    +(cli?'<div style="font-size:12px;color:var(--mu);margin-bottom:8px">Cliente cadastrado como: <b style="color:var(--tx)">'+cli.cliente+'</b></div>':'')
    +'<div style="display:flex;gap:8px;flex-wrap:wrap;margin-top:12px">'
      +'<button class="tp-btn" onclick="fecharModal();atEvoluirParaProcesso(\''+atId+'\')">⚖️ Evoluir para Processo</button>'
      +(cli?'<button class="tp-btn ghost" onclick="fecharModal();openC('+cli.id+')">📂 Abrir Pasta</button>':'')
      +'<button class="tp-btn ghost" style="color:#f87676;border-color:#f87676;margin-left:auto" onclick="atExcluir(\''+atId+'\')">🗑 Excluir</button>'
    +'</div>',
  null, null);
}

function atAbrirCliente(nome){
  const c = CLIENTS.find(x=>x.cliente===nome);
  if(c) openC(c.id); else showToast('Pasta não encontrada');
}

function atExcluir(atId){
  const idx = localAtend.findIndex(x=>x.id===atId||String(x.id)===String(atId));
  if(idx<0){ showToast('Atendimento não encontrado'); return; }
  const a = localAtend[idx];
  fecharModal();
  abrirModal('Excluir atendimento?',
    `<div style="font-size:12px;color:var(--mu);line-height:1.7">
      <p>Excluir o atendimento <strong style="color:var(--tx)">${a.assunto||''}</strong> de <strong style="color:var(--tx)">${a.cliente||''}</strong>?</p>
      <p style="margin-top:8px;color:#f87676">Esta ação não pode ser desfeita.</p>
    </div>`,
    ()=>{
      localAtend.splice(idx, 1);
      sbSet('co_atend', localAtend);
      fecharModal();
      renderPipeline();
      showToast('Atendimento excluído');
    }, 'Excluir'
  );
  setTimeout(()=>{
    const btn=document.getElementById('modal-save');
    if(btn){btn.style.background='var(--red)';btn.textContent='Excluir';}
  },50);
}

function atEvoluirParaProcesso(atId){
  const a = (localAtend||[]).find(x=>x.id===atId||String(x.id)===String(atId));
  if(!a){ showToast('Atendimento não encontrado'); return; }

  // Verificar se já tem pasta
  const existente = CLIENTS.find(c=>String(c.id)===String(a.id_cliente)) || CLIENTS.find(c=>c.cliente===a.cliente);

  abrirModal('⚖️ Evoluir para Processo — '+a.cliente,
    '<div style="padding:10px;background:var(--sf3);border-radius:8px;margin-bottom:12px;font-size:12px;color:var(--mu)">'
      +'Atendimento: <b style="color:var(--tx)">'+(a.assunto||'—')+'</b>'
      +(existente?' &nbsp;·&nbsp; Pasta já existe: <b style="color:var(--ouro)">'+existente.cliente+'</b>':'')
    +'</div>'
    +'<div class="fm-row">'
      +'<div style="flex:2"><label class="fm-lbl">Parte contrária *</label>'
        +'<input class="fm-inp" id="ep-adverso" placeholder="Nome da parte adversa"></div>'
      +'<div><label class="fm-lbl">Tipo de ação</label>'
        +'<input class="fm-inp" id="ep-tipo" placeholder="Ex: Rescisão indireta"></div>'
    +'</div>'
    +'<div class="fm-row" style="margin-top:8px">'
      +'<div><label class="fm-lbl">Número do processo</label>'
        +'<input class="fm-inp" id="ep-num" placeholder="0000000-00.0000.0.00.0000 (opcional)"></div>'
      +'<div><label class="fm-lbl">Vara / Tribunal</label>'
        +'<input class="fm-inp" id="ep-vara" placeholder="Ex: 3ª VT de BH"></div>'
    +'</div>'
    +'<div class="fm-row" style="margin-top:8px">'
      +'<div><label class="fm-lbl">Área jurídica</label>'
        +'<select class="fm-inp" id="ep-area">'
          +'<option>Trabalhista</option><option>Previdenciário</option>'
          +'<option>Cível</option><option>Família</option>'
          +'<option>Penal</option><option>Administrativo</option>'
        +'</select>'
      +'</div>'
      +'<div><label class="fm-lbl">Comarca</label>'
        +'<input class="fm-inp" id="ep-comarca" placeholder="Ex: Belo Horizonte"></div>'
    +'</div>',
  ()=>{
    const adverso  = document.getElementById('ep-adverso')?.value.trim();
    const tipo     = document.getElementById('ep-tipo')?.value.trim()||'';
    const num      = document.getElementById('ep-num')?.value.trim()||'';
    const vara     = document.getElementById('ep-vara')?.value.trim()||'';
    const area     = document.getElementById('ep-area')?.value||'Trabalhista';
    const comarca  = document.getElementById('ep-comarca')?.value.trim()||'';
    if(!adverso){ showToast('Informe a parte contrária'); return; }

    if(existente){
      // Atualizar pasta existente com dados do processo
      existente.adverso       = existente.adverso||adverso;
      existente.tipo_acao     = existente.tipo_acao||tipo;
      existente.numero        = existente.numero||num;
      existente.comarca       = existente.comarca||vara||comarca;
      existente.natureza      = existente.natureza||area;
      existente.status_consulta = 'processo';
      // Atualizar atendimento
      const idxAt = localAtend.findIndex(x=>x.id===atId||String(x.id)===String(atId));
      if(idxAt>=0) localAtend[idxAt] = {...localAtend[idxAt], status:'contratou', id_cliente:existente.id};
      sbSet('co_atend', localAtend);
      marcarAlterado(); montarClientesAgrupados(); doSearch();
      fecharModal();
      showToast('✓ Pasta atualizada com dados do processo');
      setTimeout(()=>openC(existente), 300);
    } else {
      // Criar nova pasta
      const novoId   = genId();
      const pasta    = 'AT'+String(novoId).slice(-6);
      const novoCliente = {
        id: novoId, pasta, cliente: a.cliente,
        adverso, tipo_acao: tipo, numero: num,
        comarca: vara||comarca, natureza: area,
        tel: a.tel||'', email: a.email||'',
        status_consulta: 'processo',
        criado: new Date().toISOString().slice(0,10)
      };
      CLIENTS.push(novoCliente);
      sbSalvarClientesDebounced();
      tasks[String(novoId)] = {};
      if(!localMov[novoId]) localMov[novoId]=[];
      localMov[novoId].push({
        data: new Date().toISOString().slice(0,10),
        movimentacao: '[Origem] Evoluído de atendimento: '+(a.assunto||'')+(a.data?' em '+a.data:''),
        tipo_movimentacao:'Sistema', origem:'evolucao_atendimento'
      });
      // Atualizar atendimento
      const idxAt = localAtend.findIndex(x=>x.id===atId||String(x.id)===String(atId));
      if(idxAt>=0) localAtend[idxAt] = {...localAtend[idxAt], status:'contratou', id_cliente:novoId};
      sbSet('co_atend', localAtend);
      sbSet('co_localMov', localMov);
      sbSet('co_tasks', tasks);
      marcarAlterado(); montarClientesAgrupados(); doSearch();
      fecharModal();
      audit('criacao','Atendimento evoluído para processo: '+a.cliente,'processo');
      showToast('⚖️ Processo criado — pasta '+pasta);
      setTimeout(()=>openC(novoCliente), 400);
    }
  }, '⚖️ Criar Processo');
}

window.onerror = function(msg, src, line, col, err) {
  document.getElementById('clist').innerHTML = 
    '<div style="color:#f87676;padding:16px;font-size:11px;font-family:monospace">'+
    '<strong>Erro JS:</strong><br>' + msg + '<br>linha ' + line + '</div>';
  return false;
};
// ═══════════════════════════════════════════════════════
// ══ AUTH GATE — decide entre login e app ════════════════
// ═══════════════════════════════════════════════════════
async function authBoot(){
  _sbSession = _authLoadSession();
  // Se há sessão mas está perto de expirar (ou já expirou parcialmente), tentar refresh
  if(_sbSession){
    var now = Math.floor(Date.now()/1000);
    if(_sbSession.expires_at - now < 300){  // menos de 5 min até expirar
      var ok = await authRefresh();
      if(!ok) _sbSession = null;
    }
  }
  if(!_sbSession){
    authMostrarLogin();
    return;
  }
  // Sessão válida → carregar perfil e bootar app
  _authScheduleRefresh();
  await authCarregarPerfil();  // não bloqueia se falhar
  authEsconderLogin();
  try {
    await init();
  } catch(e) {
    document.getElementById('clist').innerHTML =
      '<div style="color:#f87676;padding:16px;font-size:11px;font-family:monospace">'+
      '<strong>Erro no init():</strong><br>' + e.message + '<br>' +
      (e.stack||'').split('\n').slice(0,3).join('<br>') + '</div>';
  }
  // Veio de um link de recuperação de senha → abre modal de nova senha
  if(window._authPendingRecovery){
    window._authPendingRecovery = false;
    setTimeout(authMostrarNovaSenha, 400);
  }
}

function authMostrarLogin(){
  var ov = document.getElementById('auth-overlay');
  if(ov) ov.style.display = 'flex';
  // esconder app pra não mostrar estado vazio
  var hdr = document.querySelector('body > header');
  if(hdr) hdr.style.display = 'none';
}

function authEsconderLogin(){
  var ov = document.getElementById('auth-overlay');
  if(ov) ov.style.display = 'none';
  var hdr = document.querySelector('body > header');
  if(hdr) hdr.style.display = '';
  // atualizar label do usuário no header se existir
  var el = document.getElementById('sb-usuario');
  if(el && _sbSession && _sbSession.user){
    el.textContent = (_sbPerfil && _sbPerfil.nome) ? _sbPerfil.nome : _sbSession.user.email;
  }
}

// Handlers dos botões do form de login (chamados pelo HTML do overlay)
async function authSubmitLogin(ev){
  if(ev && ev.preventDefault) ev.preventDefault();
  var email = (document.getElementById('auth-email')||{}).value || '';
  var senha = (document.getElementById('auth-senha')||{}).value || '';
  var msg = document.getElementById('auth-msg');
  var btn = document.getElementById('auth-btn-entrar');
  if(!email || !senha){
    if(msg){ msg.textContent = 'Preencha e-mail e senha.'; msg.style.color = '#f87676'; }
    return;
  }
  if(btn){ btn.disabled = true; btn.textContent = 'Entrando...'; }
  if(msg){ msg.textContent = ''; }
  try {
    await authLogin(email.trim(), senha);
    // Sucesso → bootar app
    authEsconderLogin();
    _authScheduleRefresh();
    await authCarregarPerfil();
    await init();
  } catch(e){
    if(msg){
      msg.textContent = 'Falha no login: ' + (e.message || 'e-mail ou senha incorretos');
      msg.style.color = '#f87676';
    }
    if(btn){ btn.disabled = false; btn.textContent = 'Entrar'; }
  }
}

async function authSubmitMagicLink(){
  var email = (document.getElementById('auth-email')||{}).value || '';
  var msg = document.getElementById('auth-msg');
  if(!email){
    if(msg){ msg.textContent = 'Digite o e-mail primeiro.'; msg.style.color = '#f87676'; }
    return;
  }
  if(msg){ msg.textContent = 'Enviando link...'; msg.style.color = '#9e9e9e'; }
  try {
    await authMagicLink(email.trim());
    if(msg){
      msg.textContent = 'Link enviado! Verifique seu e-mail.';
      msg.style.color = '#97C459';
    }
  } catch(e){
    if(msg){
      msg.textContent = 'Falha: ' + (e.message || 'tente novamente');
      msg.style.color = '#f87676';
    }
  }
}

// Tela "Esqueci minha senha" — modal pra digitar o e-mail e disparar recovery.
function authMostrarEsqueciSenha(){
  var emailAtual = (document.getElementById('auth-email')||{}).value || '';
  abrirModal('🔑 Recuperar senha',
    '<div style="font-size:12px;color:var(--mu);margin-bottom:10px;line-height:1.5">'
      +'Vamos te enviar um e-mail com um link para definir uma nova senha. Clica no link e você volta pro app já autenticada para escolher a nova senha.'
    +'</div>'
    +'<div>'
      +'<label class="fm-lbl">E-mail</label>'
      +'<input class="fm-inp" id="rec-email" type="email" value="'+escapeHtml(emailAtual)+'" placeholder="seu@email.com">'
    +'</div>'
    +'<div id="rec-msg" style="min-height:18px;margin-top:10px;font-size:11px;color:var(--mu)"></div>',
    async function(){
      var email = ((document.getElementById('rec-email')||{}).value||'').trim();
      var msg = document.getElementById('rec-msg');
      if(!email){
        if(msg){ msg.textContent='Digite o e-mail.'; msg.style.color='#f87676'; }
        return;
      }
      if(msg){ msg.textContent='Enviando...'; msg.style.color='#9e9e9e'; }
      try {
        await authResetSenha(email);
        if(msg){ msg.textContent='✓ E-mail enviado. Verifique sua caixa.'; msg.style.color='#97C459'; }
        setTimeout(fecharModal, 1800);
      } catch(e){
        if(msg){ msg.textContent='Falha: '+(e.message||'tente novamente'); msg.style.color='#f87676'; }
      }
    },
    'Enviar e-mail');
}

// Tela "Defina sua nova senha" — mostrada quando o usuário volta do link de recovery.
function authMostrarNovaSenha(){
  abrirModal('🔑 Defina sua nova senha',
    '<div style="font-size:12px;color:var(--mu);margin-bottom:10px;line-height:1.5">'
      +'Você foi autenticado pelo link de recuperação. Escolha uma nova senha para o seu acesso.'
    +'</div>'
    +'<div>'
      +'<label class="fm-lbl">Nova senha (mínimo 6 caracteres)</label>'
      +'<input class="fm-inp" id="ns-senha" type="password" placeholder="••••••••">'
    +'</div>'
    +'<div style="margin-top:8px">'
      +'<label class="fm-lbl">Confirmar nova senha</label>'
      +'<input class="fm-inp" id="ns-senha2" type="password" placeholder="••••••••">'
    +'</div>'
    +'<div id="ns-msg" style="min-height:18px;margin-top:10px;font-size:11px;color:var(--mu)"></div>',
    async function(){
      var s1 = ((document.getElementById('ns-senha')||{}).value||'');
      var s2 = ((document.getElementById('ns-senha2')||{}).value||'');
      var msg = document.getElementById('ns-msg');
      if(s1.length < 6){
        if(msg){ msg.textContent='Senha precisa ter no mínimo 6 caracteres.'; msg.style.color='#f87676'; }
        return;
      }
      if(s1 !== s2){
        if(msg){ msg.textContent='As senhas não conferem.'; msg.style.color='#f87676'; }
        return;
      }
      if(msg){ msg.textContent='Atualizando...'; msg.style.color='#9e9e9e'; }
      try {
        await authAtualizarSenha(s1);
        if(msg){ msg.textContent='✓ Senha atualizada! Use ela no próximo login.'; msg.style.color='#97C459'; }
        setTimeout(function(){ fecharModal(); }, 1500);
      } catch(e){
        if(msg){ msg.textContent='Falha: '+(e.message||'tente novamente'); msg.style.color='#f87676'; }
      }
    },
    'Salvar senha');
}

// Expor no escopo global (onclick handlers do HTML)
window.authSubmitLogin = authSubmitLogin;
window.authSubmitMagicLink = authSubmitMagicLink;
window.authMostrarEsqueciSenha = authMostrarEsqueciSenha;
window.authMostrarNovaSenha = authMostrarNovaSenha;
window.authLogout = authLogout;

// Detectar magic link no hash (#access_token=... após clicar no e-mail)
(function _authHandleHash(){
  if(!window.location.hash) return;
  var h = window.location.hash.substring(1);
  var params = {};
  h.split('&').forEach(function(kv){
    var p = kv.split('=');
    if(p[0]) params[decodeURIComponent(p[0])] = decodeURIComponent(p[1]||'');
  });
  if(params.access_token && params.refresh_token){
    var expiresIn = parseInt(params.expires_in||'3600', 10);
    _authSaveSession({
      access_token: params.access_token,
      refresh_token: params.refresh_token,
      expires_in: expiresIn,
      expires_at: Math.floor(Date.now()/1000) + expiresIn,
      token_type: params.token_type || 'bearer',
      user: { id: '', email: '' }  // será preenchido depois via /auth/v1/user se necessário
    });
    // limpar o hash da URL
    history.replaceState(null, '', window.location.pathname + window.location.search);
    // Se veio de um link de recovery, força tela de nova senha após o boot
    if(params.type === 'recovery'){
      window._authPendingRecovery = true;
    }
  }
})();

authBoot();

// ═══════════════════════════════════════════════════════
// ── MOBILE HELPERS ──
// ═══════════════════════════════════════════════════════

function mbnActive(id){
  document.querySelectorAll('.mbn-btn').forEach(b=>b.classList.remove('on'));
  const el = document.getElementById(id);
  if(el) el.classList.add('on');
  // close mais menu when switching
  const mais = document.getElementById('mobile-mais-menu');
  if(mais && id !== 'mbn-mais') mais.style.display='none';
}

function mobileMenuMais(){
  const menu = document.getElementById('mobile-mais-menu');
  if(!menu) return;
  menu.style.display = menu.style.display==='none' ? 'block' : 'none';
}

// Close mais menu on outside click
document.addEventListener('click', function(e){
  const menu = document.getElementById('mobile-mais-menu');
  const btn  = document.getElementById('mbn-mais');
  if(menu && !menu.contains(e.target) && e.target!==btn && !btn?.contains(e.target)){
    menu.style.display='none';
  }
});

// Sync badge com agenda
function syncMobileBadge(){
  const badge = document.getElementById('mbn-bfut');
  const count = document.getElementById('bfut');
  if(!badge||!count) return;
  const n = parseInt(count.textContent)||0;
  badge.textContent = n>99?'99+':String(n);
  badge.style.display = n>0?'block':'none';
}
// Override atualizarStats para também sincronizar badge mobile
const _origStats = typeof atualizarStats==='function' ? atualizarStats : null;
if(_origStats){
  window._atualizarStatsOrig = _origStats;
  atualizarStats = function(){
    _atualizarStatsOrig();
    syncMobileBadge();
  };
}

// Mobile: abrir ficha esconde lista de clientes
function _mobileAbrirFicha(){
  if(window.innerWidth > 768) return;
  const wrap = document.getElementById('vcl')?.querySelector('.vcl-wrap');
  if(wrap) wrap.style.display = 'none';
  // Mostrar botão voltar
  let btn = document.getElementById('btn-voltar-mobile');
  if(!btn){
    btn = document.createElement('button');
    btn.id = 'btn-voltar-mobile';
    btn.innerHTML = '← Voltar à lista';
    btn.onclick = _mobileVoltarLista;
    const ficha = document.querySelector('.ficha-vcl') || document.getElementById('ficha-vcl');
    if(ficha) ficha.parentNode.insertBefore(btn, ficha);
  }
  btn.style.display='flex';
}

function _mobileVoltarLista(){
  if(window.innerWidth > 768) return;
  const wrap = document.getElementById('vcl')?.querySelector('.vcl-wrap');
  if(wrap) wrap.style.display = '';
  const btn = document.getElementById('btn-voltar-mobile');
  if(btn) btn.style.display='none';
  // Fechar ficha
  const ficha = document.querySelector('.ficha-vcl');
  if(ficha){ ficha.classList.remove('on'); ficha.innerHTML=''; }
  const emp2 = document.getElementById('emp2');
  if(emp2) emp2.style.display='flex';
}

// Hook no openC para disparar mobile behavior
const _origOpenC = typeof openC==='function' ? openC : null;
if(_origOpenC){
  openC = function(...args){
    _origOpenC(...args);
    _mobileAbrirFicha();
  };
}

// ═══════════════════════════════════════════════════════════════
// ══ NOTIFICAÇÕES PUSH + WORKFLOWS AUTOMATIZADOS ══
// ═══════════════════════════════════════════════════════════════

var _notifPermitido = false;
function notifPedirPermissao(){
  if(!('Notification' in window)) return;
  if(Notification.permission === 'granted'){ _notifPermitido = true; return; }
  if(Notification.permission !== 'denied'){
    Notification.requestPermission().then(function(p){ _notifPermitido = (p === 'granted'); });
  }
}

function notifEnviar(titulo, corpo, tag, onclick){
  if(!_notifPermitido || !('Notification' in window)) return;
  var n = new Notification(titulo, {
    body: corpo,
    icon: 'data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100"><circle cx="50" cy="50" r="48" fill="%23510f10" stroke="%23D4AF37" stroke-width="3"/><text x="50" y="58" text-anchor="middle" font-family="serif" font-size="36" font-weight="700" fill="%23D4AF37">CO</text></svg>',
    tag: tag || 'co-notif-' + Date.now(),
    requireInteraction: false
  });
  if(onclick) n.onclick = function(){ window.focus(); onclick(); n.close(); };
  setTimeout(function(){ n.close(); }, 15000);
}

// ── Workflows automatizados — verificação periódica ──
var _wfLastRun = '';

function wfRodar(){
  var hoje = new Date().toISOString().slice(0,10);
  if(_wfLastRun === hoje) return;
  _wfLastRun = hoje;

  var alertas = [];

  // 1. Prazos fatais de hoje e próximos 3 dias
  if(typeof prazos !== 'undefined' && prazos){
    Object.entries(prazos).forEach(function(e){
      var cid = e[0], lista = e[1] || [];
      lista.forEach(function(p){
        if(p.cumprido) return;
        var dias = Math.ceil((new Date(p.data) - new Date(hoje)) / 86400000);
        if(dias === 0){
          alertas.push({tipo:'fatal', titulo:'⚠️ PRAZO FATAL HOJE', corpo:p.titulo+' — '+_clienteNome(cid), tag:'prazo-'+p.id,
            onclick: function(){ openC(Number(cid)); }});
        } else if(dias === 1){
          alertas.push({tipo:'prazo', titulo:'📅 Prazo amanhã', corpo:p.titulo+' — '+_clienteNome(cid), tag:'prazo-'+p.id});
        } else if(dias > 0 && dias <= 3){
          alertas.push({tipo:'prazo', titulo:'📅 Prazo em '+dias+' dias', corpo:p.titulo+' — '+_clienteNome(cid), tag:'prazo-'+p.id});
        }
      });
    });
  }

  // 2. Compromissos/audiências de hoje
  (typeof localAg !== 'undefined' ? localAg : []).forEach(function(ag){
    if(ag.cumprido === 'Sim') return;
    var dt = (ag.data || ag.dt_raw || ag.inicio || '').slice(0,10);
    if(dt === hoje){
      alertas.push({tipo:'agenda', titulo:'📋 Compromisso hoje', corpo:(ag.titulo||'Evento')+(ag.obs?' — '+ag.obs:''), tag:'ag-'+ag.id});
    }
  });

  // 3. Honorários vencidos
  var honVenc = 0, honTot = 0;
  (localLanc||[]).forEach(function(l){
    if(l.pago || l.status === 'pago') return;
    if(l.tipo === 'repasse' || l.tipo === 'despesa' || l.tipo === 'despint') return;
    var venc = l.venc || l.data;
    if(venc && venc < hoje){ honVenc++; honTot += parseFloat(l.valor) || 0; }
  });
  if(honVenc > 0){
    var fV2 = function(v){return 'R$ '+v.toLocaleString('pt-BR',{minimumFractionDigits:2,maximumFractionDigits:2});};
    alertas.push({tipo:'fin', titulo:'💰 '+honVenc+' honorário'+(honVenc>1?'s':'')+' vencido'+(honVenc>1?'s':''),
      corpo:'Total: '+fV2(honTot), tag:'hon-vencidos',
      onclick: function(){ goFin(); vfSetTab('recebimentos'); }});
  }

  // 4. Repasses pendentes urgentes (vencendo em 3 dias ou vencidos)
  var repUrg = (localLanc||[]).filter(function(l){
    if(l.pago || l.status === 'pago') return false;
    if(l.tipo !== 'repasse' && !l._repasse_alvara && !l._repasse_acordo) return false;
    var venc = l.venc || l.data;
    return venc && Math.ceil((new Date(venc) - new Date(hoje)) / 86400000) <= 3;
  });
  if(repUrg.length){
    alertas.push({tipo:'repasse', titulo:'📤 '+repUrg.length+' repasse'+(repUrg.length>1?'s':'')+' urgente'+(repUrg.length>1?'s':''),
      corpo:'Vencem em breve ou já venceram', tag:'rep-urg',
      onclick: function(){ goFin(); vfSetTab('repasses'); }});
  }

  // 5. Cobranças — recebimentos vencendo em 2 dias
  var em2d2 = new Date(new Date(hoje).getTime()+2*86400000).toISOString().slice(0,10);
  var cobrar2 = (localLanc||[]).filter(function(l){
    if(l.pago || l.status === 'pago') return false;
    if(l.tipo === 'repasse' || l.tipo === 'despesa' || l.tipo === 'despint') return false;
    var venc = (l.venc||l.data||'').slice(0,10);
    return venc > hoje && venc <= em2d2;
  });
  if(cobrar2.length){
    var fV5=function(v){return 'R$ '+Math.abs(v||0).toLocaleString('pt-BR',{minimumFractionDigits:2,maximumFractionDigits:2});};
    var totCob=cobrar2.reduce(function(s,l){return s+(parseFloat(l.valor)||0);},0);
    alertas.push({tipo:'cobrar', titulo:'📣 '+cobrar2.length+' cobrança'+(cobrar2.length>1?'s':'')+' para fazer',
      corpo:fV5(totCob)+' vencem nos próximos 2 dias', tag:'cobrar',
      onclick: function(){ goFin(); vfSetTab('recebimentos'); }});
  }

  // Disparar (máx 5, priorizados)
  var prio = ['fatal','repasse','cobrar','fin','prazo','agenda'];
  alertas.sort(function(a,b){ return prio.indexOf(a.tipo) - prio.indexOf(b.tipo); });
  alertas.slice(0, 5).forEach(function(a, i){
    setTimeout(function(){ notifEnviar(a.titulo, a.corpo, a.tag, a.onclick); }, i * 2000);
  });
}

function _clienteNome(cid){
  var c = (CLIENTS||[]).find(function(x){ return String(x.id)===String(cid); });
  return c ? c.cliente : 'Processo';
}

// ── Inicializar ──
function _initNotifWorkflows(){
  notifPedirPermissao();
  setTimeout(wfRodar, 5000);
  setInterval(wfRodar, 30 * 60 * 1000);
  // Restaurar view toggle
  if(_vclView==='table'){
    document.getElementById('vcl-vb-cards')?.classList.remove('vcl-vb-on');
    document.getElementById('vcl-vb-table')?.classList.add('vcl-vb-on');
    document.querySelector('.vcl-wrap')?.classList.add('vcl-full');
  }
}
if(document.readyState === 'loading') document.addEventListener('DOMContentLoaded', _initNotifWorkflows);
else setTimeout(_initNotifWorkflows, 1000);

// ═══════════════════════════════════════════════════════════════
// ══ INTEGRAÇÃO DATAJUD (CNJ) — TRT 3ª REGIÃO ══
// ═══════════════════════════════════════════════════════════════

// ═══════════════════════════════════════════════════════
// ══ COLAR PUBLICAÇÃO — parser de Diário de Justiça ════
// ═══════════════════════════════════════════════════════

function abrirColarPublicacao(){
  abrirModal('\ud83d\udcf0 Colar Publica\u00e7\u00e3o do Di\u00e1rio',
    '<div style="margin-bottom:10px;font-size:11px;color:var(--mu)">Cole o texto do email do Recorte Digital (OAB) ou de qualquer publica\u00e7\u00e3o do DJe:</div>'
    +'<textarea class="fm-inp" id="pub-texto" rows="10" placeholder="Cole aqui o texto da publica\u00e7\u00e3o..." style="font-size:11px;font-family:monospace"></textarea>',
  function(){
    var texto = document.getElementById('pub-texto')?.value.trim();
    if(!texto){ showToast('Cole o texto da publica\u00e7\u00e3o'); return; }
    fecharModal();
    _processarPublicacao(texto);
  }, '\ud83d\udd0d Processar');
}

function _processarPublicacao(texto){
  // Extrair número(s) de processo (formato CNJ)
  // CNJ com ou sem separadores: 0000000-00.0000.0.00.0000 ou 00000000020255030014
  var reProc = /\d{7}[-.]?\d{2}[.-]?\d{4}[.-]?\d[.-]?\d{2}[.-]?\d{4}/g;
  var nums = [];
  var m;
  while((m=reProc.exec(texto))!==null){
    var num = m[0].replace(/[^0-9.-]/g,'');
    if(nums.indexOf(num)===-1) nums.push(num);
  }

  // Extrair dados da publicação
  var dataPub = '';
  var mData = texto.match(/Data de Publica[çc][aã]o\s*:?\s*(\d{2}\/\d{2}\/\d{4})/i);
  if(mData) dataPub = mData[1].split('/').reverse().join('-');
  if(!dataPub){
    var mData2 = texto.match(/Data de Disponibiliza[çc][aã]o\s*:?\s*(\d{2}\/\d{2}\/\d{4})/i);
    if(mData2) dataPub = mData2[1].split('/').reverse().join('-');
  }
  if(!dataPub) dataPub = getTodayKey();

  var tribunal = '';
  var mTrib = texto.match(/Tribunal\s*:?\s*([^\n]+)/i);
  if(mTrib) tribunal = mTrib[1].trim();

  var vara = '';
  var mVara = texto.match(/Vara\s*:?\s*([^\n]+)/i);
  if(mVara) vara = mVara[1].trim();

  var tipoPub = '';
  // Pegar "Publicação:" que NÃO é precedido de "Data de" e NÃO é só número
  var allTipos = texto.match(/(?<![Dd]ata de )Publica[çc][aã]o\s*:\s*([^\n]+)/gi)||[];
  allTipos.forEach(function(t){
    var val = t.replace(/Publica[çc][aã]o\s*:\s*/i,'').trim();
    if(val && !/^\d+\.?$/.test(val) && !/^\d{2}\/\d{2}\/\d{4}/.test(val)) tipoPub = val;
  });

  var jornal = '';
  var mJorn = texto.match(/Jornal\s*:?\s*([^\n]+)/i);
  if(mJorn) jornal = mJorn[1].trim();

  // Buscar clientes vinculados pelos números
  var vinculados = [];
  nums.forEach(function(num){
    var numLimpo = num.replace(/[^0-9]/g,'');
    (CLIENTS||[]).forEach(function(c){
      if(!c.numero) return;
      var cNumLimpo = c.numero.replace(/[^0-9]/g,'');
      if(cNumLimpo===numLimpo && vinculados.indexOf(c)===-1) vinculados.push(c);
    });
  });

  // Montar resumo para o modal
  var descPub = '[Publica\u00e7\u00e3o] '+(tipoPub||'DJe')
    +(tribunal?' \u2014 '+tribunal:'')
    +(vara?' \u2014 '+vara:'')
    +(jornal?' ('+jornal+')':'');

  var trechoTexto = texto.length>300?texto.slice(0,300)+'...':texto;

  var html = '<div style="margin-bottom:12px">';

  // Dados extraídos
  html += '<div style="background:var(--sf3);border-radius:6px;padding:10px 12px;margin-bottom:10px">'
    +'<div style="font-size:10px;font-weight:700;text-transform:uppercase;color:var(--mu);margin-bottom:6px">Dados extra\u00eddos</div>'
    +(dataPub?'<div style="font-size:11px;color:var(--tx)"><strong>Data:</strong> '+fDt(dataPub)+'</div>':'')
    +(tipoPub?'<div style="font-size:11px;color:var(--tx)"><strong>Tipo:</strong> '+escapeHtml(tipoPub)+'</div>':'')
    +(tribunal?'<div style="font-size:11px;color:var(--tx)"><strong>Tribunal:</strong> '+escapeHtml(tribunal)+'</div>':'')
    +(vara?'<div style="font-size:11px;color:var(--tx)"><strong>Vara:</strong> '+escapeHtml(vara)+'</div>':'')
    +(nums.length?'<div style="font-size:11px;color:var(--tx)"><strong>Processos:</strong> '+nums.map(escapeHtml).join(', ')+'</div>':'')
  +'</div>';

  // Clientes vinculados
  if(vinculados.length){
    html += '<div style="font-size:10px;font-weight:700;text-transform:uppercase;color:#4ade80;margin-bottom:6px">\u2713 '+vinculados.length+' processo'+(vinculados.length>1?'s':'')+' encontrado'+(vinculados.length>1?'s':'')+'</div>';
    vinculados.forEach(function(c){
      html += '<div style="display:flex;align-items:center;gap:8px;padding:6px 0;border-bottom:1px solid var(--bd)">'
        +'<input type="checkbox" checked class="pub-cli-check" data-cid="'+c.id+'" style="width:14px;height:14px">'
        +'<div style="flex:1"><div style="font-size:12px;font-weight:600;color:var(--tx)">'+escapeHtml(c.cliente)+'</div>'
          +'<div style="font-size:10px;color:var(--mu)">Pasta '+(c.pasta||'\u2014')+' \u00b7 '+escapeHtml(c.numero||'')+'</div></div>'
      +'</div>';
    });
  } else if(nums.length){
    html += '<div style="background:rgba(245,158,11,.08);border:1px solid rgba(245,158,11,.3);border-radius:6px;padding:8px 12px;font-size:11px;color:#f59e0b">'
      +'\u26a0 Processo'+(nums.length>1?'s':'')+' n\u00e3o encontrado'+(nums.length>1?'s':'')+' na base: '+nums.join(', ')+'</div>';
  } else {
    html += '<div style="background:rgba(245,158,11,.08);border:1px solid rgba(245,158,11,.3);border-radius:6px;padding:8px 12px;font-size:11px;color:#f59e0b">'
      +'\u26a0 Nenhum n\u00famero de processo identificado no texto</div>';
  }

  // Trecho do texto
  html += '<div style="margin-top:10px"><div style="font-size:9px;font-weight:700;text-transform:uppercase;color:var(--mu);margin-bottom:4px">Trecho</div>'
    +'<div style="font-size:10px;color:var(--mu);background:var(--sf3);border-radius:4px;padding:8px;max-height:100px;overflow-y:auto;font-family:monospace">'+escapeHtml(trechoTexto)+'</div></div>';

  // Opções
  html += '<div style="margin-top:10px;display:flex;gap:8px;align-items:center">'
    +'<label style="font-size:11px;color:var(--tx);display:flex;align-items:center;gap:4px"><input type="checkbox" id="pub-criar-prazo"> Criar prazo/compromisso</label>'
  +'</div>';

  html += '</div>';

  abrirModal('\ud83d\udcf0 Publica\u00e7\u00e3o Processada', html,
  function(){
    // Salvar andamento nos clientes selecionados
    var checks = document.querySelectorAll('.pub-cli-check:checked');
    var criarPrazo = document.getElementById('pub-criar-prazo')?.checked;
    var importados = 0;

    checks.forEach(function(chk){
      var cid = Number(chk.dataset.cid);
      if(!localMov[cid]) localMov[cid]=[];
      localMov[cid].unshift({
        data: dataPub, movimentacao: descPub,
        tipo_movimentacao: 'Publica\u00e7\u00e3o', origem: 'publicacao_dje'
      });
      importados++;

      // Criar prazo se marcado
      if(criarPrazo){
        var c = findClientById(cid);
        localAg.push({
          id: 'ag'+genId(), titulo: 'Providenciar: '+(tipoPub||'Publica\u00e7\u00e3o DJe'),
          tipo_compromisso: 'Prazo', cliente: c?c.cliente:'', id_processo: cid,
          dt_raw: _addDiasUteis(dataPub, 5, 'MG'), dt_fim: _addDiasUteis(dataPub, 5, 'MG'),
          inicio: _addDiasUteis(dataPub, 5, 'MG'),
          obs: 'Gerado de publica\u00e7\u00e3o: '+descPub,
          realizado: false, _prazo: true, origem: 'publicacao_prazo'
        });
        invalidarAllPend();
        sbSet('co_ag', localAg);
      }
    });

    if(importados>0){
      sbSet('co_localMov', localMov);
      marcarAlterado();
    }
    fecharModal();
    showToast('\u2713 Publica\u00e7\u00e3o registrada em '+importados+' processo'+(importados>1?'s':''));
  }, '\ud83d\udce5 Registrar nos processos');
}

// ═══════════════════════════════════════════════════════
// ══ MÓDULO INICIAIS — pipeline de petições iniciais ═══
// ═══════════════════════════════════════════════════════

var _iniciais = [];
try { _iniciais = JSON.parse(lsGet('co_iniciais')||'[]'); if(!Array.isArray(_iniciais)) _iniciais=[]; } catch(e){ _iniciais=[]; }

var INI_COLUNAS = [
  {id:'pendente', label:'Pendente', icon:'\ud83d\udccb', cor:'#f59e0b'},
  {id:'fazendo',  label:'Fazendo',  icon:'\u26a1',     cor:'#60a5fa'},
  {id:'concluida',label:'Conclu\u00edda', icon:'\u2705', cor:'#4ade80'}
];

function iniSalvar(){
  sbSet('co_iniciais', _iniciais);
  lsSet('co_iniciais', JSON.stringify(_iniciais));
}

function iniRender(){
  var el = document.getElementById('ini-content');
  if(!el) return;
  var hoje = getTodayKey();

  var cols = INI_COLUNAS.map(function(col){
    var itens = _iniciais.filter(function(i){ return (i.status||'pendente')===col.id; });
    var cards = itens.map(function(i){
      var diasAtend = i.data_atendimento ? Math.ceil((new Date(hoje)-new Date(i.data_atendimento))/86400000) : 0;
      var docsOk = (i.docs_checklist||[]).filter(function(d){return d.ok;}).length;
      var docsTotal = (i.docs_checklist||[]).length;
      return '<div class="ini-card" draggable="true" ondragstart="iniDragStart(event,\''+i.id+'\')">'
        +'<div style="display:flex;justify-content:space-between;align-items:start;margin-bottom:6px">'
          +'<div style="font-size:13px;font-weight:700;color:var(--tx)">'+escapeHtml(i.cliente||'\u2014')+'</div>'
          +'<div style="display:flex;gap:4px">'
            +'<button onclick="iniEditar(\''+i.id+'\')" style="font-size:10px;padding:2px 6px;border-radius:3px;background:var(--sf3);border:1px solid var(--bd);color:var(--mu);cursor:pointer">\u270f</button>'
            +'<button onclick="iniExcluir(\''+i.id+'\')" style="font-size:10px;padding:2px 6px;border-radius:3px;background:var(--sf3);border:1px solid rgba(201,72,74,.3);color:#c9484a;cursor:pointer">\u2715</button>'
          +'</div>'
        +'</div>'
        +'<div style="font-size:10px;color:var(--mu);margin-bottom:4px">'
          +(i.area?'<span style="padding:1px 6px;border-radius:3px;background:rgba(107,20,22,.2);color:#c9484a;font-weight:700;font-size:9px;text-transform:uppercase">'+escapeHtml(i.area)+'</span> ':'')
          +(i.responsavel?'\ud83d\udc64 '+escapeHtml(i.responsavel):'')
        +'</div>'
        +(i.data_atendimento?'<div style="font-size:10px;color:var(--mu)">Atend: '+fDt(i.data_atendimento)+(diasAtend>7?' <span style="color:#f59e0b">('+diasAtend+'d)</span>':'')+'</div>':'')
        +(docsTotal?'<div style="font-size:10px;color:var(--mu);margin-top:2px">\ud83d\udcceMocs: '+docsOk+'/'+docsTotal+(docsOk===docsTotal?' \u2713':'')+'</div>':'')
        +(i.honorarios?'<div style="font-size:10px;color:#D4AF37;margin-top:2px">\ud83d\udcb0 '+escapeHtml(i.honorarios)+'</div>':'')
        +(i.prazo?'<div style="font-size:10px;color:'+(i.prazo<hoje?'#c9484a':'var(--mu)')+';margin-top:2px">\u23f0 Prazo: '+fDt(i.prazo)+(i.prazo<hoje?' (vencido!)':'')+'</div>':'')
        +(i.obs?'<div style="font-size:10px;color:var(--mu);margin-top:4px;font-style:italic">'+escapeHtml(i.obs.slice(0,60))+(i.obs.length>60?'...':'')+'</div>':'')
        +(col.id!=='concluida'&&i.status!=='concluida'?'<div style="margin-top:6px"><button onclick="iniMover(\''+i.id+'\')" style="font-size:10px;padding:3px 8px;border-radius:4px;background:rgba(76,175,125,.1);border:1px solid rgba(76,175,125,.3);color:#4ade80;cursor:pointer">Avan\u00e7ar \u2192</button></div>':'')
        +(col.id==='concluida'&&i.numero_processo?'<div style="font-size:10px;color:#4ade80;margin-top:4px">\u2696 '+escapeHtml(i.numero_processo)+'</div>':'')
      +'</div>';
    }).join('');

    return '<div class="ini-col">'
      +'<div style="display:flex;align-items:center;justify-content:space-between;padding:8px 12px;background:var(--sf3);border-bottom:1px solid var(--bd);border-radius:8px 8px 0 0">'
        +'<span style="font-size:12px;font-weight:700;color:'+col.cor+'">'+col.icon+' '+col.label+'</span>'
        +'<span style="font-size:11px;color:var(--mu)">'+itens.length+'</span>'
      +'</div>'
      +'<div class="ini-col-body" id="inicol-'+col.id+'" ondragover="event.preventDefault();this.style.background=\'var(--sf3)\'" ondragleave="this.style.background=\'\'" ondrop="iniDrop(\''+col.id+'\',this)">'
        +(cards||'<div style="padding:12px;font-size:11px;color:var(--mu);font-style:italic">Nenhuma inicial</div>')
      +'</div>'
    +'</div>';
  }).join('');

  // Stats
  var pendentes = _iniciais.filter(function(i){return i.status==='pendente';}).length;
  var fazendo = _iniciais.filter(function(i){return i.status==='fazendo';}).length;

  el.innerHTML = (pendentes+fazendo>0?'<div style="margin-bottom:12px;font-size:11px;color:var(--mu)">'+pendentes+' pendente'+(pendentes!==1?'s':'')+' \u00b7 '+fazendo+' em andamento</div>':'')
    +'<div style="display:grid;grid-template-columns:repeat(3,1fr);gap:12px;align-items:start">'+cols+'</div>';
}

// Drag & drop
var _iniDragId = null;
function iniDragStart(e, id){ _iniDragId = id; }
function iniDrop(colId, el){
  el.style.background = '';
  if(!_iniDragId) return;
  var i = _iniciais.find(function(x){return String(x.id)===String(_iniDragId);});
  if(!i) return;
  var oldStatus = i.status;
  i.status = colId;
  if(colId==='concluida' && oldStatus!=='concluida'){
    i.data_conclusao = getTodayKey();
    iniSalvar(); iniRender();
    // Pedir número do processo via modal
    setTimeout(function(){
      abrirModal('⚖️ Processo distribuído',
        '<div style="margin-bottom:10px;font-size:13px;color:var(--mu)">Informe o número do processo (opcional):</div>'+'<input class="fm-inp" id="ini-num-proc2" placeholder="0000000-00.0000.5.03.0014">',
        function(){
          var num = (document.getElementById('ini-num-proc2')?.value||'').trim();
          if(num){ i.numero_processo = num; iniSalvar(); iniRender(); }
          fecharModal();
        }, 'Salvar'
      );
    }, 200);
  } else {
    iniSalvar(); iniRender();
  }
  _iniDragId = null;
  showToast('Inicial movida para '+colId);
}

function iniMover(id){
  var i = _iniciais.find(function(x){return String(x.id)===String(id);});
  if(!i) return;
  if(i.status==='pendente'){ i.status='fazendo'; iniSalvar(); iniRender(); showToast('Inicial em andamento ✓'); return; }
  if(i.status==='fazendo'){
    abrirModal('⚖️ Processo distribuído',
      '<div style="margin-bottom:10px;font-size:13px;color:var(--mu)">Informe o número do processo (opcional):</div>'+'<input class="fm-inp" id="ini-num-proc" placeholder="0000000-00.0000.5.03.0014">',
      function(){
        i.status='concluida';
        i.data_conclusao = getTodayKey();
        var num = (document.getElementById('ini-num-proc')?.value||'').trim();
        if(num) i.numero_processo = num;
        iniSalvar(); fecharModal(); marcarAlterado(); iniRender();
        showToast('Inicial concluída ✓');
      }, 'Concluir'
    );
  }
}

function iniNova(){
  var AREAS = ['Trabalhista','Previdenci\u00e1rio','C\u00edvel','Fam\u00edlia','Penal','Administrativo','Outro'];
  var DOCS_PADRAO = ['RG/CNH','CPF','Comprovante resid\u00eancia','CTPS','Procura\u00e7\u00e3o','Contrato honor\u00e1rios'];
  var clientesOpts = CLIENTS.map(function(c){return '<option value="'+escapeHtml(c.cliente)+'">'+escapeHtml(c.cliente)+' (Pasta '+(c.pasta||'\u2014')+')</option>';}).join('');
  // Também contatos
  var ctcOpts = ctcTodos().map(function(c){return '<option value="'+escapeHtml(c.nome)+'">'+escapeHtml(c.nome)+' (Contato)</option>';}).join('');

  abrirModal('\ud83d\udcdd Nova Inicial Pendente',
    '<div class="fm-row"><div style="flex:2"><label class="fm-lbl">Cliente *</label>'
      +'<input class="fm-inp" id="ini-cli" list="ini-cli-list" placeholder="Nome do cliente...">'
      +'<datalist id="ini-cli-list">'+clientesOpts+ctcOpts+'</datalist></div></div>'
    +'<div class="fm-row" style="margin-top:8px">'
      +'<div><label class="fm-lbl">\u00c1rea jur\u00eddica</label><select class="fm-inp" id="ini-area">'+AREAS.map(function(a){return '<option>'+a+'</option>';}).join('')+'</select></div>'
      +'<div><label class="fm-lbl">Data atendimento</label><input class="fm-inp" type="date" id="ini-dt" value="'+getTodayKey()+'"></div>'
      +'<div><label class="fm-lbl">Prazo estimado</label><input class="fm-inp" type="date" id="ini-prazo"></div>'
    +'</div>'
    +'<div class="fm-row" style="margin-top:8px">'
      +'<div><label class="fm-lbl">Respons\u00e1vel</label><select class="fm-inp" id="ini-resp"><option>Clarissa</option><option>Assistente</option><option>Estagi\u00e1rio 1</option><option>Estagi\u00e1rio 2</option></select></div>'
      +'<div><label class="fm-lbl">Honor\u00e1rios combinados</label><input class="fm-inp" id="ini-hon" placeholder="Ex: 30% \u00eaxito + R$ 500 entrada"></div>'
    +'</div>'
    +'<div style="margin-top:10px"><label class="fm-lbl">Documentos necess\u00e1rios</label>'
      +'<div id="ini-docs" style="display:flex;flex-wrap:wrap;gap:6px;margin-top:4px">'
        +DOCS_PADRAO.map(function(d,i){return '<label style="font-size:11px;display:flex;align-items:center;gap:4px;color:var(--tx);cursor:pointer"><input type="checkbox" class="ini-doc-chk" value="'+d+'"> '+d+'</label>';}).join('')
      +'</div>'
      +'<input class="fm-inp" id="ini-doc-extra" placeholder="Outros documentos (separar por v\u00edrgula)" style="margin-top:6px"></div>'
    +'<div style="margin-top:8px"><label class="fm-lbl">Observa\u00e7\u00f5es / Resumo do caso</label>'
      +'<textarea class="fm-inp" id="ini-obs" rows="3" placeholder="Breve resumo do caso, pontos relevantes..."></textarea></div>',
  function(){
    var cli = (document.getElementById('ini-cli')?.value||'').trim();
    if(!cli){ showToast('Informe o cliente'); return; }
    var docs = [];
    document.querySelectorAll('.ini-doc-chk:checked').forEach(function(chk){ docs.push({nome:chk.value, ok:false}); });
    var extra = (document.getElementById('ini-doc-extra')?.value||'').split(',').map(function(d){return d.trim();}).filter(Boolean);
    extra.forEach(function(d){ docs.push({nome:d, ok:false}); });

    _iniciais.push({
      id: 'ini'+genId(), cliente: cli,
      area: document.getElementById('ini-area')?.value||'',
      data_atendimento: document.getElementById('ini-dt')?.value||getTodayKey(),
      prazo: document.getElementById('ini-prazo')?.value||'',
      responsavel: document.getElementById('ini-resp')?.value||'Clarissa',
      honorarios: (document.getElementById('ini-hon')?.value||'').trim(),
      docs_checklist: docs,
      obs: (document.getElementById('ini-obs')?.value||'').trim(),
      status: 'pendente', criado_em: new Date().toISOString()
    });
    iniSalvar(); fecharModal(); marcarAlterado(); iniRender();
    showToast('Inicial pendente criada \u2713');
  }, '\ud83d\udcbe Salvar');
}

function iniEditar(id){
  var i = _iniciais.find(function(x){return String(x.id)===String(id);});
  if(!i) return;
  var AREAS = ['Trabalhista','Previdenci\u00e1rio','C\u00edvel','Fam\u00edlia','Penal','Administrativo','Outro'];
  var docsHtml = (i.docs_checklist||[]).map(function(d,idx){
    return '<label style="font-size:11px;display:flex;align-items:center;gap:4px;color:var(--tx);cursor:pointer"><input type="checkbox" class="inie-doc-chk" data-idx="'+idx+'" '+(d.ok?'checked':'')+' value="'+escapeHtml(d.nome)+'"> '+escapeHtml(d.nome)+'</label>';
  }).join('');

  abrirModal('\u270f Editar Inicial \u2014 '+escapeHtml(i.cliente),
    '<div class="fm-row"><div style="flex:2"><label class="fm-lbl">Cliente</label><input class="fm-inp" id="inie-cli" value="'+escapeHtml(i.cliente||'')+'"></div></div>'
    +'<div class="fm-row" style="margin-top:8px">'
      +'<div><label class="fm-lbl">\u00c1rea</label><select class="fm-inp" id="inie-area">'+AREAS.map(function(a){return '<option'+(a===i.area?' selected':'')+'>'+a+'</option>';}).join('')+'</select></div>'
      +'<div><label class="fm-lbl">Prazo</label><input class="fm-inp" type="date" id="inie-prazo" value="'+(i.prazo||'')+'"></div>'
      +'<div><label class="fm-lbl">Respons\u00e1vel</label><select class="fm-inp" id="inie-resp"><option'+(i.responsavel==='Clarissa'?' selected':'')+'>Clarissa</option><option'+(i.responsavel==='Assistente'?' selected':'')+'>Assistente</option><option'+(i.responsavel==='Estagi\u00e1rio 1'?' selected':'')+'>Estagi\u00e1rio 1</option><option'+(i.responsavel==='Estagi\u00e1rio 2'?' selected':'')+'>Estagi\u00e1rio 2</option></select></div>'
    +'</div>'
    +'<div class="fm-row" style="margin-top:8px"><div><label class="fm-lbl">Honor\u00e1rios</label><input class="fm-inp" id="inie-hon" value="'+escapeHtml(i.honorarios||'')+'"></div></div>'
    +(docsHtml?'<div style="margin-top:8px"><label class="fm-lbl">Documentos</label><div style="display:flex;flex-wrap:wrap;gap:6px;margin-top:4px">'+docsHtml+'</div></div>':'')
    +'<div style="margin-top:8px"><label class="fm-lbl">Observa\u00e7\u00f5es</label><textarea class="fm-inp" id="inie-obs" rows="3">'+escapeHtml(i.obs||'')+'</textarea></div>',
  function(){
    i.cliente = (document.getElementById('inie-cli')?.value||'').trim();
    i.area = document.getElementById('inie-area')?.value||'';
    i.prazo = document.getElementById('inie-prazo')?.value||'';
    i.responsavel = document.getElementById('inie-resp')?.value||'';
    i.honorarios = (document.getElementById('inie-hon')?.value||'').trim();
    i.obs = (document.getElementById('inie-obs')?.value||'').trim();
    // Atualizar docs checklist
    document.querySelectorAll('.inie-doc-chk').forEach(function(chk){
      var idx = parseInt(chk.dataset.idx);
      if(i.docs_checklist[idx]) i.docs_checklist[idx].ok = chk.checked;
    });
    iniSalvar(); fecharModal(); marcarAlterado(); iniRender();
    showToast('Inicial atualizada \u2713');
  }, '\ud83d\udcbe Salvar');
}

function iniExcluir(id){
  var ini = _iniciais.find(function(x){return String(x.id)===String(id);});
  abrirModal('Excluir inicial',
    '<div style="font-size:13px;color:var(--mu);line-height:1.6">Excluir a inicial de <strong style="color:var(--tx)">"'+(ini?escapeHtml(ini.cliente||'este cliente'):'este cliente')+'"</strong>?<br><span style="font-size:11px">Esta ação não pode ser desfeita.</span></div>',
    function(){
      _iniciais = _iniciais.filter(function(x){return String(x.id)!==String(id);});
      iniSalvar(); marcarAlterado(); fecharModal(); iniRender();
      showToast('Inicial excluída');
    }, 'Excluir'
  );
  setTimeout(function(){ var b=document.getElementById('modal-save'); if(b){b.style.background='var(--red)';b.textContent='Confirmar exclusão';} },50);
}


// ═══════════════════════════════════════════════════════
// ══ RELATÓRIO DE PARCEIRO/COLABORADOR ═════════════════
// ═══════════════════════════════════════════════════════

function abrirRelatorioParceiro(){
  var hoje = getTodayKey();
  var mesAtual = hoje.slice(0,7);
  // Listar parceiros/colaboradores encontrados nos lançamentos
  var parceiros = {};
  (localLanc||[]).forEach(function(l){
    if(l.parceiro_nome) parceiros[l.parceiro_nome] = 1;
    if(l.pago_por) parceiros[l.pago_por] = 1;
  });
  (_colaboradores||[]).forEach(function(c){ parceiros[c.nome] = 1; });
  var lista = Object.keys(parceiros).sort();

  var opts = lista.map(function(n){return '<option value="'+escapeHtml(n)+'">'+escapeHtml(n)+'</option>';}).join('');

  abrirModal('\ud83d\udcca Relat\u00f3rio de Parceiro / Colaborador',
    '<div class="fm-row">'
      +'<div style="flex:2"><label class="fm-lbl">Parceiro / Colaborador *</label>'
        +'<select class="fm-inp" id="rp-nome"><option value="">Selecione...</option>'+opts+'</select></div>'
      +'<div><label class="fm-lbl">M\u00eas</label>'
        +'<input class="fm-inp" type="month" id="rp-mes" value="'+mesAtual+'"></div>'
    +'</div>',
  function(){
    var nome = document.getElementById('rp-nome')?.value;
    var mes = document.getElementById('rp-mes')?.value||mesAtual;
    if(!nome){ showToast('Selecione o parceiro'); return; }
    fecharModal();
    _gerarRelatorioParceiro(nome, mes);
  }, '\ud83d\udcca Gerar relat\u00f3rio');
}

function _gerarRelatorioParceiro(nome, mes){
  var fV = function(v){return 'R$ '+Math.abs(v||0).toLocaleString('pt-BR',{minimumFractionDigits:2,maximumFractionDigits:2});};
  var nomeLower = nome.toLowerCase().trim();
  var MA = ['Janeiro','Fevereiro','Mar\u00e7o','Abril','Maio','Junho','Julho','Agosto','Setembro','Outubro','Novembro','Dezembro'];
  var mesLabel = MA[parseInt(mes.slice(5))-1]+' '+mes.slice(0,4);

  // 1. Honorários onde parceiro_nome = nome
  var honorarios = [];
  (localLanc||[]).forEach(function(l){
    if(!l.parceiro_nome) return;
    if(l.parceiro_nome.toLowerCase().trim()!==nomeLower) return;
    if(!(l.data||'').startsWith(mes)) return;
    if(!isRec(l)) return; // só recebidos
    var calc = _finCalcLanc(l);
    honorarios.push({
      cliente: l.cliente||'\u2014',
      data: l.data,
      desc: l.desc||'',
      valor: calc.base_calculo,
      comissao: calc.valor_parceiro,
      perc: l.parceiro_percentual||0
    });
  });

  // 2. Reembolsos (despesas pagas pelo parceiro)
  var reembolsos = [];
  (localLanc||[]).forEach(function(l){
    if(!l.pago_por) return;
    if(l.pago_por.toLowerCase().trim()!==nomeLower) return;
    if(!(l.data||'').startsWith(mes)) return;
    reembolsos.push({
      desc: l.desc||'\u2014',
      data: l.data,
      valor: parseFloat(l.valor)||0
    });
  });

  var totalComissao = honorarios.reduce(function(s,h){return s+h.comissao;},0);
  var totalReembolso = reembolsos.reduce(function(s,r){return s+r.valor;},0);
  var totalGeral = roundMoney(totalComissao + totalReembolso);

  // Gerar modal com resultado
  var html = '<div style="max-width:700px">';

  // Header
  html += '<div style="background:var(--sf3);border-radius:8px;padding:14px;margin-bottom:14px;text-align:center">'
    +'<div style="font-size:16px;font-weight:800;color:var(--tx)">RELAT\u00d3RIO REPASSE \u2014 '+escapeHtml(nome).toUpperCase()+'</div>'
    +'<div style="font-size:12px;color:var(--mu)">'+mesLabel+'</div>'
  +'</div>';

  // Totais
  html += '<div style="display:flex;gap:8px;margin-bottom:14px">'
    +'<div style="flex:1;padding:10px 12px;background:var(--sf2);border:1px solid var(--bd);border-radius:8px;text-align:center"><div style="font-size:9px;font-weight:700;text-transform:uppercase;color:var(--mu)">Comiss\u00e3o</div><div style="font-size:18px;font-weight:800;color:#4ade80">'+fV(totalComissao)+'</div></div>'
    +'<div style="flex:1;padding:10px 12px;background:var(--sf2);border:1px solid var(--bd);border-radius:8px;text-align:center"><div style="font-size:9px;font-weight:700;text-transform:uppercase;color:var(--mu)">Reembolsos</div><div style="font-size:18px;font-weight:800;color:#f59e0b">'+fV(totalReembolso)+'</div></div>'
    +'<div style="flex:1;padding:10px 12px;background:linear-gradient(135deg,var(--sf2),rgba(76,175,125,.1));border:1px solid rgba(76,175,125,.3);border-radius:8px;text-align:center"><div style="font-size:9px;font-weight:700;text-transform:uppercase;color:var(--mu)">Total a pagar</div><div style="font-size:18px;font-weight:800;color:#4ade80">'+fV(totalGeral)+'</div></div>'
  +'</div>';

  // Tabela honorários
  if(honorarios.length){
    html += '<div style="font-size:10px;font-weight:700;text-transform:uppercase;color:var(--mu);margin-bottom:6px">Honor\u00e1rios com comiss\u00e3o</div>'
      +'<table style="width:100%;border-collapse:collapse;margin-bottom:14px"><thead><tr style="background:var(--sf3)">'
        +'<th style="padding:6px 8px;text-align:left;font-size:10px;color:var(--mu)">Cliente</th>'
        +'<th style="padding:6px 8px;text-align:left;font-size:10px;color:var(--mu)">Data</th>'
        +'<th style="padding:6px 8px;text-align:left;font-size:10px;color:var(--mu)">Descri\u00e7\u00e3o</th>'
        +'<th style="padding:6px 8px;text-align:right;font-size:10px;color:var(--mu)">Valor</th>'
        +'<th style="padding:6px 8px;text-align:right;font-size:10px;color:var(--mu)">%</th>'
        +'<th style="padding:6px 8px;text-align:right;font-size:10px;color:var(--mu)">Comiss\u00e3o</th>'
      +'</tr></thead><tbody>';
    honorarios.forEach(function(h){
      html += '<tr style="border-bottom:1px solid var(--bd)">'
        +'<td style="padding:5px 8px;font-size:11px">'+escapeHtml(h.cliente)+'</td>'
        +'<td style="padding:5px 8px;font-size:11px;color:var(--mu)">'+fDt(h.data)+'</td>'
        +'<td style="padding:5px 8px;font-size:11px">'+escapeHtml(h.desc)+'</td>'
        +'<td style="padding:5px 8px;font-size:11px;text-align:right">'+fV(h.valor)+'</td>'
        +'<td style="padding:5px 8px;font-size:11px;text-align:right;color:var(--mu)">'+h.perc+'%</td>'
        +'<td style="padding:5px 8px;font-size:11px;text-align:right;font-weight:700;color:#4ade80">'+fV(h.comissao)+'</td>'
      +'</tr>';
    });
    html += '<tr style="background:var(--sf3)"><td colspan="5" style="padding:6px 8px;font-size:11px;font-weight:700">Total comiss\u00e3o</td><td style="padding:6px 8px;font-size:12px;font-weight:800;text-align:right;color:#4ade80">'+fV(totalComissao)+'</td></tr>';
    html += '</tbody></table>';
  } else {
    html += '<div style="font-size:11px;color:var(--mu);margin-bottom:14px">Nenhum honor\u00e1rio com comiss\u00e3o neste m\u00eas.</div>';
  }

  // Tabela reembolsos
  if(reembolsos.length){
    html += '<div style="font-size:10px;font-weight:700;text-transform:uppercase;color:var(--mu);margin-bottom:6px">Reembolsos</div>'
      +'<table style="width:100%;border-collapse:collapse;margin-bottom:14px"><thead><tr style="background:var(--sf3)">'
        +'<th style="padding:6px 8px;text-align:left;font-size:10px;color:var(--mu)">Descri\u00e7\u00e3o</th>'
        +'<th style="padding:6px 8px;text-align:left;font-size:10px;color:var(--mu)">Data</th>'
        +'<th style="padding:6px 8px;text-align:right;font-size:10px;color:var(--mu)">Valor</th>'
      +'</tr></thead><tbody>';
    reembolsos.forEach(function(r){
      html += '<tr style="border-bottom:1px solid var(--bd)">'
        +'<td style="padding:5px 8px;font-size:11px">'+escapeHtml(r.desc)+'</td>'
        +'<td style="padding:5px 8px;font-size:11px;color:var(--mu)">'+fDt(r.data)+'</td>'
        +'<td style="padding:5px 8px;font-size:11px;text-align:right;font-weight:700;color:#f59e0b">'+fV(r.valor)+'</td>'
      +'</tr>';
    });
    html += '<tr style="background:var(--sf3)"><td colspan="2" style="padding:6px 8px;font-size:11px;font-weight:700">Total reembolsos</td><td style="padding:6px 8px;font-size:12px;font-weight:800;text-align:right;color:#f59e0b">'+fV(totalReembolso)+'</td></tr>';
    html += '</tbody></table>';
  }

  html += '</div>';

  // Botões
  abrirModal('\ud83d\udcca Relat\u00f3rio \u2014 '+escapeHtml(nome)+' \u2014 '+mesLabel, html, function(){
    // Copiar para WhatsApp
    var txt = '*RELAT\u00d3RIO REPASSE '+nome.toUpperCase()+' \u2014 '+mesLabel+'*\n\n';
    if(honorarios.length){
      txt += '*Honor\u00e1rios:*\n';
      honorarios.forEach(function(h){ txt += '\u2022 '+h.cliente+' \u2014 '+escapeHtml(h.desc)+' \u2014 '+fV(h.valor)+' \u2192 '+h.perc+'% = '+fV(h.comissao)+'\n'; });
      txt += '*Total comiss\u00e3o: '+fV(totalComissao)+'*\n\n';
    }
    if(reembolsos.length){
      txt += '*Reembolsos:*\n';
      reembolsos.forEach(function(r){ txt += '\u2022 '+escapeHtml(r.desc)+' \u2014 '+fV(r.valor)+'\n'; });
      txt += '*Total reembolsos: '+fV(totalReembolso)+'*\n\n';
    }
    txt += '*TOTAL A PAGAR: '+fV(totalGeral)+'*\n\n_CO Advocacia_';
    navigator.clipboard.writeText(txt).then(function(){ showToast('\u2713 Relat\u00f3rio copiado para WhatsApp!'); }).catch(function(){});
  }, '\ud83d\udcf2 Copiar para WhatsApp');
}

var DATAJUD_URL = 'https://api-publica.datajud.cnj.jus.br';
var DATAJUD_KEY = 'cDZHYzlZa0JadVREZDJCendQbXY6SkJlTzNjLV9TRENyQk1RdnFKZGRQdw==';

// Mapa de tribunal por código do número unificado (dígitos 14-16)
var _djTribunais = {
  '5.01':'trt1','5.02':'trt2','5.03':'trt3','5.04':'trt4','5.05':'trt5',
  '5.06':'trt6','5.07':'trt7','5.08':'trt8','5.09':'trt9','5.10':'trt10',
  '5.11':'trt11','5.12':'trt12','5.13':'trt13','5.14':'trt14','5.15':'trt15',
  '5.16':'trt16','5.17':'trt17','5.18':'trt18','5.19':'trt19','5.20':'trt20',
  '5.21':'trt21','5.22':'trt22','5.23':'trt23','5.24':'trt24',
  '8.03':'tjmg','8.13':'tjmg','8.26':'tjsp','8.19':'tjrj',
  '4.01':'trf1','4.02':'trf2','4.03':'trf3','4.04':'trf4','4.05':'trf5','4.06':'trf6'
};

function _djDetectarTribunal(numero){
  // Número unificado CNJ: NNNNNNN-DD.AAAA.J.TT.OOOO
  var limpo = (numero||'').replace(/[^0-9.]/g,'');
  // Tentar extrair justiça.tribunal (posições após ano)
  var m = (numero||'').match(/\d{7}-?\d{2}\.?\d{4}\.(\d)\.(\d{2})\./);
  if(m){
    var chave = m[1]+'.'+m[2].replace(/^0/,'');
    if(_djTribunais[chave]) return _djTribunais[chave];
    var chave2 = m[1]+'.'+m[2];
    if(_djTribunais[chave2]) return _djTribunais[chave2];
  }
  return 'trt3'; // default para TRT3 (MG)
}

function _djLimparNumero(numero){
  return (numero||'').replace(/[^0-9]/g,'');
}

// Consultar movimentações de um processo (via CORS proxy que repassa headers)
function djConsultar(numero, callback){
  var trib = _djDetectarTribunal(numero);
  var apiUrl = DATAJUD_URL + '/api_publica_' + trib + '/_search';
  var numLimpo = _djLimparNumero(numero);
  var bodyStr = JSON.stringify({
    query: { match: { numeroProcesso: numLimpo } },
    size: 1
  });

  // corsproxy.io repassa headers incluindo Authorization
  var proxyUrl = 'https://corsproxy.io/?' + encodeURIComponent(apiUrl);

  fetch(proxyUrl, {
    method: 'POST',
    headers: {
      'Authorization': 'APIKey ' + DATAJUD_KEY,
      'Content-Type': 'application/json'
    },
    body: bodyStr
  })
  .then(function(r){
    if(!r.ok) throw new Error('DataJud HTTP ' + r.status);
    return r.json();
  })
  .then(function(data){
    var hits = data.hits && data.hits.hits;
    if(!hits || !hits.length){
      callback(null, 'Processo não encontrado no DataJud');
      return;
    }
    var proc = hits[0]._source;
    callback(proc, null);
  })
  .catch(function(err){
    callback(null, err.message || 'Erro ao consultar DataJud');
  });
}

// Verificar tribunal — modal flutuante sem salvar nada
function djSincronizar(cid){
  var c = findClientById(cid);
  if(!c || !c.numero){ showToast('Processo sem n\u00famero cadastrado'); return; }

  abrirModal('\ud83d\udd0d Verificando Tribunal', '<div style="text-align:center;padding:20px"><div style="font-size:24px;margin-bottom:8px">\u23f3</div><div style="color:var(--mu)">Consultando DataJud...</div><div style="font-size:10px;color:var(--mu);margin-top:4px">'+escapeHtml(c.numero)+'</div></div>', null, null);

  djConsultar(c.numero, function(proc, erro){
    fecharModal();
    if(erro){ abrirModal('\u274c Erro na consulta', '<div style="padding:12px;color:#f87676">'+escapeHtml(erro)+'</div>', null, 'Fechar'); return; }

    var movsTrib = (proc.movimentos||[]).sort(function(a,b){ return (b.dataHora||'').localeCompare(a.dataHora||''); });
    if(!movsTrib.length){ abrirModal('\ud83d\udd0d Resultado', '<div style="padding:12px;color:var(--mu)">Nenhuma movimenta\u00e7\u00e3o encontrada no tribunal.</div>', null, 'Fechar'); return; }

    // Comparar com movimentações locais
    var movsLocais = new Set();
    var cMovs = (localMov[cid]||[]).concat(c.movimentacoes||[]);
    cMovs.forEach(function(m){
      var dt = (m.data_movimentacao||m.data||'').slice(0,10);
      var txt = (m.movimentacao||m.desc||m.descricao||'').toLowerCase().slice(0,40);
      movsLocais.add(dt+'|'+txt);
    });

    var novidades = 0;
    var vara = proc.orgaoJulgador ? proc.orgaoJulgador.nome : '';
    var classe = proc.classe ? proc.classe.nome : '';

    var html = '<div style="margin-bottom:12px;background:var(--sf3);border-radius:6px;padding:10px 12px">'
      +'<div style="font-size:12px;font-weight:700;color:var(--tx)">'+escapeHtml(c.cliente)+'</div>'
      +'<div style="font-size:10px;color:var(--mu)">'+escapeHtml(c.numero)+(vara?' \u00b7 '+escapeHtml(vara):'')+(classe?' \u00b7 '+escapeHtml(classe):'')+'</div>'
    +'</div>';

    html += '<div style="font-size:10px;font-weight:700;text-transform:uppercase;color:var(--mu);margin-bottom:6px;letter-spacing:.05em">\u00daltimas movimenta\u00e7\u00f5es do tribunal ('+movsTrib.length+')</div>';
    html += '<div style="max-height:350px;overflow-y:auto">';

    movsTrib.slice(0,30).forEach(function(m){
      var dt = (m.dataHora||'').slice(0,10);
      var nome = m.nome||'';
      var compl = (m.complementosTabelados||[]).map(function(c2){return c2.nome||'';}).join(', ');
      var txtFull = nome+(compl?' \u2014 '+compl:'');
      var txtCheck = dt+'|'+txtFull.toLowerCase().slice(0,40);
      var isNova = !movsLocais.has(txtCheck);
      if(isNova) novidades++;

      html += '<div style="display:flex;gap:8px;padding:6px 0;border-bottom:1px solid var(--bd)'+(isNova?';background:rgba(245,158,11,.08);margin:0 -8px;padding-left:8px;padding-right:8px;border-radius:4px':'')+'">'
        +'<div style="min-width:70px;font-size:10px;color:var(--mu);font-weight:600">'+fDt(dt)+'</div>'
        +'<div style="flex:1">'
          +'<div style="font-size:11px;color:var(--tx)">'+escapeHtml(nome)+'</div>'
          +(compl?'<div style="font-size:10px;color:var(--mu)">'+escapeHtml(compl)+'</div>':'')
        +'</div>'
        +(isNova?'<span style="font-size:8px;padding:2px 6px;border-radius:3px;background:rgba(245,158,11,.2);color:#f59e0b;font-weight:700;align-self:center">NOVA</span>':'')
      +'</div>';
    });
    html += '</div>';

    // Resumo
    var resumo = novidades > 0
      ? '<div style="margin-top:12px;background:rgba(245,158,11,.08);border:1px solid rgba(245,158,11,.3);border-radius:6px;padding:8px 12px;font-size:11px;color:#f59e0b;font-weight:700">\u26a0 '+novidades+' movimenta\u00e7\u00e3o'+(novidades>1?'\u00f5es':'')+' nova'+(novidades>1?'s':'')+' que n\u00e3o est\u00e3o na pasta</div>'
      : '<div style="margin-top:12px;background:rgba(76,175,125,.08);border:1px solid rgba(76,175,125,.3);border-radius:6px;padding:8px 12px;font-size:11px;color:#4ade80;font-weight:700">\u2713 Pasta atualizada \u2014 nenhuma novidade</div>';

    abrirModal('\ud83d\udd0d Tribunal \u2014 '+escapeHtml(c.cliente), html+resumo, novidades>0?function(){
      // Importar novidades
      var importados = 0;
      movsTrib.forEach(function(m){
        var dt = (m.dataHora||'').slice(0,10);
        var nome = m.nome||'';
        var compl = (m.complementosTabelados||[]).map(function(c2){return c2.nome||'';}).join(', ');
        var txtFull = nome+(compl?' \u2014 '+compl:'');
        var txtCheck = dt+'|'+txtFull.toLowerCase().slice(0,40);
        if(!movsLocais.has(txtCheck)){
          if(!localMov[cid]) localMov[cid]=[];
          localMov[cid].unshift({data:dt, movimentacao:'[DataJud] '+txtFull, tipo_movimentacao:'DataJud', origem:'datajud'});
          importados++;
        }
      });
      if(importados>0){
        sbSet('co_localMov', localMov);
        marcarAlterado();
        if(AC && AC.id===cid) renderFicha(AC, AC_PROC);
      }
      fecharModal();
      showToast('\u2713 '+importados+' movimenta\u00e7\u00e3o'+(importados>1?'\u00f5es':'')+' importada'+(importados>1?'s':''));
    }:null, novidades>0?'\ud83d\udce5 Importar novidades':'Fechar');
  });
}

// Sincronizar TODOS os processos ativos com número
function djSincronizarTodos(){
  var ativos = (CLIENTS||[]).filter(function(c){
    return c.numero && !isEncerrado(c.id);
  });
  if(!ativos.length){ showToast('Nenhum processo com número cadastrado'); return; }

  showToast('🔄 Atualizando ' + ativos.length + ' processos...');
  var idx = 0, atualizados = 0;

  function proximo(){
    if(idx >= ativos.length){
      sbSalvarClientes(); marcarAlterado();
      showToast('✓ ' + atualizados + '/' + ativos.length + ' processos atualizados');
      return;
    }
    var c = ativos[idx]; idx++;
    djConsultar(c.numero, function(proc, erro){
      if(!erro && proc){
        var movs = proc.movimentos || [];
        if(movs.length){
          var ultDt = movs.reduce(function(max,m){var d=(m.dataHora||'').slice(0,10);return d>max?d:max;},'');
          if(ultDt){ c.ultima_mov=ultDt; c.ultima_mov_dias=Math.ceil((new Date()-new Date(ultDt))/86400000); atualizados++; }
        }
        if(proc.classe && proc.classe.nome && !c.natureza) c.natureza = proc.classe.nome;
        if(proc.orgaoJulgador && proc.orgaoJulgador.nome) c._vara_datajud = proc.orgaoJulgador.nome;
      }
      setTimeout(proximo, 250);
    });
  }
  proximo();
}

// ── Debounce no input de busca (#srch) ─────────────────────────
// Substitui o oninput inline por um handler com _debounce para evitar
// re-render a cada tecla (doSearch → renderVclEmpty → _vfConsolidar é caro).
document.addEventListener('DOMContentLoaded', function(){
  var srchEl = document.getElementById('srch');
  if(srchEl){
    // Remover oninput inline se existir, substituir por debounce
    srchEl.oninput = function(){ _debounce('srchInput', doSearch, 250); };
  }
});


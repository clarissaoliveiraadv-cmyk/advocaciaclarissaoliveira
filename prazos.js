'use strict';
/* ============================================================
 * repoPrazos - Repositorio de Prazos Processuais (legado)
 * ============================================================
 *
 * RESPONSABILIDADE
 * ----------------
 * Encapsular o acesso ao objeto global `prazos`
 * (formato: { [cid]: Array<prazo> }) e a chave Supabase `co_prazos`.
 *
 * IMPORTANTE: o sistema esta em transicao. A funcao interna
 * `_migrarPrazosParaAg` (no bundle.js) copia prazos para `localAg`
 * com a flag `_prazo_legado_id`. Mesmo assim, varias telas ainda
 * escrevem em `prazos[cid]` (calculadora de prazos, ficha do cliente,
 * togglePrazo, prazosConcluirComDesfecho, editarPrazo, deletarPrazo).
 * Este repo serve essas telas legadas - sem inventar fonte de
 * verdade nova nesta etapa.
 *
 * LIMITES (o que ESTE repo faz)
 * -----------------------------
 *   - listar / filtrar prazos por cliente
 *   - adicionar / atualizar / marcar cumprido / marcar deletado
 *   - persistir via `sbSet('co_prazos', prazos)`
 *   - registrar tombstone via `_tombstoneAdd('co_prazos', id)`
 *   - sinalizar mudanca via `marcarAlterado()`
 *   - aplicar payload remoto vindo de `sbAplicar` (Realtime)
 *
 * O QUE NAO DEVE SER FEITO AQUI
 * -----------------------------
 *   - NAO inserir andamentos em `localMov` (esse efeito vive
 *     no call-site `prazosConcluirComDesfecho`).
 *   - NAO chamar render (renderPrazos, renderFicha, etc.).
 *   - NAO sincronizar com `localAg` aqui. A funcao `_syncPrazoToAg`
 *     no bundle continua sendo responsabilidade do call-site.
 *   - NAO mexer em `localAg`. Para isso existe `repoAgenda`.
 *   - NAO trocar a fonte de dados. Migracao para schema relacional
 *     (tabela `compromissos` com tipo='prazo') e a Etapa 5.
 *
 * DEPENDENCIAS GLOBAIS TEMPORARIAS (Etapa 2)
 * ------------------------------------------
 *   - window.prazos          objeto global { [cid]: Array }
 *   - window.sbSet           persistencia
 *   - window._tombstoneAdd   marcacao de exclusao
 *   - window.marcarAlterado  flag de mudanca pendente
 *
 * MODO DEBUG
 * ----------
 * Setar `window.CO_DEBUG = true` no console habilita console.debug.
 * ============================================================ */
(function () {

  // ---------- helper de debug ----------
  function dbg() {
    if (!window.CO_DEBUG) return;
    try {
      var args = ['[repoPrazos]'].concat([].slice.call(arguments));
      console.debug.apply(console, args);
    } catch (_) { /* ignore */ }
  }

  // ---------- guarda do estado global ----------
  function _obj() {
    if (!window.prazos || typeof window.prazos !== 'object' || Array.isArray(window.prazos)) {
      window.prazos = {};
    }
    return window.prazos;
  }

  function _bucket(cid) {
    var o = _obj();
    if (!Array.isArray(o[cid])) o[cid] = [];
    return o[cid];
  }

  // ---------- persistencia ----------
  // _persist: side-effect EXPLICITO. Replica o que `prazosSalvar()`
  // do bundle ja fazia + a chamada a marcarAlterado() que os
  // call-sites tipicamente faziam logo em seguida.
  //   1) sbSet('co_prazos', prazos)
  //   2) marcarAlterado()
  function _persist() {
    if (typeof window.sbSet === 'function') {
      window.sbSet('co_prazos', window.prazos);
    } else {
      console.warn('[repoPrazos] sbSet indisponivel - persistencia ignorada');
    }
    if (typeof window.marcarAlterado === 'function') window.marcarAlterado();
  }

  // ============================================================
  // LEITURA
  // ============================================================

  function listarPorCliente(cid) {
    if (cid == null) return [];
    var bucket = _obj()[cid];
    return Array.isArray(bucket) ? bucket : [];
  }

  function obterPorId(cid, pid) {
    if (cid == null || pid == null) return null;
    var bucket = listarPorCliente(cid);
    for (var i = 0; i < bucket.length; i++) {
      if (bucket[i] && bucket[i].id === pid) return bucket[i];
    }
    return null;
  }

  // ============================================================
  // ESCRITA
  // ============================================================

  /**
   * adicionar(cid, prazo):
   * Push no array prazos[cid]. Cria o array se nao existir.
   * NAO gera id (call-site continua chamando genId).
   */
  function adicionar(cid, prazo) {
    if (cid == null || !prazo || prazo.id == null) {
      console.warn('[repoPrazos.adicionar] argumentos invalidos');
      return null;
    }
    var bucket = _bucket(cid);
    bucket.push(prazo);
    dbg('adicionar', cid, prazo.id);
    _persist();          // sbSet + marcarAlterado
    return prazo;
  }

  /**
   * atualizar(cid, pid, patch):
   * Merge superficial em prazos[cid][i]. Equivalente a
   * `prazos[cid][idx] = {...prazos[cid][idx], ...patch}`.
   * Retorna o objeto resultante ou null se nao encontrar.
   */
  function atualizar(cid, pid, patch) {
    var bucket = _bucket(cid);
    for (var i = 0; i < bucket.length; i++) {
      if (bucket[i] && bucket[i].id === pid) {
        var atualizado = Object.assign({}, bucket[i], patch || {});
        bucket[i] = atualizado;
        dbg('atualizar', cid, pid, Object.keys(patch || {}));
        _persist();      // sbSet + marcarAlterado
        return atualizado;
      }
    }
    dbg('atualizar: pid inexistente', cid, pid);
    return null;
  }

  /**
   * marcarCumprido(cid, pid, dados):
   * Encapsula o padrao de `togglePrazo` e parte de
   * `prazosConcluirComDesfecho`.
   *
   * dados (opcional):
   *   { obs_conclusao, protocolo }   se omitido, faz toggle simples
   *
   * Mantem `cumprido_em` automaticamente quando passa de false->true.
   */
  function marcarCumprido(cid, pid, dados) {
    var atual = obterPorId(cid, pid);
    if (!atual) {
      dbg('marcarCumprido: pid inexistente', cid, pid);
      return null;
    }
    var foiCumprido = !!atual.cumprido;
    var agora = !foiCumprido;                  // toggle
    var patch = {
      cumprido: agora,
      cumprido_em: agora ? new Date().toISOString() : null
    };
    if (dados && typeof dados.obs_conclusao !== 'undefined') {
      patch.obs_conclusao = dados.obs_conclusao;
    }
    if (dados && typeof dados.protocolo !== 'undefined') {
      patch.protocolo = dados.protocolo;
    }
    return atualizar(cid, pid, patch);
  }

  /**
   * marcarDeletado(cid, pid):
   * Soft-delete usado por `deletarPrazo`. Replica o padrao
   *   prazos[cid] = prazos[cid].map(p => p.id===pid ? {...p, deleted:true} : p)
   * + tombstone em 'co_prazos'.
   *
   * NAO faz filter (mantem item como tombstone para anti-ressurreicao
   * via Realtime, igual ao codigo atual).
   */
  function marcarDeletado(cid, pid) {
    if (cid == null || pid == null) return false;
    var bucket = _bucket(cid);
    var marcou = false;
    for (var i = 0; i < bucket.length; i++) {
      if (bucket[i] && bucket[i].id === pid) {
        bucket[i] = Object.assign({}, bucket[i], { deleted: true });
        marcou = true;
        break;
      }
    }
    if (!marcou) {
      dbg('marcarDeletado: pid inexistente', cid, pid);
      return false;
    }
    if (typeof window._tombstoneAdd === 'function') {
      window._tombstoneAdd('co_prazos', pid);
    } else {
      console.warn('[repoPrazos.marcarDeletado] _tombstoneAdd indisponivel');
    }
    dbg('marcarDeletado', cid, pid);
    _persist();          // sbSet + marcarAlterado
    return true;
  }

  // ============================================================
  // REALTIME
  // ============================================================

  /**
   * aplicarRemoto(obj): reescreve `prazos` com payload vindo do
   * Supabase Realtime. Equivalente ao case 'co_prazos' (e legado
   * 'co_td') em sbAplicar.
   * NAO chama _persist (fonte remota; gravar voltaria em loop).
   */
  function aplicarRemoto(obj) {
    if (!obj || typeof obj !== 'object' || Array.isArray(obj)) {
      window.prazos = {};
    } else {
      window.prazos = obj;
    }
    dbg('aplicarRemoto: ', Object.keys(window.prazos).length, 'clientes');
    return window.prazos;
  }

  // ============================================================
  // ESCAPE HATCH
  // ============================================================
  function _raw() { return _obj(); }
  function _marcarPersistir() { _persist(); }

  // ============================================================
  // EXPORT
  // ============================================================
  window.repoPrazos = {
    listarPorCliente: listarPorCliente,
    obterPorId: obterPorId,
    adicionar: adicionar,
    atualizar: atualizar,
    marcarCumprido: marcarCumprido,
    marcarDeletado: marcarDeletado,
    aplicarRemoto: aplicarRemoto,
    _raw: _raw,
    _marcarPersistir: _marcarPersistir
  };

  dbg('carregado');
})();

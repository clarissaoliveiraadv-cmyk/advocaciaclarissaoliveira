'use strict';
/* ============================================================
 * repoAgenda - Repositorio de Compromissos / Agenda
 * ============================================================
 *
 * RESPONSABILIDADE
 * ----------------
 * Encapsular o acesso ao array global `localAg` e a chave Supabase
 * `co_ag`. Esta deve ser a unica superficie onde o codigo do bundle
 * faz mutacoes em compromissos / audiencias / reunioes / prazos
 * legados copiados para a agenda.
 *
 * LIMITES (o que ESTE repo faz)
 * -----------------------------
 *   - listar / filtrar `localAg`
 *   - criar / atualizar / excluir compromissos no array
 *   - persistir via `sbSet('co_ag', localAg)`
 *   - registrar tombstone via `_tombstoneAdd('co_ag'|'co_localAg', id)`
 *   - sinalizar mudanca via `marcarAlterado()` e `invalidarAllPend()`
 *   - aplicar payload remoto vindo de `sbAplicar` (Realtime)
 *
 * O QUE NAO DEVE SER FEITO AQUI
 * -----------------------------
 *   - NAO inserir andamentos em `localMov` daqui. Esse efeito vive
 *     no call-site (ex.: prazosConcluirComDesfecho, novoCompromisso).
 *   - NAO chamar nenhum render (renderFicha, renderAgendaProc, etc.).
 *     Quem coordena tela e o call-site.
 *   - NAO validar regra de negocio juridica (datas relativas a prazo,
 *     fatalidade, recorrencia). Continua no bundle.
 *   - NAO mexer em `prazos` (objeto). Para isso existe `repoPrazos`.
 *   - NAO trocar a fonte de dados nesta etapa. A migracao para o
 *     schema relacional esta prevista para a Etapa 5.
 *
 * DEPENDENCIAS GLOBAIS TEMPORARIAS (Etapa 2)
 * ------------------------------------------
 * Quando o bundle for modularizado (Etapa 6), estas dependencias
 * deixarao de ser globais e passarao a ser injetadas:
 *   - window.localAg          array global
 *   - window.sbSet            persistencia Supabase + localStorage
 *   - window._tombstoneAdd    marcacao de exclusao (anti-ressurreicao)
 *   - window._tombstoneHas    consulta de tombstone
 *   - window.marcarAlterado   flag de "ha mudancas nao sincronizadas"
 *   - window.invalidarAllPend invalidacao do cache de allPend()
 *
 * MODO DEBUG
 * ----------
 * Setar `window.CO_DEBUG = true` no console habilita console.debug
 * em cada operacao. Default: silencioso.
 * ============================================================ */
(function () {

  // ---------- helper de debug (sem dependencia global) ----------
  function dbg() {
    if (!window.CO_DEBUG) return;
    try {
      var args = ['[repoAgenda]'].concat([].slice.call(arguments));
      console.debug.apply(console, args);
    } catch (_) { /* ignore */ }
  }

  // ---------- guarda do estado global ----------
  function _arr() {
    if (!Array.isArray(window.localAg)) window.localAg = [];
    return window.localAg;
  }

  // ---------- persistencia ----------
  // _persist: side-effect EXPLICITO. Os 3 efeitos abaixo sao
  // exatamente os que os call-sites antigos faziam manualmente
  // apos cada mutacao:
  //   1) sbSet('co_ag', localAg)      -> Supabase + localStorage
  //   2) marcarAlterado()             -> flag de mudanca pendente
  //   3) invalidarAllPend()           -> cache de allPend()
  function _persist() {
    if (typeof window.sbSet === 'function') {
      window.sbSet('co_ag', window.localAg);
    } else {
      console.warn('[repoAgenda] sbSet indisponivel - persistencia ignorada');
    }
    if (typeof window.marcarAlterado === 'function') window.marcarAlterado();
    if (typeof window.invalidarAllPend === 'function') window.invalidarAllPend();
  }

  // ============================================================
  // LEITURA
  // ============================================================

  function listar() {
    return _arr();
  }

  function listarPorCliente(cid) {
    if (cid == null) return [];
    return _arr().filter(function (ev) { return ev && ev.cid === cid; });
  }

  function obterPorId(id) {
    if (id == null) return null;
    var arr = _arr();
    for (var i = 0; i < arr.length; i++) {
      if (arr[i] && arr[i].id === id) return arr[i];
    }
    return null;
  }

  // ============================================================
  // ESCRITA
  // ============================================================

  /**
   * criar(ev): insere ou substitui um compromisso pelo id.
   * - NAO gera id automaticamente (call-site continua responsavel
   *   pelo genId, igual hoje).
   * - Se ja existir um item com o mesmo id, substitui (comportamento
   *   atual em varios call-sites era split entre push/replace).
   * Retorna o objeto persistido ou null se invalido.
   */
  function criar(ev) {
    if (!ev || ev.id == null) {
      console.warn('[repoAgenda.criar] ev sem id - ignorado');
      return null;
    }
    var arr = _arr();
    var idx = -1;
    for (var i = 0; i < arr.length; i++) {
      if (arr[i] && arr[i].id === ev.id) { idx = i; break; }
    }
    if (idx >= 0) {
      dbg('criar: id ja existia, substituindo', ev.id);
      arr[idx] = ev;
    } else {
      dbg('criar: novo', ev.id);
      arr.push(ev);
    }
    _persist();          // sbSet + marcarAlterado + invalidarAllPend
    return ev;
  }

  /**
   * atualizar(id, patch): merge superficial.
   * Retorna o objeto resultante, ou null se id nao existe.
   */
  function atualizar(id, patch) {
    var arr = _arr();
    for (var i = 0; i < arr.length; i++) {
      if (arr[i] && arr[i].id === id) {
        var atualizado = Object.assign({}, arr[i], patch || {});
        arr[i] = atualizado;
        dbg('atualizar', id, Object.keys(patch || {}));
        _persist();      // sbSet + marcarAlterado + invalidarAllPend
        return atualizado;
      }
    }
    dbg('atualizar: id inexistente', id);
    return null;
  }

  /**
   * marcarRealizado(id, valor):
   * Encapsula o padrao `localAg[i].realizado = !` + manter `cumprido`
   * em sincronia (presente no codigo atual).
   * Se `valor` nao for boolean, faz toggle do estado atual.
   */
  function marcarRealizado(id, valor) {
    var atual = obterPorId(id);
    if (!atual) {
      dbg('marcarRealizado: id inexistente', id);
      return null;
    }
    var novo = (typeof valor === 'boolean') ? valor : !atual.realizado;
    return atualizar(id, { realizado: novo, cumprido: novo });
  }

  /**
   * excluir(id, opts):
   * Remove o item por id e registra tombstone.
   * opts.scope:
   *   'ambos'      (default) tombstone em co_ag E co_localAg
   *                (espelha o comportamento de excluirAgCliente
   *                 e deletarPrazo, que limpam ambas as chaves)
   *   'co_ag'      tombstone apenas em co_ag
   *   'co_localAg' tombstone apenas em co_localAg
   * Retorna true se removeu, false se id nao existia.
   */
  function excluir(id, opts) {
    if (id == null) return false;
    var scope = (opts && opts.scope) || 'ambos';
    var arr = _arr();
    var antes = arr.length;
    window.localAg = arr.filter(function (ev) { return !ev || ev.id !== id; });
    var removidos = antes - window.localAg.length;
    if (removidos === 0) {
      dbg('excluir: id inexistente', id);
      return false;
    }
    if (typeof window._tombstoneAdd === 'function') {
      if (scope === 'ambos' || scope === 'co_ag')      window._tombstoneAdd('co_ag', id);
      if (scope === 'ambos' || scope === 'co_localAg') window._tombstoneAdd('co_localAg', id);
    } else {
      console.warn('[repoAgenda.excluir] _tombstoneAdd indisponivel - tombstone ignorado');
    }
    dbg('excluir', id, 'scope=' + scope);
    _persist();          // sbSet + marcarAlterado + invalidarAllPend
    return true;
  }

  // ============================================================
  // VARIANTES "idLike" - pattern legado id || id_agenda
  // ============================================================
  // No bundle.js varias funcoes (excluirAgCliente, editarAgCliente,
  // hcToggle ramo agenda, agendaConcluirComDesfecho, modal de evento)
  // resolvem o item percorrendo localAg com o pattern:
  //   String(a.id)===raw || String(a.id_agenda)===raw
  //
  // Esses dois metodos espelham EXATAMENTE essa semantica para
  // permitir que esses call-sites sejam migrados na sub-etapa 2.D
  // sem regressao. NAO sao alias - operam sobre os dois campos.
  //
  // Comparacao sempre por String(...) para casar a convencao do
  // bundle (ids podem ser number ou string conforme a origem).
  // ============================================================

  /**
   * obterPorIdLike(idLike):
   * Retorna o PRIMEIRO item de localAg cujo `id` ou `id_agenda`
   * (comparados como String) bate com idLike.
   * Retorna null se nenhum casa, ou se idLike for null/undefined.
   */
  function obterPorIdLike(idLike) {
    if (idLike == null) return null;
    var raw = String(idLike);
    var arr = _arr();
    for (var i = 0; i < arr.length; i++) {
      var ev = arr[i];
      if (!ev) continue;
      if (String(ev.id) === raw)         return ev;
      if (String(ev.id_agenda) === raw)  return ev;
    }
    dbg('obterPorIdLike: idLike inexistente', idLike);
    return null;
  }

  /**
   * excluirPorIdLike(idLike, opts):
   * Remove TODOS os itens cujo `id` ou `id_agenda` casa com idLike
   * (espelha o `localAg.filter(a => id!==raw && id_agenda!==raw)`
   * que ja existe no bundle - pode remover mais de 1 se houver
   * duplicidade entre id e id_agenda).
   *
   * Registra tombstone igual a `excluir()`. opts.scope:
   *   'ambos'      (default) tombstone em co_ag E co_localAg
   *   'co_ag'      tombstone apenas em co_ag
   *   'co_localAg' tombstone apenas em co_localAg
   *
   * Retorna true se removeu pelo menos 1 item; false se nenhum casou.
   */
  function excluirPorIdLike(idLike, opts) {
    if (idLike == null) return false;
    var raw = String(idLike);
    var scope = (opts && opts.scope) || 'ambos';
    var arr = _arr();
    var antes = arr.length;
    window.localAg = arr.filter(function (ev) {
      if (!ev) return true;
      return String(ev.id) !== raw && String(ev.id_agenda) !== raw;
    });
    var removidos = antes - window.localAg.length;
    if (removidos === 0) {
      dbg('excluirPorIdLike: idLike inexistente', idLike);
      return false;
    }
    if (typeof window._tombstoneAdd === 'function') {
      if (scope === 'ambos' || scope === 'co_ag')      window._tombstoneAdd('co_ag', raw);
      if (scope === 'ambos' || scope === 'co_localAg') window._tombstoneAdd('co_localAg', raw);
    } else {
      console.warn('[repoAgenda.excluirPorIdLike] _tombstoneAdd indisponivel - tombstone ignorado');
    }
    dbg('excluirPorIdLike', raw, 'scope=' + scope, 'removidos=' + removidos);
    _persist();          // sbSet + marcarAlterado + invalidarAllPend
    return true;
  }

  // ============================================================
  // REALTIME (consumo de payload remoto)
  // ============================================================

  /**
   * aplicarRemoto(arr): reescreve `localAg` com payload vindo do
   * Supabase Realtime, respeitando tombstones locais.
   * Equivalente ao corpo dos cases 'co_ag'/'co_localAg' em sbAplicar.
   *
   * NAO chama _persist (a fonte e remota; gravar de volta provocaria
   * loop). Apenas invalida o cache de allPend para a UI re-renderizar.
   */
  function aplicarRemoto(arr) {
    var novo = Array.isArray(arr) ? arr.slice() : [];
    if (typeof window._tombstoneHas === 'function') {
      novo = novo.filter(function (x) {
        if (!x || x.id == null) return true;
        return !window._tombstoneHas('co_ag', x.id) &&
               !window._tombstoneHas('co_localAg', x.id);
      });
    }
    window.localAg = novo;
    if (typeof window.invalidarAllPend === 'function') window.invalidarAllPend();
    dbg('aplicarRemoto:', novo.length, 'itens');
    return window.localAg;
  }

  /**
   * filtrarPorTombstones(baseKey): remove itens de localAg cujo id
   * esta tombstoneado em `baseKey`. Usado pelo sbAplicar quando
   * recebe payload "_del" via Realtime (B2/v145).
   *
   * NAO chama _persist: o filtro acontece em resposta a payload remoto;
   * regravar provocaria loop com o proprio Realtime que entregou o tombstone.
   * Equivalente funcional ao localAg.filter(...) que estava inline no bundle.
   */
  function filtrarPorTombstones(baseKey) {
    if (!baseKey) return _arr();
    var antes = _arr().length;
    window.localAg = _arr().filter(function (x) {
      if (!x || x.id == null) return true;
      return typeof window._tombstoneHas === 'function'
        ? !window._tombstoneHas(baseKey, x.id)
        : true;
    });
    var removidos = antes - window.localAg.length;
    if (typeof window.invalidarAllPend === 'function') window.invalidarAllPend();
    dbg('filtrarPorTombstones', baseKey, 'removidos=' + removidos);
    return window.localAg;
  }

  // ============================================================
  // ESCAPE HATCH (transicao - usar com parcimonia)
  // ============================================================

  /**
   * _raw(): acesso direto ao array.
   * Usar apenas em casos exoticos da transicao (dedup em massa,
   * migracoes, _migrarPrazosParaAg). Toda chamada deve vir com
   * comentario explicando o motivo. Apos mexer no array, chamar
   * _marcarPersistir().
   */
  function _raw() { return _arr(); }
  function _marcarPersistir() { _persist(); }

  // ============================================================
  // EXPORT
  // ============================================================
  window.repoAgenda = {
    listar: listar,
    listarPorCliente: listarPorCliente,
    obterPorId: obterPorId,
    obterPorIdLike: obterPorIdLike,
    criar: criar,
    atualizar: atualizar,
    marcarRealizado: marcarRealizado,
    excluir: excluir,
    excluirPorIdLike: excluirPorIdLike,
    aplicarRemoto: aplicarRemoto,
    filtrarPorTombstones: filtrarPorTombstones,
    _raw: _raw,
    _marcarPersistir: _marcarPersistir
  };

  dbg('carregado');
})();

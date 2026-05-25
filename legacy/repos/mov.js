'use strict';
/* ============================================================
 * repoMov - Repositorio de Andamentos (movimentacoes)
 * ============================================================
 * Etapa 3.A (v146): esqueleto + smoke.
 * Migracao dos call-sites do bundle ocorre na 3.B em lotes.
 *
 * RESPONSABILIDADE
 * ----------------
 * Encapsular o acesso ao objeto global `localMov`
 * (formato: { [cid]: Array<mov> }) e a chave Supabase `co_localMov`.
 *
 * Cada `mov` tem o shape (campos comuns, nem todos obrigatorios):
 *   { data, movimentacao, tipo_movimentacao, origem, id?, _id? }
 *
 * Quando um mov NAO tem `id`, a identificacao usa _movKey(m), funcao
 * top-level do bundle (promovida na v144). _movKey eh:
 *   m.id ? 'id:'+m.id : data+'|'+texto+'|'+tipo+'|'+origem
 *
 * LIMITES (o que ESTE repo faz)
 * -----------------------------
 *   - listar / filtrar movimentacoes por cliente
 *   - inserir no topo (unshift, padrao do app), push, atualizar, excluir
 *   - persistir via `sbSet('co_localMov', localMov)`
 *   - registrar tombstone via `_tombstoneAdd('co_localMov', _movKey(m))`
 *   - sinalizar mudanca via `marcarAlterado()`
 *   - aplicar payload remoto vindo de `sbAplicar` (Realtime)
 *
 * O QUE NAO DEVE SER FEITO AQUI
 * -----------------------------
 *   - NAO sincronizar com `localAg`. Cascata bilateral espelho<->compromisso
 *     (Opcao B v140) eh responsabilidade dos call-sites.
 *   - NAO chamar render (renderFicha, _render_agenda_all, etc.).
 *   - NAO mexer em `prazos`, `notes`, `tasks`. Existem (ou existirao)
 *     `repoPrazos`, `repoNotes`, `repoTasks` para isso.
 *
 * DEPENDENCIAS GLOBAIS TEMPORARIAS (Etapa 3)
 * ------------------------------------------
 *   - window.localMov         objeto global { [cid]: Array }
 *   - window._movKey          hash de identificacao (top-level v144)
 *   - window.sbSet            persistencia Supabase + localStorage
 *   - window._tombstoneAdd    marcacao de exclusao
 *   - window._tombstoneHas    consulta de tombstone
 *   - window.marcarAlterado   flag de mudanca pendente
 *
 * MODO DEBUG
 * ----------
 * Setar `window.CO_DEBUG = true` no console habilita console.debug.
 * ============================================================ */
(function () {

  function dbg() {
    if (!window.CO_DEBUG) return;
    try {
      var args = ['[repoMov]'].concat([].slice.call(arguments));
      console.debug.apply(console, args);
    } catch (_) { /* ignore */ }
  }

  // ---------- guarda do estado global ----------
  function _obj() {
    if (!window.localMov || typeof window.localMov !== 'object' || Array.isArray(window.localMov)) {
      window.localMov = {};
    }
    return window.localMov;
  }

  function _bucket(cid) {
    if (cid == null) return [];
    var o = _obj();
    var k = String(cid);
    if (!Array.isArray(o[k])) o[k] = [];
    return o[k];
  }

  // ---------- _movKey defensivo ----------
  // O bundle promoveu _movKey para top-level na v144. Aqui mantemos
  // uma copia de fallback para o caso (raro) do repo carregar antes
  // do bundle definir _movKey.
  function _key(m) {
    if (typeof window._movKey === 'function') return window._movKey(m);
    if (!m) return '';
    if (m.id) return 'id:' + m.id;
    return (m.data || '') + '|' + (m.movimentacao || m.texto || m.desc || '') +
           '|' + (m.tipo_movimentacao || m.tipo || '') + '|' + (m.origem || '');
  }

  // ---------- persistencia ----------
  // _persist: efeito EXPLICITO replicando o que os call-sites do bundle
  // fazem manualmente apos cada mutacao:
  //   1) sbSet('co_localMov', localMov)
  //   2) marcarAlterado()
  // NAO chama nenhum render (render fica no call-site).
  function _persist() {
    if (typeof window.sbSet === 'function') {
      window.sbSet('co_localMov', window.localMov);
    } else {
      console.warn('[repoMov] sbSet indisponivel - persistencia ignorada');
    }
    if (typeof window.marcarAlterado === 'function') window.marcarAlterado();
  }

  // ============================================================
  // LEITURA
  // ============================================================

  function listar() {
    return _obj();
  }

  function listarPorCliente(cid) {
    if (cid == null) return [];
    var o = _obj();
    var k = String(cid);
    return Array.isArray(o[k]) ? o[k] : [];
  }

  function existePorKey(cid, key) {
    if (cid == null || !key) return false;
    var arr = listarPorCliente(cid);
    for (var i = 0; i < arr.length; i++) {
      if (_key(arr[i]) === key) return true;
    }
    return false;
  }

  function indicePorKey(cid, key) {
    if (cid == null || !key) return -1;
    var arr = listarPorCliente(cid);
    for (var i = 0; i < arr.length; i++) {
      if (_key(arr[i]) === key) return i;
    }
    return -1;
  }

  // ============================================================
  // ESCRITA
  // ============================================================

  /**
   * inserirNoTopo(cid, mov): unshift + persist.
   * Padrao usado pela maioria dos call-sites (novos andamentos
   * aparecem no topo da timeline).
   * Retorna o mov inserido ou null se invalido.
   */
  function inserirNoTopo(cid, mov) {
    if (cid == null || !mov) {
      dbg('inserirNoTopo: cid ou mov invalido');
      return null;
    }
    var bucket = _bucket(cid);
    bucket.unshift(mov);
    dbg('inserirNoTopo', cid, _key(mov));
    _persist();
    return mov;
  }

  /**
   * adicionarNoFim(cid, mov): push + persist.
   * Caso menos comum (ex: importacao em ordem cronologica).
   */
  function adicionarNoFim(cid, mov) {
    if (cid == null || !mov) {
      dbg('adicionarNoFim: cid ou mov invalido');
      return null;
    }
    var bucket = _bucket(cid);
    bucket.push(mov);
    dbg('adicionarNoFim', cid, _key(mov));
    _persist();
    return mov;
  }

  /**
   * atualizarPorIndice(cid, idx, patch): merge superficial no item idx.
   * Espelha o padrao `lista[idx] = {...m, ...patch}` dos call-sites.
   * Retorna o item atualizado ou null se idx invalido.
   */
  function atualizarPorIndice(cid, idx, patch) {
    if (cid == null) return null;
    var bucket = _bucket(cid);
    if (idx < 0 || idx >= bucket.length) {
      dbg('atualizarPorIndice: idx fora do range', cid, idx);
      return null;
    }
    var atualizado = Object.assign({}, bucket[idx], patch || {});
    bucket[idx] = atualizado;
    dbg('atualizarPorIndice', cid, idx, Object.keys(patch || {}));
    _persist();
    return atualizado;
  }

  /**
   * atualizarPorKey(cid, key, patch): localiza por _movKey e atualiza.
   * Util quando o call-site nao tem idx mas tem o mov original.
   */
  function atualizarPorKey(cid, key, patch) {
    var idx = indicePorKey(cid, key);
    if (idx < 0) {
      dbg('atualizarPorKey: key nao encontrada', cid, key);
      return null;
    }
    return atualizarPorIndice(cid, idx, patch);
  }

  /**
   * excluirPorIndice(cid, idx, opts): splice + tombstone + persist.
   * opts.tombstone (default true): se false, NAO grava tombstone
   *   (uso raro: limpeza local sem propagacao cross-PC).
   * Retorna true se removeu, false se idx invalido.
   */
  function excluirPorIndice(cid, idx, opts) {
    opts = opts || {};
    var gravarTomb = (opts.tombstone !== false);
    if (cid == null) return false;
    var bucket = _bucket(cid);
    if (idx < 0 || idx >= bucket.length) {
      dbg('excluirPorIndice: idx fora do range', cid, idx);
      return false;
    }
    var item = bucket[idx];
    var keyItem = _key(item);
    bucket.splice(idx, 1);
    if (gravarTomb && keyItem && typeof window._tombstoneAdd === 'function') {
      window._tombstoneAdd('co_localMov', keyItem);
    }
    dbg('excluirPorIndice', cid, idx, 'tombstone=' + gravarTomb);
    _persist();
    return true;
  }

  /**
   * excluirPorKey(cid, key, opts): localiza por _movKey e exclui.
   * Mesma semantica de excluirPorIndice mas usando key como localizador.
   */
  function excluirPorKey(cid, key, opts) {
    var idx = indicePorKey(cid, key);
    if (idx < 0) {
      dbg('excluirPorKey: key nao encontrada', cid, key);
      return false;
    }
    return excluirPorIndice(cid, idx, opts);
  }

  /**
   * excluirPorFiltro(cid, predicate, opts): remove todos os movs onde
   * predicate(mov, idx) === true. Tombstone gravado para cada item removido.
   * Util para a cascata bilateral (Opcao B v140) — call-site filtra
   * espelhos com matching customizado, repo cuida da remocao + tombstones.
   * Retorna numero de itens removidos.
   */
  function excluirPorFiltro(cid, predicate, opts) {
    opts = opts || {};
    var gravarTomb = (opts.tombstone !== false);
    if (cid == null || typeof predicate !== 'function') return 0;
    var bucket = _bucket(cid);
    var removidos = [];
    var keep = [];
    bucket.forEach(function (m, i) {
      if (predicate(m, i)) {
        removidos.push(m);
      } else {
        keep.push(m);
      }
    });
    if (removidos.length === 0) return 0;
    var k = String(cid);
    _obj()[k] = keep;
    if (gravarTomb && typeof window._tombstoneAdd === 'function') {
      removidos.forEach(function (m) {
        var ks = _key(m);
        if (ks) window._tombstoneAdd('co_localMov', ks);
      });
    }
    dbg('excluirPorFiltro', cid, 'removidos=' + removidos.length, 'tombstone=' + gravarTomb);
    _persist();
    return removidos.length;
  }

  // ============================================================
  // REALTIME (consumo de payload remoto)
  // ============================================================

  /**
   * aplicarRemoto(obj): reescreve `localMov` com payload vindo do
   * Supabase Realtime, respeitando tombstones locais (co_localMov).
   *
   * NAO chama _persist (a fonte e remota; gravar de volta provocaria loop).
   * Filtra tombstones nas DUAS direcoes (local e remote).
   */
  function aplicarRemoto(obj) {
    if (!obj || typeof obj !== 'object' || Array.isArray(obj)) {
      window.localMov = {};
      return window.localMov;
    }
    var out = {};
    var aplicaTomb = (typeof window._tombstoneHas === 'function');
    Object.keys(obj).forEach(function (k) {
      var arr = Array.isArray(obj[k]) ? obj[k] : [];
      if (aplicaTomb) {
        arr = arr.filter(function (m) {
          return !window._tombstoneHas('co_localMov', _key(m));
        });
      }
      out[k] = arr.slice();
    });
    window.localMov = out;
    dbg('aplicarRemoto: chaves=' + Object.keys(out).length);
    return window.localMov;
  }

  /**
   * filtrarPorTombstones(): aplica tombstones atuais sobre localMov.
   * Usado pelo sbAplicar quando recebe co_localMov_del via Realtime.
   * NAO chama _persist.
   */
  function filtrarPorTombstones() {
    if (typeof window._tombstoneHas !== 'function') return _obj();
    var o = _obj();
    var totalAntes = 0, totalDepois = 0;
    Object.keys(o).forEach(function (k) {
      if (!Array.isArray(o[k])) return;
      totalAntes += o[k].length;
      o[k] = o[k].filter(function (m) {
        return !window._tombstoneHas('co_localMov', _key(m));
      });
      totalDepois += o[k].length;
    });
    dbg('filtrarPorTombstones: removidos=' + (totalAntes - totalDepois));
    return o;
  }

  // ============================================================
  // ESCAPE HATCH (transicao - usar com parcimonia)
  // ============================================================

  function _raw() { return _obj(); }
  function _marcarPersistir() { _persist(); }

  // ============================================================
  // EXPORT
  // ============================================================
  window.repoMov = {
    listar: listar,
    listarPorCliente: listarPorCliente,
    existePorKey: existePorKey,
    indicePorKey: indicePorKey,
    inserirNoTopo: inserirNoTopo,
    adicionarNoFim: adicionarNoFim,
    atualizarPorIndice: atualizarPorIndice,
    atualizarPorKey: atualizarPorKey,
    excluirPorIndice: excluirPorIndice,
    excluirPorKey: excluirPorKey,
    excluirPorFiltro: excluirPorFiltro,
    aplicarRemoto: aplicarRemoto,
    filtrarPorTombstones: filtrarPorTombstones,
    _raw: _raw,
    _marcarPersistir: _marcarPersistir
  };

  dbg('carregado');
})();

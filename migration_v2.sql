-- ═══════════════════════════════════════════════════════════════
-- MIGRAÇÃO: Escritório Clarissa Oliveira — Banco Profissional
-- Data: Abril 2026
-- Executar no Supabase SQL Editor (https://supabase.com/dashboard)
-- Projeto: ialglogaytwzdohfjkng
-- ═══════════════════════════════════════════════════════════════

-- ══ 1. TABELAS ═══════════════════════════════════════════════

-- Pessoas (contatos): clientes, partes contrárias, testemunhas, etc.
CREATE TABLE IF NOT EXISTS pessoas (
  id BIGINT PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
  nome TEXT NOT NULL,
  tipo TEXT DEFAULT 'cliente', -- cliente, parte_contraria, testemunha, perito, juiz, advogado
  cpf TEXT,
  rg TEXT,
  pis TEXT,
  telefone TEXT,
  telefone2 TEXT,
  email TEXT,
  data_nascimento DATE,
  naturalidade TEXT,
  nacionalidade TEXT,
  estado_civil TEXT,
  nome_mae TEXT,
  profissao TEXT,
  -- Endereço
  rua TEXT,
  numero TEXT,
  complemento TEXT,
  bairro TEXT,
  cidade TEXT,
  uf TEXT,
  cep TEXT,
  -- Dados bancários (para repasse)
  banco TEXT,
  tipo_conta TEXT,
  agencia TEXT,
  conta TEXT,
  pix TEXT,
  -- Meta
  indicacao TEXT,
  observacoes TEXT,
  criado_em TIMESTAMPTZ DEFAULT now(),
  atualizado_em TIMESTAMPTZ DEFAULT now()
);

-- Processos (pastas)
CREATE TABLE IF NOT EXISTS processos (
  id BIGINT PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
  cliente_id BIGINT REFERENCES pessoas(id) ON DELETE SET NULL,
  numero_cnj TEXT,
  natureza TEXT, -- Trabalhista, Previdenciário, Cível, Família, etc.
  tipo_acao TEXT,
  comarca TEXT,
  vara TEXT,
  instancia TEXT DEFAULT '1ª instância',
  polo TEXT, -- Autor, Réu, Reclamante, Reclamado, etc.
  adverso TEXT,
  adverso_doc TEXT,
  adverso_advogado TEXT,
  valor_causa DECIMAL(15,2),
  pedidos TEXT,
  data_distribuicao DATE,
  fase TEXT DEFAULT 'conhecimento', -- conhecimento, recursal, execucao, encerrado
  status TEXT DEFAULT 'ativo' CHECK (status IN ('ativo','encerrado','arquivado')),
  motivo_encerramento TEXT,
  data_encerramento DATE,
  data_arquivamento DATE,
  observacoes TEXT,
  criado_em TIMESTAMPTZ DEFAULT now(),
  atualizado_em TIMESTAMPTZ DEFAULT now()
);

-- Partes do processo (N:N entre pessoas e processos)
CREATE TABLE IF NOT EXISTS partes_processo (
  id BIGINT PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
  processo_id BIGINT REFERENCES processos(id) ON DELETE CASCADE,
  pessoa_id BIGINT REFERENCES pessoas(id) ON DELETE SET NULL,
  nome TEXT NOT NULL, -- redundante mas útil pra partes não cadastradas
  condicao TEXT, -- Cliente, Autor, Réu, Reclamante, Testemunha, etc.
  eh_cliente BOOLEAN DEFAULT false,
  criado_em TIMESTAMPTZ DEFAULT now()
);

-- Contrato de honorários (1 por processo, definido no início, não muda)
CREATE TABLE IF NOT EXISTS honorarios (
  id BIGINT PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
  processo_id BIGINT REFERENCES processos(id) ON DELETE CASCADE,
  modalidade TEXT CHECK (modalidade IN ('percentual','fixo_mensal','entrada_parcelas','combinado','ad_exitum')),
  percentual DECIMAL(5,2), -- % de êxito (ex: 30)
  valor_fixo DECIMAL(15,2), -- mensal fixo
  valor_entrada DECIMAL(15,2),
  num_parcelas INT,
  valor_parcela DECIMAL(15,2),
  descricao TEXT,
  criado_em TIMESTAMPTZ DEFAULT now()
);

-- Parceiros que dividem honorários em processos específicos
CREATE TABLE IF NOT EXISTS parceiros_processo (
  id BIGINT PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
  processo_id BIGINT REFERENCES processos(id) ON DELETE CASCADE,
  nome TEXT NOT NULL,
  percentual DECIMAL(5,2) NOT NULL, -- % sobre honorários do escritório
  oab TEXT,
  tipo TEXT DEFAULT 'parceiro',
  criado_em TIMESTAMPTZ DEFAULT now()
);

-- Lançamentos financeiros (por processo E globais)
CREATE TABLE IF NOT EXISTS lancamentos (
  id BIGINT PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
  processo_id BIGINT REFERENCES processos(id) ON DELETE SET NULL, -- NULL = despesa global
  tipo TEXT NOT NULL CHECK (tipo IN ('honorario','despesa','repasse','alvara','acordo','mensal','custa','outro')),
  direcao TEXT CHECK (direcao IN ('receber','pagar')),
  descricao TEXT NOT NULL,
  valor DECIMAL(15,2) NOT NULL,
  data_competencia DATE, -- data do fato gerador (quando o alvará saiu, acordo fechou)
  data DATE, -- data de registro no sistema
  vencimento DATE,
  data_baixa DATE, -- quando efetivamente foi pago/recebido
  status TEXT DEFAULT 'pendente' CHECK (status IN ('pendente','pago','vencido','estornado')),
  forma_pagamento TEXT, -- PIX, TED, Boleto, Dinheiro, Cheque
  conta_destino TEXT,
  categoria TEXT, -- Estrutura, Pessoal, Impostos, Marketing, etc. (pra despesas globais)
  reembolsavel BOOLEAN DEFAULT false, -- custa adiantada
  reembolsado BOOLEAN DEFAULT false,
  data_reembolso DATE,
  parcela_num INT,
  parcela_total INT,
  grupo_parcela TEXT, -- agrupa parcelas do mesmo lançamento
  observacoes TEXT,
  criado_por UUID REFERENCES auth.users(id) ON DELETE SET NULL,
  criado_em TIMESTAMPTZ DEFAULT now(),
  atualizado_em TIMESTAMPTZ DEFAULT now()
);

-- Movimentações (andamentos/histórico do processo)
CREATE TABLE IF NOT EXISTS movimentacoes (
  id BIGINT PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
  processo_id BIGINT REFERENCES processos(id) ON DELETE CASCADE,
  data DATE NOT NULL,
  descricao TEXT NOT NULL,
  tipo TEXT, -- Judicial, Financeiro, Sistema, Publicação, DataJud
  origem TEXT, -- manual, datajud, publicacao_dje, baixa_fin, extrato, etc.
  criado_por UUID REFERENCES auth.users(id) ON DELETE SET NULL,
  criado_em TIMESTAMPTZ DEFAULT now()
);

-- Compromissos (agenda unificada: prazos + audiências + reuniões)
CREATE TABLE IF NOT EXISTS compromissos (
  id BIGINT PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
  processo_id BIGINT REFERENCES processos(id) ON DELETE CASCADE,
  tipo TEXT CHECK (tipo IN ('prazo','audiencia','reuniao','compromisso')),
  titulo TEXT NOT NULL,
  data DATE NOT NULL,
  hora_inicio TIME,
  hora_fim TIME,
  local TEXT,
  responsavel TEXT,
  realizado BOOLEAN DEFAULT false,
  data_conclusao DATE,
  desfecho TEXT,
  observacoes TEXT,
  criado_por UUID REFERENCES auth.users(id) ON DELETE SET NULL,
  criado_em TIMESTAMPTZ DEFAULT now(),
  atualizado_em TIMESTAMPTZ DEFAULT now()
);

-- Tarefas (kanban + checklist)
CREATE TABLE IF NOT EXISTS tarefas (
  id BIGINT PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
  processo_id BIGINT REFERENCES processos(id) ON DELETE SET NULL,
  titulo TEXT NOT NULL,
  tipo TEXT DEFAULT 'tarefa',
  status TEXT DEFAULT 'todo' CHECK (status IN ('todo','doing','done')),
  prioridade TEXT DEFAULT 'media' CHECK (prioridade IN ('alta','media','baixa')),
  responsavel TEXT,
  cliente TEXT, -- nome do cliente (pra exibição rápida)
  prazo DATE,
  para_hoje DATE,
  desfecho TEXT,
  proximo_ato TEXT,
  concluido_em DATE,
  criado_em TIMESTAMPTZ DEFAULT now(),
  atualizado_em TIMESTAMPTZ DEFAULT now()
);

-- Comentários internos por processo
CREATE TABLE IF NOT EXISTS comentarios (
  id BIGINT PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
  processo_id BIGINT REFERENCES processos(id) ON DELETE CASCADE,
  texto TEXT NOT NULL,
  autor TEXT,
  criado_por UUID REFERENCES auth.users(id) ON DELETE SET NULL,
  criado_em TIMESTAMPTZ DEFAULT now()
);

-- Atendimentos (pipeline CRM)
CREATE TABLE IF NOT EXISTS atendimentos (
  id BIGINT PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
  pessoa_id BIGINT REFERENCES pessoas(id) ON DELETE SET NULL,
  assunto TEXT,
  area_juridica TEXT,
  status TEXT DEFAULT 'novo' CHECK (status IN ('novo','em_analise','proposta','contratou','nao_contratou')),
  data_atendimento DATE,
  resumo TEXT,
  processo_id BIGINT REFERENCES processos(id) ON DELETE SET NULL,
  criado_em TIMESTAMPTZ DEFAULT now(),
  atualizado_em TIMESTAMPTZ DEFAULT now()
);

-- Log de auditoria
CREATE TABLE IF NOT EXISTS audit_log (
  id BIGINT PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
  usuario_id UUID REFERENCES auth.users(id) ON DELETE SET NULL,
  acao TEXT NOT NULL,
  entidade TEXT,
  entidade_id BIGINT,
  detalhes TEXT,
  criado_em TIMESTAMPTZ DEFAULT now()
);

-- Perfis de usuário (estende auth.users)
CREATE TABLE IF NOT EXISTS perfis (
  id UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
  nome TEXT NOT NULL,
  perfil TEXT NOT NULL CHECK (perfil IN ('advogada','assistente','financeiro','estagiario')),
  ativo BOOLEAN DEFAULT true,
  criado_em TIMESTAMPTZ DEFAULT now()
);


-- ══ 2. ÍNDICES (performance) ═════════════════════════════════

CREATE INDEX IF NOT EXISTS idx_processos_cliente ON processos(cliente_id);
CREATE INDEX IF NOT EXISTS idx_processos_status ON processos(status);
CREATE INDEX IF NOT EXISTS idx_processos_cnj ON processos(numero_cnj);
CREATE INDEX IF NOT EXISTS idx_lancamentos_processo ON lancamentos(processo_id);
CREATE INDEX IF NOT EXISTS idx_lancamentos_status ON lancamentos(status);
CREATE INDEX IF NOT EXISTS idx_lancamentos_competencia ON lancamentos(data_competencia);
CREATE INDEX IF NOT EXISTS idx_lancamentos_tipo ON lancamentos(tipo);
CREATE INDEX IF NOT EXISTS idx_movimentacoes_processo ON movimentacoes(processo_id);
CREATE INDEX IF NOT EXISTS idx_movimentacoes_data ON movimentacoes(data);
CREATE INDEX IF NOT EXISTS idx_compromissos_processo ON compromissos(processo_id);
CREATE INDEX IF NOT EXISTS idx_compromissos_data ON compromissos(data);
CREATE INDEX IF NOT EXISTS idx_compromissos_realizado ON compromissos(realizado);
CREATE INDEX IF NOT EXISTS idx_tarefas_status ON tarefas(status);
CREATE INDEX IF NOT EXISTS idx_tarefas_prazo ON tarefas(prazo);
CREATE INDEX IF NOT EXISTS idx_partes_processo ON partes_processo(processo_id);
CREATE INDEX IF NOT EXISTS idx_partes_pessoa ON partes_processo(pessoa_id);
CREATE INDEX IF NOT EXISTS idx_atendimentos_pessoa ON atendimentos(pessoa_id);
CREATE INDEX IF NOT EXISTS idx_atendimentos_status ON atendimentos(status);
CREATE INDEX IF NOT EXISTS idx_honorarios_processo ON honorarios(processo_id);


-- ══ 3. TRIGGER: atualizar updated_at automaticamente ═════════

CREATE OR REPLACE FUNCTION trigger_set_updated_at()
RETURNS TRIGGER AS $$
BEGIN
  NEW.atualizado_em = now();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DO $$
DECLARE
  t TEXT;
BEGIN
  FOREACH t IN ARRAY ARRAY['pessoas','processos','lancamentos','compromissos','tarefas','atendimentos']
  LOOP
    EXECUTE format('
      DROP TRIGGER IF EXISTS set_updated_at ON %I;
      CREATE TRIGGER set_updated_at
        BEFORE UPDATE ON %I
        FOR EACH ROW
        EXECUTE FUNCTION trigger_set_updated_at();
    ', t, t);
  END LOOP;
END $$;


-- ══ 4. RLS (Row Level Security) ══════════════════════════════

-- Habilitar RLS em todas as tabelas
ALTER TABLE pessoas ENABLE ROW LEVEL SECURITY;
ALTER TABLE processos ENABLE ROW LEVEL SECURITY;
ALTER TABLE partes_processo ENABLE ROW LEVEL SECURITY;
ALTER TABLE honorarios ENABLE ROW LEVEL SECURITY;
ALTER TABLE parceiros_processo ENABLE ROW LEVEL SECURITY;
ALTER TABLE lancamentos ENABLE ROW LEVEL SECURITY;
ALTER TABLE movimentacoes ENABLE ROW LEVEL SECURITY;
ALTER TABLE compromissos ENABLE ROW LEVEL SECURITY;
ALTER TABLE tarefas ENABLE ROW LEVEL SECURITY;
ALTER TABLE comentarios ENABLE ROW LEVEL SECURITY;
ALTER TABLE atendimentos ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_log ENABLE ROW LEVEL SECURITY;
ALTER TABLE perfis ENABLE ROW LEVEL SECURITY;

-- Helper: pegar o perfil do usuário logado
CREATE OR REPLACE FUNCTION perfil_atual()
RETURNS TEXT AS $$
  SELECT perfil FROM perfis WHERE id = auth.uid();
$$ LANGUAGE sql SECURITY DEFINER STABLE;

-- ── Políticas: Advogada e Assistente veem TUDO ──
-- (perfil IN ('advogada','assistente'))

CREATE POLICY "advogada_assistente_full" ON pessoas
  FOR ALL USING (perfil_atual() IN ('advogada','assistente'));

CREATE POLICY "advogada_assistente_full" ON processos
  FOR ALL USING (perfil_atual() IN ('advogada','assistente'));

CREATE POLICY "advogada_assistente_full" ON partes_processo
  FOR ALL USING (perfil_atual() IN ('advogada','assistente'));

CREATE POLICY "advogada_assistente_full" ON honorarios
  FOR ALL USING (perfil_atual() IN ('advogada','assistente'));

CREATE POLICY "advogada_assistente_full" ON parceiros_processo
  FOR ALL USING (perfil_atual() IN ('advogada','assistente'));

CREATE POLICY "advogada_assistente_full" ON lancamentos
  FOR ALL USING (perfil_atual() IN ('advogada','assistente'));

CREATE POLICY "advogada_assistente_full" ON movimentacoes
  FOR ALL USING (perfil_atual() IN ('advogada','assistente'));

CREATE POLICY "advogada_assistente_full" ON compromissos
  FOR ALL USING (perfil_atual() IN ('advogada','assistente'));

CREATE POLICY "advogada_assistente_full" ON tarefas
  FOR ALL USING (perfil_atual() IN ('advogada','assistente'));

CREATE POLICY "advogada_assistente_full" ON comentarios
  FOR ALL USING (perfil_atual() IN ('advogada','assistente'));

CREATE POLICY "advogada_assistente_full" ON atendimentos
  FOR ALL USING (perfil_atual() IN ('advogada','assistente'));

CREATE POLICY "advogada_assistente_full" ON audit_log
  FOR ALL USING (perfil_atual() IN ('advogada','assistente'));

CREATE POLICY "advogada_assistente_full" ON perfis
  FOR ALL USING (perfil_atual() IN ('advogada','assistente'));

-- ── Estagiário: tudo EXCETO financeiro global ──

CREATE POLICY "estagiario_pessoas" ON pessoas
  FOR ALL USING (perfil_atual() = 'estagiario');

CREATE POLICY "estagiario_processos" ON processos
  FOR ALL USING (perfil_atual() = 'estagiario');

CREATE POLICY "estagiario_partes" ON partes_processo
  FOR ALL USING (perfil_atual() = 'estagiario');

CREATE POLICY "estagiario_movimentacoes" ON movimentacoes
  FOR ALL USING (perfil_atual() = 'estagiario');

CREATE POLICY "estagiario_compromissos" ON compromissos
  FOR ALL USING (perfil_atual() = 'estagiario');

CREATE POLICY "estagiario_tarefas" ON tarefas
  FOR ALL USING (perfil_atual() = 'estagiario');

CREATE POLICY "estagiario_comentarios" ON comentarios
  FOR ALL USING (perfil_atual() = 'estagiario');

CREATE POLICY "estagiario_atendimentos" ON atendimentos
  FOR ALL USING (perfil_atual() = 'estagiario');

-- Estagiário NÃO vê: lancamentos (global), honorarios, parceiros_processo

-- ── Financeiro: APENAS lancamentos globais + honorarios (leitura) ──

CREATE POLICY "financeiro_lancamentos" ON lancamentos
  FOR ALL USING (perfil_atual() = 'financeiro');

CREATE POLICY "financeiro_honorarios_read" ON honorarios
  FOR SELECT USING (perfil_atual() = 'financeiro');

CREATE POLICY "financeiro_processos_read" ON processos
  FOR SELECT USING (perfil_atual() = 'financeiro');

CREATE POLICY "financeiro_pessoas_read" ON pessoas
  FOR SELECT USING (perfil_atual() = 'financeiro');

CREATE POLICY "financeiro_perfis" ON perfis
  FOR SELECT USING (perfil_atual() = 'financeiro');


-- ══ 5. HABILITAR REALTIME ════════════════════════════════════

-- Habilitar Realtime para tabelas que precisam de sync entre PCs
ALTER PUBLICATION supabase_realtime ADD TABLE pessoas;
ALTER PUBLICATION supabase_realtime ADD TABLE processos;
ALTER PUBLICATION supabase_realtime ADD TABLE partes_processo;
ALTER PUBLICATION supabase_realtime ADD TABLE lancamentos;
ALTER PUBLICATION supabase_realtime ADD TABLE movimentacoes;
ALTER PUBLICATION supabase_realtime ADD TABLE compromissos;
ALTER PUBLICATION supabase_realtime ADD TABLE tarefas;
ALTER PUBLICATION supabase_realtime ADD TABLE comentarios;
ALTER PUBLICATION supabase_realtime ADD TABLE atendimentos;
ALTER PUBLICATION supabase_realtime ADD TABLE honorarios;
ALTER PUBLICATION supabase_realtime ADD TABLE parceiros_processo;


-- ══ 6. DADOS INICIAIS ════════════════════════════════════════

-- Nota: os 4 perfis serão criados APÓS os usuários fazerem signup
-- via Supabase Auth. Exemplo de como inserir depois:
--
-- INSERT INTO perfis (id, nome, perfil) VALUES
--   ('UUID_DA_CLARISSA', 'Clarissa de Oliveira', 'advogada'),
--   ('UUID_DA_ASSISTENTE', 'Nome da Assistente', 'assistente'),
--   ('UUID_DO_FINANCEIRO', 'Nome do Financeiro', 'financeiro'),
--   ('UUID_DO_ESTAGIARIO', 'Nome do Estagiário', 'estagiario');


-- ══ VERIFICAÇÃO ══════════════════════════════════════════════
-- Após executar, rode estas queries para confirmar:

-- SELECT count(*) FROM information_schema.tables
-- WHERE table_schema = 'public' AND table_name IN (
--   'pessoas','processos','partes_processo','honorarios',
--   'parceiros_processo','lancamentos','movimentacoes',
--   'compromissos','tarefas','comentarios','atendimentos',
--   'audit_log','perfis'
-- );
-- Resultado esperado: 13

-- SELECT tablename, rowsecurity FROM pg_tables
-- WHERE schemaname = 'public' AND rowsecurity = true;
-- Resultado esperado: 13 linhas (todas com rowsecurity = true)

-- Despesas fixas recorrentes (luz, condomínio, internet, limpeza, etc.)
-- DespesaFixa é o template cadastrado; DespesaFixaPrevisao é a instância
-- mensal gerada sob demanda. Marcar uma previsão como paga cria um
-- Lancamento de SAÍDA real vinculado.

CREATE TABLE "despesa_fixa" (
    "id" TEXT NOT NULL,
    "nome" TEXT NOT NULL,
    "categoriaId" TEXT NOT NULL,
    "contaId" TEXT NOT NULL,
    "valorEstimado" DECIMAL(14,2) NOT NULL,
    "diaVencimento" SMALLINT NOT NULL,
    "ativo" BOOLEAN NOT NULL DEFAULT true,
    "observacoes" TEXT,
    "criadoEm" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "atualizadoEm" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "despesa_fixa_pkey" PRIMARY KEY ("id")
);

CREATE INDEX "despesa_fixa_ativo_idx" ON "despesa_fixa"("ativo");

ALTER TABLE "despesa_fixa"
  ADD CONSTRAINT "despesa_fixa_categoriaId_fkey"
  FOREIGN KEY ("categoriaId") REFERENCES "categoria"("id")
  ON DELETE RESTRICT ON UPDATE CASCADE;

ALTER TABLE "despesa_fixa"
  ADD CONSTRAINT "despesa_fixa_contaId_fkey"
  FOREIGN KEY ("contaId") REFERENCES "conta_bancaria"("id")
  ON DELETE RESTRICT ON UPDATE CASCADE;

CREATE TABLE "despesa_fixa_previsao" (
    "id" TEXT NOT NULL,
    "despesaFixaId" TEXT NOT NULL,
    "competencia" DATE NOT NULL,
    "dataVencimento" DATE NOT NULL,
    "valorPrevisto" DECIMAL(14,2) NOT NULL,
    "lancamentoId" TEXT,
    "dataPagamento" DATE,
    "criadoEm" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "atualizadoEm" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "despesa_fixa_previsao_pkey" PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "despesa_fixa_previsao_lancamentoId_key"
  ON "despesa_fixa_previsao"("lancamentoId");

CREATE UNIQUE INDEX "despesa_fixa_previsao_despesaFixaId_competencia_key"
  ON "despesa_fixa_previsao"("despesaFixaId", "competencia");

CREATE INDEX "despesa_fixa_previsao_competencia_idx"
  ON "despesa_fixa_previsao"("competencia");

CREATE INDEX "despesa_fixa_previsao_dataVencimento_idx"
  ON "despesa_fixa_previsao"("dataVencimento");

ALTER TABLE "despesa_fixa_previsao"
  ADD CONSTRAINT "despesa_fixa_previsao_despesaFixaId_fkey"
  FOREIGN KEY ("despesaFixaId") REFERENCES "despesa_fixa"("id")
  ON DELETE CASCADE ON UPDATE CASCADE;

ALTER TABLE "despesa_fixa_previsao"
  ADD CONSTRAINT "despesa_fixa_previsao_lancamentoId_fkey"
  FOREIGN KEY ("lancamentoId") REFERENCES "lancamento"("id")
  ON DELETE SET NULL ON UPDATE CASCADE;

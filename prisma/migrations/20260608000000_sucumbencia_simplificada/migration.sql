-- Sucumbência simplificada:
-- 1) Remove rateio 34/33/33 (Escritório/Clarissa/Vivian) — não existe mais
--    a divisão entre sócias; o escritório tem uma única dona.
-- 2) Adiciona conta + categoria (a sucumbência agora gera um lançamento
--    de ENTRADA automaticamente, integrando o saldo).
-- 3) Mantém parceiro externo opcional, com data de repasse individual.
--
-- Como o módulo foi lançado hoje e ainda não há registros em produção,
-- a migração apaga eventuais linhas de teste e refaz o esquema.

DELETE FROM "sucumbencia";

ALTER TABLE "sucumbencia"
  DROP COLUMN IF EXISTS "percEscritorio",
  DROP COLUMN IF EXISTS "percClarissa",
  DROP COLUMN IF EXISTS "percVivian",
  DROP COLUMN IF EXISTS "dataRepasseClarissa",
  DROP COLUMN IF EXISTS "dataRepasseVivian";

ALTER TABLE "sucumbencia"
  ADD COLUMN "contaRecebimentoId" TEXT NOT NULL,
  ADD COLUMN "categoriaLancamentoId" TEXT NOT NULL,
  ADD COLUMN "dataRepasseParceiroExterno" DATE,
  ADD COLUMN "lancamentoEntradaId" TEXT;

ALTER TABLE "sucumbencia"
  ADD CONSTRAINT "sucumbencia_lancamentoEntradaId_key" UNIQUE ("lancamentoEntradaId");

ALTER TABLE "sucumbencia"
  ADD CONSTRAINT "sucumbencia_contaRecebimentoId_fkey"
  FOREIGN KEY ("contaRecebimentoId") REFERENCES "conta_bancaria"("id")
  ON DELETE RESTRICT ON UPDATE CASCADE;

ALTER TABLE "sucumbencia"
  ADD CONSTRAINT "sucumbencia_categoriaLancamentoId_fkey"
  FOREIGN KEY ("categoriaLancamentoId") REFERENCES "categoria"("id")
  ON DELETE RESTRICT ON UPDATE CASCADE;

ALTER TABLE "sucumbencia"
  ADD CONSTRAINT "sucumbencia_lancamentoEntradaId_fkey"
  FOREIGN KEY ("lancamentoEntradaId") REFERENCES "lancamento"("id")
  ON DELETE SET NULL ON UPDATE CASCADE;

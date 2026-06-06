-- CreateEnum
CREATE TYPE "Perfil" AS ENUM ('ADMIN', 'SOCIA', 'SECRETARIA', 'PARCEIRO_LEITURA');

-- CreateEnum
CREATE TYPE "NaturezaProcesso" AS ENUM ('TRABALHISTA', 'CIVEL', 'PREVIDENCIARIO', 'TRIBUTARIO', 'FAMILIA', 'OUTRO');

-- CreateEnum
CREATE TYPE "StatusProcesso" AS ENUM ('EM_ANDAMENTO', 'SUSPENSO', 'ENCERRADO', 'ARQUIVADO');

-- CreateEnum
CREATE TYPE "TipoParceiro" AS ENUM ('SOCIA', 'PARCEIRO_EXTERNO', 'FUNCIONARIO');

-- CreateEnum
CREATE TYPE "TipoConta" AS ENUM ('CAIXA_FISICO', 'CONTA_CORRENTE', 'POUPANCA', 'INVESTIMENTO');

-- CreateEnum
CREATE TYPE "TipoCategoria" AS ENUM ('RECEITA', 'DESPESA');

-- CreateEnum
CREATE TYPE "TipoParcela" AS ENUM ('NORMAL', 'UNICA', 'HONORARIOS_SUCUMBENCIA', 'EXTRAORDINARIA');

-- CreateEnum
CREATE TYPE "StatusRecebivel" AS ENUM ('PREVISTA', 'RECEBIDA', 'REPASSADA', 'CANCELADA');

-- CreateEnum
CREATE TYPE "TipoBeneficiario" AS ENUM ('CLIENTE', 'ESCRITORIO_CONTRATUAL', 'ESCRITORIO_SUCUMBENCIA', 'PARCEIRO', 'PERITO', 'FGTS', 'RESSARCIMENTO', 'CUSTAS', 'OUTRO');

-- CreateEnum
CREATE TYPE "StatusDistribuicao" AS ENUM ('RASCUNHO', 'CONFIRMADA', 'REVERTIDA');

-- CreateEnum
CREATE TYPE "StatusItemDistribuicao" AS ENUM ('PENDENTE_REPASSE', 'REPASSADO', 'RETIDO_CUSTODIA');

-- CreateEnum
CREATE TYPE "TipoLancamento" AS ENUM ('ENTRADA', 'SAIDA', 'TRANSFERENCIA');

-- CreateEnum
CREATE TYPE "StatusRessarcimento" AS ENUM ('PAGO_PELO_ESCRITORIO', 'REEMBOLSADO');

-- CreateEnum
CREATE TYPE "AcaoAuditoria" AS ENUM ('CRIAR', 'ATUALIZAR', 'EXCLUIR');

-- CreateTable
CREATE TABLE "usuario" (
    "id" TEXT NOT NULL,
    "nome" TEXT NOT NULL,
    "email" TEXT NOT NULL,
    "senhaHash" TEXT NOT NULL,
    "perfil" "Perfil" NOT NULL DEFAULT 'SECRETARIA',
    "ativo" BOOLEAN NOT NULL DEFAULT true,
    "criadoEm" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "atualizadoEm" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "usuario_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "cliente" (
    "id" TEXT NOT NULL,
    "nome" TEXT NOT NULL,
    "cpfCnpj" TEXT,
    "email" TEXT,
    "telefone" TEXT,
    "observacoes" TEXT,
    "ativo" BOOLEAN NOT NULL DEFAULT true,
    "criadoEm" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "atualizadoEm" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "cliente_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "processo" (
    "id" TEXT NOT NULL,
    "clienteId" TEXT NOT NULL,
    "numeroCnj" TEXT,
    "natureza" "NaturezaProcesso" NOT NULL DEFAULT 'OUTRO',
    "vara" TEXT,
    "tribunal" TEXT,
    "parteContraria" TEXT,
    "status" "StatusProcesso" NOT NULL DEFAULT 'EM_ANDAMENTO',
    "observacoes" TEXT,
    "ativo" BOOLEAN NOT NULL DEFAULT true,
    "criadoEm" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "atualizadoEm" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "processo_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "advogado_parceiro" (
    "id" TEXT NOT NULL,
    "nome" TEXT NOT NULL,
    "tipo" "TipoParceiro" NOT NULL DEFAULT 'PARCEIRO_EXTERNO',
    "oab" TEXT,
    "percentualPadraoSucumbencia" DECIMAL(5,4),
    "ativo" BOOLEAN NOT NULL DEFAULT true,
    "criadoEm" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "atualizadoEm" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "advogado_parceiro_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "conta_bancaria" (
    "id" TEXT NOT NULL,
    "codigo" TEXT NOT NULL,
    "nome" TEXT NOT NULL,
    "tipo" "TipoConta" NOT NULL DEFAULT 'CONTA_CORRENTE',
    "banco" TEXT,
    "agencia" TEXT,
    "conta" TEXT,
    "saldoInicial" DECIMAL(14,2) NOT NULL DEFAULT 0,
    "ativo" BOOLEAN NOT NULL DEFAULT true,
    "criadoEm" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "atualizadoEm" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "conta_bancaria_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "categoria" (
    "id" TEXT NOT NULL,
    "nome" TEXT NOT NULL,
    "tipo" "TipoCategoria" NOT NULL,
    "isPessoal" BOOLEAN NOT NULL DEFAULT false,
    "categoriaPaiId" TEXT,
    "ativo" BOOLEAN NOT NULL DEFAULT true,
    "criadoEm" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "atualizadoEm" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "categoria_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "recebivel" (
    "id" TEXT NOT NULL,
    "processoId" TEXT NOT NULL,
    "clienteId" TEXT NOT NULL,
    "dataPrevista" DATE NOT NULL,
    "tipoParcela" "TipoParcela" NOT NULL DEFAULT 'NORMAL',
    "numeroParcela" INTEGER,
    "totalParcelas" INTEGER,
    "valorIntegral" DECIMAL(14,2) NOT NULL,
    "valorParcela" DECIMAL(14,2) NOT NULL,
    "ressarcimentoEmbutido" DECIMAL(14,2) NOT NULL DEFAULT 0,
    "percHonorarios" DECIMAL(5,4) NOT NULL,
    "parceiroId" TEXT,
    "percParceiro" DECIMAL(5,4),
    "status" "StatusRecebivel" NOT NULL DEFAULT 'PREVISTA',
    "dataRecebimento" DATE,
    "contaRecebimentoId" TEXT,
    "dataRepasseCliente" DATE,
    "contaRepasseId" TEXT,
    "formaRepasse" TEXT,
    "observacoes" TEXT,
    "criadoEm" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "atualizadoEm" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "recebivel_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "distribuicao" (
    "id" TEXT NOT NULL,
    "recebivelId" TEXT NOT NULL,
    "valorBrutoRecebido" DECIMAL(14,2) NOT NULL,
    "dataRecebimento" DATE NOT NULL,
    "observacoes" TEXT,
    "status" "StatusDistribuicao" NOT NULL DEFAULT 'RASCUNHO',
    "criadoPorId" TEXT,
    "criadoEm" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "atualizadoEm" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "distribuicao_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "item_distribuicao" (
    "id" TEXT NOT NULL,
    "distribuicaoId" TEXT NOT NULL,
    "beneficiario" "TipoBeneficiario" NOT NULL,
    "descricao" TEXT,
    "valor" DECIMAL(14,2) NOT NULL,
    "status" "StatusItemDistribuicao" NOT NULL DEFAULT 'PENDENTE_REPASSE',
    "clienteId" TEXT,
    "parceiroId" TEXT,
    "lancamentoId" TEXT,
    "observacoes" TEXT,
    "criadoEm" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "atualizadoEm" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "item_distribuicao_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "lancamento" (
    "id" TEXT NOT NULL,
    "data" DATE NOT NULL,
    "descricao" TEXT NOT NULL,
    "contaId" TEXT NOT NULL,
    "tipo" "TipoLancamento" NOT NULL,
    "valor" DECIMAL(14,2) NOT NULL,
    "categoriaId" TEXT NOT NULL,
    "clienteId" TEXT,
    "processoId" TEXT,
    "recebivelId" TEXT,
    "ressarcimentoId" TEXT,
    "transferenciaParId" TEXT,
    "comprovanteUrl" TEXT,
    "observacoes" TEXT,
    "criadoPorId" TEXT,
    "criadoEm" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "atualizadoEm" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "lancamento_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ressarcimento" (
    "id" TEXT NOT NULL,
    "clienteId" TEXT NOT NULL,
    "processoId" TEXT NOT NULL,
    "data" DATE NOT NULL,
    "descricao" TEXT NOT NULL,
    "valor" DECIMAL(14,2) NOT NULL,
    "status" "StatusRessarcimento" NOT NULL DEFAULT 'PAGO_PELO_ESCRITORIO',
    "dataReembolso" DATE,
    "recebivelId" TEXT,
    "criadoEm" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "atualizadoEm" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "ressarcimento_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "parceria_paga" (
    "id" TEXT NOT NULL,
    "parceiroId" TEXT NOT NULL,
    "clienteId" TEXT NOT NULL,
    "processoId" TEXT NOT NULL,
    "dataAcordo" DATE NOT NULL,
    "valorTotal" DECIMAL(14,2) NOT NULL,
    "valorRecebido" DECIMAL(14,2) NOT NULL DEFAULT 0,
    "percHonorarios" DECIMAL(5,4) NOT NULL,
    "ressarcimentos" DECIMAL(14,2) NOT NULL DEFAULT 0,
    "percParceiro" DECIMAL(5,4) NOT NULL,
    "dataPgto" DATE,
    "observacoes" TEXT,
    "criadoEm" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "atualizadoEm" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "parceria_paga_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "sucumbencia" (
    "id" TEXT NOT NULL,
    "clienteId" TEXT NOT NULL,
    "processoId" TEXT NOT NULL,
    "valorTotal" DECIMAL(14,2) NOT NULL,
    "dataRecebimento" DATE NOT NULL,
    "parceiroExternoId" TEXT,
    "percParceiroExterno" DECIMAL(5,4),
    "percEscritorio" DECIMAL(5,4) NOT NULL DEFAULT 0.34,
    "percClarissa" DECIMAL(5,4) NOT NULL DEFAULT 0.33,
    "percVivian" DECIMAL(5,4) NOT NULL DEFAULT 0.33,
    "dataRepasseClarissa" DATE,
    "dataRepasseVivian" DATE,
    "observacoes" TEXT,
    "criadoEm" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "atualizadoEm" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "sucumbencia_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "auditoria" (
    "id" TEXT NOT NULL,
    "entidade" TEXT NOT NULL,
    "entidadeId" TEXT NOT NULL,
    "acao" "AcaoAuditoria" NOT NULL,
    "dadosAntes" JSONB,
    "dadosDepois" JSONB,
    "usuarioId" TEXT,
    "criadoEm" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "auditoria_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "usuario_email_key" ON "usuario"("email");

-- CreateIndex
CREATE INDEX "cliente_nome_idx" ON "cliente"("nome");

-- CreateIndex
CREATE UNIQUE INDEX "processo_numeroCnj_key" ON "processo"("numeroCnj");

-- CreateIndex
CREATE INDEX "processo_clienteId_idx" ON "processo"("clienteId");

-- CreateIndex
CREATE INDEX "processo_status_idx" ON "processo"("status");

-- CreateIndex
CREATE UNIQUE INDEX "conta_bancaria_codigo_key" ON "conta_bancaria"("codigo");

-- CreateIndex
CREATE UNIQUE INDEX "categoria_nome_categoriaPaiId_key" ON "categoria"("nome", "categoriaPaiId");

-- CreateIndex
CREATE INDEX "recebivel_status_dataPrevista_idx" ON "recebivel"("status", "dataPrevista");

-- CreateIndex
CREATE INDEX "recebivel_clienteId_processoId_idx" ON "recebivel"("clienteId", "processoId");

-- CreateIndex
CREATE INDEX "recebivel_processoId_idx" ON "recebivel"("processoId");

-- CreateIndex
CREATE UNIQUE INDEX "distribuicao_recebivelId_key" ON "distribuicao"("recebivelId");

-- CreateIndex
CREATE INDEX "distribuicao_status_idx" ON "distribuicao"("status");

-- CreateIndex
CREATE INDEX "item_distribuicao_distribuicaoId_idx" ON "item_distribuicao"("distribuicaoId");

-- CreateIndex
CREATE INDEX "item_distribuicao_beneficiario_status_idx" ON "item_distribuicao"("beneficiario", "status");

-- CreateIndex
CREATE INDEX "lancamento_data_contaId_idx" ON "lancamento"("data", "contaId");

-- CreateIndex
CREATE INDEX "lancamento_categoriaId_data_idx" ON "lancamento"("categoriaId", "data");

-- CreateIndex
CREATE INDEX "lancamento_recebivelId_idx" ON "lancamento"("recebivelId");

-- CreateIndex
CREATE INDEX "lancamento_clienteId_idx" ON "lancamento"("clienteId");

-- CreateIndex
CREATE INDEX "ressarcimento_clienteId_processoId_idx" ON "ressarcimento"("clienteId", "processoId");

-- CreateIndex
CREATE INDEX "ressarcimento_status_idx" ON "ressarcimento"("status");

-- CreateIndex
CREATE INDEX "parceria_paga_parceiroId_idx" ON "parceria_paga"("parceiroId");

-- CreateIndex
CREATE INDEX "parceria_paga_clienteId_processoId_idx" ON "parceria_paga"("clienteId", "processoId");

-- CreateIndex
CREATE INDEX "sucumbencia_dataRecebimento_idx" ON "sucumbencia"("dataRecebimento");

-- CreateIndex
CREATE INDEX "sucumbencia_clienteId_processoId_idx" ON "sucumbencia"("clienteId", "processoId");

-- CreateIndex
CREATE INDEX "auditoria_entidade_entidadeId_idx" ON "auditoria"("entidade", "entidadeId");

-- CreateIndex
CREATE INDEX "auditoria_criadoEm_idx" ON "auditoria"("criadoEm");

-- AddForeignKey
ALTER TABLE "processo" ADD CONSTRAINT "processo_clienteId_fkey" FOREIGN KEY ("clienteId") REFERENCES "cliente"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "categoria" ADD CONSTRAINT "categoria_categoriaPaiId_fkey" FOREIGN KEY ("categoriaPaiId") REFERENCES "categoria"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "recebivel" ADD CONSTRAINT "recebivel_processoId_fkey" FOREIGN KEY ("processoId") REFERENCES "processo"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "recebivel" ADD CONSTRAINT "recebivel_clienteId_fkey" FOREIGN KEY ("clienteId") REFERENCES "cliente"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "recebivel" ADD CONSTRAINT "recebivel_parceiroId_fkey" FOREIGN KEY ("parceiroId") REFERENCES "advogado_parceiro"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "recebivel" ADD CONSTRAINT "recebivel_contaRecebimentoId_fkey" FOREIGN KEY ("contaRecebimentoId") REFERENCES "conta_bancaria"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "recebivel" ADD CONSTRAINT "recebivel_contaRepasseId_fkey" FOREIGN KEY ("contaRepasseId") REFERENCES "conta_bancaria"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "distribuicao" ADD CONSTRAINT "distribuicao_recebivelId_fkey" FOREIGN KEY ("recebivelId") REFERENCES "recebivel"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "distribuicao" ADD CONSTRAINT "distribuicao_criadoPorId_fkey" FOREIGN KEY ("criadoPorId") REFERENCES "usuario"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "item_distribuicao" ADD CONSTRAINT "item_distribuicao_distribuicaoId_fkey" FOREIGN KEY ("distribuicaoId") REFERENCES "distribuicao"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "item_distribuicao" ADD CONSTRAINT "item_distribuicao_clienteId_fkey" FOREIGN KEY ("clienteId") REFERENCES "cliente"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "item_distribuicao" ADD CONSTRAINT "item_distribuicao_parceiroId_fkey" FOREIGN KEY ("parceiroId") REFERENCES "advogado_parceiro"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "item_distribuicao" ADD CONSTRAINT "item_distribuicao_lancamentoId_fkey" FOREIGN KEY ("lancamentoId") REFERENCES "lancamento"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "lancamento" ADD CONSTRAINT "lancamento_contaId_fkey" FOREIGN KEY ("contaId") REFERENCES "conta_bancaria"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "lancamento" ADD CONSTRAINT "lancamento_categoriaId_fkey" FOREIGN KEY ("categoriaId") REFERENCES "categoria"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "lancamento" ADD CONSTRAINT "lancamento_clienteId_fkey" FOREIGN KEY ("clienteId") REFERENCES "cliente"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "lancamento" ADD CONSTRAINT "lancamento_processoId_fkey" FOREIGN KEY ("processoId") REFERENCES "processo"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "lancamento" ADD CONSTRAINT "lancamento_recebivelId_fkey" FOREIGN KEY ("recebivelId") REFERENCES "recebivel"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "lancamento" ADD CONSTRAINT "lancamento_ressarcimentoId_fkey" FOREIGN KEY ("ressarcimentoId") REFERENCES "ressarcimento"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "lancamento" ADD CONSTRAINT "lancamento_transferenciaParId_fkey" FOREIGN KEY ("transferenciaParId") REFERENCES "lancamento"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "lancamento" ADD CONSTRAINT "lancamento_criadoPorId_fkey" FOREIGN KEY ("criadoPorId") REFERENCES "usuario"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ressarcimento" ADD CONSTRAINT "ressarcimento_clienteId_fkey" FOREIGN KEY ("clienteId") REFERENCES "cliente"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ressarcimento" ADD CONSTRAINT "ressarcimento_processoId_fkey" FOREIGN KEY ("processoId") REFERENCES "processo"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ressarcimento" ADD CONSTRAINT "ressarcimento_recebivelId_fkey" FOREIGN KEY ("recebivelId") REFERENCES "recebivel"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "parceria_paga" ADD CONSTRAINT "parceria_paga_parceiroId_fkey" FOREIGN KEY ("parceiroId") REFERENCES "advogado_parceiro"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "parceria_paga" ADD CONSTRAINT "parceria_paga_clienteId_fkey" FOREIGN KEY ("clienteId") REFERENCES "cliente"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "parceria_paga" ADD CONSTRAINT "parceria_paga_processoId_fkey" FOREIGN KEY ("processoId") REFERENCES "processo"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "sucumbencia" ADD CONSTRAINT "sucumbencia_clienteId_fkey" FOREIGN KEY ("clienteId") REFERENCES "cliente"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "sucumbencia" ADD CONSTRAINT "sucumbencia_processoId_fkey" FOREIGN KEY ("processoId") REFERENCES "processo"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "sucumbencia" ADD CONSTRAINT "sucumbencia_parceiroExternoId_fkey" FOREIGN KEY ("parceiroExternoId") REFERENCES "advogado_parceiro"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "auditoria" ADD CONSTRAINT "auditoria_usuarioId_fkey" FOREIGN KEY ("usuarioId") REFERENCES "usuario"("id") ON DELETE SET NULL ON UPDATE CASCADE;

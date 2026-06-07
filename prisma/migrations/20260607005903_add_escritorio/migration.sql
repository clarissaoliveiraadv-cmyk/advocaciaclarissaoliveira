-- CreateTable
CREATE TABLE "escritorio" (
    "id" TEXT NOT NULL DEFAULT 'default',
    "nome" TEXT NOT NULL,
    "oab" TEXT,
    "cnpj" TEXT,
    "endereco" TEXT,
    "cidade" TEXT,
    "uf" VARCHAR(2),
    "cep" TEXT,
    "telefone" TEXT,
    "email" TEXT,
    "observacoes" TEXT,
    "criadoEm" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "atualizadoEm" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "escritorio_pkey" PRIMARY KEY ("id")
);

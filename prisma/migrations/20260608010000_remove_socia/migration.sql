-- Remove o valor "SOCIA" dos enums Perfil e TipoParceiro.
-- Agora o escritório tem apenas uma dona; não existe mais a divisão entre sócias.
--
-- 1) Usuários com perfil SOCIA são promovidos para ADMIN.
-- 2) Parceiros marcados como SOCIA viram PARCEIRO_EXTERNO (mantém o registro
--    para preservar histórico de Recebíveis e Distribuições).

-- Perfil
UPDATE "usuario" SET "perfil" = 'ADMIN' WHERE "perfil" = 'SOCIA';

ALTER TYPE "Perfil" RENAME TO "Perfil_old";
CREATE TYPE "Perfil" AS ENUM ('ADMIN', 'SECRETARIA', 'PARCEIRO_LEITURA');
ALTER TABLE "usuario" ALTER COLUMN "perfil" DROP DEFAULT;
ALTER TABLE "usuario" ALTER COLUMN "perfil" TYPE "Perfil" USING ("perfil"::text::"Perfil");
ALTER TABLE "usuario" ALTER COLUMN "perfil" SET DEFAULT 'SECRETARIA';
DROP TYPE "Perfil_old";

-- TipoParceiro
UPDATE "advogado_parceiro" SET "tipo" = 'PARCEIRO_EXTERNO' WHERE "tipo" = 'SOCIA';

ALTER TYPE "TipoParceiro" RENAME TO "TipoParceiro_old";
CREATE TYPE "TipoParceiro" AS ENUM ('PARCEIRO_EXTERNO', 'FUNCIONARIO');
ALTER TABLE "advogado_parceiro" ALTER COLUMN "tipo" DROP DEFAULT;
ALTER TABLE "advogado_parceiro" ALTER COLUMN "tipo" TYPE "TipoParceiro" USING ("tipo"::text::"TipoParceiro");
ALTER TABLE "advogado_parceiro" ALTER COLUMN "tipo" SET DEFAULT 'PARCEIRO_EXTERNO';
DROP TYPE "TipoParceiro_old";

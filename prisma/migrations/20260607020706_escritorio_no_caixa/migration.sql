-- Corrige itens de distribuição cujo beneficiário é do escritório:
-- honorários (contratual e sucumbência) e ressarcimento nunca precisaram
-- de "repasse" — o dinheiro já está no caixa do escritório. Esses itens
-- passam de PENDENTE_REPASSE para RETIDO_CUSTODIA (status semântico "no caixa").
UPDATE "item_distribuicao"
SET "status" = 'RETIDO_CUSTODIA'
WHERE "beneficiario" IN ('ESCRITORIO_CONTRATUAL', 'ESCRITORIO_SUCUMBENCIA', 'RESSARCIMENTO')
  AND "status" = 'PENDENTE_REPASSE';

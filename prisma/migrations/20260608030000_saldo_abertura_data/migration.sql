-- Adiciona saldoAberturaData em conta_bancaria.
-- Quando preenchida, lançamentos com data < saldoAberturaData são ignorados
-- no cálculo do saldo da conta — permite começar o sistema "do zero" a
-- partir de uma data, sem precisar excluir histórico.

ALTER TABLE "conta_bancaria"
  ADD COLUMN "saldoAberturaData" DATE;

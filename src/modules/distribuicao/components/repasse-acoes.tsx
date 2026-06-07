"use client";

import { useTransition } from "react";
import { Lock, Unlock } from "lucide-react";
import { toast } from "sonner";
import { StatusItemDistribuicao, TipoBeneficiario } from "@prisma/client";

import { Button } from "@/components/ui/button";
import { liberarCustodia, marcarEmCustodia } from "../repasse-actions";
import { RepasseFormDialog } from "./repasse-form-dialog";
import { ReverterRepasseDialog } from "./reverter-repasse-dialog";
import type { CategoriaDespesaOpcao, ContaOpcao } from "../queries";

type Props = {
  itemId: string;
  status: StatusItemDistribuicao;
  beneficiario: TipoBeneficiario;
  valor: number;
  descricaoSugerida: string;
  contas: ContaOpcao[];
  categoriasDespesa: CategoriaDespesaOpcao[];
};

/**
 * Beneficiários cujo dinheiro pertence ao escritório — não precisam de ação.
 * Honorários e ressarcimento já estão na conta; o item é apenas informativo.
 */
const NO_CAIXA_DO_ESCRITORIO: ReadonlyArray<TipoBeneficiario> = [
  TipoBeneficiario.ESCRITORIO_CONTRATUAL,
  TipoBeneficiario.ESCRITORIO_SUCUMBENCIA,
  TipoBeneficiario.RESSARCIMENTO,
];

export function RepasseAcoes({
  itemId,
  status,
  beneficiario,
  valor,
  descricaoSugerida,
  contas,
  categoriasDespesa,
}: Props) {
  const ehEscritorio = NO_CAIXA_DO_ESCRITORIO.includes(beneficiario);

  // Itens do escritório não têm ações — o dinheiro já está no caixa.
  if (ehEscritorio) {
    return <span className="text-xs text-muted-foreground">—</span>;
  }

  if (status === StatusItemDistribuicao.REPASSADO) {
    return <ReverterRepasseDialog itemId={itemId} />;
  }

  if (status === StatusItemDistribuicao.RETIDO_CUSTODIA) {
    return <LiberarCustodiaButton itemId={itemId} />;
  }

  // PENDENTE_REPASSE (apenas obrigações reais: cliente, parceiro, perito, etc.)
  return (
    <div className="flex items-center justify-end gap-1">
      <RepasseFormDialog
        itemId={itemId}
        valorItem={valor}
        descricaoSugerida={descricaoSugerida}
        contas={contas}
        categoriasDespesa={categoriasDespesa}
      />
      <MarcarCustodiaButton itemId={itemId} />
    </div>
  );
}

function MarcarCustodiaButton({ itemId }: { itemId: string }) {
  const [pending, startTransition] = useTransition();
  function onClick() {
    startTransition(async () => {
      const result = await marcarEmCustodia(itemId);
      if (!result.ok) {
        toast.error(result.error);
        return;
      }
      toast.success("Item marcado como em custódia");
    });
  }
  return (
    <Button variant="ghost" size="sm" onClick={onClick} disabled={pending}>
      <Lock className="mr-1 h-4 w-4" />
      Em custódia
    </Button>
  );
}

function LiberarCustodiaButton({ itemId }: { itemId: string }) {
  const [pending, startTransition] = useTransition();
  function onClick() {
    startTransition(async () => {
      const result = await liberarCustodia(itemId);
      if (!result.ok) {
        toast.error(result.error);
        return;
      }
      toast.success("Custódia liberada");
    });
  }
  return (
    <Button variant="ghost" size="sm" onClick={onClick} disabled={pending}>
      <Unlock className="mr-1 h-4 w-4" />
      Liberar
    </Button>
  );
}

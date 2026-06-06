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

const ESCRITORIO: ReadonlyArray<TipoBeneficiario> = [
  TipoBeneficiario.ESCRITORIO_CONTRATUAL,
  TipoBeneficiario.ESCRITORIO_SUCUMBENCIA,
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
  if (status === StatusItemDistribuicao.REPASSADO) {
    return <ReverterRepasseDialog itemId={itemId} />;
  }

  if (status === StatusItemDistribuicao.RETIDO_CUSTODIA) {
    return <LiberarCustodiaButton itemId={itemId} />;
  }

  // PENDENTE_REPASSE
  const ehEscritorio = ESCRITORIO.includes(beneficiario);
  return (
    <div className="flex items-center justify-end gap-1">
      {!ehEscritorio && (
        <RepasseFormDialog
          itemId={itemId}
          valorItem={valor}
          descricaoSugerida={descricaoSugerida}
          contas={contas}
          categoriasDespesa={categoriasDespesa}
        />
      )}
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

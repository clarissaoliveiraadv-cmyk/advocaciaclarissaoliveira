"use client";

import { useTransition } from "react";
import { Calendar } from "lucide-react";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import { gerarPrevisoes } from "../actions";

type Props = { competencia: string };

export function GerarPrevisoesButton({ competencia }: Props) {
  const [pending, startTransition] = useTransition();

  function onClick() {
    startTransition(async () => {
      const result = await gerarPrevisoes({ competencia });
      if (!result.ok) {
        toast.error(result.error);
        return;
      }
      const { criadas, jaExistiam } = result.data;
      if (criadas === 0 && jaExistiam > 0) {
        toast.info("Todas as previsões deste mês já estavam geradas.");
      } else {
        toast.success(
          `${criadas} previsão(ões) criada(s)` +
            (jaExistiam > 0 ? ` (${jaExistiam} já existia(m))` : ""),
        );
      }
    });
  }

  return (
    <Button onClick={onClick} disabled={pending} variant="outline">
      <Calendar className="mr-2 h-4 w-4" />
      {pending ? "Gerando..." : "Gerar previsões deste mês"}
    </Button>
  );
}

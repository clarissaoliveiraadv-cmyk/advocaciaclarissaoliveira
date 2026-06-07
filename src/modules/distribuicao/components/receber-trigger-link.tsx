import Link from "next/link";
import { CheckCircle2, Inbox, Receipt } from "lucide-react";
import { StatusRecebivel } from "@prisma/client";

import { Button } from "@/components/ui/button";

type Props = { recebivelId: string; status: StatusRecebivel };

export function ReceberTriggerLink({ recebivelId, status }: Props) {
  if (status === StatusRecebivel.PREVISTA) {
    return (
      <Button asChild variant="default" size="sm">
        <Link href={`/recebiveis/${recebivelId}/receber`}>
          <Inbox className="mr-1 h-4 w-4" />
          Receber
        </Link>
      </Button>
    );
  }
  if (status === StatusRecebivel.RECEBIDA || status === StatusRecebivel.REPASSADA) {
    return (
      <div className="flex items-center gap-1">
        <Button asChild variant="ghost" size="sm" title="Comprovante para o cliente">
          <Link href={`/recebiveis/${recebivelId}/comprovante`}>
            <Receipt className="mr-1 h-4 w-4" />
            Comprovante
          </Link>
        </Button>
        <Button asChild variant="ghost" size="sm">
          <Link href={`/recebiveis/${recebivelId}/receber`}>
            <CheckCircle2 className="mr-1 h-4 w-4" />
            Distribuição
          </Link>
        </Button>
      </div>
    );
  }
  return null;
}

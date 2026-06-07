import Link from "next/link";
import { notFound } from "next/navigation";
import { ChevronLeft, FileText } from "lucide-react";

import { Button } from "@/components/ui/button";
import { getComprovante } from "@/modules/comprovante/queries";
import { ComprovanteTemplate } from "@/modules/comprovante/components/comprovante-template";
import { getOuCriarEscritorio } from "@/modules/escritorio/queries";
import { ImprimirButton } from "@/modules/prestacao-contas/components/imprimir-button";

export const dynamic = "force-dynamic";

type Params = Promise<{ id: string }>;

export default async function ComprovantePage({ params }: { params: Params }) {
  const { id } = await params;
  const [dados, escritorio] = await Promise.all([getComprovante(id), getOuCriarEscritorio()]);

  if (!dados) notFound();

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between print:hidden">
        <Link
          href="/recebiveis"
          className="inline-flex items-center text-sm text-muted-foreground hover:text-foreground"
        >
          <ChevronLeft className="mr-1 h-4 w-4" />
          Voltar para Recebíveis
        </Link>
        <div className="flex items-center gap-2">
          <Button asChild variant="outline">
            <Link href={`/prestacao-contas/${dados.processo.id}`}>
              <FileText className="mr-2 h-4 w-4" />
              Prestação de Contas
            </Link>
          </Button>
          <ImprimirButton />
        </div>
      </div>

      <ComprovanteTemplate dados={dados} escritorio={escritorio} />
    </div>
  );
}

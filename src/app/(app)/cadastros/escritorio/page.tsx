import Link from "next/link";
import { ChevronLeft } from "lucide-react";

import { getOuCriarEscritorio } from "@/modules/escritorio/queries";
import { EscritorioForm } from "@/modules/escritorio/components/escritorio-form";

export const dynamic = "force-dynamic";

export default async function EscritorioPage() {
  const escritorio = await getOuCriarEscritorio();

  return (
    <div className="space-y-6">
      <Link
        href="/cadastros"
        className="inline-flex items-center text-sm text-muted-foreground hover:text-foreground"
      >
        <ChevronLeft className="mr-1 h-4 w-4" />
        Voltar para Cadastros
      </Link>

      <header>
        <h1 className="text-2xl font-semibold">Dados do Escritório</h1>
        <p className="text-sm text-muted-foreground">
          Aparecem no cabeçalho da prestação de contas entregue aos clientes.
        </p>
      </header>

      <EscritorioForm
        initialValues={{
          nome: escritorio.nome,
          oab: escritorio.oab ?? undefined,
          cnpj: escritorio.cnpj ?? undefined,
          endereco: escritorio.endereco ?? undefined,
          cidade: escritorio.cidade ?? undefined,
          uf: escritorio.uf ?? undefined,
          cep: escritorio.cep ?? undefined,
          telefone: escritorio.telefone ?? undefined,
          email: escritorio.email ?? undefined,
          observacoes: escritorio.observacoes ?? undefined,
        }}
      />
    </div>
  );
}

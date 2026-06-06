import Link from "next/link";
import { notFound } from "next/navigation";
import { ChevronLeft } from "lucide-react";
import { StatusRecebivel } from "@prisma/client";

import {
  categoriaReceitaSugerida,
  getDistribuicaoCompleta,
  getRecebivelParaReceber,
  listOpcoesCategoriasDespesa,
  listOpcoesCategoriasReceita,
  listOpcoesContas,
  listOpcoesParceiros,
  sugerirItens,
} from "@/modules/distribuicao/queries";
import { ReceberForm } from "@/modules/distribuicao/components/receber-form";
import { DistribuicaoReadonly } from "@/modules/distribuicao/components/distribuicao-readonly";
import { ReverterButton } from "@/modules/distribuicao/components/reverter-button";
import { formatCnj } from "@/lib/format";
import { toBRL } from "@/lib/money";

export const dynamic = "force-dynamic";

type Params = Promise<{ id: string }>;

export default async function ReceberRecebivelPage({ params }: { params: Params }) {
  const { id } = await params;
  const recebivel = await getRecebivelParaReceber(id);
  if (!recebivel) notFound();

  const [
    contas,
    categoriasReceita,
    categoriasDespesa,
    parceiros,
    defaultCategoriaId,
    distribuicao,
  ] = await Promise.all([
    listOpcoesContas(),
    listOpcoesCategoriasReceita(),
    listOpcoesCategoriasDespesa(),
    listOpcoesParceiros(),
    categoriaReceitaSugerida(),
    getDistribuicaoCompleta(id),
  ]);

  const podeReceber = recebivel.status === StatusRecebivel.PREVISTA;
  const jaRecebido =
    recebivel.status === StatusRecebivel.RECEBIDA || recebivel.status === StatusRecebivel.REPASSADA;

  return (
    <div className="space-y-6">
      <Link
        href="/recebiveis"
        className="inline-flex items-center text-sm text-muted-foreground hover:text-foreground"
      >
        <ChevronLeft className="mr-1 h-4 w-4" />
        Voltar para Recebíveis
      </Link>

      <header className="space-y-1">
        <h1 className="text-2xl font-semibold">
          {podeReceber ? "Registrar recebimento" : "Distribuição confirmada"}
        </h1>
        <p className="text-sm text-muted-foreground">
          {recebivel.cliente.nome}
          {recebivel.processo.numeroCnj && ` · ${formatCnj(recebivel.processo.numeroCnj)}`}
          {" · "}
          parcela prevista de {toBRL(Number(recebivel.valorParcela))}
        </p>
      </header>

      {recebivel.status === StatusRecebivel.CANCELADA && (
        <div className="rounded-md border border-amber-300 bg-amber-50 p-4 text-sm text-amber-900">
          Este recebível está <strong>CANCELADO</strong>. Reabra-o em <code>/recebiveis</code> para
          poder registrar o recebimento.
        </div>
      )}

      {podeReceber && (
        <>
          {contas.length === 0 ? (
            <Alerta>
              Nenhuma conta bancária ativa. Cadastre em <code>/cadastros/contas</code>.
            </Alerta>
          ) : categoriasReceita.length === 0 ? (
            <Alerta>
              Nenhuma categoria de RECEITA ativa. Cadastre em <code>/cadastros/categorias</code>.
            </Alerta>
          ) : (
            <ReceberForm
              recebivelId={recebivel.id}
              recebivelDescricao={montarDescricao(recebivel)}
              clienteDoProcesso={{ id: recebivel.cliente.id, nome: recebivel.cliente.nome }}
              contas={contas}
              categoriasReceita={categoriasReceita}
              parceiros={parceiros}
              defaultCategoriaId={defaultCategoriaId}
              defaultValorBruto={Number(recebivel.valorParcela)}
              itensSugeridos={sugerirItens(recebivel)}
            />
          )}
        </>
      )}

      {jaRecebido && distribuicao && (
        <>
          <DistribuicaoReadonly
            distribuicao={distribuicao}
            contas={contas}
            categoriasDespesa={categoriasDespesa}
          />
          <div className="flex justify-end pt-2">
            <ReverterButton recebivelId={recebivel.id} />
          </div>
        </>
      )}

      {jaRecebido && !distribuicao && (
        <Alerta>
          Recebível marcado como {recebivel.status} mas nenhuma distribuição encontrada — estado
          inconsistente. Reverta manualmente no banco ou abra um chamado.
        </Alerta>
      )}
    </div>
  );
}

function Alerta({ children }: { children: React.ReactNode }) {
  return (
    <div className="rounded-md border border-amber-300 bg-amber-50 p-4 text-sm text-amber-900">
      {children}
    </div>
  );
}

function montarDescricao(
  r: { cliente: { nome: string }; processo: { numeroCnj: string | null } } & {
    tipoParcela: string;
    numeroParcela: number | null;
    totalParcelas: number | null;
  },
): string {
  const partes: string[] = [];
  partes.push(`Honorário — ${r.cliente.nome}`);
  if (r.numeroParcela && r.totalParcelas) {
    partes.push(`parcela ${r.numeroParcela}/${r.totalParcelas}`);
  }
  if (r.processo.numeroCnj) partes.push(formatCnj(r.processo.numeroCnj));
  return partes.join(" · ");
}

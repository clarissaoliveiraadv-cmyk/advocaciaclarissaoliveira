import { prisma } from "@/lib/prisma";

export const dynamic = "force-dynamic";

function brl(n: number) {
  return n.toLocaleString("pt-BR", { style: "currency", currency: "BRL" });
}

export default async function DashboardPage() {
  const [contas, totalRecebiveisPrevistos, totalRecebidoMes, totalRessarcirPendente] = await Promise.all([
    prisma.contaBancaria.findMany({ where: { ativo: true }, orderBy: { codigo: "asc" } }),
    prisma.recebivel.aggregate({
      _sum: { valorParcela: true },
      where: { status: "PREVISTA" },
    }),
    prisma.recebivel.aggregate({
      _sum: { valorParcela: true },
      where: {
        status: { in: ["RECEBIDA", "REPASSADA"] },
        dataRecebimento: { gte: new Date(new Date().getFullYear(), new Date().getMonth(), 1) },
      },
    }),
    prisma.ressarcimento.aggregate({
      _sum: { valor: true },
      where: { status: "PAGO_PELO_ESCRITORIO" },
    }),
  ]);

  const cards = [
    { label: "Recebíveis previstos", value: Number(totalRecebiveisPrevistos._sum.valorParcela ?? 0) },
    { label: "Recebido neste mês", value: Number(totalRecebidoMes._sum.valorParcela ?? 0) },
    { label: "Ressarcimento pendente", value: Number(totalRessarcirPendente._sum.valor ?? 0) },
    { label: "Contas ativas", value: contas.length, isCount: true },
  ];

  return (
    <div className="space-y-6">
      <header>
        <h1 className="text-2xl font-semibold text-slate-900">Painel</h1>
        <p className="text-sm text-slate-500">Visão geral do fluxo financeiro do escritório.</p>
      </header>

      <section className="grid grid-cols-1 gap-4 md:grid-cols-2 lg:grid-cols-4">
        {cards.map((c) => (
          <div key={c.label} className="rounded-xl border bg-white p-4 shadow-sm">
            <p className="text-xs uppercase tracking-wide text-slate-500">{c.label}</p>
            <p className="mt-2 text-2xl font-semibold text-slate-900">
              {c.isCount ? c.value : brl(c.value)}
            </p>
          </div>
        ))}
      </section>

      <section className="rounded-xl border bg-white p-6 shadow-sm">
        <h2 className="mb-4 text-lg font-semibold">Contas bancárias</h2>
        {contas.length === 0 ? (
          <p className="text-sm text-slate-500">
            Nenhuma conta cadastrada. Rode <code className="rounded bg-slate-100 px-1">npm run db:seed</code> para popular.
          </p>
        ) : (
          <table className="w-full text-sm">
            <thead className="text-left text-xs uppercase tracking-wide text-slate-500">
              <tr>
                <th className="pb-2">Código</th>
                <th className="pb-2">Nome</th>
                <th className="pb-2">Tipo</th>
                <th className="pb-2 text-right">Saldo inicial</th>
              </tr>
            </thead>
            <tbody>
              {contas.map((c) => (
                <tr key={c.id} className="border-t">
                  <td className="py-2 font-mono text-xs">{c.codigo}</td>
                  <td className="py-2">{c.nome}</td>
                  <td className="py-2 text-slate-500">{c.tipo}</td>
                  <td className="py-2 text-right">{brl(Number(c.saldoInicial))}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>

      <section className="rounded-xl border border-dashed bg-white p-6 text-sm text-slate-500">
        <strong className="block text-slate-700">Próximos passos (Fase 1 — MVP):</strong>
        <ul className="mt-2 list-disc space-y-1 pl-5">
          <li>CRUD de Clientes / Processos / Categorias / Parceiros</li>
          <li>Movimento de Caixa (lançamentos com filtro mês/conta/categoria)</li>
          <li>Recebíveis (CRUD + status PREVISTA → RECEBIDA → REPASSADA)</li>
          <li>Vinculação automática Recebível → Lançamento (eliminar duplo lançamento)</li>
          <li>Ressarcimentos</li>
          <li>Cards de saldo por conta calculados a partir de Lançamentos</li>
        </ul>
      </section>
    </div>
  );
}

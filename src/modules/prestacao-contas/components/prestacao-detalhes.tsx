import type { Escritorio, TipoBeneficiario } from "@prisma/client";
import { toBRL } from "@/lib/money";
import { formatDataBR } from "@/lib/datas";
import { formatCnj, formatCpfCnpj } from "@/lib/format";
import type { PrestacaoContas } from "../queries";

type Props = { dados: PrestacaoContas; escritorio: Escritorio };

const LABELS: Record<TipoBeneficiario, string> = {
  CLIENTE: "Repasse ao cliente",
  ESCRITORIO_CONTRATUAL: "Honorários contratuais",
  ESCRITORIO_SUCUMBENCIA: "Honorários sucumbenciais",
  PARCEIRO: "Parceria",
  PERITO: "Perito calculista",
  FGTS: "FGTS",
  RESSARCIMENTO: "Ressarcimento de custas adiantadas",
  CUSTAS: "Custas processuais",
  OUTRO: "Outros",
};

export function PrestacaoDetalhes({ dados, escritorio }: Props) {
  const hoje = formatDataBR(new Date().toISOString());
  const periodoTexto = formatPeriodo(dados.periodo);

  return (
    <article className="prestacao-print mx-auto max-w-4xl space-y-6 bg-white p-8 text-sm leading-relaxed text-slate-900 shadow-sm print:max-w-none print:shadow-none">
      <header className="border-b pb-4">
        <h1 className="text-xl font-bold uppercase tracking-wide">{escritorio.nome}</h1>
        <div className="mt-1 grid grid-cols-2 gap-x-4 text-xs text-slate-600">
          {escritorio.oab && <div>OAB: {escritorio.oab}</div>}
          {escritorio.cnpj && <div>CNPJ: {escritorio.cnpj}</div>}
          {escritorio.endereco && <div className="col-span-2">{escritorio.endereco}</div>}
          {(escritorio.cidade || escritorio.uf || escritorio.cep) && (
            <div className="col-span-2">
              {[escritorio.cidade, escritorio.uf].filter(Boolean).join(" / ")}
              {escritorio.cep ? ` · CEP ${escritorio.cep}` : ""}
            </div>
          )}
          {(escritorio.telefone || escritorio.email) && (
            <div className="col-span-2">
              {escritorio.telefone}
              {escritorio.telefone && escritorio.email && " · "}
              {escritorio.email}
            </div>
          )}
        </div>
      </header>

      <section>
        <h2 className="text-base font-bold uppercase">Prestação de Contas</h2>
        <dl className="mt-2 grid grid-cols-[140px_1fr] gap-x-3 gap-y-1">
          <dt className="text-slate-600">Cliente:</dt>
          <dd>
            <strong>{dados.cliente.nome}</strong>
            {dados.cliente.cpfCnpj && <> · CPF/CNPJ: {formatCpfCnpj(dados.cliente.cpfCnpj)}</>}
          </dd>
          <dt className="text-slate-600">Processo:</dt>
          <dd>
            {dados.processo.numeroCnj ? formatCnj(dados.processo.numeroCnj) : "(sem CNJ)"}
            {dados.processo.vara && ` · ${dados.processo.vara}`}
            {dados.processo.tribunal && ` · ${dados.processo.tribunal}`}
          </dd>
          {dados.processo.parteContraria && (
            <>
              <dt className="text-slate-600">Parte contrária:</dt>
              <dd>{dados.processo.parteContraria}</dd>
            </>
          )}
          <dt className="text-slate-600">Período:</dt>
          <dd>{periodoTexto}</dd>
          <dt className="text-slate-600">Emissão:</dt>
          <dd>{hoje}</dd>
        </dl>
      </section>

      <section>
        <h3 className="mb-2 text-sm font-bold uppercase">Movimentações recebidas</h3>
        {dados.distribuicoes.length === 0 ? (
          <p className="text-slate-500">
            Nenhum recebimento confirmado neste processo no período selecionado.
          </p>
        ) : (
          <table className="w-full border-collapse text-xs">
            <thead>
              <tr className="border-b text-left">
                <th className="py-1.5">Data</th>
                <th className="py-1.5">Parcela</th>
                <th className="py-1.5 text-right">Valor recebido</th>
                <th className="py-1.5 text-right">Honor.</th>
                <th className="py-1.5 text-right">Outros</th>
                <th className="py-1.5 text-right">Repassado ao cliente</th>
              </tr>
            </thead>
            <tbody>
              {dados.distribuicoes.map((d) => {
                const linha = sumarizarLinha(d);
                return (
                  <tr key={d.id} className="border-b">
                    <td className="py-1.5 font-mono">{formatDataBR(d.dataRecebimento)}</td>
                    <td className="py-1.5">{labelParcela(d.recebivel)}</td>
                    <td className="py-1.5 text-right font-mono tabular-nums">
                      {toBRL(Number(d.valorBrutoRecebido))}
                    </td>
                    <td className="py-1.5 text-right font-mono tabular-nums">
                      {toBRL(linha.honor)}
                    </td>
                    <td className="py-1.5 text-right font-mono tabular-nums">
                      {toBRL(linha.outros)}
                    </td>
                    <td className="py-1.5 text-right font-mono tabular-nums">
                      {toBRL(linha.cliente)}
                    </td>
                  </tr>
                );
              })}
            </tbody>
            <tfoot>
              <tr className="border-t-2 font-bold">
                <td className="py-2" colSpan={2}>
                  Totais
                </td>
                <td className="py-2 text-right font-mono tabular-nums">
                  {toBRL(dados.totalBruto)}
                </td>
                <td className="py-2 text-right font-mono tabular-nums">
                  {toBRL(dados.totalEscritorio)}
                </td>
                <td className="py-2 text-right font-mono tabular-nums">
                  {toBRL(somarOutros(dados.porBeneficiario))}
                </td>
                <td className="py-2 text-right font-mono tabular-nums">
                  {toBRL(dados.totalCliente)}
                </td>
              </tr>
            </tfoot>
          </table>
        )}
      </section>

      <section>
        <h3 className="mb-2 text-sm font-bold uppercase">Detalhamento por beneficiário</h3>
        <dl className="grid grid-cols-[1fr_auto] gap-x-6 gap-y-1">
          {(Object.entries(dados.porBeneficiario) as [TipoBeneficiario, number][])
            .filter(([, v]) => v > 0)
            .map(([b, v]) => (
              <div key={b} className="contents">
                <dt className={b === "CLIENTE" ? "font-semibold text-slate-900" : "text-slate-700"}>
                  {LABELS[b]}
                </dt>
                <dd
                  className={
                    "text-right font-mono tabular-nums " +
                    (b === "CLIENTE" ? "font-bold text-slate-900" : "text-slate-700")
                  }
                >
                  {toBRL(v)}
                </dd>
              </div>
            ))}
          <dt className="border-t pt-1 font-bold">Total bruto recebido</dt>
          <dd className="border-t pt-1 text-right font-mono font-bold tabular-nums">
            {toBRL(dados.totalBruto)}
          </dd>
        </dl>
      </section>

      {escritorio.observacoes && (
        <section className="border-t pt-4 text-xs text-slate-700">
          <p className="whitespace-pre-wrap">{escritorio.observacoes}</p>
        </section>
      )}

      <section className="pt-8">
        <p className="text-center text-xs text-slate-600">
          {(escritorio.cidade && escritorio.uf ? `${escritorio.cidade}/${escritorio.uf}, ` : "") +
            hoje}
        </p>
        <div className="mx-auto mt-10 w-72 border-t pt-1 text-center text-xs">
          {escritorio.nome}
          {escritorio.oab && <div className="text-slate-600">OAB {escritorio.oab}</div>}
        </div>
      </section>
    </article>
  );
}

function sumarizarLinha(d: PrestacaoContas["distribuicoes"][number]) {
  let honor = 0;
  let cliente = 0;
  let outros = 0;
  for (const i of d.itens) {
    const v = Number(i.valor);
    if (i.beneficiario === "CLIENTE") cliente += v;
    else if (
      i.beneficiario === "ESCRITORIO_CONTRATUAL" ||
      i.beneficiario === "ESCRITORIO_SUCUMBENCIA"
    )
      honor += v;
    else outros += v;
  }
  return { honor, cliente, outros };
}

function somarOutros(p: PrestacaoContas["porBeneficiario"]): number {
  return p.PARCEIRO + p.PERITO + p.FGTS + p.RESSARCIMENTO + p.CUSTAS + p.OUTRO;
}

function labelParcela(r: PrestacaoContas["distribuicoes"][number]["recebivel"]): string {
  const partes: string[] = [];
  if (r.numeroParcela && r.totalParcelas) partes.push(`${r.numeroParcela}/${r.totalParcelas}`);
  if (r.tipoParcela === "HONORARIOS_SUCUMBENCIA") partes.push("Sucumbência");
  else if (r.tipoParcela === "UNICA") partes.push("Única");
  else if (r.tipoParcela === "EXTRAORDINARIA") partes.push("Extra");
  return partes.join(" · ") || "—";
}

function formatPeriodo(p: PrestacaoContas["periodo"]): string {
  if (!p.inicio || !p.fim) return "Sem movimentações registradas";
  if (p.inicio.getTime() === p.fim.getTime()) return formatDataBR(p.inicio.toISOString());
  return `${formatDataBR(p.inicio.toISOString())} a ${formatDataBR(p.fim.toISOString())}`;
}

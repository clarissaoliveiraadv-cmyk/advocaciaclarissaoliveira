import type { Escritorio } from "@prisma/client";
import { CheckCircle2 } from "lucide-react";

import { toBRL } from "@/lib/money";
import { formatDataBR } from "@/lib/datas";
import { formatCnj, formatCpfCnpj } from "@/lib/format";
import type { ComprovanteRecebimento } from "../queries";

type Props = { dados: ComprovanteRecebimento; escritorio: Escritorio };

export function ComprovanteTemplate({ dados, escritorio }: Props) {
  const hoje = formatDataBR(new Date().toISOString());
  const cidadeUf =
    escritorio.cidade && escritorio.uf
      ? `${escritorio.cidade}/${escritorio.uf}`
      : (escritorio.cidade ?? "");

  return (
    <article className="prestacao-print mx-auto max-w-2xl space-y-6 bg-white p-8 text-sm leading-relaxed text-slate-900 shadow-sm print:max-w-none print:shadow-none">
      <header className="border-b pb-4 text-center">
        <h1 className="text-lg font-bold uppercase tracking-wide">{escritorio.nome}</h1>
        {escritorio.oab && <p className="text-xs text-slate-600">OAB {escritorio.oab}</p>}
        {escritorio.cnpj && <p className="text-xs text-slate-600">CNPJ {escritorio.cnpj}</p>}
      </header>

      <section className="text-center">
        <div className="mx-auto mb-2 flex h-12 w-12 items-center justify-center rounded-full bg-emerald-50">
          <CheckCircle2 className="h-7 w-7 text-emerald-700" />
        </div>
        <h2 className="text-base font-bold uppercase">Comprovante de Recebimento</h2>
        <p className="mt-1 text-xs text-slate-500">
          Referência: {dados.recebivelId.slice(-8).toUpperCase()}
        </p>
      </section>

      <section>
        <p className="mb-3 text-sm">
          Olá, <strong className="uppercase">{dados.cliente.nome}</strong>
        </p>
        <p className="text-sm">
          Confirmamos o recebimento, em favor do escritório, do valor referente ao seu processo.
        </p>
      </section>

      <section className="rounded-md border bg-slate-50 p-4">
        <dl className="grid grid-cols-[140px_1fr] gap-x-3 gap-y-2 text-sm">
          <dt className="text-slate-600">Valor recebido:</dt>
          <dd className="font-mono text-base font-bold tabular-nums">
            {toBRL(dados.valorRecebido)}
          </dd>

          <dt className="text-slate-600">Data:</dt>
          <dd className="font-mono">{formatDataBR(dados.dataRecebimento)}</dd>

          <dt className="text-slate-600">Conta:</dt>
          <dd>
            {dados.contaNome}
            <span className="ml-2 font-mono text-xs text-slate-500">({dados.contaCodigo})</span>
          </dd>

          {dados.descricao && (
            <>
              <dt className="text-slate-600">Descrição:</dt>
              <dd>{dados.descricao}</dd>
            </>
          )}

          <dt className="text-slate-600">Processo:</dt>
          <dd className="font-mono text-xs">
            {dados.processo.numeroCnj ? formatCnj(dados.processo.numeroCnj) : "(sem CNJ)"}
            {dados.processo.vara && <div className="font-sans text-sm">{dados.processo.vara}</div>}
          </dd>

          {dados.cliente.cpfCnpj && (
            <>
              <dt className="text-slate-600">CPF/CNPJ:</dt>
              <dd className="font-mono">{formatCpfCnpj(dados.cliente.cpfCnpj)}</dd>
            </>
          )}
        </dl>
      </section>

      <section className="rounded-md bg-slate-50 p-3 text-xs text-slate-600">
        <p>
          <strong>Este documento confirma apenas o recebimento na conta do escritório.</strong> A
          prestação de contas detalhada — com a divisão de honorários e o valor líquido a repassar a
          você — é enviada separadamente.
        </p>
      </section>

      <section className="pt-6">
        <p className="text-center text-xs text-slate-600">
          {cidadeUf && `${cidadeUf}, `}
          {hoje}
        </p>
        <div className="mx-auto mt-10 w-72 border-t pt-1 text-center text-xs">
          {escritorio.nome}
          {escritorio.oab && <div className="text-slate-600">OAB {escritorio.oab}</div>}
        </div>
      </section>

      {(escritorio.telefone || escritorio.email) && (
        <section className="border-t pt-3 text-center text-xs text-slate-500">
          {escritorio.telefone}
          {escritorio.telefone && escritorio.email && " · "}
          {escritorio.email}
        </section>
      )}
    </article>
  );
}

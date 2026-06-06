import { toBRL } from "@/lib/money";

type Props = {
  honor: number;
  parceiroValor: number;
  honorEscritorio: number;
  valorCliente: number;
  parceiroId: string | undefined;
};

export function RecebivelPreviewCalculos({
  honor,
  parceiroValor,
  honorEscritorio,
  valorCliente,
  parceiroId,
}: Props) {
  return (
    <div className="rounded-md border border-dashed bg-muted/30 p-3 text-sm">
      <div className="mb-2 text-xs font-medium uppercase tracking-wide text-muted-foreground">
        Pré-visualização (sugestão de divisão)
      </div>
      <dl className="grid grid-cols-2 gap-x-4 gap-y-1 text-xs">
        <dt className="text-muted-foreground">Honorários totais sugeridos</dt>
        <dd className="text-right font-mono tabular-nums">{toBRL(honor)}</dd>
        {parceiroId && (
          <>
            <dt className="text-muted-foreground">Parceiro receberá</dt>
            <dd className="text-right font-mono tabular-nums">{toBRL(parceiroValor)}</dd>
            <dt className="text-muted-foreground">Escritório (após parceiro)</dt>
            <dd className="text-right font-mono tabular-nums">{toBRL(honorEscritorio)}</dd>
          </>
        )}
        <dt className="text-muted-foreground">Valor a repassar ao cliente</dt>
        <dd className="text-right font-mono font-semibold tabular-nums">{toBRL(valorCliente)}</dd>
      </dl>
      <p className="mt-2 text-xs text-muted-foreground">
        Valores apenas sugeridos. A distribuição definitiva é confirmada na hora do recebimento.
      </p>
    </div>
  );
}

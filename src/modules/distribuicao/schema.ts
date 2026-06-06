import { z } from "zod";
import { TipoBeneficiario } from "@prisma/client";

const isBlank = (v: string | undefined) => !v || v.trim() === "";

const textoOpcional = (max: number) => z.string().trim().max(max).optional();

const valorPositivo = z.coerce
  .number()
  .finite("Valor inválido")
  .positive("Valor deve ser maior que zero");

const valorNaoNegativo = z.coerce
  .number()
  .finite("Valor inválido")
  .nonnegative("Valor não pode ser negativo");

const dataObrigatoria = z
  .string()
  .trim()
  .min(1, "Data obrigatória")
  .regex(/^\d{4}-\d{2}-\d{2}$/, "Data deve estar no formato yyyy-MM-dd");

/**
 * Cada item da distribuição. Os FKs polimórficos (clienteId, parceiroId) só
 * fazem sentido quando o beneficiário é CLIENTE ou PARCEIRO respectivamente —
 * validação cruzada no superRefine abaixo.
 */
export const itemSchema = z.object({
  beneficiario: z.nativeEnum(TipoBeneficiario),
  descricao: textoOpcional(200),
  valor: valorNaoNegativo,
  clienteId: z.string().trim().optional(),
  parceiroId: z.string().trim().optional(),
  observacoes: textoOpcional(500),
});

export const confirmarDistribuicaoSchema = z
  .object({
    recebivelId: z.string().min(1),
    dataRecebimento: dataObrigatoria,
    contaRecebimentoId: z.string().min(1, "Selecione a conta"),
    categoriaLancamentoId: z.string().min(1, "Selecione a categoria"),
    valorBrutoRecebido: valorPositivo,
    descricaoLancamento: z.string().trim().min(2).max(300),
    observacoesDistribuicao: textoOpcional(2000),
    itens: z.array(itemSchema).min(1, "Pelo menos um item é obrigatório"),
  })
  .superRefine((data, ctx) => {
    // soma de itens deve bater com o valor bruto recebido
    const soma = data.itens.reduce((acc, i) => acc + (Number(i.valor) || 0), 0);
    const delta = Math.abs(soma - data.valorBrutoRecebido);
    if (delta > 0.005) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["itens"],
        message: `Soma dos itens (${soma.toFixed(2)}) difere do valor bruto recebido (${data.valorBrutoRecebido.toFixed(2)})`,
      });
    }

    // validação por beneficiário
    data.itens.forEach((item, idx) => {
      if (item.beneficiario === TipoBeneficiario.CLIENTE && isBlank(item.clienteId)) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ["itens", idx, "clienteId"],
          message: "Cliente obrigatório quando beneficiário é CLIENTE",
        });
      }
      if (item.beneficiario === TipoBeneficiario.PARCEIRO && isBlank(item.parceiroId)) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ["itens", idx, "parceiroId"],
          message: "Parceiro obrigatório quando beneficiário é PARCEIRO",
        });
      }
    });
  });

export type ItemInput = z.infer<typeof itemSchema>;
export type ConfirmarDistribuicaoInput = z.infer<typeof confirmarDistribuicaoSchema>;

export const TIPO_BENEFICIARIO_LABELS: Record<TipoBeneficiario, string> = {
  CLIENTE: "Cliente",
  ESCRITORIO_CONTRATUAL: "Escritório — contratual",
  ESCRITORIO_SUCUMBENCIA: "Escritório — sucumbência",
  PARCEIRO: "Parceiro",
  PERITO: "Perito",
  FGTS: "FGTS",
  RESSARCIMENTO: "Ressarcimento",
  CUSTAS: "Custas",
  OUTRO: "Outro",
};

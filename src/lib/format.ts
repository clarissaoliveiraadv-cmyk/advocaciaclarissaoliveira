export function onlyDigits(value: string): string {
  return value.replace(/\D/g, "");
}

export function formatCpfCnpj(value: string): string {
  const d = onlyDigits(value);
  if (d.length === 11) {
    return d.replace(/^(\d{3})(\d{3})(\d{3})(\d{2})$/, "$1.$2.$3-$4");
  }
  if (d.length === 14) {
    return d.replace(/^(\d{2})(\d{3})(\d{3})(\d{4})(\d{2})$/, "$1.$2.$3/$4-$5");
  }
  return value;
}

export function formatTelefone(value: string): string {
  const d = onlyDigits(value);
  if (d.length === 11) return d.replace(/^(\d{2})(\d{5})(\d{4})$/, "($1) $2-$3");
  if (d.length === 10) return d.replace(/^(\d{2})(\d{4})(\d{4})$/, "($1) $2-$3");
  return value;
}

export function validarCpf(value: string): boolean {
  const cpf = onlyDigits(value);
  if (cpf.length !== 11 || /^(\d)\1+$/.test(cpf)) return false;
  const calc = (slice: number) => {
    let soma = 0;
    for (let i = 0; i < slice; i++) soma += Number(cpf[i]) * (slice + 1 - i);
    const r = (soma * 10) % 11;
    return r === 10 ? 0 : r;
  };
  return calc(9) === Number(cpf[9]) && calc(10) === Number(cpf[10]);
}

export function validarCnpj(value: string): boolean {
  const cnpj = onlyDigits(value);
  if (cnpj.length !== 14 || /^(\d)\1+$/.test(cnpj)) return false;
  const pesos1 = [5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2];
  const pesos2 = [6, ...pesos1];
  const calc = (pesos: ReadonlyArray<number>) => {
    const soma = pesos.reduce((acc, p, i) => acc + p * Number(cnpj[i]), 0);
    const r = soma % 11;
    return r < 2 ? 0 : 11 - r;
  };
  return calc(pesos1) === Number(cnpj[12]) && calc(pesos2) === Number(cnpj[13]);
}

export function validarCpfCnpj(value: string): boolean {
  const len = onlyDigits(value).length;
  if (len === 11) return validarCpf(value);
  if (len === 14) return validarCnpj(value);
  return false;
}

export function blankToUndefined(value: unknown): string | undefined {
  if (typeof value !== "string") return undefined;
  const trimmed = value.trim();
  return trimmed === "" ? undefined : trimmed;
}

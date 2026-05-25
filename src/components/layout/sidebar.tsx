import Link from "next/link";

const NAV = [
  { href: "/dashboard", label: "Painel" },
  { href: "/movimento", label: "Movimento de Caixa" },
  { href: "/recebiveis", label: "Recebíveis" },
  { href: "/ressarcimentos", label: "Ressarcimentos" },
  { href: "/parcerias", label: "Parcerias" },
  { href: "/sucumbencia", label: "Sucumbência" },
  { href: "/clientes", label: "Clientes" },
  { href: "/processos", label: "Processos" },
  { href: "/cadastros", label: "Cadastros" },
  { href: "/relatorios", label: "Relatórios" },
] as const;

export function Sidebar() {
  return (
    <aside className="w-64 shrink-0 bg-primary text-primary-foreground">
      <div className="border-b border-white/10 p-6">
        <p className="text-xs uppercase tracking-wide text-white/60">Escritório</p>
        <h2 className="text-base font-semibold leading-tight">Clarissa Oliveira</h2>
        <p className="text-xs text-white/60">Advogados Associados</p>
      </div>
      <nav className="p-3">
        <ul className="space-y-1">
          {NAV.map((item) => (
            <li key={item.href}>
              <Link
                href={item.href}
                className="block rounded-md px-3 py-2 text-sm transition hover:bg-white/10"
              >
                {item.label}
              </Link>
            </li>
          ))}
        </ul>
      </nav>
    </aside>
  );
}

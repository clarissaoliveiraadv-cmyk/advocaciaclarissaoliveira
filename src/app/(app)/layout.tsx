import Link from "next/link";
import { auth, signOut } from "@/auth";
import { redirect } from "next/navigation";

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
];

export default async function AppLayout({ children }: { children: React.ReactNode }) {
  const session = await auth();
  if (!session?.user) redirect("/login");

  return (
    <div className="flex min-h-screen">
      <aside className="w-64 shrink-0 bg-brand text-white">
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

      <div className="flex flex-1 flex-col">
        <header className="flex items-center justify-between border-b bg-white px-6 py-3">
          <div className="text-sm text-slate-500">
            Bem-vinda, <span className="font-medium text-slate-800">{session.user.name ?? session.user.email}</span>
            <span className="ml-2 rounded-full bg-slate-100 px-2 py-0.5 text-xs">{session.user.perfil}</span>
          </div>
          <form
            action={async () => {
              "use server";
              await signOut({ redirectTo: "/login" });
            }}
          >
            <button type="submit" className="text-sm text-slate-600 hover:text-brand">
              Sair
            </button>
          </form>
        </header>
        <main className="flex-1 p-6">{children}</main>
      </div>
    </div>
  );
}

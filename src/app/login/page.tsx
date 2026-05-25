import { signIn } from "@/auth";
import { redirect } from "next/navigation";

async function loginAction(formData: FormData) {
  "use server";
  const email = String(formData.get("email") ?? "");
  const senha = String(formData.get("senha") ?? "");
  try {
    await signIn("credentials", { email, senha, redirectTo: "/dashboard" });
  } catch (error) {
    if ((error as Error).message?.includes("NEXT_REDIRECT")) throw error;
    redirect("/login?erro=1");
  }
}

export default async function LoginPage({
  searchParams,
}: {
  searchParams: Promise<{ erro?: string }>;
}) {
  const { erro } = await searchParams;

  return (
    <main className="flex min-h-screen items-center justify-center bg-slate-100 p-4">
      <div className="w-full max-w-sm rounded-xl bg-white p-8 shadow-md">
        <h1 className="mb-1 text-2xl font-semibold text-brand">Advocacia Clarissa Oliveira</h1>
        <p className="mb-6 text-sm text-slate-500">Gestão Financeira</p>

        <form action={loginAction} className="space-y-4">
          <div>
            <label htmlFor="email" className="mb-1 block text-sm font-medium">E-mail</label>
            <input
              id="email"
              name="email"
              type="email"
              required
              autoComplete="email"
              className="w-full rounded-md border border-slate-300 px-3 py-2 outline-none focus:border-brand focus:ring-1 focus:ring-brand"
            />
          </div>
          <div>
            <label htmlFor="senha" className="mb-1 block text-sm font-medium">Senha</label>
            <input
              id="senha"
              name="senha"
              type="password"
              required
              autoComplete="current-password"
              className="w-full rounded-md border border-slate-300 px-3 py-2 outline-none focus:border-brand focus:ring-1 focus:ring-brand"
            />
          </div>
          {erro && (
            <p className="rounded-md bg-red-50 px-3 py-2 text-sm text-red-700">
              E-mail ou senha inválidos.
            </p>
          )}
          <button
            type="submit"
            className="w-full rounded-md bg-brand px-3 py-2 font-medium text-white transition hover:bg-brand-dark"
          >
            Entrar
          </button>
        </form>
      </div>
    </main>
  );
}

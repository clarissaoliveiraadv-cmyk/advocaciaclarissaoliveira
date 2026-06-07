import Link from "next/link";
import {
  ArrowRight,
  Building2,
  Landmark,
  ListTree,
  Receipt,
  Upload,
  UserCog,
} from "lucide-react";

import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";

const CADASTROS = [
  {
    href: "/cadastros/contas",
    title: "Contas Bancárias",
    descricao: "Contas e caixas usados nos lançamentos financeiros.",
    icon: Landmark,
    disponivel: true,
  },
  {
    href: "/cadastros/saldo-abertura",
    title: "Saldo de Abertura",
    descricao: "Informe o saldo real das contas numa data de corte para iniciar o sistema sem precisar importar histórico.",
    icon: Upload,
    disponivel: true,
  },
  {
    href: "/cadastros/categorias",
    title: "Categorias",
    descricao: "Plano de contas: receitas e despesas (hierárquico).",
    icon: ListTree,
    disponivel: true,
  },
  {
    href: "/cadastros/despesas-fixas",
    title: "Despesas Fixas",
    descricao: "Contas que se repetem mensalmente: luz, condomínio, internet, limpeza.",
    icon: Receipt,
    disponivel: true,
  },
  {
    href: "/cadastros/parceiros",
    title: "Parceiros / Advogados",
    descricao: "Parceiros externos e funcionários para sucumbência e repasses.",
    icon: UserCog,
    disponivel: true,
  },
  {
    href: "/cadastros/escritorio",
    title: "Dados do Escritório",
    descricao: "Nome, OAB, endereço — aparecem na prestação de contas entregue ao cliente.",
    icon: Building2,
    disponivel: true,
  },
] as const;

export default function CadastrosHubPage() {
  return (
    <div className="space-y-6">
      <header>
        <h1 className="text-2xl font-semibold">Cadastros básicos</h1>
        <p className="text-sm text-muted-foreground">
          Estruturas auxiliares usadas pelos demais módulos do sistema.
        </p>
      </header>

      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
        {CADASTROS.map((c) => {
          const Icon = c.icon;
          const Body = (
            <Card
              className={
                c.disponivel ? "transition hover:border-primary/40 hover:shadow" : "opacity-60"
              }
            >
              <CardHeader className="flex flex-row items-start justify-between space-y-0">
                <div className="space-y-1.5">
                  <CardTitle>{c.title}</CardTitle>
                  <CardDescription>{c.descricao}</CardDescription>
                </div>
                <Icon className="h-5 w-5 text-muted-foreground" />
              </CardHeader>
              <CardContent>
                <span className="inline-flex items-center text-sm font-medium text-primary">
                  {c.disponivel ? "Acessar" : "Em breve"}
                  {c.disponivel && <ArrowRight className="ml-1 h-4 w-4" />}
                </span>
              </CardContent>
            </Card>
          );
          return c.disponivel ? (
            <Link key={c.href} href={c.href} className="block">
              {Body}
            </Link>
          ) : (
            <div key={c.href}>{Body}</div>
          );
        })}
      </div>
    </div>
  );
}

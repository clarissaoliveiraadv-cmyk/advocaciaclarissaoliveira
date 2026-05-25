import { PrismaClient, Perfil, TipoConta, TipoCategoria } from "@prisma/client";
import bcrypt from "bcryptjs";

const prisma = new PrismaClient();

async function main() {
  // ---- USUÁRIO ADMIN INICIAL ----
  const adminEmail = "clarissaoliveira.adv@gmail.com";
  const senhaHash = await bcrypt.hash("trocar-em-producao", 10);

  await prisma.usuario.upsert({
    where: { email: adminEmail },
    update: {},
    create: {
      nome: "Clarissa Oliveira",
      email: adminEmail,
      senhaHash,
      perfil: Perfil.ADMIN,
    },
  });

  // ---- CONTAS BANCÁRIAS PADRÃO (espec §8.1) ----
  const contas = [
    { codigo: "INTER_PJ", nome: "Banco Inter PJ", tipo: TipoConta.CONTA_CORRENTE, banco: "Banco Inter" },
    { codigo: "INTER_PF", nome: "Inter PF / Cora", tipo: TipoConta.CONTA_CORRENTE, banco: "Banco Inter / Cora" },
    { codigo: "DIN", nome: "Caixa Físico", tipo: TipoConta.CAIXA_FISICO, banco: null },
  ];
  for (const c of contas) {
    await prisma.contaBancaria.upsert({
      where: { codigo: c.codigo },
      update: {},
      create: c,
    });
  }

  // ---- CATEGORIAS PADRÃO (espec §8.2) ----
  const categorias = [
    { nome: "Ressarcir", tipo: TipoCategoria.DESPESA },
    { nome: "Salário/Honorário", tipo: TipoCategoria.DESPESA },
    { nome: "Fixo", tipo: TipoCategoria.DESPESA },
    { nome: "Consumo/Insumo", tipo: TipoCategoria.DESPESA },
    { nome: "Pessoal", tipo: TipoCategoria.DESPESA, isPessoal: true },
    { nome: "Honorário Contratual", tipo: TipoCategoria.RECEITA },
    { nome: "Honorário Sucumbência", tipo: TipoCategoria.RECEITA },
    { nome: "Ressarcimento Recebido", tipo: TipoCategoria.RECEITA },
  ];
  for (const cat of categorias) {
    await prisma.categoria.upsert({
      where: { nome_categoriaPaiId: { nome: cat.nome, categoriaPaiId: null as unknown as string } },
      update: {},
      create: cat,
    }).catch(async () => {
      // Prisma exige categoriaPaiId não-null no compound key; fallback findFirst+create
      const existing = await prisma.categoria.findFirst({ where: { nome: cat.nome, categoriaPaiId: null } });
      if (!existing) await prisma.categoria.create({ data: cat });
    });
  }

  console.log("Seed concluído. Admin:", adminEmail);
}

main()
  .catch((e) => {
    console.error(e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });

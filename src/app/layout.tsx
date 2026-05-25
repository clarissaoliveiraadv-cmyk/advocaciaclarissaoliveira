import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Advocacia Clarissa Oliveira — Gestão Financeira",
  description: "Sistema de gestão de fluxo financeiro do escritório",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="pt-BR">
      <body>{children}</body>
    </html>
  );
}

import { LanguageSelector } from "../language/language";

export const Layout = ({ children }: { children: React.ReactNode }) => {
  return (
    <div className="flex flex-col justify-center items-center min-h-svh bg-[url(/background.jpg)] bg-cover">
      <LanguageSelector />
      {children}
    </div>
  );
};

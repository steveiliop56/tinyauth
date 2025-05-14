import { useAppContext } from "@/context/app-context";
import { LanguageSelector } from "../language/language";

export const Layout = ({ children }: { children: React.ReactNode }) => {
  const { backgroundImage } = useAppContext();

  return (
    <div
      className={`flex flex-col justify-center items-center min-h-svh bg-[url(${backgroundImage})] bg-cover`}
    >
      <img></img>
      <LanguageSelector />
      {children}
    </div>
  );
};

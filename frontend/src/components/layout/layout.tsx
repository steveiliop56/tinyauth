import { useAppContext } from "@/context/app-context";
import { LanguageSelector } from "../language/language";

export const Layout = ({ children }: { children: React.ReactNode }) => {
  const { backgroundImage } = useAppContext();

  return (
    <div
      className="relative flex flex-col justify-center items-center min-h-svh"
      style={{
        backgroundImage: `url(${backgroundImage})`,
        backgroundSize: "cover",
        backgroundPosition: "center",
      }}
    >
      <LanguageSelector />
      {children}
    </div>
  );
};

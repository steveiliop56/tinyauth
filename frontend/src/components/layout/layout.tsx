import { useAppContext } from "@/context/app-context";
import { LanguageSelector } from "../language/language";
import { Outlet } from "react-router";

export const Layout = () => {
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
      <Outlet />
    </div>
  );
};

import { useAppContext } from "@/context/app-context";
import { LanguageSelector } from "../components/language-selector";
import { Outlet } from "react-router";
import { VersionTooltip } from "../components/version-tooltip";

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
      <VersionTooltip />
    </div>
  );
};

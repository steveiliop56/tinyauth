import { useAppContext } from "@/context/app-context";
import { LanguageSelector } from "../language/language";
import { Outlet } from "react-router";
import { useState } from "react";
import { DomainWarning } from "../domain-warning/domain-warning";

export const Layout = () => {
  const { backgroundImage, appUrl } = useAppContext();
  const [ignoreDomainWarning, setIgnoreDomainWarning] = useState(false);
  const currentUrl = window.location.origin;

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
      {appUrl !== currentUrl && !ignoreDomainWarning ? (
        <DomainWarning
          onClick={() => setIgnoreDomainWarning(true)}
          appUrl={appUrl}
          currentUrl={currentUrl}
        />
      ) : (
        <Outlet />
      )}
    </div>
  );
};

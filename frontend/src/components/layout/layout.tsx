import { useAppContext } from "@/context/app-context";
import { LanguageSelector } from "../language/language";
import { Outlet } from "react-router";
import { useState } from "react";
import { DomainWarning } from "../domain-warning/domain-warning";

const BaseLayout = ({ children }: { children: React.ReactNode }) => {
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

export const Layout = () => {
  const { appUrl } = useAppContext();
  const [ignoreDomainWarning, setIgnoreDomainWarning] = useState(false);
  const currentUrl = window.location.origin;
  const sessionIgnore = window.sessionStorage.getItem("ignoreDomainWarning");

  const handleIgnore = () => {
    window.sessionStorage.setItem("ignoreDomainWarning", "true");
    setIgnoreDomainWarning(true);
  };

  if (
    !ignoreDomainWarning &&
    appUrl !== currentUrl &&
    sessionIgnore !== "true"
  ) {
    return (
      <BaseLayout>
        <DomainWarning
          appUrl={appUrl}
          currentUrl={currentUrl}
          onClick={() => handleIgnore()}
        />
      </BaseLayout>
    );
  }

  return (
    <BaseLayout>
      <Outlet />
    </BaseLayout>
  );
};

import { useAppContext } from "@/context/app-context";
import { LanguageSelector } from "../language/language";
import { Outlet } from "react-router";
import { useCallback, useEffect, useState } from "react";
import { DomainWarning } from "../domain-warning/domain-warning";
import { ThemeToggle } from "../theme-toggle/theme-toggle";

const BaseLayout = ({ children }: { children: React.ReactNode }) => {
  const { backgroundImage, title } = useAppContext();

  useEffect(() => {
    document.title = title;
  }, [title]);

  return (
    <div
      className="relative flex flex-col justify-center items-center min-h-svh"
      style={{
        backgroundImage: `url(${backgroundImage})`,
        backgroundSize: "cover",
        backgroundPosition: "center",
      }}
    >
      <div className="absolute top-5 right-5 flex flex-row gap-2">
        <ThemeToggle />
        <LanguageSelector />
      </div>
      {children}
    </div>
  );
};

export const Layout = () => {
  const { appUrl } = useAppContext();
  const [ignoreDomainWarning, setIgnoreDomainWarning] = useState(() => {
    return window.sessionStorage.getItem("ignoreDomainWarning") === "true";
  });
  const currentUrl = window.location.origin;

  const handleIgnore = useCallback(() => {
    window.sessionStorage.setItem("ignoreDomainWarning", "true");
    setIgnoreDomainWarning(true);
  }, [setIgnoreDomainWarning]);

  if (!ignoreDomainWarning && appUrl !== currentUrl) {
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

import { Button } from "@/components/ui/button";
import {
  Card,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { useAppContext } from "@/context/app-context";
import { useUserContext } from "@/context/user-context";
import { Trans, useTranslation } from "react-i18next";
import { Navigate, useLocation, useNavigate } from "react-router";
import { useCallback, useEffect, useRef, useState } from "react";
import { useRedirectUri } from "@/lib/hooks/redirect-uri";

export const ContinuePage = () => {
  const { cookieDomain, disableUiWarnings } = useAppContext();
  const { isLoggedIn } = useUserContext();
  const { search } = useLocation();
  const { t } = useTranslation();
  const navigate = useNavigate();

  const [isLoading, setIsLoading] = useState(false);
  const [showRedirectButton, setShowRedirectButton] = useState(false);
  const hasRedirected = useRef(false);

  const searchParams = new URLSearchParams(search);
  const redirectUri = searchParams.get("redirect_uri");

  const { url, valid, trusted, allowedProto, httpsDowngrade } = useRedirectUri(
    redirectUri,
    cookieDomain,
  );

  const urlHref = url?.href;

  const hasValidRedirect = valid && allowedProto;
  const showUntrustedWarning =
    hasValidRedirect && !trusted && !disableUiWarnings;
  const showInsecureWarning =
    hasValidRedirect && httpsDowngrade && !disableUiWarnings;
  const shouldAutoRedirect =
    isLoggedIn &&
    hasValidRedirect &&
    !showUntrustedWarning &&
    !showInsecureWarning;

  const redirectToTarget = useCallback(() => {
    if (!urlHref || hasRedirected.current) {
      return;
    }

    hasRedirected.current = true;
    window.location.assign(urlHref);
  }, [urlHref]);

  const handleRedirect = useCallback(() => {
    setIsLoading(true);
    redirectToTarget();
  }, [redirectToTarget]);

  useEffect(() => {
    if (!shouldAutoRedirect) {
      return;
    }

    const auto = setTimeout(() => {
      redirectToTarget();
    }, 100);

    const reveal = setTimeout(() => {
      setShowRedirectButton(true);
    }, 5000);

    return () => {
      clearTimeout(auto);
      clearTimeout(reveal);
    };
  }, [shouldAutoRedirect, redirectToTarget]);

  if (!isLoggedIn) {
    return (
      <Navigate
        to={`/login${redirectUri ? `?redirect_uri=${encodeURIComponent(redirectUri)}` : ""}`}
        replace
      />
    );
  }

  if (!hasValidRedirect) {
    return <Navigate to="/logout" replace />;
  }

  if (showUntrustedWarning) {
    return (
      <Card role="alert" aria-live="assertive">
        <CardHeader>
          <CardTitle className="text-xl">
            {t("continueUntrustedRedirectTitle")}
          </CardTitle>
          <CardDescription>
            <Trans
              i18nKey="continueUntrustedRedirectSubtitle"
              t={t}
              components={{
                code: <code />,
              }}
              values={{ cookieDomain }}
              shouldUnescape={true}
            />
          </CardDescription>
        </CardHeader>
        <CardFooter className="flex flex-col items-stretch gap-3">
          <Button
            onClick={handleRedirect}
            loading={isLoading}
            variant="destructive"
          >
            {t("continueTitle")}
          </Button>
          <Button
            onClick={() => navigate("/logout")}
            variant="outline"
            disabled={isLoading}
          >
            {t("cancelTitle")}
          </Button>
        </CardFooter>
      </Card>
    );
  }

  if (showInsecureWarning) {
    return (
      <Card role="alert" aria-live="assertive">
        <CardHeader>
          <CardTitle className="text-3xl">
            {t("continueInsecureRedirectTitle")}
          </CardTitle>
          <CardDescription>
            <Trans
              i18nKey="continueInsecureRedirectSubtitle"
              t={t}
              components={{
                code: <code />,
              }}
            />
          </CardDescription>
        </CardHeader>
        <CardFooter className="flex flex-col items-stretch gap-3">
          <Button
            onClick={handleRedirect}
            loading={isLoading}
            variant="warning"
          >
            {t("continueTitle")}
          </Button>
          <Button
            onClick={() => navigate("/logout")}
            variant="outline"
            disabled={isLoading}
          >
            {t("cancelTitle")}
          </Button>
        </CardFooter>
      </Card>
    );
  }

  return (
    <Card className="min-w-xs">
      <CardHeader className="gap-1.5">
        <CardTitle className="text-xl">
          {t("continueRedirectingTitle")}
        </CardTitle>
        <CardDescription>{t("continueRedirectingSubtitle")}</CardDescription>
      </CardHeader>
      {showRedirectButton && (
        <CardFooter className="flex flex-col items-stretch">
          <Button onClick={handleRedirect}>
            {t("continueRedirectManually")}
          </Button>
        </CardFooter>
      )}
    </Card>
  );
};

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
import { isValidUrl } from "@/lib/utils";
import { Trans, useTranslation } from "react-i18next";
import { Navigate, useLocation, useNavigate } from "react-router";
import { useEffect, useState } from "react";

export const ContinuePage = () => {
  const { cookieDomain } = useAppContext();
  const { isLoggedIn } = useUserContext();
  const { search } = useLocation();
  const { t } = useTranslation();
  const navigate = useNavigate();

  const [loading, setLoading] = useState(false);
  const [showRedirectButton, setShowRedirectButton] = useState(false);

  const searchParams = new URLSearchParams(search);
  const redirectUri = searchParams.get("redirect_uri");

  const isValidRedirectUri =
    redirectUri !== null ? isValidUrl(redirectUri) : false;
  const redirectUriObj = isValidRedirectUri
    ? new URL(redirectUri as string)
    : null;
  const isTrustedRedirectUri =
    redirectUriObj !== null
      ? redirectUriObj.hostname === cookieDomain ||
        redirectUriObj.hostname.endsWith(`.${cookieDomain}`)
      : false;
  const isAllowedRedirectProto =
    redirectUriObj !== null
      ? redirectUriObj.protocol === "https:" ||
        redirectUriObj.protocol === "http:"
      : false;
  const isHttpsDowngrade =
    redirectUriObj !== null
      ? redirectUriObj.protocol === "http:" &&
        window.location.protocol === "https:"
      : false;

  const handleRedirect = () => {
    setLoading(true);
    window.location.assign(redirectUriObj!.toString());
  };

  useEffect(() => {
    if (
      !isLoggedIn ||
      !isValidRedirectUri ||
      !isTrustedRedirectUri ||
      !isAllowedRedirectProto ||
      isHttpsDowngrade
    ) {
      return;
    }

    const auto = setTimeout(() => {
      handleRedirect();
    }, 100);

    const reveal = setTimeout(() => {
      setLoading(false);
      setShowRedirectButton(true);
    }, 5000);

    return () => {
      clearTimeout(auto);
      clearTimeout(reveal);
    };
  }, [
    handleRedirect,
    isAllowedRedirectProto,
    isHttpsDowngrade,
    isLoggedIn,
    isTrustedRedirectUri,
    isValidRedirectUri,
  ]);

  if (!isLoggedIn) {
    return (
      <Navigate
        to={`/login?redirect_uri=${encodeURIComponent(redirectUri || "")}`}
        replace
      />
    );
  }

  if (!isValidRedirectUri || !isAllowedRedirectProto) {
    return <Navigate to="/logout" replace />;
  }

  if (!isTrustedRedirectUri) {
    return (
      <Card role="alert" aria-live="assertive" className="min-w-xs sm:min-w-sm">
        <CardHeader>
          <CardTitle className="text-3xl">
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
            />
          </CardDescription>
        </CardHeader>
        <CardFooter className="flex flex-col items-stretch gap-2">
          <Button
            onClick={handleRedirect}
            loading={loading}
            variant="destructive"
          >
            {t("continueTitle")}
          </Button>
          <Button
            onClick={() => navigate("/logout")}
            variant="outline"
            disabled={loading}
          >
            {t("cancelTitle")}
          </Button>
        </CardFooter>
      </Card>
    );
  }

  if (isHttpsDowngrade) {
    return (
      <Card role="alert" aria-live="assertive" className="min-w-xs sm:min-w-sm">
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
        <CardFooter className="flex flex-col items-stretch gap-2">
          <Button onClick={handleRedirect} loading={loading} variant="warning">
            {t("continueTitle")}
          </Button>
          <Button
            onClick={() => navigate("/logout")}
            variant="outline"
            disabled={loading}
          >
            {t("cancelTitle")}
          </Button>
        </CardFooter>
      </Card>
    );
  }

  return (
    <Card className="min-w-xs sm:min-w-sm">
      <CardHeader>
        <CardTitle className="text-3xl">
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

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
import DOMPurify from "dompurify";
import { useEffect, useState } from "react";

export const ContinuePage = () => {
  const { isLoggedIn } = useUserContext();

  if (!isLoggedIn) {
    return <Navigate to="/login" />;
  }

  const { rootDomain } = useAppContext();
  const { search } = useLocation();
  const [loading, setLoading] = useState(false);
  const [showRedirectButton, setShowRedirectButton] = useState(false);

  const searchParams = new URLSearchParams(search);
  const redirectURI = searchParams.get("redirect_uri");

  if (!redirectURI) {
    return <Navigate to="/logout" />;
  }

  if (!isValidUrl(DOMPurify.sanitize(redirectURI))) {
    return <Navigate to="/logout" />;
  }

  const { t } = useTranslation();
  const navigate = useNavigate();

  const handleRedirect = () => {
    setLoading(true);
    window.location.href = DOMPurify.sanitize(redirectURI);
  };

  const redirectURLObj = new URL(redirectURI);

  if (
    !(redirectURLObj.hostname == rootDomain) &&
    !redirectURLObj.hostname.endsWith(`.${rootDomain}`)
  ) {
    return (
      <Card className="min-w-xs sm:min-w-sm">
        <CardHeader>
          <CardTitle className="text-3xl">
            {t("untrustedRedirectTitle")}
          </CardTitle>
          <CardDescription>
            <Trans
              i18nKey="untrustedRedirectSubtitle"
              t={t}
              components={{
                code: <code />,
              }}
              values={{ rootDomain }}
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

  if (
    redirectURLObj.protocol === "http:" &&
    window.location.protocol === "https:"
  ) {
    return (
      <Card className="min-w-xs sm:min-w-sm">
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

  useEffect(() => {
    setTimeout(() => {
      handleRedirect();
    }, 100);
    setTimeout(() => {
      setLoading(false);
      setShowRedirectButton(true);
    }, 1000);
  }, []);

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

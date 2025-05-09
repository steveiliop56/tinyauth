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
import { Navigate, useNavigate } from "react-router";

export const ContinuePage = () => {
  const params = new URLSearchParams(window.location.search);
  const redirectURI = params.get("redirect_uri");

  const { isLoggedIn } = useUserContext();
  const { domain, disableContinue } = useAppContext();
  const { t } = useTranslation();

  const navigate = useNavigate();

  if (!isLoggedIn) {
    return <Navigate to="/login" />;
  }

  if (!redirectURI) {
    return <Navigate to="/" />;
  }

  if (!isValidUrl(redirectURI)) {
    return <Navigate to="/" />;
  }

  if (disableContinue) {
    window.location.href = redirectURI;
  }

  const url = new URL(redirectURI);

  if (!url.hostname.includes(domain)) {
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
              values={{ domain }}
            />
          </CardDescription>
        </CardHeader>
        <CardFooter className="flex flex-col items-stretch gap-2">
          <Button
            onClick={() => window.location.replace(redirectURI)}
            variant="destructive"
          >
            {t("continueTitle")}
          </Button>
          <Button onClick={() => navigate("/")} variant="outline">
            {t("cancelTitle")}
          </Button>
        </CardFooter>
      </Card>
    );
  }

  if (url.protocol === "http:" && window.location.protocol === "https:") {
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
          <Button
            onClick={() => window.location.replace(redirectURI)}
            variant="warning"
          >
            {t("continueTitle")}
          </Button>
          <Button onClick={() => navigate("/")} variant="outline">
            {t("cancelTitle")}
          </Button>
        </CardFooter>
      </Card>
    );
  }

  return (
    <Card className="min-w-xs sm:min-w-sm">
      <CardHeader>
        <CardTitle className="text-3xl">{t("continueTitle")}</CardTitle>
        <CardDescription>{t("continueSubtitle")}</CardDescription>
      </CardHeader>
      <CardFooter className="flex flex-col items-stretch">
        <Button onClick={() => window.location.replace(redirectURI)}>
          {t("continueTitle")}
        </Button>
      </CardFooter>
    </Card>
  );
};

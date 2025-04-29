import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { isValidUrl } from "@/lib/utils";
import { Trans, useTranslation } from "react-i18next";
import { Navigate, useNavigate } from "react-router";

export const ContinuePage = () => {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const params = new URLSearchParams(window.location.search);

  const redirectURI = params.get("redirect_uri") ?? "";

  //psuedo
  const domain = "127.0.0.1";
  const disableContinue = false;

  if (redirectURI === "") {
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
      <Card className="min-w-xs md:max-w-sm">
        <CardHeader>
          <CardTitle className="text-3xl">
            {t("untrustedRedirectTitle")}
          </CardTitle>
          <CardDescription>
            <Trans
              i18nKey="untrustedRedirectSubtitle"
              t={t}
              components={{
                code: (
                  <code className="relative rounded bg-muted px-[0.3rem] py-[0.2rem] font-mono text-sm font-semibold" />
                ),
              }}
              values={{ domain }}
            />
          </CardDescription>
        </CardHeader>
        <CardContent className="flex flex-col gap-2 items-stretch">
          <Button
            onClick={() => window.location.replace(redirectURI)}
            variant="destructive"
          >
            {t("continueTitle")}
          </Button>
          <Button onClick={() => navigate("/")} variant="outline">
            {t("cancelTitle")}
          </Button>
        </CardContent>
      </Card>
    );
  }

  if (url.protocol === "http:" && window.location.protocol === "https:") {
    return (
      <Card className="min-w-xs md:max-w-sm">
        <CardHeader>
          <CardTitle className="text-3xl">
            {t("continueInsecureRedirectTitle")}
          </CardTitle>
          <CardDescription>
            <Trans
              i18nKey="continueInsecureRedirectSubtitle"
              t={t}
              components={{
                code: (
                  <code className="relative rounded bg-muted px-[0.3rem] py-[0.2rem] font-mono text-sm font-semibold" />
                ),
              }}
            />
          </CardDescription>
        </CardHeader>
        <CardContent className="flex flex-col gap-2 items-stretch">
          <Button
            onClick={() => window.location.replace(redirectURI)}
            variant="warning"
          >
            {t("continueTitle")}
          </Button>
          <Button onClick={() => navigate("/")} variant="outline">
            {t("cancelTitle")}
          </Button>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card className="min-w-xs md:max-w-sm">
      <CardHeader>
        <CardTitle className="text-3xl">{t("continueTitle")}</CardTitle>
        <CardDescription>{t("continueSubtitle")}</CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col items-stretch">
        <Button onClick={() => window.location.replace(redirectURI)}>
          {t("continueTitle")}
        </Button>
      </CardContent>
    </Card>
  );
};

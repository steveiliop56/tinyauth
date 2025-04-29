import { OAuthButton } from "@/components/auth/oauth-button";
import { GenericIcon } from "@/components/icons/generic";
import { GithubIcon } from "@/components/icons/github";
import { GoogleIcon } from "@/components/icons/google";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardHeader,
  CardTitle,
  CardDescription,
  CardContent,
} from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Separator } from "@/components/ui/separator";
import { useTranslation } from "react-i18next";

export const LoginPage = () => {
  const { t } = useTranslation();
  const configuredProviders = ["google", "github", "generic", "username"];
  const title = "Tinyauth";

  const oauthConfigured =
    configuredProviders.filter((provider) => provider !== "username").length >
    0;
  const userAuthConfigured = configuredProviders.includes("username");

  return (
    <Card className="max-w-xs md:max-w-sm">
      <CardHeader>
        <CardTitle className="text-center text-3xl">{title}</CardTitle>
        {configuredProviders.length > 0 && (
          <CardDescription className="text-center">
            {oauthConfigured ? t("loginTitle") : t("loginTitleSimple")}
          </CardDescription>
        )}
      </CardHeader>
      <CardContent className="flex flex-col gap-4">
        {oauthConfigured && (
          <div className="flex flex-row gap-3 flex-wrap items-center justify-center">
            {configuredProviders.includes("google") && (
              <OAuthButton title="Google" icon={<GoogleIcon />} />
            )}
            {configuredProviders.includes("github") && (
              <OAuthButton title="Github" icon={<GithubIcon />} />
            )}
            {configuredProviders.includes("generic") && (
              <OAuthButton title="Generic" icon={<GenericIcon />} />
            )}
          </div>
        )}
        {userAuthConfigured && oauthConfigured && (
          <div className="flex items-center gap-4">
            <Separator className="flex-1" />
            <span className="text-sm text-muted-foreground">
              {t("loginDivider")}
            </span>
            <Separator className="flex-1" />
          </div>
        )}
        {userAuthConfigured && (
          <div className="flex flex-col gap-4">
            <div>
              <Label htmlFor="#username">{t("loginUsername")}</Label>
              <Input
                id="username"
                placeholder={t("loginUsername")}
                className="mt-2"
              />
            </div>
            <div>
              <Label htmlFor="#password">
                <div className="flex flex-row min-w-full items-center justify-between">
                  <span>{t("loginPassword")}</span>
                  <a
                    href="/forgot"
                    className="text-muted-foreground font-normal"
                  >
                    {t("forgotPasswordTitle")}
                  </a>
                </div>
              </Label>
              <Input
                id="password"
                placeholder={t("loginPassword")}
                className="mt-2"
              />
            </div>
            <Button>{t("loginSubmit")}</Button>
          </div>
        )}
        {configuredProviders.length == 0 && (
          <h3 className="text-center text-xl text-red-600">
            {t("failedToFetchProvidersTitle")}
          </h3>
        )}
      </CardContent>
    </Card>
  );
};

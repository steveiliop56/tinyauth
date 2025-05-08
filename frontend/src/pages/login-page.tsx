import { LoginForm } from "@/components/auth/login-form";
import { GenericIcon } from "@/components/icons/generic";
import { GithubIcon } from "@/components/icons/github";
import { GoogleIcon } from "@/components/icons/google";
import {
  Card,
  CardHeader,
  CardTitle,
  CardDescription,
  CardContent,
} from "@/components/ui/card";
import { OAuthButton } from "@/components/ui/oauth-button";
import { SeperatorWithChildren } from "@/components/ui/separator";
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
      <CardContent className="flex flex-col gap-5">
        {oauthConfigured && (
          <div className="flex flex-row flex-wrap gap-3 items-center justify-center">
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
          <SeperatorWithChildren>{t("loginDivider")}</SeperatorWithChildren>
        )}
        {userAuthConfigured && <LoginForm />}
        {configuredProviders.length == 0 && (
          <h3 className="text-center text-xl text-red-600">
            {t("failedToFetchProvidersTitle")}
          </h3>
        )}
      </CardContent>
    </Card>
  );
};

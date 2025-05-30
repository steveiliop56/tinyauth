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
import { useAppContext } from "@/context/app-context";
import { useUserContext } from "@/context/user-context";
import { useIsMounted } from "@/lib/hooks/use-is-mounted";
import { LoginSchema } from "@/schemas/login-schema";
import { useMutation } from "@tanstack/react-query";
import axios, { AxiosError } from "axios";
import { useEffect } from "react";
import { useTranslation } from "react-i18next";
import { Navigate, useLocation } from "react-router";
import { toast } from "sonner";

export const LoginPage = () => {
  const { isLoggedIn } = useUserContext();

  if (isLoggedIn) {
    return <Navigate to="/logout" />;
  }

  const { configuredProviders, title, oauthAutoRedirect, genericName } = useAppContext();
  const { search } = useLocation();
  const { t } = useTranslation();
  const isMounted = useIsMounted();

  const searchParams = new URLSearchParams(search);
  const redirectUri = searchParams.get("redirect_uri");

  const oauthConfigured =
    configuredProviders.filter((provider) => provider !== "username").length >
    0;
  const userAuthConfigured = configuredProviders.includes("username");

  const oauthMutation = useMutation({
    mutationFn: (provider: string) =>
      axios.get(
        `/api/oauth/url/${provider}?redirect_uri=${encodeURIComponent(redirectUri ?? "")}`,
      ),
    mutationKey: ["oauth"],
    onSuccess: (data) => {
      toast.info(t("loginOauthSuccessTitle"), {
        description: t("loginOauthSuccessSubtitle"),
      });

      setTimeout(() => {
        window.location.href = data.data.url;
      }, 500);
    },
    onError: () => {
      toast.error(t("loginOauthFailTitle"), {
        description: t("loginOauthFailSubtitle"),
      });
    },
  });

  const loginMutation = useMutation({
    mutationFn: (values: LoginSchema) => axios.post("/api/login", values),
    mutationKey: ["login"],
    onSuccess: (data) => {
      if (data.data.totpPending) {
        window.location.replace(
          `/totp?redirect_uri=${encodeURIComponent(redirectUri ?? "")}`,
        );
        return;
      }

      toast.success(t("loginSuccessTitle"), {
        description: t("loginSuccessSubtitle"),
      });

      setTimeout(() => {
        window.location.replace(
          `/continue?redirect_uri=${encodeURIComponent(redirectUri ?? "")}`,
        );
      }, 500);
    },
    onError: (error: AxiosError) => {
      toast.error(t("loginFailTitle"), {
        description:
          error.response?.status === 429
            ? t("loginFailRateLimit")
            : t("loginFailSubtitle"),
      });
    },
  });

  useEffect(() => {
    if (isMounted()) {
      if (
        oauthConfigured &&
        configuredProviders.includes(oauthAutoRedirect) &&
        redirectUri
      ) {
        oauthMutation.mutate(oauthAutoRedirect);
      }
    }
  }, []);

  return (
    <Card className="min-w-xs sm:min-w-sm">
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
          <div className="flex flex-col gap-2 items-center justify-center">
            {configuredProviders.includes("google") && (
              <OAuthButton
                title="Google"
                icon={<GoogleIcon />}
                className="w-full"
                onClick={() => oauthMutation.mutate("google")}
                loading={oauthMutation.isPending && oauthMutation.variables === "google"}
                disabled={oauthMutation.isPending || loginMutation.isPending}
              />
            )}
            {configuredProviders.includes("github") && (
              <OAuthButton
                title="Github"
                icon={<GithubIcon />}
                className="w-full"
                onClick={() => oauthMutation.mutate("github")}
                loading={oauthMutation.isPending && oauthMutation.variables === "github"}
                disabled={oauthMutation.isPending || loginMutation.isPending}
              />
            )}
            {configuredProviders.includes("generic") && (
              <OAuthButton
                title={genericName}
                icon={<GenericIcon />}
                className="w-full"
                onClick={() => oauthMutation.mutate("generic")}
                loading={oauthMutation.isPending && oauthMutation.variables === "generic"}
                disabled={oauthMutation.isPending || loginMutation.isPending}
              />
            )}
          </div>
        )}
        {userAuthConfigured && oauthConfigured && (
          <SeperatorWithChildren>{t("loginDivider")}</SeperatorWithChildren>
        )}
        {userAuthConfigured && (
          <LoginForm
            onSubmit={(values) => loginMutation.mutate(values)}
            loading={loginMutation.isPending || oauthMutation.isPending}
          />
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

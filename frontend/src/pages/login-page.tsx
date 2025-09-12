import { LoginForm } from "@/components/auth/login-form";
import { GithubIcon } from "@/components/icons/github";
import { GoogleIcon } from "@/components/icons/google";
import { MicrosoftIcon } from "@/components/icons/microsoft";
import { OAuthIcon } from "@/components/icons/oauth";
import { PocketIDIcon } from "@/components/icons/pocket-id";
import { TailscaleIcon } from "@/components/icons/tailscale";
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
import { useEffect, useRef } from "react";
import { useTranslation } from "react-i18next";
import { Navigate, useLocation } from "react-router";
import { toast } from "sonner";

const iconMap: Record<string, React.ReactNode> = {
  google: <GoogleIcon />,
  github: <GithubIcon />,
  tailscale: <TailscaleIcon />,
  microsoft: <MicrosoftIcon />,
  pocketid: <PocketIDIcon />,
};

export const LoginPage = () => {
  const { isLoggedIn } = useUserContext();
  const { providers, title, oauthAutoRedirect } = useAppContext();
  const { search } = useLocation();
  const { t } = useTranslation();
  const isMounted = useIsMounted();

  const redirectTimer = useRef<number | null>(null);

  const searchParams = new URLSearchParams(search);
  const redirectUri = searchParams.get("redirect_uri");

  const oauthProviders = providers.filter(
    (provider) => provider.id !== "username",
  );
  const userAuthConfigured =
    providers.find((provider) => provider.id === "username") !== undefined;

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

      redirectTimer.current = window.setTimeout(() => {
        window.location.replace(data.data.url);
      }, 500);
    },
    onError: () => {
      toast.error(t("loginOauthFailTitle"), {
        description: t("loginOauthFailSubtitle"),
      });
    },
  });

  const loginMutation = useMutation({
    mutationFn: (values: LoginSchema) => axios.post("/api/user/login", values),
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

      redirectTimer.current = window.setTimeout(() => {
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
        oauthProviders.length !== 0 &&
        providers.find((provider) => provider.id === oauthAutoRedirect) &&
        !isLoggedIn &&
        redirectUri
      ) {
        oauthMutation.mutate(oauthAutoRedirect);
      }
    }
  }, []);

  useEffect(
    () => () => {
      if (redirectTimer.current) clearTimeout(redirectTimer.current);
    },
    [],
  );

  if (isLoggedIn && redirectUri) {
    return (
      <Navigate
        to={`/continue?redirect_uri=${encodeURIComponent(redirectUri)}`}
        replace
      />
    );
  }

  if (isLoggedIn) {
    return <Navigate to="/logout" replace />;
  }

  return (
    <Card className="min-w-xs sm:min-w-sm">
      <CardHeader>
        <CardTitle className="text-center text-3xl">{title}</CardTitle>
        {providers.length > 0 && (
          <CardDescription className="text-center">
            {oauthProviders.length !== 0
              ? t("loginTitle")
              : t("loginTitleSimple")}
          </CardDescription>
        )}
      </CardHeader>
      <CardContent className="flex flex-col gap-4">
        {oauthProviders.length !== 0 && (
          <div className="flex flex-col gap-2 items-center justify-center">
            {oauthProviders.map((provider) => (
              <OAuthButton
                key={provider.id}
                title={provider.name}
                icon={iconMap[provider.id] ?? <OAuthIcon />}
                className="w-full"
                onClick={() => oauthMutation.mutate(provider.id)}
                loading={
                  oauthMutation.isPending &&
                  oauthMutation.variables === provider.id
                }
                disabled={oauthMutation.isPending || loginMutation.isPending}
              />
            ))}
          </div>
        )}
        {userAuthConfigured && oauthProviders.length !== 0 && (
          <SeperatorWithChildren>{t("loginDivider")}</SeperatorWithChildren>
        )}
        {userAuthConfigured && (
          <LoginForm
            onSubmit={(values) => loginMutation.mutate(values)}
            loading={loginMutation.isPending || oauthMutation.isPending}
          />
        )}
        {providers.length == 0 && (
          <p className="text-center text-red-600 max-w-sm">
            {t("failedToFetchProvidersTitle")}
          </p>
        )}
      </CardContent>
    </Card>
  );
};

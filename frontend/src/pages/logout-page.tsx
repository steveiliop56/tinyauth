import { Button } from "@/components/ui/button";
import {
  Card,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { useUserContext } from "@/context/user-context";
import { useMutation } from "@tanstack/react-query";
import axios from "axios";
import { useEffect, useRef } from "react";
import { Trans, useTranslation } from "react-i18next";
import { Navigate } from "react-router";
import { toast } from "sonner";

export const LogoutPage = () => {
  const { provider, username, isLoggedIn, email, oauthName } = useUserContext();
  const { t } = useTranslation();

  const redirectTimer = useRef<number | null>(null);

  const logoutMutation = useMutation({
    mutationFn: () => axios.post("/api/user/logout"),
    mutationKey: ["logout"],
    onSuccess: () => {
      toast.success(t("logoutSuccessTitle"), {
        description: t("logoutSuccessSubtitle"),
      });

      redirectTimer.current = window.setTimeout(() => {
        window.location.assign("/login");
      }, 500);
    },
    onError: () => {
      toast.error(t("logoutFailTitle"), {
        description: t("logoutFailSubtitle"),
      });
    },
  });

  useEffect(
    () => () => {
      if (redirectTimer.current) clearTimeout(redirectTimer.current);
    },
    [],
  );

  if (!isLoggedIn) {
    return <Navigate to="/login" replace />;
  }

  return (
    <Card className="min-w-xs sm:min-w-sm">
      <CardHeader>
        <CardTitle className="text-3xl">{t("logoutTitle")}</CardTitle>
        <CardDescription>
          {provider !== "local" && provider !== "ldap" ? (
            <Trans
              i18nKey="logoutOauthSubtitle"
              t={t}
              components={{
                code: <code />,
              }}
              values={{
                username: email,
                provider: oauthName,
              }}
            />
          ) : (
            <Trans
              i18nKey="logoutUsernameSubtitle"
              t={t}
              components={{
                code: <code />,
              }}
              values={{
                username,
              }}
            />
          )}
        </CardDescription>
      </CardHeader>
      <CardFooter className="flex flex-col items-stretch">
        <Button
          loading={logoutMutation.isPending}
          onClick={() => logoutMutation.mutate()}
        >
          {t("logoutTitle")}
        </Button>
      </CardFooter>
    </Card>
  );
};

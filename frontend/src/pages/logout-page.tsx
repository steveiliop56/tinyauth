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
import { capitalize } from "@/lib/utils";
import { useMutation } from "@tanstack/react-query";
import axios from "axios";
import { Trans, useTranslation } from "react-i18next";
import { Navigate } from "react-router";
import { toast } from "sonner";

export const LogoutPage = () => {
  const { provider, username, isLoggedIn, email } = useUserContext();
  const { genericName } = useAppContext();
  const { t } = useTranslation();

  const logoutMutation = useMutation({
    mutationFn: () => axios.post("/api/user/logout"),
    mutationKey: ["logout"],
    onSuccess: () => {
      toast.success(t("logoutSuccessTitle"), {
        description: t("logoutSuccessSubtitle"),
      });

      const redirect = setTimeout(() => {
        window.location.replace("/login");
      }, 500);

      return () => clearTimeout(redirect);
    },
    onError: () => {
      toast.error(t("logoutFailTitle"), {
        description: t("logoutFailSubtitle"),
      });
    },
  });

  if (!isLoggedIn) {
    return <Navigate to="/login" />;
  }

  return (
    <Card className="min-w-xs sm:min-w-sm">
      <CardHeader>
        <CardTitle className="text-3xl">{t("logoutTitle")}</CardTitle>
        <CardDescription>
          {provider !== "username" ? (
            <Trans
              i18nKey="logoutOauthSubtitle"
              t={t}
              components={{
                code: <code />,
              }}
              values={{
                username: email,
                provider:
                  provider === "generic" ? genericName : capitalize(provider),
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

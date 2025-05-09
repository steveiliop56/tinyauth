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
import { Trans, useTranslation } from "react-i18next";
import { Navigate } from "react-router";

export const LogoutPage = () => {
  const { provider, username, email, isLoggedIn } = useUserContext();
  const { genericName } = useAppContext();
  const { t } = useTranslation();

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
                username: username,
              }}
            />
          )}
        </CardDescription>
      </CardHeader>
      <CardFooter className="flex flex-col items-stretch">
        <Button>{t("logoutTitle")}</Button>
      </CardFooter>
    </Card>
  );
};

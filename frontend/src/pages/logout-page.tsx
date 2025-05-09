import { Button } from "@/components/ui/button";
import {
  Card,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Code } from "@/components/ui/code";
import { capitalize } from "@/utils/utils";
import { Trans, useTranslation } from "react-i18next";

export const LogoutPage = () => {
  const { t } = useTranslation();

  const provider = "google";
  const genericName = "generic";
  const username = "username";
  const email = "smbd@example.com";

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
                code: <Code />,
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
                code: <Code />,
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

import { Button } from "@/components/ui/button";
import {
  Card,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { useState } from "react";
import { Trans, useTranslation } from "react-i18next";
import { Navigate, useLocation, useNavigate } from "react-router";

export const UnauthorizedPage = () => {
  const { search } = useLocation();
  const { t } = useTranslation();
  const navigate = useNavigate();

  const [loading, setLoading] = useState(false);

  const searchParams = new URLSearchParams(search);
  const username = searchParams.get("username");
  const resource = searchParams.get("resource");
  const groupErr = searchParams.get("groupErr");
  const ip = searchParams.get("ip");

  const handleRedirect = () => {
    setLoading(true);
    navigate("/login");
  };

  if (!username && !ip) {
    return <Navigate to="/" />;
  }

  let i18nKey = "unauthorizedLoginSubtitle";

  if (resource) {
    i18nKey = "unauthorizedResourceSubtitle";
  }

  if (groupErr === "true") {
    i18nKey = "unauthorizedGroupsSubtitle";
  }

  if (ip) {
    i18nKey = "unauthorizedIpSubtitle";
  }

  return (
    <Card className="min-w-xs">
      <CardHeader className="gap-1.5">
        <CardTitle className="text-xl">{t("unauthorizedTitle")}</CardTitle>
        <CardDescription>
          <Trans
            i18nKey={i18nKey}
            t={t}
            components={{
              code: <code />,
            }}
            values={{
              username,
              resource,
              ip,
            }}
          />
        </CardDescription>
      </CardHeader>
      <CardFooter className="flex flex-col items-stretch">
        <Button onClick={handleRedirect} loading={loading}>
          {t("unauthorizedButton")}
        </Button>
      </CardFooter>
    </Card>
  );
};

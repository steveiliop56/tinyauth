import { Button } from "@/components/ui/button";
import {
  Card,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { useNavigate } from "react-router";

export const NotFoundPage = () => {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const [loading, setLoading] = useState(false);

  const handleRedirect = () => {
    setLoading(true);
    navigate("/");
  };

  return (
    <Card className="min-w-xs">
      <CardHeader className="gap-1.5">
        <CardTitle className="text-xl">{t("notFoundTitle")}</CardTitle>
        <CardDescription>{t("notFoundSubtitle")}</CardDescription>
      </CardHeader>
      <CardFooter className="flex flex-col items-stretch">
        <Button onClick={handleRedirect} loading={loading}>
          {t("notFoundButton")}
        </Button>
      </CardFooter>
    </Card>
  );
};

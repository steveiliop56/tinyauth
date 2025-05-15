import { Button } from "@/components/ui/button";
import {
  Card,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { useTranslation } from "react-i18next";
import { useNavigate } from "react-router";

export const NotFoundPage = () => {
  const { t } = useTranslation();
  const navigate = useNavigate();

  return (
    <Card className="min-w-xs sm:min-w-sm">
      <CardHeader>
        <CardTitle className="text-3xl">{t("notFoundTitle")}</CardTitle>
        <CardDescription>{t("notFoundSubtitle")}</CardDescription>
      </CardHeader>
      <CardFooter className="flex flex-col items-stretch">
        <Button onClick={() => navigate("/")}>{t("notFoundButton")}</Button>
      </CardFooter>
    </Card>
  );
};

import {
  Card,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { useTranslation } from "react-i18next";

export const ErrorPage = () => {
  const { t } = useTranslation();

  return (
    <Card className="min-w-xs md:max-w-sm">
      <CardHeader>
        <CardTitle className="text-3xl">{t("errorTitle")}</CardTitle>
        <CardDescription>{t("errorSubtitle")}</CardDescription>
      </CardHeader>
    </Card>
  );
};

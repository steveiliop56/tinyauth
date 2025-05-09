import {
  Card,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { useTranslation } from "react-i18next";
import Markdown from "react-markdown";

export const ForgotPasswordPage = () => {
  const { t } = useTranslation();

  return (
    <Card className="min-w-xs sm:min-w-sm">
      <CardHeader>
        <CardTitle className="text-3xl">{t("forgotPasswordTitle")}</CardTitle>
        <CardDescription>
          <Markdown>
            You can reset your password by changing the `USERS` environment
            variable.
          </Markdown>
        </CardDescription>
      </CardHeader>
    </Card>
  );
};

import {
  Card,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { useAppContext } from "@/context/app-context";
import { useTranslation } from "react-i18next";
import Markdown from "react-markdown";

export const ForgotPasswordPage = () => {
  const { forgotPasswordMessage } = useAppContext();
  const { t } = useTranslation();

  return (
    <Card className="min-w-xs sm:min-w-sm">
      <CardHeader>
        <CardTitle className="text-3xl">{t("forgotPasswordTitle")}</CardTitle>
        <CardDescription>
          <Markdown>{forgotPasswordMessage !== "" ? forgotPasswordMessage : t('forgotPasswordMessage')}</Markdown>
        </CardDescription>
      </CardHeader>
    </Card>
  );
};

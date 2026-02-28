import {
  Card,
  CardContent,
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
    <Card>
      <CardHeader>
        <CardTitle className="text-xl">{t("forgotPasswordTitle")}</CardTitle>
      </CardHeader>
      <CardContent>
        <CardDescription>
          <Markdown>
            {forgotPasswordMessage !== ""
              ? forgotPasswordMessage
              : t("forgotPasswordMessage")}
          </Markdown>
        </CardDescription>
      </CardContent>
    </Card>
  );
};

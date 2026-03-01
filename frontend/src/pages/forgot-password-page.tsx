import {
  Card,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { useAppContext } from "@/context/app-context";
import { useTranslation } from "react-i18next";
import Markdown from "react-markdown";
import { useNavigate } from "react-router";

export const ForgotPasswordPage = () => {
  const { forgotPasswordMessage } = useAppContext();
  const { t } = useTranslation();
  const navigate = useNavigate();

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
      <CardFooter>
        <Button
          className="w-full"
          variant="outline"
          onClick={() => {
            navigate("/login");
          }}
        >
          {t("notFoundButton")}
        </Button>
      </CardFooter>
    </Card>
  );
};

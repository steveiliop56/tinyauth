import { FormValues, TotpForm } from "@/components/auth/totp-form";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { useId } from "react";
import { useTranslation } from "react-i18next";

export const TotpPage = () => {
  const { t } = useTranslation();
  const formId = useId();

  const onSubmit = (data: FormValues) => {
    console.log("TOTP data:", data);
  };

  return (
    <Card className="min-w-xs md:max-w-sm">
      <CardHeader>
        <CardTitle className="text-3xl">{t("totpTitle")}</CardTitle>
        <CardDescription>{t("totpSubtitle")}</CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col items-center">
        <TotpForm formId={formId} onSubmit={onSubmit} />
      </CardContent>
      <CardFooter className="flex flex-col items-stretch">
        <Button form={formId} type="submit">
          {t("continueTitle")}
        </Button>
      </CardFooter>
    </Card>
  );
};

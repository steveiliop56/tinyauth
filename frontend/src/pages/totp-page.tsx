import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import {
  InputOTP,
  InputOTPGroup,
  InputOTPSeparator,
  InputOTPSlot,
} from "@/components/ui/input-otp";
import { useTranslation } from "react-i18next";

export const TotpPage = () => {
  const { t } = useTranslation();

  return (
    <Card className="min-w-xs md:max-w-sm">
      <CardHeader>
        <CardTitle className="text-3xl">{t("totpTitle")}</CardTitle>
        <CardDescription>{t("totpSubtitle")}</CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-6 items-stretch">
        <InputOTP maxLength={6}>
          <InputOTPGroup>
            <InputOTPSlot index={0} />
            <InputOTPSlot index={1} />
            <InputOTPSlot index={2} />
          </InputOTPGroup>
          <InputOTPSeparator />
          <InputOTPGroup>
            <InputOTPSlot index={3} />
            <InputOTPSlot index={4} />
            <InputOTPSlot index={5} />
          </InputOTPGroup>
        </InputOTP>
        <Button>{t("continueTitle")}</Button>
      </CardContent>
    </Card>
  );
};

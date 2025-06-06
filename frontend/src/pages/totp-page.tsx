import { TotpForm } from "@/components/auth/totp-form";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { useUserContext } from "@/context/user-context";
import { TotpSchema } from "@/schemas/totp-schema";
import { useMutation } from "@tanstack/react-query";
import axios from "axios";
import { useId } from "react";
import { useTranslation } from "react-i18next";
import { Navigate, useLocation } from "react-router";
import { toast } from "sonner";

export const TotpPage = () => {
  const { totpPending } = useUserContext();

  if (!totpPending) {
    return <Navigate to="/" />;
  }

  const { t } = useTranslation();
  const { search } = useLocation();
  const formId = useId();

  const searchParams = new URLSearchParams(search);
  const redirectUri = searchParams.get("redirect_uri");

  const totpMutation = useMutation({
    mutationFn: (values: TotpSchema) => axios.post("/api/totp", values),
    mutationKey: ["totp"],
    onSuccess: () => {
      toast.success(t("totpSuccessTitle"), {
        description: t("totpSuccessSubtitle"),
      });

      setTimeout(() => {
        window.location.replace(
          `/continue?redirect_uri=${encodeURIComponent(redirectUri ?? "")}`,
        );
      }, 500);
    },
    onError: () => {
      toast.error(t("totpFailTitle"), {
        description: t("totpFailSubtitle"),
      });
    },
  });

  return (
    <Card className="min-w-xs sm:min-w-sm">
      <CardHeader>
        <CardTitle className="text-3xl">{t("totpTitle")}</CardTitle>
        <CardDescription>{t("totpSubtitle")}</CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col items-center">
        <TotpForm
          formId={formId}
          onSubmit={(values) => totpMutation.mutate(values)}
          loading={totpMutation.isPending}
        />
      </CardContent>
      <CardFooter className="flex flex-col items-stretch">
        <Button form={formId} type="submit" loading={totpMutation.isPending}>
          {t("continueTitle")}
        </Button>
      </CardFooter>
    </Card>
  );
};

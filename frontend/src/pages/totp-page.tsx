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
import { useEffect, useId, useRef } from "react";
import { useTranslation } from "react-i18next";
import { Navigate, useLocation } from "react-router";
import { toast } from "sonner";
import { useOIDCParams } from "@/lib/hooks/oidc";

export const TotpPage = () => {
  const { totpPending } = useUserContext();
  const { t } = useTranslation();
  const { search } = useLocation();
  const formId = useId();

  const redirectTimer = useRef<number | null>(null);

  const searchParams = new URLSearchParams(search);
  const {
    values: props,
    isOidc,
    compiled: compiledOIDCParams,
  } = useOIDCParams(searchParams);

  const totpMutation = useMutation({
    mutationFn: (values: TotpSchema) => axios.post("/api/user/totp", values),
    mutationKey: ["totp"],
    onSuccess: () => {
      toast.success(t("totpSuccessTitle"), {
        description: t("totpSuccessSubtitle"),
      });

      redirectTimer.current = window.setTimeout(() => {
        if (isOidc) {
          window.location.replace(`/authorize?${compiledOIDCParams}`);
          return;
        } else {
          window.location.replace(
            `/continue?redirect_uri=${encodeURIComponent(props.redirect_uri)}`,
          );
        }
      }, 500);
    },
    onError: () => {
      toast.error(t("totpFailTitle"), {
        description: t("totpFailSubtitle"),
      });
    },
  });

  useEffect(
    () => () => {
      if (redirectTimer.current) clearTimeout(redirectTimer.current);
    },
    [],
  );

  if (!totpPending) {
    return <Navigate to="/" replace />;
  }

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

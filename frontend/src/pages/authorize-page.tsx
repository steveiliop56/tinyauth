import { useUserContext } from "@/context/user-context";
import { useMutation, useQuery } from "@tanstack/react-query";
import { Navigate, useNavigate } from "react-router";
import { useLocation } from "react-router";
import {
  Card,
  CardHeader,
  CardTitle,
  CardDescription,
  CardFooter,
} from "@/components/ui/card";
import { getOidcClientInfoScehma } from "@/schemas/oidc-schemas";
import { Button } from "@/components/ui/button";
import axios from "axios";
import { toast } from "sonner";
import { useOIDCParams } from "@/lib/hooks/oidc";
import { useTranslation } from "react-i18next";

export const AuthorizePage = () => {
  const { isLoggedIn } = useUserContext();
  const { search } = useLocation();
  const { t } = useTranslation();
  const navigate = useNavigate();

  const searchParams = new URLSearchParams(search);
  const {
    values: props,
    missingParams,
    isOidc,
    compiled: compiledOIDCParams,
  } = useOIDCParams(searchParams);

  const getClientInfo = useQuery({
    queryKey: ["client", props.client_id],
    queryFn: async () => {
      const res = await fetch(`/api/oidc/clients/${props.client_id}`);
      const data = await getOidcClientInfoScehma.parseAsync(await res.json());
      return data;
    },
    enabled: isOidc,
  });

  const authorizeMutation = useMutation({
    mutationFn: () => {
      return axios.post("/api/oidc/authorize", {
        scope: props.scope,
        response_type: props.response_type,
        client_id: props.client_id,
        redirect_uri: props.redirect_uri,
        state: props.state,
      });
    },
    mutationKey: ["authorize", props.client_id],
    onSuccess: (data) => {
      toast.info(t("authorizeSuccessTitle"), {
        description: t("authorizeSuccessSubtitle"),
      });
      window.location.replace(data.data.redirect_uri);
    },
    onError: (error) => {
      window.location.replace(
        `/error?error=${encodeURIComponent(error.message)}`,
      );
    },
  });

  if (!isLoggedIn) {
    return <Navigate to={`/login?${compiledOIDCParams}`} replace />;
  }

  if (missingParams.length > 0) {
    return (
      <Navigate
        to={`/error?error=${encodeURIComponent(`Missing parameters: ${missingParams.join(", ")}`)}`}
        replace
      />
    );
  }

  if (getClientInfo.isLoading) {
    return (
      <Card className="min-w-xs sm:min-w-sm">
        <CardHeader>
          <CardTitle className="text-3xl">
            {t("authorizeLoadingTitle")}
          </CardTitle>
          <CardDescription>{t("authorizeLoadingSubtitle")}</CardDescription>
        </CardHeader>
      </Card>
    );
  }

  if (getClientInfo.isError) {
    return (
      <Navigate
        to={`/error?error=${encodeURIComponent(`Failed to load client information`)}`}
        replace
      />
    );
  }

  return (
    <Card className="min-w-xs sm:min-w-sm">
      <CardHeader>
        <CardTitle className="text-3xl">
          {t("authorizeCardTitle", {
            app: getClientInfo.data?.name || "Unknown",
          })}
        </CardTitle>
        <CardDescription>{t("authorizeSubtitle")}</CardDescription>
      </CardHeader>
      <CardFooter className="flex flex-col items-stretch gap-2">
        <Button
          onClick={() => authorizeMutation.mutate()}
          loading={authorizeMutation.isPending}
        >
          {t("authorizeTitle")}
        </Button>
        <Button
          onClick={() => navigate("/")}
          disabled={authorizeMutation.isPending}
          variant="outline"
        >
          {t("cancelTitle")}
        </Button>
      </CardFooter>
    </Card>
  );
};

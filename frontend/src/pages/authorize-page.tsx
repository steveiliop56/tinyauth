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
  CardContent,
} from "@/components/ui/card";
import { getOidcClientInfoSchema } from "@/schemas/oidc-schemas";
import { Button } from "@/components/ui/button";
import axios from "axios";
import { toast } from "sonner";
import { useOIDCParams } from "@/lib/hooks/oidc";
import { useTranslation } from "react-i18next";
import { TFunction } from "i18next";
import { Mail, Shield, User, Users } from "lucide-react";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip";

type Scope = {
  id: string;
  name: string;
  description: string;
  icon: React.ReactNode;
};

const scopeMapIconProps = {
  className: "stroke-muted-foreground stroke-[1.75] h-4",
};

const createScopeMap = (t: TFunction<"translation", undefined>): Scope[] => {
  return [
    {
      id: "openid",
      name: t("openidScopeName"),
      description: t("openidScopeDescription"),
      icon: <Shield {...scopeMapIconProps} />,
    },
    {
      id: "email",
      name: t("emailScopeName"),
      description: t("emailScopeDescription"),
      icon: <Mail {...scopeMapIconProps} />,
    },
    {
      id: "profile",
      name: t("profileScopeName"),
      description: t("profileScopeDescription"),
      icon: <User {...scopeMapIconProps} />,
    },
    {
      id: "groups",
      name: t("groupsScopeName"),
      description: t("groupsScopeDescription"),
      icon: <Users {...scopeMapIconProps} />,
    },
  ];
};

export const AuthorizePage = () => {
  const { isLoggedIn } = useUserContext();
  const { search } = useLocation();
  const { t } = useTranslation();
  const navigate = useNavigate();
  const scopeMap = createScopeMap(t);

  const searchParams = new URLSearchParams(search);
  const {
    values: props,
    missingParams,
    isOidc,
    compiled: compiledOIDCParams,
  } = useOIDCParams(searchParams);
  const scopes = props.scope ? props.scope.split(" ").filter(Boolean) : [];

  const getClientInfo = useQuery({
    queryKey: ["client", props.client_id],
    queryFn: async () => {
      const res = await fetch(`/api/oidc/clients/${props.client_id}`);
      const data = await getOidcClientInfoSchema.parseAsync(await res.json());
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

  if (missingParams.length > 0) {
    return (
      <Navigate
        to={`/error?error=${encodeURIComponent(t("authorizeErrorMissingParams", { missingParams: missingParams.join(", ") }))}`}
        replace
      />
    );
  }

  if (!isLoggedIn) {
    return <Navigate to={`/login?${compiledOIDCParams}`} replace />;
  }

  if (getClientInfo.isLoading) {
    return (
      <Card className="gap-0">
        <CardHeader>
          <CardTitle className="text-xl">
            {t("authorizeLoadingTitle")}
          </CardTitle>
        </CardHeader>
        <CardContent>
          <CardDescription>{t("authorizeLoadingSubtitle")}</CardDescription>
        </CardContent>
      </Card>
    );
  }

  if (getClientInfo.isError) {
    return (
      <Navigate
        to={`/error?error=${encodeURIComponent(t("authorizeErrorClientInfo"))}`}
        replace
      />
    );
  }

  return (
    <Card>
      <CardHeader className="mb-2">
        <div className="flex flex-col gap-3 items-center justify-center">
          <div className="bg-accent-foreground text-muted text-xl font-bold font-sans rounded-lg px-4 py-3">
            {getClientInfo.data?.name.slice(0, 1)}
          </div>
          <CardTitle className="text-xl">
            {t("authorizeCardTitle", {
              app: getClientInfo.data?.name || "Unknown",
            })}
          </CardTitle>
          <CardDescription className="text-sm max-w-sm text-center">
            {scopes.includes("openid")
              ? t("authorizeSubtitle")
              : t("authorizeSubtitleOAuth")}
          </CardDescription>
        </div>
      </CardHeader>
      <CardContent className="mb-2">
        {scopes.includes("openid") && (
          <div className="flex flex-wrap gap-2 items-center justify-center">
            {scopes.map((id) => {
              const scope = scopeMap.find((s) => s.id === id);
              if (!scope) return null;
              return (
                <Tooltip key={scope.id}>
                  <TooltipTrigger className="flex flex-row justify-center items-center gap-1 rounded-full bg-secondary font-light pl-2 pr-4 py-1 border-border border">
                    <div>{scope.icon}</div>
                    <div className="text-sm text-accent-foreground">
                      {scope.name}
                    </div>
                  </TooltipTrigger>
                  <TooltipContent>{scope.description}</TooltipContent>
                </Tooltip>
              );
            })}
          </div>
        )}
      </CardContent>
      <CardFooter className="flex flex-col items-stretch gap-3">
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

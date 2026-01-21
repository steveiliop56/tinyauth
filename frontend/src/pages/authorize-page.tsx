import { useUserContext } from "@/context/user-context";
import { useQuery } from "@tanstack/react-query";
import { Navigate } from "react-router";
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

type AuthorizePageProps = {
  scope: string;
  responseType: string;
  clientId: string;
  redirectUri: string;
  state: string;
};

const optionalAuthorizeProps = ["state"];

export const AuthorizePage = () => {
  const { isLoggedIn } = useUserContext();
  const { search } = useLocation();

  const searchParams = new URLSearchParams(search);

  // If there is a better way to do this, please do let me know
  const props: AuthorizePageProps = {
    scope: searchParams.get("scope") || "",
    responseType: searchParams.get("response_type") || "",
    clientId: searchParams.get("client_id") || "",
    redirectUri: searchParams.get("redirect_uri") || "",
    state: searchParams.get("state") || "",
  };

  const getClientInfo = useQuery({
    queryKey: ["client", props.clientId],
    queryFn: async () => {
      const res = await fetch(`/api/oidc/clients/${props.clientId}`);
      const data = await getOidcClientInfoScehma.parseAsync(await res.json());
      return data;
    },
  });

  if (!isLoggedIn) {
    // TODO: Pass the params to the login page, so user can login -> authorize
    return <Navigate to="/login" replace />;
  }

  for (const key in Object.keys(props)) {
    if (
      !props[key as keyof AuthorizePageProps] &&
      !optionalAuthorizeProps.includes(key)
    ) {
      // TODO: Add reason for error
      return <Navigate to="/error" replace />;
    }
  }

  if (getClientInfo.isLoading) {
    return (
      <Card className="min-w-xs sm:min-w-sm">
        <CardHeader>
          <CardTitle className="text-3xl">Loading...</CardTitle>
          <CardDescription>
            Please wait while we load the client information.
          </CardDescription>
        </CardHeader>
      </Card>
    );
  }

  if (getClientInfo.isError) {
    // TODO: Add reason for error
    return <Navigate to="/error" replace />;
  }

  return (
    <Card className="min-w-xs sm:min-w-sm">
      <CardHeader>
        <CardTitle className="text-3xl">
          Continue to {getClientInfo.data?.name || "Unknown"}?
        </CardTitle>
        <CardDescription>
          Would you like to continue to this app? Please keep in mind that this
          app will have access to your email and other information.
        </CardDescription>
      </CardHeader>
      <CardFooter className="flex flex-col items-stretch gap-2">
        <Button>Authorize</Button>
        <Button variant="outline">Cancel</Button>
      </CardFooter>
    </Card>
  );
};

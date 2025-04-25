import { useEffect } from "react"; // <--- Added Import
import { Paper, Title, Text, Divider, Loader, Center } from "@mantine/core"; // <--- Added Loader, Center
import { notifications } from "@mantine/notifications";
import { useMutation } from "@tanstack/react-query";
import axios, { type AxiosError, type AxiosResponse } from "axios"; // <--- Added AxiosResponse (optional but good practice)
import { useUserContext } from "../context/user-context";
import { Navigate } from "react-router";
import { Layout } from "../components/layouts/layout";
import { OAuthButtons } from "../components/auth/oauth-buttons";
import { LoginFormValues } from "../schemas/login-schema";
import { LoginForm } from "../components/auth/login-forn";
import { isQueryValid } from "../utils/utils";
import { useAppContext } from "../context/app-context";
import { useTranslation } from "react-i18next";

export const LoginPage = () => {
  const queryString = window.location.search;
  const params = new URLSearchParams(queryString);
  const redirectUri = params.get("redirect_uri") ?? "";

  const { isLoggedIn } = useUserContext();
  // Destructure autoOidcLogin from context (assuming context provider/schema fixed)
  const { configuredProviders, title, genericName, autoOidcLogin } = useAppContext();
  const { t } = useTranslation();

  const oauthProviders = configuredProviders.filter(
    (value) => value !== "username",
  );

  // Define loginOAuthMutation before useEffect
  // Explicitly typed for clarity (Optional, but can help prevent errors)
  const loginOAuthMutation = useMutation<
    AxiosResponse, // Success response type
    AxiosError,    // Error type
    string         // Type of variable passed to mutate (provider name)
   >({
    mutationFn: (provider: string) => {
      // Ensure redirectUri is included if present and encode it
      const apiUrl = redirectUri
         ? `/api/oauth/url/${provider}?redirect_uri=${encodeURIComponent(redirectUri)}`
         : `/api/oauth/url/${provider}`;
      return axios.get(apiUrl);
    },
    onError: () => {
      notifications.show({
        title: t("loginOauthFailTitle"),
        message: t("loginOauthFailSubtitle"),
        color: "red",
      });
      // Consider adding state to show an error message instead of loader if redirect fails
    },
    onSuccess: (data) => {
      // Check if data.data.url exists before redirecting
      if (data?.data?.url) {
          notifications.show({
            title: t("loginOauthSuccessTitle"),
            message: t("loginOauthSuccessSubtitle"),
            color: "blue",
          });
          // Consider removing setTimeout if you want instant redirect
          setTimeout(() => {
            window.location.href = data.data.url;
          }, 500);
      } else {
          // Handle case where URL is missing in response
           notifications.show({
             title: t("loginOauthFailTitle"),
             message: "OAuth URL missing in response.", // Or a translated message
             color: "red",
           });
      }
    },
  });

  // --- ADD useEffect FOR AUTO REDIRECT ---
  useEffect(() => {
    // Don't run if already logged in (context is loaded due to Suspense)
    if (isLoggedIn) {
      return;
    }

    // Check conditions for auto-redirect
    // Ensure configuredProviders and autoOidcLogin are available (they should be due to Suspense)
    const oidcProvidersForCheck = configuredProviders?.filter(p => p !== 'username') ?? []; // Add nullish coalescing for safety
    if (autoOidcLogin === true && oidcProvidersForCheck.length === 1) {
      const providerToRedirect = oidcProvidersForCheck[0];
      // Check if mutation is not already running to prevent loops
      if (!loginOAuthMutation.isPending) {
         console.log(`Auto OIDC Login enabled with single provider: ${providerToRedirect}. Triggering redirect...`);
         loginOAuthMutation.mutate(providerToRedirect);
      }
    }
    // Add dependencies: run when these values change (or on initial load after Suspense)
    // Note: loginOAuthMutation object itself is stable, mutate function reference is stable
  }, [autoOidcLogin, configuredProviders, isLoggedIn, loginOAuthMutation.mutate, loginOAuthMutation.isPending]);
  // --- END useEffect ---


  if (isLoggedIn) {
    // Already logged in, redirect away from login page
    return <Navigate to="/logout" />; // Or maybe "/" or "/continue?redirect_uri=..."
  }

  // --- Optional: Loading state while auto-redirect mutation is pending ---
  // Show loader only if the mutation is running AND it was likely triggered by auto-login logic
  const shouldShowLoader = loginOAuthMutation.isPending && (autoOidcLogin === true && oauthProviders.length === 1);
  if (shouldShowLoader) {
      return (
          <Layout>
               <Center style={{ height: '200px' }}>
                  <Loader />
                  {/* Optionally add text like "Redirecting to login..." */}
               </Center>
          </Layout>
      );
  }
  // --- End Optional Loading State ---


  // Mutation hook for username/password login
  const loginMutation = useMutation<
    AxiosResponse,      // Type of data expected on success
    AxiosError,         // Type of error expected on failure
    LoginFormValues     // Type of variables passed to mutationFn
  >({
    mutationFn: (login: LoginFormValues) => {
      return axios.post("/api/login", login);
    },
    onError: (error: AxiosError) => { // Changed variable name from data to error
      if (error.response) {
        if (error.response.status === 429) {
          notifications.show({
            title: t("loginFailTitle"),
            message: t("loginFailRateLimit"),
            color: "red",
          });
          return;
        }
      }
      notifications.show({
        title: t("loginFailTitle"),
        message: t("loginFailSubtitle"),
        color: "red",
      });
    },
    onSuccess: async (data: AxiosResponse) => { // Ensure data is AxiosResponse
      // Check the actual data structure from your API
      // It's likely nested under `data.data`
      if (data?.data?.totpPending) {
        window.location.replace(`/totp?redirect_uri=${redirectUri}`);
        return;
      }

      notifications.show({
        title: t("loginSuccessTitle"),
        message: t("loginSuccessSubtitle"),
        color: "green",
      });

      setTimeout(() => {
        if (!isQueryValid(redirectUri)) {
          window.location.replace("/");
          return;
        }
        window.location.replace(`/continue?redirect_uri=${redirectUri}`);
      }, 500);
    },
  });

  // Handler for the username/password form submission
  const handleSubmit = (values: LoginFormValues) => {
    loginMutation.mutate(values);
  };

  // Render the login page options if not auto-redirecting/loading
  return (
    <Layout>
      <Title ta="center">{title}</Title>
      <Paper shadow="md" p="xl" mt={30} radius="md" withBorder>
        {/* Render OAuth buttons only if there are OAuth providers */}
        {oauthProviders.length > 0 && (
          <>
            <Text size="lg" fw={500} ta="center">
              {t("loginTitle")}
            </Text>
            <OAuthButtons
              oauthProviders={oauthProviders}
              isPending={loginOAuthMutation.isPending}
              mutate={loginOAuthMutation.mutate}
              genericName={genericName}
            />
            {/* Show divider only if both OAuth and username options are available */}
            {configuredProviders.includes("username") && (
              <Divider
                label={t("loginDivider")}
                labelPosition="center"
                my="lg"
              />
            )}
          </>
        )}
        {/* Render Login form only if username provider is configured */}
        {configuredProviders.includes("username") && (
          <LoginForm
            isPending={loginMutation.isPending}
            onSubmit={handleSubmit} // Pass the handler here
          />
        )}
      </Paper>
    </Layout>
  );
};
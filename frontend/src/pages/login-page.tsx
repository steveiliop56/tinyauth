import { Paper, Title, Text, Divider } from "@mantine/core";
import { notifications } from "@mantine/notifications";
import { useMutation } from "@tanstack/react-query";
import axios, { type AxiosError } from "axios";
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
  const { configuredProviders, title, genericName } = useAppContext();
  const { t } = useTranslation();

  const oauthProviders = configuredProviders.filter(
    (value) => value !== "username",
  );

  if (isLoggedIn) {
    return <Navigate to="/logout" />;
  }

  const loginMutation = useMutation({
    mutationFn: (login: LoginFormValues) => {
      return axios.post("/api/login", login);
    },
    onError: (data: AxiosError) => {
      if (data.response) {
        if (data.response.status === 429) {
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
    onSuccess: async (data) => {
      if (data.data.totpPending) {
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

  const loginOAuthMutation = useMutation({
    mutationFn: (provider: string) => {
      return axios.get(
        `/api/oauth/url/${provider}?redirect_uri=${redirectUri}`,
      );
    },
    onError: () => {
      notifications.show({
        title: t("loginOauthFailTitle"),
        message: t("loginOauthFailSubtitle"),
        color: "red",
      });
    },
    onSuccess: (data) => {
      notifications.show({
        title: t("loginOauthSuccessTitle"),
        message: t("loginOauthSuccessSubtitle"),
        color: "blue",
      });
      setTimeout(() => {
        window.location.href = data.data.url;
      }, 500);
    },
  });

  const handleSubmit = (values: LoginFormValues) => {
    loginMutation.mutate(values);
  };

  return (
    <Layout>
      <Title ta="center">{title}</Title>
      <Paper shadow="md" p="xl" mt={30} radius="md" withBorder>
        {oauthProviders.length > 0 && (
          <>
            <Text size="lg" fw={500} ta="center">
              {t("loginTitle")}
            </Text>
            <OAuthButtons
              oauthProviders={oauthProviders}
              isLoading={loginOAuthMutation.isLoading}
              mutate={loginOAuthMutation.mutate}
              genericName={genericName}
            />
            {configuredProviders.includes("username") && (
              <Divider
                label={t("loginDivider")}
                labelPosition="center"
                my="lg"
              />
            )}
          </>
        )}
        {configuredProviders.includes("username") && (
          <LoginForm
            isLoading={loginMutation.isLoading}
            onSubmit={handleSubmit}
          />
        )}
      </Paper>
    </Layout>
  );
};

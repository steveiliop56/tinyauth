import { Button, Code, Paper, Text } from "@mantine/core";
import { notifications } from "@mantine/notifications";
import { useMutation } from "@tanstack/react-query";
import axios from "axios";
import { useUserContext } from "../context/user-context";
import { Navigate } from "react-router";
import { Layout } from "../components/layouts/layout";
import { capitalize } from "../utils/utils";
import { useAppContext } from "../context/app-context";
import { Trans, useTranslation } from "react-i18next";

export const LogoutPage = () => {
  const { isLoggedIn, oauth, provider, email, username } = useUserContext();
  const { genericName } = useAppContext();
  const { t } = useTranslation();

  if (!isLoggedIn) {
    return <Navigate to="/login" />;
  }

  const logoutMutation = useMutation({
    mutationFn: () => {
      return axios.post("/api/logout");
    },
    onError: () => {
      notifications.show({
        title: t("logoutFailTitle"),
        message: t("logoutFailSubtitle"),
        color: "red",
      });
    },
    onSuccess: () => {
      notifications.show({
        title: t("logoutSuccessTitle"),
        message: t("logoutSuccessSubtitle"),
        color: "green",
      });
      setTimeout(() => {
        window.location.replace("/login");
      }, 500);
    },
  });

  return (
    <Layout>
      <Paper shadow="md" p={30} mt={30} radius="md" withBorder>
        <Text size="xl" fw={700}>
          {t("logoutTitle")}
        </Text>
        <Text>
          {oauth ? (
            <Trans
              i18nKey="logoutOauthSubtitle"
              t={t}
              components={{ Code: <Code /> }}
              values={{
                provider:
                  provider === "generic" ? genericName : capitalize(provider),
                username: email,
              }}
            />
          ) : (
            <Trans
              i18nKey="logoutUsernameSubtitle"
              t={t}
              components={{ Code: <Code /> }}
              values={{
                username: username,
              }}
            />
          )}
        </Text>
        <Button
          fullWidth
          mt="xl"
          onClick={() => logoutMutation.mutate()}
          loading={logoutMutation.isPending}
        >
          {t("logoutTitle")}
        </Button>
      </Paper>
    </Layout>
  );
};

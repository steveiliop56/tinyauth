import { Navigate } from "react-router";
import { useUserContext } from "../context/user-context";
import { Title, Paper, Text } from "@mantine/core";
import { Layout } from "../components/layouts/layout";
import { TotpForm } from "../components/auth/totp-form";
import { useMutation } from "@tanstack/react-query";
import axios from "axios";
import { notifications } from "@mantine/notifications";
import { useAppContext } from "../context/app-context";
import { useTranslation } from "react-i18next";

export const TotpPage = () => {
  const queryString = window.location.search;
  const params = new URLSearchParams(queryString);
  const redirectUri = params.get("redirect_uri") ?? "";

  const { totpPending, isLoggedIn } = useUserContext();
  const { title } = useAppContext();
  const { t } = useTranslation();

  if (isLoggedIn) {
    return <Navigate to={`/logout`} />;
  }

  if (!totpPending) {
    return <Navigate to={`/login?redirect_uri=${redirectUri}`} />;
  }

  const totpMutation = useMutation({
    mutationFn: async (totp: { code: string }) => {
      await axios.post("/api/totp", totp);
    },
    onError: () => {
      notifications.show({
        title: t("totpFailTitle"),
        message: t("totpFailSubtitle"),
        color: "red",
      });
    },
    onSuccess: () => {
      notifications.show({
        title: t("totpSuccessTitle"),
        message: t("totpSuccessSubtitle"),
        color: "green",
      });
      setTimeout(() => {
        window.location.replace(`/continue?redirect_uri=${redirectUri}`);
      }, 500);
    },
  });

  return (
    <Layout>
      <Title ta="center">{title}</Title>
      <Paper shadow="md" p="xl" mt={30} radius="md" withBorder>
        <Text size="lg" fw={500} mb="md" ta="center">
          {t("totpTitle")}
        </Text>
        <TotpForm
          isPending={totpMutation.isPending}
          onSubmit={(values) => totpMutation.mutate(values)}
        />
      </Paper>
    </Layout>
  );
};

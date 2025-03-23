import { Button, Code, Paper, Text } from "@mantine/core";
import { notifications } from "@mantine/notifications";
import { Navigate } from "react-router";
import { useUserContext } from "../context/user-context";
import { Layout } from "../components/layouts/layout";
import { ReactNode } from "react";
import { isQueryValid } from "../utils/utils";
import { useAppContext } from "../context/app-context";
import { Trans, useTranslation } from "react-i18next";

export const ContinuePage = () => {
  const queryString = window.location.search;
  const params = new URLSearchParams(queryString);
  const redirectUri = params.get("redirect_uri") ?? "";

  const { isLoggedIn } = useUserContext();
  const { disableContinue } = useAppContext();
  const { t } = useTranslation();

  if (!isLoggedIn) {
    return <Navigate to={`/login?redirect_uri=${redirectUri}`} />;
  }

  if (!isQueryValid(redirectUri)) {
    return <Navigate to="/" />;
  }

  const redirect = () => {
    notifications.show({
      title: t("continueRedirectingTitle"),
      message: t("continueRedirectingSubtitle"),
      color: "blue",
    });
    setTimeout(() => {
      window.location.href = redirectUri;
    }, 500);
  };

  let uri;

  try {
    uri = new URL(redirectUri);
  } catch {
    return (
      <ContinuePageLayout>
        <Text size="xl" fw={700}>
          {t("Invalid redirect")}
        </Text>
        <Text>{t("The redirect URL is invalid")}</Text>
      </ContinuePageLayout>
    );
  }

  if (disableContinue) {
    window.location.href = redirectUri;
    return (
      <ContinuePageLayout>
        <Text size="xl" fw={700}>
          {t("continueRedirectingTitle")}
        </Text>
        <Text>{t("continueRedirectingSubtitle")}</Text>
      </ContinuePageLayout>
    );
  }

  if (window.location.protocol === "https:" && uri.protocol === "http:") {
    return (
      <ContinuePageLayout>
        <Text size="xl" fw={700}>
          {t("continueInsecureRedirectTitle")}
        </Text>
        <Text>
          <Trans
            i18nKey="continueInsecureRedirectSubtitle"
            t={t}
            components={{ Code: <Code /> }}
          />
        </Text>
        <Button fullWidth mt="xl" color="yellow" onClick={redirect}>
          {t("continueTitle")}
        </Button>
      </ContinuePageLayout>
    );
  }

  return (
    <ContinuePageLayout>
      <Text size="xl" fw={700}>
        {t("continueTitle")}
      </Text>
      <Text>{t("continueSubtitle")}</Text>
      <Button fullWidth mt="xl" onClick={redirect}>
        {t("continueTitle")}
      </Button>
    </ContinuePageLayout>
  );
};

export const ContinuePageLayout = ({ children }: { children: ReactNode }) => {
  return (
    <Layout>
      <Paper shadow="md" p={30} mt={30} radius="md" withBorder>
        {children}
      </Paper>
    </Layout>
  );
};

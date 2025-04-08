import { Button, Code, Paper, Text } from "@mantine/core";
import { Layout } from "../components/layouts/layout";
import { Navigate } from "react-router";
import { isQueryValid } from "../utils/utils";
import { Trans, useTranslation } from "react-i18next";

export const UnauthorizedPage = () => {
  const queryString = window.location.search;
  const params = new URLSearchParams(queryString);
  const username = params.get("username") ?? "";
  const resource = params.get("resource") ?? "";

  const { t } = useTranslation();

  if (!isQueryValid(username)) {
    return <Navigate to="/" />;
  }

  return (
    <Layout>
      <Paper shadow="md" p={30} mt={30} radius="md" withBorder>
        <Text size="xl" fw={700}>
          {t("Unauthorized")}
        </Text>
        <Text>
          {isQueryValid(resource) ? (
            <Text>
              <Trans
                i18nKey="unauthorizedResourceSubtitle"
                t={t}
                components={{ Code: <Code /> }}
                values={{ resource, username }}
              />
            </Text>
          ) : (
            <Text>
              <Trans
                i18nKey="unauthorizedLoginSubtitle"
                t={t}
                components={{ Code: <Code /> }}
                values={{ username }}
              />
            </Text>
          )}
        </Text>
        <Button
          fullWidth
          mt="xl"
          onClick={() => window.location.replace("/login")}
        >
          {t("unauthorizedButton")}
        </Button>
      </Paper>
    </Layout>
  );
};

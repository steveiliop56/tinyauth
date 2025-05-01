import { Button, Code, Paper, Text } from "@mantine/core";
import { Layout } from "../components/layouts/layout";
import { Navigate } from "react-router";
import { Trans, useTranslation } from "react-i18next";
import React from "react";
import { isValidQuery } from "../utils/utils";

export const UnauthorizedPage = () => {
  const queryString = window.location.search;
  const params = new URLSearchParams(queryString);
  const username = params.get("username") ?? "";
  const groupErr = params.get("groupErr") ?? "";
  const resource = params.get("resource") ?? "";

  const { t } = useTranslation();

  if (!isValidQuery(username)) {
    return <Navigate to="/" />;
  }

  if (isValidQuery(resource) && !isValidQuery(groupErr)) {
    return (
      <UnauthorizedLayout>
        <Trans
          i18nKey="unauthorizedResourceSubtitle"
          t={t}
          components={{ Code: <Code /> }}
          values={{ resource, username }}
        />
      </UnauthorizedLayout>
    );
  }

  if (isValidQuery(groupErr) && isValidQuery(resource)) {
    return (
      <UnauthorizedLayout>
        <Trans
          i18nKey="unauthorizedGroupsSubtitle"
          t={t}
          components={{ Code: <Code /> }}
          values={{ username, resource }}
        />
      </UnauthorizedLayout>
    );
  }

  return (
    <UnauthorizedLayout>
      <Trans
        i18nKey="unauthorizedLoginSubtitle"
        t={t}
        components={{ Code: <Code /> }}
        values={{ username }}
      />
    </UnauthorizedLayout>
  );
};

const UnauthorizedLayout = ({ children }: { children: React.ReactNode }) => {
  const { t } = useTranslation();

  return (
    <Layout>
      <Paper shadow="md" p={30} mt={30} radius="md" withBorder>
        <Text size="xl" fw={700}>
          {t("Unauthorized")}
        </Text>
        <Text>{children}</Text>
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

import { Button, Code, Paper, Text } from "@mantine/core";
import { Layout } from "../components/layouts/layout";
import { Navigate } from "react-router";
import { isQueryValid } from "../utils/utils";
import { Trans, useTranslation } from "react-i18next";
import React from "react";

export const UnauthorizedPage = () => {
  const queryString = window.location.search;
  const params = new URLSearchParams(queryString);
  const username = params.get("username") ?? "";
  const groupErr = params.get("groupErr") ?? "";
  const resource = params.get("resource") ?? "";

  const { t } = useTranslation();

  if (!isQueryValid(username)) {
    return <Navigate to="/" />;
  }

  if (isQueryValid(resource) && !isQueryValid(groupErr)) {
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

  if (isQueryValid(groupErr) && isQueryValid(resource)) {
    return (
      <UnauthorizedLayout>
        <Trans
        i18nKey="unauthorizedGroupsSubtitle"
        t={t}
        components={{ Code: <Code /> }}
        values={{ username, resource }}
         />
      </UnauthorizedLayout>
    )
  }

  return (
    <UnauthorizedLayout>
      <Trans
        i18nKey="unaothorizedLoginSubtitle"
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
        <Text>
        {children}
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

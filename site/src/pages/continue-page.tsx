import { Button, Code, Paper, Text } from "@mantine/core";
import { notifications } from "@mantine/notifications";
import { Navigate } from "react-router";
import { useUserContext } from "../context/user-context";
import { Layout } from "../components/layouts/layout";
import { ReactNode } from "react";
import { isQueryValid } from "../utils/utils";
import { useAppContext } from "../context/app-context";

export const ContinuePage = () => {
  const queryString = window.location.search;
  const params = new URLSearchParams(queryString);
  const redirectUri = params.get("redirect_uri") ?? "";

  const { isLoggedIn } = useUserContext();
  const { disableContinue } = useAppContext();

  if (!isLoggedIn) {
    return <Navigate to={`/login?redirect_uri=${redirectUri}`} />;
  }

  if (!isQueryValid(redirectUri)) {
    return <Navigate to="/" />;
  }

  const redirect = () => {
    notifications.show({
      title: "Redirecting",
      message: "You should be redirected to the app soon",
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
          Invalid Redirect
        </Text>
        <Text>
          The redirect URL is invalid, please contact the app owner to fix the
          issue.
        </Text>
      </ContinuePageLayout>
    );
  }

  if (disableContinue) {
    window.location.href = redirectUri;
    return (
      <ContinuePageLayout>
        <Text size="xl" fw={700}>
          Redirecting
        </Text>
        <Text>You should be redirected to your app soon.</Text>
      </ContinuePageLayout>
    );
  }

  if (window.location.protocol === "https:" && uri.protocol === "http:") {
    return (
      <ContinuePageLayout>
        <Text size="xl" fw={700}>
          Insecure Redirect
        </Text>
        <Text>
          Your are trying to redirect from <Code>https</Code> to{" "}
          <Code>http</Code>, are you sure you want to continue?
        </Text>
        <Button fullWidth mt="xl" color="yellow" onClick={redirect}>
          Continue
        </Button>
      </ContinuePageLayout>
    );
  }

  return (
    <ContinuePageLayout>
      <Text size="xl" fw={700}>
        Continue
      </Text>
      <Text>Click the button to continue to your app.</Text>
      <Button fullWidth mt="xl" onClick={redirect}>
        Continue
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

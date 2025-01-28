import { Button, Code, Paper, Text } from "@mantine/core";
import { notifications } from "@mantine/notifications";
import { Navigate } from "react-router";
import { useUserContext } from "../context/user-context";
import { Layout } from "../components/layouts/layout";
import { ReactNode } from "react";

export const ContinuePage = () => {
  const queryString = window.location.search;
  const params = new URLSearchParams(queryString);
  const redirectUri = params.get("redirect_uri");

  const { isLoggedIn, disableContinue } = useUserContext();

  if (!isLoggedIn) {
    return <Navigate to={`/login?redirect_uri=${redirectUri}`} />;
  }

  if (redirectUri === "null") {
    return <Navigate to="/" />;
  }

  const redirect = () => {
    notifications.show({
      title: "Redirecting",
      message: "You should be redirected to the app soon",
      color: "blue",
    });
    setTimeout(() => {
      window.location.href = redirectUri!;
    }, 500);
  };

  const urlParsed = URL.parse(redirectUri!);

  if (
    window.location.protocol === "https:" &&
    urlParsed!.protocol === "http:"
  ) {
    return (
      <ContinuePageLayout>
        <Text size="xl" fw={700}>
          Insecure Redirect
        </Text>
        <Text>
          Your are logged in but trying to redirect from <Code>https</Code> to{" "}
          <Code>http</Code>, please click the button to redirect.
        </Text>
        <Button fullWidth mt="xl" onClick={redirect}>
          Continue
        </Button>
      </ContinuePageLayout>
    );
  }

  if (disableContinue) {
    window.location.href = redirectUri!;
    return (
      <ContinuePageLayout>
        <Text size="xl" fw={700}>
          Redirecting
        </Text>
        <Text>You should be redirected to your app soon.</Text>
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

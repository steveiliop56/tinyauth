import { Button, Paper, Text } from "@mantine/core";
import { notifications } from "@mantine/notifications";
import { Navigate } from "react-router";
import { useUserContext } from "../context/user-context";
import { Layout } from "../components/layouts/layout";

export const ContinuePage = () => {
  const queryString = window.location.search;
  const params = new URLSearchParams(queryString);
  const redirectUri = params.get("redirect_uri");

  const { isLoggedIn } = useUserContext();

  if (!isLoggedIn) {
    return <Navigate to="/login" />;
  }

  const redirect = () => {
    notifications.show({
      title: "Redirecting",
      message: "You should be redirected to the app soon",
      color: "blue",
    });
    setTimeout(() => {
      window.location.replace(redirectUri!);
    }, 500);
  };

  return (
    <Layout>
      <Paper shadow="md" p={30} mt={30} radius="md" withBorder>
        {redirectUri ? (
          <>
            <Text size="xl" fw={700}>
              Continue
            </Text>
            <Text>Click the button to continue to your app.</Text>
            <Button fullWidth mt="xl" onClick={redirect}>
              Continue
            </Button>
          </>
        ) : (
          <>
            <Text size="xl" fw={700}>
              Logged in
            </Text>
            <Text>You are now signed in and can use your apps.</Text>
          </>
        )}
      </Paper>
    </Layout>
  );
};

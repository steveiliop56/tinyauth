import { Button, Code, Paper, Text } from "@mantine/core";
import { notifications } from "@mantine/notifications";
import { useMutation } from "@tanstack/react-query";
import axios from "axios";
import { useUserContext } from "../context/user-context";
import { Navigate } from "react-router";
import { Layout } from "../components/layouts/layout";
import { capitalize } from "../utils/utils";
import { useAppContext } from "../context/app-context";

export const LogoutPage = () => {
  const { isLoggedIn, username, oauth, provider } = useUserContext();
  const { genericName } = useAppContext();

  if (!isLoggedIn) {
    return <Navigate to="/login" />;
  }

  const logoutMutation = useMutation({
    mutationFn: () => {
      return axios.post("/api/logout");
    },
    onError: () => {
      notifications.show({
        title: "Failed to logout",
        message: "Please try again",
        color: "red",
      });
    },
    onSuccess: () => {
      notifications.show({
        title: "Logged out",
        message: "Goodbye!",
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
          Logout
        </Text>
        <Text>
          You are currently logged in as <Code>{username}</Code>
          {oauth &&
            ` using ${capitalize(provider === "generic" ? genericName : provider)} OAuth`}
          . Click the button below to log out.
        </Text>
        <Button
          fullWidth
          mt="xl"
          onClick={() => logoutMutation.mutate()}
          loading={logoutMutation.isLoading}
        >
          Logout
        </Button>
      </Paper>
    </Layout>
  );
};

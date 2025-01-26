import { Button, Code, Paper, Text } from "@mantine/core";
import { Layout } from "../components/layouts/layout";
import { useUserContext } from "../context/user-context";
import { Navigate } from "react-router";

export const UnauthorizedPage = () => {
  const queryString = window.location.search;
  const params = new URLSearchParams(queryString);
  const username = params.get("email");

  const { isLoggedIn } = useUserContext();

  if (isLoggedIn) {
    return <Navigate to="/" />;
  }

  if (username === "null") {
    return <Navigate to="/" />;
  }

  return (
    <Layout>
      <Paper shadow="md" p={30} mt={30} radius="md" withBorder>
        <Text size="xl" fw={700}>
          Unauthorized
        </Text>
        <Text>
          The user with username <Code>{username}</Code> is not authorized to
          login.
        </Text>
        <Button
          fullWidth
          mt="xl"
          onClick={() => window.location.replace("/login")}
        >
          Try again
        </Button>
      </Paper>
    </Layout>
  );
};

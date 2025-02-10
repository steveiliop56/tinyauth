import { Button, Code, Paper, Text } from "@mantine/core";
import { Layout } from "../components/layouts/layout";
import { Navigate } from "react-router";

export const UnauthorizedPage = () => {
  const queryString = window.location.search;
  const params = new URLSearchParams(queryString);
  const username = params.get("username") ?? "";
  const resource = params.get("resource") ?? "";

  if (username === "null" || username === "") {
    return <Navigate to="/" />;
  }

  return (
    <Layout>
      <Paper shadow="md" p={30} mt={30} radius="md" withBorder>
        <Text size="xl" fw={700}>
          Unauthorized
        </Text>
        <Text>
          The user with username <Code>{username}</Code> is not authorized to{" "}
          {resource !== "null" && resource !== "" ? (
            <span>
              access the <Code>{resource}</Code> resource.
            </span>
          ) : (
            "login."
          )}
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

import { Button, Paper, Text } from "@mantine/core";
import { Layout } from "../components/layouts/layout";

export const InternalServerError = () => {
  return (
    <Layout>
      <Paper shadow="md" p={30} mt={30} radius="md" withBorder>
        <Text size="xl" fw={700}>
          Internal Server Error
        </Text>
        <Text>
          An error occured on the server and it currently cannot serve your
          request.
        </Text>
        <Button fullWidth mt="xl" onClick={() => window.location.replace("/")}>
          Try again
        </Button>
      </Paper>
    </Layout>
  );
};

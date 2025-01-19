import { Button, Paper, Text } from "@mantine/core";
import { Layout } from "../components/layouts/layout";

export const NotFoundPage = () => {
  return (
    <Layout>
      <Paper shadow="md" p={30} mt={30} radius="md" withBorder>
        <Text size="xl" fw={700}>
          Not found
        </Text>
        <Text>The page you are looking for does not exist.</Text>
        <Button fullWidth mt="xl" onClick={() => window.location.replace("/")}>
          Go home
        </Button>
      </Paper>
    </Layout>
  );
};
